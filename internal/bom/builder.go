package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"
	"github.com/OmniTrustILM/cbom-lens/internal/stats"
	"github.com/google/uuid"
)

var programVersion string

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		programVersion = "unknown"
	} else {
		programVersion = info.Main.Version
	}
}

// Builder is a builder pattern for a CycloneDX BOM structure
type Builder struct {
	version      cdx.SpecVersion
	validator    Validator
	components   map[string]*cdx.Component
	dependencies map[string]*[]string
	// rels are crypto relationships a converter stated outright, keyed by the
	// whole edge so the same request seen at two paths contributes one. Held
	// with the converter's raw refs; model() canonicalises them alongside the
	// components, so an edge and its endpoints cannot end up on different
	// sides of the safeRefs rewrite.
	rels    map[cbom.Relationship]struct{}
	counter *stats.Stats
	clock   func() time.Time
	serial  func() string
}

func NewBuilder(config model.CBOM) (*Builder, error) {
	var versions = map[string]cdx.SpecVersion{
		"1.6": cdx.SpecVersion1_6,
		"1.7": cdx.SpecVersion1_7,
	}

	version, ok := versions[config.Version]
	if !ok {
		return nil, fmt.Errorf("unsupported cbom spec version %s", config.Version)
	}
	// emitterFor is the single source of truth for renderable versions: a
	// version must not be accepted here unless BOM() can actually emit it.
	if _, err := emitterFor(version); err != nil {
		return nil, fmt.Errorf("unsupported cbom spec version %s: %w", config.Version, err)
	}

	// Built here so an unusable schema set fails at construction rather than
	// after a full scan has already been paid for.
	validator, err := NewValidator(version)
	if err != nil {
		return nil, fmt.Errorf("preparing the %s schema set: %w", config.Version, err)
	}

	return &Builder{
		version:      version,
		validator:    validator,
		components:   make(map[string]*cdx.Component),
		dependencies: make(map[string]*[]string),
		rels:         make(map[cbom.Relationship]struct{}),
		clock:        func() time.Time { return time.Now().UTC() },
		serial:       func() string { return "urn:uuid:" + uuid.New().String() },
	}, nil
}

func (b *Builder) WithCounter(counter *stats.Stats) *Builder {
	b.counter = counter
	return b
}

// WithClock overrides the timestamp source. A nil f keeps the default clock.
func (b *Builder) WithClock(f func() time.Time) *Builder {
	if f != nil {
		b.clock = f
	}
	return b
}

// WithSerial overrides the serial number source. A nil f keeps the default
// generator.
func (b *Builder) WithSerial(f func() string) *Builder {
	if f != nil {
		b.serial = f
	}
	return b
}

// AppendDetections folds each detection into the Builder: one component stored
// per bom-ref, plus the detection's dependency edges, unioned per ref. A repeat
// of a bom-ref does not replace the component already held -- what the second
// detection knows and the first does not is merged into it explicitly, which
// today means its evidence location, its related-crypto-material format and its
// certificate source_format. The dependency edges are the one thing that is not
// first-wins at all: two detections naming one ref are describing one asset's
// edges, and both are right, so mergeDependsOn unions them and sorts the result.
// That sentence used to read "first ref wins", which cost a certificate its edge
// to its own public-key algorithm whenever a CRL signed with the same algorithm
// happened to be scanned first.
//
// A detection passed here comes back unchanged. The components are stored as
// copies: cloneOnStore detaches the parts the Builder writes to -- evidence, and
// the cryptoProperties a Builder writer can reach, meaning the certificate and
// related-material refs down to securedBy and the ikev2 transform slices -- so
// neither a later merge, a later evidence location, nor the bom-ref
// canonicalisation performed on every BOM()/AsJSON() call is observable through
// the model.Detection the caller still holds. Everything else reachable from a
// stored component remains the caller's memory: licenses, pedigree, external
// references and nested components, and also parts of cryptoProperties nothing
// here writes, such as algorithmProperties, cipherSuites and cryptoRefArray.
// That is a statement about today's writers, not a promise about the type or an
// exhaustive list; cloneOnStore says why the named omissions are safe and what a
// new Builder write would have to add.
//
// The dependency edges are copied on the same terms: mergeDependsOn stores a
// slice it allocated itself and never the *[]string the detection carried, so
// the union cannot grow the caller's slice or write into its backing array.
func (b *Builder) AppendDetections(ctx context.Context, detections ...model.Detection) *Builder {
	for _, d := range detections {
		b.appendDetection(ctx, d)
	}
	return b
}

func (b *Builder) appendDetection(ctx context.Context, detection model.Detection) {
	for _, dep := range detection.Dependencies {
		if dep.Ref == "" {
			continue
		}
		b.mergeDependsOn(ctx, dep)
	}

	for _, rel := range detection.Rels {
		// A half-built edge is not stored. model() would drop it on the
		// unresolvable-endpoint path anyway, with a warning naming an empty
		// ref, which reads as a Builder fault rather than a producer one.
		if rel.From == "" || rel.To == "" || rel.Kind == "" {
			slog.WarnContext(ctx, "dropping crypto relationship: incomplete edge",
				"from", string(rel.From), "to", string(rel.To), "kind", string(rel.Kind))
			continue
		}
		b.rels[rel] = struct{}{}
	}

	for _, compo := range detection.Components {
		if reason, drop := missingIdentity(compo); drop {
			// A component without a ref or a name cannot be stored: the map is
			// keyed by ref, and a nameless component is unreadable in the
			// emitted document. Dropping it silently is how a scanned .csr and
			// .crl produced an empty BOM and exit 0 -- the producers built
			// refless components and nothing said so. Warn, not Debug: the
			// audience is whoever has to explain a missing asset in a delivered
			// BOM, and after the CSR/CRL fix no production path reaches here.
			//
			// For reason="no bom-ref and no name" the line carried name="",
			// ref="" and nothing else, so it said an asset was thrown away
			// without saying which. Type, asset type and description are what
			// is in hand to tell one dropped component from another.
			//
			// detection.source is the SCANNER's label and is not the producer.
			// Converter.Leak stamps "LEAKS" onto components PEMBundle's
			// producers built, so a defect in internal/cdxprops/pem.go reads
			// here as one in the gitleaks path. Naming the producer would mean
			// threading producer identity through model.Detection, which is
			// out of scope; the field names say "detection", so the line
			// reports where the detection came from and does not claim to
			// identify what built the component.
			var assetType cdx.CryptoAssetType
			if compo.CryptoProperties != nil {
				assetType = compo.CryptoProperties.AssetType
			}
			slog.WarnContext(ctx, "dropping component: cannot be identified",
				"reason", reason,
				"name", compo.Name,
				"ref", compo.BOMRef,
				"component.type", compo.Type,
				"component.asset_type", assetType,
				"component.description", compo.Description,
				"detection.source", detection.Source,
				"detection.location", detection.Location)
			continue
		}
		stored, ok := b.components[compo.BOMRef]
		if ok {
			// First-wins keeps the stored component and discards the rest of
			// the second one, so anything the second detection knows and the
			// first does not has to be merged here explicitly, exactly as
			// evidence.occurrences already is.
			mergeRelatedCryptoMaterialFormat(ctx, stored, &compo)
			mergeCertificateSourceFormat(ctx, stored, &compo)
			addEvidenceLocation(stored, detection.Location)
			continue
		}
		// Clone BEFORE addEvidenceLocation, not after: addEvidenceLocation is
		// itself one of the writers being contained, so a copy taken after it
		// ran would already have clobbered the caller's Evidence.
		owned := cloneOnStore(compo)
		addEvidenceLocation(&owned, detection.Location)
		b.components[owned.BOMRef] = &owned
	}
}

// cloneOnStore returns compo with the parts the Builder writes to detached from
// the caller's memory.
//
// appendDetection stores a struct copy of each component, and a struct copy
// shares every pointer field with the model.Detection the caller still holds.
// Four Builder writes reached back through those pointers, so each item copied
// below is here because a named writer reaches it -- this is not a deep copy
// and must not drift into one.
//
// Evidence, because addEvidenceLocation allocates one only when the component
// arrives without it. Converter.Leak brings its own, carrying the line number
// gitleaks reported, and the occurrence set is rebuilt from locations alone --
// so writing through the caller's Evidence silently erased that line.
// RelatedCryptoMaterialProperties, because mergeRelatedCryptoMaterialFormat
// writes format into it and, on the arm where the stored component has none,
// hangs a freshly allocated one off cryptoProperties. CertificateProperties,
// RelatedCryptoMaterialProperties.SecuredBy, the five transform slices under
// ProtocolProperties.IKEv2TransformTypes, ProtocolProperties.CryptoRefArray and
// the Algorithms slice inside each ProtocolProperties.CipherSuites entry,
// because replaceBOMReferences is a reflect walk that rewrites every
// cdx.BOMReference it can reach in place, on every stored component, on every
// render. That is the walk's entire reach within one component; the ikev2 ones
// had nothing watching them, since no producer here emits ikev2TransformTypes.
//
// The last two are here because the walk grew (#205). It used to substitute
// BOMReference-typed FIELDS OF A STRUCT and never elements of a slice of them,
// which is what let cryptoRefArray and cipherSuites[].algorithms -- both
// []cdx.BOMReference -- be left aliased to the caller. Now that those elements
// are rewritten too, not copying them writes the Builder's safe refs back into
// the detection the caller still holds.
//
// Deliberately not copied, and why that is safe. AlgorithmProperties, and the
// CipherSuites fields other than Algorithms: no Builder code writes any of them,
// and emit17's mapComponent17, which does, takes its own copy in
// emit17.cloneComponent first. That is why the two helpers stay separate and
// differently shaped -- one shared helper would over-copy at both call sites and
// would falsify emit17's promise to clone only what mapComponent17 writes.
// Component.Components and
// Component.Pedigree are the one place the walk could still reach caller memory
// -- a nested component re-exposes all nine paths -- but nothing in this repo
// ever builds a nested component or a pedigree, so the walk never descends
// there. A producer that starts to, or a Builder write aimed at anything else on
// cdx.Component, has to extend this helper, or it will quietly reach into the
// caller's detection again.
func cloneOnStore(compo cdx.Component) cdx.Component {
	if compo.Evidence != nil {
		ev := *compo.Evidence
		compo.Evidence = &ev
	}
	if compo.CryptoProperties == nil {
		return compo
	}

	cp := *compo.CryptoProperties
	if cp.CertificateProperties != nil {
		certp := *cp.CertificateProperties
		cp.CertificateProperties = &certp
	}
	if cp.RelatedCryptoMaterialProperties != nil {
		matp := *cp.RelatedCryptoMaterialProperties
		if matp.SecuredBy != nil {
			sb := *matp.SecuredBy
			matp.SecuredBy = &sb
		}
		cp.RelatedCryptoMaterialProperties = &matp
	}
	if cp.ProtocolProperties != nil {
		pp := *cp.ProtocolProperties
		pp.CryptoRefArray = cloneBackingArray(pp.CryptoRefArray)
		pp.CipherSuites = cloneCipherSuites(pp.CipherSuites)
		if pp.IKEv2TransformTypes != nil {
			tt := *pp.IKEv2TransformTypes
			tt.Encr = cloneBackingArray(tt.Encr)
			tt.PRF = cloneBackingArray(tt.PRF)
			tt.Integ = cloneBackingArray(tt.Integ)
			tt.KE = cloneBackingArray(tt.KE)
			tt.Auth = cloneBackingArray(tt.Auth)
			pp.IKEv2TransformTypes = &tt
		}
		cp.ProtocolProperties = &pp
	}
	compo.CryptoProperties = &cp

	return compo
}

// cloneBackingArray copies the array behind one ref-holding slice -- an IKEv2
// transform-type slice, a cryptoRefArray, or one suite's algorithms -- so
// replaceBOMReferences rewrites the Builder's elements and not the caller's.
// Copying the enclosing struct alone would not do it: these fields are slice
// pointers, and the BOMRefs the walk writes live in the elements.
//
// A nil pointer, and a non-nil pointer to a nil slice, are returned as they
// came: there is no backing array to protect, and replacing the latter with an
// allocated empty slice would turn a null into a [] in the emitted document.
func cloneBackingArray[T any](p *[]T) *[]T {
	if p == nil || *p == nil {
		return p
	}
	out := make([]T, len(*p))
	copy(out, *p)
	return &out
}

// cloneCipherSuites detaches the refs the walk rewrites inside a cipher-suite
// slice: the suite array itself, and the algorithms array within each suite.
//
// Both hops are needed. Copying only the outer array leaves every suite's
// Algorithms pointer aliased to the caller's, and that inner slice is where the
// BOMRefs live; copying only the inner arrays would mean writing the new
// pointers into the caller's suite structs. The other suite fields are shared
// on purpose -- nothing in the Builder writes them.
func cloneCipherSuites(p *[]cdx.CipherSuite) *[]cdx.CipherSuite {
	suites := cloneBackingArray(p)
	if suites == nil {
		return suites
	}
	for i := range *suites {
		(*suites)[i].Algorithms = cloneBackingArray((*suites)[i].Algorithms)
	}
	return suites
}

// missingIdentity reports whether a component lacks the bom-ref and/or name
// needed to store and emit it, and if so, why: reason names which half of
// the component's identity is absent, so the drop warning says what is
// wrong with the component rather than reading as a Builder failure.
//
// shouldDrop and reason are computed together from the same fields, so they
// cannot disagree: reason is meaningful only when shouldDrop is true, and a
// component reported "no name" is, by construction, one whose Name is "".
// When shouldDrop is false, reason is "" and the caller must not log it.
func missingIdentity(c cdx.Component) (reason string, shouldDrop bool) {
	switch {
	case c.BOMRef == "" && c.Name == "":
		return "no bom-ref and no name", true
	case c.BOMRef == "":
		return "no bom-ref", true
	case c.Name == "":
		return "no name", true
	default:
		return "", false
	}
}

// BOM returns a cdx.BOM based on a data inside the Builder. It builds the
// version-neutral IR via model() and renders it through the Emitter for the
// Builder's spec version.
func (b *Builder) BOM(ctx context.Context) cdx.BOM {
	e, err := emitterFor(b.version)
	if err != nil {
		// NewBuilder validates the version against emitterFor, so this is
		// unreachable for Builders constructed through NewBuilder.
		panic(err)
	}
	return e.Emit(ctx, b.model(ctx))
}

// model returns the version-neutral cbom.BOMModel built from the Builder's
// accumulated components/dependencies maps. A single canonical safeRefs map
// is applied to both assets and relationship endpoints, so a dependsOn edge's
// From/To always match the wire ref used for the corresponding asset (see
// safeRefs/safeRef). BOM() renders the result through the version's Emitter.
func (b *Builder) model(ctx context.Context) cbom.BOMModel {
	sr := b.safeRefs()

	var rels []cbom.Relationship

	// Extract crypto rels before the assets loop: sr.component below rewrites
	// the reference fields of the Builder's stored components in place, so this
	// reads them while they are still raw.
	wire := make(map[string]struct{}, len(sr.refs))
	for _, w := range sr.refs {
		wire[w] = struct{}{}
	}
	for _, compop := range b.components {
		rels = append(rels, cryptoRels(ctx, sr.refs, wire, compop)...)
	}

	// Crypto relationships a converter stated outright, for edges with no 1.6
	// field for cryptoRels to read back. Canonicalised through the same map and
	// dropped on the same terms as everything else, with the same identity
	// fallback for a ref that is already a wire value.
	//
	// Sorted before appending because b.rels is a map and its iteration order is
	// random: the sort at the end of this function is stable by From only, so
	// two edges out of one asset would otherwise swap places between runs and
	// move bytes in the emitted document.
	stated := make([]cbom.Relationship, 0, len(b.rels))
	for rel := range b.rels {
		stated = append(stated, rel)
	}
	slices.SortFunc(stated, func(a, b cbom.Relationship) int {
		if v := strings.Compare(string(a.From), string(b.From)); v != 0 {
			return v
		}
		if v := strings.Compare(string(a.To), string(b.To)); v != 0 {
			return v
		}
		return strings.Compare(string(a.Kind), string(b.Kind))
	})
	resolve := func(raw cbom.AssetRef) (cbom.AssetRef, bool) {
		if to, ok := sr.refs[string(raw)]; ok {
			return cbom.AssetRef(to), true
		}
		if _, ok := wire[string(raw)]; ok {
			return raw, true
		}
		return "", false
	}
	for _, rel := range stated {
		from, ok := resolve(rel.From)
		if !ok {
			slog.WarnContext(ctx, "dropping crypto relationship: source has no component",
				"from", string(rel.From), "to", string(rel.To), "kind", string(rel.Kind))
			continue
		}
		to, ok := resolve(rel.To)
		if !ok {
			slog.WarnContext(ctx, "dropping crypto relationship: target has no component",
				"from", string(rel.From), "to", string(rel.To), "kind", string(rel.Kind))
			continue
		}
		rels = append(rels, cbom.Relationship{From: from, To: to, Kind: rel.Kind})
	}

	assets := make([]cbom.Asset, 0, len(b.components))
	for _, compop := range b.components {
		if compop == nil {
			continue
		}
		comp := sr.component(ctx, *compop)
		assets = append(assets, cbom.Asset{
			Ref:       cbom.AssetRef(comp.BOMRef),
			Component: comp,
		})
	}
	slices.SortFunc(assets, func(a, b cbom.Asset) int {
		return strings.Compare(string(a.Ref), string(b.Ref))
	})

	// Flatten dependsOn into per-edge RelDependsOn, preserving within-source
	// order (emit16 regroups same-From edges into one dependsOn array; the
	// golden corpus pins the rendering). Edges whose endpoints do not resolve
	// to a stored component are dropped: emitting a fabricated ref would be
	// dangling, and minting one would be nondeterministic.
	for ref, depsp := range b.dependencies {
		if depsp == nil {
			continue
		}
		from, ok := sr.refs[ref]
		if !ok {
			slog.WarnContext(ctx, "dropping dependency entry: ref has no component", "ref", ref)
			continue
		}
		for _, dep := range *depsp {
			to, ok := sr.refs[dep]
			if !ok {
				slog.WarnContext(ctx, "dropping dependency edge: target has no component", "from", ref, "to", dep)
				continue
			}
			rels = append(rels, cbom.Relationship{
				From: cbom.AssetRef(from),
				To:   cbom.AssetRef(to),
				Kind: cbom.RelDependsOn,
			})
		}
	}
	// Stable sort by From only, so within-From order (slice order) is preserved.
	slices.SortStableFunc(rels, func(a, b cbom.Relationship) int {
		return strings.Compare(string(a.From), string(b.From))
	})

	var statsProps []cdx.Property
	if b.counter != nil {
		statsProps = bomStatistics(b.counter)
	}

	return cbom.BOMModel{
		Assets:       assets,
		Rels:         rels,
		SerialNumber: b.serial(),
		Timestamp:    b.clock().Format(time.RFC3339),
		StatsProps:   statsProps,
	}
}

// cryptoRels derives version-neutral crypto relationships from the embedded
// 1.6 reference fields still written by the converters. Endpoints resolve
// through refs (raw -> wire) with an identity fallback for already-canonical
// values: model() canonicalises the Builder's OWN stored components in place,
// so a second model() call on the same Builder reads refs that are already wire
// values and must still resolve them. That in-place rewrite no longer escapes
// the Builder -- appendDetection clones what it stores -- but it is still what
// makes the fallback necessary. Unresolvable targets are dropped with a warning,
// mirroring dependsOn handling. Transitional: this extraction retires per
// converter as they migrate to emitting Rels natively.
func cryptoRels(ctx context.Context, r refs, wire map[string]struct{}, compo *cdx.Component) []cbom.Relationship {
	if compo == nil || compo.CryptoProperties == nil {
		return nil
	}
	from := r[compo.BOMRef]
	resolve := func(raw string) (string, bool) {
		if to, ok := r[raw]; ok {
			return to, true
		}
		if _, ok := wire[raw]; ok {
			return raw, true
		}
		return "", false
	}
	var rels []cbom.Relationship
	add := func(kind cbom.RelationshipKind, raw string) {
		if raw == "" {
			return
		}
		to, ok := resolve(raw)
		if !ok {
			slog.WarnContext(ctx, "dropping crypto relationship: target has no component",
				"from", compo.BOMRef, "to", raw, "kind", string(kind))
			return
		}
		rels = append(rels, cbom.Relationship{From: cbom.AssetRef(from), To: cbom.AssetRef(to), Kind: kind})
	}
	cp := compo.CryptoProperties
	if cp.CertificateProperties != nil {
		add(cbom.RelSignatureAlgorithm, string(cp.CertificateProperties.SignatureAlgorithmRef))
		add(cbom.RelSubjectPublicKey, string(cp.CertificateProperties.SubjectPublicKeyRef))
	}
	if cp.RelatedCryptoMaterialProperties != nil {
		add(cbom.RelMaterialAlgorithm, string(cp.RelatedCryptoMaterialProperties.AlgorithmRef))
	}
	if cp.ProtocolProperties != nil && cp.ProtocolProperties.CryptoRefArray != nil {
		for _, ref := range *cp.ProtocolProperties.CryptoRefArray {
			add(cbom.RelProtocolCrypto, string(ref))
		}
	}
	return rels
}

// AsJSON encodes the BOM into JSON format, validating it against the vendored
// schema set for the Builder's spec version before anything is written.
//
// Validation is on the emit path rather than only in tests because 1.7's
// registry fields are closed enumerations: a single out-of-vocabulary value
// invalidates the whole document. CBOM-Lens is currently the only producer
// emitting those fields, so no downstream tool would catch such a document --
// refusing to write it is the only place the mistake can still be caught. The
// schema set is embedded, so this costs no network access.
func (b *Builder) AsJSON(ctx context.Context, w io.Writer) error {
	bom := b.BOM(ctx)

	// Validate the compact encoding: JSON Schema is whitespace-insensitive, so
	// the pretty form would only inflate peak memory without validating
	// anything more.
	var compact bytes.Buffer
	if err := cdx.NewBOMEncoder(&compact, cdx.BOMFileFormatJSON).Encode(&bom); err != nil {
		return err
	}

	// Validate against the version this Builder was constructed for, not
	// against whatever specVersion happens to be encoded. Rediscovering the
	// version from the payload would make validation follow the document,
	// so an emitter writing the wrong specVersion would be checked against
	// the wrong schema and pass.
	if err := b.validateAs(b.version, compact.Bytes()); err != nil {
		return err
	}

	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(true).Encode(&bom)
}

// validateAs checks raw against the schema for version, first confirming that
// the document declares that version. The declared-version check is what makes
// an emitter/configuration mismatch an error instead of a silent pass: the two
// are independent inputs, and cbom-repository rejects any document whose
// specVersion disagrees with what the uploader declared.
func (b *Builder) validateAs(version cdx.SpecVersion, raw []byte) error {
	var declared struct {
		SpecVersion cdx.SpecVersion `json:"specVersion"`
	}
	if err := json.Unmarshal(raw, &declared); err != nil {
		return fmt.Errorf("reading specVersion from the encoded BOM: %w", err)
	}
	if declared.SpecVersion != version {
		return fmt.Errorf(
			"refusing to emit a CBOM: builder is %s but the document declares %s",
			version, declared.SpecVersion)
	}

	schema, err := b.validator.versionToSchema(version)
	if err != nil {
		return err
	}
	if err := b.validator.validateBytes(schema, raw); err != nil {
		return fmt.Errorf("refusing to emit a CBOM that fails %s schema validation: %w", version, err)
	}
	return nil
}

// Add (append) an evidence.occurrence location if non-empty.
// ensures location is present only once
func addEvidenceLocation(c *cdx.Component, locations ...string) {
	if c == nil || locations == nil {
		return
	}
	if c.Evidence == nil {
		c.Evidence = &cdx.Evidence{}
	}
	if c.Evidence.Occurrences == nil {
		c.Evidence.Occurrences = &[]cdx.EvidenceOccurrence{}
	}

	stored := make(map[string]struct{})
	for _, occ := range *c.Evidence.Occurrences {
		stored[occ.Location] = struct{}{}
	}
	for _, loc := range locations {
		stored[loc] = struct{}{}
	}

	if len(stored) == 0 {
		return
	}

	occurences := make([]cdx.EvidenceOccurrence, 0, len(stored))
	for _, loc := range slices.Sorted(maps.Keys(stored)) {
		occurences = append(occurences, cdx.EvidenceOccurrence{
			Location: loc,
		})
	}

	c.Evidence.Occurrences = &occurences
}

// mergeDependsOn folds one detection's dependency entry into the edges already
// stored under the same bom-ref, so the emitted dependsOn array is decided by
// the SET of detections naming that ref as a source and never by the order they
// arrive in.
//
// Only the Builder can decide this. A signature algorithm's bom-ref is a pure
// function of the x509.SignatureAlgorithm enum and the OID
// (cdxprops.signatureAlgorithmComponents), so every ECDSA-SHA256 signature in a
// scan -- on a certificate, on a CRL, on anything else PKIX signs -- lands on
// ONE ref. That is deliberate, and it is the same property that lets one
// certificate found at three paths dedupe to one asset. What it means here is
// that two producers describe the edges of one asset and neither can see the
// other: cdxprops.certHitToComponents claims {publicKeyAlg, hash} because a
// certificate's signature algorithm decomposes into both, while cdxprops.crlToCDX
// claims {hash} because a revocation list has no subject key to name. Scanning
// fans out over goroutines (internal/parallel) onto one channel
// (cmd/cbom-lens/lens.go), so which of them reached the Builder first was a coin
// flip, and under first-wins the loser's edges were dropped with a Debug line.
// The certificate lost the edge to its own public-key algorithm, and nothing
// dangled or was flagged, because the components at both ends were still stored
// by whichever detection carried them. The committed golden corpus contains that
// exact pair -- one certificate and one CRL sharing crypto/algorithm/
// sha-256-ecdsa -- and survived only by luck: the certificate is appended first
// and the CRL's edge set is a subset of it.
//
// The union is the only defensible answer. dependsOn is a SET in CycloneDX, both
// claims are true of the same asset, and dropping either loses a fact -- so
// unlike mergeRelatedCryptoMaterialFormat there is nothing to tie-break and this
// never warns. It is mergeCertificateSourceFormat's situation, one field over.
//
// The SORT is what makes the fix complete rather than half of one. Builder.model
// flattens this map into one Relationship per edge and stable-sorts by From
// ONLY, so within-From order is slice order, and regroupDependsOn -- shared by
// emit16 and emit17 -- regroups consecutive same-From edges without deduping or
// reordering. The order of this slice is therefore the byte order of the
// delivered document, which two goldens pin. A union that appended in arrival
// order would restore every edge and still emit a different byte sequence per
// permutation: the same nondeterminism moved one field along, and invisible to
// any test that compares dependsOn as a set.
//
// RAW refs are sorted, not the canonical ones model() mints, and the two orders
// are not always the same. safeRef keeps everything before the "@" and replaces
// the digest with a UUIDv5 of the whole raw ref, so it is order-preserving only
// for pairs that already differ before the "@". Two targets CAN share that
// prefix and be different assets: cdxprops.parse_tls builds a TLS_RSA_WITH_*
// key-exchange facet as crypto/algorithm/rsa-2048 with primitive key-agree and
// functions [keyderive,keygen] (parse_tls.go:138), while a certificate's subject
// key builds crypto/algorithm/rsa-2048 with primitive pke and the rsaEncryption
// OID (algorithm.go:600) -- one name, two genuinely different assets, two
// digests. Their UUIDs then sort in an order unrelated to their digests, and the
// emitted array is not ascending on the wire.
//
// That pair is reachable but is NOT in the committed corpus, so the fixture in
// builder_test.go is synthetic. The example this comment used to give -- a
// signing and an encrypting RSA-2048 certificate naming two rsa-2048 assets --
// was real when it was written and is now false: it described the KeyUsage-derived
// primitive that #217 removed, and those two certificates now name one asset.
//
// That is accepted, because the requirement is determinism and not lexicographic
// wire order: the raw refs are a pure function of the detections, so the emitted
// sequence is too, which is the whole property first-wins lacked. Sorting the
// canonical refs instead would mean minting them here, before model() knows the
// full component set -- trading a cosmetic gain for the ordering being computed
// twice, in two places, from different inputs.
//
// The stored slice is always one this function allocated. Three ways to write
// this are wrong and none fails loudly. Assigning dep.Dependencies adopts the
// caller's pointer outright, so every later merge rewrites the caller's
// detection. The other two only compound that one: given a stored slice this
// function allocated, append(*stored, ...) through the held *[]string and
// merged := append(*stored, ...) into a fresh pointer both damage the Builder's
// OWN earlier slice -- reachable by the caller only once pointer adoption has
// put the caller's array there, which is exactly the composite a refactor
// reintroduces by halves. slices.Sorted allocates unconditionally, which is what
// makes all three dead by construction and keeps AppendDetections' promise that
// a detection handed to it comes back unchanged true for the dependency half --
// today that promise rested on nothing, since first-wins simply never wrote.
// This is what cloneOnStore does for components.
//
// A union that comes out empty creates no key at all, so a nil Dependencies and
// an empty one converge. model() skips a nil entry silently but WARNS "dropping
// dependency entry: ref has no component" for a non-nil empty one whose ref has
// no component -- a warning about discarding zero edges.
//
// Targets are neither filtered for existence nor checked for self-reference. At
// merge time "this target has no component" is not knowable: appendDetection
// folds Dependencies in BEFORE the same detection's Components, and across
// detections arrival order is arbitrary, so the component that resolves a target
// is routinely in a detection not yet appended. Dropping an edge here would
// delete a good one for being early. model() runs once over everything and is the
// only place that can tell a dangling target from an early one.
func (b *Builder) mergeDependsOn(ctx context.Context, dep cdx.Dependency) {
	var stored []string
	if p := b.dependencies[dep.Ref]; p != nil {
		stored = *p
	}

	targets := make(map[string]struct{}, len(stored))
	for _, to := range stored {
		targets[to] = struct{}{}
	}
	before := len(targets)

	if dep.Dependencies != nil {
		for _, to := range *dep.Dependencies {
			if to == "" {
				continue
			}
			targets[to] = struct{}{}
		}
	}

	merged := slices.Sorted(maps.Keys(targets))

	// Compared as a SEQUENCE, not as a set, and not by length: a stored run that
	// is out of order or repeats a target differs from the sorted union and is
	// rebuilt, while a length test would let [sha-256, sha-256] swallow an
	// arriving ecdsa-p-256. It also makes the whole call a no-op -- no
	// allocation, no map write -- for the ordinary case of one certificate found
	// in three files re-presenting the identical edge set three times.
	if slices.Equal(merged, stored) {
		return
	}
	b.dependencies[dep.Ref] = &merged

	// Only when a SECOND contributor actually widened an existing set. Not on the
	// first store, which is every edge in a normal scan, and not on a rebuild
	// that merely re-sorted, which adds no fact.
	if before > 0 && len(merged) > before {
		slog.DebugContext(ctx, "one ref's dependency edges came from more than one detection",
			"ref", dep.Ref,
			"edges", strings.Join(merged, ","),
			"added", len(merged)-before)
	}
}

// mergeRelatedCryptoMaterialFormat folds an incoming component's
// relatedCryptoMaterialProperties.format into the one already stored under the
// same bom-ref, so the emitted value is decided by the SET of detections that
// resolve to that ref and never by the order they arrive in.
//
// Only the Builder can decide this. setPEMFormat stamps format=PEM over what
// Converter.PEMBundle collected; the same key reached through Converter.CertHit
// (DER, PKCS7-DER, PKCS12, JKS, nmap TLS) carries none, and a public key's
// bom-ref is a pure digest of its marshalled SPKI (cdxprops.hashPublicKey), so
// neither producer can see that the other ran. Scanning fans out over goroutines
// (internal/parallel) onto one channel (cmd/cbom-lens/lens.go), so under
// first-wins a key present both as /etc/ssl/certs/ca.pem and inside
// /etc/ssl/store.p12 gained or lost format between identical runs. Putting the
// format in the hash instead was rejected: that gives one asset N refs, the
// defect #217 exists to remove.
//
// A non-empty format therefore always survives, and two DIFFERING non-empty
// values -- unreachable while setPEMFormat is the only writer of the field --
// resolve to the lexicographically smaller. The tie-break exists to be TOTAL and
// order-independent, so a second writer cannot quietly reinstate the
// nondeterminism this removes; a disagreement is logged because it means two
// detections described one asset differently.
//
// The struct is allocated on stored when missing, but only for a
// related-crypto-material asset, mirroring setPEMFormat's gate: inventing
// relatedCryptoMaterialProperties on an algorithm or a certificate is #213, and
// a whole cryptoProperties would fabricate an assetType no producer chose. No
// current producer leaves it nil on material, so that arm guards the next one.
//
// Both writes land on stored.CryptoProperties, which appendDetection cloned
// before storing, so they stay inside the Builder. The merge needs no copy of
// its own: nothing it takes from incoming escapes into stored -- it reads one
// string, and the struct it allocates when stored has none is made here. What
// it must never become is a merge that assigns a sub-struct OUT of incoming
// INTO stored; that would re-alias the second detection, and cloneOnStore,
// which runs only on the first-store path, could not undo it.
func mergeRelatedCryptoMaterialFormat(ctx context.Context, stored, incoming *cdx.Component) {
	if stored == nil || incoming == nil {
		return
	}
	if incoming.CryptoProperties == nil || incoming.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		return
	}
	format := incoming.CryptoProperties.RelatedCryptoMaterialProperties.Format
	if format == "" {
		return
	}
	if stored.CryptoProperties == nil {
		return
	}

	props := stored.CryptoProperties.RelatedCryptoMaterialProperties
	if props == nil {
		if stored.CryptoProperties.AssetType != cdx.CryptoAssetTypeRelatedCryptoMaterial {
			return
		}
		props = &cdx.RelatedCryptoMaterialProperties{}
		stored.CryptoProperties.RelatedCryptoMaterialProperties = props
	}

	switch props.Format {
	case format:
		return
	case "":
		props.Format = format
		return
	}

	kept, discarded := min(props.Format, format), max(props.Format, format)
	slog.WarnContext(ctx, "detections disagree on the format of one component",
		"ref", stored.BOMRef,
		"kept", kept,
		"discarded", discarded)
	props.Format = kept
}

// certificateSourceFormats returns, in document order, the value of every
// ilm:component:certificate:source_format property carried by c.
//
// An empty value is not an observation and is skipped. model.CertHit.Source is
// a plain string and nothing obliges a scanner to fill it, so
// ilm.CertificateProperties will happily write source_format=""; since "" sorts
// before every entry of the real vocabulary, admitting it would put a valueless
// property at the head of every certificate one scanner failed to label.
func certificateSourceFormats(c *cdx.Component) []string {
	if c == nil || c.Properties == nil {
		return nil
	}
	var out []string
	for _, p := range *c.Properties {
		if p.Name == ilm.CertificateSourceFormat && p.Value != "" {
			out = append(out, p.Value)
		}
	}
	return out
}

// mergeCertificateSourceFormat folds an incoming component's
// ilm:component:certificate:source_format properties into the ones already
// stored under the same bom-ref, so the emitted values are decided by the SET of
// detections that resolve to that ref and never by the order they arrive in.
//
// Only the Builder can decide this. ilm.CertificateProperties writes whatever
// model.CertHit.Source it was handed -- PEM, DER, PKCS7-PEM, PKCS7-DER, PKCS12,
// JKS, JCEKS, ZIP/<subsource>, NMAP -- while a certificate's bom-ref is
// crypto/certificate/<name>@<digest of cert.Raw> (cdxprops.certComponent), a
// pure function of the certificate's own bytes carrying nothing about where or
// how it was found. That is deliberate: it is what lets one certificate found in
// three places dedupe to one asset. Converter.CertHit runs once per hit and the
// Converter is a value copied across the scanning goroutines, so no producer can
// see that another source found the same certificate; scanning fans out over
// goroutines (internal/parallel) onto one channel (cmd/cbom-lens/lens.go), so
// under first-wins the emitted source_format was whichever detection happened to
// finish first. Putting the source into the hash instead was rejected: that
// gives one asset N refs, the defect #217 exists to remove.
//
// Unlike mergeRelatedCryptoMaterialFormat, this keeps EVERY distinct value
// rather than tie-breaking, and never warns. format describes the OBJECT, so two
// encodings of one key mean a producer is wrong; source_format describes
// PROVENANCE, and a certificate really can sit in a .pem and inside a .p12 and
// be served on 443 at the same time. Both claims are true, so discarding one
// would lose a fact, and a warning would fire on the ordinary deployment rather
// than on a defect. Repeated property names are explicitly legal in both
// schemas: "Duplicate names are allowed, each potentially having a different
// value", and neither puts uniqueItems on the properties array. The values are
// sorted ascending and deduped by exact, case-sensitive, byte-wise comparison of
// the property VALUE; the scanners emit fixed literals, and normalising them
// would rewrite a producer's claim, which would be a second defect.
//
// It reads the incoming component's PROPERTY rather than detection.Source
// because that field is the SCANNER's label and not the producer's fact (see
// appendDetection's drop warning). Reading the property is also what keeps the
// whole merge a no-op when --ilm is off, so vanilla CycloneDX output stays
// byte-identical without giving the Builder an ilm flag it does not have.
//
// That used to hold for a simpler reason than the one that holds now:
// certComponent assigned Properties only under --ilm, so a vanilla certificate
// had none to read and the nil check in certificateSourceFormats ended it. The
// assumption died with #217, which moved the certificate's keyUsage off the RSA
// algorithm asset and onto an UNGATED key_usage property -- the committed
// non-ILM golden carries one at corpus-1.6.json:524-529. What is load-bearing
// now is that certificateSourceFormats selects by the ILM property NAME: a
// key_usage property is invisible to it, incomingValues comes back empty, and
// this function returns before touching anything. A second ungated property is
// free for the same reason, and a merge that unioned properties generically
// would not be -- which is the other half of why this one is scoped to a single
// name.
//
// The merge is scoped to this ONE property name. A generic property-set union
// would look tidier and would also re-sort base64_content and fingerprint --
// which cannot disagree anyway: base64_content is base64(cert.Raw) and
// fingerprint is sha256(cert.Raw) while the ref is name@sha256(cert.Raw), so two
// components under one ref carry the same cert.Raw modulo a SHA-256 collision.
// source_format is the only ILM certificate property that can differ, and
// everything else stays first-wins.
//
// A detection that adds nothing to the set is a no-op, but the test for that is
// slices.Equal against the stored values IN DOCUMENT ORDER, which is stricter
// than set equality on purpose. A stored run that is already the sorted union
// survives untouched; one that is out of order or repeats a value is rebuilt and
// comes out ascending and deduped. Comparing merely lengths would let [PEM, PEM]
// swallow an arriving DER -- the two are both two entries long -- and dropping an
// observed source is the defect this exists to prevent. Comparing sets would keep
// every source but leave a disordered or repeating stored run un-normalised, so
// the emitted order would again depend on which detection arrived first. Only the
// source_format run is ever rewritten; the surrounding properties keep their
// values and their relative order either way.
//
// When stored carries no source_format at all the run is appended only to a
// certificate asset, mirroring mergeRelatedCryptoMaterialFormat's gate:
// stamping a certificate's provenance onto an algorithm or key material is #213
// one field over, and a component with no cryptoProperties has no asset type to
// vouch for it. Like that sibling's, the gate sits in the arm that would INVENT
// the field and not at the top of the function, so a component that somehow
// already carried the property would have a value folded into its existing run
// without a type check. Nothing reaches that: cdxprops.certComponent is the only
// writer of this name and always sets assetType=certificate. The gate guards
// creation, which is what #213 actually was.
//
// The rebuilt list is assigned as a NEW pointer and is never appended through
// the existing one. cloneOnStore deep-copies Evidence and CryptoProperties and
// stops there, so stored.Properties is the very pointer the caller's
// model.Detection holds; appending through it writes into the caller's
// detection whenever that slice has spare capacity, and does it silently.
// Allocating fresh means this merge -- unlike mergeRelatedCryptoMaterialFormat,
// which writes through shared nested pointers -- does not mutate the incoming
// Detection at all.
//
// This was argued from a capacity until #217: ilm.CertificateProperties hands
// out a slice of length 3 and capacity 20, and certComponent assigned that slice
// to Properties directly, so an in-place append had 17 free slots to scribble
// into. The provenance is stale -- certComponent now BUILDS Properties by
// appending, key_usage first and the ILM run after, so ilm's array is copied and
// never adopted -- but the conclusion is not, because it never rested on the
// capacity. The Builder does not own this array whatever its capacity turns out
// to be.
func mergeCertificateSourceFormat(ctx context.Context, stored, incoming *cdx.Component) {
	if stored == nil || incoming == nil {
		return
	}

	incomingValues := certificateSourceFormats(incoming)
	if len(incomingValues) == 0 {
		return
	}
	storedValues := certificateSourceFormats(stored)

	observed := make(map[string]struct{}, len(storedValues)+len(incomingValues))
	for _, v := range storedValues {
		observed[v] = struct{}{}
	}
	for _, v := range incomingValues {
		observed[v] = struct{}{}
	}
	merged := slices.Sorted(maps.Keys(observed))

	// The same certificate found in the same format twice -- one CA shipped in
	// two files under /etc/ssl/certs -- changes nothing but evidence.occurrences.
	// Compared as a SEQUENCE, not as a set: a stored run that is out of order or
	// repeats a value differs from the sorted union and is rebuilt, and a length
	// test in its place would let [PEM, PEM] swallow an arriving DER.
	if slices.Equal(merged, storedValues) {
		return
	}

	var props []cdx.Property
	if stored.Properties != nil {
		props = *stored.Properties
	}

	appendRun := func(dst []cdx.Property) []cdx.Property {
		for _, v := range merged {
			dst = append(dst, cdx.Property{Name: ilm.CertificateSourceFormat, Value: v})
		}
		return dst
	}

	// The whole run lands at the position of the FIRST source_format property and
	// any later one is dropped, so a producer that put other properties before
	// its provenance does not find them shuffled. The run itself is always
	// emitted ascending, replacing whatever order the stored one happened to be
	// in; it is the OTHER properties whose order is preserved.
	out := make([]cdx.Property, 0, len(props)+len(merged))
	var placed bool
	for _, p := range props {
		if p.Name != ilm.CertificateSourceFormat {
			out = append(out, p)
			continue
		}
		if placed {
			continue
		}
		out = appendRun(out)
		placed = true
	}
	if !placed {
		if stored.CryptoProperties == nil ||
			stored.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			return
		}
		out = appendRun(out)
	}

	stored.Properties = &out

	// Debug, never Warn: a certificate deployed in more than one place is normal
	// operations, not a producer defect, and a warning on the common path is a
	// warning nobody reads.
	if len(merged) > 1 {
		slog.DebugContext(ctx, "certificate observed in more than one source format",
			"ref", stored.BOMRef,
			"source_formats", strings.Join(merged, ","))
	}
}

func bomStatistics(counter *stats.Stats) []cdx.Property {
	stats := maps.Collect(counter.Stats())
	var props = make([]cdx.Property, 0, len(stats))
	for _, name := range slices.Sorted(maps.Keys(stats)) {
		props = append(props, cdx.Property{
			Name:  name,
			Value: stats[name],
		})
	}
	return props
}

type refs map[string]string

type safeRefs struct {
	refs refs
}

func (b Builder) safeRefs() safeRefs {
	var refs = make(map[string]string, len(b.components))
	for _, compop := range b.components {
		if compop == nil {
			continue
		}
		if _, ok := refs[compop.BOMRef]; !ok {
			refs[compop.BOMRef] = safeRef(compop.BOMRef)
		}
	}
	return safeRefs{refs: refs}
}

func (s safeRefs) component(_ context.Context, compo cdx.Component) cdx.Component {
	// safeRefs is built from the same components map this compo comes from,
	// so the lookup always hits.
	compo.BOMRef = s.refs[compo.BOMRef]

	replaceBOMReferences(s.refs, reflect.ValueOf(&compo))

	return compo
}

func safeRef(bomRef string) string {
	before, _, ok := strings.Cut(bomRef, "@")
	uid := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(bomRef))
	if !ok {
		return uid.String()
	}
	return before + "@" + uid.String()
}

// bomReferenceType is the Go type both replaceBOMReferences and the
// referential-integrity walker in refintegrity_test.go treat as a bom-ref, so
// they cannot disagree about the type. They are not otherwise symmetric: the
// walker also classifies name-shaped plain-string fields (ref, dependsOn,
// *Ref) as uses, and the rewriter never touches those -- they are populated
// after canonicalization or handled separately in model.
var bomReferenceType = reflect.TypeFor[cdx.BOMReference]()

// replaceBOMReferences rewrites every settable cdx.BOMReference reachable from
// v to its safe ref. A value with no entry in refs is left alone, so a
// dangling ref stays visibly dangling instead of being blanked into an
// invisible one.
//
// v must be a pointer or otherwise addressable: the walker rewrites in place,
// and a struct passed by value yields unsettable fields it skips silently.
//
// The type check sits outside the Kind switch because cdx.BOMReference is a
// string type. A BOMReference that is not directly a struct field — an
// element of a []cdx.BOMReference such as cryptoRefArray or
// cipherSuites[].algorithms, or a *cdx.BOMReference — arrives here as a bare
// reflect.String, and a check reachable only from the Struct branch never
// sees it (issue #205).
//
// Settability is the limit of in-place rewriting, and it turns on how the
// value is held rather than on the container: a map value or interface holding
// a BOMReference *directly* is unsettable and skipped, as is a struct held
// directly as a map value, but one held through a pointer or slice from the
// same place is settable and is rewritten. cyclonedx-go has no map, interface
// or array field at all today, so none of this is reachable. A release
// introducing one fails TestCycloneDXRefFieldInventory, which pins the ref
// field types; and any such ref the corpus populates is reported as a use by
// the walker in refintegrity_test.go, turning TestBOMReferentialIntegrity_1_6
// red rather than shipping a dangling ref.
//
// Refs are only rewritten, never chained: refs maps raw refs to safe refs and
// no safe ref is itself a raw key, so walking a slice shared by several
// components (nmap hands one cryptoRefArray to every protocol component on a
// port) is idempotent. TestBuilder_RepeatedEmitIsStable pins that.
func replaceBOMReferences(refs map[string]string, v reflect.Value) {
	if !v.IsValid() {
		return
	}

	if v.Type() == bomReferenceType {
		// Map values and non-pointer roots are unaddressable; SetString
		// would panic on them.
		if !v.CanSet() {
			return
		}
		if old := v.String(); old != "" {
			if safe, ok := refs[old]; ok {
				v.SetString(safe)
			}
		}
		return
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		replaceBOMReferences(refs, v.Elem())

	case reflect.Interface:
		if v.IsNil() {
			return
		}
		replaceBOMReferences(refs, v.Elem())

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if !field.CanSet() {
				continue
			}
			replaceBOMReferences(refs, field)
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			replaceBOMReferences(refs, v.Index(i))
		}

	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			replaceBOMReferences(refs, iter.Value())
		}
	}
}
