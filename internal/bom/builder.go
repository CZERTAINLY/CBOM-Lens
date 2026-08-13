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
	counter      *stats.Stats
	clock        func() time.Time
	serial       func() string
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
		_, ok := b.dependencies[dep.Ref]
		if ok {
			slog.DebugContext(ctx, "ignoring dependency: already stored", "ref", dep.Ref)
			continue
		}
		b.dependencies[dep.Ref] = dep.Dependencies
	}

	for _, compo := range detection.Components {
		if compo.BOMRef == "" || compo.Name == "" {
			continue
		}
		stored, ok := b.components[compo.BOMRef]
		if ok {
			addEvidenceLocation(stored, detection.Location)
			continue
		}
		addEvidenceLocation(&compo, detection.Location)
		b.components[compo.BOMRef] = &compo
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

	// Extract crypto rels before the assets loop: sr.component below mutates
	// shared nested pointers in place, so this reads the raw reference fields.
	wire := make(map[string]struct{}, len(sr.refs))
	for _, w := range sr.refs {
		wire[w] = struct{}{}
	}
	for _, compop := range b.components {
		rels = append(rels, cryptoRels(ctx, sr.refs, wire, compop)...)
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
// values (model() mutates shared nested pointers in place on its first run —
// pre-existing quirk). Unresolvable targets are dropped with a warning,
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
// Settability is the limit of in-place rewriting: a BOMReference held as a
// map value, or inside an interface, cannot be set and is skipped. No such
// field exists in cyclonedx-go, and one appearing in a future release would
// fail loudly rather than ship dangling refs — the referential-integrity
// walker in refintegrity_test.go reports map- and interface-held refs as
// uses, so TestBOMReferentialIntegrity_1_6 turns red.
//
// Refs are only rewritten, never chained: refs maps raw refs to safe refs and
// no safe ref is itself a raw key, so walking a slice shared by several
// components (nmap hands one cryptoRefArray to every protocol component on a
// port) is idempotent. TestBuilder_RepeatedEmitIsStable pins that.
func replaceBOMReferences(refs map[string]string, v reflect.Value) {
	if !v.IsValid() {
		return
	}

	if v.Type() == reflect.TypeFor[cdx.BOMReference]() {
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
