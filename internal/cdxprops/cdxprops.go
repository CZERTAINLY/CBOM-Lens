package cdxprops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
)

type Converter struct {
	// ilm control if extra ilm properties will be included or not
	ilm bool
	// bomRefHasher controls which algorithm will be used
	// to generate non-algorithm BOMRef. Defaults to sha256
	bomRefHasher func([]byte) string
	// implementationPlatform, when non-empty, overrides the runtime.GOARCH
	// derived value. BOMRefHash covers implementationPlatform, so tests pin it
	// to keep refs architecture-independent.
	implementationPlatform cdx.ImplementationPlatform
}

func NewConverter() Converter {
	return Converter{
		ilm: false,
		bomRefHasher: func(b []byte) string {
			hash := sha256.Sum256(b)
			return "sha256:" + hex.EncodeToString(hash[:])
		},
	}
}

// WithIlmExtensions configures the mode in which ILM specific properties will be included in Components or not
// Default is no
func (c Converter) WithIlmExtensions(ilm bool) Converter {
	c.ilm = ilm
	return c
}

// WithImplementationPlatform overrides the runtime.GOARCH derived
// implementation platform. Component BOMRefs are content hashes covering this
// field, so pinning it makes refs reproducible across architectures.
func (c Converter) WithImplementationPlatform(platform cdx.ImplementationPlatform) Converter {
	c.implementationPlatform = platform
	return c
}

// Leak converts the finding to detection.
// Supports jwt, token, key, password, private-key and an unknown fallback;
// leakToComponents maps the rule to both the component and the detection type.
// Returns nil if given Leak should be ignored
// safe to be used by different go routines
func (c Converter) Leak(ctx context.Context, leaks model.Leaks) *model.Detection {
	var compos = make([]cdx.Component, 0, len(leaks.Findings))
	var deps = make([]cdx.Dependency, 0, len(leaks.Findings))
	// The detection carries one type for a whole file of findings, so it takes
	// the type of the first finding that actually contributed a component --
	// which is the value this produced before, when the type was read back off
	// compos[0]. leakToComponents derives it from the rule, so a private-key
	// finding no longer changes its label depending on whether a PEM bundle
	// came with it.
	var typ model.DetectionType
	for _, finding := range leaks.Findings {
		leakType, leakCompos, leakDeps := c.leakToComponents(ctx, leaks.Location, finding)
		if typ == "" && len(leakCompos) > 0 {
			typ = leakType
		}
		compos = append(compos, leakCompos...)
		deps = append(deps, leakDeps...)
	}

	if len(compos) == 0 {
		return nil
	}
	if len(deps) == 0 {
		deps = nil
	}

	return &model.Detection{
		Source:       "LEAKS",
		Type:         typ,
		Location:     leaks.Location,
		Components:   compos,
		Dependencies: deps,
	}
}

func (c Converter) CertHit(ctx context.Context, hit model.CertHit) *model.Detection {
	if hit.Cert == nil {
		return nil
	}

	compos, deps, err := c.certHitToComponents(ctx, hit)
	if err != nil {
		slog.ErrorContext(ctx, "can't parse certificate", "error", err)
		return nil
	}
	if compos == nil {
		return nil
	}

	return &model.Detection{
		Source:       hit.Source,
		Type:         model.DetectionTypeCertificate,
		Location:     hit.Location,
		Components:   compos,
		Dependencies: deps,
	}
}

// Nmap converts nmap port scanning results into detections with CycloneDX components, dependencies and services.
//
// The function attempts to resolve the system hostname for the location field, instead of using 127.0.0.1 (localhost).
// This will change in future when nmap scans multiple hosts.
//
// Returns nil if an error is encountered during processing.
// For empty nmap port scanning results, empty slice (not nil) is returned.
func (c Converter) Nmap(ctx context.Context, nmap model.Nmap) []model.Detection {

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "N/A"
	}

	detections := make([]model.Detection, len(nmap.Ports))
	for i, port := range nmap.Ports {
		compos, deps, services, err := c.parseNmap(ctx, port)

		if err != nil {
			slog.WarnContext(ctx, "failed to parse nmap", "error", err)
			return nil
		}

		detections[i] = model.Detection{
			Source:       "NMAP",
			Type:         model.DetectionTypePort,
			Location:     port.Protocol + "://" + hostname + ":" + strconv.Itoa(port.PortNumber),
			Components:   compos,
			Dependencies: deps,
			Services:     services,
		}
	}

	return detections
}

func (c Converter) PEMBundle(ctx context.Context, bundle model.PEMBundle) *model.Detection {
	var compos []cdx.Component
	var deps []cdx.Dependency

	for _, cert := range bundle.Certificates {
		d := c.CertHit(ctx, cert)
		if d == nil {
			continue
		}
		compos = append(compos, d.Components...)
		deps = append(deps, d.Dependencies...)
	}

	for _, privKey := range bundle.PrivateKeys {
		pubKey, err := getPublicKey(privKey)
		if err != nil {
			slog.WarnContext(ctx, "can't extract a publicKey from a privateKey: skipping", "error", err, "bundle.location", bundle.Location)
			continue
		}
		pubKeyAlgo, pubKeyCompo := c.publicKeyComponents(
			ctx,
			getPublicKeyAlgorithm(pubKey),
			pubKey,
			nil,
		)
		// publicKeyComponents yields nothing for a key it cannot identify, and
		// the private key's own ref is derived from the public key's digest. An
		// empty pubKeyID would give every such private key the ref
		// crypto/private_key/<alg>@ with no digest, and since Builder keys
		// components by bom-ref, distinct private keys would collapse into one
		// — the same defect fixed for public keys, one field over.
		//
		// No key type reaches this state today: a DSA private key fails to parse
		// and post-quantum private keys land in ParseErrors, so neither enters
		// bundle.PrivateKeys. Guarded because the pem.go crash was also
		// unreachable until a change elsewhere made it reachable.
		_, pubKeyID, _ := strings.Cut(pubKeyCompo.BOMRef, "@")
		if pubKeyID == "" {
			slog.WarnContext(ctx, "skipping private key: its public key could not be identified",
				"bundle.location", bundle.Location)
			continue
		}
		privKeyAlgo, privKeyCompo := c.PrivateKey(ctx, pubKeyID, privKey)

		compos = append(compos, pubKeyAlgo, pubKeyCompo, privKeyAlgo, privKeyCompo)
	}

	bundleCompos, bundleDeps, err := c.restOfPEMBundleToCDX(ctx, bundle)
	if err != nil {
		// This log is the error's only destination: PEMBundle has no error
		// return and the caller gets a Detection either way. It used to name
		// neither the file nor the block, so a host whose keys all sit under
		// OIDs the registry does not carry lost every one of them from the CBOM
		// and the operator got an anonymous multi-line blob per file.
		// restOfPEMBundleToCDX now tags each joined error with its block index
		// and PEM type.
		//
		// The location is NOT added here. service.scan already installs it on
		// the context with log.ContextAttrs, so a "location" attribute at this
		// call site emitted the key twice in every record -- last-wins in most
		// parsers, a validation error in some pipelines. Pinned by
		// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock.
		//
		// Giving PEMBundle an error return is the real fix and is out of
		// scope, so this stays a Warn.
		slog.WarnContext(ctx, "analyzing bundle returned an error", "error", err)
	}
	compos = append(compos, bundleCompos...)
	// Merged the same way the certificate loop above merges CertHit's edges: a
	// dependency the converter built but the Detection does not carry never
	// reaches the Builder, so the component pair would be emitted with nothing
	// between them.
	deps = append(deps, bundleDeps...)

	for i := range compos {
		setPEMFormat(&compos[i])
	}

	return &model.Detection{
		Source: "PEM",
		// A PEM bundle is not a port. DetectionTypePort here was a copy-paste
		// from the nmap converter, and it left DetectionTypePEM -- which exists
		// for exactly this -- assigned nowhere.
		Type:         model.DetectionTypePEM,
		Location:     bundle.Location,
		Components:   compos,
		Dependencies: deps,
	}
}

func (c Converter) ImplementationPlatform() cdx.ImplementationPlatform {
	if c.implementationPlatform != "" {
		return c.implementationPlatform
	}
	switch runtime.GOARCH {
	case "amd64":
		return cdx.ImplementationPlatformX86_64
	case "386":
		return cdx.ImplementationPlatformX86_32
	case "arm64":
		return cdx.ImplementationPlatformARMv8A
	case "ppc64":
		return cdx.ImplementationPlatformPPC64
	case "ppc64le":
		return cdx.ImplementationPlatformPPC64LE
	case "s390x":
		return cdx.ImplementationPlatformS390x
	default:
		return cdx.ImplementationPlatformUnknown
	}
}

// BOMRefHash generates a unique BOM reference for components that lack inherent
// identification (e.g., crypto/algorithm, crypto/hash). The reference is computed
// by hashing the JSON representation of the component itself (with BOMRef cleared)
// and formatting it as "name@hash". This ensures deterministic, collision-resistant
// identifiers for components defined solely by their properties.
func (c Converter) BOMRefHash(compo *cdx.Component, name string) {
	if compo == nil {
		return
	}
	compo.BOMRef = ""
	compo.Evidence = nil
	b, _ := json.Marshal(compo)
	h := c.bomRefHasher(b)
	compo.BOMRef = name + "@" + h
}

func setAlgorithmPrimitive(compo *cdx.Component, primitive cdx.CryptoPrimitive) {
	if compo == nil {
		return
	}
	if compo.CryptoProperties == nil {
		compo.CryptoProperties = &cdx.CryptoProperties{}
	}
	if compo.CryptoProperties.AlgorithmProperties == nil {
		compo.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
	}
	compo.CryptoProperties.AlgorithmProperties.Primitive = primitive
}

// setPEMFormat records the bundle's serialisation on a component, but only on
// key material. relatedCryptoMaterialProperties describes a serialised object:
// an algorithm is not serialised and has no encoding, and a certificate's
// encoding belongs in certificateProperties.certificateFormat. Stamping it onto
// everything the bundle produced made 20 of 32 assets in a real scan answer
// "yes" to "is this key material?" (#213).
//
// The gate is the asset type, not "did the producer already build the struct":
// gating on the struct's existence would encode which producer happened to
// build it, so a future related-crypto-material producer that leaves it nil
// would silently lose its format.
//
// CryptoProperties is deliberately NOT created. publicKeyComponents returns a
// zero Component for a key it cannot identify, and inventing an assetType-less
// cryptoProperties on it is worse than leaving it for Builder.appendDetection
// to drop. This stays central rather than moving into the producers: the
// assignment lived in restOfPEMBundleToCDX once and dereferenced exactly that
// nil, taking the whole scan down (see pem.go).
func setPEMFormat(compo *cdx.Component) {
	if compo == nil || compo.CryptoProperties == nil {
		return
	}
	if compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeRelatedCryptoMaterial {
		return
	}
	if compo.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		compo.CryptoProperties.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{}
	}
	compo.CryptoProperties.RelatedCryptoMaterialProperties.Format = "PEM"
}

func addAlgorithmCrpyoFunctions(compo *cdx.Component, functions ...cdx.CryptoFunction) {
	if compo == nil {
		return
	}
	if compo.CryptoProperties == nil {
		compo.CryptoProperties = &cdx.CryptoProperties{}
	}
	if compo.CryptoProperties.AlgorithmProperties == nil {
		compo.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
	}

	set := make(map[cdx.CryptoFunction]struct{})
	for _, f := range *compo.CryptoProperties.AlgorithmProperties.CryptoFunctions {
		set[f] = struct{}{}
	}
	for _, f := range functions {
		set[f] = struct{}{}
	}
	funcs := slices.Collect(maps.Keys(set))
	slices.SortFunc(funcs, func(a, b cdx.CryptoFunction) int {
		return strings.Compare(string(a), string(b))
	})
	var p *[]cdx.CryptoFunction
	if len(funcs) != 0 {
		p = &funcs
	}
	compo.CryptoProperties.AlgorithmProperties.CryptoFunctions = p
}
