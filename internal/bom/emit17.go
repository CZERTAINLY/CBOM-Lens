package bom

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/model/cbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// emit17 renders the BOMModel as CycloneDX 1.7 using crypto-registry
// semantics: crypto relationships come exclusively from BOMModel.Rels
// (canonical, resolvable by construction), deprecated 1.6 reference and
// rename fields are cleared, and the closed-enum fields are populated via
// the total mapping tables in cdx17map.go (omit on miss).
type emit17 struct{}

func (emit17) SpecVersion() cdx.SpecVersion { return cdx.SpecVersion1_7 }

// relatedCryptoType maps relationship kinds to the wire `type` vocabulary.
// The 1.7 schema has no enum here (free string, examples publicKey/
// privateKey/algorithm) — the golden test asserts these values.
// RelProtocolCrypto is target-aware (see Emit): a protocol's cryptoRefArray
// historically points at CERTIFICATES, and labeling those "algorithm" would
// be semantically wrong even though schema-legal.
var relatedCryptoType = map[cbom.RelationshipKind]string{
	cbom.RelSignatureAlgorithm: "algorithm",
	cbom.RelSubjectPublicKey:   "publicKey",
	cbom.RelMaterialAlgorithm:  "algorithm",
	cbom.RelProtocolCrypto:     "algorithm", // overridden per target asset type
}

func (emit17) Emit(ctx context.Context, m cbom.BOMModel) cdx.BOM {
	assetRefs := make(map[string]struct{}, len(m.Assets))
	assetTypes := make(map[string]cdx.CryptoAssetType, len(m.Assets))
	for _, a := range m.Assets {
		assetRefs[string(a.Ref)] = struct{}{}
		if a.Component.CryptoProperties != nil {
			assetTypes[string(a.Ref)] = a.Component.CryptoProperties.AssetType
		}
	}

	// Group crypto relationships by From, preserving within-From order
	// (m.Rels ordering contract).
	related := make(map[string][]cdx.RelatedCryptographicAsset)
	for _, r := range m.Rels {
		typ, ok := relatedCryptoType[r.Kind]
		if !ok {
			continue // RelDependsOn renders via regroupDependsOn below
		}
		if r.Kind == cbom.RelProtocolCrypto && assetTypes[string(r.To)] == cdx.CryptoAssetTypeCertificate {
			typ = "certificate"
		}
		related[string(r.From)] = append(related[string(r.From)],
			cdx.RelatedCryptographicAsset{Type: typ, Ref: string(r.To)})
	}

	components := make([]cdx.Component, 0, len(m.Assets))
	for _, a := range m.Assets {
		c := cloneComponent(a.Component)
		c.BOMRef = string(a.Ref)
		mapComponent17(ctx, &c, related[string(a.Ref)], assetRefs)
		components = append(components, c)
	}

	dependencies := regroupDependsOn(m.Rels)

	var mp *[]cdx.Property
	if m.StatsProps != nil {
		mp = &m.StatsProps
	}

	return cdx.BOM{
		JSONSchema:   "https://cyclonedx.org/schema/bom-1.7.schema.json",
		BOMFormat:    cdx.BOMFormat,
		SpecVersion:  cdx.SpecVersion1_7,
		SerialNumber: m.SerialNumber,
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: m.Timestamp,
			Lifecycles: &[]cdx.Lifecycle{
				{Name: "", Phase: cdx.LifecyclePhaseOperations, Description: ""},
			},
			Component: &cdx.Component{
				Type:    cdx.ComponentTypeApplication,
				Name:    "CBOM-Lens",
				Version: programVersion,
				Manufacturer: &cdx.OrganizationalEntity{
					Name:    "CZERTAINLY",
					Address: &cdx.PostalAddress{},
					URL:     &[]string{"https://www.czertainly.com"},
				},
			},
			Properties: mp,
		},
		Components:   &components,
		Dependencies: &dependencies,
		Properties:   &[]cdx.Property{},
	}
}

// cloneComponent deep-copies a component via JSON round-trip. Asset.Component
// shares nested pointers with Builder state; emit17 mutates crypto
// properties, so it must own its copy.
func cloneComponent(c cdx.Component) cdx.Component {
	data, err := json.Marshal(c)
	if err != nil {
		// cdx.Component is a plain data struct; marshal cannot fail for
		// values the Builder stores. Keep the original on the impossible path.
		return c
	}
	var out cdx.Component
	if err := json.Unmarshal(data, &out); err != nil {
		return c
	}
	return out
}

// mapComponent17 applies the 1.6→1.7 field migration to one (cloned)
// component: clears the deprecated ref-shaped fields, attaches
// relatedCryptographicAssets derived from the IR relationships, maps
// closed-enum fields, and canonicalizes cipherSuites[].algorithms.
func mapComponent17(ctx context.Context, c *cdx.Component, rels []cdx.RelatedCryptographicAsset, assetRefs map[string]struct{}) {
	cp := c.CryptoProperties
	if cp == nil {
		return
	}

	if ap := cp.AlgorithmProperties; ap != nil {
		// v0.11.0 declares EllipticCurve and AlgorithmFamily as plain string.
		// Sources checked in trust order: SSH curve field, EC-key/TLS-group
		// parameterSetIdentifier, OID-definitive names (Ed25519). The
		// fabricated hash-derived curve strings match none of these tables.
		if mapped, ok := curveField17[ap.Curve]; ok {
			ap.EllipticCurve = mapped
		} else if mapped, ok := paramSet17[ap.ParameterSetIdentifier]; ok {
			ap.EllipticCurve = mapped
		} else if mapped, ok := nameCurve17[c.Name]; ok {
			ap.EllipticCurve = mapped
		} else if ap.Curve != "" {
			slog.DebugContext(ctx, "no 1.7 ellipticCurve mapping; omitting", "curve", ap.Curve, "ref", c.BOMRef)
		}
		// `curve` is dual-emitted, NOT cleared. In 1.7 it is deprecated by
		// annotation only (JSON Schema draft-07 has no such keyword), it is
		// not mutually exclusive with ellipticCurve, and it is removed only
		// in 2.0. Since ellipticCurve is omitted wherever no trusted mapping
		// exists, and every downstream converter silently drops the new
		// field, clearing `curve` would destroy curve information outright
		// for exactly those assets. Dual-emit is the lossless migration
		// posture until 2.0.
		ap.AlgorithmFamily = algorithmFamily17(c.Name, ap.Primitive)
	}

	// rels attach to exactly one properties struct: certificate first, else
	// material, else protocol (assets carry one of the three in practice;
	// the guard prevents double-attachment on a hypothetical overlap).
	attached := false
	if certp := cp.CertificateProperties; certp != nil {
		// certificateExtension -> certificateFileExtension is a lossless
		// rename, so migrate and clear.
		certp.CertificateFileExtension = strings.TrimPrefix(certp.CertificateExtension, ".")
		certp.CertificateExtension = ""
		// The ref-shaped fields ARE cleared: relatedCryptographicAssets
		// supersedes them with structurally guaranteed ref integrity, and
		// re-emitting them would reintroduce the dangling-ref class emit17
		// exists to eliminate.
		certp.SignatureAlgorithmRef = ""
		certp.SubjectPublicKeyRef = ""
		if len(rels) > 0 {
			certp.RelatedCryptographicAssets = &rels
			attached = true
		}
	}

	if matp := cp.RelatedCryptoMaterialProperties; matp != nil {
		matp.AlgorithmRef = ""
		if len(rels) > 0 && !attached {
			matp.RelatedCryptographicAssets = &rels
			attached = true
		}
	}

	if pp := cp.ProtocolProperties; pp != nil {
		pp.CryptoRefArray = nil
		if len(rels) > 0 && !attached {
			pp.RelatedCryptographicAssets = &rels
		}
		if pp.CipherSuites != nil {
			for i := range *pp.CipherSuites {
				canonicalizeSuiteAlgorithms(ctx, &(*pp.CipherSuites)[i], assetRefs)
			}
		}
	}
}

// canonicalizeSuiteAlgorithms repairs cipherSuites[].algorithms entries: the
// production reflection rewriter misses []cdx.BOMReference elements (known
// 1.6 defect, frozen there for byte-compat), so raw pre-canonical refs reach
// the emitter. Keep entries that are already asset refs, canonicalize raw
// ones whose safeRef form resolves, drop the rest with a warning — 1.7
// output must have zero dangling refs.
func canonicalizeSuiteAlgorithms(ctx context.Context, suite *cdx.CipherSuite, assetRefs map[string]struct{}) {
	if suite.Algorithms == nil {
		return
	}
	out := make([]cdx.BOMReference, 0, len(*suite.Algorithms))
	for _, ref := range *suite.Algorithms {
		s := string(ref)
		if _, ok := assetRefs[s]; ok {
			out = append(out, ref)
			continue
		}
		canonical := safeRef(s)
		if _, ok := assetRefs[canonical]; ok {
			out = append(out, cdx.BOMReference(canonical))
			continue
		}
		slog.WarnContext(ctx, "dropping cipher-suite algorithm ref: no matching component", "ref", s)
	}
	if len(out) == 0 {
		suite.Algorithms = nil // omit rather than emit "algorithms": []
		return
	}
	suite.Algorithms = &out
}
