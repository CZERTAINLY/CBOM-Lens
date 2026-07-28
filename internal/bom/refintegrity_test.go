package bom

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file is a test-only referential-integrity net for emitted BOMs
// (issue #180): every ref-shaped use in a cdx.BOM must point at a bom-ref
// defined in the same document.

// refSite records a single ref-shaped use inside a cdx.BOM: the path of the
// field holding it, in json-name notation (e.g.
// "components[24].cryptoProperties.protocolProperties.cipherSuites[0].algorithms[1]"),
// and the referenced value.
type refSite struct {
	Path string
	Ref  string
}

// refFieldKind classifies how a struct field participates in bom-ref
// referential integrity.
type refFieldKind int

const (
	refFieldNone refFieldKind = iota
	refFieldDef               // defines a bom-ref other fields may point at
	refFieldUse               // points at a bom-ref defined elsewhere
)

var bomReferenceType = reflect.TypeFor[cdx.BOMReference]()

// classifyRefField decides whether a cyclonedx-go struct field defines a
// bom-ref, uses one, or is irrelevant to referential integrity. It is shared
// by the collectBOMRefs walker and the TestCycloneDXRefFieldInventory
// tripwire so both always agree on what counts as a ref.
//
//   - DEF: json base name "bom-ref" (any string-kind type, including
//     cdx.BOMReference — e.g. Assessor.BOMRef). Checked first so a
//     BOMReference-typed definition is never miscounted as a use.
//   - USE: type cdx.BOMReference (wherever it appears), or a string-kind
//     field whose json base name is "ref", "dependsOn", "provides",
//     "requirement", "parent", "requirements" (refLinkType fields of the
//     1.6 declarations/definitions trees), or has suffix "Ref"/"Refs".
//   - Unexported fields are skipped. json:"-" fields are NOT skipped:
//     choice wrappers (ToolsChoice, MLDatasetChoice, and in newer
//     cyclonedx-go versions the IKEv2 transform and evidence-identity
//     wrappers) hide wire-visible content behind json:"-" plus a custom
//     MarshalJSON, so the name falls back to the Go field name instead
//     (e.g. MLDatasetChoice.Ref -> "Ref" suffix -> use).
func classifyRefField(f reflect.StructField) refFieldKind {
	if !f.IsExported() {
		return refFieldNone
	}
	name := jsonBaseName(f)
	base := refBaseType(f.Type)
	if base.Kind() != reflect.String {
		return refFieldNone
	}
	if name == "bom-ref" {
		return refFieldDef
	}
	switch {
	case base == bomReferenceType,
		name == "ref", name == "dependsOn", name == "provides",
		name == "requirement", name == "parent", name == "requirements",
		strings.HasSuffix(name, "Ref"), strings.HasSuffix(name, "Refs"):
		return refFieldUse
	}
	return refFieldNone
}

// jsonBaseName returns the field's wire name: the json tag up to the first
// comma, falling back to the Go field name for untagged fields and for
// json:"-" fields (whose wire shape, if any, is decided by the enclosing
// type's custom MarshalJSON, not by the tag).
func jsonBaseName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "" || name == "-" {
		return f.Name
	}
	return name
}

// refBaseType strips pointers, slices, arrays, and map values down to the
// scalar type a ref field ultimately holds.
func refBaseType(t reflect.Type) reflect.Type {
	for {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			t = t.Elem()
		default:
			return t
		}
	}
}

// collectBOMRefs walks the in-memory bom and returns every bom-ref
// definition plus every ref-shaped use site. Empty refs and "urn:cdx:"
// BOM-links (which point outside the document by design) are skipped.
//
// The walk inspects the in-memory cdx.BOM rather than the wire JSON, so it
// must not trust json tags alone: json:"-" fields are walked too, because
// choice wrappers (ToolsChoice, MLDatasetChoice, ...) emit them through
// custom MarshalJSON. Paths through such fields use the Go field name.
func collectBOMRefs(bom *cdx.BOM) (map[string]struct{}, []refSite) {
	defs := make(map[string]struct{})
	var uses []refSite
	walkBOMRefs(reflect.ValueOf(bom), "", defs, &uses)
	return defs, uses
}

func walkBOMRefs(v reflect.Value, path string, defs map[string]struct{}, uses *[]refSite) {
	if !v.IsValid() {
		return
	}
	// Hoisted before the Kind switch: a cdx.BOMReference is a use wherever
	// it appears — scalar field, slice/array element, or map value. (Fields
	// classified refFieldDef never reach this point.)
	if v.Type() == bomReferenceType {
		recordRefUse(uses, path, v.String())
		return
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		walkBOMRefs(v.Elem(), path, defs, uses)

	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			fieldPath := joinRefPath(path, jsonBaseName(f))
			switch classifyRefField(f) {
			case refFieldDef:
				if def := refString(v.Field(i)); def != "" {
					defs[def] = struct{}{}
				}
			case refFieldUse:
				collectRefUses(v.Field(i), fieldPath, uses)
			default:
				walkBOMRefs(v.Field(i), fieldPath, defs, uses)
			}
		}

	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walkBOMRefs(v.Index(i), fmt.Sprintf("%s[%d]", path, i), defs, uses)
		}

	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			walkBOMRefs(iter.Value(), fmt.Sprintf("%s[%v]", path, iter.Key()), defs, uses)
		}
	}
}

// collectRefUses records every string-kind scalar reachable inside a field
// classified refFieldUse (scalar, slice/array elements, map values).
func collectRefUses(v reflect.Value, path string, uses *[]refSite) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		collectRefUses(v.Elem(), path, uses)
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			collectRefUses(v.Index(i), fmt.Sprintf("%s[%d]", path, i), uses)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			collectRefUses(iter.Value(), fmt.Sprintf("%s[%v]", path, iter.Key()), uses)
		}
	case reflect.String:
		recordRefUse(uses, path, v.String())
	}
}

func recordRefUse(uses *[]refSite, path, ref string) {
	if ref == "" || strings.HasPrefix(ref, "urn:cdx:") {
		return
	}
	*uses = append(*uses, refSite{Path: path, Ref: ref})
}

// refString unwraps pointers and returns the string value of a
// string-kind definition field, or "" when unset.
func refString(v reflect.Value) string {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.String {
		return v.String()
	}
	return ""
}

func joinRefPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// danglingBOMRefs returns every ref-shaped use in bom that does not resolve
// to a bom-ref defined in the same document.
func danglingBOMRefs(bom *cdx.BOM) []refSite {
	defs, uses := collectBOMRefs(bom)
	var dangling []refSite
	for _, use := range uses {
		if _, ok := defs[use.Ref]; !ok {
			dangling = append(dangling, use)
		}
	}
	return dangling
}

// assertRefIntegrity fails the test unless the dangling (ref, site) pairs in
// bom match allowlist exactly, in both directions. Occurrences are pinned,
// not just distinct values: a new dangling site that reuses an already
// allowlisted value still fails. Non-fatal by design — it reports every
// violation in both directions before failing (hence assert*, not the
// package-usual require*). A nil allowlist requires a fully resolving
// document.
func assertRefIntegrity(t *testing.T, bom *cdx.BOM, allowlist map[string][]string) {
	t.Helper()

	actual := make(map[string][]string)
	for _, site := range danglingBOMRefs(bom) {
		actual[site.Ref] = append(actual[site.Ref], site.Path)
	}
	// Sort per-ref paths so failure output is stable regardless of walk order
	// (map-held refs traverse in randomized order).
	for _, paths := range actual {
		slices.Sort(paths)
	}

	var unexpected strings.Builder
	for _, ref := range slices.Sorted(maps.Keys(actual)) {
		for _, path := range actual[ref] {
			if !slices.Contains(allowlist[ref], path) {
				fmt.Fprintf(&unexpected, "  %s\n    at %s\n", ref, path)
			}
		}
	}
	if unexpected.Len() > 0 {
		t.Errorf("BOM contains dangling ref sites not on the allowlist:\n%s"+
			"fix the rewriter/emitter, do not extend the allowlist", unexpected.String())
	}

	for _, ref := range slices.Sorted(maps.Keys(allowlist)) {
		for _, path := range allowlist[ref] {
			if !slices.Contains(actual[ref], path) {
				t.Errorf("allowlisted ref no longer dangles at %s: %s\nremove it from the allowlist", path, ref)
			}
		}
	}
}

// tlsProtoPath locates the TLS protocol component holding all dangling sites
// pinned by testdata/golden/corpus-1.6.json.
const tlsProtoPath = "components[24].cryptoProperties.protocolProperties"

// knownDanglingRefs16 pins every dangling occurrence (ref -> exact sites) in
// testdata/golden/corpus-1.6.json. Root cause: replaceBOMReferences in
// builder.go skips []cdx.BOMReference elements, so cipherSuites[*].algorithms
// and cryptoRefArray keep the original content-hash refs while the components
// they point at are rewritten to safe refs (issue #180). Whether 1.6 output
// should be canonicalized to fix them is a pending maintainer decision.
//
// Do NOT add entries here: a new dangling ref — or a new site reusing one of
// these values — means a rewriter/emitter bug.
var knownDanglingRefs16 = map[string][]string{
	"crypto/algorithm/SHA256@sha256:692805caccd5d10a24c5f2607f1b2f92365d45637bbffb19327571938ff523f1": {
		tlsProtoPath + ".cipherSuites[0].algorithms[1]",
		tlsProtoPath + ".cipherSuites[2].algorithms[1]",
	},
	"crypto/algorithm/SHA384@sha256:a8e74cac63b436f2f31be1f23f252e84d4f5549731e6a71907ecc9dbaa37335c": {
		tlsProtoPath + ".cipherSuites[1].algorithms[1]",
	},
	"crypto/algorithm/aes-128-gcm@sha256:eba74aba1360630b92c4fa07d5920b01dca555dae748eb1a4671b76f61763dee": {
		tlsProtoPath + ".cipherSuites[0].algorithms[0]",
	},
	"crypto/algorithm/aes-256-gcm@sha256:fae137f8ede9ab0261320d5b0beb9495a96cccdbb0a2c9927069a97a5c5c47a1": {
		tlsProtoPath + ".cipherSuites[1].algorithms[0]",
	},
	"crypto/algorithm/chacha20-poly1305@sha256:0412f91c044da1c8efc045a41876c2b7fe44c30aff1bd9023b0493c9f8d46181": {
		tlsProtoPath + ".cipherSuites[2].algorithms[0]",
	},
	"crypto/certificate/www.ssllabs.com@sha256:9c4ae7bf5170ee7598b8de289e1be7fe54c254d440c24a587958000c2e1a82bb": {
		tlsProtoPath + ".cryptoRefArray[0]",
	},
}

func TestBOMReferentialIntegrity_1_6(t *testing.T) {
	ctx := t.Context()
	bom := goldenBuilder(t).AppendDetections(ctx, fixtureDetections(t)...).BOM(ctx)
	assertRefIntegrity(t, &bom, knownDanglingRefs16)
}

// refFieldInventory walks the exported struct-type graph reachable from
// cdx.BOM and returns one sorted line per field classifyRefField considers a
// bom-ref definition ("def ...") or use ("use ...").
//
// Unlike the value walker, this type walker cannot descend into interface
// types (their dynamic content is unknown statically); the value walker's
// entry hoist still catches BOMReference values behind interfaces at runtime
// (see TestWalkBOMRefs_BOMReferenceHoist).
func refFieldInventory() []string {
	visited := make(map[reflect.Type]bool)
	var inventory []string

	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			walk(t.Elem())
			return
		case reflect.Struct:
		default:
			return
		}
		if visited[t] {
			return
		}
		visited[t] = true
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			switch classifyRefField(f) {
			case refFieldUse:
				inventory = append(inventory,
					fmt.Sprintf("use %s.%s json=%s %s", t.Name(), f.Name, jsonBaseName(f), f.Type))
			case refFieldDef:
				inventory = append(inventory,
					fmt.Sprintf("def %s.%s json=%s %s", t.Name(), f.Name, jsonBaseName(f), f.Type))
			default:
				walk(f.Type)
			}
		}
	}
	walk(reflect.TypeFor[cdx.BOM]())

	slices.Sort(inventory)
	return inventory
}

// TestCycloneDXRefFieldInventory pins classifyRefField's view of the
// vendored cyclonedx-go version — every field it recognizes as a bom-ref
// definition or use — so a dependency bump that adds, removes, or renames a
// ref-shaped field fails loudly here instead of silently escaping both
// collectBOMRefs and replaceBOMReferences. It is only as complete as the
// classifier: a genuinely new ref shape that matches no rule still needs a
// human eye on the cyclonedx-go diff.
func TestCycloneDXRefFieldInventory(t *testing.T) {
	expected := []string{
		"def Annotation.BOMRef json=bom-ref string",
		"def Assessor.BOMRef json=bom-ref cyclonedx.BOMReference",
		"def Claim.BOMRef json=bom-ref string",
		"def Component.BOMRef json=bom-ref string",
		"def ComponentData.BOMRef json=bom-ref string",
		"def Composition.BOMRef json=bom-ref string",
		"def DeclarationEvidence.BOMRef json=bom-ref string",
		"def EvidenceOccurrence.BOMRef json=bom-ref string",
		"def Formula.BOMRef json=bom-ref string",
		"def License.BOMRef json=bom-ref string",
		"def MLModelCard.BOMRef json=bom-ref string",
		"def MLModelEnergyProvider.BOMRef json=bom-ref string",
		"def OrganizationalContact.BOMRef json=bom-ref string",
		"def OrganizationalEntity.BOMRef json=bom-ref string",
		"def PostalAddress.BOMRef json=bom-ref string",
		"def Service.BOMRef json=bom-ref string",
		"def StandardDefinition.BOMRef json=bom-ref string",
		"def StandardLevel.BOMRef json=bom-ref string",
		"def StandardRequirement.BOMRef json=bom-ref string",
		"def Task.BOMRef json=bom-ref string",
		"def TaskTrigger.BOMRef json=bom-ref string",
		"def TaskWorkspace.BOMRef json=bom-ref string",
		"def Vulnerability.BOMRef json=bom-ref string",
		"def Workflow.BOMRef json=bom-ref string",
		"use Affects.Ref json=ref string",
		"use Annotation.Subjects json=subjects *[]cyclonedx.BOMReference",
		"use Attestation.Assessor json=assessor cyclonedx.BOMReference",
		"use AttestationConformance.MitigationStrategies json=mitigationStrategies *[]cyclonedx.BOMReference",
		"use AttestationMap.Claims json=claims *[]cyclonedx.BOMReference",
		"use AttestationMap.CounterClaims json=counterClaims *[]cyclonedx.BOMReference",
		"use AttestationMap.Requirement json=requirement string",
		"use CertificateProperties.SignatureAlgorithmRef json=signatureAlgorithmRef cyclonedx.BOMReference",
		"use CertificateProperties.SubjectPublicKeyRef json=subjectPublicKeyRef cyclonedx.BOMReference",
		"use CipherSuite.Algorithms json=algorithms *[]cyclonedx.BOMReference",
		"use Claim.CounterEvidence json=counterEvidence *[]cyclonedx.BOMReference",
		"use Claim.Evidence json=evidence *[]cyclonedx.BOMReference",
		"use Claim.MitigationStrategies json=mitigationStrategies *[]cyclonedx.BOMReference",
		"use Claim.Target json=target cyclonedx.BOMReference",
		"use Composition.Assemblies json=assemblies *[]cyclonedx.BOMReference",
		"use Composition.Dependencies json=dependencies *[]cyclonedx.BOMReference",
		"use Composition.Vulnerabilities json=vulnerabilities *[]cyclonedx.BOMReference",
		"use CryptoProtocolProperties.CryptoRefArray json=cryptoRefArray *[]cyclonedx.BOMReference",
		"use Dependency.Dependencies json=dependsOn *[]string",
		"use Dependency.Provides json=provides *[]string",
		"use Dependency.Ref json=ref string",
		"use EvidenceIdentity.Tools json=tools *[]cyclonedx.BOMReference",
		"use IKEv2TransformTypes.Auth json=auth *[]cyclonedx.BOMReference",
		"use IKEv2TransformTypes.Encr json=encr *[]cyclonedx.BOMReference",
		"use IKEv2TransformTypes.Integ json=integ *[]cyclonedx.BOMReference",
		"use IKEv2TransformTypes.KE json=ke *[]cyclonedx.BOMReference",
		"use IKEv2TransformTypes.PRF json=prf *[]cyclonedx.BOMReference",
		"use MLDatasetChoice.Ref json=Ref string",
		"use RelatedCryptoMaterialProperties.AlgorithmRef json=algorithmRef cyclonedx.BOMReference",
		"use ResourceReferenceChoice.Ref json=ref string",
		"use SecuredBy.AlgorithmRef json=algorithmRef cyclonedx.BOMReference",
		"use StandardLevel.Requirements json=requirements *[]string",
		"use StandardRequirement.Parent json=parent string",
	}

	actual := refFieldInventory()
	require.Equal(t, expected, actual,
		"the set of ref fields in cyclonedx-go changed. For every added or removed field:\n"+
			" 1. confirm collectBOMRefs handles it correctly: name-pattern and cdx.BOMReference-typed\n"+
			"    fields are classified automatically, but check the classification against what the\n"+
			"    wire actually carries — json:\"-\" fields in particular are emitted by custom\n"+
			"    MarshalJSON (a wrapper's BOMRef may BE the whole wire value). Extend\n"+
			"    classifyRefField for anything it misses or misreads.\n"+
			" 2. decide whether replaceBOMReferences in builder.go must rewrite it, and file (or\n"+
			"    reference) an issue if it does not.\n"+
			" 3. re-pin the expected inventory in this test.\n"+
			"actual inventory:\n%s", strings.Join(actual, "\n"))
}

func TestDanglingBOMRefs(t *testing.T) {
	tests := []struct {
		name string
		bom  cdx.BOM
		want []refSite
	}{
		{
			// THE bug class of issue #180: replaceBOMReferences recurses into
			// slices element-by-element, but its BOMReference check only fires
			// on struct fields, so elements of a []cdx.BOMReference are never
			// rewritten and dangle.
			name: "dangling []BOMReference element is caught",
			bom: cdx.BOM{
				Components: &[]cdx.Component{{
					BOMRef: "crypto/protocol/tls@1",
					CryptoProperties: &cdx.CryptoProperties{
						ProtocolProperties: &cdx.CryptoProtocolProperties{
							CipherSuites: &[]cdx.CipherSuite{{
								Algorithms: &[]cdx.BOMReference{"crypto/algorithm/missing@1"},
							}},
						},
					},
				}},
			},
			want: []refSite{{
				Path: "components[0].cryptoProperties.protocolProperties.cipherSuites[0].algorithms[0]",
				Ref:  "crypto/algorithm/missing@1",
			}},
		},
		{
			name: "dangling scalar BOMReference is caught",
			bom: cdx.BOM{
				Components: &[]cdx.Component{{
					BOMRef: "crypto/certificate/leaf@1",
					CryptoProperties: &cdx.CryptoProperties{
						CertificateProperties: &cdx.CertificateProperties{
							SignatureAlgorithmRef: "crypto/algorithm/missing@1",
						},
					},
				}},
			},
			want: []refSite{{
				Path: "components[0].cryptoProperties.certificateProperties.signatureAlgorithmRef",
				Ref:  "crypto/algorithm/missing@1",
			}},
		},
		{
			name: "dangling Dependency.Ref and dependsOn entries are caught",
			bom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{{
					Ref:          "missing-from",
					Dependencies: &[]string{"missing-to"},
				}},
			},
			want: []refSite{
				{Path: "dependencies[0].ref", Ref: "missing-from"},
				{Path: "dependencies[0].dependsOn[0]", Ref: "missing-to"},
			},
		},
		{
			// Choice wrappers mark fields json:"-" and emit them through
			// custom MarshalJSON (ToolsChoice, MLDatasetChoice, ...), so a
			// json:"-" field can be wire-visible: a component defined under
			// metadata.tools.components is a real definition and a ref to it
			// must resolve, not report as dangling.
			name: "component defined under a json dash choice wrapper resolves",
			bom: cdx.BOM{
				Metadata: &cdx.Metadata{
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{{BOMRef: "tool-component@1", Name: "scanner"}},
					},
				},
				Dependencies: &[]cdx.Dependency{{Ref: "tool-component@1"}},
			},
			want: nil,
		},
		{
			name: "resolving ref is not reported",
			bom: cdx.BOM{
				Components: &[]cdx.Component{
					{BOMRef: "crypto/algorithm/present@1"},
					{
						BOMRef: "crypto/protocol/tls@1",
						CryptoProperties: &cdx.CryptoProperties{
							ProtocolProperties: &cdx.CryptoProtocolProperties{
								CipherSuites: &[]cdx.CipherSuite{{
									Algorithms: &[]cdx.BOMReference{"crypto/algorithm/present@1"},
								}},
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "empty refs are skipped",
			bom: cdx.BOM{
				Components: &[]cdx.Component{{
					BOMRef: "crypto/certificate/leaf@1",
					CryptoProperties: &cdx.CryptoProperties{
						CertificateProperties: &cdx.CertificateProperties{
							SignatureAlgorithmRef: "",
						},
					},
				}},
			},
			want: nil,
		},
		{
			name: "urn:cdx: BOM-links are skipped",
			bom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{{
					Ref: "urn:cdx:11111111-1111-1111-1111-111111111111/1#component-1",
				}},
			},
			want: nil,
		},
		{
			name: "nil pointers are handled",
			bom:  cdx.BOM{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Site order is coupled to reflection traversal order, which is
			// not part of the contract; compare as sets.
			require.ElementsMatch(t, tt.want, danglingBOMRefs(&tt.bom))
		})
	}
}

func TestClassifyRefField(t *testing.T) {
	// Synthetic fields mirror shapes found in cyclonedx-go: hiddenRef is the
	// unexported case, DashBOMRef mirrors v0.11.0's IKEv2Auth.BOMRef
	// (json:"-" but emitted as the entire wire value by custom MarshalJSON).
	type synthetic struct {
		DashBOMRef cdx.BOMReference `json:"-"`
		hiddenRef  cdx.BOMReference
	}

	tests := []struct {
		name  string
		field reflect.StructField
		want  refFieldKind
	}{
		{
			name:  "unexported field is skipped",
			field: fieldByName(t, reflect.TypeFor[synthetic](), "hiddenRef"),
			want:  refFieldNone,
		},
		{
			name:  "json dash ref-shaped field is a use",
			field: fieldByName(t, reflect.TypeFor[synthetic](), "DashBOMRef"),
			want:  refFieldUse,
		},
		{
			// ToolsChoice.Components is json:"-" but struct-based, so it is
			// not itself a ref — the walker recurses into it instead.
			name:  "json dash struct-typed choice field is not classified",
			field: fieldByName(t, reflect.TypeFor[cdx.ToolsChoice](), "Components"),
			want:  refFieldNone,
		},
		{
			// Assessor.BOMRef is cdx.BOMReference-typed but json "bom-ref":
			// a definition, never a use.
			name:  "bom-ref named BOMReference-typed field is a definition",
			field: fieldByName(t, reflect.TypeFor[cdx.Assessor](), "BOMRef"),
			want:  refFieldDef,
		},
		// The three declarations/definitions fields below are refLinkType in
		// the CycloneDX 1.6 schema but match none of the generic name
		// patterns, so they are classified by exact name. Scanned against
		// v0.10.0 and v0.11.0: no other string-kind field shares these names
		// (StandardDefinition.Requirements shares "requirements" but is a
		// struct slice, excluded by the string-kind gate).
		{
			name:  "attestation map requirement is a use",
			field: fieldByName(t, reflect.TypeFor[cdx.AttestationMap](), "Requirement"),
			want:  refFieldUse,
		},
		{
			name:  "standard requirement parent is a use",
			field: fieldByName(t, reflect.TypeFor[cdx.StandardRequirement](), "Parent"),
			want:  refFieldUse,
		},
		{
			name:  "standard level requirements are uses",
			field: fieldByName(t, reflect.TypeFor[cdx.StandardLevel](), "Requirements"),
			want:  refFieldUse,
		},
		{
			name:  "struct-slice requirements field is not classified",
			field: fieldByName(t, reflect.TypeFor[cdx.StandardDefinition](), "Requirements"),
			want:  refFieldNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, classifyRefField(tt.field))
		})
	}

	// Reference the unexported field so it exists for the reflection probe
	// above without tripping the unused linter.
	_ = synthetic{hiddenRef: ""}.hiddenRef
}

// fieldByName fetches a struct field for classification tests, failing the
// test when the field disappears in a dependency bump.
func fieldByName(t *testing.T, st reflect.Type, name string) reflect.StructField {
	t.Helper()
	f, ok := st.FieldByName(name)
	require.True(t, ok, "field %s.%s not found", st.Name(), name)
	return f
}

// TestWalkBOMRefs_BOMReferenceHoist covers the walker's entry check that
// catches cdx.BOMReference values not reached through a classified struct
// field. No such shape exists in cyclonedx-go v0.10.0/v0.11.0 — the check is
// a backstop for future map- or interface-held refs — so a synthetic struct
// exercises it: a BOMReference inside map[string]any bypasses field
// classification (its base type is an interface, not string-kind) and is
// caught only at walk entry, after the interface unwrap.
func TestWalkBOMRefs_BOMReferenceHoist(t *testing.T) {
	type synthetic struct {
		Extra map[string]any `json:"extra,omitempty"`
	}

	defs := make(map[string]struct{})
	var uses []refSite
	walkBOMRefs(reflect.ValueOf(synthetic{
		Extra: map[string]any{"key": cdx.BOMReference("crypto/algorithm/missing@1")},
	}), "", defs, &uses)

	require.Empty(t, defs)
	require.Equal(t, []refSite{{Path: "extra[key]", Ref: "crypto/algorithm/missing@1"}}, uses)
}
