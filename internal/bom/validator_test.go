package bom_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/bom"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestValidator_Validate_Errors(t *testing.T) {
	// given
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	tests := []struct {
		scenario string
		given    func(*cdx.BOM)
		then     string
	}{
		{
			scenario: "when components is empty",
			given: func(bom *cdx.BOM) {
				var empty []cdx.Component
				bom.Components = &empty
			},
			then: "BOM validation failed:\n/: properties: Property 'components' does not match the schema\n/components: type: Value is null but should be array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			// when bom
			b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			bom := b.BOM(t.Context())
			tt.given(&bom)

			// and when []byte
			var buf bytes.Buffer
			enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
			require.NoError(t, enc.Encode(&bom))

			errBOM := validator.Validate(&bom)
			errBytes := validator.ValidateBytes(buf.Bytes())

			if errBOM == nil {
				t.Logf("%s", buf.String())
			}

			// then
			require.Error(t, errBOM)
			require.Contains(t, errBOM.Error(), tt.then)
			require.Error(t, errBytes)
			require.Contains(t, errBytes.Error(), tt.then)
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	// given
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	tests := []struct {
		scenario string
		given    func(*testing.T) *bom.Builder
	}{
		{
			scenario: "empty builder",
			given: func(t *testing.T) *bom.Builder {
				t.Helper()
				b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
				require.NoError(t, err)
				return b
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			// when
			bom := tt.given(t).BOM(t.Context())
			var buf bytes.Buffer
			enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
			require.NoError(t, enc.Encode(&bom))

			errBOM := validator.Validate(&bom)
			errBytes := validator.ValidateBytes(buf.Bytes())

			if errBOM != nil {
				t.Logf("%s", buf.String())
			}
			// then
			require.NoError(t, errBOM)
			require.NoError(t, errBytes)
		})
	}
}

// TestValidator_OfflineStrictness proves the validator enforces constraints
// coming from the spdx.schema.json and jsf-0.82.schema.json subschemas even
// without network access.
func TestValidator_OfflineStrictness(t *testing.T) {
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	t.Run("bogus SPDX license id is rejected", func(t *testing.T) {
		b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		bom := b.BOM(t.Context())
		bom.Components = &[]cdx.Component{
			{
				Type: cdx.ComponentTypeLibrary,
				Name: "bogus-license-component",
				Licenses: &cdx.Licenses{
					{License: &cdx.License{ID: "TOTALLY-BOGUS-LICENSE-9.9"}},
				},
			},
		}

		err = validator.Validate(&bom)
		require.Error(t, err)
		// The failure chain must name the license id — not just any
		// components violation — so this test keeps covering the SPDX
		// subschema constraint it is named for.
		require.Contains(t, err.Error(), "Property 'licenses' does not match")
		require.Contains(t, err.Error(), "Property 'id' does not match")
	})

	t.Run("valid SPDX license id is accepted", func(t *testing.T) {
		b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		bom := b.BOM(t.Context())
		bom.Components = &[]cdx.Component{
			{
				Type: cdx.ComponentTypeLibrary,
				Name: "mit-licensed-component",
				Licenses: &cdx.Licenses{
					{License: &cdx.License{ID: "MIT"}},
				},
			},
		}

		require.NoError(t, validator.Validate(&bom))
	})

	t.Run("garbage signature is rejected", func(t *testing.T) {
		raw := bomBytesWithSignature(t, map[string]any{"garbage": true})

		err := validator.ValidateBytes(raw)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Property 'signature' does not match")
	})
}

// TestValidator_RepresentativeEmittedBOM validates a BOM assembled the same
// way production code does (builder + detections) and shaped like real
// scanner output: cryptographic assets with RFC3339 validity timestamps,
// evidence occurrence locations (including Windows paths), external
// references and dependencies. It guards against schema "format" assertions
// over-tightening validation of legitimately emitted BOMs.
func TestValidator_RepresentativeEmittedBOM(t *testing.T) {
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	builder, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	deps := []string{"crypto/algorithm/rsa-2048@1.2.840.113549.1.1.11"}
	builder.AppendDetections(t.Context(),
		model.Detection{
			Location: `C:\Program Files\test\server.crt`,
			Components: []cdx.Component{
				{
					BOMRef: "crypto/certificate/cn=test@sha256:aabbcc",
					Name:   "CN=Test",
					Type:   cdx.ComponentTypeCryptographicAsset,
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeCertificate,
						CertificateProperties: &cdx.CertificateProperties{
							SubjectName:           "CN=Test",
							IssuerName:            "CN=Test CA",
							NotValidBefore:        "2024-01-01T00:00:00Z",
							NotValidAfter:         "2034-01-01T00:00:00Z",
							SignatureAlgorithmRef: "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.11",
							CertificateFormat:     "X.509",
							CertificateExtension:  "crt",
						},
					},
					ExternalReferences: &[]cdx.ExternalReference{
						{
							Type: cdx.ERTypeWebsite,
							URL:  "https://www.omnitrust.com",
						},
					},
				},
				{
					BOMRef: "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.11",
					Name:   "RSA-2048",
					Type:   cdx.ComponentTypeCryptographicAsset,
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeAlgorithm,
						OID:       "1.2.840.113549.1.1.11",
					},
				},
			},
			Dependencies: []cdx.Dependency{
				{
					Ref:          "crypto/certificate/cn=test@sha256:aabbcc",
					Dependencies: &deps,
				},
			},
		},
		model.Detection{
			Location: "/etc/ssl/certs/server.crt",
			Components: []cdx.Component{
				{
					BOMRef: "crypto/certificate/cn=test@sha256:aabbcc",
					Name:   "CN=Test",
					Type:   cdx.ComponentTypeCryptographicAsset,
				},
			},
		},
	)

	bomDoc := builder.BOM(t.Context())

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	require.NoError(t, enc.Encode(&bomDoc))

	errBOM := validator.Validate(&bomDoc)
	errBytes := validator.ValidateBytes(buf.Bytes())
	if errBOM != nil || errBytes != nil {
		t.Logf("%s", buf.String())
	}
	require.NoError(t, errBOM)
	require.NoError(t, errBytes)
}

// bomBytesWithSignature encodes a minimal valid BOM and injects the given
// value as the root-level "signature" property.
func bomBytesWithSignature(t *testing.T, signature map[string]any) []byte {
	t.Helper()

	b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	bom := b.BOM(t.Context())

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	require.NoError(t, enc.Encode(&bom))

	var doc map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	doc["signature"] = signature
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

// TestValidator_JSFSignature exercises the jsf-0.82 signer.algorithm oneOf:
// [enum of standard algorithms, {type: string, format: "uri"}]. Without
// format assertion the uri branch matches any string, which inverts the
// check: standard algorithms match both branches (oneOf violation) while
// garbage matches exactly one.
func TestValidator_JSFSignature(t *testing.T) {
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	t.Run("well-formed ES256 signature is accepted", func(t *testing.T) {
		raw := bomBytesWithSignature(t, map[string]any{
			"algorithm": "ES256",
			"value":     "dGVzdA",
		})
		require.NoError(t, validator.ValidateBytes(raw))
	})

	t.Run("proprietary URI algorithm is accepted", func(t *testing.T) {
		raw := bomBytesWithSignature(t, map[string]any{
			"algorithm": "https://example.com/custom-algorithm",
			"value":     "dGVzdA",
		})
		require.NoError(t, validator.ValidateBytes(raw))
	})

	t.Run("unrecognized algorithm is rejected", func(t *testing.T) {
		raw := bomBytesWithSignature(t, map[string]any{
			"algorithm": "not-a-real-algorithm",
			"value":     "dGVzdA",
		})
		err := validator.ValidateBytes(raw)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Property 'signature' does not match")
	})
}

// TestValidator_DeepNesting locks the recursion-tracking fix that arrived
// with the kaptinlin/jsonschema v0.9.3 bump (fixed in v0.9.2): v0.7.5 broke
// recursive $ref cycles with a depth heuristic that turned validation
// fail-open, silently ACCEPTING invalid content nested at component depth
// >= 5. Both directions are asserted so the check can neither regress to
// fail-open nor over-tighten into rejecting valid deep nesting.
func TestValidator_DeepNesting(t *testing.T) {
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	// deeplyNested wraps leaf into a components-in-components chain so that
	// leaf sits at the given nesting depth (level 1 = direct child of the
	// BOM's components array).
	deeplyNested := func(depth int, leaf cdx.Component) cdx.Component {
		comp := leaf
		for level := depth - 1; level >= 1; level-- {
			comp = cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       fmt.Sprintf("nested-level-%d", level),
				Components: &[]cdx.Component{comp},
			}
		}
		return comp
	}

	validate := func(t *testing.T, leaf cdx.Component) (error, error) {
		t.Helper()
		b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		doc := b.BOM(t.Context())
		doc.Components = &[]cdx.Component{deeplyNested(8, leaf)}

		var buf bytes.Buffer
		enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		require.NoError(t, enc.Encode(&doc))

		return validator.Validate(&doc), validator.ValidateBytes(buf.Bytes())
	}

	t.Run("invalid type enum at depth 8 is rejected", func(t *testing.T) {
		errBOM, errBytes := validate(t, cdx.Component{
			Type: "not-a-component-type",
			Name: "deep-invalid-leaf",
		})

		// The error format flattens the evaluation tree, deduplicates
		// identical lines, and the underlying library resets instance
		// pointers at every $ref hop — so no accumulated
		// /components/0/.../type pointer exists to match. Depth is proven
		// by the value instead: the bogus type exists only on the depth-8
		// leaf, so an enum violation naming it can only come from
		// descending all eight levels (v0.7.5 bailed out fail-open and
		// produced no error at all). Assertions pin structural fragments —
		// JSON pointer, keyword, offending value — not translated
		// message text.
		for _, err := range []error{errBOM, errBytes} {
			require.Error(t, err)
			require.Regexp(t, `(?m)^/components: items: `, err.Error())
			require.Regexp(t, `(?m)^/0: \$ref: `, err.Error())
			require.Regexp(t, `(?m)^/type: enum: Value not-a-component-type`, err.Error())
		}
	})

	t.Run("fully valid nesting at depth 8 is accepted", func(t *testing.T) {
		errBOM, errBytes := validate(t, cdx.Component{
			Type: cdx.ComponentTypeLibrary,
			Name: "deep-valid-leaf",
		})

		require.NoError(t, errBOM)
		require.NoError(t, errBytes)
	})
}

func TestValidator_NoVersions(t *testing.T) {
	_, err := bom.NewValidator()
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one")
}

func TestValidator_UnsupportedVersion(t *testing.T) {
	_, err := bom.NewValidator(cdx.SpecVersion1_0)
	require.Error(t, err)
	require.EqualError(t, err, "unknown schema version: 1.0")

	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)
	b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	bom := b.BOM(t.Context())

	bom.SpecVersion = cdx.SpecVersion1_5

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	require.NoError(t, enc.Encode(&bom))

	errBOM := validator.Validate(&bom)
	errBytes := validator.ValidateBytes(buf.Bytes())

	require.Error(t, errBOM)
	require.EqualError(t, errBOM, "unsupported BOM specification version: supported 1.6: got: 1.5")
	require.Error(t, errBytes)
	require.EqualError(t, errBytes, "unsupported BOM specification version: supported 1.6: got: 1.5")

}

func TestValidator_17(t *testing.T) {
	v, err := bom.NewValidator(cdx.SpecVersion1_7)
	require.NoError(t, err)

	minimal := func(algProps string) []byte {
		return []byte(`{
			"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
			"components": [{
				"type": "cryptographic-asset", "name": "x", "bom-ref": "x@1",
				"cryptoProperties": {
					"assetType": "algorithm",
					"algorithmProperties": {` + algProps + `}
				}
			}]
		}`)
	}

	t.Run("valid ellipticCurve accepted", func(t *testing.T) {
		require.NoError(t, v.ValidateBytes(minimal(`"ellipticCurve": "secg/secp256r1"`)))
	})
	t.Run("bare curve name rejected (closed enum)", func(t *testing.T) {
		require.Error(t, v.ValidateBytes(minimal(`"ellipticCurve": "secp256r1"`)))
	})
	t.Run("bogus algorithmFamily rejected", func(t *testing.T) {
		require.Error(t, v.ValidateBytes(minimal(`"algorithmFamily": "HQC"`)))
	})
}

// TestValidator_AcceptsUpstreamConformanceFixtures is a positive control on the
// vendored schema set, using the specification's own examples of valid 1.7
// cryptography documents.
//
// Every other validator test feeds it either a document CBOM-Lens produced or a
// hand-written invalid one. Neither can detect a schema snapshot that is subtly
// wrong, or a $ref registered under a URI that never resolves so a subschema is
// silently skipped: a validator that accepts everything passes those tests too.
// Feeding it something external, known-good and not of our making is what makes
// "the enum is genuinely enforced" a tested claim rather than an assumption.
func TestValidator_AcceptsUpstreamConformanceFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "spec-conformance")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	v, err := bom.NewValidator(cdx.SpecVersion1_7)
	require.NoError(t, err)

	var checked int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			require.NoError(t, err)
			require.NoError(t, v.ValidateBytes(raw),
				"upstream conformance fixture must validate against the vendored 1.7 schema set")
		})
		checked++
	}
	// Guards against the fixtures being moved or renamed away, which would
	// otherwise make this test vacuously green.
	require.NotZero(t, checked, "no conformance fixtures found in %s", dir)
}
