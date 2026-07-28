package bom_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/bom"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

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
			then: "BOM validation failed:\nproperties: Property 'components' does not match the schema",
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
// without network access. Before the fix the $refs to those subschemas were
// resolved via HTTP at compile time and silently imposed no constraints when
// the fetch failed (fail-open).
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
		require.Contains(t, err.Error(), "components")
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
		require.Contains(t, err.Error(), "signature")
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
							URL:  "https://www.czertainly.com",
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
		require.Contains(t, err.Error(), "signature")
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
