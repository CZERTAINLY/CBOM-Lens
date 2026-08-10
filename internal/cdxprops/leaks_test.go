package cdxprops_test

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	pemscan "github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestLeakToComponent(t *testing.T) {
	key, err := cdxtest.GenECPrivateKey(elliptic.P224())
	require.NoError(t, err)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	content := pem.EncodeToMemory(pemBlock)

	cksum := func(s string) string {
		hash := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	const jwtToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30`
	const apiKey = `AKIALALEMEL33243OLIA`
	const passwd = `nbusr123`

	var startLine = 42
	tests := []struct {
		scenario string
		given    model.Leaks
		then     *model.Detection
	}{
		{
			scenario: "private key should not be ignored",
			given: model.Leaks{
				Location: "privKey.pem",
				Findings: []model.Finding{
					{
						RuleID:    "private-key",
						StartLine: startLine,
						Secret:    string(content),
					},
				},
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "PRIVATE-KEY",
				Location: "/path/to/file",
			},
		},
		{
			scenario: "jwt token detection",
			given: model.Leaks{
				Location: "/path/to/file",
				Findings: []model.Finding{
					{
						RuleID:      "jwt-token",
						Description: "Found JWT token",
						StartLine:   42,
						Secret:      jwtToken,
					},
				},
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "TOKEN",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/token/" + cksum(jwtToken),
						Name:        "jwt-token",
						Description: "Found JWT token",
						Type:        cdx.ComponentTypeCryptographicAsset,
						CryptoProperties: &cdx.CryptoProperties{
							AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
							RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
								Type: cdx.RelatedCryptoMaterialTypeToken,
							},
						},
						Evidence: &cdx.Evidence{
							Occurrences: &[]cdx.EvidenceOccurrence{
								{
									Location: "/path/to/file",
									Line:     intPtr(42),
								},
							},
						},
					},
				},
			},
		},
		{
			scenario: "api key detection",
			given: model.Leaks{
				Location: "/path/to/file",
				Findings: []model.Finding{
					{
						RuleID:      "api-key",
						Description: "Found API key",
						StartLine:   10,
						Secret:      apiKey,
					},
				},
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "KEY",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/key/" + cksum(apiKey),
						Name:        "api-key",
						Description: "Found API key",
						Type:        cdx.ComponentTypeCryptographicAsset,
						CryptoProperties: &cdx.CryptoProperties{
							AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
							RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
								Type: cdx.RelatedCryptoMaterialTypeKey,
							},
						},
						Evidence: &cdx.Evidence{
							Occurrences: &[]cdx.EvidenceOccurrence{
								{
									Location: "/path/to/file",
									Line:     intPtr(10),
								},
							},
						},
					},
				},
			},
		},
		{
			scenario: "password detection",
			given: model.Leaks{
				Location: "/path/to/file",
				Findings: []model.Finding{
					{
						RuleID:      "password-leak",
						Description: "Found password",
						StartLine:   15,
						Secret:      passwd,
					},
				},
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "PASSWORD",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/password/" + cksum(passwd),
						Name:        "password-leak",
						Description: "Found password",
						Type:        cdx.ComponentTypeCryptographicAsset,
						CryptoProperties: &cdx.CryptoProperties{
							AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
							RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
								Type: cdx.RelatedCryptoMaterialTypePassword,
							},
						},
						Evidence: &cdx.Evidence{
							Occurrences: &[]cdx.EvidenceOccurrence{
								{
									Location: "/path/to/file",
									Line:     intPtr(15),
								},
							},
						},
					},
				},
			},
		},
		{
			scenario: "unknown type detection",
			given: model.Leaks{
				Location: "/path/to/file",
				Findings: []model.Finding{
					{
						RuleID:      "something-else",
						Description: "Unknown type",
						StartLine:   20,
					},
				},
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "UNKNOWN",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/unknown/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						Name:        "something-else",
						Description: "Unknown type",
						Type:        cdx.ComponentTypeCryptographicAsset,
						CryptoProperties: &cdx.CryptoProperties{
							AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
							RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
								Type: cdx.RelatedCryptoMaterialTypeUnknown,
							},
						},
						Evidence: &cdx.Evidence{
							Occurrences: &[]cdx.EvidenceOccurrence{
								{
									Location: "/path/to/file",
									Line:     intPtr(20),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {

			var c = cdxprops.NewConverter()
			detection := c.Leak(t.Context(), tt.given)
			if tt.then == nil {
				require.Nil(t, detection)
				return
			}
			if tt.then.Type == "PRIVATE-KEY" {
				require.Len(t, detection.Components, 1)
			} else {
				require.Equal(t, tt.then, detection)
			}
		})
	}
}

// TestLeak_PrivateKeyBundleDoesNotPanic covers the mainline "gitleaks found a
// private key" path, which no test reached before: the private-key row above
// leaves Finding.PEMBundle zero, so leakToComponents never delegates to
// PEMBundle there.
//
// In production the gitleaks scanner attaches a real bundle for that rule, and
// Converter.Leak then reads
// compos[0].CryptoProperties.RelatedCryptoMaterialProperties.Type. compos[0]
// from a PEM bundle is the key's ALGORITHM, which carries no material
// properties -- the blanket format=PEM loop was the only thing keeping that
// pointer non-nil (#213).
//
// So this test is green on the unfixed tree by construction: it pins the guard,
// not the bug. Restoring the unconditional dereference while keeping the
// asset-type-gated setPEMFormat panics here, which is the regression it exists
// to catch.
//
// It deliberately does not assert d.Type. That is "" on this path both before
// and after the fix, because compos[0] is an algorithm whose material Type is
// empty; Leak derives the detection type positionally from compos[0], which is
// wrong independently of #213. Asserting the current "" would bless it and
// asserting PRIVATE-KEY would fail, so the field is left to its own fix.
func TestLeak_PrivateKeyBundleDoesNotPanic(t *testing.T) {
	t.Parallel()

	// Both cases mirror internal/scanner/gitleaks: rule "private-key" plus the
	// bundle produced by the real PEM scanner over the same bytes.
	ecKey, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})

	mldsaPEM, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	tests := []struct {
		scenario string
		content  []byte
		location string
	}{
		{
			scenario: "classical EC private key",
			content:  ecPEM,
			location: "ec-private-key.pem",
		},
		{
			// A PQC key never parses into bundle.PrivateKeys: it lands in
			// ParseErrors and yields a single algorithm component, so compos[0]
			// is an algorithm with no material properties at all.
			scenario: "ML-DSA-65 private key",
			content:  mldsaPEM,
			location: cdxtest.MLDSA65PrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()

			bundle, err := pemscan.Scanner{}.Scan(t.Context(), tt.content, tt.location)
			require.NoError(t, err)

			leaks := model.Leaks{
				Location: tt.location,
				Findings: []model.Finding{
					{
						RuleID:    "private-key",
						StartLine: 1,
						Secret:    string(tt.content),
						PEMBundle: bundle,
					},
				},
			}

			var d *model.Detection
			require.NotPanics(t, func() {
				d = cdxprops.NewConverter().Leak(t.Context(), leaks)
			})
			require.NotNil(t, d)
			require.NotEmpty(t, d.Components)
		})
	}
}

// helper function to create int pointer
func intPtr(i int) *int {
	return &i
}
