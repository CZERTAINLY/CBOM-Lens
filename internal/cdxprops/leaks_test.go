package cdxprops_test

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/report"
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
				Findings: []report.Finding{
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
				Findings: []report.Finding{
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
				Findings: []report.Finding{
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
				Findings: []report.Finding{
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
				Findings: []report.Finding{
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

// helper function to create int pointer
func intPtr(i int) *int {
	return &i
}
