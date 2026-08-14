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
				Type:     model.DetectionTypeLeakPrivateKey,
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
			if tt.then.Type == model.DetectionTypeLeakPrivateKey {
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
// PEMBundle there. In production the gitleaks scanner attaches a real bundle
// for that rule.
//
// It no longer pins a nil-guard. Converter.Leak used to read
// compos[0].CryptoProperties.RelatedCryptoMaterialProperties.Type, and compos[0]
// from a PEM bundle is the key's ALGORITHM, which carries no material
// properties once the blanket format=PEM loop is gone (#213). That positional
// read has been deleted -- the detection type comes from the rule -- so there
// is no dereference left to protect.
//
// What survives is the end-to-end shape of the path: a real bundle, classical
// and post-quantum, still yields components. TestLeak_DetectionTypeIsRuleDerived
// asserts the type these findings report.
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
			// ParseErrors and is recovered by analyzeParseError, which yields
			// the key material and its algorithm. Before that recovery emitted
			// key material, this bundle produced an algorithm and nothing else.
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

// TestLeak_DetectionTypeIsRuleDerived pins Detection.Type to the gitleaks rule
// rather than to whatever component happened to land first.
//
// The three private-key rows are the point: the same rule, once bare, once with
// an RSA PEM bundle and once with an ML-DSA one, must all report PRIVATE-KEY.
// Reading the type off compos[0] gave "PRIVATE-KEY" only for the bare finding
// -- an RSA bundle leads with the key's algorithm and a PQC bundle has nothing
// but an algorithm, so both reported "". The remaining rows pin the values the
// other rules have always produced, including jwt reporting TOKEN.
func TestLeak_DetectionTypeIsRuleDerived(t *testing.T) {
	t.Parallel()

	rsaKey, err := cdxtest.GenRSAPrivateKey(2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})

	mldsaPEM, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	scan := func(t *testing.T, content []byte, location string) model.PEMBundle {
		t.Helper()
		bundle, err := pemscan.Scanner{}.Scan(t.Context(), content, location)
		require.NoError(t, err)
		return bundle
	}

	tests := []struct {
		scenario string
		findings func(t *testing.T) []model.Finding
		want     model.DetectionType
	}{
		{
			scenario: "private-key rule without a PEM bundle",
			findings: func(*testing.T) []model.Finding {
				return []model.Finding{{RuleID: "private-key", StartLine: 1, Secret: string(rsaPEM)}}
			},
			want: model.DetectionTypeLeakPrivateKey,
		},
		{
			scenario: "private-key rule with an RSA PEM bundle",
			findings: func(t *testing.T) []model.Finding {
				return []model.Finding{{
					RuleID:    "private-key",
					StartLine: 1,
					Secret:    string(rsaPEM),
					PEMBundle: scan(t, rsaPEM, "rsa-private-key.pem"),
				}}
			},
			want: model.DetectionTypeLeakPrivateKey,
		},
		{
			scenario: "private-key rule with an ML-DSA PEM bundle",
			findings: func(t *testing.T) []model.Finding {
				return []model.Finding{{
					RuleID:    "private-key",
					StartLine: 1,
					Secret:    string(mldsaPEM),
					PEMBundle: scan(t, mldsaPEM, cdxtest.MLDSA65PrivateKey),
				}}
			},
			want: model.DetectionTypeLeakPrivateKey,
		},
		{
			scenario: "jwt rule reports TOKEN",
			findings: func(*testing.T) []model.Finding {
				return []model.Finding{{RuleID: "jwt-token", StartLine: 1, Secret: "header.payload.sig"}}
			},
			want: model.DetectionTypeLeakTOKEN,
		},
		{
			scenario: "password rule",
			findings: func(*testing.T) []model.Finding {
				return []model.Finding{{RuleID: "password-leak", StartLine: 1, Secret: "hunter2"}}
			},
			want: model.DetectionTypeLeakPASSWORD,
		},
		{
			scenario: "unrecognised rule",
			findings: func(*testing.T) []model.Finding {
				return []model.Finding{{RuleID: "something-else", StartLine: 1, Secret: "x"}}
			},
			want: model.DetectionTypeUNKNOWN,
		},
		{
			// One detection carries one type for a whole file, so the first
			// finding that contributes a component wins. Pinned so a later
			// refactor cannot silently switch to last-wins.
			scenario: "two findings: the first one wins",
			findings: func(*testing.T) []model.Finding {
				return []model.Finding{
					{RuleID: "jwt-token", StartLine: 1, Secret: "header.payload.sig"},
					{RuleID: "password-leak", StartLine: 2, Secret: "hunter2"},
				}
			},
			want: model.DetectionTypeLeakTOKEN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()

			d := cdxprops.NewConverter().Leak(t.Context(), model.Leaks{
				Location: "/path/to/file",
				Findings: tt.findings(t),
			})
			require.NotNil(t, d)
			require.NotEmpty(t, d.Components)
			require.Equal(t, tt.want, d.Type)
		})
	}
}

// TestPEMBundle_DetectionTypeIsPEM pins the PEM converter's own detection type.
// It reported PORT, copy-pasted from the nmap converter, while DetectionTypePEM
// sat unused.
func TestPEMBundle_DetectionTypeIsPEM(t *testing.T) {
	t.Parallel()

	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	certPEM, err := cert.CertPEM()
	require.NoError(t, err)

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), certPEM, "cert.pem")
	require.NoError(t, err)

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)
	require.Equal(t, model.DetectionTypePEM, d.Type)
}

// TestLeak_CarriesTheRelationshipsPEMBundleBuilt pins the leak path's Rels to
// the PEM path's, because the leak path reaches them only by delegation.
//
// Converter.Leak's private-key branch hands the finding's bundle to
// Converter.PEMBundle and returns what comes back. It used to return the
// Components and the Dependencies and drop the Rels, which is the one carrier
// with no 1.6 reference field behind it: Builder.cryptoRels recovers
// algorithmRef and its siblings by reading them back off the components, but a
// certificate request's edge to the key it asks to have certified is stated in
// Rels and nowhere else, so dropping it lost the edge outright rather than
// degrading it. A file holding a private key beside a request reaches this path
// whenever gitleaks reports the key, and the parallel PEM detection that would
// have carried the same edge is not guaranteed -- a library caller can invoke
// Converter.Leak on its own.
//
// Asserting equality against PEMBundle's own output rather than against a
// literal is what keeps this true as csrToCDX grows edges: the delegation
// either forwards them or this fails.
func TestLeak_CarriesTheRelationshipsPEMBundleBuilt(t *testing.T) {
	t.Parallel()

	key, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	_, csrDER, err := cdxtest.GenCSR(key)
	require.NoError(t, err)

	content := append(
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})...,
	)
	const location = "key-and-request.pem"

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), content, location)
	require.NoError(t, err)
	require.Len(t, bundle.CertificateRequests, 1, "the fixture must reach csrToCDX")

	c := cdxprops.NewConverter()

	// Taken from the path that builds the edge, so the two cannot agree by both
	// producing nothing.
	want := c.PEMBundle(t.Context(), bundle)
	require.NotEmpty(t, want.Rels, "the request must contribute a relationship")

	got := c.Leak(t.Context(), model.Leaks{
		Location: location,
		Findings: []model.Finding{{
			RuleID:    "private-key",
			StartLine: 1,
			Secret:    string(content),
			PEMBundle: bundle,
		}},
	})
	require.NotNil(t, got)
	require.Equal(t, want.Rels, got.Rels)
}

// helper function to create int pointer
func intPtr(i int) *int {
	return &i
}
