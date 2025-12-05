package pem_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	czpem "github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

	"github.com/stretchr/testify/require"
)

func TestDetector(t *testing.T) {
	type given struct {
		data   []byte
		bundle model.PEMBundle
	}

	testCases := []struct {
		scenario string
		given    func(t *testing.T) given
		then     error
	}{
		{
			scenario: "single certificate",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Der,
				})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						Certificates: []model.CertHit{{Cert: cert.Cert, Source: "PEM", Location: "test.pem"}},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE", Order: 0, Bytes: cert.Der, Headers: map[string]string{}},
						},
						Location: "test.pem",
					},
				}
			},
			then: nil,
		},
		{
			scenario: "PKCS#8 private key (Ed25519)",
			given: func(t *testing.T) given {
				cb := cdxtest.CertBuilder{}.WithSignatureAlgorithm(x509.PureEd25519)
				cert, err := cb.Generate()
				require.NoError(t, err)

				pemBytes, err := cert.PrivKeyPEM()
				require.NoError(t, err)

				block, _ := pem.Decode(pemBytes)
				require.NotNil(t, block)

				return given{
					data: pemBytes,
					bundle: model.PEMBundle{
						PrivateKeys: []model.PrivateKeyInfo{
							{
								Key:    cert.Key,
								Source: "PKCS8-PEM",
							},
						},
						RawBlocks: []model.PEMBlock{
							{Type: "PRIVATE KEY", Order: 0, Bytes: block.Bytes, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "EC private key (ECDSAWithSHA256)",
			given: func(t *testing.T) given {
				cb := cdxtest.CertBuilder{}.WithSignatureAlgorithm(x509.ECDSAWithSHA256)
				cert, err := cb.Generate()
				require.NoError(t, err)

				pemBytes, err := cert.PrivKeyPEM()
				require.NoError(t, err)

				block, _ := pem.Decode(pemBytes)
				require.NotNil(t, block)

				return given{
					data: pemBytes,
					bundle: model.PEMBundle{
						PrivateKeys: []model.PrivateKeyInfo{
							{
								Key:    cert.Key,
								Source: "EC-PEM",
							}},
						RawBlocks: []model.PEMBlock{
							{Type: "EC PRIVATE KEY", Order: 0, Bytes: block.Bytes, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "OpenSSH private key",
			given: func(t *testing.T) given {
				key, pemBytes, err := cdxtest.GenOpenSSHPrivateKey()
				require.NoError(t, err)

				block, _ := pem.Decode(pemBytes)
				require.NotNil(t, block)

				return given{
					data: pemBytes,
					bundle: model.PEMBundle{
						PrivateKeys: []model.PrivateKeyInfo{{
							Key:    key,
							Source: "PEM",
						}},
						RawBlocks: []model.PEMBlock{
							{Type: "OPENSSH PRIVATE KEY", Order: 0, Bytes: block.Bytes, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "certificate request",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				csr, csrDER, err := cdxtest.GenCSR(cert.Key)
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						CertificateRequests: []*x509.CertificateRequest{csr},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE REQUEST", Order: 0, Bytes: csrDER, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "public key",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey())
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						PublicKeys: []crypto.PublicKey{cert.PublicKey()},
						RawBlocks: []model.PEMBlock{
							{Type: "PUBLIC KEY", Order: 0, Bytes: pubDER, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "CRL",
			given: func(t *testing.T) given {
				b := cdxtest.CertBuilder{}.
					WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
					WithIsCA(true)
				cert, err := b.Generate()
				require.NoError(t, err)

				crl, crlDER, err := cdxtest.GenCRL(cert.Cert, cert.Key.(crypto.Signer))
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						CRLs: []*x509.RevocationList{crl},
						RawBlocks: []model.PEMBlock{
							{Type: "X509 CRL", Order: 0, Bytes: crlDER, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "certificate chain (leaf, intermediate, root)",
			given: func(t *testing.T) given {
				leaf, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)
				intermediate, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)
				root, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				var buf bytes.Buffer
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Der}))
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Der}))
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Der}))

				return given{
					data: buf.Bytes(),
					bundle: model.PEMBundle{
						Certificates: []model.CertHit{
							{Cert: leaf.Cert, Source: "PEM", Location: "test.pem"},
							{Cert: intermediate.Cert, Source: "PEM", Location: "test.pem"},
							{Cert: root.Cert, Source: "PEM", Location: "test.pem"},
						},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE", Order: 0, Bytes: leaf.Der, Headers: map[string]string{}},
							{Type: "CERTIFICATE", Order: 1, Bytes: intermediate.Der, Headers: map[string]string{}},
							{Type: "CERTIFICATE", Order: 2, Bytes: root.Der, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "empty input",
			given: func(t *testing.T) given {
				return given{
					data:   []byte{},
					bundle: model.PEMBundle{},
				}
			},
			then: model.ErrNoMatch,
		},
		{
			scenario: "invalid PEM data",
			given: func(t *testing.T) given {
				return given{
					data:   []byte("not a PEM file"),
					bundle: model.PEMBundle{},
				}
			},
			then: model.ErrNoMatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			// Arrange
			given := tc.given(t)
			given.bundle.Location = "test.pem"

			// Act
			bundle, err := czpem.Scanner{}.Scan(t.Context(), given.data, "test.pem")

			// Assert
			if tc.then != nil {
				require.Error(t, err)
				require.Equal(t, tc.then.Error(), err.Error())
			} else {
				require.NoError(t, err)

				t.Logf("bundle.ParseErrors: %+v", bundle.ParseErrors)

				for idx, gotErr := range bundle.ParseErrors {
					expectedErr, ok := given.bundle.ParseErrors[idx]
					require.True(t, ok)
					require.NotNil(t, gotErr)
					require.NotNil(t, expectedErr)
					require.EqualError(t, gotErr, expectedErr.Error())
				}
				given.bundle.ParseErrors = nil
				bundle.ParseErrors = nil

				require.Equal(t, given.bundle, bundle)
			}
		})
	}
}
