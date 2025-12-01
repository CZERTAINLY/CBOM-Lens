package cdxtest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"golang.org/x/crypto/ssh"
	"software.sslmate.com/src/go-pkcs12"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestGenSelfSignedCert(t *testing.T) {
	// Generate the self-signed certificate
	selfSigned, err := cdxtest.GenSelfSignedCert()

	// require no error occurred
	require.NoError(t, err)

	// Verify the certificate is not nil and contains expected values
	require.NotNil(t, selfSigned.Der)
	require.NotNil(t, selfSigned.Cert)
	require.NotNil(t, selfSigned.Key)

	// Verify certificate fields
	require.Equal(t, "Test Cert", selfSigned.Cert.Subject.CommonName)
	require.True(t, selfSigned.Cert.BasicConstraintsValid)

	// Verify key usage
	expectedKeyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	require.Equal(t, expectedKeyUsage, selfSigned.Cert.KeyUsage)

	// Verify ExtKeyUsage
	require.Contains(t, selfSigned.Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	certPEM, err := selfSigned.CertPEM()
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)

	privKeyPEM, err := selfSigned.PrivKeyPEM()
	require.NoError(t, err)
	require.NotEmpty(t, privKeyPEM)
}

func TestGetProp(t *testing.T) {
	tests := []struct {
		name     string
		comp     cdx.Component
		propName string
		want     string
	}{
		{
			name: "existing property",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: "test", Value: "value"},
					{Name: "other", Value: "othervalue"},
				},
			},
			propName: "test",
			want:     "value",
		},
		{
			name: "non-existing property",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: "test", Value: "value"},
				},
			},
			propName: "notfound",
			want:     "",
		},
		{
			name:     "nil properties",
			comp:     cdx.Component{},
			propName: "test",
			want:     "",
		},
		{
			name: "empty properties",
			comp: cdx.Component{
				Properties: &[]cdx.Property{},
			},
			propName: "test",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cdxtest.GetProp(tt.comp, tt.propName)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestHasEvidencePath(t *testing.T) {
	tests := []struct {
		name    string
		comp    cdx.Component
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil evidence",
			comp:    cdx.Component{},
			wantErr: true,
			errMsg:  "evidence is nil",
		},
		{
			name: "nil occurrences",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{},
			},
			wantErr: true,
			errMsg:  "evidence occurrences is nil",
		},
		{
			name: "empty occurrences",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{},
				},
			},
			wantErr: true,
			errMsg:  "evidence occurrences is empty",
		},
		{
			name: "empty location",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: ""},
					},
				},
			},
			wantErr: true,
			errMsg:  "location is empty",
		},
		{
			name: "wrong path",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: "/absolute/wrong/path"},
					},
				},
			},
			wantErr: true,
			errMsg:  "unexpected location: got /absolute/wrong/path, expected: testdata",
		},
		{
			name: "valid evidence path",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: "testdata"},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cdxtest.HasEvidencePath(tt.comp, "testdata")
			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHasFormatAndDERBase64(t *testing.T) {
	// Test constants
	const (
		formatKey  = "test.format"
		base64Key  = "test.content"
		certFormat = "DER"
	)

	// Generate a valid test certificate
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	validB64 := base64.StdEncoding.EncodeToString(cert.Der)

	tests := []struct {
		name    string
		comp    cdx.Component
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil properties",
			comp:    cdx.Component{},
			wantErr: true,
			errMsg:  "certificate format property is empty",
		},
		{
			name: "empty format",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: base64Key, Value: validB64},
				},
			},
			wantErr: true,
			errMsg:  "certificate format property is empty",
		},
		{
			name: "empty base64",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
				},
			},
			wantErr: true,
			errMsg:  "certificate base64 content property is empty",
		},
		{
			name: "invalid base64",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
					{Name: base64Key, Value: "invalid-base64"},
				},
			},
			wantErr: true,
			errMsg:  "failed to decode base64 content:",
		},
		{
			name: "invalid certificate",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
					{Name: base64Key, Value: "YWJjZGVm"}, // valid base64 but invalid cert
				},
			},
			wantErr: true,
			errMsg:  "failed to parse certificate:",
		},
		{
			name: "valid certificate",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
					{Name: base64Key, Value: validB64},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cdxtest.HasFormatAndDERBase64(tt.comp, formatKey, base64Key)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
func TestCertBuilder_WithKeyUsage(t *testing.T) {
	builder := cdxtest.CertBuilder{}.WithKeyUsage(x509.KeyUsageCertSign)
	cert, err := builder.Generate()
	require.NoError(t, err)
	require.Equal(t, x509.KeyUsageCertSign, cert.Cert.KeyUsage)
}

func TestCertBuilder_WithIsCA(t *testing.T) {
	t.Run("CA certificate", func(t *testing.T) {
		builder := cdxtest.CertBuilder{}.WithIsCA(true)
		cert, err := builder.Generate()
		require.NoError(t, err)
		require.True(t, cert.Cert.IsCA)
	})

	t.Run("non-CA certificate", func(t *testing.T) {
		builder := cdxtest.CertBuilder{}.WithIsCA(false)
		cert, err := builder.Generate()
		require.NoError(t, err)
		require.False(t, cert.Cert.IsCA)
	})
}

func TestCertBuilder_WithSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name            string
		algo            x509.SignatureAlgorithm
		expectedKeyType string
	}{
		{
			name:            "RSA SHA256",
			algo:            x509.SHA256WithRSA,
			expectedKeyType: "*rsa.PrivateKey",
		},
		{
			name:            "RSA SHA384",
			algo:            x509.SHA384WithRSA,
			expectedKeyType: "*rsa.PrivateKey",
		},
		{
			name:            "RSA SHA512",
			algo:            x509.SHA512WithRSA,
			expectedKeyType: "*rsa.PrivateKey",
		},
		{
			name:            "ECDSA SHA256",
			algo:            x509.ECDSAWithSHA256,
			expectedKeyType: "*ecdsa.PrivateKey",
		},
		{
			name:            "ECDSA SHA384",
			algo:            x509.ECDSAWithSHA384,
			expectedKeyType: "*ecdsa.PrivateKey",
		},
		{
			name:            "ECDSA SHA512",
			algo:            x509.ECDSAWithSHA512,
			expectedKeyType: "*ecdsa.PrivateKey",
		},
		{
			name:            "Ed25519",
			algo:            x509.PureEd25519,
			expectedKeyType: "ed25519.PrivateKey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := cdxtest.CertBuilder{}.WithSignatureAlgorithm(tt.algo)
			cert, err := builder.Generate()
			require.NoError(t, err)
			require.Equal(t, tt.algo, cert.Cert.SignatureAlgorithm)

			keyType := ""
			switch cert.Key.(type) {
			case *rsa.PrivateKey:
				keyType = "*rsa.PrivateKey"
			case *ecdsa.PrivateKey:
				keyType = "*ecdsa.PrivateKey"
			case ed25519.PrivateKey:
				keyType = "ed25519.PrivateKey"
			}
			require.Equal(t, tt.expectedKeyType, keyType)
		})
	}
}

func TestCertBuilder_ChainedMethods(t *testing.T) {
	cert, err := cdxtest.CertBuilder{}.
		WithKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).
		WithIsCA(true).
		WithSignatureAlgorithm(x509.ECDSAWithSHA256).
		Generate()

	require.NoError(t, err)
	require.True(t, cert.Cert.IsCA)
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, cert.Cert.KeyUsage)
	require.Equal(t, x509.ECDSAWithSHA256, cert.Cert.SignatureAlgorithm)
	_, ok := cert.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)
}

func TestSelfSignedCert_PublicKey(t *testing.T) {
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	pubKey := cert.PublicKey()
	require.NotNil(t, pubKey)

	// Verify public key matches the certificate
	require.Equal(t, cert.Cert.PublicKey, pubKey)
}

func TestSelfSignedCert_CertPEM(t *testing.T) {
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	pemBytes, err := cert.CertPEM()
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	// Verify PEM format
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Equal(t, cert.Der, block.Bytes)

	// Verify can be parsed back
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, cert.Cert.Subject.CommonName, parsedCert.Subject.CommonName)
}

func TestSelfSignedCert_PrivKeyMarshal(t *testing.T) {
	tests := []struct {
		name string
		algo x509.SignatureAlgorithm
	}{
		{"RSA", x509.SHA256WithRSA},
		{"ECDSA", x509.ECDSAWithSHA256},
		{"Ed25519", x509.PureEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cdxtest.CertBuilder{}.WithSignatureAlgorithm(tt.algo).Generate()
			require.NoError(t, err)

			keyBytes, err := cert.PrivKeyMarshal()
			require.NoError(t, err)
			require.NotEmpty(t, keyBytes)

			// Verify can be parsed back
			switch tt.algo {
			case x509.SHA256WithRSA:
				key, err := x509.ParsePKCS1PrivateKey(keyBytes)
				require.NoError(t, err)
				require.NotNil(t, key)
			case x509.ECDSAWithSHA256:
				key, err := x509.ParseECPrivateKey(keyBytes)
				require.NoError(t, err)
				require.NotNil(t, key)
			case x509.PureEd25519:
				key, err := x509.ParsePKCS8PrivateKey(keyBytes)
				require.NoError(t, err)
				require.NotNil(t, key)
			}
		})
	}
}

func TestSelfSignedCert_PrivKeyPEM(t *testing.T) {
	tests := []struct {
		name         string
		algo         x509.SignatureAlgorithm
		expectedType string
	}{
		{"RSA", x509.SHA256WithRSA, "RSA PRIVATE KEY"},
		{"ECDSA", x509.ECDSAWithSHA256, "EC PRIVATE KEY"},
		{"Ed25519", x509.PureEd25519, "PRIVATE KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cdxtest.CertBuilder{}.WithSignatureAlgorithm(tt.algo).Generate()
			require.NoError(t, err)

			pemBytes, err := cert.PrivKeyPEM()
			require.NoError(t, err)
			require.NotEmpty(t, pemBytes)

			// Verify PEM format
			block, _ := pem.Decode(pemBytes)
			require.NotNil(t, block)
			require.Equal(t, tt.expectedType, block.Type)
			require.NotEmpty(t, block.Bytes)

			// Verify contains PEM markers
			pemStr := string(pemBytes)
			require.Contains(t, pemStr, "-----BEGIN")
			require.Contains(t, pemStr, "-----END")
		})
	}
}

func TestSelfSignedCert_PKCS12(t *testing.T) {
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	p12, err := cert.PKCS12()
	require.NoError(t, err)
	require.NotEmpty(t, p12)

	// Verify can be decoded
	key, parsedCert, _, err := pkcs12.DecodeChain(p12, cdxtest.Password)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.NotNil(t, parsedCert)
	require.Equal(t, cert.Cert.Subject.CommonName, parsedCert.Subject.CommonName)
}

func TestSelfSignedCert_PKCS12_WithDifferentKeyTypes(t *testing.T) {
	tests := []struct {
		name string
		algo x509.SignatureAlgorithm
	}{
		{"RSA", x509.SHA256WithRSA},
		{"ECDSA", x509.ECDSAWithSHA256},
		// Note: Ed25519 may not be supported by all PKCS12 implementations
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cdxtest.CertBuilder{}.WithSignatureAlgorithm(tt.algo).Generate()
			require.NoError(t, err)

			p12, err := cert.PKCS12()
			require.NoError(t, err)
			require.NotEmpty(t, p12)

			// Verify can be decoded
			_, parsedCert, _, err := pkcs12.DecodeChain(p12, cdxtest.Password)
			require.NoError(t, err)
			require.NotNil(t, parsedCert)
		})
	}
}

func TestGenECPrivateKey(t *testing.T) {
	key, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)
	require.NotNil(t, key)

	// Verify it's a P256 key
	require.Equal(t, elliptic.P256(), key.Curve)
}

func TestGenEd25519PrivateKey(t *testing.T) {
	pubKey, privKey, err := cdxtest.GenEd25519Keys()
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// Verify key lengths
	require.Equal(t, ed25519.PublicKeySize, len(pubKey))
	require.Equal(t, ed25519.PrivateKeySize, len(privKey))

	// Verify public key can be derived from private key
	derivedPubKey := privKey.Public().(ed25519.PublicKey)
	require.Equal(t, pubKey, derivedPubKey)
}

func TestGenCSR(t *testing.T) {
	tests := []struct {
		name   string
		keyGen func() (crypto.PrivateKey, error)
	}{
		{
			name: "RSA",
			keyGen: func() (crypto.PrivateKey, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
		},
		{
			name: "ECDSA",
			keyGen: func() (crypto.PrivateKey, error) {
				return cdxtest.GenECPrivateKey(elliptic.P224())
			},
		},
		{
			name: "Ed25519",
			keyGen: func() (crypto.PrivateKey, error) {
				_, priv, err := cdxtest.GenEd25519Keys()
				return priv, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyGen()
			require.NoError(t, err)

			csr, der, err := cdxtest.GenCSR(key)
			require.NoError(t, err)
			require.NotNil(t, csr)
			require.NotEmpty(t, der)

			// Verify CSR properties
			require.Equal(t, "Test CSR", csr.Subject.CommonName)
			require.Equal(t, []string{"Test Org"}, csr.Subject.Organization)

			// Verify signature
			err = csr.CheckSignature()
			require.NoError(t, err)

			// Verify can be parsed back
			parsedCSR, err := x509.ParseCertificateRequest(der)
			require.NoError(t, err)
			require.Equal(t, csr.Subject.CommonName, parsedCSR.Subject.CommonName)
		})
	}
}

func TestGenCRL(t *testing.T) {
	cert, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)

	signer, ok := cert.Key.(crypto.Signer)
	require.True(t, ok, "private key must be a crypto.Signer")

	crl, der, err := cdxtest.GenCRL(cert.Cert, signer)
	require.NoError(t, err)
	require.NotNil(t, crl)
	require.NotEmpty(t, der)

	// Verify CRL properties
	require.Equal(t, int64(1), crl.Number.Int64())
	require.Len(t, crl.RevokedCertificateEntries, 1)
	require.Equal(t, int64(42), crl.RevokedCertificateEntries[0].SerialNumber.Int64())

	// Verify can be parsed back
	parsedCRL, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	require.Equal(t, crl.Number, parsedCRL.Number)
}

func TestGenCRL_WithDifferentKeyTypes(t *testing.T) {
	tests := []struct {
		name string
		algo x509.SignatureAlgorithm
	}{
		{"RSA", x509.SHA256WithRSA},
		{"ECDSA", x509.ECDSAWithSHA256},
		{"Ed25519", x509.PureEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cdxtest.CertBuilder{}.
				WithSignatureAlgorithm(tt.algo).
				WithIsCA(true).
				WithKeyUsage(x509.KeyUsageCRLSign).
				Generate()
			require.NoError(t, err)

			signer, ok := cert.Key.(crypto.Signer)
			require.True(t, ok)

			crl, der, err := cdxtest.GenCRL(cert.Cert, signer)
			require.NoError(t, err)
			require.NotNil(t, crl)
			require.NotEmpty(t, der)
		})
	}
}

func TestGenOpenSSHPrivateKey(t *testing.T) {
	priv, pemBytes, err := cdxtest.GenOpenSSHPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotEmpty(t, pemBytes)

	// Verify it's Ed25519
	require.Equal(t, ed25519.PrivateKeySize, len(priv))

	// Verify PEM format
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "OPENSSH PRIVATE KEY", block.Type)

	// Verify can be parsed back
	parsedKey, err := ssh.ParseRawPrivateKey(pemBytes)
	require.NoError(t, err)
	require.NotNil(t, parsedKey)

	// Verify it's the same key
	parsedEd25519, ok := parsedKey.(*ed25519.PrivateKey)
	require.True(t, ok)
	require.Equal(t, priv, *parsedEd25519)
}

func TestGenOpenSSHPrivateKey_Format(t *testing.T) {
	_, pemBytes, err := cdxtest.GenOpenSSHPrivateKey()
	require.NoError(t, err)

	pemStr := string(pemBytes)
	require.True(t, strings.HasPrefix(pemStr, "-----BEGIN OPENSSH PRIVATE KEY-----"))
	require.True(t, strings.HasSuffix(strings.TrimSpace(pemStr), "-----END OPENSSH PRIVATE KEY-----"))
}

func TestPassword_Constant(t *testing.T) {
	// Verify the password constant is set correctly
	require.Equal(t, "changeit", cdxtest.Password)
}

func TestCertBuilder_DefaultValues(t *testing.T) {
	t.Run("default generates RSA certificate", func(t *testing.T) {
		builder := cdxtest.CertBuilder{}
		cert, err := builder.Generate()
		require.NoError(t, err)

		_, ok := cert.Key.(*rsa.PrivateKey)
		require.True(t, ok)
		require.Equal(t, x509.SHA256WithRSA, cert.Cert.SignatureAlgorithm)
	})

	t.Run("default key usage", func(t *testing.T) {
		builder := cdxtest.CertBuilder{}
		cert, err := builder.Generate()
		require.NoError(t, err)

		expectedUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		require.Equal(t, expectedUsage, cert.Cert.KeyUsage)
	})

	t.Run("default is not CA", func(t *testing.T) {
		builder := cdxtest.CertBuilder{}
		cert, err := builder.Generate()
		require.NoError(t, err)

		require.False(t, cert.Cert.IsCA)
	})
}

func TestSelfSignedCert_CertificateValidity(t *testing.T) {
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	// Verify certificate is currently valid
	now := time.Now()
	require.True(t, cert.Cert.NotBefore.Before(now))
	require.True(t, cert.Cert.NotAfter.After(now))

	// Verify validity period
	duration := cert.Cert.NotAfter.Sub(cert.Cert.NotBefore)
	require.Greater(t, duration, 2*time.Hour)
}

func TestSelfSignedCert_SubjectKeyId(t *testing.T) {
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	// Verify SubjectKeyId is set
	require.NotEmpty(t, cert.Cert.SubjectKeyId)
	require.Len(t, cert.Cert.SubjectKeyId, 20) // SHA-1 hash is 20 bytes
}
