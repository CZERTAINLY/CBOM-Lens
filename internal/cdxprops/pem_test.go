package cdxprops_test

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func TestConverter_PEM(t *testing.T) {
	const location = "/test/bundle.pem"
	ctx := context.Background()

	// Generate test certificate
	selfSigned, err := cdxtest.CertBuilder{}.
		WithSignatureAlgorithm(x509.SHA256WithRSA).
		Generate()
	require.NoError(t, err)

	// Generate CSR
	csrKey, err := cdxtest.GenECPrivateKey(elliptic.P224())
	require.NoError(t, err)
	csr, _, err := cdxtest.GenCSR(csrKey)
	require.NoError(t, err)

	// Generate CRL
	crlCert, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := crlCert.Key.(crypto.Signer)
	require.True(t, ok)
	crl, _, err := cdxtest.GenCRL(crlCert.Cert, signer)
	require.NoError(t, err)

	// Generate public key
	pubKey, _, err := cdxtest.GenEd25519Keys()
	require.NoError(t, err)

	// ML-DSA-65 private and public keys
	mldsa65PrivateKey, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)
	mldsa65PrivateKeyPEM, _ := pem.Decode(mldsa65PrivateKey)
	require.NotNil(t, mldsa65PrivateKeyPEM)
	mldsa65PublicKey, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	mldsa65PublicKeyPEM, _ := pem.Decode(mldsa65PublicKey)
	require.NotNil(t, mldsa65PublicKeyPEM)

	// Create comprehensive PEM bundle
	bundle := model.PEMBundle{
		Certificates: []model.CertHit{
			{
				Cert:     selfSigned.Cert,
				Source:   "PEM",
				Location: location,
			},
		},
		PrivateKeys: []model.PrivateKeyInfo{
			{
				Key:        selfSigned.Key,
				Type:       "RSA",
				Source:     "PEM",
				BlockIndex: -1,
			},
			{
				Key:        csrKey,
				Type:       "ECDSA",
				Source:     "PEM",
				BlockIndex: -1,
			},
		},
		CertificateRequests: []*x509.CertificateRequest{csr},
		PublicKeys:          []crypto.PublicKey{pubKey},
		CRLs:                []*x509.RevocationList{crl},
		RawBlocks: []model.PEMBlock{
			{
				Type:    mldsa65PrivateKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   mldsa65PrivateKeyPEM.Bytes,
				Order:   0,
			},
			{
				Type:    mldsa65PublicKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   mldsa65PublicKeyPEM.Bytes,
				Order:   1,
			},
			{
				Type:    mldsa65PrivateKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   []byte("garbage"),
				Order:   2,
			},
			{
				Type:    mldsa65PublicKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   []byte("garbage"),
				Order:   3,
			},
		},
		ParseErrors: map[int]error{
			0: errors.New("ml-dsa-65"),
			1: errors.New("ml-dsa-65"),
			2: errors.New("garbage"),
			3: errors.New("garbage"),
		},
	}

	// Execute
	c := cdxprops.NewConverter()
	detection := c.PEMBundle(ctx, bundle)
	require.NotNil(t, detection)

	components := detection.Components
	// Verify we got all expected components
	require.Len(t, components, 20)

	for idx, c := range components {
		t.Logf("%d: name=%s, description=%s", idx, c.Name, c.Description)
	}
}
