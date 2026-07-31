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
	pemscan "github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

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

// TestPEMBundle_StandaloneDSAPublicKeyDoesNotPanic covers the crash that
// shipped undetected because nothing fed a *dsa.PublicKey through
// bundle.PublicKeys.
//
// Go parses a DSA PUBLIC KEY block happily but refuses to marshal
// *dsa.PublicKey, so publicKeyComponents cannot identify the key and returns no
// key component. restOfPEMBundleToCDX then dereferenced its CryptoProperties
// unconditionally and panicked, aborting the whole scan on one input file.
func TestPEMBundle_StandaloneDSAPublicKeyDoesNotPanic(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.DSA2048PublicKey)
	require.NoError(t, err)

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), data, cdxtest.DSA2048PublicKey)
	require.NoError(t, err)
	require.NotEmpty(t, bundle.PublicKeys, "fixture must reach bundle.PublicKeys, or this proves nothing")

	var d *model.Detection
	require.NotPanics(t, func() {
		d = cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	})
	require.NotNil(t, d)

	// Whatever is emitted must be well formed: no component may carry a nil
	// CryptoProperties, and none may have an empty name or ref.
	for _, compo := range d.Components {
		require.NotEmpty(t, compo.Name, "component with no name")
		require.NotEmpty(t, compo.BOMRef, "component with no bom-ref")
		require.NotNil(t, compo.CryptoProperties, "%s has nil CryptoProperties", compo.Name)
	}
}
