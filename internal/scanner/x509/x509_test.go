package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	czX509 "github.com/CZERTAINLY/CBOM-lens/internal/scanner/x509"

	"github.com/stretchr/testify/require"
)

func Test_Detector_NoMatch(t *testing.T) {
	t.Parallel()

	// Test that detector returns no match for invalid data
	var d czX509.Scanner
	hits, err := d.Scan(t.Context(), []byte("invalid data"), "testpath")
	require.NoError(t, err)
	require.Len(t, hits, 0)
}

func Test_Detector_IgnorePrivateKey(t *testing.T) {
	t.Parallel()
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	// private keys, CRLs and others are ignored by x509 detector, which is focused on *x509.Certificate only
	privKeyPEM, err := selfSigned.PrivKeyPEM()
	require.NoError(t, err)

	// Test that detector returns no match for private key PEM
	var d czX509.Scanner
	hits, err := d.Scan(t.Context(), privKeyPEM, "testpath")
	require.NoError(t, err)
	require.Len(t, hits, 0)
}
