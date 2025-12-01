package x509_test

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	czX509 "github.com/CZERTAINLY/CBOM-lens/internal/scanner/x509"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/require"
)

func Test_Detect_JKS_Truststore(t *testing.T) {
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	der := selfSigned.Der

	// Create a JKS with a single trusted cert entry
	ks := keystore.New()
	err = ks.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: der,
		},
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	err = ks.Store(&buf, []byte("changeit"))
	require.NoError(t, err)
	jksBytes := buf.Bytes()

	var d czX509.Scanner
	got, err := d.Scan(t.Context(), jksBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func Test_Detect_JKS_PrivateKeyEntry_WithChain(t *testing.T) {
	t.Parallel()
	// Leaf + "CA" (both self-signed for simplicity, but store a chain of two)
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	leafDER := selfSigned.Der
	leafKey := selfSigned.Key
	selfSigned, err = cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	caDER := selfSigned.Der

	// JKS with a PrivateKeyEntry that contains a chain [leaf, ca]
	ks := keystore.New()
	// encode leaf key in PKCS#8 for keystore-go
	p8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)

	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   p8,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: leafDER},
			{Type: "X509", Content: caDER},
		},
	}
	require.NoError(t, ks.SetPrivateKeyEntry("leaf", entry, []byte("changeit")))

	var buf bytes.Buffer
	require.NoError(t, ks.Store(&buf, []byte("changeit")))

	var d czX509.Scanner
	got, err := d.Scan(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func Test_JKS_Edge_Cases(t *testing.T) {
	t.Parallel()

	// Test JKS with malformed data to improve sniff coverage
	badJKSData := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x99} // Bad version

	var d czX509.Scanner
	_, err := d.Scan(t.Context(), badJKSData, "testpath")
	require.NoError(t, err)

	// Test with data that looks like magic but isn't long enough
	shortData := []byte{0xFE, 0xED} // Too short
	_, err = d.Scan(t.Context(), shortData, "testpath")
	require.NoError(t, err)
}
