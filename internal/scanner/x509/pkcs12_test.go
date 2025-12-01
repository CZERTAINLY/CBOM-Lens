package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	czX509 "github.com/CZERTAINLY/CBOM-lens/internal/scanner/x509"

	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func Test_Detect_PKCS12_WithKey(t *testing.T) {
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert
	key := selfSigned.Key

	// Build a PFX with key+cert
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "changeit")
	require.NoError(t, err)

	var d czX509.Scanner
	got, err := d.Scan(t.Context(), pfx, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func Test_PKCS12_Edge_Cases(t *testing.T) {
	t.Parallel()

	// Test PKCS12 with different passwords and edge cases
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert
	key := selfSigned.Key

	// Test with empty password
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "")
	require.NoError(t, err)

	var d czX509.Scanner
	got, err := d.Scan(t.Context(), pfx, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func Test_PKCS12_InvalidData(t *testing.T) {
	t.Parallel()

	// Test PKCS12 sniffing with various invalid data
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x30, 0x82}},
		{"invalid ASN.1", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"wrong tag", []byte{0x31, 0x82, 0x01, 0x23}}, // SET instead of SEQUENCE
		{"wrong version", []byte{
			0x30, 0x82, 0x01, 0x23, // SEQUENCE
			0x02, 0x01, 0xFF, // version 255 (too high)
		}},
	}

	var d czX509.Scanner
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.Scan(t.Context(), tt.data, "testpath")
			require.NoError(t, err)
		})
	}
}
