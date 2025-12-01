package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	czX509 "github.com/CZERTAINLY/CBOM-lens/internal/scanner/x509"
	"github.com/stretchr/testify/require"
)

func Test_DER_Detection(t *testing.T) {
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	der := selfSigned.Der

	selfSigned, err = cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	der2 := selfSigned.Der
	concatDER := append(append([]byte{}, der...), der2...)

	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
		wantLen   int
	}{
		{"DER single", der, true, 1},
		{"DER concatenated", concatDER, true, 2},
		{"Invalid", []byte("not a cert"), false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d czX509.Scanner
			got, err := d.Scan(t.Context(), tt.input, "testpath")
			if !tt.wantMatch {
				require.NoError(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, tt.wantLen)
		})
	}
}

func Test_DER_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"random bytes", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"incomplete DER header", []byte{0x30, 0x82}},
		{"incomplete DER length", []byte{0x30, 0x82, 0x01, 0x00}}, // Valid DER header but incomplete
		{"valid ASN.1 but not certificate", []byte{
			0x30, 0x09, // SEQUENCE
			0x02, 0x01, 0x01, // INTEGER 1
			0x02, 0x01, 0x02, // INTEGER 2
			0x02, 0x01, 0x03, // INTEGER 3
		}},
		{"DER with wrong tag", []byte{
			0x04, 0x10, // OCTET STRING instead of SEQUENCE
			0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x00, 0x00, 0x00,
		}},
		{"truncated DER certificate", []byte{
			0x30, 0x82, 0x02, 0x00, // SEQUENCE with length 512 but data is much shorter
			0x30, 0x82, 0x01, 0x00, // Another SEQUENCE but truncated
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

func Test_DER_CertificateChain(t *testing.T) {
	t.Parallel()

	// Create multiple certificates and concatenate them
	certs := make([][]byte, 3)
	for i := range certs {
		selfSigned, err := cdxtest.GenSelfSignedCert()
		require.NoError(t, err)
		der := selfSigned.Der
		certs[i] = der
	}

	// Concatenate all certificates
	var concatenated []byte
	for _, cert := range certs {
		concatenated = append(concatenated, cert...)
	}

	var d czX509.Scanner
	got, err := d.Scan(t.Context(), concatenated, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 3)
}
