package cdxprops

import (
	"testing"

	"crypto/x509"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops/czertainly"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestCurveInformation(t *testing.T) {
	tests := []struct {
		name   string
		sigAlg x509.SignatureAlgorithm
		want   string
	}{
		{"ECDSAWithSHA1", x509.ECDSAWithSHA1, "secp256r1"},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, "secp256r1"},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, "secp384r1"},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, "secp521r1"},
		{"NonECDSA", x509.SHA256WithRSA, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := curveInformation(tt.sigAlg)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetAlgorithmProperties_Table(t *testing.T) {
	tests := []struct {
		name           string
		sigAlg         x509.SignatureAlgorithm
		wantHash       string
		wantParamSetID string
		wantPadding    cdx.CryptoPadding
		wantFamily     string
	}{
		{
			name:           "SHA256WithRSA",
			sigAlg:         x509.SHA256WithRSA,
			wantHash:       "SHA-256",
			wantParamSetID: "256",
			wantPadding:    cdx.CryptoPaddingPKCS1v15,
			wantFamily:     "RSASSA-PKCS1",
		},
		{
			name:           "SHA512WithRSAPSS",
			sigAlg:         x509.SHA512WithRSAPSS,
			wantHash:       "SHA-512",
			wantParamSetID: "512",
			wantPadding:    cdx.CryptoPadding(""), // no padding set for RSASSA-PSS in code
			wantFamily:     "RSASSA-PSS",
		},
		{
			name:           "PureEd25519",
			sigAlg:         x509.PureEd25519,
			wantHash:       "SHA-512",
			wantParamSetID: "256",
			wantPadding:    cdx.CryptoPadding(""),
			wantFamily:     "EdDSA",
		},
		{
			name:           "Unknown",
			sigAlg:         x509.UnknownSignatureAlgorithm,
			wantHash:       "",
			wantParamSetID: "0",
			wantPadding:    cdx.CryptoPadding(""),
			wantFamily:     "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Converter
			// enable czertainly-specific properties
			// set the unexported flag directly (test in same package)
			c.czertainly = true

			cryptoProps, props, hash := c.getAlgorithmProperties(tt.sigAlg)

			// cryptoProps checks
			require.Equal(t, tt.wantParamSetID, cryptoProps.ParameterSetIdentifier)
			// Padding is an enum; compare directly
			require.Equal(t, tt.wantPadding, cryptoProps.Padding)
			// Execution environment and primitive should be set
			require.Equal(t, cdx.CryptoPrimitiveSignature, cryptoProps.Primitive)
			require.NotNil(t, cryptoProps.ExecutionEnvironment)

			// hash
			require.Equal(t, tt.wantHash, hash)

			// czertainly property should be present and first property when czertainly==true
			require.GreaterOrEqual(t, len(props), 1)
			found := false
			for _, p := range props {
				if p.Name == czertainly.SignatureAlgorithmFamily {
					require.Equal(t, tt.wantFamily, p.Value)
					found = true
				}
			}
			require.True(t, found, "expected czertainly signature algorithm family property to be present")
		})
	}
}

func TestGetAlgorithmProperties_NoCzertainly(t *testing.T) {
	var c Converter
	c.czertainly = false

	_, props, _ := c.getAlgorithmProperties(x509.SHA256WithRSA)
	// when czertainly flag is false, no czertainly-specific properties should be returned
	for _, p := range props {
		require.NotEqual(t, czertainly.SignatureAlgorithmFamily, p.Name)
	}
}

func TestSigAlgRefMap(t *testing.T) {
	require.Equal(t, cdx.BOMReference("crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11"), sigAlgRef[x509.SHA256WithRSA])
	require.Equal(t, cdx.BOMReference("crypto/algorithm/ed25519@1.3.101.112"), sigAlgRef[x509.PureEd25519])
}

func TestPqcSigOIDRefMap(t *testing.T) {
	require.Equal(t, cdx.BOMReference("crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17"), pqcSigOIDRef["2.16.840.1.101.3.4.3.17"])
	require.Equal(t, cdx.BOMReference("crypto/algorithm/xmss-hashsig@1.3.6.1.5.5.7.6.34"), pqcSigOIDRef["1.3.6.1.5.5.7.6.34"])
}

func TestSpkiOIDRefMap(t *testing.T) {
	require.Equal(t, cdx.BOMReference("crypto/key/ml-kem-512@2.16.840.1.101.3.4.4.1"), spkiOIDRef["2.16.840.1.101.3.4.4.1"])
	require.Equal(t, cdx.BOMReference("crypto/key/xmss@1.3.6.1.5.5.7.6.34"), spkiOIDRef["1.3.6.1.5.5.7.6.34"])
}

func TestCurveInformation2(t *testing.T) {
	require.Equal(t, "secp256r1", curveInformation(x509.ECDSAWithSHA256))
	require.Equal(t, "secp384r1", curveInformation(x509.ECDSAWithSHA384))
	require.Equal(t, "secp521r1", curveInformation(x509.ECDSAWithSHA512))
	require.Equal(t, "", curveInformation(x509.SHA256WithRSA))
}

func TestGetAlgorithmProperties(t *testing.T) {
	cv := Converter{}
	props, extra, hash := cv.getAlgorithmProperties(x509.SHA256WithRSA)
	require.Equal(t, cdx.CryptoPrimitiveSignature, props.Primitive)
	require.Equal(t, "256", props.ParameterSetIdentifier)
	require.Equal(t, cdx.CryptoPaddingPKCS1v15, props.Padding)
	require.Equal(t, "SHA-256", hash)
	require.NotNil(t, props.ClassicalSecurityLevel)
	require.Equal(t, 112, *props.ClassicalSecurityLevel)
	require.Empty(t, props.Curve)
	require.Empty(t, extra)

	props, extra, hash = cv.getAlgorithmProperties(x509.ECDSAWithSHA384)
	require.Equal(t, "secp384r1", props.Curve)
	require.Equal(t, "SHA-384", hash)
	require.NotNil(t, props.ClassicalSecurityLevel)
	require.Equal(t, 192, *props.ClassicalSecurityLevel)

	props, extra, hash = cv.getAlgorithmProperties(x509.PureEd25519)
	require.Equal(t, "256", props.ParameterSetIdentifier)
	require.Equal(t, "SHA-512", hash)
	require.Equal(t, 128, *props.ClassicalSecurityLevel)
}
