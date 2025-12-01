package cdxprops

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected TLSInfo
	}{
		{"TLSv1.3", TLSInfo{"tls", "1.3", "1.3.6.1.5.5.7.6.2"}},
		{"TLSv1.2", TLSInfo{"tls", "1.2", "1.3.6.1.5.5.7.6.1"}},
		{"SSLv3", TLSInfo{"ssl", "3.0", "1.3.6.1.4.1.311.10.3.2"}},
		{"TLS 1.0", TLSInfo{"tls", "1.0", "1.3.6.1.4.1.311.10.3.3"}},
		{"unknown", TLSInfo{"n/a", "n/a", "n/a"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseTLSInfo(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSSHHostKey(t *testing.T) {
	key := model.SSHHostKey{
		Type:        "ssh-ed25519",
		Bits:        "256",
		Key:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE",
		Fingerprint: "aa:bb:cc:dd",
	}

	t.Run("without czertainly properties", func(t *testing.T) {
		c := NewConverter().WithCzertainlyExtensions(false)

		compo := c.ParseSSHHostKey(key)
		require.Equal(t, "crypto/algorithm/ssh-ed25519@256", compo.BOMRef)
		require.Equal(t, "ssh-ed25519", compo.Name)
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, compo.Type)
		require.NotNil(t, compo.CryptoProperties)
		require.Equal(t, cdx.CryptoAssetTypeAlgorithm, compo.CryptoProperties.AssetType)
		require.NotNil(t, compo.CryptoProperties.AlgorithmProperties)
		require.Equal(t, "ed25519@1.3.101.112", compo.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
		require.Equal(t, "ed25519@1.3.101.112", compo.CryptoProperties.OID)
		require.Nil(t, compo.Properties)
	})

	t.Run("with czertainly properties", func(t *testing.T) {
		c := NewConverter().WithCzertainlyExtensions(true)

		compo := c.ParseSSHHostKey(key)
		require.NotNil(t, compo.Properties)
		props := *compo.Properties
		// Expect czertainly added content and fingerprint properties
		foundContent := false
		foundFingerprint := false
		for _, p := range props {
			if p.Name == czertainly.SSHHostKeyContent {
				require.Equal(t, key.Key, p.Value)
				foundContent = true
			}
			if p.Name == czertainly.SSHHostKeyFingerprintContent {
				require.Equal(t, key.Fingerprint, p.Value)
				foundFingerprint = true
			}
		}
		require.True(t, foundContent)
		require.True(t, foundFingerprint)
	})
}

func TestParseTLSInfo(t *testing.T) {
	tests := []struct {
		input    string
		expected TLSInfo
	}{
		{"TLSv1.3", TLSInfo{Name: "tls", Version: "1.3", OID: "1.3.6.1.5.5.7.6.2"}},
		{"SSLv3", TLSInfo{Name: "ssl", Version: "3.0", OID: "1.3.6.1.4.1.311.10.3.2"}},
		{"TLS 1.2", TLSInfo{Name: "tls", Version: "1.2", OID: "1.3.6.1.5.5.7.6.1"}},
		{"unknown", TLSInfo{Name: "n/a", Version: "n/a", OID: "n/a"}},
	}
	for _, tt := range tests {
		info := ParseTLSInfo(tt.input)
		require.Equal(t, tt.expected, info)
	}
}

func TestPublicKeySizeFromPkeyRef(t *testing.T) {
	require.Equal(t, "2048", publicKeySizeFromPkeyRef("crypto/algorithm/rsa-2048@sha256:foo"))
	require.Equal(t, "secp256r1", publicKeySizeFromPkeyRef("crypto/algorithm/ecdsa-secp256r1@sha256:bar"))
	require.Equal(t, "", publicKeySizeFromPkeyRef("crypto/algorithm/unknown@sha256:baz"))
	require.Equal(t, "", publicKeySizeFromPkeyRef(""))
}

func TestParseSSHAlgorithm(t *testing.T) {
	prop := parseSSHAlgorithm("ecdsa-sha2-nistp256")
	require.Equal(t, "nistp256@1.2.840.10045.3.1.7", prop.ParameterSetIdentifier)
	require.Equal(t, cdx.CryptoPrimitiveSignature, prop.Primitive)
	require.NotNil(t, prop.CryptoFunctions)

	prop = parseSSHAlgorithm("ssh-ed25519")
	require.Equal(t, "ed25519@1.3.101.112", prop.ParameterSetIdentifier)

	prop = parseSSHAlgorithm("unknown-algo")
	require.Equal(t, "unknown", prop.ParameterSetIdentifier)
	require.Equal(t, "", prop.Curve)
}

func TestParseSSHHostKey2(t *testing.T) {
	cv := NewConverter()
	key := model.SSHHostKey{Type: "ecdsa-sha2-nistp256", Bits: "256"}
	compo := cv.ParseSSHHostKey(key)
	require.Equal(t, "crypto/algorithm/ecdsa-sha2-nistp256@256", compo.BOMRef)
	require.Equal(t, "ecdsa-sha2-nistp256", compo.Name)
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, compo.Type)
	require.NotNil(t, compo.CryptoProperties)
	require.Equal(t, cdx.CryptoAssetTypeAlgorithm, compo.CryptoProperties.AssetType)
	require.Equal(t, "nistp256@1.2.840.10045.3.1.7", compo.CryptoProperties.OID)
}

func TestParseTLSCiphers(t *testing.T) {
	cv := NewConverter()
	ciphers := []model.SSLCipher{
		{Name: "TLS_AES_128_GCM_SHA256"},
		{Name: "TLS_RSA_WITH_AES_128_CBC_SHA"},
	}
	suites := cv.parseTLSCiphers(t.Context(), ciphers, "")
	require.Len(t, suites, 2)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", suites[0].name)
	require.Equal(t, "TLS_RSA_WITH_AES_128_CBC_SHA", suites[1].name)
	require.NotEmpty(t, suites[0].identifiers)
	require.NotEmpty(t, suites[0].compos)
}

func TestCipherSuite_cdx(t *testing.T) {
	compos := []cdx.Component{
		{BOMRef: "ref1"},
		{BOMRef: "ref2"},
	}
	cs := cipherSuite{
		name:        "TLS_AES_128_GCM_SHA256",
		compos:      compos,
		identifiers: []string{"0x13", "0x01"},
	}
	cdxSuite := cs.cdx()
	require.Equal(t, "TLS_AES_128_GCM_SHA256", cdxSuite.Name)
	require.NotNil(t, cdxSuite.Algorithms)
	require.Len(t, *cdxSuite.Algorithms, 2)
	require.Equal(t, "ref1", string((*cdxSuite.Algorithms)[0]))
	require.Equal(t, []string{"0x13", "0x01"}, *cdxSuite.Identifiers)
}

func TestTlsCipherToCompos(t *testing.T) {
	cv := NewConverter()
	cipherEnum := model.SSLEnumCiphers{
		Name: "TLSv1.3",
		Ciphers: []model.SSLCipher{
			{Name: "TLS_AES_128_GCM_SHA256"},
			{Name: "TLS_AES_256_GCM_SHA384"},
		},
	}
	compos := cv.tlsCipherToCompos(t.Context(), cipherEnum, nil, "")
	require.NotEmpty(t, compos)
	require.Equal(t, "TLSv1.3", compos[0].Name)
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, compos[0].Type)
	require.NotNil(t, compos[0].CryptoProperties)
	require.Equal(t, cdx.CryptoAssetTypeProtocol, compos[0].CryptoProperties.AssetType)
	require.NotNil(t, compos[0].CryptoProperties.ProtocolProperties)
	require.Equal(t, "1.3", compos[0].CryptoProperties.ProtocolProperties.Version)
	require.NotNil(t, compos[0].CryptoProperties.ProtocolProperties.CipherSuites)
	require.Len(t, *compos[0].CryptoProperties.ProtocolProperties.CipherSuites, 2)
}
