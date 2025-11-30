package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected cdxprops.TLSInfo
	}{
		{"TLSv1.3", cdxprops.TLSInfo{"tls", "1.3", "1.3.6.1.5.5.7.6.2"}},
		{"TLSv1.2", cdxprops.TLSInfo{"tls", "1.2", "1.3.6.1.5.5.7.6.1"}},
		{"SSLv3", cdxprops.TLSInfo{"ssl", "3.0", "1.3.6.1.4.1.311.10.3.2"}},
		{"TLS 1.0", cdxprops.TLSInfo{"tls", "1.0", "1.3.6.1.4.1.311.10.3.3"}},
		{"unknown", cdxprops.TLSInfo{"n/a", "n/a", "n/a"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cdxprops.ParseTLSInfo(tt.input)
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
		c := cdxprops.NewConverter().WithCzertainlyExtenstions(false)

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
		c := cdxprops.NewConverter().WithCzertainlyExtenstions(true)

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
