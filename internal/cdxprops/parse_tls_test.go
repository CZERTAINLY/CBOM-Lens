package cdxprops

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestKeyExchangeAlgorithm_info(t *testing.T) {
	algo := KeyExchangeAlgorithm(KexDHE)
	info, ok := algo.info("2048")
	require.True(t, ok)
	require.Equal(t, "DHE-2048", info.name)
	require.Equal(t, 112, info.classicalSecurityLevel)
	require.Contains(t, info.cryptoFunctions, cdx.CryptoFunctionKeyderive)

	algo = KeyExchangeAlgorithm(KexECDHE)
	info, ok = algo.info("secp256r1")
	require.True(t, ok)
	require.Equal(t, "ECDHE-secp256r1", info.name)
	require.Equal(t, 128, info.classicalSecurityLevel)

	algo = KeyExchangeAlgorithm(KexRSA)
	info, ok = algo.info("4096")
	require.True(t, ok)
	require.Equal(t, "RSA-4096", info.name)
	require.Equal(t, 152, info.classicalSecurityLevel)

	info, ok = KeyExchangeAlgorithm("UNKNOWN").info("foo")
	require.False(t, ok)
}

func TestKeyAuthenticationAlgorithm_info(t *testing.T) {
	algo := KeyAuthenticationAlgorithm(KauthECDSA)
	info, ok := algo.info("secp384r1")
	require.True(t, ok)
	require.Equal(t, "ECDSA-secp384r1", info.name)
	require.Equal(t, 192, info.classicalSecurityLevel)
	require.Contains(t, info.cryptoFunctions, cdx.CryptoFunctionSign)

	algo = KeyAuthenticationAlgorithm(KauthRSA)
	info, ok = algo.info("2048")
	require.True(t, ok)
	require.Equal(t, "RSA-2048", info.name)
	require.Equal(t, 112, info.classicalSecurityLevel)

	algo = KeyAuthenticationAlgorithm("")
	info, ok = algo.info("foo")
	require.False(t, ok)
}

func TestCipherAlgorithm_info(t *testing.T) {
	algo := CipherAlgorithm(CipherRC4)
	info, ok := algo.info(KeyLen128, CipherModeEmpty)
	require.True(t, ok)
	require.Equal(t, "RC4-128", info.name)
	require.Equal(t, 128, info.classicalSecurityLevel)

	algo = CipherAlgorithm(Cipher3DES)
	info, ok = algo.info(KeyLen168, CipherModeEDE_CBC)
	require.True(t, ok)
	require.Equal(t, "3DES-EDE-CBC", info.name)
	require.Equal(t, 112, info.classicalSecurityLevel)

	algo = CipherAlgorithm(CipherAES)
	info, ok = algo.info(KeyLen128, CipherModeCBC)
	require.True(t, ok)
	require.Equal(t, "AES-128-CBC", info.name)
	require.Equal(t, 128, info.classicalSecurityLevel)

	algo = CipherAlgorithm(CipherAES)
	info, ok = algo.info(KeyLen256, CipherModeGCM)
	require.True(t, ok)
	require.Equal(t, "AES-256-GCM", info.name)
	require.Equal(t, 256, info.classicalSecurityLevel)

	algo = CipherAlgorithm(CipherCHACHA20)
	info, ok = algo.info(KeyLen256, CipherModePOLY1305)
	require.True(t, ok)
	require.Equal(t, "ChaCha20-Poly1305", info.name)
	require.Equal(t, 128, info.classicalSecurityLevel)

	info, ok = CipherAlgorithm("UNKNOWN").info(KeyLen128, CipherModeCBC)
	require.False(t, ok)
}

func TestParseCipherSuite(t *testing.T) {
	cs, ok := ParseCipherSuite(model.SSLCipher{Name: "TLS_AES_128_GCM_SHA256"})
	require.True(t, ok)
	require.EqualValues(t, CipherAES, cs.Cipher)
	require.EqualValues(t, KeyLen128, cs.KeyLen)
	require.EqualValues(t, CipherModeGCM, cs.Mode)
	require.EqualValues(t, HashSHA256, cs.Hash)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", cs.Name)

	cs, ok = ParseCipherSuite(model.SSLCipher{Name: "TLS_AKE_WITH_AES_128_GCM_SHA256"})
	require.True(t, ok)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", cs.Name)

	cs, ok = ParseCipherSuite(model.SSLCipher{Name: "NON_EXISTENT_SUITE"})
	require.False(t, ok)
}
