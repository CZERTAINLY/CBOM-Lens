package xcrypto_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/xcrypto"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/stretchr/testify/require"
)

func TestParsePKCS8PrivateKey_MLDSA65(t *testing.T) {
	data, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)

	cryptoPrivateKey, err := xcrypto.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	privateKey, ook := cryptoPrivateKey.(*mldsa65.PrivateKey)
	require.True(t, ook)
	publicKey, ook := privateKey.Public().(*mldsa65.PublicKey)
	require.True(t, ook)
	h := hashPublicKey(t, publicKey)
	require.Equal(t, cdxtest.MLDSA65PublicKeyHash, hex.EncodeToString(h))
}

func hashPublicKey(t *testing.T, publicKey crypto.PublicKey) []byte {
	t.Helper()
	derBytes, err := xcrypto.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	h := sha256.Sum256(derBytes)
	return h[:]
}
