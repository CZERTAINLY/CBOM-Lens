package xcrypto_test

import (
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/xcrypto"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/stretchr/testify/require"
)

func TestParsePKIXPublicKey_MLDSA65(t *testing.T) {
	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "PUBLIC KEY", block.Type)

	cryptoPublicKey, err := xcrypto.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	publicKey, ook := cryptoPublicKey.(*mldsa65.PublicKey)
	require.True(t, ook)
	h := hashPublicKey(t, publicKey)
	require.Equal(t, cdxtest.MLDSA65PublicKeyHash, hex.EncodeToString(h))
}
