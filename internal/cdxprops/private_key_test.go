package cdxprops

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrivateKey_UnsizedAlgorithmPublishesNoSize states the guard its two
// siblings already carry: relatedCryptoMaterialProperties.size is written only
// when the algorithm states one.
//
// unsupportedPKCS8PrivateKey and publicKeyComponents both check
// `info.keySize > 0` before assigning, because the schema field is in BITS and a
// wrong value there validates -- nothing downstream can tell 0 from a key that
// really is zero bits long, which no key is. Converter.PrivateKey assigned
// unconditionally, so any key whose type privateKeyInfo does not name took the
// "Unknown" arm, whose keySize is 0, and published `"size": 0`.
//
// An X25519 key is the input because it is the one a step away: getPublicKey
// grows a *ecdh.PrivateKey case and the key flows straight here, while
// privateKeyInfo's switch still does not name it. Every type privateKeyInfo
// does name carries a size today, so no fixture in the tree reaches the arm and
// nothing else in the suite would notice the guard's absence.
func TestPrivateKey_UnsizedAlgorithmPublishesNoSize(t *testing.T) {
	t.Parallel()

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	algo, compo := NewConverter().PrivateKey(t.Context(), "fixture-id", key)

	require.Equal(t, "Unknown", compo.Name,
		"a key type the switch does not name is Unknown, not a guess")
	require.NotEmpty(t, algo.BOMRef,
		"the algorithm asset is still built: the key exists whether or not it can be sized")

	props := compo.CryptoProperties.RelatedCryptoMaterialProperties
	require.Nil(t, props.Size,
		"an algorithm that states no size must publish none: size is in bits, "+
			"and a zero validates against the schema as a real claim")
}
