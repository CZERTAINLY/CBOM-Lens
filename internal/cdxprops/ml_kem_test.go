package cdxprops

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
	"github.com/stretchr/testify/require"
)

// mlKEM768OID is id-alg-ml-kem-768 = { kems(2.16.840.1.101.3.4.4) 2 },
// registered in the NIST CSOR.
var mlKEM768OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}

// synthPKCS8 builds a minimal PKCS#8 PrivateKeyInfo carrying oid, with a
// privateKey body the size of that algorithm's expanded private key.
//
// unsupportedPKCS8PrivateKey never interprets the body as key material, so
// zero bytes of the right length exercise the real parse path without embedding
// a key. The length matters: the function refuses to report a key from a body
// that is not a legal encoding of one, so the old four-byte placeholder would
// make every sized OID in the sweep return an algorithm and no key, and the
// sweep's key assertions would be testing the rejection path while claiming to
// test the happy one.
//
// This deliberately uses the EXPANDED size rather than the seed. Both are
// accepted, and sizing the synthetic body at the seed would make the sweep pass
// even if the seed alternative stopped being accepted -- which is how real
// seed-only keys were dropped once already.
//
// Algorithms the registry states no size for (XMSS, XMSS-MT, HSS-LMS) get one
// byte. Nothing can be validated for them, so any non-empty body yields their
// key -- but the body has to be non-empty: an empty one is refused for every
// algorithm, and a zero-length body would put those three OIDs back on the
// rejection path this helper exists to stay off.
func synthPKCS8(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	info := unsupportedAlgorithms[oid.String()]
	size := 1
	switch sizes := info.pqc.(type) {
	case kemInfo:
		if sizes.decapKeySize > 0 {
			size = sizes.decapKeySize
		}
	case pqcInfo:
		if sizes.privKeySize > 0 {
			size = sizes.privKeySize
		}
	}
	return synthPKCS8Body(t, oid, size)
}

// synthPKCS8Body is synthPKCS8 with the privateKey body length chosen, so the
// undersized-body rejection can be driven directly.
func synthPKCS8Body(t *testing.T, oid asn1.ObjectIdentifier, bodyLen int) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: make([]byte, bodyLen),
	})
	require.NoError(t, err)
	return der
}

// synthPKIX builds a minimal SubjectPublicKeyInfo carrying oid, with a
// publicKey BIT STRING the size of that algorithm's public key -- its
// encapsulation key for a KEM.
//
// unsupportedPKIX never interprets those bytes as key material, so zeroes of
// the right length exercise the real parse path without embedding a key. The
// length matters: the function refuses to report a key from a body that is not
// exactly the size the registry states, so the old four-byte 0xdeadbeef
// placeholder would make every sized OID in the sweep return an algorithm and
// no key, and the sweep's key assertions would be testing the rejection path
// while claiming to test the happy one. That four-byte body is the literal
// input the guard was written to refuse.
//
// Algorithms the registry states no size for (XMSS, XMSS-MT, HSS-LMS) get one
// byte, mirroring synthPKCS8. Nothing can be validated for them, so any
// non-empty body yields their key -- but the body has to be non-empty: an empty
// one is refused for every algorithm, and a zero-length body would put those
// three OIDs back on the rejection path this helper exists to stay off.
func synthPKIX(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	info := unsupportedAlgorithms[oid.String()]
	size := 1
	switch sizes := info.pqc.(type) {
	case kemInfo:
		if sizes.encapKeySize > 0 {
			size = sizes.encapKeySize
		}
	case pqcInfo:
		if sizes.pubKeySize > 0 {
			size = sizes.pubKeySize
		}
	}
	return synthPKIXBody(t, oid, size)
}

// synthPKIXBody is synthPKIX with the publicKey body length chosen, so the
// wrong-size rejection can be driven directly.
func synthPKIXBody(t *testing.T, oid asn1.ObjectIdentifier, bodyLen int) []byte {
	t.Helper()

	der, err := asn1.Marshal(pkixStruct{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: make([]byte, bodyLen), BitLength: bodyLen * 8},
	})
	require.NoError(t, err)
	return der
}

// TestMLKEM768PKCS8PrivateKey is the test that proves the ML-KEM gap is
// closed. Before ML-KEM had registry entries, this call returned
// `unsupported fallback oid "2.16.840.1.101.3.4.4.2"` -- a PQC-readiness
// sensor refusing to recognise the flagship NIST KEM.
func TestMLKEM768PKCS8PrivateKey(t *testing.T) {
	t.Parallel()

	c := NewConverter().WithIlmExtensions(true)
	_, algo, err := c.unsupportedPKCS8PrivateKey(t.Context(), synthPKCS8(t, mlKEM768OID))
	require.NoError(t, err, "an ML-KEM PKCS#8 key must be recognised, not rejected")

	require.Equal(t, "ML-KEM-768", algo.Name)
	require.Equal(t, "2.16.840.1.101.3.4.4.2", algo.CryptoProperties.OID)

	props := algo.CryptoProperties.AlgorithmProperties
	require.Equal(t, "768", props.ParameterSetIdentifier)
	require.Equal(t, cdx.CryptoPrimitiveKEM, props.Primitive,
		"an ML-KEM key is a kem, not a signature scheme")
	require.ElementsMatch(t, []cdx.CryptoFunction{
		cdx.CryptoFunctionEncapsulate,
		cdx.CryptoFunctionDecapsulate,
	}, *props.CryptoFunctions)

	// FIPS 203 sec. 8: ML-KEM-768 is claimed to be in security category 3.
	require.NotNil(t, props.NistQuantumSecurityLevel)
	require.Equal(t, 3, *props.NistQuantumSecurityLevel)
	// FIPS 203 Table 2, required RBG strength.
	require.Equal(t, 192, *props.ClassicalSecurityLevel)

	// FIPS 203 Table 3 sizes, reported through the ilm extension.
	require.Equal(t, "1184", cdxtestGetProp(algo, ilm.AlgorithmPublicKeySize),
		"encapsulation key")
	require.Equal(t, "2400", cdxtestGetProp(algo, ilm.AlgorithmPrivateKeySize),
		"decapsulation key")
	require.Equal(t, "1088", cdxtestGetProp(algo, ilm.AlgorithmCiphertextSize))
	require.Empty(t, cdxtestGetProp(algo, ilm.AlgorithmSignatureSize),
		"a KEM has no signature size")
}

// TestMLKEM768PKIXPublicKey covers the public-key half of the same gap.
func TestMLKEM768PKIXPublicKey(t *testing.T) {
	t.Parallel()

	c := NewConverter()
	key, algo, err := c.unsupportedPKIX(t.Context(), synthPKIX(t, mlKEM768OID))
	require.NoError(t, err)

	require.Equal(t, "ML-KEM-768", algo.Name)
	require.Equal(t, cdx.CryptoPrimitiveKEM,
		algo.CryptoProperties.AlgorithmProperties.Primitive,
		"unsupportedPKIX used to hardcode primitive=signature for every OID")

	require.Equal(t, "ML-KEM-768", key.Name)
	require.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey,
		key.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	require.Equal(t, "2.16.840.1.101.3.4.4.2", key.CryptoProperties.OID)
}

// TestSLHDSAPKIXKeepsSignaturePrimitive checks that routing the primitive
// through the registry did not silently reclassify the signature schemes.
func TestSLHDSAPKIXKeepsSignaturePrimitive(t *testing.T) {
	t.Parallel()

	c := NewConverter()
	_, algo, err := c.unsupportedPKIX(t.Context(), synthPKIX(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}))
	require.NoError(t, err)

	require.Equal(t, "SLH-DSA-SHA2-128S", algo.Name)
	require.Equal(t, cdx.CryptoPrimitiveSignature,
		algo.CryptoProperties.AlgorithmProperties.Primitive)
}

// cdxtestGetProp reads a property value off a component. The cdxtest helper of
// the same name cannot be used here: cdxtest imports nothing from cdxprops,
// but these are internal tests in package cdxprops, and cdxtest is a sibling
// package that this package's non-test code must not depend on.
func cdxtestGetProp(compo cdx.Component, name string) string {
	if compo.Properties == nil {
		return ""
	}
	for _, p := range *compo.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
