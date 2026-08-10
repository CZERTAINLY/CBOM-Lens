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

// synthPKCS8 builds a minimal PKCS#8 PrivateKeyInfo carrying oid.
//
// unsupportedPKCS8PrivateKey only reads version and privateKeyAlgorithm, so a
// placeholder privateKey octet string is enough to exercise the real parse
// path without embedding key material.
func synthPKCS8(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: []byte{0x04, 0x02, 0xde, 0xad},
	})
	require.NoError(t, err)
	return der
}

// synthPKIX builds a minimal SubjectPublicKeyInfo carrying oid.
func synthPKIX(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	der, err := asn1.Marshal(pkixStruct{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: []byte{0xde, 0xad, 0xbe, 0xef}, BitLength: 32},
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
	_, algo, err := c.unsupportedPKCS8PrivateKey(synthPKCS8(t, mlKEM768OID))
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
	key, algo, err := c.unsupportedPKIX(synthPKIX(t, mlKEM768OID))
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
	_, algo, err := c.unsupportedPKIX(synthPKIX(t,
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
