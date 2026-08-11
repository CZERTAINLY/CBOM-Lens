package cdxprops

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func Test_spkiOID(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := spkiOID(selfSigned.Cert)
	require.Equal(t, "1.2.840.113549.1.1.1", res)

	selfSigned.Cert.RawSubjectPublicKeyInfo = []byte("garbage")
	res = spkiOID(selfSigned.Cert)
	require.Equal(t, "", res)
}

func Test_readSignatureAlgorithmRef(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp := cdx.BOMReference("crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11")
	require.Equal(t, exp, res)

	selfSigned.Cert.SignatureAlgorithm = -1
	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "2.16.840.1.101.3.4.3.17")
	exp = cdx.BOMReference("crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17")
	require.Equal(t, exp, res)

	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp = cdx.BOMReference("crypto/algorithm/unknown@unknown")
	require.Equal(t, exp, res)

	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "0.0.0.0")
	exp = cdx.BOMReference("crypto/algorithm/unknown@unknown")
	require.Equal(t, exp, res)
}

func Test_sigAlgOID(t *testing.T) {
	t.Parallel()
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := sigAlgOID(selfSigned.Cert)
	require.Equal(t, "1.2.840.113549.1.1.11", res)

	selfSigned.Cert.Raw = []byte("broken")
	res = sigAlgOID(selfSigned.Cert)
	require.Equal(t, "", res)

}

func TestConverter_certConverter(t *testing.T) {
	t.Parallel()
	c := NewConverter().WithIlmExtensions(true)

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	compo := c.certComponent(t.Context(), model.CertHit{
		Cert:     selfSigned.Cert,
		Source:   "cdxtest",
		Location: t.Name(),
	})

	require.NotZero(t, compo)
}

// TestCertHitToComponents_NoMaterialPropsOnCertificate pins the removal of
// certificateRelatedProperties (#213).
//
// That helper created an empty relatedCryptoMaterialProperties on every
// certificate and wrote nothing into it, which is what produced the
// "relatedCryptoMaterialProperties": {} blocks in the goldens and made every
// certificate answer "yes" to "is this key material?". The certificate's own
// properties -- including the two refs certHitToComponents writes right after
// the deleted call -- must be untouched by its removal.
//
// This is deliberately at the certHitToComponents level rather than per
// caller. Every certificate in the tool comes through here: the PEM bundle via
// Converter.PEMBundle, a scanned file via Converter.CertHit, and a TLS service
// via Converter.NMAP -> tlsToCompos, which forwards TLSCerts to CertHit. So the
// deletion's whole blast radius is one function, pinned once. The golden corpus
// covers the emitted end of it, including a certificate lifted from the nmap
// fixture (see buildRepresentativeCorpus in internal/bom).
func TestCertHitToComponents_NoMaterialPropsOnCertificate(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	compos, _, err := NewConverter().certHitToComponents(
		t.Context(),
		model.CertHit{Cert: selfSigned.Cert, Source: "cdxtest", Location: t.Name()},
	)
	require.NoError(t, err)

	var found bool
	for _, compo := range compos {
		if compo.CryptoProperties == nil ||
			compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			continue
		}
		found = true

		require.Nil(t, compo.CryptoProperties.RelatedCryptoMaterialProperties,
			"a certificate is not key material: its encoding belongs in "+
				"certificateProperties.certificateFormat (#213)")

		certProps := compo.CryptoProperties.CertificateProperties
		require.NotNil(t, certProps)
		require.NotEmpty(t, certProps.SignatureAlgorithmRef)
		require.NotEmpty(t, certProps.SubjectPublicKeyRef)
	}
	require.True(t, found, "no certificate component emitted")
}

// TestPKCS8Struct_ParsesRFC5958TrailingFields pins the assumption that made it
// safe to add PrivateKey to pkcs8Struct.
//
// RFC 5958's OneAsymmetricKey extends RFC 5208's PrivateKeyInfo with two
// trailing optional elements, attributes [0] and publicKey [1]. pkcs8Struct
// declares neither, so if Go's asn1 rejected undeclared trailing elements the
// size check would reject every key encoded that way -- and the failure would
// be the exact one the check exists to prevent, only inverted: a real key
// reported as absent.
//
// It does not: encoding/asn1 tolerates extra elements at the end of a SEQUENCE
// so sequences can be extended. The three corpus fixtures do not exercise this
// (all three unmarshal with zero trailing bytes), so it is pinned explicitly
// here rather than left to a fixture that might be regenerated.
func TestPKCS8Struct_ParsesRFC5958TrailingFields(t *testing.T) {
	t.Parallel()

	body := make([]byte, 4032)
	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"tag:1,optional"`
	}{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}},
		PrivateKey: body,
		PublicKey:  asn1.BitString{Bytes: make([]byte, 1952), BitLength: 1952 * 8},
	})
	require.NoError(t, err)

	var pkcs8 pkcs8Struct
	rest, err := asn1.Unmarshal(der, &pkcs8)
	require.NoError(t, err, "a OneAsymmetricKey encoding must still parse")
	require.Empty(t, rest)
	require.Equal(t, "2.16.840.1.101.3.4.3.18", pkcs8.Algo.Algorithm.String())
	require.Len(t, pkcs8.PrivateKey, len(body),
		"the trailing publicKey must not bleed into the measured body")

	// And it must survive the size check rather than be discarded as too small.
	key, algo, err := NewConverter().unsupportedPKCS8PrivateKey(t.Context(), der)
	require.NoError(t, err)
	require.Equal(t, "ML-DSA-65", algo.Name)
	require.NotNil(t, key, "a full-size body must yield a key component")
	require.NotEmpty(t, key.BOMRef)
}

func Test_hashRawPublicKey(t *testing.T) {
	t.Parallel()
	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.Equal(t, "PUBLIC KEY", block.Type)

	c := NewConverter()
	value, hash := c.hashRawPublicKey(block.Bytes)
	require.NotEmpty(t, value)
	require.Equal(t, cdxtest.MLDSA65PublicKeyHash, hash)
}
