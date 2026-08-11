package cdxprops

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
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

// wantSignatureAlg is a hand-written expectation for one call to
// signatureAlgorithmComponents: the algorithm component's Name, the identity
// half of its bom-ref, the OID read out of the DER, and the name of the hash it
// decomposes into -- empty when it decomposes into none.
//
// The digest half of the bom-ref is deliberately not stated. BOMRefHash hashes
// the component's own JSON, which carries implementationPlatform, so the digest
// is a function of the machine the test runs on and pinning it here would pin
// GOARCH. What the two paths below share is asserted by comparing them to each
// other, digest included.
type wantSignatureAlg struct {
	name    string
	refName string
	oid     string
	hash    string
}

// ecdsaSHA256Components is the expectation a P-256 certificate and a revocation
// list signed by it must BOTH meet, stated once so that "both paths agree" and
// "both paths are right" are the same assertion.
var ecdsaSHA256Components = wantSignatureAlg{
	name:    "ECDSA-SHA256",
	refName: "crypto/algorithm/sha-256-ecdsa",
	oid:     "1.2.840.10045.4.3.2",
	hash:    "SHA-256",
}

// TestSignatureAlgorithmComponents_PinsAlgorithmAndHash writes down what the
// shared core puts in a document for a signed PKIX structure.
//
// Its predecessor asserted signatureAlgorithmComponents against
// certHitToSignatureAlgComponent, a one-line delegation to it. That equality
// holds for any body the pair could have -- one that names every algorithm
// "MUTANT", or ignores the OID fallback, or reads no OID at all -- so it went
// green under mutations of everything it appeared to cover. Values written by
// hand are the only ones that go red when the core is wrong.
//
// The three rows are chosen for the paths they reach. ECDSA is answered by Go's
// enum alone. Ed25519 is answered by the enum too and still decomposes into
// SHA-512, because RFC 8032 builds it on SHA-512 -- it is not the no-hash case,
// and two production comments used to say it was. ML-DSA is a real fixture
// whose algorithm Go's enum does not name, so its name, its ref and its
// parameters all have to come from the OID in the certificate's own DER, and it
// is the row with no hash. Its Name is the registry's algorithmName, ref path
// and all; that is what the code emits today, pinned as found.
func TestSignatureAlgorithmComponents_PinsAlgorithmAndHash(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		cert func(t *testing.T) *x509.Certificate
		want wantSignatureAlg
	}{
		"ECDSA": {
			cert: func(t *testing.T) *x509.Certificate {
				return certSignedWith(t, x509.ECDSAWithSHA256)
			},
			want: ecdsaSHA256Components,
		},
		"Ed25519": {
			cert: func(t *testing.T) *x509.Certificate {
				return certSignedWith(t, x509.PureEd25519)
			},
			want: wantSignatureAlg{
				name:    "Ed25519",
				refName: "crypto/algorithm/ed25519",
				oid:     "1.3.101.112",
				hash:    "SHA-512",
			},
		},
		"ML-DSA": {
			cert: mlDSA65Cert,
			want: wantSignatureAlg{
				name:    "crypto/algorithm/ml-dsa-65",
				refName: "crypto/algorithm/ml-dsa-65",
				oid:     "2.16.840.1.101.3.4.3.18",
				hash:    "",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cert := tt.cert(t)
			sigAlgCompo, hashAlgCompo := NewConverter().certHitToSignatureAlgComponent(
				t.Context(),
				model.CertHit{Cert: cert, Source: "cdxtest", Location: t.Name()},
			)
			requireSignatureAlgComponents(t, tt.want, sigAlgCompo, hashAlgCompo)
		})
	}
}

// TestSignatureAlgorithmComponents_CertificateAndCRLShareTheCore states the
// property the extraction was for: a certificate and a revocation list signed
// with the same algorithm describe that algorithm identically, down to the
// content-addressed bom-ref, because both hand the same two values -- the
// algorithm enum and the DER -- to one function.
//
// Equality alone would be satisfied by two identically wrong components, so
// both sides are also held to ecdsaSHA256Components. If crlToCDX ever passed
// something else -- the TBS bytes, the issuing certificate's algorithm, a
// constant -- one side moves and the pair of components in a document holding
// both a certificate and its CRL becomes two refs for one algorithm.
func TestSignatureAlgorithmComponents_CertificateAndCRLShareTheCore(t *testing.T) {
	t.Parallel()

	ca, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithSignatureAlgorithm(x509.ECDSAWithSHA256).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := ca.Key.(crypto.Signer)
	require.True(t, ok)

	crl, _, err := cdxtest.GenCRL(ca.Cert, signer)
	require.NoError(t, err)
	require.Equal(t, x509.ECDSAWithSHA256, crl.SignatureAlgorithm,
		"the list must be signed with the algorithm under test, or the two "+
			"paths are being compared on different inputs")

	c := NewConverter()
	certSig, certHash := c.certHitToSignatureAlgComponent(
		t.Context(),
		model.CertHit{Cert: ca.Cert, Source: "cdxtest", Location: t.Name()},
	)
	requireSignatureAlgComponents(t, ecdsaSHA256Components, certSig, certHash)

	compos, deps := c.crlToCDX(t.Context(), crl)
	var crlSig, crlHash cdx.Component
	for _, compo := range compos {
		if compo.CryptoProperties == nil || compo.CryptoProperties.AlgorithmProperties == nil {
			continue
		}
		if compo.CryptoProperties.AlgorithmProperties.Primitive == cdx.CryptoPrimitiveHash {
			crlHash = compo
			continue
		}
		crlSig = compo
	}
	requireSignatureAlgComponents(t, ecdsaSHA256Components, crlSig, &crlHash)

	require.Equal(t, certSig, crlSig,
		"one algorithm, one component: a list and a certificate signed the same "+
			"way must not produce two")
	require.Equal(t, *certHash, crlHash)

	require.Len(t, deps, 1)
	require.Equal(t, crlSig.BOMRef, deps[0].Ref)
	require.NotNil(t, deps[0].Dependencies)
	require.Equal(t, []string{crlHash.BOMRef}, *deps[0].Dependencies,
		"the edge must name the hash component the list actually carries")
}

// requireSignatureAlgComponents states want over one pair of returns from
// signatureAlgorithmComponents.
func requireSignatureAlgComponents(t *testing.T, want wantSignatureAlg, sigAlgCompo cdx.Component, hashAlgCompo *cdx.Component) {
	t.Helper()

	require.Equal(t, want.name, sigAlgCompo.Name)
	require.NotNil(t, sigAlgCompo.CryptoProperties)
	require.Equal(t, want.oid, sigAlgCompo.CryptoProperties.OID)

	refName, digest, found := strings.Cut(sigAlgCompo.BOMRef, "@")
	require.True(t, found, "a bom-ref is name@digest, got %q", sigAlgCompo.BOMRef)
	require.Equal(t, want.refName, refName)
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, digest)

	if want.hash == "" {
		require.Nil(t, hashAlgCompo, "%s decomposes into nothing", want.name)
		return
	}
	require.NotNil(t, hashAlgCompo, "%s decomposes into %s", want.name, want.hash)
	require.Equal(t, want.hash, hashAlgCompo.Name)
	require.Equal(t, "crypto/algorithm/"+strings.ToLower(want.hash),
		strings.Split(hashAlgCompo.BOMRef, "@")[0])
}

// certSignedWith generates a self-signed certificate carrying the given
// signature algorithm, and checks that it really carries it: CertBuilder falls
// back to RSA for anything it cannot key, which would silently turn a row of
// the table above into a second copy of the RSA row.
func certSignedWith(t *testing.T, algo x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	gen, err := cdxtest.CertBuilder{}.WithSignatureAlgorithm(algo).Generate()
	require.NoError(t, err)
	require.Equal(t, algo, gen.Cert.SignatureAlgorithm)
	return gen.Cert
}

// mlDSA65Cert loads the ML-DSA-65 certificate fixture. Go parses it and leaves
// SignatureAlgorithm at UnknownSignatureAlgorithm, which is the state that
// makes the OID in the DER the only thing left to identify the algorithm by.
func mlDSA65Cert(t *testing.T) *x509.Certificate {
	t.Helper()

	data, err := cdxtest.TestData(cdxtest.MLDSA65Certificate)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, x509.UnknownSignatureAlgorithm, cert.SignatureAlgorithm,
		"the fixture is here for the algorithm Go's enum does not name")
	return cert
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
