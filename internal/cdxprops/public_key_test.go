package cdxprops

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // a DSA certificate is the branch's one live classical user
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	"github.com/stretchr/testify/require"
)

// mlDSA65OID is id-ml-dsa-65 = { sigAlgs(2.16.840.1.101.3.4.3) 18 }, registered
// in the NIST CSOR. Its sibling mlKEM768OID lives in ml_kem_test.go.
var mlDSA65OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

// x25519OID is id-X25519, RFC 8410 sec. 3. crypto/x509 declares it
// (oidPublicKeyX25519, x509.go:493) and deliberately leaves it out of
// getPublicKeyAlgorithmFromOID's switch, so a certificate carrying it parses
// with PublicKeyAlgorithm == UnknownPublicKeyAlgorithm and PublicKey nil -- an
// unknown algorithm that is nonetheless a real one.
var x25519OID = asn1.ObjectIdentifier{1, 3, 101, 110}

// xmssOID is id-alg-xmss-hashsig, RFC 9802 sec. 4.2. It is the third kind of
// algorithm the guard has to tell apart, and the only one the registry NAMES
// without stating a public key size: RFC 9802 puts the parameter set in the
// key value rather than the OID, so registryPublicKeyBodySize returns 0 and the
// length comparison has nothing to compare. Its sibling in the external test
// package lives in pqc_body_shape_test.go.
var xmssOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 34}

// TestCertWithSPKI_GoAcceptsAnUnknownAlgorithmSPKI is the executable half of the
// reason publicKeyComponents needs a body check at all.
//
// The claim it pins is about crypto/x509, not about this package:
// x509.ParseCertificate reads the subjectPublicKey BIT STRING structurally,
// finds an algorithm OID its enum does not name, leaves PublicKey nil and
// returns SUCCESSFULLY -- it never looks at the body. Everything downstream
// therefore receives a certificate that Go vouched for, carrying four bytes of
// garbage where a 1952-byte ML-DSA-65 public key belongs, and
// RawSubjectPublicKeyInfo holding them.
//
// If this test ever fails because ParseCertificate started rejecting such a
// certificate, the guard in publicKeyComponents is unreachable and the tests
// below are testing nothing.
func TestCertWithSPKI_GoAcceptsAnUnknownAlgorithmSPKI(t *testing.T) {
	t.Parallel()

	spki := synthPKIXBody(t, mlDSA65OID, 4)

	der, err := cdxtest.CertWithSPKI(spki)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err,
		"Go must accept this certificate, or nothing downstream can ever see it")

	require.Equal(t, x509.UnknownPublicKeyAlgorithm, cert.PublicKeyAlgorithm,
		"getPublicKeyAlgorithmFromOID knows RSA, DSA, ECDSA and Ed25519 and nothing else")
	require.Nil(t, cert.PublicKey,
		"parsePublicKey is not called for an unknown algorithm, so nothing has "+
			"looked at these bytes")
	require.Equal(t, spki, cert.RawSubjectPublicKeyInfo,
		"the raw SPKI is captured before the algorithm is looked at, and it is "+
			"what publicKeyComponents publishes as key material")

	// And the signature algorithm is a real, unrelated one, so an assertion
	// about "the ML-DSA-65 algorithm component" downstream cannot be satisfied
	// by the algorithm this certificate was signed with.
	require.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}

func TestConverter_publicKeyComponents(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.MLDSA65Certificate)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	c := NewConverter()
	algo, key := c.publicKeyComponents(t.Context(), -1, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

	require.Equal(t, "ML-DSA-65", algo.Name)
	require.Equal(t, "ML-DSA-65", key.Name)
}

// selfSignedRSACert builds an RSA certificate with the given KeyUsage over a
// freshly generated key. It exists so that the several KeyUsage values a
// certificate can declare are all reachable without committing a fixture for
// each.
func selfSignedRSACert(t *testing.T, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return rsaCertForKey(t, key, usage)
}

// rsaCertForKey is the half of selfSignedRSACert that does not generate a key,
// split out because the interesting statements are about ONE key certified
// several ways: a fresh key per certificate cannot tell "the algorithm asset is
// a function of the key" apart from "the algorithm asset is a function of
// nothing the certificate carries".
//
// usage == 0 is a supported input and not a degenerate one: x509.CreateCertificate
// omits the keyUsage extension entirely for it, which is the shape of every
// certificate that declines to constrain its key.
func rsaCertForKey(t *testing.T, key *rsa.PrivateKey, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "encipherment.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		KeyUsage:     usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// algorithmComponentOf picks the one algorithm asset out of compos, failing if
// there is not exactly one. Written as a search rather than an index because
// every producer under test returns its components in its own order, and an
// index would silently start asserting about a different component the day one
// of them appends something.
func algorithmComponentOf(t *testing.T, compos []cdx.Component) cdx.Component {
	t.Helper()

	var found []cdx.Component
	for _, compo := range compos {
		if compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
			found = append(found, compo)
		}
	}
	require.Len(t, found, 1, "expected exactly one algorithm component")
	return found[0]
}

// TestPublicKeyComponents_RSAAlgorithmIsAFunctionOfTheKeyNotTheCertificate is
// the primary statement of this fix at the producer level: a cryptographic
// primitive is a property of the ALGORITHM, so nothing a certificate declares
// about how it intends to use a key may reach the algorithm asset built from
// that key.
//
// publicKeyComponents used to read cert.KeyUsage and stamp "signature" onto the
// RSA algorithm component when the certificate signed and did not encipher, and
// "pke" otherwise -- BEFORE BOMRefHash digested the component. A bom-ref is a
// hash of the component's own contents, so one RSA-2048 key had one ref when
// found in a signing certificate and a different one when found in an
// encipherment certificate, a CSR or a bare PUBLIC KEY block; Builder's
// first-wins dedup then made which of the two survived depend on the order the
// detections happened to arrive in.
//
// "pke" is the schema's own worked example for RSA (bom-1.6.schema.json:5079
// names pke "public-key encryption schemes (pke, e.g. RSA)" and signature "e.g.
// ECDSA"), and the specification's 1.7 certificate conformance fixture gives a
// TLS leaf's rsaEncryption asset "pke" while carrying the signing fact on the
// separate SHA512withRSA asset. That separate asset is why nothing is lost: this
// package already emits crypto/algorithm/sha-256-rsa with primitive "signature"
// for exactly the certificates whose KeyUsage the old branch was reading.
//
// The zero-usage row is not filler. It is the only row that reached the "else"
// arm of the old branch without any keyUsage extension at all, so a
// reintroduction that reads the extension only when present still fails here.
func TestPublicKeyComponents_RSAAlgorithmIsAFunctionOfTheKeyNotTheCertificate(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	usages := []struct {
		name  string
		usage x509.KeyUsage
	}{
		{"no keyUsage extension", 0},
		{"digitalSignature", x509.KeyUsageDigitalSignature},
		{"keyEncipherment", x509.KeyUsageKeyEncipherment},
		{"signing CA", x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
	}

	c := NewConverter()
	var first cdx.Component
	for i, u := range usages {
		cert := rsaCertForKey(t, key, u.usage)
		algo, _ := c.publicKeyComponents(t.Context(), x509.RSA, &key.PublicKey, cert.RawSubjectPublicKeyInfo)

		require.NotNil(t, algo.CryptoProperties)
		require.NotNil(t, algo.CryptoProperties.AlgorithmProperties)
		require.Equal(t, cdx.CryptoPrimitivePKE,
			algo.CryptoProperties.AlgorithmProperties.Primitive,
			"%s: RSA is a public-key encryption scheme whatever this certificate "+
				"permits its key to do", u.name)

		if i == 0 {
			first = algo
			continue
		}
		require.Equal(t, first, algo,
			"%s: one key must yield one algorithm asset, and a bom-ref is a hash "+
				"of the component, so any KeyUsage-derived field here splits the "+
				"asset in two", u.name)
	}
	require.NotEmpty(t, first.BOMRef, "the loop must have run")
}

// TestRSAAlgorithmAsset_IsOneAssetWhicheverProducerBuiltIt widens the statement
// above from one producer to all four that can describe an RSA key.
//
// Two of them disagreed. publicKeyComponents derived the primitive from
// KeyUsage (see the test above), and Converter.PrivateKey set no primitive at
// all -- so the committed golden corpus carried the same RSA-2048 key twice,
// as crypto/algorithm/rsa-2048@0e37c10e-... from the certificate and
// @a11419cf-... from the private key in the very same scan, differing in
// nothing but the presence of the field.
//
// Equality is asserted over the WHOLE component and not only over the ref. Two
// components that agree on a content-hashed ref necessarily agree on everything
// the hash covers, so a ref-only assertion is the weaker half of the same claim;
// stating it over the component says which field moved when it fails.
func TestRSAAlgorithmAsset_IsOneAssetWhicheverProducerBuiltIt(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := rsaCertForKey(t, key,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.example"}}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	c := NewConverter()

	fromCertificate, _ := c.publicKeyComponents(t.Context(), x509.RSA, &key.PublicKey, cert.RawSubjectPublicKeyInfo)

	csrCompos, _, _ := c.csrToCDX(t.Context(), csr)
	fromCSR := algorithmComponentOf(t, csrCompos)

	fromBarePublicKey, _ := c.publicKeyComponents(t.Context(), x509.RSA, &key.PublicKey, nil)

	fromPrivateKey, _ := c.PrivateKey(t.Context(), "fixture-id", key)

	for name, got := range map[string]cdx.Component{
		"certificate signing key": fromCSR,
		"bare PUBLIC KEY block":   fromBarePublicKey,
		"private key":             fromPrivateKey,
	} {
		require.Equal(t, fromCertificate, got,
			"%s: the same RSA key must produce the same algorithm asset as the "+
				"certificate path, or the document carries one asset under two "+
				"refs and the Builder picks by arrival order", name)
	}
}

// TestCertHitToComponents_KeyUsageMovesNoContentHashedRef states the constraint
// that makes the certificate component the only legal home for the KeyUsage
// fact this fix takes off the algorithm.
//
// Of the three refs a certificate detection mints, two are content hashes of
// something KeyUsage does not belong to and one is a hash of the certificate's
// own DER. The algorithm ref is a BOMRefHash over the marshalled component, so
// anything KeyUsage-derived stamped there moves it -- that IS the defect. The
// key ref is a digest of the marshalled SPKI, which KeyUsage is not part of, so
// a KeyUsage-derived field on the key component would leave two DIFFERENT
// components sharing one ref and let Builder's first-wins pick between them: the
// defect moved rather than removed, and invisible to any test that compares refs
// alone, which is why the key COMPONENTS are compared here and not just their
// refs. The certificate ref is a pure function of cert.Raw, and the keyUsage
// extension is inside cert.Raw, so a keyUsage-derived value there is
// order-independent by construction -- the same argument
// mergeCertificateSourceFormat already makes for base64_content and fingerprint.
func TestCertHitToComponents_KeyUsageMovesNoContentHashedRef(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signing := rsaCertForKey(t, key,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
	encipherment := rsaCertForKey(t, key, x509.KeyUsageKeyEncipherment)

	c := NewConverter()

	pick := func(cert *x509.Certificate) (algo, keyCompo, certCompo cdx.Component) {
		compos, _, err := c.certHitToComponents(t.Context(), model.CertHit{Cert: cert})
		require.NoError(t, err)
		for _, compo := range compos {
			switch {
			case strings.HasPrefix(compo.BOMRef, "crypto/algorithm/rsa-"):
				algo = compo
			case strings.HasPrefix(compo.BOMRef, "crypto/key/rsa-"):
				keyCompo = compo
			case strings.HasPrefix(compo.BOMRef, "crypto/certificate/"):
				certCompo = compo
			}
		}
		require.NotEmpty(t, algo.BOMRef)
		require.NotEmpty(t, keyCompo.BOMRef)
		require.NotEmpty(t, certCompo.BOMRef)
		return
	}

	signAlgo, signKey, signCert := pick(signing)
	encAlgo, encKey, encCert := pick(encipherment)

	require.Equal(t, signAlgo, encAlgo,
		"the algorithm ref is a hash of the algorithm component, so the two "+
			"certificates must contribute the identical component")
	require.Equal(t, signKey, encKey,
		"the key ref is a digest of the SPKI alone, so two key components under "+
			"that one ref must be identical -- otherwise which one the document "+
			"carries is decided by arrival order")

	require.NotEqual(t, signCert.BOMRef, encCert.BOMRef,
		"two different certificates are two different assets")
	for _, cert := range []*x509.Certificate{signing, encipherment} {
		digest := sha256.Sum256(cert.Raw)
		require.Contains(t,
			[]string{signCert.BOMRef, encCert.BOMRef},
			"crypto/certificate/"+cert.Subject.CommonName+"@sha256:"+hex.EncodeToString(digest[:]),
			"a certificate ref is a pure function of its own DER, which is what "+
				"makes a keyUsage-derived value on it order-independent")
	}
}

// TestAlgorithmAsset_PQCKeyIsOneAssetFromACertificateAndFromAPublicKeyBlock is
// green before this change and must stay green after it.
//
// The certificate path and the `PUBLIC KEY` path resolve the same registry
// entry by the same OID, build the component with the same
// componentWOBomRef, take the primitive from the same helper and hash with the
// same algorithmName -- byte-identical, hence one ref. Unifying the primitive
// rule across producers is exactly the kind of refactor that can update one of
// two lockstep constructions and leave the other, and nothing else in the
// package compares these two call sites.
//
// The ML-KEM row is the one that says the rule is the registry's and not a
// hardcoded default: an encapsulation key reported as a signature scheme is the
// defect algorithmPrimitive was written to close, and a "just always say pke for
// anything non-signing" simplification of this fix fails here.
func TestAlgorithmAsset_PQCKeyIsOneAssetFromACertificateAndFromAPublicKeyBlock(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		certFixture string
		keyFixture  string
		algo        string
		primitive   cdx.CryptoPrimitive
	}{
		"ML-DSA-65": {
			cdxtest.MLDSA65Certificate, cdxtest.MLDSA65PublicKey,
			"ML-DSA-65", cdx.CryptoPrimitiveSignature,
		},
		"ML-KEM-768": {
			cdxtest.MLKEM768Certificate, cdxtest.MLKEM768PublicKey,
			"ML-KEM-768", cdx.CryptoPrimitiveKEM,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := NewConverter()

			certPEM, err := cdxtest.TestData(tt.certFixture)
			require.NoError(t, err)
			certBlock, _ := pem.Decode(certPEM)
			require.NotNil(t, certBlock)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)
			fromCertificate, _ := c.publicKeyComponents(
				t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

			keyPEM, err := cdxtest.TestData(tt.keyFixture)
			require.NoError(t, err)
			keyBlock, _ := pem.Decode(keyPEM)
			require.NotNil(t, keyBlock)
			require.Equal(t, "PUBLIC KEY", keyBlock.Type)
			_, fromPublicKeyBlock, err := c.unsupportedPKIX(t.Context(), keyBlock.Bytes)
			require.NoError(t, err)

			require.Equal(t, tt.algo, fromCertificate.Name)
			require.Equal(t, tt.primitive,
				fromCertificate.CryptoProperties.AlgorithmProperties.Primitive,
				"the registry states this algorithm's primitive and nothing else may")
			require.Equal(t, fromCertificate, fromPublicKeyBlock,
				"one key seen twice, through two producers, is one asset")
		})
	}
}

// TestCertHitToComponents_RSAAlgorithmIsPKEWhateverTheKeyUsage covers the
// classical half of the primitive-overwrite defect, over the whole
// certHitToComponents path rather than over publicKeyComponents alone.
//
// certHitToComponents used to re-stamp "signature" onto every algorithm
// component it had been handed, AFTER publicKeyComponents had hashed them, which
// left a bom-ref describing contents the component no longer had. The
// keyEncipherment row guards that regression and always did.
//
// Its stated RULE was wrong, and that is what the second row corrects: "an RSA
// key whose KeyUsage is keyEncipherment only is classified as pke" implies the
// classification depends on the KeyUsage. It does not. RSA is a public-key
// encryption scheme, so both rows expect pke, and a re-stamp reintroduced only
// for the signing case would now be caught here too.
func TestCertHitToComponents_RSAAlgorithmIsPKEWhateverTheKeyUsage(t *testing.T) {
	t.Parallel()

	for name, usage := range map[string]x509.KeyUsage{
		"keyEncipherment":  x509.KeyUsageKeyEncipherment,
		"digitalSignature": x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cert := selfSignedRSACert(t, usage)

			compos, _, err := NewConverter().certHitToComponents(t.Context(), model.CertHit{Cert: cert})
			require.NoError(t, err)

			var found bool
			for _, compo := range compos {
				if compo.CryptoProperties == nil ||
					compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm ||
					!strings.HasPrefix(compo.Name, "RSA-") {
					continue
				}
				require.NotNil(t, compo.CryptoProperties.AlgorithmProperties)
				require.Equal(t, cdx.CryptoPrimitivePKE,
					compo.CryptoProperties.AlgorithmProperties.Primitive,
					"an rsaEncryption key is a public-key encryption scheme; the "+
						"signing fact rides on the separate sha-256-rsa asset")
				found = true
			}
			require.True(t, found, "no RSA algorithm component emitted for the certificate")
		})
	}
}

// TestCertHitToComponents_BOMRefsMatchContents is the general form of the same
// defect: a BOMRef is a hash of the component it names, so mutating a component
// after BOMRefHash has run leaves a reference that no longer describes its own
// contents. Re-hashing every emitted component must reproduce its BOMRef.
func TestCertHitToComponents_BOMRefsMatchContents(t *testing.T) {
	t.Parallel()

	for name, cert := range map[string]*x509.Certificate{
		"rsa keyEncipherment": selfSignedRSACert(t, x509.KeyUsageKeyEncipherment),
		"rsa digitalSignature": selfSignedRSACert(t,
			x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := NewConverter()
			compos, _, err := c.certHitToComponents(t.Context(), model.CertHit{Cert: cert})
			require.NoError(t, err)
			require.NotEmpty(t, compos)

			// Counted so a ref-naming change cannot make this test vacuously
			// green: every component would be skipped and nothing asserted.
			var checked int
			for _, compo := range compos {
				// Only crypto/algorithm refs are hashes of the component JSON.
				// crypto/key and crypto/certificate refs hash the key or the
				// DER instead, so re-hashing the component cannot reproduce
				// them and they are out of scope here.
				refName, _, ok := strings.Cut(compo.BOMRef, "@")
				if !ok || !strings.HasPrefix(refName, "crypto/algorithm/") {
					continue
				}
				want := compo.BOMRef

				rehashed := compo
				c.BOMRefHash(&rehashed, refName)
				checked++
				require.Equal(t, want, rehashed.BOMRef,
					"%s: BOMRef does not match a re-hash of its own contents, "+
						"so the component was mutated after being hashed", compo.Name)
			}
			require.NotZero(t, checked,
				"no crypto/algorithm component was examined, so this test proved "+
					"nothing -- has the ref naming changed?")
		})
	}
}

// TestPublicKeyComponents_PQCKeysAreDistinct pins the fix for the collapse of
// every post-quantum key into one component.
//
// Go does not parse ML-DSA/ML-KEM/SLH-DSA public keys, so x509 leaves
// cert.PublicKey nil and MarshalPKIXPublicKey fails. hashPublicKey used to
// discard that error and return two empty strings, producing the bom-ref
// "crypto/key/<alg>@" with no digest for every PQC certificate. Builder keys
// components by bom-ref, so N distinct PQC keys merged into a single
// component and the key material was omitted entirely.
func TestPublicKeyComponents_PQCKeysAreDistinct(t *testing.T) {
	fixtures := []string{
		cdxtest.MLDSA65Certificate,
		cdxtest.SLHDSASHA2128sCertificate,
		cdxtest.MLKEM768Certificate,
	}

	conv := NewConverter()
	refs := make(map[string]string, len(fixtures))

	for _, f := range fixtures {
		raw, err := cdxtest.TestData(f)
		require.NoError(t, err)
		block, _ := pem.Decode(raw)
		require.NotNil(t, block, f)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, f)

		// Precondition: this is the situation being guarded against.
		require.Nil(t, cert.PublicKey, "%s: expected an unparseable PQC key", f)
		require.NotEmpty(t, cert.RawSubjectPublicKeyInfo, "%s: no SPKI to fall back to", f)

		_, key := conv.publicKeyComponents(t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

		require.False(t, strings.HasSuffix(key.BOMRef, "@"),
			"%s: bom-ref %q has an empty digest", f, key.BOMRef)
		require.NotEmpty(t, key.CryptoProperties.RelatedCryptoMaterialProperties.Value,
			"%s: key material was dropped", f)

		if prev, dup := refs[key.BOMRef]; dup {
			t.Fatalf("%s and %s collapsed into the same bom-ref %q", prev, f, key.BOMRef)
		}
		refs[key.BOMRef] = f
	}

	require.Len(t, refs, len(fixtures), "each PQC key must get its own component")
}

// certWithSPKI wraps cdxtest.CertWithSPKI and parses the result, which is where
// the interesting half of the claim lives: a certificate Go refuses never
// reaches publicKeyComponents, so a test built on one that does not parse would
// be measuring nothing.
func certWithSPKI(t *testing.T, spki []byte) *x509.Certificate {
	t.Helper()

	der, err := cdxtest.CertWithSPKI(spki)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err, "Go accepts an SPKI whose algorithm it does not know")
	return cert
}

// TestPublicKeyComponents_CertificateGarbageSPKIYieldsNoKey is the certificate
// half of the rule unsupportedPKIX already enforces for a `PUBLIC KEY` block.
//
// The same four bytes under the same OID were refused under a
// SubjectPublicKeyInfo in a PEM block and accepted under a CERTIFICATE, because
// the certificate path hashed cert.RawSubjectPublicKeyInfo without anything
// having looked at the body: Go leaves PublicKey nil for an algorithm its enum
// does not name and returns successfully, so the branch that publishes the raw
// SPKI as key material was the only reader those bytes ever had.
//
// The one-short and one-long rows are what make this an equality rather than a
// floor, for the reason spelled out on rejectPublicKeyBody: with the key encoded
// directly in the BIT STRING there is nothing to pad it with.
//
// Asserting the ALGORITHM comes out whole is load-bearing, not decoration. The
// obvious "why build what we are about to reject" refactor hoists the guard
// above setAlgorithmPrimitive and BOMRefHash; Builder.appendDetection drops a
// component with no bom-ref, so under that refactor the algorithm disappears
// too and a rejected certificate contributes nothing but itself -- the same
// silent loss this guard exists to prevent, moved one component over.
func TestPublicKeyComponents_CertificateGarbageSPKIYieldsNoKey(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		oid       asn1.ObjectIdentifier
		bodyLen   int
		algo      string
		dotted    string
		refPrefix string
	}{
		"ML-DSA-65 four bytes of garbage": {
			mlDSA65OID, 4, "ML-DSA-65",
			"2.16.840.1.101.3.4.3.18", "crypto/algorithm/ml-dsa-65@",
		},
		"ML-DSA-65 one byte short": {
			mlDSA65OID, 1951, "ML-DSA-65",
			"2.16.840.1.101.3.4.3.18", "crypto/algorithm/ml-dsa-65@",
		},
		"ML-DSA-65 one byte long": {
			mlDSA65OID, 1953, "ML-DSA-65",
			"2.16.840.1.101.3.4.3.18", "crypto/algorithm/ml-dsa-65@",
		},
		"ML-KEM-768 one byte short": {
			mlKEM768OID, 1183, "ML-KEM-768",
			"2.16.840.1.101.3.4.4.2", "crypto/algorithm/ml-kem-768@",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cert := certWithSPKI(t, synthPKIXBody(t, tt.oid, tt.bodyLen))
			require.Nil(t, cert.PublicKey,
				"the branch under test is the one Go's parser leaves empty")

			algo, key := NewConverter().publicKeyComponents(
				t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

			require.Nil(t, key,
				"a body that cannot be this algorithm's public key must not be "+
					"reported as one")

			require.Equal(t, tt.algo, algo.Name,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			require.NotNil(t, algo.CryptoProperties)
			require.Equal(t, tt.dotted, algo.CryptoProperties.OID)
			require.NotNil(t, algo.CryptoProperties.AlgorithmProperties,
				"an algorithm built after the rejection would have no properties")
			require.True(t, strings.HasPrefix(algo.BOMRef, tt.refPrefix),
				"Builder.appendDetection drops a component with no bom-ref, so a "+
					"rejected certificate would lose its algorithm too: got %q", algo.BOMRef)
		})
	}
}

// TestCertHitToComponents_RejectedKeyLeavesNoDanglingRef states what a whole
// certificate looks like once its key has been refused.
//
// Dropping a component is the easy half; the document has to stay internally
// consistent afterwards. Three things could go wrong and each is asserted: the
// zero Component could be appended anyway, and Builder.appendDetection would
// drop it with a warning that reads as a Builder failure (missingIdentity,
// builder.go:305-316); the certificate's subjectPublicKeyRef could still name
// the ref of a component that is no longer there; and a dependency edge could
// point at one.
//
// The certificate itself must survive. Its existence is established by its own
// DER and its algorithm reference by the OID, both true whatever the body holds
// -- dropping the whole certificate would delete a real asset and make a
// malformed key REDUCE the inventory.
func TestCertHitToComponents_RejectedKeyLeavesNoDanglingRef(t *testing.T) {
	t.Parallel()

	cert := certWithSPKI(t, synthPKIXBody(t, mlDSA65OID, 4))

	compos, deps, err := NewConverter().certHitToComponents(
		t.Context(),
		model.CertHit{Cert: cert, Source: "cdxtest", Location: t.Name()},
	)
	require.NoError(t, err)
	require.NotEmpty(t, compos)

	refs := make(map[string]struct{}, len(compos))
	var certCompo cdx.Component
	for _, compo := range compos {
		require.NotEmpty(t, compo.BOMRef,
			"%q has no bom-ref: Builder.appendDetection drops it and warns", compo.Name)
		require.NotEmpty(t, compo.Name,
			"%q has no name: same contract, other half", compo.BOMRef)
		require.False(t, strings.HasPrefix(compo.BOMRef, "crypto/key/"),
			"the key was refused, so no key asset may be emitted: %q", compo.BOMRef)
		refs[compo.BOMRef] = struct{}{}

		if compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			certCompo = compo
		}
	}

	require.NotEmpty(t, certCompo.BOMRef, "the certificate itself must survive")
	certProps := certCompo.CryptoProperties.CertificateProperties
	require.NotNil(t, certProps)
	require.Empty(t, certProps.SubjectPublicKeyRef,
		"an empty ref is absent; a ref naming a dropped component is dangling")

	require.NotEmpty(t, certProps.SignatureAlgorithmRef,
		"the certificate is still signed, whatever its subject key holds")
	require.Contains(t, refs, string(certProps.SignatureAlgorithmRef))

	for _, dep := range deps {
		require.Contains(t, refs, dep.Ref)
		require.NotNil(t, dep.Dependencies)
		for _, to := range *dep.Dependencies {
			require.Contains(t, refs, to,
				"a dependency edge must not name a component the document does not carry")
		}
	}
}

// TestPublicKeyComponents_RealPQCCertificatesStillYieldTheirKey is the other
// direction of the guard, over certificates OpenSSL wrote real keys into.
//
// Synthetic bodies cannot catch a check written against the wrong field or the
// wrong unit, because a test that sizes its input from the same wrong field
// agrees with itself. These three fixtures cannot be talked into agreeing:
// their BIT STRING content is 1952, 1184 and 32 bytes because a real key is in
// there.
func TestPublicKeyComponents_RealPQCCertificatesStillYieldTheirKey(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		fixture string
		algo    string
	}{
		"ML-DSA-65":         {cdxtest.MLDSA65Certificate, "ML-DSA-65"},
		"ML-KEM-768":        {cdxtest.MLKEM768Certificate, "ML-KEM-768"},
		"SLH-DSA-SHA2-128S": {cdxtest.SLHDSASHA2128sCertificate, "SLH-DSA-SHA2-128S"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err)
			block, _ := pem.Decode(data)
			require.NotNil(t, block)

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			require.Nil(t, cert.PublicKey,
				"this fixture reaches the guarded branch because Go cannot parse its key")

			algo, key := NewConverter().publicKeyComponents(
				t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

			require.Equal(t, tt.algo, key.Name)
			require.True(t, strings.HasPrefix(key.BOMRef,
				"crypto/key/"+strings.ToLower(tt.algo)+"@sha256:"),
				"got %q", key.BOMRef)

			relProps := key.CryptoProperties.RelatedCryptoMaterialProperties
			require.NotEmpty(t, relProps.Value,
				"a public key is not a secret and must be published")
			require.Equal(t, cdx.BOMReference(algo.BOMRef), relProps.AlgorithmRef)
		})
	}
}

// TestPublicKeyComponents_DSACertificateStillYieldsItsKey is the
// non-regression that matters most, because it is the only one whose subject is
// a REAL key travelling the guarded branch today.
//
// x509.MarshalPKIXPublicKey has no *dsa.PublicKey case (x509.go:135-137
// returns "unsupported public key type" for anything but RSA, ECDSA, Ed25519
// and ECDH), but parsePublicKey does parse DSA, so a DSA certificate arrives
// with a perfectly good key, fails hashPublicKey, and falls back to hashing its
// raw SPKI. That is the branch this change adds a length check to. It stays
// accepted because extractAlgorithmInfo never sets pqc for DSA, so
// registryPublicKeyBodySize is 0 and rejectPublicKeyBody has nothing to compare
// against -- but "the guard has nothing to say about DSA" is a claim about the
// registry, and nothing in this repository tested a DSA CERTIFICATE at all: the
// one DSA fixture is a standalone `PUBLIC KEY` block exercising the cert==nil
// arm.
//
// The three preconditions are load-bearing. Without them a certificate that
// silently stopped being DSA, or whose key Go started marshalling, would leave
// this test green while proving nothing about the branch.
//
// The certificate is built by putting the fixture's own SubjectPublicKeyInfo --
// which is exactly what the PEM body of a `PUBLIC KEY` block is -- where a
// certificate carries its subject key, so the key under test is a real
// 2048-bit DSA key and not a hand-poked struct field.
func TestPublicKeyComponents_DSACertificateStillYieldsItsKey(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.DSA2048PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "PUBLIC KEY", block.Type)

	cert := certWithSPKI(t, block.Bytes)

	c := NewConverter()

	require.Equal(t, x509.DSA, cert.PublicKeyAlgorithm,
		"the fixture must still be DSA, or this row tests something else")
	require.IsType(t, &dsa.PublicKey{}, cert.PublicKey,
		"Go parses DSA, so this branch is reached with a real key in hand")
	_, _, err = c.hashPublicKey(cert.PublicKey)
	require.Error(t, err,
		"a DSA certificate must still take the cert!=nil fallback, or this proves nothing")

	algo, key := c.publicKeyComponents(
		t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

	require.Equal(t, "DSA-2048", algo.Name)
	require.Equal(t, "DSA-2048", key.Name)
	require.True(t, strings.HasPrefix(key.BOMRef, "crypto/key/dsa-2048@sha256:"),
		"got %q", key.BOMRef)
	require.NotEmpty(t, key.CryptoProperties.RelatedCryptoMaterialProperties.Value)
}

// TestPublicKeyComponents_UnknownAlgorithmCertificateStillYieldsItsKey pins
// that the guard did not become a general "reject every key Go cannot parse".
//
// X25519 is the sharpest case available: crypto/x509 declares its OID
// (oidPublicKeyX25519) and deliberately leaves it out of
// getPublicKeyAlgorithmFromOID, so the certificate parses with PublicKey nil
// exactly like a post-quantum one -- but the registry has no entry for it, so
// there is no size to compare against and nothing to justify dropping the key.
// A 32-byte X25519 public key is a real key and must be reported as one, under
// the only name this package can give it.
func TestPublicKeyComponents_UnknownAlgorithmCertificateStillYieldsItsKey(t *testing.T) {
	t.Parallel()

	// RFC 7748 sec. 6.1: an X25519 public key is 32 bytes.
	cert := certWithSPKI(t, synthPKIXBody(t, x25519OID, 32))
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, cert.PublicKeyAlgorithm)
	require.Nil(t, cert.PublicKey)

	algo, key := NewConverter().publicKeyComponents(
		t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

	require.Equal(t, "Unknown", algo.Name,
		"the registry does not carry X25519, so this is the name the code gives it")
	require.Equal(t, "Unknown", key.Name)
	require.True(t, strings.HasPrefix(key.BOMRef, "crypto/key/unknown@sha256:"),
		"got %q", key.BOMRef)
	require.NotEmpty(t, key.CryptoProperties.RelatedCryptoMaterialProperties.Value,
		"with no size in the registry there is nothing to check, and dropping the key is worse")
}

// TestPublicKeyComponents_CertificateEmptySPKIBodyYieldsNoKey covers the one arm
// of rejectPublicKeyBody that the length comparison cannot stand in for, over
// the one input class where it is the ONLY thing standing between a certificate
// and an invented key asset.
//
// registryPublicKeyBodySize returns 0 for every algorithm the registry does not
// size -- everything outside it (X25519 here) and the three entries inside it
// that state no size (XMSS, XMSS-MT, HSS-LMS; RFC 9802 puts the parameters in
// the key value, not in the OID). For those the length comparison never fires,
// so `no encoding of any key is zero bytes` is the whole of the check. A
// certificate whose subjectPublicKey BIT STRING is empty parses: cryptobyte
// accepts `03 01 00` (one padding octet, no content), the algorithm OID is
// outside Go's enum so PublicKey is left nil, and the fallback branch then
// hashes an SPKI that carries no key at all -- publishing `crypto/key/...` over
// zero bytes of evidence.
//
// It is a separate test rather than rows on
// TestPublicKeyComponents_CertificateGarbageSPKIYieldsNoKey because it fails to
// a DIFFERENT mutant. Every row there is also refused by a length comparison
// written inline at this call site, which is precisely the "second opinion on
// one rule" rejectPublicKeyBody's doc comment exists to forbid; that refactor
// passes the whole package without these two rows.
func TestPublicKeyComponents_CertificateEmptySPKIBodyYieldsNoKey(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		oid       asn1.ObjectIdentifier
		algo      string
		refPrefix string
	}{
		// Outside the registry entirely: publicKeyAlgorithmInfo names it
		// Unknown and there is no entry to take a size from.
		"algorithm outside the registry": {
			x25519OID, "Unknown", "crypto/algorithm/unknown@",
		},
		// Inside the registry, deliberately unsized. This row is the family the
		// empty-body arm was written for.
		"registry entry that states no size": {
			xmssOID, "XMSS", "crypto/algorithm/xmss@",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cert := certWithSPKI(t, synthPKIXBody(t, tt.oid, 0))
			require.Nil(t, cert.PublicKey,
				"the branch under test is the one Go's parser leaves empty")

			spki, ok := spkiFromRaw(cert.RawSubjectPublicKeyInfo)
			require.True(t, ok)
			require.Empty(t, spki.PublicKey.Bytes,
				"precondition: Go really did hand on a certificate with no key in it")

			algo, key := NewConverter().publicKeyComponents(
				t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

			require.Nil(t, key,
				"an empty body cannot hold a key of any algorithm, sized or not")

			require.Equal(t, tt.algo, algo.Name,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			require.True(t, strings.HasPrefix(algo.BOMRef, tt.refPrefix),
				"Builder.appendDetection drops a component with no bom-ref, so a "+
					"rejected certificate would lose its algorithm too: got %q", algo.BOMRef)
		})
	}
}

// TestPublicKeyComponents_UnsizedAlgorithmCertificateStillYieldsItsKey is the
// other direction of the row above, and the reason the empty-body arm cannot
// simply be widened into "reject whatever the registry cannot size".
//
// XMSS is in the registry and carries no public key size, so nothing here can
// validate its body; refusing it would delete a real key from the inventory of
// exactly the hash-based schemes a PQC-readiness scanner exists to find.
//
// The one-byte row is the load-bearing one, and it is here because "with no
// size in the registry there is nothing to check" invites a floor: add
// `|| len(spki.PublicKey.Bytes) < 32` beside the guard as a minimum-plausible-key
// sanity check and every other certificate in this package still passes -- a DSA
// SPKI body runs to hundreds of bytes and an X25519 one is exactly 32. This is
// the only certificate row a floor at any threshold above one byte can reach,
// and its `PUBLIC KEY` sibling
// (TestPQCPipeline_PKIXUnsizedAlgorithmRejectsOnlyAnEmptyBody) cannot reach the
// certificate call site at all. The 68-byte row is a real XMSS-SHA2_10_256
// public key's length, so a check reintroduced against some specific number
// rather than a floor has to get past that too.
func TestPublicKeyComponents_UnsizedAlgorithmCertificateStillYieldsItsKey(t *testing.T) {
	t.Parallel()

	// One byte is the smallest body the empty-body arm lets through; 68 bytes is
	// the length of a real XMSS-SHA2_10_256 public key (RFC 8391 sec. 4.1.7:
	// oid || root || SEED, 4 + 32 + 32).
	for _, bodyLen := range []int{1, 68} {
		t.Run(fmt.Sprintf("%d byte body", bodyLen), func(t *testing.T) {
			t.Parallel()

			cert := certWithSPKI(t, synthPKIXBody(t, xmssOID, bodyLen))
			require.Nil(t, cert.PublicKey)

			algo, key := NewConverter().publicKeyComponents(
				t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

			require.Equal(t, "XMSS", key.Name)
			require.True(t, strings.HasPrefix(key.BOMRef, "crypto/key/xmss@sha256:"),
				"got %q", key.BOMRef)
			require.Equal(t, "1.3.6.1.5.5.7.6.34", key.CryptoProperties.OID)
			require.NotEmpty(t, key.CryptoProperties.RelatedCryptoMaterialProperties.Value,
				"with no size in the registry there is nothing to check, and dropping the key is worse")
			require.Equal(t, cdx.BOMReference(algo.BOMRef),
				key.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef)
		})
	}
}

// TestPublicKeyComponents_UndecodableCertificateSPKIYieldsNoKeyAndSaysWhy pins
// the branch above the body check: the one where spkiFromRaw could not decode the
// subjectPublicKeyInfo at all.
//
// Nothing that reaches this function through x509.ParseCertificate can trigger
// it -- the parser reads the same field with cryptobyte before handing the
// certificate on -- so the only way to state the claim is to corrupt
// RawSubjectPublicKeyInfo the way Test_spkiFromRaw already does, which is also the
// shape a future caller building an x509.Certificate by hand would arrive in.
//
// The MESSAGE is asserted, not merely the drop. Delete this branch, or let
// spkiFromRaw return its half-filled struct with ok=true, and the key is still
// dropped -- the zero pkixStruct's BIT STRING is empty, so the body check
// refuses it on the next line. What changes is the diagnosis the operator gets:
// "these bytes are not a SubjectPublicKeyInfo" becomes "this algorithm's public
// key is not 0 bytes long", which sends them looking at the key when the fault
// is in the structure around it. Without this test both edits pass the package.
//
// Not parallel: it swaps the process-wide slog default. Go resumes parallel
// tests only after the sequential ones finish, so staying sequential is the
// isolation.
func TestPublicKeyComponents_UndecodableCertificateSPKIYieldsNoKeyAndSaysWhy(t *testing.T) {
	data, err := cdxtest.TestData(cdxtest.DSA2048PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	// A DSA certificate is the only one that reaches the cert != nil fallback
	// with a key Go DID parse, so the corruption below is the only thing under
	// test: publicKeyAlgorithmInfo still names DSA-2048 off the parsed key,
	// and the OID fallback that reads the same decode is not involved.
	cert := certWithSPKI(t, block.Bytes)
	require.Equal(t, x509.DSA, cert.PublicKeyAlgorithm)
	cert.RawSubjectPublicKeyInfo = []byte("garbage")

	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	algo, key := NewConverter().publicKeyComponents(
		t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

	require.Nil(t, key,
		"bytes that are not a SubjectPublicKeyInfo are not evidence of a key")
	require.Equal(t, "DSA-2048", algo.Name,
		"the algorithm is established by the parsed key, not by the raw field")

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a dropped key at Debug level is a silently dropped key")
	require.Contains(t, logged, "subjectPublicKeyInfo could not be decoded",
		"an undecodable structure is a different fault from a wrong-sized body, "+
			"and the operator is told which one it was")
	require.Contains(t, logged, "algorithm=DSA-2048",
		"the operator has to know which key was dropped")
}
