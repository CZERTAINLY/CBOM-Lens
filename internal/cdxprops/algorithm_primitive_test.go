package cdxprops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"

	"github.com/stretchr/testify/require"
)

// selfSignedCertFor builds a self-signed certificate over an already-generated
// key pair. It takes the public and private halves separately because Ed25519's
// public half is a value and RSA's and ECDSA's are pointers, and the callers
// below care only that the certificate carries the key they generated.
func selfSignedCertFor(t *testing.T, pub crypto.PublicKey, priv crypto.Signer, cn string) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0).UTC(),
		NotAfter:     time.Unix(1<<31, 0).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestAlgorithmInfo_EveryClassicalAlgorithmStatesItsOwnPrimitive pins the
// primitive of each classical algorithm at the one place that now decides it.
//
// #217 took the primitive out of publicKeyComponents, where it had been derived
// from the certificate's KeyUsage, and put it in extractAlgorithmInfo, where the
// algorithm is named. Doing so turned four adjacent, near-identical
// `meta.primitive = ...` lines into four independent facts, and made each of
// them a place a copy-paste slip can land unnoticed.
//
// Three of the four had no test behind them and the fourth had none at all.
// Setting DSA's primitive to pke passed the entire suite, because no DSA
// certificate is in the golden corpus and nothing else asserted it. Setting
// ECDSA's or Ed25519's to pke was caught only by the two goldens, which fail
// with a raw byte diff that names no rule and tells a reader nothing about which
// invariant broke.
//
// Each row states the value twice, and the two assertions fail for different
// reasons. The algorithmInfo assertion is the RULE: it fails when the registry
// branch is wrong. The component assertion is what a consumer actually reads: it
// fails when a producer stops routing through algorithmPrimitive, which is how
// the private-key path came to emit no primitive at all before this fix.
func TestAlgorithmInfo_EveryClassicalAlgorithmStatesItsOwnPrimitive(t *testing.T) {
	t.Parallel()

	// RSA is pke and everything else here is signature, which is the schemas'
	// own pairing: bom-1.6.schema.json describes pke as "public-key encryption
	// schemes (pke, e.g. RSA)" and signature as "signatures (e.g. ECDSA)".
	for name, tt := range map[string]struct {
		key  func(t *testing.T) (x509.PublicKeyAlgorithm, crypto.PublicKey, *x509.Certificate)
		want cdx.CryptoPrimitive
	}{
		"RSA": {
			key: func(t *testing.T) (x509.PublicKeyAlgorithm, crypto.PublicKey, *x509.Certificate) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return x509.RSA, &k.PublicKey, selfSignedCertFor(t, &k.PublicKey, k, "rsa.example")
			},
			want: cdx.CryptoPrimitivePKE,
		},
		"ECDSA": {
			key: func(t *testing.T) (x509.PublicKeyAlgorithm, crypto.PublicKey, *x509.Certificate) {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return x509.ECDSA, &k.PublicKey, selfSignedCertFor(t, &k.PublicKey, k, "ecdsa.example")
			},
			want: cdx.CryptoPrimitiveSignature,
		},
		"Ed25519": {
			key: func(t *testing.T) (x509.PublicKeyAlgorithm, crypto.PublicKey, *x509.Certificate) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return x509.Ed25519, pub, selfSignedCertFor(t, pub, priv, "ed25519.example")
			},
			want: cdx.CryptoPrimitiveSignature,
		},
		// DSA cannot be generated into a certificate by crypto/x509 -- it
		// signs nothing since Go 1.16 -- so the one committed DSA key is
		// grafted into a certificate as its subjectPublicKeyInfo, exactly the
		// way TestPublicKeyComponents_DSACertificateStillYieldsItsKey does it.
		"DSA": {
			key: func(t *testing.T) (x509.PublicKeyAlgorithm, crypto.PublicKey, *x509.Certificate) {
				data, err := cdxtest.TestData(cdxtest.DSA2048PublicKey)
				require.NoError(t, err)
				block, _ := pem.Decode(data)
				require.NotNil(t, block)
				cert := certWithSPKI(t, block.Bytes)
				require.Equal(t, x509.DSA, cert.PublicKeyAlgorithm,
					"the fixture must still be DSA, or this row tests something else")
				return x509.DSA, cert.PublicKey, cert
			},
			want: cdx.CryptoPrimitiveSignature,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			alg, pub, cert := tt.key(t)

			info := publicKeyAlgorithmInfo(alg, pub)
			require.Equal(t, tt.want, info.primitive,
				"the primitive is a property of the algorithm and is established "+
					"where the algorithm is named")

			algo, _ := NewConverter().publicKeyComponents(t.Context(), alg, pub, cert.RawSubjectPublicKeyInfo)
			require.NotNil(t, algo.CryptoProperties)
			require.NotNil(t, algo.CryptoProperties.AlgorithmProperties)
			require.Equal(t, tt.want, algo.CryptoProperties.AlgorithmProperties.Primitive,
				"the emitted component must carry the algorithm's own primitive, "+
					"or some producer has stopped taking it from algorithmPrimitive")
		})
	}
}

// TestAlgorithmPrimitive_UnknownPlaceholderFallbackIsLoadBearing pins the one
// branch of algorithmPrimitive that no other test reaches: the fallback taken by
// an algorithmInfo that states no primitive.
//
// Only extractAlgorithmInfo's Unknown placeholder reaches it -- every registry
// entry states its own primitive and every classical branch now does too -- and
// the fallback exists for a single stated reason: it reproduces the value this
// package emitted before #217, so the Unknown asset's bom-ref does not move. A
// bom-ref is a hash of the component, so "the fallback is only a default" is
// false; it is part of an identity that downstream documents already reference.
//
// Nothing asserted this. Changing `return cdx.CryptoPrimitiveSignature` to
// `return ""` passed the whole suite -- including both goldens, which carry no
// Unknown algorithm asset -- while silently rewriting the ref of every X25519
// certificate's algorithm component in every delivered document.
//
// The last assertion is the one that says WHY the fallback is not cosmetic: the
// same component built without it hashes to a different ref. If that assertion
// ever fails, primitive has stopped being part of the hashed contents and the
// fallback really has become a default, which would be worth knowing.
//
// This test asserts what the code does, not what it should do. The Unknown
// placeholder calling itself a signature scheme is wrong -- X25519 reaches this
// branch and is a key-agreement algorithm -- and the production comment says so
// and defers the fix. When that thread lands, this test is what it has to
// change, deliberately and with the goldens.
func TestAlgorithmPrimitive_UnknownPlaceholderFallbackIsLoadBearing(t *testing.T) {
	t.Parallel()

	info := extractAlgorithmInfo("Unknown", nil)
	require.Empty(t, info.primitive,
		"nothing named this algorithm, so the placeholder states no primitive")
	require.Equal(t, cdx.CryptoPrimitiveSignature, algorithmPrimitive(info),
		"the fallback reproduces the value emitted before #217")

	// RFC 7748 sec. 6.1: an X25519 public key is 32 bytes. crypto/x509 knows the
	// OID and deliberately leaves it out of getPublicKeyAlgorithmFromOID, so
	// this is a real certificate that reaches the placeholder.
	cert := certWithSPKI(t, synthPKIXBody(t, x25519OID, 32))
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, cert.PublicKeyAlgorithm)

	c := NewConverter()
	algo, _ := c.publicKeyComponents(t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert.RawSubjectPublicKeyInfo)

	require.Equal(t, "Unknown", algo.Name)
	require.NotNil(t, algo.CryptoProperties)
	require.NotNil(t, algo.CryptoProperties.AlgorithmProperties)
	// This asserted "signature" when it was written, and said in its own
	// comment that the thread fixing the placeholder is what would have to
	// change it. That thread landed: publicKeyComponents no longer lets the
	// fallback decide what an unnameable algorithm does. It reads the OID off
	// the SubjectPublicKeyInfo -- which is present whether or not a
	// certificate carried it -- and states "unknown" rather than claiming a
	// key-agreement algorithm signs.
	//
	// The fallback itself is untouched and still asserted above, because it is
	// still what algorithmPrimitive returns for an info stating no primitive.
	// What changed is that no producer now hands it one: this is the branch
	// that used to, and the assertions below say it stopped.
	require.Equal(t, cdx.CryptoPrimitiveUnknown,
		algo.CryptoProperties.AlgorithmProperties.Primitive,
		"an algorithm nothing names states no primitive rather than a false one")
	require.Equal(t, "1.3.101.110", algo.CryptoProperties.OID,
		"the SPKI says which algorithm this is, so the sentinel is not published")

	// The same component, built the same way, minus the primitive. This says
	// the primitive is INSIDE the digest, which is why neither the fallback
	// nor the value above is cosmetic: a bom-ref is a hash of the component,
	// and downstream documents already reference it.
	//
	// It isolates the primitive deliberately. Comparing against the untouched
	// placeholder info would differ in the OID too -- which this change also
	// moved -- and would then prove nothing about the primitive in particular.
	withPrimitive := info
	withPrimitive.oid = algo.CryptoProperties.OID
	withoutPrimitive := withPrimitive.componentWOBomRef(false)
	c.BOMRefHash(&withoutPrimitive, info.algorithmName)

	withPrimitive.primitive = cdx.CryptoPrimitiveUnknown
	stated := withPrimitive.componentWOBomRef(false)
	setAlgorithmPrimitive(&stated, algorithmPrimitive(withPrimitive))
	c.BOMRefHash(&stated, info.algorithmName)

	require.NotEqual(t, withoutPrimitive.BOMRef, stated.BOMRef,
		"the primitive is inside the digest, so what this branch states about an "+
			"unnameable algorithm is part of that asset's identity")
	require.Equal(t, stated.BOMRef, algo.BOMRef,
		"and the ref the producer emitted is the one that identity predicts")
}
