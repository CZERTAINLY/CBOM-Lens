package cdxprops_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	pemlib "encoding/pem"
	"log/slog"
	"strings"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file is the public-key counterpart of pqc_body_shape_test.go, and it
// exists because only the private half ever got a body check. A
// SubjectPublicKeyInfo carrying the ML-DSA-65 OID and four bytes of garbage
// produced a full "an ML-DSA-65 public key exists here" component, silently,
// while the same four bytes under the same OID in a PKCS#8 wrapper had been
// refused since the private-key guard landed.
//
// The test it must pass is simpler than the private one, and deliberately so.
// RFC 9881 sec. 6 makes a PKCS#8 privateKey a CHOICE -- seed, expandedKey, or
// both -- so several lengths are legal and the encodings have to be enumerated.
// RFC 9881 sec. 4, and the SLH-DSA (RFC 9909 sec. 5) and ML-KEM (RFC 9935
// sec. 4) equivalents, put the encoded public key directly in the BIT STRING
// with no CHOICE at all. One algorithm, one legal length. So the cases below
// pin an EXACT match: one byte short and one byte long are both wrong, and
// there is no wrapper for a `derOctetStringOf`-style shape test to look at.

// The registry's public-key sizes in BYTES, from FIPS 204 Table 2, FIPS 205
// Table 2 and FIPS 203 Table 3. They are repeated here rather than read from
// the registry so that a test failure says the registry changed, instead of
// changing with it.
const (
	mlDSA65PubKey    = 1952
	mlKEM768EncapKey = 1184
	slhDSA128sPubKey = 32
)

// pkixDERBody builds a SubjectPublicKeyInfo carrying oid whose publicKey BIT
// STRING holds exactly body, so a test can state the length it means.
//
// The struct is declared here rather than reusing the production pkixStruct:
// this is an external test package, and pinning the wire shape the production
// code must read is the point. BitLength is set from body because a BIT STRING
// whose declared bit count disagrees with its content is a different defect
// from the one under test.
func pkixDERBody(t *testing.T, oid asn1.ObjectIdentifier, body []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: body, BitLength: len(body) * 8},
	})
	require.NoError(t, err)

	return der
}

// pemPublicKey wraps DER in a `PUBLIC KEY` block. Go's stdlib cannot parse a
// post-quantum SubjectPublicKeyInfo, so the scanner routes it to ParseErrors
// and the block reaches analyzeParseError -- the production path.
func pemPublicKey(der []byte) []byte {
	return pemlib.EncodeToMemory(&pemlib.Block{Type: "PUBLIC KEY", Bytes: der})
}

// assetsOfPub splits a detection's components by asset type, asserting the zero
// Component is never appended. It is assetsOf with a `PUBLIC KEY` envelope, kept
// separate so that no private-key test changes shape when this one does.
func assetsOfPub(t *testing.T, der []byte) (algorithms, material []cdx.Component) {
	t.Helper()

	return assetsOfPubPEM(t, pemPublicKey(der))
}

// assetsOfPubPEM is assetsOfPub taking the PEM bytes directly, so a real
// fixture file can travel the same path as a synthetic one.
func assetsOfPubPEM(t *testing.T, data []byte) (algorithms, material []cdx.Component) {
	t.Helper()

	bundle, err := pem.Scanner{}.Scan(t.Context(), data, "synthetic.pem")
	require.NoError(t, err, "the PEM envelope itself is well formed")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)

	for _, compo := range d.Components {
		require.NotNil(t, compo.CryptoProperties, "the zero Component must never be appended")
		switch compo.CryptoProperties.AssetType {
		case cdx.CryptoAssetTypeAlgorithm:
			algorithms = append(algorithms, compo)
		case cdx.CryptoAssetTypeRelatedCryptoMaterial:
			material = append(material, compo)
		}
	}

	return algorithms, material
}

// TestPQCPipeline_PKIXUndersizedBodyYieldsAlgorithmNotKey pins the bodies that
// cannot be the public key the OID names.
//
// The four-byte cases are the literal defect: that is the body every synthetic
// SubjectPublicKeyInfo in this package carried, and every one of them was
// reported as a fully formed public key. The one-byte-short and one-byte-long
// cases are what makes this an equality rather than a floor -- a floor would
// pass the long one, and would pass the short one at every threshold below the
// real size.
func TestPQCPipeline_PKIXUndersizedBodyYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		body []byte
	}{
		{"ML-DSA-65 four bytes of garbage", mlDSA65OID, noise(4)},
		{"ML-KEM-768 four bytes of garbage", mlKEM768OID, noise(4)},
		{"ML-DSA-65 one byte short", mlDSA65OID, noise(mlDSA65PubKey - 1)},
		{"ML-KEM-768 one byte short", mlKEM768OID, noise(mlKEM768EncapKey - 1)},
		// Too long is as wrong as too short: the BIT STRING is the key, with
		// no CHOICE and nothing to pad, so an extra byte means these are not
		// the bytes of an ML-DSA-65 public key.
		{"ML-DSA-65 one byte long", mlDSA65OID, noise(mlDSA65PubKey + 1)},
		{"SLH-DSA-SHA2-128S empty", slhDSA128sOID, nil},
		{"SLH-DSA-SHA2-128S one byte short", slhDSA128sOID, noise(slhDSA128sPubKey - 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			algorithms, material := assetsOfPub(t, pkixDERBody(t, tt.oid, tt.body))

			require.Len(t, algorithms, 1,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			require.Empty(t, material,
				"a body that is not this algorithm's public key must not be reported as one")
		})
	}
}

// TestPQCPipeline_PKIXRejectedBodyStillYieldsAUsableAlgorithm pins the half of
// the claim that survives a rejection. The OID establishes that the algorithm
// is referenced whatever the body holds, so the algorithm component still has
// to come out WHOLE -- not merely present.
//
// The rejection test above counts components, and a count cannot tell a usable
// algorithm from a broken one. Building the component before rejecting the body
// is load-bearing ordering: the obvious "why build what we are about to reject"
// refactor hoists the guard above setAlgorithmPrimitive and BOMRefHash, and
// leaves an algorithm with an empty primitive and no bom-ref.
// Builder.appendDetection drops a component that has no bom-ref, so under that
// refactor a rejected block contributes NOTHING to the CBOM -- the same silent
// disappearance this guard exists to prevent, moved one component over, and
// invisible to every assertion that only counts. That reordering passed the
// entire package before this test existed; each case below fails against it.
//
// The primitive is asserted per algorithm because registryPrimitive falls back
// to signature: an ML-KEM encapsulation key taking that fallback is reported as
// something that signs, which is the defect the fallback was added to stop.
func TestPQCPipeline_PKIXRejectedBodyStillYieldsAUsableAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		body      []byte
		dotted    string
		refPrefix string
		primitive cdx.CryptoPrimitive
	}{
		{
			name: "ML-DSA-65", oid: mlDSA65OID, body: noise(4),
			dotted: "2.16.840.1.101.3.4.3.18", refPrefix: "crypto/algorithm/ml-dsa-65@",
			primitive: cdx.CryptoPrimitiveSignature,
		},
		{
			name: "ML-KEM-768", oid: mlKEM768OID, body: noise(4),
			dotted: "2.16.840.1.101.3.4.4.2", refPrefix: "crypto/algorithm/ml-kem-768@",
			primitive: cdx.CryptoPrimitiveKEM,
		},
		// The unsized entries reach the same rejection through the empty-body
		// branch instead of the length comparison, so their algorithm has to
		// survive it too.
		{
			name: "XMSS", oid: xmssOID, body: nil,
			dotted: "1.3.6.1.5.5.7.6.34", refPrefix: "crypto/algorithm/xmss@",
			primitive: cdx.CryptoPrimitiveSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			algorithms, material := assetsOfPub(t, pkixDERBody(t, tt.oid, tt.body))

			require.Empty(t, material, "this body is not a key")
			require.Len(t, algorithms, 1)
			algo := algorithms[0]

			require.Equal(t, tt.name, algo.Name)
			require.Equal(t, tt.dotted, algo.CryptoProperties.OID,
				"the oid is what established the algorithm in the first place")
			require.NotNil(t, algo.CryptoProperties.AlgorithmProperties)
			require.Equal(t, tt.primitive, algo.CryptoProperties.AlgorithmProperties.Primitive,
				"a KEM reported as a signature scheme is a mislabel the rejection path must not reintroduce")
			require.True(t, strings.HasPrefix(string(algo.BOMRef), tt.refPrefix),
				"Builder.appendDetection drops a component with no bom-ref, so a rejected block would vanish from the CBOM entirely: got %q",
				algo.BOMRef)
		})
	}
}

// TestPQCPipeline_PKIXOneBadKeyDoesNotTakeTheGoodOneWithIt puts a garbage
// public key and a well-sized one in a single file.
//
// Every other case here holds one block, and a one-block file cannot tell "the
// offending key was dropped" from "the file produced nothing" -- both look like
// an empty material list. Over-application is the natural failure mode of any
// guard that drops a component, and PEM bundles are routinely concatenations,
// so the claim that has to hold is that the drop is per-KEY: the garbage under
// the ML-DSA-65 OID vanishes and the well-sized ML-KEM-768 key beside it is
// still reported, from the same file, in the same pass.
//
// It also pins that the block a rejection is applied to is the block it was
// read from -- restOfPEMBundleToCDX picks that by index, an index that only has
// to be right when there is more than one block. Pinning the OID of the
// surviving key rather than just counting is what makes that visible.
func TestPQCPipeline_PKIXOneBadKeyDoesNotTakeTheGoodOneWithIt(t *testing.T) {
	t.Parallel()

	var file []byte
	file = append(file, pemPublicKey(pkixDERBody(t, mlDSA65OID, noise(4)))...)
	file = append(file, pemPublicKey(pkixDERBody(t, mlKEM768OID, noise(mlKEM768EncapKey)))...)

	algorithms, material := assetsOfPubPEM(t, file)

	require.Len(t, material, 1, "exactly one of the two blocks carries a key")
	require.Equal(t, "ML-KEM-768", material[0].Name,
		"the surviving key must be the well-sized one, not the garbage under the ML-DSA-65 OID")

	names := make([]string, 0, len(algorithms))
	for _, algo := range algorithms {
		names = append(names, algo.Name)
	}
	require.ElementsMatch(t, []string{"ML-DSA-65", "ML-KEM-768"}, names,
		"both OIDs are referenced by the file, whatever their bodies hold")
}

// TestPQCPipeline_PKIXExactSizeBodyYieldsItsKey is the other direction: a body
// of exactly the registry's size is the key, and must be reported as one.
//
// The bodies are noise of the right length, not real keys. Nothing
// distinguishes a valid ML-DSA public key from 1952 arbitrary bytes -- there is
// no content test to make -- so the length is all this can check, and that is
// exactly what it must accept.
func TestPQCPipeline_PKIXExactSizeBodyYieldsItsKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		algo string
		size int
	}{
		{"ML-DSA-65", mlDSA65OID, "ML-DSA-65", mlDSA65PubKey},
		{"ML-KEM-768", mlKEM768OID, "ML-KEM-768", mlKEM768EncapKey},
		{"SLH-DSA-SHA2-128S", slhDSA128sOID, "SLH-DSA-SHA2-128S", slhDSA128sPubKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, material := assetsOfPub(t, pkixDERBody(t, tt.oid, noise(tt.size)))

			require.Len(t, material, 1, "a %d-byte body is a %s public key", tt.size, tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
			// The inverted assertion of the private-key sibling, which
			// requires Value to be EMPTY. A public key is not a secret and
			// must be published: dropping it here would cost consumers the
			// only copy of the key material the document carries.
			require.NotEmpty(t, material[0].CryptoProperties.RelatedCryptoMaterialProperties.Value,
				"a public key is not a secret and must be published")
		})
	}
}

// TestPQCPipeline_PKIXUnsizedAlgorithmRejectsOnlyAnEmptyBody covers the entries
// the registry states no size for: XMSS, XMSS-MT and HSS-LMS put their
// parameters in the key value rather than the OID (RFC 9802), so there is no
// length to compare against.
//
// Nothing can be validated there, and refusing those keys would be the worse
// error. An EMPTY body is still refused: no encoding of any key is zero bytes,
// so it is the one thing that can be ruled out without knowing the algorithm.
func TestPQCPipeline_PKIXUnsizedAlgorithmRejectsOnlyAnEmptyBody(t *testing.T) {
	t.Parallel()

	t.Run("empty body", func(t *testing.T) {
		t.Parallel()

		algorithms, material := assetsOfPub(t, pkixDERBody(t, xmssOID, nil))

		require.Len(t, algorithms, 1)
		require.Empty(t, material, "an empty body cannot hold a key of any algorithm")
	})

	t.Run("one byte", func(t *testing.T) {
		t.Parallel()

		_, material := assetsOfPub(t, pkixDERBody(t, xmssOID, noise(1)))

		require.Len(t, material, 1,
			"with no size in the registry there is nothing to check, and dropping the key is worse")
	})
}

// TestPQCPipeline_PKIXRealFixturesStillYieldTheirKey is the guard against
// getting the field or the unit wrong in a way synthetic bodies would paper
// over.
//
// Every size in the registry has a sibling in bits (the schema's
// relatedCryptoMaterialProperties.size) and a sibling for the other half of the
// keypair, and a check written against any of those would still pass a test
// whose synthetic bodies were sized from the same wrong field. Real fixtures
// cannot be talked into agreeing: their BIT STRING content is 1952, 1184 and 32
// bytes because OpenSSL wrote a real key there.
func TestPQCPipeline_PKIXRealFixturesStillYieldTheirKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture string
		algo    string
	}{
		{cdxtest.MLDSA65PublicKey, "ML-DSA-65"},
		{cdxtest.MLKEM768PublicKey, "ML-KEM-768"},
		{cdxtest.SLHDSASHA2128sPublicKey, "SLH-DSA-SHA2-128S"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err, "fixture %s", tt.fixture)

			_, material := assetsOfPubPEM(t, data)

			require.Len(t, material, 1, "a real %s public key must still be reported", tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
		})
	}
}

// TestPQCPipeline_PKIXRejectedBodyIsLoggedAtWarn pins the operator-facing half
// of the guard, exactly as its private-key sibling does.
//
// A key dropped silently is indistinguishable, in the document and in the
// output, from a file that never held a key: the operator is told "no public
// key here" about a file they believe holds one, and nothing says why. Debug
// level is silence in a tool whose default output is not verbose.
//
// It cannot run in parallel: slog.SetDefault is process-wide.
func TestPQCPipeline_PKIXRejectedBodyIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	_, material := assetsOfPub(t, pkixDERBody(t, mlDSA65OID, noise(100)))
	require.Empty(t, material)

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a dropped key at Debug level is a silently dropped key")
	require.Contains(t, logged, "not reporting a public key")
	require.Contains(t, logged, "algorithm=ML-DSA-65",
		"the operator has to know which key was dropped")
	require.Contains(t, logged, "body_bytes=100",
		"and what was wrong with it")
}
