package cdxprops_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	pemlib "encoding/pem"
	"log/slog"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file pins WHICH privateKey bodies support the claim "a private key
// exists here". A length floor cannot: the smallest legal ML-DSA body is a
// 34-byte seed encoding, so any floor low enough to accept it also accepts 32
// arbitrary bytes under the same OID -- the exact "confident private key over
// garbage" report the guard was written to stop. The encodings are enumerable,
// so they are checked as encodings.
//
// RFC 9881 sec. 6 (ML-DSA) and RFC 9882 (ML-KEM) make privateKey a CHOICE of
// seed [0] OCTET STRING, expandedKey OCTET STRING, or a SEQUENCE of both.
// SLH-DSA (RFC 9883) has no seed alternative and stores the key raw. Bodies
// below are built from those definitions rather than from a fixture, because
// the defect this replaces came from believing the corpus covered the encoding
// space.

var (
	mlDSA65OID     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	mlKEM768OID    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	slhDSA128sOID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	xmssOID        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 34}
	xmssMTOID      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 35}
	hssLMSOID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 17}
	mlDSA65Seed    = 32
	mlDSA65Expand  = 4032
	mlKEM768Seed   = 64
	mlKEM768Expand = 2400
)

// pkcs8DERBody builds a PKCS#8 PrivateKeyInfo carrying oid whose privateKey
// OCTET STRING holds exactly body, so a test can state the encoding it means
// instead of a length and hope.
func pkcs8DERBody(t *testing.T, oid asn1.ObjectIdentifier, body []byte) []byte {
	t.Helper()

	return pkcs8DERVersionBody(t, 0, oid, body)
}

// pkcs8DERVersionBody is pkcs8DERBody with the version chosen.
func pkcs8DERVersionBody(t *testing.T, version int, oid asn1.ObjectIdentifier, body []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version:    version,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: body,
	})
	require.NoError(t, err)

	return der
}

// pemPrivateKey wraps DER in a `PRIVATE KEY` block. Go's stdlib cannot parse a
// post-quantum PKCS#8 key, so the scanner routes it to ParseErrors and the
// block reaches analyzeParseError -- the production path.
func pemPrivateKey(der []byte) []byte {
	return pemlib.EncodeToMemory(&pemlib.Block{Type: "PRIVATE KEY", Bytes: der})
}

// noise returns n bytes that are not a key and are not zero either. Zero-filled
// bodies happen to be invalid DER (0x00 is not a tag), so noise made of them
// would pass a shape check for the wrong reason.
func noise(n int) []byte {
	return bytes.Repeat([]byte{0xab}, n)
}

// seedChoice encodes the seed alternative, `[0] OCTET STRING`: 0x80 0x20 for
// ML-DSA's 32 bytes.
func seedChoice(t *testing.T, n int) []byte {
	t.Helper()

	body, err := asn1.MarshalWithParams(noise(n), "tag:0")
	require.NoError(t, err)

	return body
}

// expandedChoice encodes the expandedKey alternative, a plain OCTET STRING.
func expandedChoice(t *testing.T, n int) []byte {
	t.Helper()

	body, err := asn1.Marshal(noise(n))
	require.NoError(t, err)

	return body
}

// bothChoice encodes the `both` alternative, SEQUENCE { seed, expandedKey } --
// what OpenSSL emits by default and what every PQC fixture in this repo holds.
func bothChoice(t *testing.T, seed, expanded int) []byte {
	t.Helper()

	body, err := asn1.Marshal(struct {
		Seed     []byte
		Expanded []byte
	}{noise(seed), noise(expanded)})
	require.NoError(t, err)

	return body
}

// assetsOf splits a detection's components by asset type, asserting the zero
// Component is never appended.
func assetsOf(t *testing.T, der []byte) (algorithms, material []cdx.Component) {
	t.Helper()

	bundle, err := pem.Scanner{}.Scan(t.Context(), pemPrivateKey(der), "synthetic.pem")
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

// TestPQCPipeline_IllegalBodyEncodingYieldsAlgorithmNotKey covers the window a
// length floor leaves open. Each body here is the length of something real, or
// longer, and none of them is a legal encoding of a private key.
func TestPQCPipeline_IllegalBodyEncodingYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		body []byte
	}{
		// Exactly the seed length, but bare bytes rather than `[0]
		// OCTET STRING`. A floor at the seed accepts this, which is the whole
		// defect: 32 bytes of noise reported as a full ML-DSA-65 private key.
		{"ML-DSA-65 bare seed-length noise", mlDSA65OID, noise(mlDSA65Seed)},
		{"ML-KEM-768 bare seed-length noise", mlKEM768OID, noise(mlKEM768Seed)},
		// The length of the seed ENCODING, still not that encoding.
		{"ML-DSA-65 noise the length of a seed encoding", mlDSA65OID, noise(mlDSA65Seed + 2)},
		{"ML-KEM-768 noise the length of a seed encoding", mlKEM768OID, noise(mlKEM768Seed + 2)},
		// Between the two alternatives: too long to be a seed, too short to be
		// an expanded key, and a floor at the seed accepts every one.
		{"ML-DSA-65 noise between the alternatives", mlDSA65OID, noise(100)},
		{"ML-DSA-65 long noise", mlDSA65OID, noise(2000)},
		{"ML-KEM-768 long noise", mlKEM768OID, noise(1000)},
		// A well-formed OCTET STRING of the WRONG size. The tag is right, so
		// only checking the encoding's shape and not its length would pass it.
		{"ML-DSA-65 expandedKey one byte short", mlDSA65OID, expandedChoice(t, mlDSA65Expand-1)},
		{"ML-KEM-768 expandedKey one byte short", mlKEM768OID, expandedChoice(t, mlKEM768Expand-1)},
		// A well-formed seed of the wrong size, and one under the OID of an
		// algorithm that has no seed alternative at all.
		{"ML-DSA-65 seed one byte short", mlDSA65OID, seedChoice(t, mlDSA65Seed-1)},
		{"SLH-DSA-SHA2-128S seed encoding", slhDSA128sOID, seedChoice(t, 32)},
		// The `both` SEQUENCE with its halves swapped: both lengths are legal
		// somewhere, neither is legal in that position.
		{"ML-DSA-65 both with halves swapped", mlDSA65OID, bothChoice(t, mlDSA65Expand, mlDSA65Seed)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			algorithms, material := assetsOf(t, pkcs8DERBody(t, tt.oid, tt.body))

			require.Len(t, algorithms, 1,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			require.Empty(t, material,
				"a body that is not a legal private-key encoding must not be reported as a key")
		})
	}
}

// TestPQCPipeline_LegalBodyEncodingsYieldTheirKey is the other direction, and
// the reason the check reads the encoding instead of raising the floor: all
// three CHOICE alternatives are legal, and they differ in length by two orders
// of magnitude.
//
// The bodies are noise of the right shape, not real keys. Nothing distinguishes
// a valid seed from 32 arbitrary bytes -- there is no content test to make --
// so the encoding and its declared lengths are all this can check, and that is
// exactly what it must accept.
func TestPQCPipeline_LegalBodyEncodingsYieldTheirKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		algo string
		body []byte
	}{
		{"ML-DSA-65 seed", mlDSA65OID, "ML-DSA-65", seedChoice(t, mlDSA65Seed)},
		{"ML-DSA-65 expandedKey", mlDSA65OID, "ML-DSA-65", expandedChoice(t, mlDSA65Expand)},
		{"ML-DSA-65 both", mlDSA65OID, "ML-DSA-65", bothChoice(t, mlDSA65Seed, mlDSA65Expand)},
		{"ML-KEM-768 seed", mlKEM768OID, "ML-KEM-768", seedChoice(t, mlKEM768Seed)},
		{"ML-KEM-768 expandedKey", mlKEM768OID, "ML-KEM-768", expandedChoice(t, mlKEM768Expand)},
		{"ML-KEM-768 both", mlKEM768OID, "ML-KEM-768", bothChoice(t, mlKEM768Seed, mlKEM768Expand)},
		// SLH-DSA stores the key raw, with no wrapper: the fixture's body is 64
		// bytes for SHA2-128s, not 66.
		{"SLH-DSA-SHA2-128S raw", slhDSA128sOID, "SLH-DSA-SHA2-128S", noise(64)},
		// A raw body of the expanded length is not RFC 9881's encoding, but it
		// is what a producer that skips the CHOICE wrapper emits, and rejecting
		// it would report a real key as absent -- the failure this whole check
		// exists to avoid, inverted. Accepted deliberately.
		{"ML-DSA-65 raw expanded key", mlDSA65OID, "ML-DSA-65", noise(mlDSA65Expand)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, material := assetsOf(t, pkcs8DERBody(t, tt.oid, tt.body))

			require.Len(t, material, 1, "a legal %s encoding is a private key", tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
			require.Empty(t, material[0].CryptoProperties.RelatedCryptoMaterialProperties.Value,
				"the secret must never be published")
		})
	}
}

// TestPQCPipeline_UndefinedPrivateKeyEncodingRejectsOnlyEmptyBody covers XMSS,
// XMSS-MT and HSS-LMS, where the gap is not an unstated SIZE but a missing
// ENCODING: no RFC says what the PKCS#8 privateKey OCTET STRING holds under
// these three OIDs, so beyond "not zero bytes" there is nothing to check.
//
// RFC 8554 sec. 3.3: "The private key format is not included as it is not
// needed for interoperability and an implementation MAY use any private key
// format." Sec. 4.2 and sec. 5.2 repeat it per level -- "The format of the
// LM-OTS private key is an internal matter to the implementation, and this
// document does not attempt to define it" and the same sentence for the LMS
// private key. RFC 8391 sec. 4.1.7: "Note that we do not define any specific
// format or handling for the XMSS private key SK by introducing this
// algorithm", and sec. 4.2.2: "This document does not define any specific
// format for the XMSS^MT private key SK_MT as it is not required for
// interoperability."
//
// A code review raised RFC 8554 sec. 6.1 as a counter-example, arguing the HSS
// private key is structured as u32str(L) followed by per-level state and is
// therefore validatable. The primary text was checked and the claim does not
// hold: the sentences above are the document's own statement about its scope.
// The one concrete byte layout in RFC 8554 is the private key data in Test
// Case 2 of Appendix F, which sec. 3.3 introduces with "However, for clarity,
// we include an example of private key data" -- an illustration, explicitly not
// a format. A future reader will find Appendix F and mistake it for a spec.
//
// So the sub-cases below are deliberate: one arbitrary byte IS accepted as a
// private key, because with no defined encoding the alternative is dropping
// real keys, which is the worse error. The twenty-four-byte case pins a floor
// that was considered and rejected -- see rejectPrivateKeyBody's doc comment --
// so it cannot be reintroduced without a test change.
func TestPQCPipeline_UndefinedPrivateKeyEncodingRejectsOnlyEmptyBody(t *testing.T) {
	t.Parallel()

	algos := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"XMSS", xmssOID},
		{"XMSS-MT", xmssMTOID},
		{"HSS-LMS", hssLMSOID},
	}

	bodies := []struct {
		name string
		body []byte
		// material is how many private-key components the body must yield: 0 or
		// 1. Stated as a number so the empty case and the accepted cases read
		// off the same table rather than as two shapes of assertion.
		material int
		why      string
	}{
		{
			name:     "empty body",
			body:     nil,
			material: 0,
			why:      "an empty body cannot hold a key of any algorithm",
		},
		{
			// The behaviour the review wanted changed. Kept, because no RFC
			// defines an encoding to measure this against.
			name:     "one byte",
			body:     noise(1),
			material: 1,
			why:      "no encoding is defined for this OID, so dropping the key is the worse error",
		},
		{
			// RFC 9858 Table 2 adds LMS_SHA256_M24_* and LMS_SHAKE_M24_*, all
			// m=24 -- the smallest m of any registered LMS parameter set, and
			// so the lowest floor a length check could have used. It is not
			// applied: that m bounds an optional, internal, explicitly
			// non-interoperable key-GENERATION input, not the bytes a producer
			// puts in a transmitted PKCS#8 body, and RFC 8391 states no
			// equivalent number for XMSS at all.
			//
			// This case sits ON the boundary, so it does NOT catch the floor
			// itself: `len(body) < 24` accepts twenty-four bytes and this case
			// still passes. The "one byte" case above is what fails when the
			// floor is added. What this case catches is the off-by-one form,
			// `<= 24` or `< 25`, which rejects the very parameter set the
			// number was taken from -- verified by mutation, both ways.
			name:     "twenty-four bytes",
			body:     noise(24),
			material: 1,
			why:      "the m=24 floor from RFC 9858 was considered and rejected; it must stay rejected",
		},
	}

	for _, algo := range algos {
		for _, body := range bodies {
			t.Run(algo.name+"/"+body.name, func(t *testing.T) {
				t.Parallel()

				algorithms, material := assetsOf(t, pkcs8DERBody(t, algo.oid, body.body))

				require.Len(t, algorithms, 1,
					"the OID establishes the algorithm is referenced, whatever the body holds")
				// Each OID must reach its OWN registry entry. Counting
				// components cannot see a copy-pasted row mapping XMSS-MT's OID
				// onto XMSS's entry: the counts are 1 and 1 either way, so every
				// sub-case would still pass while the document named the wrong
				// algorithm. Naming the algorithm is also the proof that these
				// three OIDs reach rejectPrivateKeyBody at all rather than
				// being dropped earlier as an unregistered OID, which yields no
				// components whatsoever.
				require.Equal(t, algo.name, algorithms[0].Name)

				require.Len(t, material, body.material, body.why)
				if body.material == 0 {
					return
				}

				// These three OIDs accept a body nothing could validate, which
				// makes them the entries most likely to carry garbage -- and so
				// the ones where publishing that body would hurt most. That is
				// exactly the risk the review raised, so it is pinned here and
				// not only in the sized-algorithm tests above: an unvalidatable
				// body must still never reach the emitted document.
				key := material[0]
				require.Equal(t, algo.name, key.Name)

				props := key.CryptoProperties.RelatedCryptoMaterialProperties
				require.NotNil(t, props)
				require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, props.Type,
					"an accepted body is claimed to be a private key, so it must say so")
				require.Empty(t, props.Value,
					"the secret must never be published, least of all bytes nothing validated")
				// The registry states no size for these entries. A guessed one
				// would be in bytes where the schema wants bits, and would
				// validate, so nothing downstream would ever catch it.
				require.Nil(t, props.Size)
			})
		}
	}
}

// TestPQCPipeline_TrailingDataAfterPKCS8YieldsNoComponents pins that the DER
// must end where the PrivateKeyInfo ends.
//
// asn1.Unmarshal returns what it did not consume, and discarding that accepted
// anything appended to a key. The ref is a digest of the whole block, so one
// key plus n different tails is n distinct private-key assets in the document
// -- unbounded, all claiming to be the same key. x509.ParsePKCS8PrivateKey
// rejects trailing data for the same reason.
func TestPQCPipeline_TrailingDataAfterPKCS8YieldsNoComponents(t *testing.T) {
	t.Parallel()

	der := pkcs8DERBody(t, mlDSA65OID, bothChoice(t, mlDSA65Seed, mlDSA65Expand))

	algorithms, material := assetsOf(t, append(der, noise(4)...))

	require.Empty(t, material, "a key with junk appended is not a key")
	require.Empty(t, algorithms,
		"the wrapper is malformed, so it establishes nothing -- not even the algorithm")
}

// TestPQCPipeline_UnsupportedPKCS8VersionYieldsNoComponents pins the version
// field, which was read into a struct and then never looked at.
//
// RFC 5208 defines version 0 and RFC 5958 adds 1 for a OneAsymmetricKey that
// carries a publicKey. Anything else is not a structure this code knows how to
// read, so measuring its privateKey field is measuring a field that may not be
// the private key at all.
func TestPQCPipeline_UnsupportedPKCS8VersionYieldsNoComponents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version int
	}{
		{"negative", -1},
		{"future", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			der := pkcs8DERVersionBody(t, tt.version, mlDSA65OID,
				bothChoice(t, mlDSA65Seed, mlDSA65Expand))

			algorithms, material := assetsOf(t, der)

			require.Empty(t, material)
			require.Empty(t, algorithms)
		})
	}
}

// TestPQCPipeline_RejectedBodyIsLoggedAtWarn pins the operator-facing half of
// the guard.
//
// Dropping a key silently is what #213 shipped and what this replaced: the
// document says "no private key here" about a file the operator believes holds
// one, and nothing tells them why. A mutation moving this line to Debug -- in a
// tool whose default output is not verbose, so Debug is silence -- was caught by
// no test in the repository.
//
// It cannot run in parallel: slog.SetDefault is process-wide.
func TestPQCPipeline_RejectedBodyIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	_, material := assetsOf(t, pkcs8DERBody(t, mlDSA65OID, noise(100)))
	require.Empty(t, material)

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a dropped key at Debug level is a silently dropped key")
	require.Contains(t, logged, "not reporting a private key")
	require.Contains(t, logged, "algorithm=ML-DSA-65",
		"the operator has to know which key was dropped")
	require.Contains(t, logged, "body_bytes=100",
		"and what was wrong with it")
}
