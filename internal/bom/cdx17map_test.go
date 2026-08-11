package bom

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// defsEnum loads one enum from the vendored cryptography-defs pin, so the
// tables can never drift from the schema that validates the output.
func defsEnum(t *testing.T, def string) map[string]struct{} {
	t.Helper()
	data, err := schemaFS.ReadFile("schemas/cryptography-defs.schema.json")
	require.NoError(t, err)
	var doc struct {
		Definitions map[string]struct {
			Enum []string `json:"enum"`
		} `json:"definitions"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.NotEmpty(t, doc.Definitions[def].Enum, "definition %s not found", def)
	set := make(map[string]struct{}, len(doc.Definitions[def].Enum))
	for _, v := range doc.Definitions[def].Enum {
		set[v] = struct{}{}
	}
	return set
}

func TestCurveTables17_ValuesAreInEnum(t *testing.T) {
	enum := defsEnum(t, "ellipticCurvesEnum")
	for _, table := range []map[string]string{curveField17, paramSet17, nameCurve17} {
		for from, to := range table {
			_, ok := enum[to]
			require.Truef(t, ok, "curve mapping [%q] = %q is not in ellipticCurvesEnum (registry drift?)", from, to)
		}
	}
}

func TestCurveTables17_TrustedSourcesOnly(t *testing.T) {
	// Hash-derived fabrications (curveInformation on signature-algorithm
	// assets) write bare secg names into the CURVE FIELD — they must never
	// map there. The same strings ARE trusted in parameterSetIdentifier
	// (TLS ECDHE observed groups), hence the split tables.
	for _, fabricated := range []string{"secp256r1", "secp384r1", "secp521r1"} {
		_, ok := curveField17[fabricated]
		require.Falsef(t, ok, "%q must not be mapped via the curve field (fabricated source)", fabricated)
		_, ok = paramSet17[fabricated]
		require.Truef(t, ok, "%q must be mapped via parameterSetIdentifier (trusted TLS group)", fabricated)
	}
	// publicKeySizeFromPkeyRef resolves a curve from the first certificate on
	// the port, not from the cipher suite being described, so its lowercase
	// spellings must stay unmapped: on a dual-certificate host they would put
	// an EC curve on an RSA auth facet.
	for _, untrusted := range []string{"p-224", "p-256", "p-384", "p-521"} {
		_, ok := paramSet17[untrusted]
		require.Falsef(t, ok,
			"%q must not be mapped (derived from another certificate)", untrusted)
	}
	// Spot-check the trusted sources.
	require.Equal(t, "secg/secp256r1", curveField17["nistp256"]) // SSH, RFC 5656
	require.Equal(t, "other/Ed25519", curveField17["ed25519"])   // SSH, RFC 8709
	require.Equal(t, "secg/secp256r1", paramSet17["P-256"])      // SPKI param set
	require.Equal(t, "secg/secp224r1", paramSet17["P-224"])
	require.Equal(t, "other/Curve25519", paramSet17["ecdh_x25519"]) // nmap raw group
	require.Equal(t, "other/Ed25519", nameCurve17["Ed25519"])       // OID-definitive
}

func TestAlgorithmFamily17(t *testing.T) {
	enum := defsEnum(t, "algorithmFamiliesEnum")
	type tc struct {
		name      string
		primitive cdx.CryptoPrimitive
		want      string
	}
	cases := []tc{
		// corpus names
		{"SHA-256", cdx.CryptoPrimitiveHash, "SHA-2"},
		{"SHA-384", cdx.CryptoPrimitiveHash, "SHA-2"},
		{"SHA-512", cdx.CryptoPrimitiveHash, "SHA-2"},
		{"AES-128-GCM", cdx.CryptoPrimitiveBlockCipher, "AES"},
		{"AES-256-GCM", cdx.CryptoPrimitiveBlockCipher, "AES"},
		{"ChaCha20-Poly1305", cdx.CryptoPrimitiveBlockCipher, "ChaCha20"},
		{"ECDSA-P-256", cdx.CryptoPrimitiveSignature, "ECDSA"},
		{"Ed25519", cdx.CryptoPrimitiveSignature, "EdDSA"},
		{"ECDSA-SHA256", cdx.CryptoPrimitiveSignature, "ECDSA"},
		{"SHA256-RSA", cdx.CryptoPrimitiveSignature, "RSASSA-PKCS1"},
		// bare names emitted by extractAlgorithmInfo — the name IS the family
		{"ECDSA", cdx.CryptoPrimitiveSignature, "ECDSA"},
		{"DSA", cdx.CryptoPrimitiveSignature, "DSA"},
		// other producers
		{"SHA-1", cdx.CryptoPrimitiveHash, "SHA-1"},
		{"SHA3-256", cdx.CryptoPrimitiveHash, "SHA-3"},
		{"SHAKE-256", cdx.CryptoPrimitiveHash, "SHA-3"},
		{"3DES-EDE-CBC", cdx.CryptoPrimitiveBlockCipher, "3DES"},
		{"RC4-128", cdx.CryptoPrimitiveBlockCipher, "RC4"},
		{"ML-DSA-65", cdx.CryptoPrimitiveSignature, "ML-DSA"},
		{"ML-KEM-512", cdx.CryptoPrimitiveKEM, "ML-KEM"},
		{"SLH-DSA-SHA2-128S", cdx.CryptoPrimitiveSignature, "SLH-DSA"},
		{"XMSS", cdx.CryptoPrimitiveSignature, "XMSS"},
		{"XMSS-MT", cdx.CryptoPrimitiveSignature, "XMSS"},
		{"HSS-LMS", cdx.CryptoPrimitiveSignature, "LMS"},
		{"DHE-2048", cdx.CryptoPrimitiveKeyAgree, "FFDH"},
		{"ECDHE-ecdh_x25519", cdx.CryptoPrimitiveKeyAgree, "ECDH"},
		{"ecdsa-sha2-nistp256", cdx.CryptoPrimitiveSignature, "ECDSA"},
		{"ssh-ed25519", cdx.CryptoPrimitiveSignature, "EdDSA"},
		{"rsa-sha2-256", cdx.CryptoPrimitiveSignature, "RSASSA-PKCS1"},
		{"ssh-rsa", cdx.CryptoPrimitiveSignature, "RSASSA-PKCS1"},
		{"ssh-dss", cdx.CryptoPrimitiveSignature, "DSA"},
		// TLS RSA facets share the name; primitive disambiguates
		{"RSA-2048", cdx.CryptoPrimitiveKeyAgree, "RSAES-PKCS1"}, // kex facet
		{"RSA-2048", cdx.CryptoPrimitiveSignature, ""},           // auth facet: PKCS1-vs-PSS unknowable
		{"RSA-2048", "", ""}, // bare SPKI key
		// deliberate omissions (closed enum / unknowable / not algorithms)
		{"RSA", cdx.CryptoPrimitiveSignature, ""},
		{"HQC-128", cdx.CryptoPrimitiveSignature, ""},
		{"Unknown", "", ""},
		{"0", "", ""},
		{"TLSv1.3", "", ""},
	}
	for _, c := range cases {
		got := algorithmFamily17(c.name, c.primitive)
		require.Equalf(t, c.want, got, "algorithmFamily17(%q, %q)", c.name, c.primitive)
		if got != "" {
			_, ok := enum[got]
			require.Truef(t, ok, "family %q not in algorithmFamiliesEnum", got)
		}
	}
}

// TestCurveTables17_ExactMappings pins every curve mapping by value.
//
// TestCurveTables17_ValuesAreInEnum only checks that each target is *somewhere*
// in the 246-entry enum, which a wrong-but-valid target passes: mapping
// secp384r1 to secg/secp521r1, or secp192r1 to secg/secp192k1 (both k1 and r1
// are enum members), would go unnoticed. A full literal is the only form that
// catches a transposition, and the two-directional comparison makes an added or
// removed row a test failure rather than a silent change.
func TestCurveTables17_ExactMappings(t *testing.T) {
	want := map[string]map[string]string{
		"curveField17": {
			// RFC 5656 sec. 10.1: nistpN is secpNr1. RFC 8709 for ed25519.
			// Note the enum spells the Edwards curve "Ed25519", capitalised,
			// unlike the secg/ entries -- transcribe, do not normalise.
			"nistp256": "secg/secp256r1",
			"nistp384": "secg/secp384r1",
			"nistp521": "secg/secp521r1",
			"ed25519":  "other/Ed25519",
		},
		"nameCurve17": {
			"Ed25519": "other/Ed25519", // OID 1.3.101.112
		},
	}
	got := map[string]map[string]string{
		"curveField17": curveField17,
		"nameCurve17":  nameCurve17,
	}

	for table, wantRows := range want {
		gotRows := got[table]
		require.Equal(t, len(wantRows), len(gotRows),
			"%s changed size: rows were added or removed without updating this test", table)
		for from, to := range wantRows {
			actual, ok := gotRows[from]
			require.Truef(t, ok, "%s lost the mapping for %q", table, from)
			require.Equalf(t, to, actual, "%s[%q]", table, from)
		}
		for from := range gotRows {
			_, ok := wantRows[from]
			require.Truef(t, ok, "%s gained an unreviewed mapping for %q", table, from)
		}
	}

	// paramSet17 in full. This is the table where a transposition is easiest to
	// miss and most damaging: both secg/secp192r1 and secg/secp192k1 are enum
	// members, so swapping r1 for k1 would assert the wrong curve about a real
	// key while passing every enum-membership check.
	wantParamSet := map[string]string{
		"P-224":                "secg/secp224r1",
		"P-256":                "secg/secp256r1",
		"P-384":                "secg/secp384r1",
		"P-521":                "secg/secp521r1",
		"secp192r1":            "secg/secp192r1",
		"secp224r1":            "secg/secp224r1",
		"secp256r1":            "secg/secp256r1",
		"secp384r1":            "secg/secp384r1",
		"secp521r1":            "secg/secp521r1",
		"secp256k1":            "secg/secp256k1",
		"x25519":               "other/Curve25519",
		"ecdh_x25519":          "other/Curve25519",
		"x448":                 "other/Curve448",
		"ecdh_x448":            "other/Curve448",
		"brainpoolP256r1":      "brainpool/brainpoolP256r1",
		"brainpoolP384r1":      "brainpool/brainpoolP384r1",
		"brainpoolP512r1":      "brainpool/brainpoolP512r1",
		"brainpoolP256r1tls13": "brainpool/brainpoolP256r1",
		"brainpoolP384r1tls13": "brainpool/brainpoolP384r1",
		"brainpoolP512r1tls13": "brainpool/brainpoolP512r1",
	}
	require.Equal(t, len(wantParamSet), len(paramSet17),
		"paramSet17 changed size: rows were added or removed without updating this test")
	for from, to := range wantParamSet {
		actual, ok := paramSet17[from]
		require.Truef(t, ok, "paramSet17 lost the mapping for %q", from)
		require.Equalf(t, to, actual, "paramSet17[%q]", from)
	}
	for from := range paramSet17 {
		_, ok := wantParamSet[from]
		require.Truef(t, ok, "paramSet17 gained an unreviewed mapping for %q", from)
	}
}

// TestAlgorithmFamily17_TablesAreInEnum walks the family tables themselves,
// rather than only the values the case list in TestAlgorithmFamily17 happens to
// produce. That left RIPEMD, MD2, MD4, MD5, BLAKE2, ML-KEM and RSASSA-PSS
// unguarded: all valid at HEAD, none pinned, so a typo in any of them would
// have produced an invalid document with no test failing.
func TestAlgorithmFamily17_TablesAreInEnum(t *testing.T) {
	families := defsEnum(t, "algorithmFamiliesEnum")

	for name, family := range familyExact {
		_, ok := families[family]
		require.Truef(t, ok,
			"familyExact[%q] = %q is not in algorithmFamiliesEnum (registry drift?)", name, family)
	}
	for _, p := range familyPrefix {
		_, ok := families[p.family]
		require.Truef(t, ok,
			"familyPrefix %q -> %q is not in algorithmFamiliesEnum (registry drift?)", p.prefix, p.family)
	}
	require.NotEmpty(t, familyExact)
	require.NotEmpty(t, familyPrefix)
}
