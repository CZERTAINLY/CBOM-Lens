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
		{"SLH-DSA-SHA2-128S", cdx.CryptoPrimitiveSignature, "SLH-DSA"},
		{"XMSS", cdx.CryptoPrimitiveSignature, "XMSS"},
		{"HSS-LMS", cdx.CryptoPrimitiveSignature, "LMS"},
		{"DHE-2048", cdx.CryptoPrimitiveKeyAgree, "FFDH"},
		{"ECDHE-ecdh_x25519", cdx.CryptoPrimitiveKeyAgree, "ECDH"},
		{"ecdsa-sha2-nistp256", cdx.CryptoPrimitiveSignature, "ECDSA"},
		{"ssh-ed25519", cdx.CryptoPrimitiveSignature, "EdDSA"},
		{"rsa-sha2-256", cdx.CryptoPrimitiveSignature, "RSASSA-PKCS1"},
		{"ssh-rsa", cdx.CryptoPrimitiveSignature, "RSASSA-PKCS1"},
		{"ssh-dss", cdx.CryptoPrimitiveSignature, "DSA"},
		// PQC cert sig-alg components carry the fallback algorithmName form
		{"crypto/algorithm/ml-dsa-65", cdx.CryptoPrimitiveSignature, "ML-DSA"},
		{"crypto/algorithm/slh-dsa-sha2-128s", cdx.CryptoPrimitiveSignature, "SLH-DSA"},
		{"crypto/algorithm/hss-lms", cdx.CryptoPrimitiveSignature, "LMS"},
		{"crypto/algorithm/hqc-128", cdx.CryptoPrimitiveSignature, ""},
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
