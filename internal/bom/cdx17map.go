package bom

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// The 1.7 ellipticCurve enum is CLOSED with no wildcard: absent key => omit
// the field. Canonical namespace: secg/* for short-Weierstrass curves.
// Three tables, split by SOURCE FIELD, because the trusted and fabricated
// producers overlap in string space across fields but not within one field:
//
//   - curveField17 keys the algorithmProperties.curve field. Trusted writer:
//     SSH host keys (nmap algoMap: nistp*/ed25519). The OTHER curve-field
//     writer, curveInformation on signature-algorithm assets, emits bare
//     secp256r1/384/521 — hash-derived GUESSES (a P-384 key can sign
//     SHA-256), deliberately unmapped here.
//   - paramSet17 keys parameterSetIdentifier. Trusted writers: EC keys
//     (elliptic.Curve.Params().Name, "P-256" style) and TLS ECDHE kex facets
//     (raw observed named groups from nmap ssl-enum-ciphers: bare secg
//     names, x25519/ecdh_x25519, brainpool). Bare secg strings ARE trusted
//     here — the fabricated writer never touches parameterSetIdentifier
//     with curve names (it writes digest sizes like "256").
//   - nameCurve17 keys the component name, for algorithms whose OID fixes
//     the curve outright.
//
// Every value in all three tables is pinned against the vendored
// cryptography-defs snapshot by TestCurveTables17_ValuesAreInEnum.

// curveField17 maps algorithmProperties.curve values (SSH sources only).
var curveField17 = map[string]string{
	// RFC 5656 §10.1: nistpN ≡ secpNr1; RFC 8709 ed25519 (edwards25519).
	"nistp256": "secg/secp256r1",
	"nistp384": "secg/secp384r1",
	"nistp521": "secg/secp521r1",
	"ed25519":  "other/Ed25519",
}

// paramSet17 maps parameterSetIdentifier values that are curve identifiers.
var paramSet17 = map[string]string{
	// EC keys — elliptic.Curve.Params().Name (real SPKI data).
	"P-224": "secg/secp224r1",
	"P-256": "secg/secp256r1",
	"P-384": "secg/secp384r1",
	"P-521": "secg/secp521r1",
	// lowercase variants derived from refs by publicKeySizeFromPkeyRef
	"p-224": "secg/secp224r1",
	"p-256": "secg/secp256r1",
	"p-384": "secg/secp384r1",
	"p-521": "secg/secp521r1",
	// TLS ECDHE named groups observed by nmap (raw kex_info).
	"secp192r1":            "secg/secp192r1",
	"secp224r1":            "secg/secp224r1",
	"secp256r1":            "secg/secp256r1",
	"secp384r1":            "secg/secp384r1",
	"secp521r1":            "secg/secp521r1",
	"secp256k1":            "secg/secp256k1",
	"x25519":               "other/Curve25519",
	"ecdh_x25519":          "other/Curve25519", // nmap tls.lua group-29 spelling
	"x448":                 "other/Curve448",
	"ecdh_x448":            "other/Curve448",
	"brainpoolP256r1":      "brainpool/brainpoolP256r1",
	"brainpoolP384r1":      "brainpool/brainpoolP384r1",
	"brainpoolP512r1":      "brainpool/brainpoolP512r1",
	"brainpoolP256r1tls13": "brainpool/brainpoolP256r1",
	"brainpoolP384r1tls13": "brainpool/brainpoolP384r1",
	"brainpoolP512r1tls13": "brainpool/brainpoolP512r1",
}

// nameCurve17 maps component names whose algorithm intrinsically fixes the
// curve (OID-definitive, no fabrication risk).
var nameCurve17 = map[string]string{
	"Ed25519": "other/Ed25519", // OID 1.3.101.112, RFC 8032 edwards25519
}

// algorithmFamily17 returns the CycloneDX 1.7 algorithmFamiliesEnum value
// for an algorithm component, or "" to omit the field. The enum is CLOSED:
// unmapped names (HQC — absent from the enum; Unknown; protocol assets) get
// no family rather than a guess. primitive disambiguates the TLS "RSA-<n>"
// name collision: the kex facet (key-agree primitive) is knowably RSA key
// transport = RSAES-PKCS1 (RFC 5246 §7.4.7.1); the auth facet and bare SPKI
// RSA keys stay unmapped (PKCS1-vs-PSS unknowable from a suite or the
// rsaEncryption OID). The PQC rules deliberately do NOT consult primitive:
// the PKCS#8 path attaches none.
func algorithmFamily17(name string, primitive cdx.CryptoPrimitive) string {
	if fam, ok := familyExact[name]; ok {
		return fam
	}
	// PSS before PKCS1: both contain "-RSA".
	if strings.Contains(name, "-RSAPSS") {
		return "RSASSA-PSS"
	}
	if strings.Contains(name, "-RSA") {
		return "RSASSA-PKCS1"
	}
	if strings.HasPrefix(name, "RSA-") && primitive == cdx.CryptoPrimitiveKeyAgree {
		return "RSAES-PKCS1" // TLS RSA key transport facet
	}
	for _, r := range familyPrefix {
		if strings.HasPrefix(name, r.prefix) {
			return r.family
		}
	}
	return ""
}

var familyExact = map[string]string{
	"ChaCha20-Poly1305": "ChaCha20",
	"3DES-EDE-CBC":      "3DES",
	"RC4-128":           "RC4",
	"Ed25519":           "EdDSA",
	"SHA-1":             "SHA-1",
	"RIPEMD-160":        "RIPEMD",
	"MD2":               "MD2",
	"MD4":               "MD4",
	"MD5":               "MD5",
	"XMSS":              "XMSS",
	"XMSS-MT":           "XMSS",
	"HSS-LMS":           "LMS",
	"ssh-ed25519":       "EdDSA",
	"ssh-rsa":           "RSASSA-PKCS1",
	"ssh-dss":           "DSA",
	// extractAlgorithmInfo's key-less fallbacks emit the bare family name as
	// the component name (algorithm.go: "ECDSA" without a curve, "DSA"
	// without a modulus). Bare "RSA" is deliberately absent — the padding
	// scheme is unknowable from rsaEncryption.
	"ECDSA": "ECDSA",
	"DSA":   "DSA",
	// x509 sig-alg components for PQC carry the fallback algorithmName as
	// their Name (x509.go: sigAlg.String()=="0" branch) — map those forms.
	"crypto/algorithm/xmss":    "XMSS",
	"crypto/algorithm/xmss-mt": "XMSS",
	"crypto/algorithm/hss-lms": "LMS",
}

var familyPrefix = []struct{ prefix, family string }{
	{"AES-", "AES"},
	{"SHA3-", "SHA-3"},
	{"SHAKE-", "SHA-3"},
	{"SHA-", "SHA-2"}, // SHA-224/256/384/512[/224|/256]; SHA-1 caught by exact map first
	{"BLAKE2", "BLAKE2"},
	{"ML-DSA-", "ML-DSA"},
	{"ML-KEM-", "ML-KEM"},
	{"SLH-DSA-", "SLH-DSA"},
	{"crypto/algorithm/ml-dsa-", "ML-DSA"},   // PQC sig-alg fallback name form
	{"crypto/algorithm/slh-dsa-", "SLH-DSA"}, // (crypto/algorithm/hqc-* stays unmapped)
	{"ECDSA-", "ECDSA"},
	{"DSA-", "DSA"},
	{"ECDHE-", "ECDH"},
	{"DHE-", "FFDH"},
	{"ecdsa-sha2-", "ECDSA"},
	{"rsa-sha2-", "RSASSA-PKCS1"}, // RFC 8332 §3
}
