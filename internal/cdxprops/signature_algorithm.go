package cdxprops

import (
	"crypto/x509"
	"strings"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Classic (non-PQC) signature algorithms mapped from Go’s enum.
var sigAlgRef = map[x509.SignatureAlgorithm]cdx.BOMReference{
	x509.MD5WithRSA:       "crypto/algorithm/md5-rsa@1.2.840.113549.1.1.4",
	x509.SHA1WithRSA:      "crypto/algorithm/sha-1-rsa@1.2.840.113549.1.1.5",
	x509.SHA256WithRSA:    "crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11",
	x509.SHA384WithRSA:    "crypto/algorithm/sha-384-rsa@1.2.840.113549.1.1.12",
	x509.SHA512WithRSA:    "crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13",
	x509.DSAWithSHA1:      "crypto/algorithm/sha-1-dsa@1.2.840.10040.4.3",
	x509.DSAWithSHA256:    "crypto/algorithm/sha-256-dsa@2.16.840.1.101.3.4.3.2",
	x509.ECDSAWithSHA1:    "crypto/algorithm/sha-1-ecdsa@1.2.840.10045.4.1",
	x509.ECDSAWithSHA256:  "crypto/algorithm/sha-256-ecdsa@1.2.840.10045.4.3.2",
	x509.ECDSAWithSHA384:  "crypto/algorithm/sha-384-ecdsa@1.2.840.10045.4.3.3",
	x509.ECDSAWithSHA512:  "crypto/algorithm/sha-512-ecdsa@1.2.840.10045.4.3.4",
	x509.SHA256WithRSAPSS: "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
	x509.SHA384WithRSAPSS: "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
	x509.SHA512WithRSAPSS: "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
	x509.PureEd25519:      "crypto/algorithm/ed25519@1.3.101.112",
}

// PQC signature AlgorithmIdentifier OIDs (outer signatureAlgorithm).
var pqcSigOIDRef = map[string]cdx.BOMReference{
	// ML-DSA (FIPS 204)
	"2.16.840.1.101.3.4.3.17": "crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17",
	"2.16.840.1.101.3.4.3.18": "crypto/algorithm/ml-dsa-65@2.16.840.1.101.3.4.3.18",
	"2.16.840.1.101.3.4.3.19": "crypto/algorithm/ml-dsa-87@2.16.840.1.101.3.4.3.19",

	// SLH-DSA (FIPS 205) — SHA2
	"2.16.840.1.101.3.4.3.20": "crypto/algorithm/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
	"2.16.840.1.101.3.4.3.21": "crypto/algorithm/slh-dsa-sha2-128f@2.16.840.1.101.3.4.3.21",
	"2.16.840.1.101.3.4.3.22": "crypto/algorithm/slh-dsa-sha2-192s@2.16.840.1.101.3.4.3.22",
	"2.16.840.1.101.3.4.3.23": "crypto/algorithm/slh-dsa-sha2-192f@2.16.840.1.101.3.4.3.23",
	"2.16.840.1.101.3.4.3.24": "crypto/algorithm/slh-dsa-sha2-256s@2.16.840.1.101.3.4.3.24",
	"2.16.840.1.101.3.4.3.25": "crypto/algorithm/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
	// SLH-DSA (FIPS 205) — SHAKE
	"2.16.840.1.101.3.4.3.26": "crypto/algorithm/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
	"2.16.840.1.101.3.4.3.27": "crypto/algorithm/slh-dsa-shake-128f@2.16.840.1.101.3.4.3.27",
	"2.16.840.1.101.3.4.3.28": "crypto/algorithm/slh-dsa-shake-192s@2.16.840.1.101.3.4.3.28",
	"2.16.840.1.101.3.4.3.29": "crypto/algorithm/slh-dsa-shake-192f@2.16.840.1.101.3.4.3.29",
	"2.16.840.1.101.3.4.3.30": "crypto/algorithm/slh-dsa-shake-256s@2.16.840.1.101.3.4.3.30",
	"2.16.840.1.101.3.4.3.31": "crypto/algorithm/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",

	// IETF stateful hash-based signatures in X.509
	"1.2.840.113549.1.9.16.3.17": "crypto/algorithm/hss-lms-hashsig@1.2.840.113549.1.9.16.3.17", // HSS/LMS
	"1.3.6.1.5.5.7.6.34":         "crypto/algorithm/xmss-hashsig@1.3.6.1.5.5.7.6.34",            // XMSS
	"1.3.6.1.5.5.7.6.35":         "crypto/algorithm/xmssmt-hashsig@1.3.6.1.5.5.7.6.35",          // XMSS^MT
}

// getAlgorithmProperties generates crypto algorithm properties for a signature algorithm
func (c Converter) getAlgorithmProperties(sigAlg x509.SignatureAlgorithm, oidFallback string) (cdx.CryptoAlgorithmProperties, []cdx.Property, string) {
	var algorithmFamily string
	var hash string
	var paramSetID string
	var padding cdx.CryptoPadding
	// nil until something establishes it; the Unknown default leaves it unset.
	var classicalSecurityLevel *int
	// nil means the field is omitted. See algorithmInfo for why this is a
	// pointer rather than an int.
	var nqsl *int

	switch sigAlg {
	case x509.MD2WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "128" // MD2 digest size
		hash = "MD2"
		// Broken: no collision resistance left. Stated, not inherited
		// from the zero value, so it reads as a claim rather than a gap.
		classicalSecurityLevel = ptr(0)

	case x509.MD5WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "128" // MD5 digest size
		hash = "MD5"
		classicalSecurityLevel = ptr(0) // Broken

	case x509.SHA1WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "160" // SHA-1 digest size
		hash = "SHA-1"
		classicalSecurityLevel = ptr(0) // Broken

	case x509.SHA256WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "256" // SHA-256 digest size
		padding = cdx.CryptoPaddingPKCS1v15
		hash = "SHA-256"
		classicalSecurityLevel = ptr(112)

	case x509.SHA384WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "384" // SHA-384 digest size
		padding = cdx.CryptoPaddingPKCS1v15
		hash = "SHA-384"
		classicalSecurityLevel = ptr(128)

	case x509.SHA512WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "512" // SHA-512 digest size
		padding = cdx.CryptoPaddingPKCS1v15
		hash = "SHA-512"
		classicalSecurityLevel = ptr(256)

	case x509.SHA256WithRSAPSS:
		algorithmFamily = "RSASSA-PSS"
		paramSetID = "256" // SHA-256 digest size
		hash = "SHA-256"
		classicalSecurityLevel = ptr(112)

	case x509.SHA384WithRSAPSS:
		algorithmFamily = "RSASSA-PSS"
		paramSetID = "384" // SHA-384 digest size
		hash = "SHA-384"
		classicalSecurityLevel = ptr(128)

	case x509.SHA512WithRSAPSS:
		algorithmFamily = "RSASSA-PSS"
		paramSetID = "512" // SHA-512 digest size
		hash = "SHA-512"
		classicalSecurityLevel = ptr(256)

	case x509.ECDSAWithSHA1:
		algorithmFamily = "ECDSA"
		paramSetID = "160" // SHA-1 digest size
		hash = "SHA-1"
		classicalSecurityLevel = ptr(0) // Broken: SHA-1

	case x509.ECDSAWithSHA256:
		algorithmFamily = "ECDSA"
		paramSetID = "256" // SHA-256 digest size
		hash = "SHA-256"
		classicalSecurityLevel = ptr(128)

	case x509.ECDSAWithSHA384:
		algorithmFamily = "ECDSA"
		paramSetID = "384" // SHA-384 digest size
		hash = "SHA-384"
		classicalSecurityLevel = ptr(192)

	case x509.ECDSAWithSHA512:
		algorithmFamily = "ECDSA"
		paramSetID = "512" // SHA-512 digest size
		hash = "SHA-512"
		classicalSecurityLevel = ptr(256)

	case x509.DSAWithSHA1:
		algorithmFamily = "DSA"
		paramSetID = "160" // SHA-1 digest size
		hash = "SHA-1"
		classicalSecurityLevel = ptr(0) // Broken: SHA-1

	case x509.DSAWithSHA256:
		algorithmFamily = "DSA"
		paramSetID = "256" // SHA-256 digest size
		hash = "SHA-256"
		classicalSecurityLevel = ptr(112)

	case x509.PureEd25519:
		algorithmFamily = "EdDSA"
		paramSetID = "256" // Ed25519 key size
		// not a parameter https://www.rfc-editor.org/rfc/rfc8032
		hash = "SHA-512"
		classicalSecurityLevel = ptr(128)

	default:
		algorithmFamily = "Unknown"
		paramSetID = "0"
	}

	// [sign] is the default for the classical enum path above, which has no
	// registry entry to consult. A registry hit below replaces it.
	cryptoFunctions := []cdx.CryptoFunction{cdx.CryptoFunctionSign}

	// The outer signatureAlgorithm OID normally names a signature scheme, so
	// [sign]/signature is the default. A registry hit below can contradict that
	// -- the three ML-KEM OIDs are KEMs -- and the primitive must follow the
	// same entry the cryptoFunctions come from, or one component reports
	// `primitive: signature` beside `cryptoFunctions: [decapsulate,
	// encapsulate]`.
	primitive := cdx.CryptoPrimitiveSignature

	var props []cdx.Property
	if oidFallback != "" && algorithmFamily == "Unknown" {
		info, ok := unsupportedAlgorithms[oidFallback]
		if ok {
			primitive = algorithmPrimitive(info)
			algorithmFamily = info.name
			paramSetID = info.paramSetID
			if info.classicalSecurityLevel != nil {
				// Copy; do not alias the shared registry entry.
				classicalSecurityLevel = ptr(*info.classicalSecurityLevel)
			}
			// Defer to the registry rather than overriding it with [sign].
			// Reporting fewer functions than the algorithm component built
			// from the same entry made the two disagree inside one document.
			if fns := sortedCryptoFunctions(info.cryptoFunctions); fns != nil {
				cryptoFunctions = fns
			}
			if info.nistQuantumSecurityLevel != nil {
				// Copy the value; do not alias the shared registry entry.
				nqsl = ptr(*info.nistQuantumSecurityLevel)
			}
			// fallback for PQC
			switch {
			case strings.Contains(info.algorithmName, "slh-dsa-sha2"):
				hash = "SHA-256"
			case strings.Contains(info.algorithmName, "slh-dsa-shake"):
				hash = "SHAKE-256"
			}
			if c.ilm {
				// Plain assignment: ilmPqcProps already appends to the
				// slice it is given. The previous
				// `props = append(props, ilmPqcProps(props, ...)...)`
				// duplicated every property already in props, and was harmless
				// only because props happened to be empty here.
				props = ilmPqcProps(props, info.pqc)
			}
		}
	}

	execEnv := cdx.CryptoExecutionEnvironmentSoftwarePlainRAM

	cryptoProps := cdx.CryptoAlgorithmProperties{
		Primitive:                primitive,
		ParameterSetIdentifier:   paramSetID,
		ExecutionEnvironment:     execEnv,
		CryptoFunctions:          &cryptoFunctions,
		ImplementationPlatform:   c.ImplementationPlatform(),
		Padding:                  padding,
		Curve:                    curveInformation(sigAlg),
		ClassicalSecurityLevel:   classicalSecurityLevel,
		NistQuantumSecurityLevel: nqsl,
	}

	if c.ilm {
		p := cdx.Property{
			Name:  ilm.SignatureAlgorithmFamily,
			Value: algorithmFamily,
		}
		props = append(props, p)
	}

	return cryptoProps, props, hash
}

// curveInformation returns the curve name for ECDSA signature algorithms
func curveInformation(sigAlg x509.SignatureAlgorithm) string {
	switch sigAlg {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256:
		return "secp256r1" // P-256
	case x509.ECDSAWithSHA384:
		return "secp384r1" // P-384
	case x509.ECDSAWithSHA512:
		return "secp521r1" // P-521
	default:
		return ""
	}
}
