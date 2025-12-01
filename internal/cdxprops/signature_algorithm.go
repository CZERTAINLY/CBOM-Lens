package cdxprops

import (
	"crypto/x509"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"

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

// Public-key OIDs seen in SubjectPublicKeyInfo.algorithm (includes KEMs).
var spkiOIDRef = map[string]cdx.BOMReference{
	// ML-DSA (same OIDs as signature; appears as key type too)
	"2.16.840.1.101.3.4.3.17": "crypto/key/ml-dsa-44@2.16.840.1.101.3.4.3.17",
	"2.16.840.1.101.3.4.3.18": "crypto/key/ml-dsa-65@2.16.840.1.101.3.4.3.18",
	"2.16.840.1.101.3.4.3.19": "crypto/key/ml-dsa-87@2.16.840.1.101.3.4.3.19",

	// ML-KEM (FIPS 203)
	"2.16.840.1.101.3.4.4.1": "crypto/key/ml-kem-512@2.16.840.1.101.3.4.4.1",
	"2.16.840.1.101.3.4.4.2": "crypto/key/ml-kem-768@2.16.840.1.101.3.4.4.2",
	"2.16.840.1.101.3.4.4.3": "crypto/key/ml-kem-1024@2.16.840.1.101.3.4.4.3",

	// SLH-DSA (FIPS 205)
	"2.16.840.1.101.3.4.3.20": "crypto/key/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
	"2.16.840.1.101.3.4.3.21": "crypto/key/slh-dsa-sha2-128f@2.16.840.1.101.3.4.3.21",
	"2.16.840.1.101.3.4.3.22": "crypto/key/slh-dsa-sha2-192s@2.16.840.1.101.3.4.3.22",
	"2.16.840.1.101.3.4.3.23": "crypto/key/slh-dsa-sha2-192f@2.16.840.1.101.3.4.3.23",
	"2.16.840.1.101.3.4.3.24": "crypto/key/slh-dsa-sha2-256s@2.16.840.1.101.3.4.3.24",
	"2.16.840.1.101.3.4.3.25": "crypto/key/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
	"2.16.840.1.101.3.4.3.26": "crypto/key/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
	"2.16.840.1.101.3.4.3.27": "crypto/key/slh-dsa-shake-128f@2.16.840.1.101.3.4.3.27",
	"2.16.840.1.101.3.4.3.28": "crypto/key/slh-dsa-shake-192s@2.16.840.1.101.3.4.3.28",
	"2.16.840.1.101.3.4.3.29": "crypto/key/slh-dsa-shake-192f@2.16.840.1.101.3.4.3.29",
	"2.16.840.1.101.3.4.3.30": "crypto/key/slh-dsa-shake-256s@2.16.840.1.101.3.4.3.30",
	"2.16.840.1.101.3.4.3.31": "crypto/key/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",

	// XMSS / XMSS-MT (IETF, same OIDs show in SPKI)
	"1.3.6.1.5.5.7.6.34": "crypto/key/xmss@1.3.6.1.5.5.7.6.34",
	"1.3.6.1.5.5.7.6.35": "crypto/key/xmss-mt@1.3.6.1.5.5.7.6.35",

	// HSS/LMS (IETF)
	"1.2.840.113549.1.9.16.3.17": "crypto/key/hss-lms@1.2.840.113549.1.9.16.3.17",

	// HQC (ISO/ETSI — commonly used OIDs)
	"1.3.9999.6.1.1": "crypto/key/hqc-128@1.3.9999.6.1.1",
	"1.3.9999.6.1.2": "crypto/key/hqc-192@1.3.9999.6.1.2",
	"1.3.9999.6.1.3": "crypto/key/hqc-256@1.3.9999.6.1.3",
}

// getAlgorithmProperties generates crypto algorithm properties for a signature algorithm
func (c Converter) getAlgorithmProperties(sigAlg x509.SignatureAlgorithm) (cdx.CryptoAlgorithmProperties, []cdx.Property, string) {
	var algorithmFamily string
	var hash string
	var paramSetID string
	var padding cdx.CryptoPadding
	var classicalSecurityLevel int
	var nistQuantumSecurityLevel int

	switch sigAlg {
	case x509.MD2WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "128" // MD2 digest size
		hash = "MD2"

	case x509.MD5WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "128" // MD5 digest size
		hash = "MD5"

	case x509.SHA1WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "160" // SHA-1 digest size
		hash = "SHA-1"

	case x509.SHA256WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "256" // SHA-256 digest size
		padding = cdx.CryptoPaddingPKCS1v15
		hash = "SHA-256"
		classicalSecurityLevel = 112

	case x509.SHA384WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "384" // SHA-384 digest size
		padding = cdx.CryptoPaddingPKCS1v15
		hash = "SHA-384"
		classicalSecurityLevel = 128

	case x509.SHA512WithRSA:
		algorithmFamily = "RSASSA-PKCS1"
		paramSetID = "512" // SHA-512 digest size
		padding = cdx.CryptoPaddingPKCS1v15
		hash = "SHA-512"
		classicalSecurityLevel = 256

	case x509.SHA256WithRSAPSS:
		algorithmFamily = "RSASSA-PSS"
		paramSetID = "256" // SHA-256 digest size
		hash = "SHA-256"
		classicalSecurityLevel = 112

	case x509.SHA384WithRSAPSS:
		algorithmFamily = "RSASSA-PSS"
		paramSetID = "384" // SHA-384 digest size
		hash = "SHA-384"
		classicalSecurityLevel = 128

	case x509.SHA512WithRSAPSS:
		algorithmFamily = "RSASSA-PSS"
		paramSetID = "512" // SHA-512 digest size
		hash = "SHA-512"
		classicalSecurityLevel = 256

	case x509.ECDSAWithSHA1:
		algorithmFamily = "ECDSA"
		paramSetID = "160" // SHA-1 digest size
		hash = "SHA-1"

	case x509.ECDSAWithSHA256:
		algorithmFamily = "ECDSA"
		paramSetID = "256" // SHA-256 digest size
		hash = "SHA-256"
		classicalSecurityLevel = 128

	case x509.ECDSAWithSHA384:
		algorithmFamily = "ECDSA"
		paramSetID = "384" // SHA-384 digest size
		hash = "SHA-384"
		classicalSecurityLevel = 192

	case x509.ECDSAWithSHA512:
		algorithmFamily = "ECDSA"
		paramSetID = "512" // SHA-512 digest size
		hash = "SHA-512"
		classicalSecurityLevel = 256

	case x509.DSAWithSHA1:
		algorithmFamily = "DSA"
		paramSetID = "160" // SHA-1 digest size
		hash = "SHA-1"

	case x509.DSAWithSHA256:
		algorithmFamily = "DSA"
		paramSetID = "256" // SHA-256 digest size
		hash = "SHA-256"
		classicalSecurityLevel = 112

	case x509.PureEd25519:
		algorithmFamily = "EdDSA"
		paramSetID = "256" // Ed25519 key size
		// not a parameter https://www.rfc-editor.org/rfc/rfc8032
		hash = "SHA-512"
		classicalSecurityLevel = 128

	default:
		algorithmFamily = "Unknown"
		paramSetID = "0"
		classicalSecurityLevel = 0
	}

	execEnv := cdx.CryptoExecutionEnvironmentSoftwarePlainRAM
	var nqsl *int
	if nistQuantumSecurityLevel != 0 {
		nqsl = &nistQuantumSecurityLevel
	}

	cryptoProps := cdx.CryptoAlgorithmProperties{
		Primitive:                cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier:   paramSetID,
		ExecutionEnvironment:     execEnv,
		CryptoFunctions:          &[]cdx.CryptoFunction{cdx.CryptoFunctionSign},
		ImplementationPlatform:   c.ImplementationPlatform(),
		Padding:                  padding,
		Curve:                    curveInformation(sigAlg),
		ClassicalSecurityLevel:   &classicalSecurityLevel,
		NistQuantumSecurityLevel: nqsl,
	}

	var props []cdx.Property
	if c.czertainly {
		p := cdx.Property{
			Name:  czertainly.SignatureAlgorithmFamily,
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
