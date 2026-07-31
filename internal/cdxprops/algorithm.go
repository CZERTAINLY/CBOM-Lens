package cdxprops

import (
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ptr returns a pointer to v. It exists so registry literals can distinguish
// "unspecified" from a genuine zero value.
func ptr[T any](v T) *T {
	return &v
}

// Internal shared structure for algorithm metadata
type algorithmInfo struct {
	name            string
	oid             string
	paramSetID      string
	keySize         int
	algorithmName   string
	cryptoFunctions []cdx.CryptoFunction
	// nil means "not established". A real 0 (MD5, SHA-1) is a claim; absence
	// is not. Emitting 0 for an unrecognised algorithm asserted that it has
	// zero bits of classical security, which is a different statement.
	classicalSecurityLevel *int
	// nistQuantumSecurityLevel is a pointer so that "no standard assigns a
	// category" (nil, field omitted) stays distinguishable from the genuine
	// claim "meets none of the NIST categories" (ptr(0), field emitted as 0).
	// CycloneDX gives 0 that specific meaning, so collapsing the two would
	// make cbom-lens assert something no standard says.
	nistQuantumSecurityLevel *int
	pqc                      isPqcInfo
	// primitive is the CycloneDX cryptographic primitive. Empty means the
	// caller decides, which is what the classical switch-ladder path relies on
	// (publicKeyComponents derives signature vs pke from the certificate's
	// KeyUsage). Registry entries state it, because a KEM is not a signature
	// scheme and no amount of KeyUsage inspection will turn it into one.
	primitive cdx.CryptoPrimitive
}

type isPqcInfo interface {
	isPqcInfo()
}

// pqcInfo holds the sizes of a post-quantum signature scheme.
type pqcInfo struct {
	privKeySize   int
	pubKeySize    int
	signatureSize int
}

func (pqcInfo) isPqcInfo() {}

// kemInfo holds the sizes of a key-encapsulation mechanism. A KEM has no
// signature, and its two keys are an encapsulation key and a decapsulation
// key rather than a public/private signing pair, so it needs its own shape;
// reusing pqcInfo would have meant reporting a signature size for something
// that cannot sign.
type kemInfo struct {
	encapKeySize   int
	decapKeySize   int
	ciphertextSize int
}

func (kemInfo) isPqcInfo() {}

var unsupportedAlgorithms = map[string]algorithmInfo{
	// ML-DSA (FIPS 204). Object identifiers from RFC 9881 sec. 3
	// (nistAlgorithm(4) sigAlgs(3) 17..19). Claimed security categories and
	// lambda (the "collision strength of c-tilde" column, used here as the
	// classical security level) from FIPS 204 Table 1. Key and signature
	// sizes from FIPS 204 Table 2.
	"2.16.840.1.101.3.4.3.17": {
		name:          "ML-DSA-44",
		oid:           "2.16.840.1.101.3.4.3.17",
		paramSetID:    "44",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-44",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(128),
		nistQuantumSecurityLevel: ptr(2),
		pqc: pqcInfo{
			privKeySize:   2560,
			pubKeySize:    1312,
			signatureSize: 2420,
		},
	},
	"2.16.840.1.101.3.4.3.18": {
		name:          "ML-DSA-65",
		oid:           "2.16.840.1.101.3.4.3.18",
		paramSetID:    "65",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-65",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(192),
		nistQuantumSecurityLevel: ptr(3),
		pqc: pqcInfo{
			privKeySize:   4032,
			pubKeySize:    1952,
			signatureSize: 3309,
		},
	},
	"2.16.840.1.101.3.4.3.19": {
		name:          "ML-DSA-87",
		oid:           "2.16.840.1.101.3.4.3.19",
		paramSetID:    "87",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-87",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(256),
		nistQuantumSecurityLevel: ptr(5),
		pqc: pqcInfo{
			privKeySize:   4896,
			pubKeySize:    2592,
			signatureSize: 4627,
		},
	},

	// SLH-DSA (FIPS 205) — SHA2. Object identifiers registered in the NIST
	// CSOR under nistAlgorithm(4) sigAlgs(3) 20..31. Security categories and
	// public key / signature sizes from FIPS 205 Table 2; private key sizes
	// (4n bytes) from RFC 9909 App. B Table 1, which tabulates all three.
	// Classical levels from RFC 9909 sec. 1: the three security levels are
	// "at least as secure as a generic block cipher of 128, 192, or 256 bits".
	"2.16.840.1.101.3.4.3.20": {
		name:          "SLH-DSA-SHA2-128S",
		oid:           "2.16.840.1.101.3.4.3.20",
		paramSetID:    "128S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-128s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(128),
		nistQuantumSecurityLevel: ptr(1),
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 7856,
		},
	},
	"2.16.840.1.101.3.4.3.21": {
		name:          "SLH-DSA-SHA2-128F",
		oid:           "2.16.840.1.101.3.4.3.21",
		paramSetID:    "128F",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-128f",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(128),
		nistQuantumSecurityLevel: ptr(1),
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 17088,
		},
	},
	"2.16.840.1.101.3.4.3.22": {
		name:          "SLH-DSA-SHA2-192S",
		oid:           "2.16.840.1.101.3.4.3.22",
		paramSetID:    "192S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-192s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(192),
		nistQuantumSecurityLevel: ptr(3),
		pqc: pqcInfo{
			privKeySize:   96,
			pubKeySize:    48,
			signatureSize: 16224,
		},
	},
	"2.16.840.1.101.3.4.3.23": {
		name:          "SLH-DSA-SHA2-192F",
		oid:           "2.16.840.1.101.3.4.3.23",
		paramSetID:    "192F",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-192f",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(192),
		nistQuantumSecurityLevel: ptr(3),
		pqc: pqcInfo{
			privKeySize:   96,
			pubKeySize:    48,
			signatureSize: 35664,
		},
	},
	"2.16.840.1.101.3.4.3.24": {
		name:          "SLH-DSA-SHA2-256S",
		oid:           "2.16.840.1.101.3.4.3.24",
		paramSetID:    "256S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-256s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(256),
		nistQuantumSecurityLevel: ptr(5),
		pqc: pqcInfo{
			privKeySize:   128,
			pubKeySize:    64,
			signatureSize: 29792,
		},
	},
	"2.16.840.1.101.3.4.3.25": {
		name:          "SLH-DSA-SHA2-256F",
		oid:           "2.16.840.1.101.3.4.3.25",
		paramSetID:    "256F",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-256f",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(256),
		nistQuantumSecurityLevel: ptr(5),
		pqc: pqcInfo{
			privKeySize:   128,
			pubKeySize:    64,
			signatureSize: 49856,
		},
	},

	// SLH-DSA (FIPS 205) — SHAKE. RFC 9909 App. B: byte-identical sizes to
	// the SHA2 parameter sets at the same security level.
	"2.16.840.1.101.3.4.3.26": {
		name:          "SLH-DSA-SHAKE-128S",
		oid:           "2.16.840.1.101.3.4.3.26",
		paramSetID:    "128S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-128s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(128),
		nistQuantumSecurityLevel: ptr(1),
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 7856,
		},
	},
	"2.16.840.1.101.3.4.3.27": {
		name:          "SLH-DSA-SHAKE-128F",
		oid:           "2.16.840.1.101.3.4.3.27",
		paramSetID:    "128F",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-128f",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(128),
		nistQuantumSecurityLevel: ptr(1),
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 17088,
		},
	},
	"2.16.840.1.101.3.4.3.28": {
		name:          "SLH-DSA-SHAKE-192S",
		oid:           "2.16.840.1.101.3.4.3.28",
		paramSetID:    "192S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-192s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(192),
		nistQuantumSecurityLevel: ptr(3),
		pqc: pqcInfo{
			privKeySize:   96,
			pubKeySize:    48,
			signatureSize: 16224,
		},
	},
	"2.16.840.1.101.3.4.3.29": {
		name:          "SLH-DSA-SHAKE-192F",
		oid:           "2.16.840.1.101.3.4.3.29",
		paramSetID:    "192F",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-192f",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(192),
		nistQuantumSecurityLevel: ptr(3),
		pqc: pqcInfo{
			privKeySize:   96,
			pubKeySize:    48,
			signatureSize: 35664,
		},
	},
	"2.16.840.1.101.3.4.3.30": {
		name:          "SLH-DSA-SHAKE-256S",
		oid:           "2.16.840.1.101.3.4.3.30",
		paramSetID:    "256S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-256s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(256),
		nistQuantumSecurityLevel: ptr(5),
		pqc: pqcInfo{
			privKeySize:   128,
			pubKeySize:    64,
			signatureSize: 29792,
		},
	},
	"2.16.840.1.101.3.4.3.31": {
		name:          "SLH-DSA-SHAKE-256F",
		oid:           "2.16.840.1.101.3.4.3.31",
		paramSetID:    "256F",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-256f",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive:                cdx.CryptoPrimitiveSignature,
		classicalSecurityLevel:   ptr(256),
		nistQuantumSecurityLevel: ptr(5),
		pqc: pqcInfo{
			privKeySize:   128,
			pubKeySize:    64,
			signatureSize: 49856,
		},
	},

	// ML-KEM (FIPS 203). Object identifiers registered in the NIST CSOR under
	// kems ::= { nistAlgorithms 4 }: id-alg-ml-kem-512(1), -768(2), -1024(3).
	// FIPS 203 itself assigns no OIDs. OpenSSL 3.5.3 reports the same three
	// identifiers for its ML-KEM implementations, which corroborates them.
	//
	// Security categories from FIPS 203 sec. 8: "ML-KEM-512 is claimed to be
	// in security category 1, ML-KEM-768 ... category 3, and ML-KEM-1024 ...
	// category 5." classicalSecurityLevel is the "required RBG strength
	// (bits)" column of FIPS 203 Table 2: 128 / 192 / 256.
	//
	// Sizes from FIPS 203 Table 3, "Sizes (in bytes) of keys and ciphertexts
	// of ML-KEM". The shared secret is 32 bytes for all three parameter sets
	// and is not a property of the algorithm identifier, so it is not modelled.
	"2.16.840.1.101.3.4.4.1": {
		name:          "ML-KEM-512",
		oid:           "2.16.840.1.101.3.4.4.1",
		paramSetID:    "512",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-kem-512",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
		},
		primitive:                cdx.CryptoPrimitiveKEM,
		classicalSecurityLevel:   ptr(128),
		nistQuantumSecurityLevel: ptr(1),
		pqc: kemInfo{
			encapKeySize:   800,
			decapKeySize:   1632,
			ciphertextSize: 768,
		},
	},
	"2.16.840.1.101.3.4.4.2": {
		name:          "ML-KEM-768",
		oid:           "2.16.840.1.101.3.4.4.2",
		paramSetID:    "768",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-kem-768",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
		},
		primitive:                cdx.CryptoPrimitiveKEM,
		classicalSecurityLevel:   ptr(192),
		nistQuantumSecurityLevel: ptr(3),
		pqc: kemInfo{
			encapKeySize:   1184,
			decapKeySize:   2400,
			ciphertextSize: 1088,
		},
	},
	"2.16.840.1.101.3.4.4.3": {
		name:          "ML-KEM-1024",
		oid:           "2.16.840.1.101.3.4.4.3",
		paramSetID:    "1024",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-kem-1024",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
		},
		primitive:                cdx.CryptoPrimitiveKEM,
		classicalSecurityLevel:   ptr(256),
		nistQuantumSecurityLevel: ptr(5),
		pqc: kemInfo{
			encapKeySize:   1568,
			decapKeySize:   3168,
			ciphertextSize: 1568,
		},
	},

	// XMSS and XMSS-MT. Object identifiers from RFC 9802 sec. 2:
	// id-alg-xmss-hashsig(34) and id-alg-xmssmt-hashsig(35) under
	// pkix(7) algorithms(6).
	"1.3.6.1.5.5.7.6.34": {
		name:          "XMSS",
		oid:           "1.3.6.1.5.5.7.6.34",
		paramSetID:    "xmss",
		keySize:       0,
		algorithmName: "crypto/algorithm/xmss",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive: cdx.CryptoPrimitiveSignature,
		// classicalSecurityLevel assumes the n=32 (SHA-256) parameter
		// families. The AlgorithmIdentifier does not carry the parameter set,
		// so this is the best available approximation; see docs/pqc-support.md.
		classicalSecurityLevel: ptr(256),
		// nistQuantumSecurityLevel is deliberately unset. SP 800-208 assigns
		// no NIST security category to stateful hash-based signatures. The
		// field must be omitted rather than set to 0, because CycloneDX
		// defines 0 as "meets none of the categories".
		nistQuantumSecurityLevel: nil,
		// pqc is deliberately nil. RFC 9802 sec. 2: the public key and
		// signature values themselves identify the hash function and tree
		// height, so the sizes are not derivable from the OID we matched on.
		pqc: nil,
	},
	"1.3.6.1.5.5.7.6.35": {
		name:          "XMSS-MT",
		oid:           "1.3.6.1.5.5.7.6.35",
		paramSetID:    "xmss-mt",
		keySize:       0,
		algorithmName: "crypto/algorithm/xmss-mt",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive: cdx.CryptoPrimitiveSignature,
		// classicalSecurityLevel assumes the n=32 (SHA-256) parameter
		// families. The AlgorithmIdentifier does not carry the parameter set,
		// so this is the best available approximation; see docs/pqc-support.md.
		classicalSecurityLevel: ptr(256),
		// nistQuantumSecurityLevel is deliberately unset. SP 800-208 assigns
		// no NIST security category to stateful hash-based signatures. The
		// field must be omitted rather than set to 0, because CycloneDX
		// defines 0 as "meets none of the categories".
		nistQuantumSecurityLevel: nil,
		// pqc is deliberately nil. RFC 9802 sec. 2: the public key and
		// signature values themselves identify the hash function and tree
		// height, so the sizes are not derivable from the OID we matched on.
		pqc: nil,
	},

	// HSS/LMS. Object identifier from RFC 9708 sec. 2:
	// id-alg-hss-lms-hashsig = 1.2.840.113549.1.9.16.3.17.
	"1.2.840.113549.1.9.16.3.17": {
		name:          "HSS-LMS",
		oid:           "1.2.840.113549.1.9.16.3.17",
		paramSetID:    "hss-lms",
		keySize:       0,
		algorithmName: "crypto/algorithm/hss-lms",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		},
		primitive: cdx.CryptoPrimitiveSignature,
		// classicalSecurityLevel assumes the n=32 (SHA-256) parameter
		// families. The AlgorithmIdentifier does not carry the parameter set,
		// so this is the best available approximation; see docs/pqc-support.md.
		classicalSecurityLevel: ptr(256),
		// nistQuantumSecurityLevel is deliberately unset. SP 800-208 assigns
		// no NIST security category to stateful hash-based signatures. The
		// field must be omitted rather than set to 0, because CycloneDX
		// defines 0 as "meets none of the categories".
		nistQuantumSecurityLevel: nil,
		// pqc is deliberately nil. RFC 9802 sec. 2: the public key and
		// signature values themselves identify the hash function and tree
		// height, so the sizes are not derivable from the OID we matched on.
		pqc: nil,
	},

	// HQC is deliberately absent.
	//
	// HQC has no assigned object identifier. The NIST CSOR algorithm
	// registration page has no HQC arc (FIPS 207 is unpublished), and
	// open-quantum-safe/oqs-provider records the OID of every HQC variant as
	// NULL in ALGORITHMS.md.
	//
	// This map used to claim 1.3.9999.6.1.{1,2,3} for HQC-128/192/256. Those
	// three OIDs exist, but they are not HQC: in oqs-provider's
	// oqs-template/generate.yml they belong to SPHINCS+-Haraka-128f-robust
	// (NIST Round 3) and its p256 and rsa3072 hybrid variants. Matching them
	// as HQC turned a SPHINCS+ signature artifact into a reported HQC KEM.
	//
	// See docs/pqc-support.md for the documented gap.
}

// extractAlgorithmInfo is the unified internal function
func extractAlgorithmInfo(keyType string, key any) algorithmInfo {
	var meta algorithmInfo

	switch keyType {
	case "RSA":
		meta.oid = "1.2.840.113549.1.1.1"
		// encapsulate/decapsulate are KEM functions. An rsaEncryption key is
		// not a KEM: it encrypts, decrypts, signs and verifies. This matches
		// what the ECDSA and Ed25519 cases below declare for themselves.
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionEncrypt,
			cdx.CryptoFunctionDecrypt,
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}

		// Try to extract size from actual key if available
		if rsaKey, ok := key.(interface{ BitLen() int }); ok {
			meta.keySize = rsaKey.BitLen()
			meta.paramSetID = fmt.Sprintf("%d", meta.keySize)
			meta.name = fmt.Sprintf("RSA-%d", meta.keySize)
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/rsa-%d", meta.keySize)
			switch meta.keySize {
			case 1024:
				meta.classicalSecurityLevel = ptr(80)
			case 2048:
				meta.classicalSecurityLevel = ptr(112)
			case 3072:
				meta.classicalSecurityLevel = ptr(128)
			case 4096:
				meta.classicalSecurityLevel = ptr(152)
			}
		} else {
			meta.name = "RSA"
			meta.algorithmName = "crypto/algorithm/rsa"
		}

	case "ECDSA":
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}

		// Try to extract curve info
		type curveProvider interface {
			GetCurve() elliptic.Curve
		}

		if cp, ok := key.(curveProvider); ok && cp.GetCurve() != nil {
			curve := cp.GetCurve()
			curveName := curve.Params().Name
			meta.keySize = curve.Params().BitSize
			meta.paramSetID = curveName
			meta.name = fmt.Sprintf("ECDSA-%s", curveName)

			// Named-curve OIDs per RFC 5480 section 2.1.1.1 and bits of
			// security per RFC 5480 section 4.
			switch curveName {
			case "P-224":
				// secp224r1 ::= { iso(1) identified-organization(3)
				//                 certicom(132) curve(0) 33 }
				// RFC 5480 sec. 2.1.1.1; 112-bit level per sec. 4.
				meta.oid = "1.3.132.0.33"
				meta.classicalSecurityLevel = ptr(112)
			case "P-256":
				meta.oid = "1.2.840.10045.3.1.7"
				meta.classicalSecurityLevel = ptr(128)
			case "P-384":
				meta.oid = "1.3.132.0.34"
				meta.classicalSecurityLevel = ptr(192)
			case "P-521":
				meta.oid = "1.3.132.0.35"
				meta.classicalSecurityLevel = ptr(256)
			default:
				meta.oid = "1.2.840.10045.2.1"
			}
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/ecdsa-%s", strings.ToLower(curveName))
		} else {
			meta.name = "ECDSA"
			meta.oid = "1.2.840.10045.2.1"
			meta.algorithmName = "crypto/algorithm/ecdsa"
		}

	case "Ed25519":
		meta.name = "Ed25519"
		meta.oid = "1.3.101.112" //NOSONAR - this is OID and not IP address
		meta.paramSetID = "256"
		meta.keySize = 256
		meta.classicalSecurityLevel = ptr(128)
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}
		meta.algorithmName = "crypto/algorithm/ed25519"

	case "DSA":
		meta.oid = "1.2.840.10040.4.1"
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}

		if dsaKey, ok := key.(interface{ BitLen() int }); ok {
			meta.keySize = dsaKey.BitLen()
			switch dsaKey.BitLen() {
			case 1024:
				meta.classicalSecurityLevel = ptr(80)
			case 2048:
				meta.classicalSecurityLevel = ptr(112)
			case 3072:
				meta.classicalSecurityLevel = ptr(128)
			}
			meta.paramSetID = fmt.Sprintf("%d", meta.keySize)
			meta.name = fmt.Sprintf("DSA-%d", meta.keySize)
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/dsa-%d", meta.keySize)
		} else {
			meta.name = "DSA"
			meta.algorithmName = "crypto/algorithm/dsa"
		}

	default:
		meta.name = "Unknown"
		meta.oid = "0.0.0.0"
		meta.algorithmName = "crypto/algorithm/unknown"
	}

	return meta
}

// Adapters to provide unified interfaces
type rsaKeyAdapter struct {
	key *rsa.PublicKey
}

func (a rsaKeyAdapter) BitLen() int {
	return a.key.N.BitLen()
}

type ecKeyAdapter struct {
	key *ecdsa.PublicKey
}

func (a ecKeyAdapter) GetCurve() elliptic.Curve {
	return a.key.Curve
}

type dsaKeyAdapter struct {
	key *dsa.PublicKey
}

func (a dsaKeyAdapter) BitLen() int {
	return a.key.P.BitLen()
}

// sortedCryptoFunctions returns a sorted copy of fns, or nil when fns is
// empty. Sorting keeps the emitted document stable, which matters because
// component BOMRefs are content hashes over the serialized component.
func sortedCryptoFunctions(fns []cdx.CryptoFunction) []cdx.CryptoFunction {
	if len(fns) == 0 {
		return nil
	}
	out := slices.Clone(fns)
	slices.SortFunc(out, func(a, b cdx.CryptoFunction) int {
		return strings.Compare(string(a), string(b))
	})
	return out
}

func (i algorithmInfo) componentWOBomRef(withCzertainly bool) cdx.Component {
	var nqsl *int
	if i.nistQuantumSecurityLevel != nil {
		// Copy the value rather than aliasing the registry's pointer: the
		// emitted component is handed to callers who may mutate it, and
		// unsupportedAlgorithms is package-global shared state.
		nqsl = ptr(*i.nistQuantumSecurityLevel)
	}

	sortedFunctions := sortedCryptoFunctions(i.cryptoFunctions)

	algoProps := &cdx.CryptoAlgorithmProperties{
		ExecutionEnvironment:     cdx.CryptoExecutionEnvironmentSoftwarePlainRAM,
		ClassicalSecurityLevel:   i.classicalSecurityLevel,
		NistQuantumSecurityLevel: nqsl,
	}
	if len(sortedFunctions) > 0 {
		algoProps.CryptoFunctions = &sortedFunctions
	}

	cryptoProps := &cdx.CryptoProperties{
		AssetType:           cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: algoProps,
	}

	if i.oid != "" {
		cryptoProps.OID = i.oid
	}

	if i.paramSetID != "" {
		cryptoProps.AlgorithmProperties.ParameterSetIdentifier = i.paramSetID
	}

	compo := cdx.Component{
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             i.name,
		CryptoProperties: cryptoProps,
	}

	var props []cdx.Property
	if withCzertainly {
		props = czertainlyPqcProps(props, i.pqc)
	}

	if len(props) > 0 {
		compo.Properties = &props
	}
	return compo
}

// czertainlyPqcProps appends the czertainly size properties for x to props and
// returns the result. When x carries no size metadata it returns props
// unchanged, so callers can always assign the result back.
//
// It used to return nil in that case, which made the natural call
// `props = czertainlyPqcProps(props, ...)` silently discard everything the
// caller had already collected.
func czertainlyPqcProps(props []cdx.Property, x isPqcInfo) []cdx.Property {
	switch i := x.(type) {
	case pqcInfo:
		return pqcProps(props, i)
	case kemInfo:
		return kemProps(props, i)
	}
	return props
}

func kemProps(props []cdx.Property, i kemInfo) []cdx.Property {
	return append(props, []cdx.Property{
		// The decapsulation key is the KEM's private half and the
		// encapsulation key its public half, so they reuse the existing
		// property names rather than inventing parallel ones.
		{
			Name:  czertainly.AlgorithmPrivateKeySize,
			Value: strconv.Itoa(i.decapKeySize),
		},
		{
			Name:  czertainly.AlgorithmPublicKeySize,
			Value: strconv.Itoa(i.encapKeySize),
		},
		{
			Name:  czertainly.AlgorithmCiphertextSize,
			Value: strconv.Itoa(i.ciphertextSize),
		},
	}...)
}

func pqcProps(props []cdx.Property, i pqcInfo) []cdx.Property {
	props2 := []cdx.Property{
		{
			Name:  czertainly.AlgorithmPrivateKeySize,
			Value: strconv.Itoa(i.privKeySize),
		},
		{
			Name:  czertainly.AlgorithmPublicKeySize,
			Value: strconv.Itoa(i.pubKeySize),
		},
		{
			Name:  czertainly.AlgorithmSignatureSize,
			Value: strconv.Itoa(i.signatureSize),
		},
	}
	return append(props, props2...)
}
