package cdxprops

import (
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Internal shared structure for algorithm metadata
type algorithmInfo struct {
	name                     string
	oid                      string
	paramSetID               string
	keySize                  int
	algorithmName            string
	cryptoFunctions          []cdx.CryptoFunction
	classicalSecurityLevel   int
	nistQuantumSecurityLevel int
	pqc                      isPqcInfo
}

type isPqcInfo interface {
	isPqcInfo()
}

type pqcInfo struct {
	privKeySize   int
	pubKeySize    int
	signatureSize int
}

func (pqcInfo) isPqcInfo() {}

var unsupportedAlgorithms = map[string]algorithmInfo{
	// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
	"2.16.840.1.101.3.4.3.17": {
		name:          "ML-DSA-44",
		oid:           "2.16.840.1.101.3.4.3.17",
		paramSetID:    "44",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-44",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: 2,
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
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 3,
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
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   4896,
			pubKeySize:    2592,
			signatureSize: 4627,
		},
	},
	// SLH-DSA (FIPS 205) — SHA2: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
	"2.16.840.1.101.3.4.3.20": {
		name:          "SLH-DSA-SHA2-128S",
		oid:           "2.16.840.1.101.3.4.3.20",
		paramSetID:    "128S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-sha2-128s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: 1,
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
		},
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: 1,
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
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 3,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
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
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 3,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
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
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 17088,
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
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 37760,
		},
	},
	// SLH-DSA (FIPS 205) — SHAKE
	"2.16.840.1.101.3.4.3.26": {
		name:          "SLH-DSA-SHAKE-128S",
		oid:           "2.16.840.1.101.3.4.3.26",
		paramSetID:    "128S",
		keySize:       0,
		algorithmName: "crypto/algorithm/slh-dsa-shake-128s",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: 1,
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
		},
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: 1,
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
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 3,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
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
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 3,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
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
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 17088,
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
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   64,
			pubKeySize:    32,
			signatureSize: 37760,
		},
	},
	// XMSS / XMSS-MT (IETF, same OIDs show in SPKI)
	"1.3.6.1.5.5.7.6.34": {
		name:          "XMSS",
		oid:           "1.3.6.1.5.5.7.6.34",
		paramSetID:    "xmss",
		keySize:       0,
		algorithmName: "crypto/algorithm/xmss",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   4,
			pubKeySize:    32,
			signatureSize: 2144,
		},
	},
	"1.3.6.1.5.5.7.6.35": {
		name:          "XMSS-MT",
		oid:           "1.3.6.1.5.5.7.6.35",
		paramSetID:    "xmss-mt",
		keySize:       0,
		algorithmName: "crypto/algorithm/xmss-mt",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   4,
			pubKeySize:    32,
			signatureSize: 2144,
		},
	},
	// HSS/LMS (IETF)
	"1.2.840.113549.1.9.16.3.17": {
		name:          "HSS-LMS",
		oid:           "1.2.840.113549.1.9.16.3.17",
		paramSetID:    "hss-lms",
		keySize:       0,
		algorithmName: "crypto/algorithm/hss-lms",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   0, // Variable
			pubKeySize:    32,
			signatureSize: 0, // Variable
		},
	},
	// HQC (ISO/ETSI — commonly used OIDs)
	"1.3.9999.6.1.1": {
		name:          "HQC-128",
		oid:           "1.3.9999.6.1.1",
		paramSetID:    "128",
		keySize:       0,
		algorithmName: "crypto/algorithm/hqc-128",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionEncrypt,
		},
		classicalSecurityLevel:   128,
		nistQuantumSecurityLevel: 1,
		pqc: pqcInfo{
			privKeySize:   2176,
			pubKeySize:    2176,
			signatureSize: 256,
		},
	},
	"1.3.9999.6.1.2": {
		name:          "HQC-192",
		oid:           "1.3.9999.6.1.2",
		paramSetID:    "192",
		keySize:       0,
		algorithmName: "crypto/algorithm/hqc-192",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionEncrypt,
		},
		classicalSecurityLevel:   192,
		nistQuantumSecurityLevel: 3,
		pqc: pqcInfo{
			privKeySize:   4096,
			pubKeySize:    4096,
			signatureSize: 384,
		},
	},
	"1.3.9999.6.1.3": {
		name:          "HQC-256",
		oid:           "1.3.9999.6.1.3",
		paramSetID:    "256",
		keySize:       0,
		algorithmName: "crypto/algorithm/hqc-256",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionEncrypt,
		},
		classicalSecurityLevel:   256,
		nistQuantumSecurityLevel: 5,
		pqc: pqcInfo{
			privKeySize:   8192,
			pubKeySize:    8192,
			signatureSize: 512,
		},
	},
}

// extractAlgorithmInfo is the unified internal function
func extractAlgorithmInfo(keyType string, key any) algorithmInfo {
	var meta algorithmInfo

	switch keyType {
	case "RSA":
		meta.oid = "1.2.840.113549.1.1.1"
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
		}

		// Try to extract size from actual key if available
		if rsaKey, ok := key.(interface{ BitLen() int }); ok {
			meta.keySize = rsaKey.BitLen()
			meta.paramSetID = fmt.Sprintf("%d", meta.keySize)
			meta.name = fmt.Sprintf("RSA-%d", meta.keySize)
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/rsa-%d", meta.keySize)
			switch meta.keySize {
			case 1024:
				meta.classicalSecurityLevel = 80
			case 2048:
				meta.classicalSecurityLevel = 112
			case 3072:
				meta.classicalSecurityLevel = 128
			case 4096:
				meta.classicalSecurityLevel = 152
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

			switch curveName {
			case "P-224":
				meta.oid = "1.2.840.10045.3.1.1"
				meta.classicalSecurityLevel = 80
			case "P-256":
				meta.oid = "1.2.840.10045.3.1.7"
				meta.classicalSecurityLevel = 128
			case "P-384":
				meta.oid = "1.3.132.0.34"
				meta.classicalSecurityLevel = 192
			case "P-521":
				meta.oid = "1.3.132.0.35"
				meta.classicalSecurityLevel = 256
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
		meta.classicalSecurityLevel = 128
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
				meta.classicalSecurityLevel = 80
			case 2048:
				meta.classicalSecurityLevel = 112
			case 3072:
				meta.classicalSecurityLevel = 128
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

func (i algorithmInfo) componentWOBomRef(withCzertainly bool) cdx.Component {
	var nqsl *int
	if i.nistQuantumSecurityLevel != 0 {
		nqsl = &i.nistQuantumSecurityLevel
	}

	cryptoProps := &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
			ExecutionEnvironment:     cdx.CryptoExecutionEnvironmentSoftwarePlainRAM,
			CryptoFunctions:          &i.cryptoFunctions,
			ClassicalSecurityLevel:   &i.classicalSecurityLevel,
			NistQuantumSecurityLevel: nqsl,
		},
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

func czertainlyPqcProps(props []cdx.Property, x isPqcInfo) []cdx.Property {
	switch i := x.(type) {
	case pqcInfo:
		return pqcProps(props, i)
	}
	return nil
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
