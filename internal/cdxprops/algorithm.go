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
	name                   string
	oid                    string
	paramSetID             string
	keySize                int
	algorithmName          string
	cryptoFunctions        []cdx.CryptoFunction
	classicalSecurityLevel int
	pqc                    pqcInfo
}

type pqcInfo struct {
	nistQuantumSecurityLevel int
	privKeySize              int
	pubKeySize               int
	signatureSize            int
}

var pqcAlgorithms = map[string]algorithmInfo{
	// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
	"ML-DSA-44": {
		name:          "ML-DSA-44",
		oid:           "2.16.840.1.101.3.4.3.17",
		paramSetID:    "44",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-44",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel: 128,
		pqc: pqcInfo{
			nistQuantumSecurityLevel: 2,
			privKeySize:              2560,
			pubKeySize:               1312,
			signatureSize:            2420,
		},
	},
	"ML-DSA-65": {
		name:          "ML-DSA-65",
		oid:           "2.16.840.1.101.3.4.3.18",
		paramSetID:    "65",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-65",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel: 192,
		pqc: pqcInfo{
			nistQuantumSecurityLevel: 3,
			privKeySize:              4032,
			pubKeySize:               1952,
			signatureSize:            3309,
		},
	},
	"ML-DSA-87": {
		name:          "ML-DSA-87",
		oid:           "2.16.840.1.101.3.4.3.19",
		paramSetID:    "87",
		keySize:       0,
		algorithmName: "crypto/algorithm/ml-dsa-87",
		cryptoFunctions: []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
		},
		classicalSecurityLevel: 192,
		pqc: pqcInfo{
			nistQuantumSecurityLevel: 5,
			privKeySize:              4896,
			pubKeySize:               2592,
			signatureSize:            4627,
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

	case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
		return pqcAlgorithms[keyType]

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
	if i.pqc.nistQuantumSecurityLevel != 0 {
		nqsl = &i.pqc.nistQuantumSecurityLevel
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

	if withCzertainly && nqsl != nil {
		compo.Properties = &[]cdx.Property{
			{
				Name:  czertainly.AlgorithmPrivateKeySize,
				Value: strconv.Itoa(i.pqc.privKeySize),
			},
			{
				Name:  czertainly.AlgorithmPublicKeySize,
				Value: strconv.Itoa(i.pqc.pubKeySize),
			},
			{
				Name:  czertainly.AlgorithmSignatureSize,
				Value: strconv.Itoa(i.pqc.signatureSize),
			},
		}
	}
	return compo
}
