package cdxprops

import (
	"crypto"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// HashAlgorithmInfo contains security properties for hash algorithms
type hashAlgorithmInfo struct {
	Name                   string
	ParameterSetIdentifier int
	ClassicalSecurityLevel *int   // Security level in bits; nil = not established
	OID                    string // Object Identifier
}

var unsupportedInfo = hashAlgorithmInfo{
	Name:                   "Unsupported",
	ParameterSetIdentifier: 0,
	// ClassicalSecurityLevel deliberately nil: an unrecognised hash has no
	// established security level, which is not the same as a level of 0.
	OID: "0.0.0.0",
}

var hashInfoMap2 = map[string]hashAlgorithmInfo{
	"MD2": {
		Name:                   "MD2",
		ParameterSetIdentifier: 128,
		ClassicalSecurityLevel: ptr(0),
		OID:                    "1.2.840.113549.2.2",
	},
	// RFC 8702 section 2 assigns the SHAKE identifiers under the NIST
	// hashAlgs arc: id-shake128 = { ... csor(3) nistAlgorithm(4) 2 11 },
	// id-shake256 = { ... csor(3) nistAlgorithm(4) 2 12 }.
	"SHAKE128": {
		Name:                   "SHAKE-128",
		ParameterSetIdentifier: 128,
		ClassicalSecurityLevel: ptr(128),
		OID:                    "2.16.840.1.101.3.4.2.11",
	},
	"SHAKE256": {
		Name:                   "SHAKE-256",
		ParameterSetIdentifier: 256,
		ClassicalSecurityLevel: ptr(256),
		OID:                    "2.16.840.1.101.3.4.2.12",
	},
}

var hashInfoMap = map[crypto.Hash]hashAlgorithmInfo{
	crypto.MD4: {
		Name:                   "MD4",
		ParameterSetIdentifier: 128,
		ClassicalSecurityLevel: ptr(0), // Broken
		OID:                    "1.2.840.113549.2.4",
	},
	crypto.MD5: {
		Name:                   "MD5",
		ParameterSetIdentifier: 128,
		ClassicalSecurityLevel: ptr(0), // Broken
		OID:                    "1.2.840.113549.2.5",
	},
	crypto.SHA1: {
		Name:                   "SHA-1",
		ParameterSetIdentifier: 160,
		ClassicalSecurityLevel: ptr(0), // Broken (collision attacks exist)
		OID:                    "1.3.14.3.2.26",
	},
	crypto.SHA224: {
		Name:                   "SHA-224",
		ParameterSetIdentifier: 224,
		ClassicalSecurityLevel: ptr(112), // 112-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.4",
	},
	crypto.SHA256: {
		Name:                   "SHA-256",
		ParameterSetIdentifier: 256,
		ClassicalSecurityLevel: ptr(128), // 128-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.1",
	},
	crypto.SHA384: {
		Name:                   "SHA-384",
		ParameterSetIdentifier: 384,
		ClassicalSecurityLevel: ptr(192), // 192-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.2",
	},
	crypto.SHA512: {
		Name:                   "SHA-512",
		ParameterSetIdentifier: 512,
		ClassicalSecurityLevel: ptr(256), // 256-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.3",
	},
	crypto.SHA512_224: {
		Name:                   "SHA-512/224",
		ParameterSetIdentifier: 224,
		ClassicalSecurityLevel: ptr(112), // 112-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.5",
	},
	crypto.SHA512_256: {
		Name:                   "SHA-512/256",
		ParameterSetIdentifier: 256,
		ClassicalSecurityLevel: ptr(128), // 128-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.6",
	},
	crypto.SHA3_224: {
		Name:                   "SHA3-224",
		ParameterSetIdentifier: 224,
		ClassicalSecurityLevel: ptr(112), // 112-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.7",
	},
	crypto.SHA3_256: {
		Name:                   "SHA3-256",
		ParameterSetIdentifier: 256,
		ClassicalSecurityLevel: ptr(128), // 128-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.8",
	},
	crypto.SHA3_384: {
		Name:                   "SHA3-384",
		ParameterSetIdentifier: 384,
		ClassicalSecurityLevel: ptr(192), // 192-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.9",
	},
	crypto.SHA3_512: {
		Name:                   "SHA3-512",
		ParameterSetIdentifier: 512,
		ClassicalSecurityLevel: ptr(256), // 256-bit collision resistance
		OID:                    "2.16.840.1.101.3.4.2.10",
	},
	crypto.RIPEMD160: {
		Name:                   "RIPEMD-160",
		ParameterSetIdentifier: 160,
		ClassicalSecurityLevel: ptr(80), // 80-bit collision resistance
		OID:                    "1.3.36.3.2.1",
	},
	crypto.BLAKE2s_256: {
		Name:                   "BLAKE2s-256",
		ParameterSetIdentifier: 256,
		ClassicalSecurityLevel: ptr(128), // 128-bit collision resistance
		OID:                    "1.3.6.1.4.1.1722.12.2.2.8",
	},
	crypto.BLAKE2b_256: {
		Name:                   "BLAKE2b-256",
		ParameterSetIdentifier: 256,
		ClassicalSecurityLevel: ptr(128), // 128-bit collision resistance
		OID:                    "1.3.6.1.4.1.1722.12.2.1.8",
	},
	crypto.BLAKE2b_384: {
		Name:                   "BLAKE2b-384",
		ParameterSetIdentifier: 384,
		ClassicalSecurityLevel: ptr(192), // 192-bit collision resistance
		OID:                    "1.3.6.1.4.1.1722.12.2.1.12",
	},
	crypto.BLAKE2b_512: {
		Name:                   "BLAKE2b-512",
		ParameterSetIdentifier: 512,
		ClassicalSecurityLevel: ptr(256), // 256-bit collision resistance
		OID:                    "1.3.6.1.4.1.1722.12.2.1.16",
	},
}

var stringToHash = map[string]crypto.Hash{
	"MD4":        crypto.MD4,
	"MD5":        crypto.MD5,
	"SHA1":       crypto.SHA1,
	"SHA224":     crypto.SHA224,
	"SHA256":     crypto.SHA256,
	"SHA384":     crypto.SHA384,
	"SHA512":     crypto.SHA512,
	"SHA512/224": crypto.SHA512_224,
	"SHA512/256": crypto.SHA512_256,
	"SHA3224":    crypto.SHA3_224,
	"SHA3256":    crypto.SHA3_256,
	"SHA3384":    crypto.SHA3_384,
	"SHA3512":    crypto.SHA3_512,
	"RIPEMD160":  crypto.RIPEMD160,
	"BLAKE2s256": crypto.BLAKE2s_256,
	"BLAKE2b256": crypto.BLAKE2b_256,
	"BLAKE2b384": crypto.BLAKE2b_384,
	"BLAKE2b512": crypto.BLAKE2b_512,
}

func (c Converter) hashAlgorithmCompo(name string) cdx.Component {
	name = strings.ToUpper(name)
	// normalize hash names
	if name == "SHA" {
		name = "SHA1"
	}
	// drop - everywhere
	name = strings.ReplaceAll(name, "-", "")

	var info hashAlgorithmInfo
	if h, ok := stringToHash[name]; ok {
		if ok {
			info = hashInfoMap[h]
		}
	} else {
		i, ok := hashInfoMap2[name]
		if !ok {
			info = unsupportedInfo
			info.Name = name
		} else {
			info = i
		}
	}

	compo := cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: info.Name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitiveHash,
				ParameterSetIdentifier: strconv.Itoa(info.ParameterSetIdentifier),
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentSoftwarePlainRAM,
				ImplementationPlatform: c.ImplementationPlatform(),
				Mode:                   cdx.CryptoAlgorithmModeUnknown, // Hash functions don't have modes
				Padding:                cdx.CryptoPaddingUnknown,       // Not applicable
				CryptoFunctions: &[]cdx.CryptoFunction{
					cdx.CryptoFunctionDigest,
				},
				ClassicalSecurityLevel: info.ClassicalSecurityLevel,
			},
			OID: info.OID,
		},
	}

	c.BOMRefHash(&compo, "crypto/algorithm/"+strings.ToLower(info.Name))
	return compo
}
