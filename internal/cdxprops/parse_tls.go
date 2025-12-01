package cdxprops

import (
	"strconv"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type Protocol uint8

const (
	ProtocolUnknown = iota
	SSL
	TLS
)

type KeyExchangeAlgorithm string

const (
	KexDHE   = "DHE"
	KexECDHE = "ECDHE"
	KexRSA   = "RSA"
)

type KeyAuthenticationAlgorithm string

const (
	KauthEmpty = ""
	KauthECDSA = "ECDSA"
	KauthRSA   = "RSA"
)

type KeyExchange struct {
	Exchange KeyExchangeAlgorithm
	Auth     KeyAuthenticationAlgorithm
}

type CipherAlgorithm string

const (
	CipherUnknown  = "UNKNOWN"
	CipherRC4      = "RC4"
	Cipher3DES     = "3DES"
	CipherAES      = "AES"
	CipherCHACHA20 = "CHACHA20"
)

type KeyLen int

const (
	KeyLenUnspecified = 0
	KeyLen128         = 128
	KeyLen168         = 168
	KeyLen256         = 256
)

type CipherMode string

const (
	CipherModeCBC      = "CBC"
	CipherModeCCM      = "CCM"
	CipherModeEDE_CBC  = "EDE_CBC"
	CipherModeEmpty    = ""
	CipherModeGCM      = "GCM"
	CipherModePOLY1305 = "POLY1305"
	CipherModeUnknown  = "UNKNOWN"
)

type HashAlgorithm string

const (
	HashSHA    = "SHA"
	HashSHA256 = "SHA256"
	HashSHA384 = "SHA384"
)

type CipherSuite struct {
	Protocol    Protocol
	KeyExchange KeyExchange
	KexInfo     string
	Cipher      CipherAlgorithm
	KeyLen      KeyLen
	Mode        CipherMode
	Hash        HashAlgorithm
	Name        string
	Code        CipherSuiteCode
}

func (kex KeyExchangeAlgorithm) info(kexInfo string) (algorithmInfo, bool) {
	cryptoFunctions := []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive, cdx.CryptoFunctionKeygen}
	switch kex {
	case KexDHE:
		var level int
		var size int
		switch kexInfo {
		case "1024":
			level = 80
			size = 1024
		case "2048":
			level = 112
			size = 2048
		case "3072":
			level = 128
			size = 3072
		case "4096":
			level = 152
			size = 4096
		default:
			level = 112 // default to 2048 bits
			size = 2048
		}
		return algorithmInfo{
			name:                   "DHE-" + strconv.Itoa(size),
			oid:                    "1.2.840.113549.1.3.1",
			algorithmName:          "crypto/algorithm/dhe-" + strconv.Itoa(size),
			paramSetID:             kexInfo,
			cryptoFunctions:        cryptoFunctions,
			classicalSecurityLevel: level,
		}, true
	case KexECDHE:
		return algorithmInfo{
			name:                   "ECDHE-" + kexInfo,
			oid:                    "1.3.132.1.12",
			algorithmName:          "crypto/algorithm/ecdhe-" + kexInfo,
			paramSetID:             kexInfo,
			cryptoFunctions:        cryptoFunctions,
			classicalSecurityLevel: inferECDSASecurityLevel(kexInfo),
		}, true
	case KexRSA:
		if kexInfo == "" {
			kexInfo = "2048"
		}
		return algorithmInfo{
			name:                   "RSA-" + kexInfo,
			oid:                    "1.2.840.113549.1.1.1",
			algorithmName:          "crypto/algorithm/rsa-" + kexInfo,
			paramSetID:             kexInfo,
			cryptoFunctions:        cryptoFunctions,
			classicalSecurityLevel: inferRSASecurityLevel(kexInfo),
		}, true
	default:
		return algorithmInfo{}, false
	}
}

func (auth KeyAuthenticationAlgorithm) info(keyLen string) (algorithmInfo, bool) {
	switch auth {
	case KauthECDSA:
		return algorithmInfo{
			name:                   "ECDSA-" + keyLen,
			oid:                    "1.2.840.10045.4.3.2",
			algorithmName:          "crypto/algorithm/ecdsa",
			paramSetID:             keyLen,
			cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
			classicalSecurityLevel: inferECDSASecurityLevel(keyLen),
		}, true
	case KauthRSA:
		return algorithmInfo{
			name:                   "RSA-" + keyLen,
			oid:                    "1.2.840.113549.1.1.1",
			algorithmName:          "crypto/algorithm/rsa",
			paramSetID:             keyLen,
			cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
			classicalSecurityLevel: inferRSASecurityLevel(keyLen),
		}, true
	default:
		return algorithmInfo{}, false
	}
}

// Example helper functions:
func inferECDSASecurityLevel(curve string) int {
	switch curve {
	case "secp256r1", "x25519":
		return 128
	case "secp384r1":
		return 192
	case "secp521r1":
		return 256
	default:
		return 128
	}
}

func inferRSASecurityLevel(bits string) int {
	switch bits {
	case "1024":
		return 80
	case "2048":
		return 112
	case "3072":
		return 128
	case "4096":
		return 152
	default:
		return 112
	}
}

func (cipher CipherAlgorithm) info(keyLen KeyLen, mode CipherMode) (algorithmInfo, bool) {
	var info algorithmInfo
	switch {
	case cipher == CipherRC4 && keyLen == KeyLen128:
		info = algorithmInfo{
			name:                   "RC4-128",
			oid:                    "1.2.840.113549.3.4",
			algorithmName:          "crypto/algorithm/rc4-128",
			keySize:                int(KeyLen128),
			paramSetID:             string(CipherModeEmpty),
			cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
			classicalSecurityLevel: 128,
		}
	case cipher == Cipher3DES && mode == CipherModeEDE_CBC:
		info = algorithmInfo{
			name:                   "3DES-EDE-CBC",
			oid:                    "1.2.840.113549.3.7",
			algorithmName:          "crypto/algorithm/3des-ede-cbc",
			keySize:                int(KeyLen168),
			paramSetID:             string(CipherModeEDE_CBC),
			cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
			classicalSecurityLevel: 112,
		}
	case cipher == CipherAES:
		switch {
		case keyLen == KeyLen128 && mode == CipherModeCBC:
			info = algorithmInfo{
				name:                   "AES-128-CBC",
				oid:                    "2.16.840.1.101.3.4.1.2",
				algorithmName:          "crypto/algorithm/aes-128-cbc",
				keySize:                int(KeyLen128),
				paramSetID:             string(CipherModeCBC),
				cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
				classicalSecurityLevel: 128,
			}
		case keyLen == KeyLen256 && mode == CipherModeCBC:
			info = algorithmInfo{
				name:                   "AES-256-CBC",
				oid:                    "2.16.840.1.101.3.4.1.42",
				algorithmName:          "crypto/algorithm/aes-256-cbc",
				keySize:                int(KeyLen256),
				paramSetID:             string(CipherModeCBC),
				cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
				classicalSecurityLevel: 256,
			}
		case keyLen == KeyLen128 && mode == CipherModeGCM:
			info = algorithmInfo{
				name:                   "AES-128-GCM",
				oid:                    "2.16.840.1.101.3.4.1.6",
				algorithmName:          "crypto/algorithm/aes-128-gcm",
				keySize:                int(KeyLen128),
				paramSetID:             string(CipherModeGCM),
				cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
				classicalSecurityLevel: 128,
			}
		case keyLen == KeyLen256 && mode == CipherModeGCM:
			info = algorithmInfo{
				name:                   "AES-256-GCM",
				oid:                    "2.16.840.1.101.3.4.1.46",
				algorithmName:          "crypto/algorithm/aes-256-gcm",
				keySize:                int(KeyLen256),
				paramSetID:             string(CipherModeGCM),
				cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
				classicalSecurityLevel: 256,
			}
		}
	case cipher == CipherCHACHA20 && mode == CipherModePOLY1305:
		info = algorithmInfo{
			name:                   "ChaCha20-Poly1305",
			oid:                    "ietf-rfc8439",
			algorithmName:          "crypt/algorithm/chacha20-poly1305",
			keySize:                int(KeyLen256),
			paramSetID:             string(CipherModePOLY1305),
			cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
			classicalSecurityLevel: 128,
		}
	default:
		return algorithmInfo{}, false
	}
	return info, true
}

var _fallbackNames = map[string]string{
	// defined in Go crypto/tls
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	// openssl compat names for TLS 1.3
	"TLS_AKE_WITH_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
	"TLS_AKE_WITH_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
	"TLS_AKE_WITH_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
}

var byCode = map[CipherSuiteCode]CipherSuite{
	// TLS 1.3 (no key exchange/auth in struct -> zero KeyExchange)
	TLS_AES_128_GCM_SHA256: {
		Protocol: TLS,
		Cipher:   CipherAES,
		KeyLen:   KeyLen128,
		Mode:     CipherModeGCM,
		Hash:     HashSHA256,
	},
	TLS_AES_256_GCM_SHA384: {
		Protocol: TLS,
		Cipher:   CipherAES,
		KeyLen:   KeyLen256,
		Mode:     CipherModeGCM,
		Hash:     HashSHA384,
	},
	TLS_CHACHA20_POLY1305_SHA256: {
		Protocol: TLS,
		Cipher:   CipherCHACHA20,
		KeyLen:   KeyLen256,
		Mode:     CipherModePOLY1305,
		Hash:     HashSHA256,
	},

	// RSA
	TLS_RSA_WITH_RC4_128_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherRC4,
		KeyLen:      KeyLen128,
		Mode:        CipherModeEmpty,
		Hash:        HashSHA,
	},
	TLS_RSA_WITH_3DES_EDE_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      Cipher3DES,
		KeyLen:      KeyLen168,
		Mode:        CipherModeEDE_CBC,
		Hash:        HashSHA,
	},
	TLS_RSA_WITH_AES_128_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_RSA_WITH_AES_128_CBC_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA256,
	},
	TLS_RSA_WITH_AES_128_GCM_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeGCM,
		Hash:        HashSHA256,
	},
	TLS_RSA_WITH_AES_256_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_RSA_WITH_AES_256_CBC_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA256,
	},
	TLS_RSA_WITH_AES_256_GCM_SHA384: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeGCM,
		Hash:        HashSHA384,
	},

	// DHE_RSA
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA256,
	},
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeGCM,
		Hash:        HashSHA256,
	},
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA256,
	},
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeGCM,
		Hash:        HashSHA384,
	},
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexDHE, Auth: KauthRSA},
		Cipher:      CipherCHACHA20,
		KeyLen:      KeyLen256,
		Mode:        CipherModePOLY1305,
		Hash:        HashSHA256,
	},

	// ECDHE_ECDSA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA256,
	},
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeGCM,
		Hash:        HashSHA256,
	},
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeGCM,
		Hash:        HashSHA384,
	},
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherCHACHA20,
		KeyLen:      KeyLen256,
		Mode:        CipherModePOLY1305,
		Hash:        HashSHA256,
	},
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA},
		Cipher:      CipherRC4,
		KeyLen:      KeyLen128,
		Mode:        CipherModeEmpty,
		Hash:        HashSHA,
	},

	// ECDHE_RSA
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      Cipher3DES,
		KeyLen:      KeyLen168,
		Mode:        CipherModeEDE_CBC,
		Hash:        HashSHA,
	},
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeCBC,
		Hash:        HashSHA256,
	},
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen128,
		Mode:        CipherModeGCM,
		Hash:        HashSHA256,
	},
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA,
	},
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeCBC,
		Hash:        HashSHA384,
	},
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherAES,
		KeyLen:      KeyLen256,
		Mode:        CipherModeGCM,
		Hash:        HashSHA384,
	},
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherCHACHA20,
		KeyLen:      KeyLen256,
		Mode:        CipherModePOLY1305,
		Hash:        HashSHA256,
	},
	TLS_ECDHE_RSA_WITH_RC4_128_SHA: {
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexECDHE, Auth: KauthRSA},
		Cipher:      CipherRC4,
		KeyLen:      KeyLen128,
		Mode:        CipherModeEmpty,
		Hash:        HashSHA,
	},
}

// ParseCipherSuite parses a TLS cipher suite name into its components.
// this function check fallback names and returned CipherSuite name is
// always normalized
func ParseCipherSuite(c model.SSLCipher) (CipherSuite, bool) {
	var ret CipherSuite
	name := c.Name

	// fallback names
	if fallback, ok := _fallbackNames[name]; ok {
		name = fallback
	}

	code, ok := Code(name)
	if !ok {
		return ret, false
	}

	suite, ok := byCode[code]
	if !ok {
		return ret, false
	}

	suite.Name = name
	suite.Code = code
	suite.KexInfo = c.KexInfo
	return suite, true
}
