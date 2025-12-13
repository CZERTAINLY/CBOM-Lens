package cdxprops

import (
	"context"
	"crypto"
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// publicKeyAlgComponent creates a CycloneDX component for a public key algorithm
func (c Converter) publicKeyComponents(ctx context.Context, pubKeyAlg x509.PublicKeyAlgorithm, pubKey crypto.PublicKey, cert *x509.Certificate) (algo, key cdx.Component) {
	info := publicKeyAlgorithmInfo(pubKeyAlg, pubKey)

	if info.oid == "0.0.0.0" && cert != nil {
		oidFallback := spkiOID(cert)
		var ok bool
		info, ok = unsupportedAlgorithms[oidFallback]
		if oidFallback != "" && !ok {
			slog.WarnContext(ctx, "can't find public key components", "oid", oidFallback)
		}
	}

	var primitive = cdx.CryptoPrimitiveSignature

	var keyUsage x509.KeyUsage
	if cert != nil {
		keyUsage = cert.KeyUsage
	}

	if strings.Contains(info.name, "RSA") {
		if keyUsage != 0 &&
			(keyUsage&x509.KeyUsageDigitalSignature+
				keyUsage&x509.KeyUsageCRLSign+
				keyUsage&x509.KeyUsageCertSign > 0) &&
			(keyUsage&x509.KeyUsageKeyEncipherment == 0) {
			primitive = cdx.CryptoPrimitiveSignature
		} else {
			primitive = cdx.CryptoPrimitivePKE
		}
	}

	algo = info.componentWOBomRef(c.czertainly)
	setAlgorithmPrimitive(&algo, primitive)
	if primitive == cdx.CryptoPrimitivePKE {
		addAlgorithmCrpyoFunctions(&algo, cdx.CryptoFunctionSign)
	}
	c.BOMRefHash(&algo, info.algorithmName)

	pubKeyValue, pubKeyHash := c.hashPublicKey(pubKey)
	// public key properties
	var bomRef = fmt.Sprintf(
		"crypto/key/%s@%s",
		strings.ToLower(info.name),
		pubKeyHash,
	)

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePublicKey,
		AlgorithmRef: cdx.BOMReference(algo.BOMRef),
		Value:        pubKeyValue,
	}

	if info.keySize > 0 {
		relatedProps.Size = &info.keySize
	}

	key = cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   info.name,
		BOMRef: bomRef,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             info.oid,
			RelatedCryptoMaterialProperties: relatedProps,
		},
	}
	return
}

func (c Converter) hashPublicKey(pubKey crypto.PublicKey) (value, hash string) {
	// Marshal to PKIX/SPKI format (standard DER encoding)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}

	value = base64.StdEncoding.EncodeToString(pubKeyBytes)
	hash = c.bomRefHasher(pubKeyBytes)
	return
}

func publicKeyAlgorithmInfo(pubKeyAlg x509.PublicKeyAlgorithm, pubKey crypto.PublicKey) algorithmInfo {
	var keyType string
	var key any

	switch pubKeyAlg {
	case x509.RSA:
		keyType = "RSA"
		if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
			key = rsaKeyAdapter{rsaKey}
		}
	case x509.ECDSA:
		keyType = "ECDSA"
		if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			key = ecKeyAdapter{ecKey}
		}
	case x509.Ed25519:
		keyType = "Ed25519"
	case x509.DSA:
		keyType = "DSA"
		if dsaKey, ok := pubKey.(*dsa.PublicKey); ok {
			key = dsaKeyAdapter{dsaKey}
		}
	default:
		keyType = "Unknown"
	}

	return extractAlgorithmInfo(keyType, key)
}

func getPublicKeyAlgorithm(pubKey crypto.PublicKey) x509.PublicKeyAlgorithm {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return x509.RSA
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case ed25519.PublicKey:
		return x509.Ed25519
	case *dsa.PublicKey:
		return x509.DSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}
