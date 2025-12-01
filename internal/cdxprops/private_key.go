package cdxprops

import (
	"context"
	"crypto"
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func (c Converter) PrivateKey(ctx context.Context, id string, key crypto.PrivateKey) (algoCompo, keyCompo cdx.Component) {
	info := privateKeyInfo(key)

	algoCompo = info.componentWOBomRef(c.czertainly)
	c.BOMRefHash(&algoCompo, info.algorithmName)

	bomRef := "crypto/private_key/" + strings.ToLower(algoCompo.Name) + "@" + id

	keyCompo = cdx.Component{
		BOMRef:      bomRef,
		Type:        cdx.ComponentTypeCryptographicAsset,
		Name:        info.name,
		Description: "Private Key",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:         cdx.RelatedCryptoMaterialTypePrivateKey,
				AlgorithmRef: cdx.BOMReference(algoCompo.BOMRef),
				Size:         &info.keySize,
			},
			OID: info.oid,
		},
	}
	return
}

func privateKeyInfo(key crypto.PrivateKey) algorithmInfo {
	var kt string
	var keyInterface any

	switch k := key.(type) {
	case model.PrivateKeyInfo:
		return privateKeyInfo(k.Key)
	case *rsa.PrivateKey:
		kt = "RSA"
		keyInterface = rsaKeyAdapter{&k.PublicKey}
	case *ecdsa.PrivateKey:
		kt = "ECDSA"
		keyInterface = ecKeyAdapter{&k.PublicKey}
	case ed25519.PrivateKey:
		kt = "Ed25519"
	default:
		kt = "Unknown"
	}

	meta := extractAlgorithmInfo(kt, keyInterface)

	return meta
}

func getPublicKey(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privKey.(type) {
	case model.PrivateKeyInfo:
		return getPublicKey(k.Key)
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *dsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", k)
	}
}
