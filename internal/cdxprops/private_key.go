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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
)

func (c Converter) PrivateKey(ctx context.Context, id string, key crypto.PrivateKey) (algoCompo, keyCompo cdx.Component) {
	info := privateKeyInfo(key)

	algoCompo = info.componentWOBomRef(c.ilm)
	// This path stamped no primitive at all, which made the SAME key describe
	// its algorithm differently depending on which half of the keypair the
	// scanner found. It is visible in the committed golden corpus: one scan of
	// one fixture directory produced crypto/algorithm/rsa-2048@0e37c10e-... from
	// the certificate and @a11419cf-... from the private key, two components
	// differing in nothing but the presence of this field, both named RSA-2048,
	// both oid 1.2.840.113549.1.1.1.
	setAlgorithmPrimitive(&algoCompo, algorithmPrimitive(info))
	c.BOMRefHash(&algoCompo, info.algorithmName)

	bomRef := "crypto/private_key/" + strings.ToLower(algoCompo.Name) + "@" + id

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePrivateKey,
		AlgorithmRef: cdx.BOMReference(algoCompo.BOMRef),
	}
	// Size only when the algorithm states one, the same guard the two other
	// producers of this field carry. The field is in BITS and a wrong value
	// validates, so nothing downstream distinguishes "0" from a key that is
	// really zero bits long -- and privateKeyInfo's default arm yields keySize
	// 0 for every key type its switch does not name.
	if info.keySize > 0 {
		relatedProps.Size = &info.keySize
	}

	keyCompo = cdx.Component{
		BOMRef:      bomRef,
		Type:        cdx.ComponentTypeCryptographicAsset,
		Name:        info.name,
		Description: "Private Key",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: relatedProps,
			OID:                             info.oid,
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
