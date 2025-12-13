package cdxprops

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// PEMBundleToCDX converts a PEM bundle to CycloneDX components
func (c Converter) restOfPEMBundleToCDX(ctx context.Context, bundle model.PEMBundle, location string) ([]cdx.Component, error) {
	components := make([]cdx.Component, 0)
	var errs []error

	// Convert certificate requests
	for _, csr := range bundle.CertificateRequests {
		components = append(components, csrToCDX(csr, location))
	}

	// Convert public keys
	for _, pubKey := range bundle.PublicKeys {
		algo, pubKeyCompo := c.publicKeyComponents(ctx, getPublicKeyAlgorithm(pubKey), pubKey, nil)
		pubKeyCompo.CryptoProperties.RelatedCryptoMaterialProperties.Format = "PEM"
		components = append(components, algo)
		components = append(components, pubKeyCompo)
	}

	// Convert CRLs
	for _, crl := range bundle.CRLs {
		components = append(components, crlToCDX(crl, location))
	}

	// try to parse unrecognized parts of a PEM
	for _, i := range slices.Sorted(maps.Keys(bundle.ParseErrors)) {
		parseErr := bundle.ParseErrors[i]
		block := bundle.RawBlocks[i]
		compos, err := c.analyzeParseError(block, parseErr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		components = append(components, compos...)
	}

	return components, errors.Join(errs...)
}

func csrToCDX(csr *x509.CertificateRequest, _ string) cdx.Component {
	compo := cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: fmt.Sprintf("CSR: %s", csr.Subject.CommonName),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypeOther,
			},
		},
		Properties: &[]cdx.Property{
			{Name: "pem_type", Value: "CSR"},
			{Name: "subject", Value: csr.Subject.String()},
		},
	}
	return compo
}

func crlToCDX(crl *x509.RevocationList, location string) cdx.Component {
	compo := cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: "Certificate Revocation List",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypeOther,
			},
		},
		Properties: &[]cdx.Property{
			{Name: "location", Value: location},
			{Name: "issuer", Value: crl.Issuer.String()},
			{Name: "this_update", Value: crl.ThisUpdate.Format(time.RFC3339)},
			{Name: "next_update", Value: crl.NextUpdate.Format(time.RFC3339)},
			{Name: "revoked_count", Value: fmt.Sprintf("%d", len(crl.RevokedCertificateEntries))},
		},
	}
	return compo
}

// Helper functions
func (c Converter) analyzeParseError(block model.PEMBlock, origErr error) ([]cdx.Component, error) {
	switch block.Type {
	case "PRIVATE KEY":
		algo, err := c.unsupportedPKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Join(origErr, err)
		}
		return []cdx.Component{algo}, nil
	case "PUBLIC KEY":
		key, algo, err := c.unsupportedPKIX(block.Bytes)
		if err != nil {
			return nil, errors.Join(origErr, err)
		}
		return []cdx.Component{key, algo}, nil
	}
	return nil, origErr
}

// ********** PQC support **********

func (c Converter) unsupportedPKCS8PrivateKey(der []byte) (cdx.Component, error) {
	var pkcs8 pkcs8Struct
	_, err := asn1.Unmarshal(der, &pkcs8)
	if err != nil {
		return cdx.Component{}, fmt.Errorf("parsing PKCS#8 via ASN.1: %w", err)
	}
	info, ok := unsupportedAlgorithms[pkcs8.Algo.Algorithm.String()]
	if !ok {
		return cdx.Component{}, fmt.Errorf("unsupported fallback oid %q", pkcs8.Algo.Algorithm.String())
	}

	algo := info.componentWOBomRef(c.czertainly)
	c.BOMRefHash(&algo, info.algorithmName)
	return algo, nil
}

func (c Converter) unsupportedPKIX(der []byte) (key, algo cdx.Component, err error) {
	var pubKey pkixStruct
	_, err = asn1.Unmarshal(der, &pubKey)
	if err != nil {
		err = fmt.Errorf("parsing PKIX via ASN.1: %w", err)
		return
	}
	info, ok := unsupportedAlgorithms[pubKey.Algorithm.Algorithm.String()]
	if !ok {
		err = fmt.Errorf("unsupported fallback oid %q", pubKey.Algorithm.Algorithm.String())
		return
	}

	algo = info.componentWOBomRef(c.czertainly)
	setAlgorithmPrimitive(&algo, cdx.CryptoPrimitiveSignature)
	c.BOMRefHash(&algo, info.algorithmName)

	pubKeyValue, pubKeyHash := c.hashRawPublicKey(der)
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

func (c Converter) hashRawPublicKey(der []byte) (value, hash string) {
	value = base64.StdEncoding.EncodeToString(der)
	hash = c.bomRefHasher(der)
	return
}
