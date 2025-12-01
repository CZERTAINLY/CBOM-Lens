package cdxprops

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"maps"
	"slices"
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
		algo, pubKeyCompo := c.publicKeyComponents(ctx, getPublicKeyAlgorithm(pubKey), pubKey, 0)
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
		compo, err := c.analyzeParseError(block, parseErr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		components = append(components, compo)
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
func (c Converter) analyzeParseError(block model.PEMBlock, parseErr error) (cdx.Component, error) {
	if block.Type == "PRIVATE KEY" {
		var pkcs8Key pkcs8
		_, err := asn1.Unmarshal(block.Bytes, &pkcs8Key)
		if err != nil {
			return cdx.Component{}, fmt.Errorf("parsing PKCS#8 via ASN.1: %w", err)
		}

		info, ok := unsupportedAlgorithms[pkcs8Key.Algo.Algorithm.String()]
		if !ok {
			return cdx.Component{}, parseErr
		}
		// FIXME: correct components
		algo, _, err := c.unsupportedPKCS8PrivateKey(pkcs8Key, info, block.Bytes)
		if err != nil {
			return cdx.Component{}, errors.Join(parseErr, err)
		}
		return algo, nil
	}
	return cdx.Component{}, parseErr
}

// ********** PQC support **********

// PKCS#8 PrivateKeyInfo structure
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// ML-KEM private key structure
type unsupportedPrivateKey struct {
	Seed       []byte
	PrivateKey []byte
}

func (c Converter) unsupportedPKCS8PrivateKey(pkcs8Key pkcs8, info algorithmInfo, _ []byte) (algo, key cdx.Component, err error) {
	var privKey unsupportedPrivateKey
	_, err = asn1.Unmarshal(pkcs8Key.PrivateKey, &privKey)
	if err != nil {
		err = fmt.Errorf("parsing PKCS#8 private key via ASN.1: %w", err)
		return
	}

	algo = info.componentWOBomRef(c.czertainly)
	c.BOMRefHash(&algo, info.algorithmName)

	return
}
