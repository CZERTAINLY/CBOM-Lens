package cdxprops

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
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
