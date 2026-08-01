package cdxprops

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func (c Converter) leakToComponents(ctx context.Context, location string, finding model.Finding) ([]cdx.Component, []cdx.Dependency) {
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case finding.RuleID == "private-key":
		cryptoType = cdx.RelatedCryptoMaterialTypePrivateKey
		if !isZero(finding.PEMBundle) {
			d := c.PEMBundle(ctx, finding.PEMBundle)
			if d == nil {
				return nil, nil
			}
			return d.Components, d.Dependencies
		}
	case strings.Contains(finding.RuleID, "jwt"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(finding.RuleID, "token"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(finding.RuleID, "key"):
		cryptoType = cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(finding.RuleID, "password"):
		cryptoType = cdx.RelatedCryptoMaterialTypePassword
	default:
		cryptoType = cdx.RelatedCryptoMaterialTypeUnknown
	}

	bomRef := fmt.Sprintf("crypto/%s/%s", string(cryptoType), c.bomRefHasher([]byte(finding.Secret)))

	compo := cdx.Component{
		BOMRef:      bomRef,
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cryptoType,
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: location,
					Line:     &finding.StartLine,
				},
			},
		},
	}

	return []cdx.Component{compo}, nil
}

func isZero[T any](x T) bool {
	return reflect.ValueOf(x).IsZero()
}
