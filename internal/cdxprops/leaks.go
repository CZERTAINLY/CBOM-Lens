package cdxprops

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// leakDetectionTypes maps the material type a gitleaks rule resolves to onto
// the Detection.Type the finding reports. Deriving the detection type from the
// RULE rather than from the produced components is what makes the two
// private-key branches agree: a private-key finding that carries a PEM bundle
// delegates to PEMBundle and produces certificates and algorithms, none of
// which describe the finding, so reading the type back off the first component
// labelled the same gitleaks hit "PRIVATE-KEY" without a bundle and "" with
// one.
//
// jwt is absent on purpose. The switch below resolves it to
// RelatedCryptoMaterialTypeToken, so a jwt finding has always reported "TOKEN"
// and model.DetectionTypeLeakJWT has never been reachable. Splitting it out
// here would make TOKEN and JWT ambiguous for a "token"-ruled finding with no
// consumer asking for the distinction.
var leakDetectionTypes = map[cdx.RelatedCryptoMaterialType]model.DetectionType{
	cdx.RelatedCryptoMaterialTypePrivateKey: model.DetectionTypeLeakPrivateKey,
	cdx.RelatedCryptoMaterialTypeToken:      model.DetectionTypeLeakTOKEN,
	cdx.RelatedCryptoMaterialTypeKey:        model.DetectionTypeLeakKEY,
	cdx.RelatedCryptoMaterialTypePassword:   model.DetectionTypeLeakPASSWORD,
	cdx.RelatedCryptoMaterialTypeUnknown:    model.DetectionTypeUNKNOWN,
}

func (c Converter) leakToComponents(ctx context.Context, location string, finding model.Finding) (model.DetectionType, []cdx.Component, []cdx.Dependency) {
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case finding.RuleID == "private-key":
		cryptoType = cdx.RelatedCryptoMaterialTypePrivateKey
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

	detectionType, ok := leakDetectionTypes[cryptoType]
	if !ok {
		detectionType = model.DetectionTypeUNKNOWN
	}

	// Only the private-key branch sets this cryptoType, so delegating here is
	// equivalent to the `case` this used to sit in — except that the detection
	// type is now resolved first and therefore shared by both branches.
	if cryptoType == cdx.RelatedCryptoMaterialTypePrivateKey && !isZero(finding.PEMBundle) {
		d := c.PEMBundle(ctx, finding.PEMBundle)
		if d == nil {
			return detectionType, nil, nil
		}
		return detectionType, d.Components, d.Dependencies
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

	return detectionType, []cdx.Component{compo}, nil
}

func isZero[T any](x T) bool {
	return reflect.ValueOf(x).IsZero()
}
