package cdxprops

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// leakDetectionType derives the Detection.Type a leak finding reports from the
// material type its gitleaks rule resolved to.
//
// Deriving the detection type from the RULE rather than from the produced
// components is what makes the two private-key branches agree: a private-key
// finding that carries a PEM bundle delegates to PEMBundle and produces
// certificates and algorithms, none of which describe the finding, so reading
// the type back off the first component labelled the same gitleaks hit
// "PRIVATE-KEY" without a bundle and "" with one.
//
// Deriving it by uppercasing, rather than looking it up in a table, is what
// makes it stay correct. A table covers the material types whoever wrote it
// remembered; add a case to the switch in leakToComponents -- say a
// certificate rule resolving to RelatedCryptoMaterialTypeCertificate -- and
// the table's miss branch turns it into UNKNOWN with no log and no failing
// test. Uppercasing is right for every material type CycloneDX has or will
// have, and it reproduces all five values the table held exactly;
// TestLeakDetectionType_MatchesDeclaredConstants pins that against the
// declared model constants, which are what fix the vocabulary.
//
// jwt is absent on purpose. The switch resolves it to
// RelatedCryptoMaterialTypeToken, so a jwt finding has always reported "TOKEN"
// and model.DetectionTypeLeakJWT has never been reachable. Splitting it out
// would make TOKEN and JWT ambiguous for a "token"-ruled finding with no
// consumer asking for the distinction.
func leakDetectionType(cryptoType cdx.RelatedCryptoMaterialType) model.DetectionType {
	return model.DetectionType(strings.ToUpper(string(cryptoType)))
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

	detectionType := leakDetectionType(cryptoType)

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
