package cdxprops

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	"github.com/stretchr/testify/require"
)

// TestSetPEMFormat pins the gate setPEMFormat applies (#213).
//
// Two properties matter beyond "material gets the format": the setter must not
// manufacture a CryptoProperties on a component that has none, and the gate
// must be the asset type rather than the presence of the struct — gating on the
// struct would encode which producer happened to build it.
func TestSetPEMFormat(t *testing.T) {
	t.Parallel()

	// rcmp builds a component of the given asset type with a
	// relatedCryptoMaterialProperties already in place.
	withRCMP := func(assetType cdx.CryptoAssetType, typ cdx.RelatedCryptoMaterialType) *cdx.Component {
		return &cdx.Component{
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: assetType,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type: typ,
				},
			},
		}
	}
	bare := func(assetType cdx.CryptoAssetType) *cdx.Component {
		return &cdx.Component{
			CryptoProperties: &cdx.CryptoProperties{AssetType: assetType},
		}
	}

	tests := []struct {
		scenario string
		given    *cdx.Component
		// then is run on the component after setPEMFormat.
		then func(t *testing.T, compo *cdx.Component)
	}{
		{
			scenario: "nil component does not panic",
			given:    nil,
			then:     func(*testing.T, *cdx.Component) {},
		},
		{
			scenario: "nil CryptoProperties is not manufactured",
			given:    &cdx.Component{Name: "unidentifiable key"},
			then: func(t *testing.T, compo *cdx.Component) {
				require.Nil(t, compo.CryptoProperties,
					"inventing an assetType-less cryptoProperties is worse than "+
						"leaving the zero component for the Builder to drop")
			},
		},
		{
			scenario: "algorithm without material properties keeps none",
			given:    bare(cdx.CryptoAssetTypeAlgorithm),
			then: func(t *testing.T, compo *cdx.Component) {
				require.Nil(t, compo.CryptoProperties.RelatedCryptoMaterialProperties,
					"an algorithm is not serialised and has no encoding")
			},
		},
		{
			scenario: "algorithm with pre-built material properties gets no format",
			given:    withRCMP(cdx.CryptoAssetTypeAlgorithm, cdx.RelatedCryptoMaterialTypeUnknown),
			then: func(t *testing.T, compo *cdx.Component) {
				rcmp := compo.CryptoProperties.RelatedCryptoMaterialProperties
				require.NotNil(t, rcmp)
				require.Empty(t, rcmp.Format,
					"the gate is the asset type, not whether the producer "+
						"happened to build the struct")
			},
		},
		{
			scenario: "certificate keeps no material properties",
			given:    bare(cdx.CryptoAssetTypeCertificate),
			then: func(t *testing.T, compo *cdx.Component) {
				require.Nil(t, compo.CryptoProperties.RelatedCryptoMaterialProperties,
					"a certificate's encoding belongs in certificateFormat")
			},
		},
		{
			scenario: "protocol keeps no material properties",
			given:    bare(cdx.CryptoAssetTypeProtocol),
			then: func(t *testing.T, compo *cdx.Component) {
				require.Nil(t, compo.CryptoProperties.RelatedCryptoMaterialProperties)
			},
		},
		{
			scenario: "related crypto material with existing properties gets the format",
			given: withRCMP(cdx.CryptoAssetTypeRelatedCryptoMaterial,
				cdx.RelatedCryptoMaterialTypePrivateKey),
			then: func(t *testing.T, compo *cdx.Component) {
				rcmp := compo.CryptoProperties.RelatedCryptoMaterialProperties
				require.NotNil(t, rcmp)
				require.Equal(t, "PEM", rcmp.Format)
				require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, rcmp.Type,
					"the existing type must survive")
			},
		},
		{
			scenario: "related crypto material without properties gets them created",
			given:    bare(cdx.CryptoAssetTypeRelatedCryptoMaterial),
			then: func(t *testing.T, compo *cdx.Component) {
				rcmp := compo.CryptoProperties.RelatedCryptoMaterialProperties
				require.NotNil(t, rcmp,
					"a future related-crypto-material producer that leaves the "+
						"struct nil must not silently lose its format")
				require.Equal(t, "PEM", rcmp.Format)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()

			require.NotPanics(t, func() { setPEMFormat(tt.given) })
			tt.then(t, tt.given)
		})
	}
}

// TestLeakDetectionType_MatchesDeclaredConstants is what pins the leak
// detection vocabulary now that leakDetectionType derives the value instead of
// looking it up.
//
// The derivation is self-maintaining; the declared model constants are what
// fix the wire strings. Asserting the derived value against the constant, for
// every material type the rule switch can produce, is therefore the whole
// contract: neither side can move without this failing.
//
// The last row is the point of the change. A hand-written table covers the
// entries someone remembered, and a material type it does not list becomes
// UNKNOWN with no log and no failing test; a table's miss branch is also dead
// code, since cryptoType is only ever assigned by that switch. Deriving the
// value means a case added to the switch tomorrow is already correct.
func TestLeakDetectionType_MatchesDeclaredConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		cryptoType cdx.RelatedCryptoMaterialType
		want       model.DetectionType
	}{
		// Every material type leakToComponents' switch can assign, each
		// checked against the constant model declares for it.
		{cdx.RelatedCryptoMaterialTypePrivateKey, model.DetectionTypeLeakPrivateKey},
		{cdx.RelatedCryptoMaterialTypeToken, model.DetectionTypeLeakTOKEN},
		{cdx.RelatedCryptoMaterialTypeKey, model.DetectionTypeLeakKEY},
		{cdx.RelatedCryptoMaterialTypePassword, model.DetectionTypeLeakPASSWORD},
		{cdx.RelatedCryptoMaterialTypeUnknown, model.DetectionTypeUNKNOWN},

		// Not reachable from the switch today. These stand in for the material
		// type someone adds a rule for tomorrow -- gitleaks has rules for both
		// -- and each must derive its own name rather than collapse to
		// UNKNOWN. secret-key also covers the hyphenated shape, so the
		// derivation cannot quietly become a single-word transform.
		{cdx.RelatedCryptoMaterialTypeCredential, model.DetectionType("CREDENTIAL")},
		{cdx.RelatedCryptoMaterialTypeSecretKey, model.DetectionType("SECRET-KEY")},
	}

	for _, tt := range tests {
		t.Run(string(tt.cryptoType), func(t *testing.T) {
			t.Parallel()

			got := leakDetectionType(tt.cryptoType)
			require.Equal(t, tt.want, got)

			// The failure mode a lookup table has is silently answering
			// UNKNOWN for anything it does not list, so state it separately:
			// only the material type that IS unknown may report UNKNOWN.
			if tt.cryptoType != cdx.RelatedCryptoMaterialTypeUnknown {
				require.NotEqual(t, model.DetectionTypeUNKNOWN, got)
			}
		})
	}
}
