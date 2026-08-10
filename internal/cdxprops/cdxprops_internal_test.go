package cdxprops

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

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
