package cbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestDetectionConstruction(t *testing.T) {
	// Test AssetRef
	assetRef := AssetRef("test-ref")
	require.NotEmpty(t, assetRef)

	// Test KeyMeta: Bits and Curve are mutually exclusive
	keyMeta := &KeyMeta{Bits: 2048}
	require.Equal(t, 2048, keyMeta.Bits)
	require.Empty(t, keyMeta.Curve)

	// Test Asset construction with Ref, Component, and KeyMeta
	component := cdx.Component{
		Type: cdx.ComponentTypeApplication,
		Name: "test-component",
	}
	asset := Asset{
		Ref:       assetRef,
		Component: component,
		Key:       keyMeta,
	}
	require.Equal(t, assetRef, asset.Ref)
	require.Equal(t, "test-component", asset.Component.Name)
	require.Equal(t, 2048, asset.Key.Bits)

	// Test Relationship construction
	rel := Relationship{
		From: AssetRef("from-ref"),
		To:   AssetRef("to-ref"),
		Kind: RelSignatureAlgorithm,
	}
	require.Equal(t, AssetRef("from-ref"), rel.From)
	require.Equal(t, AssetRef("to-ref"), rel.To)

	// Test RelationshipKind constants have expected string values
	require.Equal(t, RelationshipKind("signature-algorithm"), RelSignatureAlgorithm)
	require.Equal(t, RelationshipKind("subject-public-key"), RelSubjectPublicKey)
	require.Equal(t, RelationshipKind("material-algorithm"), RelMaterialAlgorithm)
	require.Equal(t, RelationshipKind("protocol-crypto"), RelProtocolCrypto)
	require.Equal(t, RelationshipKind("depends-on"), RelDependsOn)

	// Test DetectionType constants have expected string values
	require.Equal(t, DetectionType("UNKNOWN"), DetectionTypeUNKNOWN)
	require.Equal(t, DetectionType("JWT"), DetectionTypeLeakJWT)
	require.Equal(t, DetectionType("TOKEN"), DetectionTypeLeakTOKEN)
	require.Equal(t, DetectionType("KEY"), DetectionTypeLeakKEY)
	require.Equal(t, DetectionType("PASSWORD"), DetectionTypeLeakPASSWORD)
	require.Equal(t, DetectionType("CERTIFICATE"), DetectionTypeCertificate)
	require.Equal(t, DetectionType("PORT"), DetectionTypePort)
	require.Equal(t, DetectionType("PEM"), DetectionTypePEM)
	require.Equal(t, DetectionType("PRIVATE-KEY"), DetectionTypeLeakPrivateKey)

	// Test Detection construction
	detection := Detection{
		Source:   "PEM",
		Type:     DetectionTypePEM,
		Location: "/path/to/cert.pem",
		Assets: []Asset{
			asset,
		},
		Services: []cdx.Service{},
		Rels: []Relationship{
			rel,
		},
	}
	require.Equal(t, "PEM", detection.Source)
	require.Equal(t, DetectionTypePEM, detection.Type)
	require.Equal(t, "/path/to/cert.pem", detection.Location)
	require.Len(t, detection.Assets, 1)
	require.Len(t, detection.Rels, 1)

	// Test BOMModel construction
	bomModel := BOMModel{
		Assets:       []Asset{asset},
		Rels:         []Relationship{rel},
		Services:     []cdx.Service{},
		SerialNumber: "test-serial",
		Timestamp:    "2026-07-22T00:00:00Z",
		StatsProps:   []cdx.Property{},
	}
	require.Equal(t, "test-serial", bomModel.SerialNumber)
	require.Equal(t, "2026-07-22T00:00:00Z", bomModel.Timestamp)
	require.Len(t, bomModel.Assets, 1)
	require.Len(t, bomModel.Rels, 1)
}
