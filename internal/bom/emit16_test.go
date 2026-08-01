package bom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"
	"github.com/stretchr/testify/require"
)

// allRelationshipKinds lists every declared cbom.RelationshipKind. A new kind
// added to the IR must be added here and triaged in
// TestEmit16_RelationshipKindExhaustive below.
var allRelationshipKinds = []cbom.RelationshipKind{
	cbom.RelSignatureAlgorithm,
	cbom.RelSubjectPublicKey,
	cbom.RelMaterialAlgorithm,
	cbom.RelProtocolCrypto,
	cbom.RelDependsOn,
}

func TestEmit16_ZeroModel(t *testing.T) {
	bom := emit16{}.Emit(t.Context(), cbom.BOMModel{})

	require.Equal(t, "CycloneDX", bom.BOMFormat)
	require.Equal(t, cdx.SpecVersion1_6, bom.SpecVersion)
	require.Equal(t, 1, bom.Version)
	require.NotNil(t, bom.Components)
	require.Empty(t, *bom.Components)
	require.NotNil(t, bom.Dependencies)
	require.Empty(t, *bom.Dependencies)
	require.NotNil(t, bom.Metadata)
	require.Nil(t, bom.Metadata.Properties)
}

func TestEmit16_SerialAndTimestampPassThrough(t *testing.T) {
	m := cbom.BOMModel{
		SerialNumber: "urn:uuid:22222222-2222-2222-2222-222222222222",
		Timestamp:    "2024-01-02T03:04:05Z",
	}

	bom := emit16{}.Emit(t.Context(), m)

	require.Equal(t, m.SerialNumber, bom.SerialNumber)
	require.Equal(t, m.Timestamp, bom.Metadata.Timestamp)
}

func TestEmit16_ComponentsVerbatimInAssetOrder(t *testing.T) {
	m := cbom.BOMModel{
		Assets: []cbom.Asset{
			{Ref: "a@1", Component: cdx.Component{BOMRef: "a@1", Name: "alpha", Type: cdx.ComponentTypeCryptographicAsset}},
			{Ref: "b@2", Component: cdx.Component{BOMRef: "b@2", Name: "beta", Type: cdx.ComponentTypeLibrary}},
		},
	}

	bom := emit16{}.Emit(t.Context(), m)

	require.Len(t, *bom.Components, 2)
	require.Equal(t, m.Assets[0].Component, (*bom.Components)[0])
	require.Equal(t, m.Assets[1].Component, (*bom.Components)[1])
}

// TestEmit16_BOMRefFromAssetRef: Asset.Ref is the canonical identity; the
// emitter must stamp it onto the wire component so the two can never drift.
func TestEmit16_BOMRefFromAssetRef(t *testing.T) {
	m := cbom.BOMModel{
		Assets: []cbom.Asset{
			{Ref: "canonical@ref", Component: cdx.Component{BOMRef: "stale@ref", Name: "x"}},
		},
	}

	bom := emit16{}.Emit(t.Context(), m)

	require.Equal(t, "canonical@ref", (*bom.Components)[0].BOMRef)
}

func TestEmit16_RegroupsRelsByFrom(t *testing.T) {
	// Input honors the BOMModel contract: Rels grouped by From (stable-sorted),
	// within-From order meaningful.
	m := cbom.BOMModel{
		Rels: []cbom.Relationship{
			{From: "a", To: "y", Kind: cbom.RelDependsOn},
			{From: "a", To: "x", Kind: cbom.RelDependsOn},
			{From: "b", To: "z", Kind: cbom.RelDependsOn},
			{From: "c", To: "w", Kind: cbom.RelDependsOn},
		},
	}

	bom := emit16{}.Emit(t.Context(), m)

	require.Equal(t, []cdx.Dependency{
		{Ref: "a", Dependencies: &[]string{"y", "x"}},
		{Ref: "b", Dependencies: &[]string{"z"}},
		{Ref: "c", Dependencies: &[]string{"w"}},
	}, *bom.Dependencies)
}

func TestEmit16_RelationshipKindExhaustive(t *testing.T) {
	// Every RelationshipKind must be deliberately triaged for the 1.6 emitter:
	// either rendered as a dependency row, or skipped because 1.6 carries the
	// link inside the component payload (SignatureAlgorithmRef,
	// SubjectPublicKeyRef, AlgorithmRef, cipherSuites[].algorithms). A kind
	// missing from both sets means emit16 was not updated for it.
	rendered := map[cbom.RelationshipKind]bool{
		cbom.RelDependsOn: true,
	}
	skipped := map[cbom.RelationshipKind]bool{
		cbom.RelSignatureAlgorithm: true,
		cbom.RelSubjectPublicKey:   true,
		cbom.RelMaterialAlgorithm:  true,
		cbom.RelProtocolCrypto:     true,
	}

	for _, kind := range allRelationshipKinds {
		require.Truef(t, rendered[kind] || skipped[kind],
			"RelationshipKind %q not triaged for emit16: add it to rendered or skipped", kind)

		m := cbom.BOMModel{
			Rels: []cbom.Relationship{{From: "a", To: "b", Kind: kind}},
		}
		bom := emit16{}.Emit(t.Context(), m)

		if rendered[kind] {
			require.Lenf(t, *bom.Dependencies, 1, "kind %q must produce a dependency row", kind)
		} else {
			require.Emptyf(t, *bom.Dependencies, "kind %q must not produce a dependency row", kind)
		}
	}
}

func TestEmit16_SkipsNonDependsOnKindsInterleaved(t *testing.T) {
	m := cbom.BOMModel{
		Rels: []cbom.Relationship{
			{From: "a", To: "sig", Kind: cbom.RelSignatureAlgorithm},
			{From: "a", To: "x", Kind: cbom.RelDependsOn},
			{From: "a", To: "pk", Kind: cbom.RelSubjectPublicKey},
			{From: "a", To: "y", Kind: cbom.RelDependsOn},
			{From: "b", To: "alg", Kind: cbom.RelMaterialAlgorithm},
		},
	}

	bom := emit16{}.Emit(t.Context(), m)

	require.Equal(t, []cdx.Dependency{
		{Ref: "a", Dependencies: &[]string{"x", "y"}},
	}, *bom.Dependencies)
}

func TestEmit16_StatsPropsNilVsEmpty(t *testing.T) {
	t.Run("nil StatsProps omits metadata properties", func(t *testing.T) {
		bom := emit16{}.Emit(t.Context(), cbom.BOMModel{StatsProps: nil})
		require.Nil(t, bom.Metadata.Properties)
	})

	t.Run("empty non-nil StatsProps keeps empty array", func(t *testing.T) {
		bom := emit16{}.Emit(t.Context(), cbom.BOMModel{StatsProps: []cdx.Property{}})
		require.NotNil(t, bom.Metadata.Properties)
		require.Empty(t, *bom.Metadata.Properties)
	})
}
