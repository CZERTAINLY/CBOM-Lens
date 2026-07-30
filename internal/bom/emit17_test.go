package bom

import (
	"encoding/json"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model/cbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestEmit17_ZeroModel(t *testing.T) {
	bom := emit17{}.Emit(t.Context(), cbom.BOMModel{})
	require.Equal(t, cdx.SpecVersion1_7, bom.SpecVersion)
	require.Equal(t, "https://cyclonedx.org/schema/bom-1.7.schema.json", bom.JSONSchema)
	require.NotNil(t, bom.Components)
	require.NotNil(t, bom.Dependencies)
}

func TestEmit17_CryptoRelsBecomeRelatedCryptographicAssets(t *testing.T) {
	m := cbom.BOMModel{
		Assets: []cbom.Asset{
			{Ref: "alg@1", Component: cdx.Component{BOMRef: "alg@1", Name: "alg"}},
			{Ref: "cert@1", Component: cdx.Component{
				BOMRef: "cert@1", Name: "cert",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeCertificate,
					CertificateProperties: &cdx.CertificateProperties{
						SignatureAlgorithmRef: "stale@raw",
						SubjectPublicKeyRef:   "stale@raw",
						CertificateExtension:  ".pem",
					},
				},
			}},
			{Ref: "key@1", Component: cdx.Component{BOMRef: "key@1", Name: "key"}},
		},
		Rels: []cbom.Relationship{
			{From: "cert@1", To: "alg@1", Kind: cbom.RelSignatureAlgorithm},
			{From: "cert@1", To: "key@1", Kind: cbom.RelSubjectPublicKey},
		},
	}
	bom := emit17{}.Emit(t.Context(), m)

	var cert *cdx.Component
	for i := range *bom.Components {
		if (*bom.Components)[i].BOMRef == "cert@1" {
			cert = &(*bom.Components)[i]
		}
	}
	require.NotNil(t, cert)
	cp := cert.CryptoProperties.CertificateProperties
	// Deprecated ref-shaped fields cleared; new fields set.
	require.Empty(t, cp.SignatureAlgorithmRef)
	require.Empty(t, cp.SubjectPublicKeyRef)
	require.Empty(t, cp.CertificateExtension)
	require.Equal(t, "pem", cp.CertificateFileExtension)
	require.NotNil(t, cp.RelatedCryptographicAssets)
	require.Equal(t, []cdx.RelatedCryptographicAsset{
		{Type: "algorithm", Ref: "alg@1"},
		{Type: "publicKey", Ref: "key@1"},
	}, *cp.RelatedCryptographicAssets)
}

func TestEmit17_MaterialAndProtocolRels(t *testing.T) {
	suites := []cdx.CipherSuite{{
		Name:       "TLS_X",
		Algorithms: &[]cdx.BOMReference{"alg@raw-dangling", "alg@1"},
	}}
	m := cbom.BOMModel{
		Assets: []cbom.Asset{
			{Ref: "alg@1", Component: cdx.Component{BOMRef: "alg@1", Name: "alg"}},
			{Ref: "mat@1", Component: cdx.Component{
				BOMRef: "mat@1", Name: "mat",
				CryptoProperties: &cdx.CryptoProperties{
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						AlgorithmRef: "stale@raw",
					},
				},
			}},
			{Ref: "proto@1", Component: cdx.Component{
				BOMRef: "proto@1", Name: "proto",
				CryptoProperties: &cdx.CryptoProperties{
					ProtocolProperties: &cdx.CryptoProtocolProperties{
						CryptoRefArray: &[]cdx.BOMReference{"stale@raw"},
						CipherSuites:   &suites,
					},
				},
			}},
		},
		Rels: []cbom.Relationship{
			{From: "mat@1", To: "alg@1", Kind: cbom.RelMaterialAlgorithm},
			{From: "proto@1", To: "alg@1", Kind: cbom.RelProtocolCrypto},
		},
	}
	bom := emit17{}.Emit(t.Context(), m)

	byRef := map[string]cdx.Component{}
	for _, c := range *bom.Components {
		byRef[c.BOMRef] = c
	}
	mat := byRef["mat@1"].CryptoProperties.RelatedCryptoMaterialProperties
	require.Empty(t, mat.AlgorithmRef)
	require.Equal(t, []cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: "alg@1"}},
		*mat.RelatedCryptographicAssets)

	proto := byRef["proto@1"].CryptoProperties.ProtocolProperties
	require.Nil(t, proto.CryptoRefArray)
	require.Equal(t, []cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: "alg@1"}},
		*proto.RelatedCryptographicAssets)
	// cipherSuites[].algorithms canonicalized: dangling raw ref dropped,
	// resolvable ref kept.
	require.Equal(t, []cdx.BOMReference{"alg@1"}, *(*proto.CipherSuites)[0].Algorithms)
}

func TestEmit17_CurveMapping(t *testing.T) {
	mkAsset := func(ref, curve, paramSet string) cbom.Asset {
		return cbom.Asset{Ref: cbom.AssetRef(ref), Component: cdx.Component{
			BOMRef: ref, Name: ref,
			CryptoProperties: &cdx.CryptoProperties{
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Curve:                  curve,
					ParameterSetIdentifier: paramSet,
				},
			},
		}}
	}
	m := cbom.BOMModel{Assets: []cbom.Asset{
		mkAsset("ssh@1", "nistp256", ""),     // trusted SSH curve -> mapped
		mkAsset("sig@1", "secp256r1", "256"), // fabricated -> omitted
		mkAsset("key@1", "", "P-256"),        // SPKI param set -> mapped
		// TLS auth facet. publicKeySizeFromPkeyRef derives this
		// parameterSetIdentifier from the FIRST certificate on the port, not
		// from the cipher suite's own certificate, so on a dual-certificate
		// host an RSA auth facet can carry an EC certificate's curve. Mapping
		// it would assert an elliptic curve on RSA.
		mkAsset("RSA-p-256", "", "p-256"), // untrusted lowercase -> omitted
	}}
	bom := emit17{}.Emit(t.Context(), m)
	byRef := map[string]*cdx.CryptoAlgorithmProperties{}
	for _, c := range *bom.Components {
		byRef[c.BOMRef] = c.CryptoProperties.AlgorithmProperties
	}
	require.Equal(t, "secg/secp256r1", string(byRef["ssh@1"].EllipticCurve))
	require.Empty(t, byRef["sig@1"].EllipticCurve)
	require.Equal(t, "secg/secp256r1", string(byRef["key@1"].EllipticCurve))
	require.Empty(t, byRef["RSA-p-256"].EllipticCurve,
		"a parameterSetIdentifier derived from another certificate must not "+
			"put a curve on an RSA component")

	// Dual-emit: `curve` is deprecated-by-annotation in 1.7, not removed, and
	// is not mutually exclusive with ellipticCurve. Clearing it would lose
	// data outright wherever ellipticCurve is omitted (fabricated sig-alg
	// curves, unmapped groups), because downstream converters silently drop
	// the new field. It passes through verbatim until 2.0 removes it.
	require.Equal(t, "nistp256", byRef["ssh@1"].Curve)
	require.Equal(t, "secp256r1", byRef["sig@1"].Curve)
	require.Empty(t, byRef["key@1"].Curve)
}

func TestEmit17_DoesNotMutateInput(t *testing.T) {
	suites := []cdx.CipherSuite{{Algorithms: &[]cdx.BOMReference{"raw@1"}}}
	m := cbom.BOMModel{Assets: []cbom.Asset{{
		Ref: "proto@1",
		Component: cdx.Component{
			BOMRef: "proto@1", Name: "p",
			CryptoProperties: &cdx.CryptoProperties{
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Curve: "nistp256"},
				ProtocolProperties:  &cdx.CryptoProtocolProperties{CipherSuites: &suites},
			},
		},
	}}}
	before, err := json.Marshal(m)
	require.NoError(t, err)
	_ = emit17{}.Emit(t.Context(), m)
	after, err := json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after), "Emit must not mutate its input")
}

func TestEmit17_RelationshipKindExhaustive(t *testing.T) {
	props := map[cbom.RelationshipKind]*cdx.CryptoProperties{
		cbom.RelSignatureAlgorithm: {CertificateProperties: &cdx.CertificateProperties{}},
		cbom.RelSubjectPublicKey:   {CertificateProperties: &cdx.CertificateProperties{}},
		cbom.RelMaterialAlgorithm:  {RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{}},
		cbom.RelProtocolCrypto:     {ProtocolProperties: &cdx.CryptoProtocolProperties{}},
	}
	for _, kind := range allRelationshipKinds {
		m := cbom.BOMModel{
			Assets: []cbom.Asset{{Ref: "a", Component: cdx.Component{
				BOMRef: "a", Name: "a", CryptoProperties: props[kind],
			}}},
			Rels: []cbom.Relationship{{From: "a", To: "b", Kind: kind}},
		}
		bom := emit17{}.Emit(t.Context(), m)

		if kind == cbom.RelDependsOn {
			require.Lenf(t, *bom.Dependencies, 1, "kind %q must render as a dependency row", kind)
			continue
		}
		require.Containsf(t, props, kind,
			"RelationshipKind %q not triaged for emit17: add its properties struct to this test and its rendering to mapComponent17", kind)
		cp := (*bom.Components)[0].CryptoProperties
		got := 0
		if cp.CertificateProperties != nil && cp.CertificateProperties.RelatedCryptographicAssets != nil {
			got += len(*cp.CertificateProperties.RelatedCryptographicAssets)
		}
		if cp.RelatedCryptoMaterialProperties != nil && cp.RelatedCryptoMaterialProperties.RelatedCryptographicAssets != nil {
			got += len(*cp.RelatedCryptoMaterialProperties.RelatedCryptographicAssets)
		}
		if cp.ProtocolProperties != nil && cp.ProtocolProperties.RelatedCryptographicAssets != nil {
			got += len(*cp.ProtocolProperties.RelatedCryptographicAssets)
		}
		require.Equalf(t, 1, got, "kind %q must render exactly one relatedCryptographicAssets entry", kind)
	}
}
