package cdxprops_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/bom"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file closes the end-to-end gap: before it, no post-quantum algorithm
// travelled the whole way from a real key file through the scanner, the
// converter, the Builder and the emitter into a schema-valid document. The
// registry could have been perfect and the pipeline still could have dropped,
// mangled or failed to validate every PQC component.
//
// It is deliberately NOT a byte-golden. Emission internals are being rewritten
// for CycloneDX 1.7 in parallel, and a byte comparison would break on every
// unrelated formatting change. Instead the document is unmarshalled and
// asserted on by content.
//
// This test lives in package cdxprops_test so it can import internal/bom
// without creating an import cycle.

// buildPQCDocument scans the given fixtures with the real PEM scanner, converts
// them, feeds them to the Builder, and returns the emitted JSON.
func buildPQCDocument(t *testing.T, fixtures ...string) []byte {
	t.Helper()

	c := cdxprops.NewConverter().
		WithCzertainlyExtensions(true).
		WithImplementationPlatform(cdx.ImplementationPlatformX86_64)

	var detections []model.Detection
	for _, f := range fixtures {
		data, err := cdxtest.TestData(f)
		require.NoError(t, err, "fixture %s", f)

		bundle, err := pem.Scanner{}.Scan(t.Context(), data, f)
		require.NoError(t, err, "scanning %s", f)

		d := c.PEMBundle(t.Context(), bundle)
		require.NotNil(t, d, "no detection for %s", f)
		detections = append(detections, *d)
	}

	b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, b.AppendDetections(t.Context(), detections...).AsJSON(t.Context(), &buf))
	return buf.Bytes()
}

// TestPQCPipeline_ValidatesAndCarriesRegistryData is the whole point: real key
// files in, schema-valid document out, with the standards data intact.
func TestPQCPipeline_ValidatesAndCarriesRegistryData(t *testing.T) {
	t.Parallel()

	raw := buildPQCDocument(t,
		cdxtest.MLDSA65PrivateKey,
		cdxtest.SLHDSASHA2128sPrivateKey,
		cdxtest.SLHDSASHA2128sCertificate,
		cdxtest.MLKEM768PrivateKey,
		cdxtest.MLKEM768PublicKey,
		cdxtest.MLKEM768Certificate,
	)

	v, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)
	require.NoError(t, v.ValidateBytes(raw),
		"a document containing PQC components must validate against CycloneDX 1.6")

	var doc cdx.BOM
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotNil(t, doc.Components)

	byName := map[string]cdx.Component{}
	for _, compo := range *doc.Components {
		if compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
			byName[compo.Name] = compo
		}
	}

	t.Run("ML-DSA-65", func(t *testing.T) {
		compo, ok := byName["ML-DSA-65"]
		require.True(t, ok, "ML-DSA-65 algorithm component missing from the document")

		// RFC 9881: id-ml-dsa-65 = nistAlgorithm(4) sigAlgs(3) 18
		require.Equal(t, "2.16.840.1.101.3.4.3.18", compo.CryptoProperties.OID)

		props := compo.CryptoProperties.AlgorithmProperties
		require.Equal(t, cdx.CryptoPrimitiveSignature, props.Primitive)
		require.Equal(t, "65", props.ParameterSetIdentifier)
		// FIPS 204 Table 1: Category 3, lambda 192.
		require.Equal(t, 3, *props.NistQuantumSecurityLevel)
		require.Equal(t, 192, *props.ClassicalSecurityLevel)
		require.Equal(t, []cdx.CryptoFunction{
			cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify,
		}, *props.CryptoFunctions)

		// FIPS 204 Table 2.
		require.Equal(t, "4032", cdxtest.GetProp(compo, czertainly.AlgorithmPrivateKeySize))
		require.Equal(t, "1952", cdxtest.GetProp(compo, czertainly.AlgorithmPublicKeySize))
		require.Equal(t, "3309", cdxtest.GetProp(compo, czertainly.AlgorithmSignatureSize))
	})

	t.Run("SLH-DSA-SHA2-128S", func(t *testing.T) {
		compo, ok := byName["SLH-DSA-SHA2-128S"]
		require.True(t, ok, "SLH-DSA-SHA2-128S algorithm component missing")

		require.Equal(t, "2.16.840.1.101.3.4.3.20", compo.CryptoProperties.OID)

		props := compo.CryptoProperties.AlgorithmProperties
		require.Equal(t, "128S", props.ParameterSetIdentifier)
		// FIPS 205 Table 2: category 1.
		require.Equal(t, 1, *props.NistQuantumSecurityLevel)
		require.Equal(t, 128, *props.ClassicalSecurityLevel)

		// FIPS 205 Table 2 / RFC 9909 App. B: pk 32, priv 64, sig 7856.
		// These are the fixture's real sizes too: its SPKI BIT STRING is 33
		// bytes (1 + 32) and its certificate signature is 7857 (1 + 7856).
		require.Equal(t, "64", cdxtest.GetProp(compo, czertainly.AlgorithmPrivateKeySize))
		require.Equal(t, "32", cdxtest.GetProp(compo, czertainly.AlgorithmPublicKeySize))
		require.Equal(t, "7856", cdxtest.GetProp(compo, czertainly.AlgorithmSignatureSize))
	})

	t.Run("ML-KEM-768", func(t *testing.T) {
		compo, ok := byName["ML-KEM-768"]
		require.True(t, ok,
			"ML-KEM-768 algorithm component missing; ML-KEM keys used to be dropped entirely")

		// NIST CSOR: id-alg-ml-kem-768 = { kems 2 }.
		require.Equal(t, "2.16.840.1.101.3.4.4.2", compo.CryptoProperties.OID)

		props := compo.CryptoProperties.AlgorithmProperties
		require.Equal(t, "768", props.ParameterSetIdentifier)
		require.Equal(t, []cdx.CryptoFunction{
			cdx.CryptoFunctionDecapsulate, cdx.CryptoFunctionEncapsulate,
		}, *props.CryptoFunctions)
		// FIPS 203 sec. 8: category 3. Table 2: required RBG strength 192.
		require.Equal(t, 3, *props.NistQuantumSecurityLevel)
		require.Equal(t, 192, *props.ClassicalSecurityLevel)

		// FIPS 203 Table 3. The 1184 matches the fixture: its SPKI BIT STRING
		// is 1185 bytes = 1 unused-bits octet + 1184.
		require.Equal(t, "1184", cdxtest.GetProp(compo, czertainly.AlgorithmPublicKeySize),
			"encapsulation key")
		require.Equal(t, "2400", cdxtest.GetProp(compo, czertainly.AlgorithmPrivateKeySize),
			"decapsulation key")
		require.Equal(t, "1088", cdxtest.GetProp(compo, czertainly.AlgorithmCiphertextSize))
		require.Empty(t, cdxtest.GetProp(compo, czertainly.AlgorithmSignatureSize),
			"a KEM has no signature size")
	})
}

// TestPQCPipeline_NoStaleHQCOrSHAKEOIDs checks the corrected data cannot
// reappear in emitted output.
//
// A "must not contain" assertion is only worth anything if the forbidden value
// is producible from the inputs; otherwise it passes for the wrong reason and
// would keep passing if the defect returned. The fixtures here cannot produce
// an EC curve OID or a SHAKE hash, so the guard is anchored on the registry
// instead: the values must be absent from the tables that feed emission, which
// is where a regression would actually land -- see
// TestRegistry_NoRetiredValues in the internal test package, which has access
// to the unexported registry.
func TestPQCPipeline_NoStaleHQCOrSHAKEOIDs(t *testing.T) {
	t.Parallel()

	raw := buildPQCDocument(t,
		cdxtest.SLHDSASHA2128sCertificate,
		cdxtest.MLKEM768Certificate,
	)
	doc := string(raw)

	forbidden := []string{
		"1.3.9999",              // the SPHINCS+ arc formerly mislabelled HQC
		"2.16.840.1.101.3.6.5.", // the nonexistent SHAKE arc
		"1.2.840.10045.3.1.1",   // secp192r1, formerly on P-224
		"HQC",
	}

	for _, gone := range forbidden {
		require.NotContains(t, doc, gone,
			"%q must not appear in emitted output", gone)
	}

}

// TestPQCPipeline_MalformedKeyDoesNotPanicOrFabricate covers the negative path
// end to end: a valid PEM envelope around truncated DER must yield no
// component rather than a made-up one.
func TestPQCPipeline_MalformedKeyDoesNotPanicOrFabricate(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.MLDSA65MalformedPrivateKey)
	require.NoError(t, err)

	bundle, err := pem.Scanner{}.Scan(t.Context(), data, cdxtest.MLDSA65MalformedPrivateKey)
	require.NoError(t, err, "the PEM envelope itself is well formed")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)
	require.Empty(t, d.Components,
		"an unparseable key must produce no components, not a guessed algorithm")
}

// TestPQCPipeline_MLKEMCertificateReportsKEMPrimitive asserts that a
// certificate carrying an ML-KEM public key describes it as a KEM.
//
// certHitToComponents used to overwrite the primitive with a hardcoded
// "signature" after publicKeyComponents had already set the registry value and
// hashed the component, which produced a self-contradictory component:
// primitive "signature" next to cryptoFunctions [decapsulate, encapsulate].
// The primitive is now whatever publicKeyComponents hashed, so the component's
// BOMRef and its contents agree.
func TestPQCPipeline_MLKEMCertificateReportsKEMPrimitive(t *testing.T) {
	t.Parallel()

	raw := buildPQCDocument(t, cdxtest.MLKEM768Certificate)

	var doc cdx.BOM
	require.NoError(t, json.Unmarshal(raw, &doc))

	var found bool
	for _, compo := range *doc.Components {
		if compo.Name != "ML-KEM-768" || compo.CryptoProperties == nil ||
			compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
			continue
		}
		props := compo.CryptoProperties.AlgorithmProperties
		if props == nil || props.CryptoFunctions == nil {
			continue
		}
		require.Contains(t, *props.CryptoFunctions, cdx.CryptoFunctionEncapsulate)
		require.Equal(t, cdx.CryptoPrimitiveKEM, props.Primitive,
			"an ML-KEM key must be reported as a kem, not a signature scheme")
		found = true
	}
	require.True(t, found, "no ML-KEM-768 algorithm component in the certificate document")
}
