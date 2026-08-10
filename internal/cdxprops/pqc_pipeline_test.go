package cdxprops_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	pemlib "encoding/pem"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/bom"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

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
	return buildPQCDocumentVersion(t, "1.6", fixtures...)
}

// buildPQCDocumentVersion is buildPQCDocument with the spec version chosen, so
// the post-quantum path can be exercised against the 1.7 emitter and its
// closed-enum registry fields rather than only against 1.6.
func buildPQCDocumentVersion(t *testing.T, version string, fixtures ...string) []byte {
	t.Helper()

	c := cdxprops.NewConverter().
		WithIlmExtensions(true).
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

	b, err := bom.NewBuilder(model.CBOM{Version: version})
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
		require.Equal(t, "4032", cdxtest.GetProp(compo, ilm.AlgorithmPrivateKeySize))
		require.Equal(t, "1952", cdxtest.GetProp(compo, ilm.AlgorithmPublicKeySize))
		require.Equal(t, "3309", cdxtest.GetProp(compo, ilm.AlgorithmSignatureSize))
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
		require.Equal(t, "64", cdxtest.GetProp(compo, ilm.AlgorithmPrivateKeySize))
		require.Equal(t, "32", cdxtest.GetProp(compo, ilm.AlgorithmPublicKeySize))
		require.Equal(t, "7856", cdxtest.GetProp(compo, ilm.AlgorithmSignatureSize))
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
		require.Equal(t, "1184", cdxtest.GetProp(compo, ilm.AlgorithmPublicKeySize),
			"encapsulation key")
		require.Equal(t, "2400", cdxtest.GetProp(compo, ilm.AlgorithmPrivateKeySize),
			"decapsulation key")
		require.Equal(t, "1088", cdxtest.GetProp(compo, ilm.AlgorithmCiphertextSize))
		require.Empty(t, cdxtest.GetProp(compo, ilm.AlgorithmSignatureSize),
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

// TestPQCPipeline_1_7RegistryFields closes the gap where no post-quantum asset
// ever reached the 1.7 emitter: the corpus contains none, and this file's other
// tests all built 1.6 documents, so the ML-DSA / ML-KEM / SLH-DSA rules that are
// the bulk of cdx17map.go were exercised only by their unit table and no PQC
// document was ever validated against the 1.7 schema set.
//
// That matters more here than for a classical algorithm: algorithmFamily is a
// closed enumeration, so an unmapped post-quantum family is not a missing field
// but an invalid document -- and AsJSON validates, so reaching the assertions
// below at all proves the document conforms.
func TestPQCPipeline_1_7RegistryFields(t *testing.T) {
	t.Parallel()

	raw := buildPQCDocumentVersion(t, "1.7",
		cdxtest.MLDSA65PrivateKey,
		cdxtest.SLHDSASHA2128sPrivateKey,
		cdxtest.MLKEM768PublicKey,
	)

	var doc struct {
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name             string `json:"name"`
			CryptoProperties struct {
				AlgorithmProperties struct {
					AlgorithmFamily string `json:"algorithmFamily"`
					EllipticCurve   string `json:"ellipticCurve"`
				} `json:"algorithmProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Equal(t, "1.7", doc.SpecVersion)

	families := map[string]string{}
	for _, c := range doc.Components {
		if f := c.CryptoProperties.AlgorithmProperties.AlgorithmFamily; f != "" {
			families[f] = c.Name
		}
	}

	for _, want := range []string{"ML-DSA", "SLH-DSA", "ML-KEM"} {
		require.Contains(t, families, want,
			"post-quantum family %q must reach the 1.7 registry field; got %v", want, families)
	}

	// No post-quantum algorithm here is on a curve, so asserting the absence
	// guards against a mapping table reaching for one.
	for _, c := range doc.Components {
		if f := c.CryptoProperties.AlgorithmProperties.AlgorithmFamily; f == "ML-DSA" || f == "SLH-DSA" || f == "ML-KEM" {
			require.Empty(t, c.CryptoProperties.AlgorithmProperties.EllipticCurve,
				"%s is not an elliptic-curve algorithm", c.Name)
		}
	}
}

// TestPQCPipeline_PrivateKeyYieldsKeyMaterial closes the gap where a
// post-quantum private key contributed no related-crypto-material asset at all.
//
// unsupportedPKCS8PrivateKey returned only an algorithm component while its
// sibling unsupportedPKIX returned a key and an algorithm, so once #213 stopped
// stamping relatedCryptoMaterialProperties onto everything, a scan of an
// ML-DSA, SLH-DSA or ML-KEM private key named the algorithm and never said a
// key existed. A consumer counting key material saw zero.
//
// The last assertion is the load-bearing one and the reason this test builds a
// whole document rather than inspecting a component: the private DER must not
// appear in the output. unsupportedPKIX publishes its DER as
// relatedCryptoMaterialProperties.value, which is correct there because that
// DER is a public key; the same field on this path would put the secret into a
// document that gets uploaded and shared.
func TestPQCPipeline_PrivateKeyYieldsKeyMaterial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture string
		name    string
	}{
		{cdxtest.MLDSA65PrivateKey, "ML-DSA-65"},
		{cdxtest.SLHDSASHA2128sPrivateKey, "SLH-DSA-SHA2-128S"},
		{cdxtest.MLKEM768PrivateKey, "ML-KEM-768"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw := buildPQCDocument(t, tt.fixture)

			var doc cdx.BOM
			require.NoError(t, json.Unmarshal(raw, &doc))
			require.NotNil(t, doc.Components)

			refs := map[string]cdx.Component{}
			var material []cdx.Component
			for _, compo := range *doc.Components {
				refs[compo.BOMRef] = compo
				if compo.CryptoProperties != nil &&
					compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeRelatedCryptoMaterial {
					material = append(material, compo)
				}
			}
			require.Len(t, material, 1,
				"a post-quantum private key must contribute exactly one key-material asset")

			key := material[0]
			require.Equal(t, tt.name, key.Name)

			props := key.CryptoProperties.RelatedCryptoMaterialProperties
			require.NotNil(t, props)
			require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, props.Type)
			require.Equal(t, "PEM", props.Format)
			// size is in bits in the schema while the registry's post-quantum
			// sizes are FIPS 203/204 byte counts. Emitting one would understate
			// the key eightfold and still validate, so nothing downstream would
			// catch it.
			require.Nil(t, props.Size)

			// The algorithmRef must resolve inside the document. It is the only
			// link this key has to its algorithm: the bom-ref hashes the
			// private DER, from which the public half cannot be recovered, so
			// unlike a classical keypair there is no shared digest to pair on.
			require.NotEmpty(t, props.AlgorithmRef)
			algo, ok := refs[string(props.AlgorithmRef)]
			require.True(t, ok, "algorithmRef %q does not resolve in the document", props.AlgorithmRef)
			require.Equal(t, cdx.CryptoAssetTypeAlgorithm, algo.CryptoProperties.AssetType)

			// The secret must not be in the document, in any component or
			// property. This is the assertion protecting "no secret in the
			// BOM"; everything else above is descriptive.
			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err)
			block, _ := pemlib.Decode(data)
			require.NotNil(t, block)
			require.NotContains(t, string(raw), base64.StdEncoding.EncodeToString(block.Bytes),
				"the private key DER reached the emitted document")

			// Nor its digest. The bom-ref is built from sha256(private DER),
			// and what keeps that off the wire is Builder.safeRef rewriting
			// every ref to <prefix>@<uuidv5> -- an indirection in another
			// package that nothing here would otherwise notice losing. Without
			// it the document would carry a value derived from the secret,
			// letting anyone holding a candidate key file confirm that exact
			// file was scanned, at the location evidence records.
			derDigest := sha256.Sum256(block.Bytes)
			require.NotContains(t, string(raw), hex.EncodeToString(derDigest[:]),
				"the private key's digest reached the emitted document")
		})
	}
}
