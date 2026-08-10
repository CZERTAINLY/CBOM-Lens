package cdxprops_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// TestPQCPipeline_MalformedKeyDoesNotPanicOrFabricate covers ONE negative path
// end to end: DER that is not valid ASN.1 at all. The parse fails before any
// component is built, so nothing downstream is exercised.
//
// The name overpromised for as long as that was the only case here. DER that
// parses cleanly as a PKCS#8 wrapper but carries a body far too small to be
// the key its OID names is the harder half, and it is covered by
// TestPQCPipeline_UndersizedBodyYieldsAlgorithmNotKey below.
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

// pkcs8PEM wraps a synthetic PKCS#8 PrivateKeyInfo carrying oid and a body of
// bodyLen bytes in a `PRIVATE KEY` PEM block. Go's stdlib cannot parse a
// post-quantum PKCS#8 key, so the scanner routes it to ParseErrors and the
// block reaches analyzeParseError -- the real production path.
func pkcs8PEM(t *testing.T, oid asn1.ObjectIdentifier, bodyLen int) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: make([]byte, bodyLen),
	})
	require.NoError(t, err)

	return pemlib.EncodeToMemory(&pemlib.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestPQCPipeline_UndersizedBodyYieldsAlgorithmNotKey pins the distinction
// between the two claims a PKCS#8 block can support.
//
// Validating only the wrapper and the OID meant the key body was never looked
// at: pkcs8Struct decoded version and privateKeyAlgorithm and stopped. A
// SEQUENCE carrying the ML-DSA-65 OID and four bytes where a 4032-byte key
// belongs produced a full related-crypto-material component named ML-DSA-65,
// with no log at any level -- so a consumer counting key material counted a
// key that is not there, which inverts the reason that component was added.
//
// The OID still yields the algorithm. "This file references ML-DSA-65" is what
// the bytes actually support, and it is what this path reported before it
// learned to emit key material.
func TestPQCPipeline_UndersizedBodyYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		bodyLen int
	}{
		// The original reproduction: four bytes, 0xdeadbeef's length.
		{"ML-DSA-65 four-byte body", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 4},
		{"ML-KEM-768 four-byte body", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}, 4},
		// One byte short of the SMALLEST legal encoding, which is the seed:
		// 32 bytes for ML-DSA (RFC 9881 sec. 6) and 64 for ML-KEM's (d, z).
		// This is the boundary the lower bound must still reject.
		//
		// It is deliberately not one byte short of the EXPANDED key. A body of
		// 4031 is accepted, and must be: an ML-DSA-65 key stored as a seed is
		// 32 bytes, so any floor high enough to reject 4031 also rejects every
		// seed-encoded key in existence. See
		// TestPQCPipeline_SeedEncodedKeysYieldTheirKey.
		{"ML-DSA-65 one byte under the seed", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 31},
		{"ML-KEM-768 one byte under the seed", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}, 63},
		// SLH-DSA has no seed alternative (RFC 9882), so its floor stays the
		// full 64-byte private key.
		{"SLH-DSA-SHA2-128S empty body", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}, 0},
		{"SLH-DSA-SHA2-128S one byte short", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}, 63},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bundle, err := pem.Scanner{}.Scan(t.Context(), pkcs8PEM(t, tt.oid, tt.bodyLen), "synthetic.pem")
			require.NoError(t, err, "the PEM envelope itself is well formed")

			d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
			require.NotNil(t, d)

			var algorithms, material []cdx.Component
			for _, compo := range d.Components {
				require.NotNil(t, compo.CryptoProperties,
					"the zero Component must never be appended")
				switch compo.CryptoProperties.AssetType {
				case cdx.CryptoAssetTypeAlgorithm:
					algorithms = append(algorithms, compo)
				case cdx.CryptoAssetTypeRelatedCryptoMaterial:
					material = append(material, compo)
				}
			}

			require.Len(t, algorithms, 1,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			require.Empty(t, material,
				"a body too small to be the key must not be reported as a key")
		})
	}
}

// TestPQCPipeline_SeedEncodedKeysYieldTheirKey is the regression test for a
// false negative the size guard shipped with: it rejected real keys.
//
// RFC 9881 sec. 6 makes the ML-DSA privateKey field a CHOICE of seed [0] (32
// bytes), expandedKey (4032 for ML-DSA-65), or both, and calls the seed the
// RECOMMENDED form. ML-KEM has the same shape with a 64-byte (d, z) seed. So
// one algorithm has legal bodies differing by two orders of magnitude.
//
// Every other post-quantum fixture in this repo is OpenSSL's default "both"
// encoding -- decoding their bodies gives SEQUENCE{OCTET STRING(32), OCTET
// STRING(4032)} and SEQUENCE{OCTET STRING(64), OCTET STRING(2400)} -- so a
// floor set at the expanded size passed every fixture and still reported a
// genuine seed-only key as no key at all. Node.js exports seed-only by
// default, so those are keys in the wild, and "this file has no private key"
// about a file that does is the same defect as #213 with the sign flipped.
//
// The fixtures are real `openssl genpkey` output, not synthetic lengths,
// because the bug was in believing the corpus represented the encoding space.
func TestPQCPipeline_SeedEncodedKeysYieldTheirKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture string
		algo    string
	}{
		{"ML-DSA-65 seed-only", cdxtest.MLDSA65SeedOnlyPrivateKey, "ML-DSA-65"},
		{"ML-KEM-768 seed-only", cdxtest.MLKEM768SeedOnlyPrivateKey, "ML-KEM-768"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err)

			bundle, err := pem.Scanner{}.Scan(t.Context(), data, tt.fixture)
			require.NoError(t, err)

			d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
			require.NotNil(t, d)

			var material []cdx.Component
			for _, compo := range d.Components {
				if compo.CryptoProperties != nil &&
					compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeRelatedCryptoMaterial {
					material = append(material, compo)
				}
			}

			require.Len(t, material, 1,
				"a seed-encoded %s private key is a private key; the size guard "+
					"must not report it as absent", tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
			require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey,
				material[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
			require.Empty(t, material[0].CryptoProperties.RelatedCryptoMaterialProperties.Value,
				"a seed IS the secret, so it must not be published either")
		})
	}
}

// TestPQCPipeline_RealFixturesStillYieldTheirKey guards the other direction of
// the same check: the size guard must not reject real keys.
//
// It is not redundant with TestPQCPipeline_PrivateKeyYieldsKeyMaterial, which
// asserts the shape of the emitted key. This asserts only that the key is
// there, and says why the bound has to be ">=" rather than "==": PKCS#8 wraps
// the standardised key in an algorithm-specific encoding whose overhead varies
// -- 42 bytes for ML-DSA-65, 74 for ML-KEM-768, 0 for SLH-DSA-SHA2-128S. An
// equality check would reject two of these three real files.
func TestPQCPipeline_RealFixturesStillYieldTheirKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture string
		name    string
	}{
		{cdxtest.MLDSA65PrivateKey, "ML-DSA-65"},
		{cdxtest.MLKEM768PrivateKey, "ML-KEM-768"},
		{cdxtest.SLHDSASHA2128sPrivateKey, "SLH-DSA-SHA2-128S"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err)

			bundle, err := pem.Scanner{}.Scan(t.Context(), data, tt.fixture)
			require.NoError(t, err)

			d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
			require.NotNil(t, d)

			var found bool
			for _, compo := range d.Components {
				if compo.CryptoProperties != nil &&
					compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeRelatedCryptoMaterial {
					require.Equal(t, tt.name, compo.Name)
					found = true
				}
			}
			require.True(t, found,
				"the private-key size guard rejected a real %s key", tt.name)
		})
	}
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

			// Nor the literal digest. Builder.safeRef rewrites the ref to
			// <prefix>@<uuidv5>, so the sha256 hex does not appear.
			//
			// Be clear about what this does and does not buy. safeRef is
			// uuid.NewSHA1(NameSpaceDNS, rawRef) -- deterministic -- and the
			// raw ref contains the digest, so the emitted UUID is still a
			// function of the private DER and reconstructible from a candidate
			// key file alone. This assertion pins the encoding, NOT secrecy;
			// the accepted-and-documented oracle is described on
			// unsupportedPKCS8PrivateKey. What it would catch is the digest
			// being emitted somewhere safeRef does not reach -- a property, a
			// description, a second ref field added later.
			derDigest := sha256.Sum256(block.Bytes)
			require.NotContains(t, string(raw), hex.EncodeToString(derDigest[:]),
				"the private key's digest reached the emitted document")
		})
	}
}
