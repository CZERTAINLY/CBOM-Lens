package bom

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/nmap"
	pemscan "github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	nmapv4 "github.com/Ullaakut/nmap/v4"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

// buildRepresentativeCorpus assembles a small, stable set of model.Detection
// values via the real cdxprops.Converter, covering:
//   - one certificate detection (sig-alg + public-key + hash-alg dependency edge)
//   - one leak detection
//   - one CSR and one CRL
//   - one nmap/TLS port detection
//
// All inputs come from committed testdata so the output is reproducible on
// any machine. Anything the real converters derive from the local
// environment (e.g. os.Hostname() used by Converter.Nmap for the detection
// Location) is normalized to a fixed value afterwards so the golden does not
// depend on where the test runs.
func buildRepresentativeCorpus(t *testing.T) []model.Detection {
	t.Helper()
	ctx := context.Background()
	// Component BOMRefs are content hashes covering implementationPlatform
	// (runtime.GOARCH); pin the platform so refs — and with them the golden —
	// are identical on every architecture.
	conv := cdxprops.NewConverter().WithImplementationPlatform(cdx.ImplementationPlatformX86_64)

	var detections []model.Detection

	// internal/nmap/testdata/raw.json is only exposed to the nmap package's
	// own tests (via an embed.FS in a _test.go file), so it is read directly
	// from disk here, relative to this package's directory.
	rawJSON, err := os.ReadFile(filepath.Join("..", "nmap", "testdata", "raw.json"))
	require.NoError(t, err)
	var raw struct {
		Info nmapv4.Host `json:"Info"`
	}
	require.NoError(t, json.Unmarshal(rawJSON, &raw))

	// 1. Certificate detection: the real RSA/SHA-256 leaf certificate
	// embedded (as a "ssl-cert" script PEM element) in the committed nmap
	// fixture above. Unlike the ML-DSA-65 test certificate, a classical
	// hash-then-sign certificate exercises the
	// signature-algorithm -> {public-key-algorithm, hash-algorithm}
	// dependency edge that certHitToComponents produces, so it is the more
	// representative choice for this golden.
	cert := certFromNmapFixture(t, raw.Info)
	certDetection := conv.CertHit(ctx, model.CertHit{
		Cert:     cert,
		Source:   "PEM",
		Location: "/fixtures/rsa-leaf-cert.pem",
	})
	require.NotNil(t, certDetection)
	require.NotEmpty(t, certDetection.Dependencies, "expected a signature-algorithm dependency edge")
	detections = append(detections, *certDetection)

	// 2. Leak detection: a fixed, well-known JWT literal (no randomness).
	const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
	leakDetection := conv.Leak(ctx, model.Leaks{
		Location: "/fixtures/leak.env",
		Findings: []model.Finding{
			{
				RuleID:      "jwt-token",
				Description: "Found JWT token",
				StartLine:   1,
				Secret:      jwtToken,
			},
		},
	})
	require.NotNil(t, leakDetection)
	detections = append(detections, *leakDetection)

	// 3. EC P-256 certificate (committed static fixture): exercises the
	// ECDSA public-key path and AlgorithmProperties.Curve — the exact field
	// CycloneDX 1.7 renames to ellipticCurve, so the 1.6 rendering must be
	// pinned before an emit17 exists.
	ecCert := certFromPEMFixture(t, filepath.Join("testdata", "fixtures", "ec-p256-cert.pem"))
	ecDetection := conv.CertHit(ctx, model.CertHit{
		Cert:     ecCert,
		Source:   "PEM",
		Location: "/fixtures/ec-p256-cert.pem",
	})
	require.NotNil(t, ecDetection)
	detections = append(detections, *ecDetection)

	// 4. Ed25519 certificate (committed static fixture): EdDSA signature path,
	// which has no classical hash-then-sign decomposition.
	edCert := certFromPEMFixture(t, filepath.Join("testdata", "fixtures", "ed25519-cert.pem"))
	edDetection := conv.CertHit(ctx, model.CertHit{
		Cert:     edCert,
		Source:   "PEM",
		Location: "/fixtures/ed25519-cert.pem",
	})
	require.NotNil(t, edDetection)
	detections = append(detections, *edDetection)

	// 5. PEM private-key bundle through the real scanner: related-crypto-material
	// (private key) path.
	keyPEM, err := os.ReadFile(filepath.Join("testdata", "fixtures", "rsa-private-key.pem"))
	require.NoError(t, err)
	bundle, err := pemscan.Scanner{}.Scan(ctx, keyPEM, "/fixtures/rsa-private-key.pem")
	require.NoError(t, err)
	pemDetection := conv.PEMBundle(ctx, bundle)
	require.NotNil(t, pemDetection)
	detections = append(detections, *pemDetection)

	// 6. Password leak: a second relatedCryptoMaterial type besides token.
	passwordDetection := conv.Leak(ctx, model.Leaks{
		Location: "/fixtures/leak.env",
		Findings: []model.Finding{
			{
				RuleID:      "generic-password",
				Description: "Found password",
				StartLine:   3,
				Secret:      "hunter2-fixture-password",
			},
		},
	})
	require.NotNil(t, passwordDetection)
	detections = append(detections, *passwordDetection)

	// 7. CSR and CRL through the real scanner. Both used to be built without a
	// bom-ref, so Builder.appendDetection dropped them and a scanned .csr or
	// .crl produced nothing at all. Nothing pinned that end to end, which is
	// why they are in the corpus now.
	//
	// The fixtures are committed static bytes rather than cdxtest.GenCSR /
	// GenCRL output: those generate a fresh key and use time.Now(), so the
	// golden would churn on every run.
	pkiPEM, err := os.ReadFile(filepath.Join("testdata", "fixtures", "csr.pem"))
	require.NoError(t, err)
	crlPEM, err := os.ReadFile(filepath.Join("testdata", "fixtures", "crl.pem"))
	require.NoError(t, err)
	pkiBundle, err := pemscan.Scanner{}.Scan(ctx, append(pkiPEM, crlPEM...), "/fixtures/pki.pem")
	require.NoError(t, err)
	require.Len(t, pkiBundle.CertificateRequests, 1)
	require.Len(t, pkiBundle.CRLs, 1)
	pkiDetection := conv.PEMBundle(ctx, pkiBundle)
	require.NotNil(t, pkiDetection)
	detections = append(detections, *pkiDetection)

	// 8. Nmap/TLS port detection: same committed raw nmap scan fixture.
	nmapModel := nmap.HostToModel(ctx, raw.Info)
	nmapDetections := conv.Nmap(ctx, nmapModel)
	require.NotEmpty(t, nmapDetections)

	// Converter.Nmap derives Location from os.Hostname(), which varies by
	// machine. Normalize it to a fixed, deterministic value so the golden
	// output does not depend on where the test runs.
	nmapDetection := nmapDetections[0]
	nmapDetection.Location = "tcp://fixture-host:443"
	detections = append(detections, nmapDetection)

	return detections
}

// fixtureDetections returns a representative, hand-built corpus covering
// certificate, leak, and nmap detections, built from committed testdata via
// the real cdxprops.Converter so the corpus mirrors real output.
func fixtureDetections(t *testing.T) []model.Detection {
	t.Helper()
	return buildRepresentativeCorpus(t)
}

func goldenBuilder(t *testing.T) *Builder {
	t.Helper()
	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	return b.WithClock(func() time.Time { return fixed }).
		WithSerial(func() string { return "urn:uuid:11111111-1111-1111-1111-111111111111" })
}

func TestGolden_1_6(t *testing.T) {
	b := goldenBuilder(t).AppendDetections(context.Background(), fixtureDetections(t)...)
	var buf bytes.Buffer
	require.NoError(t, b.AsJSON(context.Background(), &buf))

	// The golden must always be a schema-valid 1.6 document, especially at
	// -update time when new corpus entries are captured.
	v, err := NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)
	require.NoError(t, v.ValidateBytes(buf.Bytes()), "golden output must validate against the CycloneDX 1.6 schema")

	path := filepath.Join("testdata", "golden", "corpus-1.6.json")
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run: go test ./internal/bom -run TestGolden_1_6 -update")
	require.Equal(t, string(want), buf.String())
}

// TestGolden_NoMaterialPropsOnNonMaterialAssets states #213 over the whole
// pipeline, in both spec versions: relatedCryptoMaterialProperties describes a
// serialised object, so only a related-crypto-material asset may carry it.
//
// The corpus used to emit it on one algorithm (with format=PEM, from
// Converter.PEMBundle's blanket loop) and on all three certificates (empty,
// from certificateRelatedProperties), so a consumer filtering assets by the
// presence of that field over-counted key material by a factor of three.
func TestGolden_NoMaterialPropsOnNonMaterialAssets(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			detections := fixtureDetections(t)
			b, err := NewBuilder(model.CBOM{Version: version})
			require.NoError(t, err)
			fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
			b = b.WithClock(func() time.Time { return fixed }).
				WithSerial(func() string { return "urn:uuid:11111111-1111-1111-1111-111111111111" }).
				AppendDetections(context.Background(), detections...)

			var buf bytes.Buffer
			require.NoError(t, b.AsJSON(context.Background(), &buf))

			var decoded cdx.BOM
			require.NoError(t, cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON).Decode(&decoded))
			require.NotNil(t, decoded.Components)

			// Counted so a corpus change cannot make this vacuous.
			var material, other int
			for _, c := range *decoded.Components {
				cp := c.CryptoProperties
				if cp == nil {
					continue
				}
				if cp.AssetType == cdx.CryptoAssetTypeRelatedCryptoMaterial {
					material++
					continue
				}
				other++
				require.Nil(t, cp.RelatedCryptoMaterialProperties,
					"%s (%s): a %s asset must not carry "+
						"relatedCryptoMaterialProperties (#213)",
					c.Name, c.BOMRef, cp.AssetType)
			}
			require.NotZero(t, material, "corpus must contain key material")
			require.NotZero(t, other, "corpus must contain non-material crypto assets")
		})
	}
}

// certFromPEMFixture reads and parses the first certificate from a committed
// PEM fixture file.
func certFromPEMFixture(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "failed to PEM-decode %s", path)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// certFromNmapFixture extracts and parses the leaf certificate embedded in
// the "ssl-cert" nmap script output of host (as a PEM "elem" value, the way
// nmap emits it). This mirrors internal/nmap's own sslCerts() parsing so the
// certificate matches exactly what a real nmap/cdxprops run would see.
func certFromNmapFixture(t *testing.T, host nmapv4.Host) *x509.Certificate {
	t.Helper()
	for _, port := range host.Ports {
		for _, script := range port.Scripts {
			if script.ID != "ssl-cert" {
				continue
			}
			for _, el := range script.Elements {
				if el.Key != "pem" {
					continue
				}
				decoded := html.UnescapeString(el.Value)
				block, _ := pem.Decode([]byte(decoded))
				require.NotNil(t, block, "failed to PEM-decode ssl-cert element")
				cert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)
				return cert
			}
		}
	}
	t.Fatal("no ssl-cert PEM element found in nmap fixture")
	return nil
}

// TestGolden_DependsOnIsIndependentOfDetectionOrder is the corpus-level
// tripwire: the same representative scan, appended back to front, must deliver
// the SAME dependency rows byte for byte, in both spec versions.
//
// The unit tests in builder_test.go build their own detections; this one runs
// the real converters over the committed fixtures, which is where a collision
// nobody modelled shows up. The corpus already contains one -- a certificate and
// a CRL both signed ECDSA-SHA256, sharing crypto/algorithm/sha-256-ecdsa -- and
// it survived first-wins only because the certificate happens to be appended
// first and the CRL's edge set is a subset of it. Reversed, first-wins drops the
// certificate's edge to its own public-key algorithm and this test fails, while
// TestGolden_1_6 does not: a golden pins one arrival order, and the order is the
// bug.
//
// Scoped to the dependency rows deliberately. The WHOLE document is NOT yet
// order-independent: certificateExtension (1.6) / certificateFileExtension (1.7)
// is filepath.Ext(hit.Location) on a component whose bom-ref is a digest of
// cert.Raw alone, so the nmap and the PEM sighting of one certificate disagree
// on it and the first appended wins -- reversing this corpus flips it from
// ".pem" to ".44:443". That is the same defect this change fixed for dependsOn,
// one field over, and out of scope here. Widening this test to the whole
// document is the right move once that is fixed; weakening it is not.
func TestGolden_DependsOnIsIndependentOfDetectionOrder(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			forward := fixtureDetections(t)
			reversed := fixtureDetections(t)
			slices.Reverse(reversed)

			want := goldenDependencyRows(t, renderDependsOnBOM(t, version, forward...))
			got := goldenDependencyRows(t, renderDependsOnBOM(t, version, reversed...))

			// The corpus really does exercise the merge, so two empty renderings
			// cannot pass this by agreeing about nothing.
			require.NotEmpty(t, want)
			require.Contains(t, want, `"dependsOn"`,
				"the corpus must contain at least one dependency edge")

			require.Equal(t, want, got,
				"appending the same scan in the opposite order must deliver the "+
					"same dependency rows byte for byte")
		})
	}
}

// TestGolden_OneRSAKeyIsOneAlgorithmAssetInEveryArrivalOrder is the delivered-
// document form of the whole fix, and it asserts the WHOLE document rather than
// only its dependency rows.
//
// One RSA-2048 key is described here by four detections: a signing certificate,
// an encipherment certificate, a certificate request, and a PEM bundle holding
// the private key. Before this change those four disagreed about the algorithm
// asset. publicKeyComponents read cert.KeyUsage and stamped signature or pke
// onto the algorithm component BEFORE hashing it into its own bom-ref, and
// Converter.PrivateKey stamped nothing at all, so the four detections minted up
// to three different crypto/algorithm/rsa-2048@... refs for one key -- and the
// Builder dedups by ref and keeps the first, so which of them the document
// carried, and which of them the private key's algorithmRef pointed at, was
// decided by the order the scanners reported in.
//
// All 24 permutations, not a forward/reverse pair. A pair cannot tell a set from
// last-wins, nor either from an accumulator that is stable but arrival-ordered;
// with four elements any order-sensitive union produces at least two distinct
// renderings, and n>=3 is the smallest size that separates "sorted set" from
// "last writer wins under a total comparator".
//
// The fixture deliberately does NOT include one certificate found at two
// locations. certificateExtension is filepath.Ext(hit.Location) on a component
// whose ref digests cert.Raw alone, a documented and out-of-scope order
// dependence (see TestGolden_DependsOnIsIndependentOfDetectionOrder), and a
// fixture carrying it would fail this test for a reason that is not this fix.
// Two different certificates at two paths avoid it while still colliding on
// everything this fix is about: one key, one algorithm, one shared
// signature-algorithm ref. It does exercise mergeRelatedCryptoMaterialFormat,
// since the bundle's copy of the public key carries format=PEM and the
// certificates' copies carry none.
func TestGolden_OneRSAKeyIsOneAlgorithmAssetInEveryArrivalOrder(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	detections := oneRSAKeyDetections(t, key)
	require.Len(t, detections, 4)

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			var want string
			var wantOrder string
			for _, order := range permutations(len(detections)) {
				permuted := make([]model.Detection, 0, len(detections))
				for _, i := range order {
					permuted = append(permuted, detections[i])
				}
				got := renderDependsOnBOM(t, version, permuted...)

				// Counted before the comparison, so two identically truncated
				// renderings cannot pass this by agreeing about nothing.
				require.Equal(t, 1, countRefsWithPrefix(t, got, "crypto/algorithm/rsa-2048@"),
					"order %v: one RSA-2048 key is one algorithm asset", order)

				if want == "" {
					want, wantOrder = got, fmt.Sprint(order)
					continue
				}
				require.Equal(t, want, got,
					"order %v delivers a different document from order %s",
					order, wantOrder)
			}
		})
	}
}

// oneRSAKeyDetections describes a single RSA key four ways, through the real
// converters: two certificates that differ only in what they permit the key to
// do, a request to certify it, and the private half in a PEM bundle. Everything
// that would otherwise vary per run -- the clock, the serial, the architecture
// the refs are hashed on -- is pinned by the caller or by the converter.
func oneRSAKeyDetections(t *testing.T, key *rsa.PrivateKey) []model.Detection {
	t.Helper()
	ctx := context.Background()

	// Component BOMRefs hash implementationPlatform, so pin it here for the same
	// reason buildRepresentativeCorpus does.
	conv := cdxprops.NewConverter().WithImplementationPlatform(cdx.ImplementationPlatformX86_64)

	cert := func(cn string, usage x509.KeyUsage) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(usage)),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Unix(0, 0).UTC(),
			NotAfter:     time.Unix(1<<31, 0).UTC(),
			KeyUsage:     usage,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		parsed, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return parsed
	}

	signing := conv.CertHit(ctx, model.CertHit{
		Cert:     cert("rsa-signing.fixture.test", x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		Source:   "PEM",
		Location: "/fixtures/rsa-signing.pem",
	})
	require.NotNil(t, signing)

	encipherment := conv.CertHit(ctx, model.CertHit{
		Cert:     cert("rsa-encipherment.fixture.test", x509.KeyUsageKeyEncipherment),
		Source:   "PEM",
		Location: "/fixtures/rsa-encipherment.pem",
	})
	require.NotNil(t, encipherment)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "rsa-request.fixture.test"}}, key)
	require.NoError(t, err)
	csrBundle, err := pemscan.Scanner{}.Scan(ctx,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		"/fixtures/rsa-request.csr")
	require.NoError(t, err)
	require.Len(t, csrBundle.CertificateRequests, 1)
	csr := conv.PEMBundle(ctx, csrBundle)
	require.NotNil(t, csr)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyBundle, err := pemscan.Scanner{}.Scan(ctx,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"/fixtures/rsa-private-key.pem")
	require.NoError(t, err)
	require.Len(t, keyBundle.PrivateKeys, 1)
	privateKey := conv.PEMBundle(ctx, keyBundle)
	require.NotNil(t, privateKey)

	return []model.Detection{*signing, *encipherment, *csr, *privateKey}
}

// countRefsWithPrefix counts the components of doc whose bom-ref starts with
// prefix. It decodes rather than counting substrings because a ref also appears
// wherever something points at it, and the question here is how many ASSETS
// exist.
func countRefsWithPrefix(t *testing.T, doc, prefix string) int {
	t.Helper()

	var bom cdx.BOM
	require.NoError(t, json.Unmarshal([]byte(doc), &bom))
	require.NotNil(t, bom.Components)

	var n int
	for _, c := range *bom.Components {
		if strings.HasPrefix(c.BOMRef, prefix) {
			n++
		}
	}
	return n
}

// permutations returns every ordering of the indices 0..n-1, by Heap's
// algorithm. Written out rather than pulled in so the test states its own
// coverage: len(permutations(4)) is 24, and a generator that quietly produced
// fewer would weaken the assertion above without failing anything.
func permutations(n int) [][]int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}

	var out [][]int
	var generate func(k int)
	generate = func(k int) {
		if k == 1 {
			out = append(out, slices.Clone(idx))
			return
		}
		for i := range k {
			generate(k - 1)
			if k%2 == 0 {
				idx[i], idx[k-1] = idx[k-1], idx[i]
			} else {
				idx[0], idx[k-1] = idx[k-1], idx[0]
			}
		}
	}
	generate(n)
	return out
}

// goldenDependencyRows re-encodes just the dependencies array of doc, so that a
// difference elsewhere in the document cannot be mistaken for a dependency one.
func goldenDependencyRows(t *testing.T, doc string) string {
	t.Helper()

	var bom cdx.BOM
	require.NoError(t, json.Unmarshal([]byte(doc), &bom))
	require.NotNil(t, bom.Dependencies)

	raw, err := json.MarshalIndent(bom.Dependencies, "", "  ")
	require.NoError(t, err)
	return string(raw)
}

func TestGolden_1_7(t *testing.T) {
	b, err := NewBuilder(model.CBOM{Version: "1.7"})
	require.NoError(t, err)
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	b = b.WithClock(func() time.Time { return fixed }).
		WithSerial(func() string { return "urn:uuid:11111111-1111-1111-1111-111111111111" }).
		AppendDetections(context.Background(), fixtureDetections(t)...)

	var buf bytes.Buffer
	require.NoError(t, b.AsJSON(context.Background(), &buf))

	v, err := NewValidator(cdx.SpecVersion1_7)
	require.NoError(t, err)
	require.NoError(t, v.ValidateBytes(buf.Bytes()), "1.7 output must validate against the 1.7 schema set")

	// Zero tolerance for dangling refs in 1.7 (unlike 1.6's frozen allowlist).
	var bom17 cdx.BOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom17))
	assertRefIntegrity(t, &bom17, nil)

	// Parsing coverage (#175 acceptance): the document must round-trip
	// through the library decoder, not just encoding/json.
	var decoded cdx.BOM
	require.NoError(t, cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON).Decode(&decoded))
	require.Equal(t, cdx.SpecVersion1_7, decoded.SpecVersion)

	// The superseded 1.6 fields are schema-legal in 1.7 — assert absence
	// explicitly. `curve` is deliberately NOT on this list: it is dual-emitted
	// (see mapComponent17), because it is deprecated by annotation only, is not
	// mutually exclusive with ellipticCurve, and carries curve information for
	// every asset whose curve has no trusted 1.7 mapping.
	for _, superseded := range []string{
		`"signatureAlgorithmRef"`, `"subjectPublicKeyRef"`, `"algorithmRef"`,
		`"cryptoRefArray"`, `"certificateExtension"`,
	} {
		require.NotContains(t, buf.String(), superseded,
			"superseded 1.6 field must be absent from 1.7 output")
	}

	// Dual-emit, positively asserted: the fabricated sig-alg curve keeps its
	// `curve` value and gains no ellipticCurve, while the real EC key's
	// parameterSetIdentifier maps to a namespaced enum value.
	require.Contains(t, buf.String(), `"curve": "secp256r1"`,
		"deprecated curve must still be emitted in 1.7 (dual-emit)")
	require.Contains(t, buf.String(), `"ellipticCurve": "secg/secp256r1"`,
		"corpus must exercise the 1.7 ellipticCurve enum")

	// The schema has no enum for relatedCryptographicAssets[].type — pin the
	// vocabulary ourselves.
	seenTypes := map[string]bool{}
	for _, c := range *bom17.Components {
		cp := c.CryptoProperties
		if cp == nil {
			continue
		}
		var lists []*[]cdx.RelatedCryptographicAsset
		if cp.CertificateProperties != nil {
			lists = append(lists, cp.CertificateProperties.RelatedCryptographicAssets)
		}
		if cp.RelatedCryptoMaterialProperties != nil {
			lists = append(lists, cp.RelatedCryptoMaterialProperties.RelatedCryptographicAssets)
		}
		if cp.ProtocolProperties != nil {
			lists = append(lists, cp.ProtocolProperties.RelatedCryptographicAssets)
		}
		for _, l := range lists {
			if l == nil {
				continue
			}
			for _, rca := range *l {
				seenTypes[rca.Type] = true
				require.Contains(t, []string{"algorithm", "publicKey", "certificate"}, rca.Type)
			}
		}
	}
	require.True(t, seenTypes["algorithm"], "corpus must exercise type=algorithm")
	// The protocol's cryptoRefArray edge targets a certificate asset; the
	// emitter labels it by target asset type.
	require.True(t, seenTypes["certificate"], "corpus must exercise type=certificate")
	// certHitToComponents points subjectPublicKeyRef at the key material since
	// #204, so this edge is target-labelled "publicKey".
	require.True(t, seenTypes["publicKey"],
		"subjectPublicKeyRef must target the key material, so the edge is "+
			"labelled publicKey -- the shape the specification's own 1.7 "+
			"conformance fixtures use")

	path := filepath.Join("testdata", "golden", "corpus-1.7.json")
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run: go test ./internal/bom -run TestGolden_1_7 -update")
	require.Equal(t, string(want), buf.String())
}
