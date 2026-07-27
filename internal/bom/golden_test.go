package bom

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"html"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/nmap"
	pemscan "github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	nmapv3 "github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

// buildRepresentativeCorpus assembles a small, stable set of model.Detection
// values via the real cdxprops.Converter, covering:
//   - one certificate detection (sig-alg + public-key + hash-alg dependency edge)
//   - one leak detection
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
		Info nmapv3.Host `json:"Info"`
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

	// 7. Nmap/TLS port detection: same committed raw nmap scan fixture.
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
func certFromNmapFixture(t *testing.T, host nmapv3.Host) *x509.Certificate {
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
