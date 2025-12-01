package x509

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
)

// zipScanner handles ZIP/JAR/APK META-INF certificate detection
type zipScanner struct{}

// scan finds certificates in ZIP files (typically in META-INF for signed Java/Android artifacts)
func (d zipScanner) scan(ctx context.Context, b []byte) []certHit {
	slog.DebugContext(ctx, "Detecting ZIP/JAR/APK META-INF")

	var out []certHit

	// Check if it's a ZIP file
	if bytes.HasPrefix(b, []byte("PK\x03\x04")) {
		for _, h := range scanZIPForCerts(ctx, b) {
			out = append(out, certHit{
				Cert:   h.Cert,
				Source: "ZIP/" + h.Source,
			})
		}
	}

	slog.DebugContext(ctx, "Result of ZIP/JAR/APK META-INF detection", "hits", len(out))
	return out
}

func scanZIPForCerts(ctx context.Context, b []byte) []certHit {
	var out []certHit
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil
	}
	for _, f := range zr.File {
		name := strings.ToUpper(f.Name)
		if !strings.HasPrefix(name, "META-INF/") {
			continue
		}
		// Typical: CERT.RSA, *.RSA, *.DSA, *.EC, *.PK7
		//nolint:staticcheck // cbom-lens is going to recognize even obsoleted crypto
		if !(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") ||
			strings.HasSuffix(name, ".EC") || strings.HasSuffix(name, ".PK7") ||
			name == "META-INF/CERT.RSA") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		_ = rc.Close()

		// Recursively analyze entry contents (they're usually PKCS#7)
		sub := findAllCerts(ctx, data)
		for _, h := range sub {
			out = append(out, certHit{Cert: h.Cert, Source: h.Source})
		}
	}
	return out
}
