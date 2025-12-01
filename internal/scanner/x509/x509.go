package x509

import (
	"context"
	"crypto/sha256"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

type certHit = model.CertHit

// Scanner tries to parse the X509 certificate(s) and return a proper hit objects
type Scanner struct{}

func (s Scanner) Scan(ctx context.Context, b []byte, path string) ([]model.CertHit, error) {
	hits := findAllCerts(ctx, b)

	for idx := range hits {
		hits[idx].Location = path
	}

	return hits, nil
}

// -------- Certificate extraction (multi-source) --------

// scanner interface for certificate detection
type scanner interface {
	scan(ctx context.Context, b []byte) []model.CertHit
}

func findAllCerts(ctx context.Context, b []byte) []model.CertHit {
	seen := make(map[[32]byte]struct{})
	add := func(hits []certHit, out *[]certHit) {
		for _, h := range hits {
			if h.Cert == nil {
				continue
			}
			fp := sha256.Sum256(h.Cert.Raw)
			if _, dup := seen[fp]; dup {
				continue
			}
			seen[fp] = struct{}{}
			*out = append(*out, h)
		}
	}

	out := make([]certHit, 0, 4)

	// Initialize all scanners
	scanners := []scanner{
		jksScanner{},    // 2) JKS / JCEKS (Java keystores)
		pkcs12Scanner{}, // 3) PKCS#12 (PFX)
		derScanner{},    // 4) Raw DER (single/concatenated certs, or DER-encoded PKCS#7)
		zipScanner{},    // 5) ZIP/JAR/APK META-INF
	}

	// Run all detectors
	for _, d := range scanners {
		hits := d.scan(ctx, b)
		add(hits, &out)
	}

	return out
}
