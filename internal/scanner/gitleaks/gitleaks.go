package gitleaks

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type Scanner struct {
	pool sync.Pool
	mx   sync.Mutex
}

func NewScanner() (*Scanner, error) {
	first, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("creating new gitleaks detector: %w", err)
	}
	d := &Scanner{}
	d.pool = sync.Pool{
		New: func() any {
			d.mx.Lock()
			defer d.mx.Unlock()
			detector, err := detect.NewDetectorDefaultConfig()
			if err != nil {
				panic(err)
			}
			return detector
		},
	}
	d.pool.Put(first)
	return d, nil
}

// Detect uses github.com/zricethezav/gitleaks/v8 to detect possible leaked files
// This method is SAFE to be called from multiple goroutines
func (d *Scanner) Scan(ctx context.Context, b []byte, path string) (model.Leaks, error) {
	// Check for context cancellation early to respect caller deadlines and
	// to avoid unnecessary work; this also makes ctx a used parameter.
	select {
	case <-ctx.Done():
		return model.Leaks{}, ctx.Err()
	default:
	}

	detector := d.pool.Get().(*detect.Detector)
	defer d.pool.Put(detector)

	reports := detector.DetectString(string(b))
	var findings = make([]model.Finding, len(reports))
	for i, r := range reports {
		findings[i] = model.Finding{
			RuleID:      r.RuleID,
			Description: r.Description,
			StartLine:   r.StartLine,
			Secret:      r.Secret,
		}
		if r.RuleID == "private-key" {
			bundle, err := pem.Scanner{}.Scan(ctx, b, path)
			if err == nil {
				findings[i].PEMBundle = bundle
			} else {
				slog.WarnContext(ctx, "can't parse private-key", "error", err)
			}
		}
	}

	return model.Leaks{
		Location: path,
		Findings: findings,
	}, nil
}
