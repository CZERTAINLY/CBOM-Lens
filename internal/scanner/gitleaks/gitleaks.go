package gitleaks

import (
	"context"
	"fmt"
	"sync"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

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

	return model.Leaks{
		Location: path,
		Findings: detector.DetectString(string(b)),
	}, nil
}
