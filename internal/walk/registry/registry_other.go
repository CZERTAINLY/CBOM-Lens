//go:build !windows

package registry

import (
	"context"
	"errors"
	"iter"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
)

// Walk yields a single error on non-Windows platforms when the registry
// scanner is enabled, because the Windows registry is not available.
func Walk(_ context.Context, _ *stats.Stats, cfg model.Registry) iter.Seq2[model.Entry, error] {
	return func(yield func(model.Entry, error) bool) {
		if cfg.Enabled {
			yield(nil, errors.New("registry scanner is only supported on Windows"))
		}
	}
}
