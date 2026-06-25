//go:build !windows

package registry_test

import (
	"context"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalk_NonWindows_enabled_returnsError(t *testing.T) {
	cfg := model.Registry{Enabled: true, Paths: []model.RegistryPath{{Hive: "HKLM", Key: `SOFTWARE`}}}
	seq := registry.Walk(context.Background(), nil, cfg)
	var errs []error
	seq(func(_ model.Entry, err error) bool {
		if err != nil {
			errs = append(errs, err)
		}
		return true
	})
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "only supported on Windows")
}

func TestWalk_NonWindows_disabled_silent(t *testing.T) {
	cfg := model.Registry{Enabled: false}
	seq := registry.Walk(context.Background(), nil, cfg)
	var count int
	seq(func(_ model.Entry, err error) bool {
		count++
		return true
	})
	assert.Zero(t, count)
}
