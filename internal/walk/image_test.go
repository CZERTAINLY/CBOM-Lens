package walk_test

import (
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk"

	"github.com/stretchr/testify/require"
)

func TestWrongHost(t *testing.T) {
	config := model.ContainerConfig{
		Name: t.Name(),
		Type: "docker",
		// no unix:// prefix, but this won't be a valid path anyway
		Host:   "#!var/run/not-a-docker.sock",
		Images: nil,
	}

	// the goal of this test is to not segfault😃
	idx := 0
	counter := stats.New(t.Name())
	for entry, err := range walk.Images(t.Context(), counter, []model.ContainerConfig{config}) {
		require.Nil(t, entry)
		require.Error(t, err)
		idx++
	}
	require.Equal(t, 1, idx)
	for key, value := range counter.Stats() {
		var exp = "0"
		switch {
		case strings.HasSuffix(key, model.StatsSourcesTotal):
			exp = "1"
		case strings.HasSuffix(key, model.StatsSourcesSkipped):
			exp = "1"
		}
		require.Equal(t, exp, value)
	}
}
