package walk_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
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
	for entry, err := range walk.Images(t.Context(), []model.ContainerConfig{config}) {
		require.Nil(t, entry)
		require.Error(t, err)
		idx++
	}
	require.Equal(t, 1, idx)
}
