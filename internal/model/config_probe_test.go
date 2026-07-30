package model_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/dockertest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfig_ProbesDockerHost(t *testing.T) {
	// a stub daemon answering the /_ping probe
	daemon := dockertest.New(t)
	t.Setenv("DOCKER_HOST", daemon.Host)

	cfg := model.DefaultConfig(t.Context())

	require.True(t, cfg.Containers.Enabled)
	// containment, not equality: machines with a real docker/podman
	// socket contribute additional entries
	require.Contains(t, cfg.Containers.Config, model.ContainerConfig{
		Name:   "docker",
		Type:   "docker",
		Host:   daemon.Host,
		Images: []string{},
	})
}
