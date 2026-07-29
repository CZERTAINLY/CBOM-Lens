package model_test

import (
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

// fakeDockerDaemon starts a minimal Docker Engine API server on a unix
// socket that answers the version-negotiation ping. Returns the socket path.
func fakeDockerDaemon(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets required")
	}
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("Api-Version", "1.51")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestDefaultConfig_ProbesDockerHost(t *testing.T) {
	sock := fakeDockerDaemon(t)
	t.Setenv("DOCKER_HOST", "unix://"+sock)

	cfg := model.DefaultConfig(t.Context())

	require.True(t, cfg.Containers.Enabled)
	// containment, not equality: machines with a real docker/podman
	// socket contribute additional entries
	require.Contains(t, cfg.Containers.Config, model.ContainerConfig{
		Name:   "docker",
		Type:   "docker",
		Host:   "unix://" + sock,
		Images: []string{},
	})
}
