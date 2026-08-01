package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/dockertest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/stats"

	"github.com/stretchr/testify/require"
)

// TestLensDo_BrokenContainerSourceIsReported drives a container host that
// cannot be listed through the whole pipeline — walk.Images, parallel.Map and
// goScan — and asserts the failure is visible to an operator afterwards: as a
// warning in the log and as cbom_lens_sources_errors in the emitted BOM.
// Before the fix the run was indistinguishable from a healthy scan of a host
// with no images.
func TestLensDo_BrokenContainerSourceIsReported(t *testing.T) {
	daemon := dockertest.New(t, dockertest.WithImages(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "image list failed", http.StatusInternalServerError)
	}))

	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	cfg := model.Scan{
		Filesystem: model.Filesystem{Enabled: false},
		Containers: model.Containers{
			Enabled: true,
			Config: model.ContainersConfig{{
				Name: "broken",
				Type: model.ContainerTypeDocker,
				Host: daemon.Host,
			}},
		},
		Ports: model.Ports{Enabled: false},
		CBOM:  model.CBOM{Version: "1.6"},
	}

	counter := stats.New("cbom_lens")
	lens, err := NewLens(t.Context(), counter, cfg)
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, lens.Do(t.Context(), &out))

	var doc struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
		Components []json.RawMessage `json:"components"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))

	props := make(map[string]string, len(doc.Metadata.Properties))
	for _, p := range doc.Metadata.Properties {
		props[p.Name] = p.Value
	}
	require.Equal(t, "1", props["cbom_lens_sources_total"], "properties: %v", props)
	require.Equal(t, "1", props["cbom_lens_sources_errors"],
		"a container host that cannot be listed must be reported in the BOM: %v", props)
	require.Empty(t, doc.Components, "the broken source cannot contribute components")

	require.Contains(t, logBuf.String(), "can't list images on container host",
		"the failure must also be visible in the log at warn level")
}
