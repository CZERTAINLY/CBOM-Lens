package walk_test

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

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
		case strings.HasSuffix(key, "sources_total"):
			exp = "1"
		case strings.HasSuffix(key, "sources_errors"):
			exp = "1"
		}
		require.Equal(t, exp, value)
	}
}

func TestImage(t *testing.T) {
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}

	tempdir := t.TempDir()
	root, err := os.OpenRoot(tempdir)
	require.NoError(t, err)

	err = root.Mkdir("a", 0o755)
	require.NoError(t, err)
	aTXT, err := root.Create("a/a.txt")
	require.NoError(t, err)
	_, err = aTXT.Write([]byte("hello a.txt\n"))
	require.NoError(t, err)
	err = root.Mkdir("a/b", 0o755)
	require.NoError(t, err)
	err = root.Mkdir("a/c", 0o755)
	require.NoError(t, err)
	xTXT, err := root.Create("a/c/c.txt")
	require.NoError(t, err)
	_, err = xTXT.Write([]byte("layer1\n"))
	require.NoError(t, err)

	// /a/c/c.txt has a different content in new layer
	// cbom-lens deals with squashed layers, because that's what is
	// visible when container is running
	dockerfile := []byte(`
FROM busybox:latest
COPY a/ /a/
# overwrite c/c.txt in a new layer
RUN echo "this is a new layer, longer content is 42" > /a/c/c.txt
`)
	f, err := root.Create("Dockerfile")
	require.NoError(t, err)
	t.Cleanup(func() {
		err = f.Close()
		require.NoError(t, err)
	})
	_, err = f.Write(dockerfile)
	require.NoError(t, err)
	err = f.Sync()
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    tempdir,
			Dockerfile: "Dockerfile",
		},
		WaitingFor: wait.ForExit(),
	}

	c, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	info, err := c.Inspect(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		err = c.Terminate(context.Background())
		require.NoError(t, err)
	})

	t.Run("walk.OneImage", func(t *testing.T) {
		config := model.ContainerConfig{
			Name: t.Name(),
			Type: model.ContainerTypeDocker,
			Host: host,
			Images: []string{
				info.Image,
			},
		}
		configs := model.ContainersConfig{config}

		actual := make([]then, 0, 10)
		counter := stats.New(t.Name())
		for entry, err := range walk.Images(t.Context(), counter, configs) {
			if strings.HasPrefix(entry.Path(), "/a") {
				actual = append(actual, testEntry(t, entry, err))
			}
		}

		require.Len(t, actual, 2)
		require.ElementsMatch(t,
			[]then{
				{path: "/a/a.txt", size: 12},
				{path: "/a/c/c.txt", size: 42}, // len of RUN echo command above
			},
			actual,
		)
		for key, value := range counter.Stats() {
			var exp = "0"
			switch {
			case strings.HasSuffix(key, "sources_total"):
				exp = "1"
			case strings.HasSuffix(key, "files_excluded") || strings.HasSuffix(key, "files_total"):
				require.NotEqual(t, "0", value)
				continue
			}
			require.Equal(t, exp, value, key)
		}
	})

	t.Run("walk.Images", func(t *testing.T) {
		if testing.Short() {
			t.Skipf("%s is skipped via -short", t.Name())
		}
		if testing.Verbose() {
			slog.SetDefault(log.New(true))
		}
		actual := make([]then, 0, 10)
		cfg := model.Containers{
			Enabled: true,
			Config: []model.ContainerConfig{
				{
					Host: host,
					Images: []string{
						info.Image,
					},
				},
			},
		}
		counter := stats.New(t.Name())
		for entry, err := range walk.Images(t.Context(), counter, cfg.Config) {
			if err != nil {
				t.Logf("err=%+v", err)
				continue
			}
			if strings.HasPrefix(entry.Path(), "/a") {
				actual = append(actual, testEntry(t, entry, err))
			}
		}

		require.GreaterOrEqual(t, len(actual), 2)
		require.Contains(t, actual, then{path: "/a/a.txt", size: 12})
		require.Contains(t, actual, then{path: "/a/c/c.txt", size: 42})

		// we can't test anything - this runs under all docker
		// images, so hard to say how this will ends
		stats := maps.Collect(counter.Stats())
		t.Logf("stats=%+v", stats)
	})
}

type then struct {
	path string
	size int64
	err  error
}

func testEntry(t *testing.T, entry model.Entry, err error) then {
	t.Helper()
	if err != nil {
		return then{
			path: entry.Path(),
			err:  err,
		}
	}

	f, openErr := entry.Open()
	require.NoError(t, openErr)
	var b []byte
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})
	b, err = io.ReadAll(f)
	require.NoError(t, err)

	info, err := entry.Stat()
	require.NoError(t, err)
	require.Equal(t, int64(len(b)), info.Size())

	return then{path: entry.Path(), size: int64(len(b))}
}
