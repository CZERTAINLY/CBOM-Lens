package walk_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk"
	"github.com/stretchr/testify/require"
)

func TestFS_NilRoot(t *testing.T) {
	t.Parallel()
	counter := stats.New(t.Name())
	seq := walk.FS(t.Context(), counter, nil, "fstest://")
	// When root is nil, FS should return a nil iterator and not panic.
	require.Nil(t, any(seq))
	for _, value := range counter.Stats() {
		require.Equal(t, "0", value)
	}
}

func TestFS_CanceledContext(t *testing.T) {
	t.Parallel()
	root := fstest.MapFS{
		"a.txt":   &fstest.MapFile{Data: []byte("a"), Mode: 0o644},
		"b":       &fstest.MapFile{Mode: fs.ModeDir | 0o755},
		"b/b.txt": &fstest.MapFile{Data: []byte("bb"), Mode: 0o644},
	}
	ctx, cancel := context.WithCancel(t.Context())
	// cancel before iteration starts to exercise ctx.Err() early return path
	cancel()

	counter := stats.New(t.Name())
	seq := walk.FS(ctx, counter, root, "fstest://")
	require.NotNil(t, seq)
	count := 0
	for range seq {
		count++
	}
	require.Equal(t, 0, count, "no entries should be yielded when context is canceled")
	for _, value := range counter.Stats() {
		require.Equal(t, "0", value)
	}
}

func TestFstest(t *testing.T) {
	t.Parallel()
	root := fstest.MapFS{
		"a": &fstest.MapFile{
			Data:    []byte("aaa"),
			Mode:    0644,
			ModTime: time.Now(),
		},
		"b": &fstest.MapFile{
			Mode:    0755 | fs.ModeDir,
			ModTime: time.Now(),
		},
		"b/b.txt": &fstest.MapFile{
			Data:    []byte("bbbbbb"),
			Mode:    0644,
			ModTime: time.Now(),
		},
		"b/foo.sock": &fstest.MapFile{
			Mode:    0644 | fs.ModeSocket,
			ModTime: time.Now(),
		},
	}

	actual := make([]then, 0, 2)
	counter := stats.New(t.Name())
	for entry, err := range walk.FS(t.Context(), counter, root, "fstest://") {
		actual = append(actual, testEntry(t, entry, err))
	}

	require.Len(t, actual, 2)
	require.ElementsMatch(t,
		[]then{
			{path: filepath.Join("fstest://", "a"), size: 3},
			{path: filepath.Join("fstest://", "b/b.txt"), size: 6},
		},
		actual,
	)

	// three files examined (directory does not count)
	// one - the socket type - is excluded
	for key, value := range counter.Stats() {
		var exp = "0"
		switch {
		case strings.HasSuffix(key, "files_excluded"):
			exp = "1"
		case strings.HasSuffix(key, "files_total"):
			exp = "3"
		}
		require.Equal(t, exp, value, key)
	}
}
