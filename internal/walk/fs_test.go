package walk_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

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
