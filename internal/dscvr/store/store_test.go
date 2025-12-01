package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr/store"

	"github.com/stretchr/testify/require"
)

const specialFilename = ":memory:"

func TestInitDB(t *testing.T) {
	t.Run("fail", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), "/non/existing/path")
		require.Error(t, err)
		require.Nil(t, db)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)
	})

	t.Run("fail exec context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		db, err := store.InitDB(ctx, specialFilename)
		require.Error(t, err)
		require.Nil(t, db)
		require.True(t, errors.Is(err, context.Canceled))
	})
}

func TestStart(t *testing.T) {
	t.Run("single start", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)
	})
	t.Run("return values", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		err = store.Start(context.Background(), db, "uuid-2")
		require.NoError(t, err)
		// if discovery already started, no error is returned
		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		err = store.Start(context.Background(), db, "uuid-2")
		require.NoError(t, err)
		// if it has already finished ...
		err = store.FinishOK(context.Background(), db, "uuid-1", "uuid-key-1")
		require.NoError(t, err)
		err = store.FinishErr(context.Background(), db, "uuid-2", "failure reason")
		require.NoError(t, err)
		// ...ErrAlreadyFinished is returned
		err = store.Start(context.Background(), db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrAlreadyFinished))
		err = store.Start(context.Background(), db, "uuid-2")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrAlreadyFinished))
	})
	t.Run("fail canceled context", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = store.Start(ctx, db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled))
	})
}

func TestGet(t *testing.T) {
	t.Run("test case #1", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		var dr store.DiscoveryRow
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))
		require.Equal(t, store.DiscoveryRow{}, dr)

		// start discovery `uuid-1`
		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		require.Equal(t, dr.UUID, "uuid-1")
		require.Equal(t, dr.InProgress, true)
		require.Nil(t, dr.Success)
		require.Nil(t, dr.UploadKey)
		require.Nil(t, dr.FailureReason)

		// conclude `uuid-1` as OK
		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.NoError(t, err)
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		require.Equal(t, dr.UUID, "uuid-1")
		require.Equal(t, dr.InProgress, false)
		require.Equal(t, *dr.Success, true)
		require.Equal(t, *dr.UploadKey, "upload-key-1")
		require.Nil(t, dr.FailureReason)

		// delete discovery "uuid-1"
		err = store.Delete(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))
		require.Equal(t, store.DiscoveryRow{}, dr)

		// start discovery `uuid-1`
		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		// conclude `uuid-1` as Failure
		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.NoError(t, err)
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		require.Equal(t, dr.UUID, "uuid-1")
		require.Equal(t, dr.InProgress, false)
		require.Equal(t, *dr.Success, false)
		require.Equal(t, *dr.FailureReason, "failure reason")
		require.Nil(t, dr.UploadKey)
	})
	t.Run("fail canceled context", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = store.Get(ctx, db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled))
	})
}

func TestFinish(t *testing.T) {
	t.Run("FinishOK", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.NoError(t, err)
		var dr store.DiscoveryRow
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		require.Equal(t, dr.UUID, "uuid-1")
		require.Equal(t, dr.InProgress, false)
		require.Equal(t, *dr.Success, true)
		require.Equal(t, *dr.UploadKey, "upload-key-1")
		require.Nil(t, dr.FailureReason)

		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrAlreadyFinished))

		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrAlreadyFinished))

		err = store.Delete(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))
	})

	t.Run("FinishErr", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.NoError(t, err)
		var dr store.DiscoveryRow
		dr, err = store.Get(context.Background(), db, "uuid-1")
		require.NoError(t, err)
		require.Equal(t, dr.UUID, "uuid-1")
		require.Equal(t, dr.InProgress, false)
		require.Equal(t, *dr.Success, false)
		require.Equal(t, *dr.FailureReason, "failure reason")
		require.Nil(t, dr.UploadKey)

		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrAlreadyFinished))

		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrAlreadyFinished))

		err = store.Delete(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))
	})
	t.Run("fail canceled context", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = store.FinishOK(ctx, db, "uuid-1", "upload-key-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled))

		err = store.FinishErr(ctx, db, "uuid-1", "failure reason")
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled))
	})
}

func TestDelete(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		err = store.Delete(context.Background(), db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.Delete(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.FinishOK(context.Background(), db, "uuid-1", "upload-key-1")
		require.NoError(t, err)

		err = store.Delete(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.Start(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.FinishErr(context.Background(), db, "uuid-1", "failure reason")
		require.NoError(t, err)

		err = store.Delete(context.Background(), db, "uuid-1")
		require.NoError(t, err)

		err = store.Delete(context.Background(), db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))
	})
	t.Run("fail canceled context", func(t *testing.T) {
		t.Parallel()
		db, err := store.InitDB(context.Background(), specialFilename)
		require.NoError(t, err)
		require.NotNil(t, db)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = store.Delete(ctx, db, "uuid-1")
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled))
	})

}
