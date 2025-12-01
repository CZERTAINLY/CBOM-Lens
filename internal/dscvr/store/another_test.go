package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr/store"

	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.InitDB(context.Background(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	return db
}

func TestTwoInitDB(t *testing.T) {
	tests := []struct {
		name    string
		dbPath  string
		wantErr bool
	}{
		{
			name:    "in-memory database",
			dbPath:  ":memory:",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := store.InitDB(context.Background(), tt.dbPath)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, db)
			require.NoError(t, db.Close())
		})
	}
}

func TestTwoStart(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*sql.DB)
		uuid    string
		wantErr error
	}{
		{
			name:    "new discovery",
			setup:   func(db *sql.DB) {},
			uuid:    "test-uuid-1",
			wantErr: nil,
		},
		{
			name: "discovery already in progress",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-2")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-2",
			wantErr: nil,
		},
		{
			name: "discovery already finished",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-3")
				require.NoError(t, err)
				err = store.FinishOK(context.Background(), db, "test-uuid-3", "upload-key")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-3",
			wantErr: store.ErrAlreadyFinished,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			tt.setup(db)

			err := store.Start(context.Background(), db, tt.uuid)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTwoGet(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*sql.DB)
		uuid     string
		wantErr  error
		validate func(*testing.T, store.DiscoveryRow)
	}{
		{
			name:    "discovery not found",
			setup:   func(db *sql.DB) {},
			uuid:    "non-existent",
			wantErr: store.ErrNotFound,
		},
		{
			name: "discovery in progress",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-1")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-1",
			wantErr: nil,
			validate: func(t *testing.T, d store.DiscoveryRow) {
				require.Equal(t, "test-uuid-1", d.UUID)
				require.True(t, d.InProgress)
				require.Nil(t, d.Success)
				require.Nil(t, d.UploadKey)
				require.Nil(t, d.FailureReason)
			},
		},
		{
			name: "discovery finished successfully",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-2")
				require.NoError(t, err)
				err = store.FinishOK(context.Background(), db, "test-uuid-2", "upload-key-123")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-2",
			wantErr: nil,
			validate: func(t *testing.T, d store.DiscoveryRow) {
				require.Equal(t, "test-uuid-2", d.UUID)
				require.False(t, d.InProgress)
				require.NotNil(t, d.Success)
				require.True(t, *d.Success)
				require.NotNil(t, d.UploadKey)
				require.Equal(t, "upload-key-123", *d.UploadKey)
				require.Nil(t, d.FailureReason)
			},
		},
		{
			name: "discovery finished with error",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-3")
				require.NoError(t, err)
				err = store.FinishErr(context.Background(), db, "test-uuid-3", "some error")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-3",
			wantErr: nil,
			validate: func(t *testing.T, d store.DiscoveryRow) {
				require.Equal(t, "test-uuid-3", d.UUID)
				require.False(t, d.InProgress)
				require.NotNil(t, d.Success)
				require.False(t, *d.Success)
				require.Nil(t, d.UploadKey)
				require.NotNil(t, d.FailureReason)
				require.Equal(t, "some error", *d.FailureReason)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			tt.setup(db)

			result, err := store.Get(context.Background(), db, tt.uuid)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

func TestTwoFinishOK(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*sql.DB)
		uuid      string
		uploadKey string
		wantErr   error
	}{
		{
			name:      "discovery not found",
			setup:     func(db *sql.DB) {},
			uuid:      "non-existent",
			uploadKey: "key",
			wantErr:   store.ErrNotFound,
		},
		{
			name: "success",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-1")
				require.NoError(t, err)
			},
			uuid:      "test-uuid-1",
			uploadKey: "upload-key-123",
			wantErr:   nil,
		},
		{
			name: "already finished",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-2")
				require.NoError(t, err)
				err = store.FinishOK(context.Background(), db, "test-uuid-2", "key")
				require.NoError(t, err)
			},
			uuid:      "test-uuid-2",
			uploadKey: "another-key",
			wantErr:   store.ErrAlreadyFinished,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			tt.setup(db)

			err := store.FinishOK(context.Background(), db, tt.uuid, tt.uploadKey)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)

				// Verify the state
				result, err := store.Get(context.Background(), db, tt.uuid)
				require.NoError(t, err)
				require.False(t, result.InProgress)
				require.NotNil(t, result.Success)
				require.True(t, *result.Success)
				require.NotNil(t, result.UploadKey)
				require.Equal(t, tt.uploadKey, *result.UploadKey)
			}
		})
	}
}

func TestTwoFinishErr(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*sql.DB)
		uuid    string
		reason  string
		wantErr error
	}{
		{
			name:    "discovery not found",
			setup:   func(db *sql.DB) {},
			uuid:    "non-existent",
			reason:  "error",
			wantErr: store.ErrNotFound,
		},
		{
			name: "success",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-1")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-1",
			reason:  "timeout occurred",
			wantErr: nil,
		},
		{
			name: "already finished",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-2")
				require.NoError(t, err)
				err = store.FinishErr(context.Background(), db, "test-uuid-2", "error")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-2",
			reason:  "another error",
			wantErr: store.ErrAlreadyFinished,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			tt.setup(db)

			err := store.FinishErr(context.Background(), db, tt.uuid, tt.reason)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)

				// Verify the state
				result, err := store.Get(context.Background(), db, tt.uuid)
				require.NoError(t, err)
				require.False(t, result.InProgress)
				require.NotNil(t, result.Success)
				require.False(t, *result.Success)
				require.NotNil(t, result.FailureReason)
				require.Equal(t, tt.reason, *result.FailureReason)
			}
		})
	}
}

func TestTwoDelete(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*sql.DB)
		uuid    string
		wantErr error
	}{
		{
			name:    "discovery not found",
			setup:   func(db *sql.DB) {},
			uuid:    "non-existent",
			wantErr: store.ErrNotFound,
		},
		{
			name: "delete existing discovery",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-1")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-1",
			wantErr: nil,
		},
		{
			name: "delete finished discovery",
			setup: func(db *sql.DB) {
				err := store.Start(context.Background(), db, "test-uuid-2")
				require.NoError(t, err)
				err = store.FinishOK(context.Background(), db, "test-uuid-2", "key")
				require.NoError(t, err)
			},
			uuid:    "test-uuid-2",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			tt.setup(db)

			err := store.Delete(context.Background(), db, tt.uuid)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)

				// Verify it's actually deleted
				_, err := store.Get(context.Background(), db, tt.uuid)
				require.ErrorIs(t, err, store.ErrNotFound)
			}
		})
	}
}

func TestDiscoveryRow_String(t *testing.T) {
	trueVal := true
	falseVal := false
	uploadKey := "test-key"
	failureReason := "test-reason"

	tests := []struct {
		name     string
		row      store.DiscoveryRow
		expected string
	}{
		{
			name: "all fields nil",
			row: store.DiscoveryRow{
				Discovery: store.Discovery{
					UUID:       "test-uuid",
					InProgress: true,
				},
			},
			expected: `uuid: "test-uuid", in_progress: true, success: nil, upload_key: nil, failure_reason: nil`,
		},
		{
			name: "success true with upload key",
			row: store.DiscoveryRow{
				Discovery: store.Discovery{
					UUID:       "test-uuid",
					InProgress: false,
					Success:    &trueVal,
					UploadKey:  &uploadKey,
				},
			},
			expected: `uuid: "test-uuid", in_progress: false, success: true, upload_key: "test-key", failure_reason: nil`,
		},
		{
			name: "success false with failure reason",
			row: store.DiscoveryRow{
				Discovery: store.Discovery{
					UUID:          "test-uuid",
					InProgress:    false,
					Success:       &falseVal,
					FailureReason: &failureReason,
				},
			},
			expected: `uuid: "test-uuid", in_progress: false, success: false, upload_key: nil, failure_reason: "test-reason"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.row.String()
			require.Equal(t, tt.expected, result)
		})
	}
}
