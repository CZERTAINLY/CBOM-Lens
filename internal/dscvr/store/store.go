package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrAlreadyFinished = errors.New("already finished")
)

type Discovery struct {
	UUID          string
	InProgress    bool
	Success       *bool
	UploadKey     *string
	FailureReason *string
}

type DiscoveryRow struct {
	Discovery
	ID int
}

func (d DiscoveryRow) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("uuid: %q, in_progress: %t", d.UUID, d.InProgress))
	if d.Success != nil {
		sb.WriteString(fmt.Sprintf(", success: %t", *d.Success))
	} else {
		sb.WriteString(", success: nil")
	}
	if d.UploadKey != nil {
		sb.WriteString(fmt.Sprintf(", upload_key: %q", *d.UploadKey))
	} else {
		sb.WriteString(", upload_key: nil")
	}
	if d.FailureReason != nil {
		sb.WriteString(fmt.Sprintf(", failure_reason: %q", *d.FailureReason))
	} else {
		sb.WriteString(", failure_reason: nil")
	}
	return sb.String()
}

func InitDB(ctx context.Context, dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS discoveries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL UNIQUE,
			in_progress BOOLEAN NOT NULL,
			success BOOLEAN DEFAULT NULL,
			upload_key TEXT DEFAULT NULL,
			failure_reason TEXT DEFAULT NULL
		)`,
	)
	if err != nil {
		return nil, err
	}
	return db, nil
}

type TxCallback = func(ctx context.Context, tx *sql.Tx) error

func Tx(ctx context.Context, db *sql.DB, fn TxCallback) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("Calling `tx.Rollback()` failed.", slog.String("err", err.Error()))
		}
	}()

	if err := fn(ctx, tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction failed: %w", err)
	}

	return nil
}

// Start persists, on success, information that a discovery identified by 'uuid' is in progress.
// If discovery identified by `uuid` is still in progress, no error is returned,
// if it has already finished ErrAlreadyFinished is returned.
func Start(ctx context.Context, db *sql.DB, uuid string) error {
	return Tx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		var discoveryRow DiscoveryRow
		row := tx.QueryRowContext(ctx,
			`SELECT in_progress FROM discoveries WHERE uuid=?`, uuid,
		)
		err := row.Scan(&discoveryRow.InProgress)
		switch {
		case err == nil && discoveryRow.InProgress:
			return nil
		case err == nil && !discoveryRow.InProgress:
			return ErrAlreadyFinished
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("executing sql query failed: %w", err)
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO discoveries (uuid, in_progress) VALUES (?,?);`, uuid, true,
		)
		if err != nil {
			return fmt.Errorf("executing sql insert failed: %w", err)
		}

		return nil
	})
}

// Get returns info about a discovery identified by 'uuid' on success,
// ErrNotFound when discovery identified by 'uuid' does not exist,
// error otherwise.
func Get(ctx context.Context, db *sql.DB, uuid string) (DiscoveryRow, error) {
	var discoveryRow DiscoveryRow
	txErr := Tx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT * FROM discoveries WHERE uuid=?`, uuid,
		)
		err := row.Scan(
			&discoveryRow.ID,
			&discoveryRow.UUID,
			&discoveryRow.InProgress,
			&discoveryRow.Success,
			&discoveryRow.UploadKey,
			&discoveryRow.FailureReason,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("executing sql query failed: %w", err)
		}

		return nil
	})
	return discoveryRow, txErr
}

// FinishOK on success stores information that discovery, identified by 'uuid', has finished
// successfully and stores the uploadKey with it,
// if the discovery has already finished, ErrAlreadyFinished is returned,
// if the discovery doesn't exist, ErrNotFound is returned,
// error otherwise.
func FinishOK(ctx context.Context, db *sql.DB, uuid, uploadKey string) error {
	return Tx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		if err := checkIsInProgress(ctx, tx, uuid); err != nil {
			return err
		}

		_, err := tx.ExecContext(ctx,
			`UPDATE discoveries
			 SET
				in_progress = false,
				success = true,
				upload_key = ?
			WHERE uuid = ?;
			`, uploadKey, uuid,
		)
		if err != nil {
			return fmt.Errorf("executing sql update failed: %w", err)
		}

		return nil
	})
}

// FinishErr stores information that discovery, identified by 'uuid', has failed
// and stores the failure reason with it,
// if the discovery has already finished, ErrAlreadyFinished is returned,
// if the discovery doesn't exist, ErrNotFound is returned,
// error otherwise.
func FinishErr(ctx context.Context, db *sql.DB, uuid, reason string) error {
	return Tx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		if err := checkIsInProgress(ctx, tx, uuid); err != nil {
			return err
		}

		_, err := tx.ExecContext(ctx,
			`UPDATE discoveries
			 SET
				in_progress = false,
				success = false,
				failure_reason = ?
			WHERE uuid = ?;
			`, reason, uuid,
		)
		if err != nil {
			return fmt.Errorf("executing sql update failed: %w", err)
		}

		return nil
	})
}

func checkIsInProgress(ctx context.Context, tx *sql.Tx, uuid string) error {
	var discoveryRow DiscoveryRow
	row := tx.QueryRowContext(ctx,
		`SELECT in_progress FROM discoveries WHERE uuid=?`, uuid,
	)
	err := row.Scan(&discoveryRow.InProgress)
	switch {
	case err == nil && !discoveryRow.InProgress:
		return ErrAlreadyFinished
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("executing sql query failed: %w", err)
	}
	return nil
}

// Delete deletes discovery identified by 'uuid' on success,
// ErrNotFound when discovery identified by 'uuid' does not exist,
// error otherwise.
func Delete(ctx context.Context, db *sql.DB, uuid string) error {
	return Tx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx,
			`DELETE FROM discoveries WHERE uuid=?`, uuid,
		)
		if err != nil {
			return fmt.Errorf("executing sql delete failed: %w", err)
		}

		ra, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("fetching affected rows failed: %w", err)
		}
		if ra != 1 {
			return ErrNotFound
		}

		return nil
	})
}
