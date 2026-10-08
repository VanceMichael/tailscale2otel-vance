package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// manifestKey is the metadata row holding the writer manifest. It lives in the
// same metadata table the tailnet identity uses, so no second table is needed
// and no migration is implied.
const manifestKey = "writer.manifest"

// manifestSchema is the version of the manifest shape below. A future
// incompatible change bumps this and upgrades on load; reading an unknown
// shape is refused rather than silently mis-accounting.
const manifestSchema = 1

const (
	runStateOpen   = "open"
	runStateClosed = "closed"
)

// storedCounters is the cumulative counter snapshot carried by the manifest.
// Every value is cumulative across the whole life of the database, so a
// restart continues the totals rather than restarting them.
type storedCounters struct {
	Admitted      int64 `json:"admitted"`
	Committed     int64 `json:"committed"`
	WriteLost     int64 `json:"write_lost"`
	QueueDrops    int64 `json:"queue_drops"`
	ShutdownDrops int64 `json:"shutdown_drops"`
	Retries       int64 `json:"retries"`
}

// writerManifest is the persisted write-lifecycle record.
//
// It is written at three points: immediately at Open (run_state=open), inside
// the same transaction as every committed batch, and at Close after the final
// drain (run_state=closed). That order is what lets the next Open explain the
// previous run: a closed manifest with reconciled counters, a closed manifest
// carrying declared losses, or an open manifest left by a killed process.
//
// Timestamps are *time.Time so a missing one is omitted as null/absent rather
// than rendered as the Go zero time.
type writerManifest struct {
	Schema           int            `json:"schema"`
	RunState         string         `json:"run_state"`
	OpenedAt         *time.Time     `json:"opened_at,omitempty"`
	ClosedAt         *time.Time     `json:"closed_at,omitempty"`
	Counters         storedCounters `json:"counters"`
	LastSuccessAt    *time.Time     `json:"last_success_at,omitempty"`
	LastLostAt       *time.Time     `json:"last_lost_at,omitempty"`
	LastLostReason   string         `json:"last_lost_reason,omitempty"`
	LastCheckpointAt *time.Time     `json:"last_checkpoint_at,omitempty"`
}

// loadManifest reads the persisted manifest. A missing row returns (nil, nil):
// a brand-new database has nothing to explain yet.
func loadManifest(ctx context.Context, db *sql.DB) (*writerManifest, error) {
	var raw string
	switch err := db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = ?", manifestKey).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("sqlitestore: read writer manifest: %w", err)
	}

	var m writerManifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("sqlitestore: decode writer manifest: %w", err)
	}
	if m.Schema != manifestSchema {
		return nil, fmt.Errorf("sqlitestore: writer manifest schema = %d, this build understands %d", m.Schema, manifestSchema)
	}
	return &m, nil
}

// upsertManifestSQL stores the manifest as a single key/value row. The key is a
// package constant and the value is bound JSON, never interpolated.
var upsertManifestSQL = `INSERT INTO metadata(key, value) VALUES(?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value`

// persistManifest writes m, bound as JSON. Callers own the context budget and
// decide whether a failure is fatal or best-effort.
func persistManifest(ctx context.Context, db *sql.DB, m *writerManifest) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("sqlitestore: encode writer manifest: %w", err)
	}
	if _, err := db.ExecContext(ctx, upsertManifestSQL, manifestKey, string(raw)); err != nil {
		return fmt.Errorf("sqlitestore: persist writer manifest: %w", err)
	}
	return nil
}
