package flowstore

import "time"

// Store is the narrow seam the admin flow view codes against, so the bounded
// in-memory ring and an opt-in persistent backend are interchangeable (#294).
//
// It is deliberately the SMALLEST set of methods production actually calls.
// Recent and RecentRange are absent on purpose: RecentPage is documented as
// their superset and is what the handlers use, so putting them here would
// oblige every backend to implement two read paths nothing reads.
//
// The package contract still binds every implementation:
//
//   - Record must not block, fail, or propagate an error. A persistent backend
//     satisfies this by enqueuing to a bounded buffer and returning; it must
//     never do disk I/O on the caller's goroutine. Overflow drops and counts,
//     exactly as an overflowing bucket folds into Other.
//   - Every dimension stays bounded. Memory bounds by per-bucket key caps;
//     a persistent backend bounds by retention sweep and a hard row cap.
//
// Close releases whatever the backend holds. Memory has nothing to release and
// returns nil, so the composition root can close unconditionally rather than
// type-switching on the backend it happens to have built.
type Store interface {
	Record(o Observation)
	RecordResult(o Observation) Admission
	Query(q Query) Result
	RecentPage(q RecentQuery) RecentPage
	Stats() Stats
	Limits() Limits
	Close() error
}

// Backend kinds reported by Stats. These are wire values on the versioned
// /api/flows.json contract and in the export provenance line, so they are
// renamed only with a contract version bump.
const (
	BackendMemory = "memory"
	BackendSQLite = "sqlite"
)

// Backend reports which store implementation served a request and whether it
// is healthy, for the admin status surface and the component-health verdict
// (#318).
//
// Everything past Kind and Healthy is optional and omitted by the memory ring,
// which has no path, no queue and no file. The persistent backend fills them
// so an operator can see the write-behind queue backing up or the database
// growing BEFORE it turns into dropped observations.
//
// flowstore remains an introspection model rather than a telemetry pipeline.
// The app layer may project selected bounded numeric fields into its established
// OTLP facade; paths, errors, and queue internals stay on the admin API only.
type Backend struct {
	// Kind is BackendMemory or BackendSQLite.
	Kind string `json:"kind"`
	// Path is the database file backing this store, when there is one.
	Path string `json:"path,omitempty"`
	// Healthy is false once the backend has failed in a way that means the
	// view is no longer trustworthy — a failed write drain, a failed migration.
	Healthy bool `json:"healthy"`
	// Error is the most recent failure, empty when Healthy.
	Error string `json:"error,omitempty"`
	// Queued is the number of observations waiting to be written.
	Queued int `json:"queued,omitempty"`
	// QueueDrops counts observations dropped because the write-behind queue was
	// full. Non-zero means the view is missing traffic that OTLP still carries.
	// Only a full-queue loss lands here: a failed write is LostRows, never
	// folded into this counter.
	QueueDrops int64 `json:"queue_drops,omitempty"`
	// WrittenRows counts observations that reached a durable Commit, each
	// exactly once. Cumulative across restarts.
	WrittenRows int64 `json:"written_rows,omitempty"`
	// LostRows counts observations that were admitted into the bounded queue
	// but never reached a commit: the write retry budget was exhausted, the
	// error was unrecoverable, or the shutdown write budget ran out.
	// LostReason records the most recent cause. This is deliberately a
	// distinct counter from QueueDrops rather than a disguised queue drop.
	LostRows int64 `json:"lost_rows,omitempty"`
	// LostReason is the most recent LostRows cause, empty when no write loss.
	LostReason string `json:"lost_reason,omitempty"`
	// ShutdownDrops counts observations that reached Record after Close began,
	// at or after the shutdown linearization boundary. They never enter a
	// batch and are counted consistently rather than left unconsumed.
	ShutdownDrops int64 `json:"shutdown_drops,omitempty"`
	// WriteRetries counts additional write attempts after a transient failure
	// (database lock, timeout, interrupt).
	WriteRetries int64 `json:"write_retries,omitempty"`
	// LastSuccessAt is the time of the most recent durable batch commit.
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	// PreviousRun summarizes the process that last opened the database,
	// carried by the persisted writer manifest. Present when a manifest
	// existed at Open, so a restart can explain the prior success, declared
	// losses and any interrupted shutdown.
	PreviousRun *PreviousRun `json:"previous_run,omitempty"`
	// Rows is the number of connections currently retained on disk.
	Rows int64 `json:"rows,omitempty"`
	// SizeBytes is the on-disk size of the database.
	SizeBytes int64 `json:"size_bytes,omitempty"`
	// JournalSizeBytes is the on-disk size of the SQLite write-ahead journal,
	// when this backend uses one. It is zero for the memory backend and when
	// the WAL sidecar does not currently exist.
	JournalSizeBytes int64 `json:"journal_size_bytes,omitempty"`
	// LastCheckpointAt is when the backend last successfully checkpointed its
	// SQLite write-ahead journal. It is zero before the first checkpoint.
	LastCheckpointAt time.Time `json:"last_checkpoint_at,omitempty"`
}

// Memory satisfies Store. A compile-time assertion rather than a runtime one:
// the composition root selects a backend by config, and a missing method should
// fail the build, not the first request to /flows.
var _ Store = (*Memory)(nil)

// PreviousRun summarizes the prior process recorded in the persisted writer
// manifest, read once when a persistent store opens. It is how a restart
// accounts for the previous run: a clean close, declared write losses and an
// interrupted (killed before close) run are distinguishable rather than all
// reading as an ordinary startup.
type PreviousRun struct {
	// State is PreviousRunClean or PreviousRunInterrupted.
	State string `json:"state"`
	// OpenedAt/ClosedAt bracket the previous process. ClosedAt is zero for an
	// interrupted run.
	OpenedAt time.Time `json:"opened_at,omitempty"`
	ClosedAt time.Time `json:"closed_at,omitempty"`
	// Counters carries the previous run's final cumulative counters.
	Counters PreviousRunCounters `json:"counters"`
	// LastSuccessAt is the previous run's last durable commit.
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	// LastLostReason is the previous run's last declared write-loss cause.
	LastLostReason string `json:"last_lost_reason,omitempty"`
	// Unresolved counts admitted observations the manifest knew about but
	// which have neither a commit nor a declared loss — only possible for an
	// interrupted run, bounded structurally by the queue and batch sizes.
	Unresolved int64 `json:"unresolved,omitempty"`
}

// PreviousRunCounters is the final counter snapshot of the previous process.
type PreviousRunCounters struct {
	Admitted      int64 `json:"admitted"`
	Committed     int64 `json:"committed"`
	LostRows       int64 `json:"lost_rows"`
	QueueDrops     int64 `json:"queue_drops"`
	ShutdownDrops  int64 `json:"shutdown_drops"`
}

const (
	// PreviousRunClean means the prior process closed its store after a full
	// drain: its counter totals reconcile with what is on disk.
	PreviousRunClean = "clean"
	// PreviousRunInterrupted means the prior process ended before Close could
	// drain and account for its in-memory batch.
	PreviousRunInterrupted = "interrupted"
)

// Close implements Store. The in-memory ring owns no file handle, goroutine or
// connection, so there is nothing to release and nothing that can fail — it is
// reclaimed with the process. It exists so callers need not know which backend
// they hold.
func (m *Memory) Close() error { return nil }
