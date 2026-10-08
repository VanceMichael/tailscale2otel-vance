package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rknightion/tailscale2otel/v5/internal/flowstore"
)

// RecordResult implements flowstore.Store. It honors the package's hard
// contract — never blocks, never does I/O, never returns an error to the
// caller beyond the Admission verdict — by admitting synchronously and then
// handing the (possibly redacted) observation to the write-behind queue with
// a non-blocking send. A full queue drops and counts, exactly as an
// overflowing bucket in the memory store folds into Other.
func (s *Store) RecordResult(o flowstore.Observation) flowstore.Admission {
	adm := s.admit(&o)
	if adm != flowstore.AdmissionAccepted {
		return adm
	}

	// PII must never reach disk if the configured policy would strip it from
	// telemetry — see Options.Redact's doc comment. This runs before the
	// observation is even offered to the queue.
	if s.opts.Redact != nil {
		s.opts.Redact(&o)
	}
	o = flowstore.NormalizeObservationForRetention(o)

	// Shutdown gate. The closed check and the producer registration are one
	// atomic step with Close, so every observation is either admitted BEFORE
	// the linearization boundary — its producer is counted in inflight and
	// Close waits before the final drain — or is counted, once, as a shutdown
	// drop. Nothing can be sent into the channel after the writer's final
	// drain.
	s.gateMu.Lock()
	if s.closed {
		s.gateMu.Unlock()
		s.mu.Lock()
		s.shutdownDrops++
		s.mu.Unlock()
		return adm
	}
	s.inflight.Add(1)
	s.gateMu.Unlock()
	defer s.inflight.Done()

	select {
	case s.queue <- o:
		s.mu.Lock()
		s.admitted++
		s.mu.Unlock()
	default:
		s.mu.Lock()
		s.queueDrops++
		s.mu.Unlock()
	}
	return adm
}

// insertSQL is built once from the package's column constants. As in the old
// flush, every observation value is bound as a parameter; only this package's
// own column list and matching "?" placeholders are interpolated.
//
//nolint:gosec // G201: column list is a package constant, values are bound parameters
var insertSQL = fmt.Sprintf(
	"INSERT INTO flows (%s) VALUES (%s)",
	strings.Join(columns, ", "), strings.Join(questionMarks(len(columns)), ", "),
)

func questionMarks(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "?"
	}
	return out
}

// run is the single write-behind goroutine: it drains s.queue in batches,
// flushing on a full batch or a periodic tick, and runs the retention sweep on
// its own slower tick. A failed flush no longer discards its batch: writeBatch
// keeps the same observations, retries them with its bounded policy and only
// records a declared loss when a budget is exhausted or the error is
// unrecoverable.
func (s *Store) run() {
	defer s.wg.Done()

	flushTicker := time.NewTicker(s.opts.FlushInterval)
	defer flushTicker.Stop()
	sweepTicker := time.NewTicker(s.opts.SweepInterval)
	defer sweepTicker.Stop()
	// A zero incremental-vacuum interval is deliberately not a disabled mode:
	// it inherits the sweep cadence. Use the sweep case for that mode so one
	// tick performs delete, checkpoint and reclamation in that order. An
	// explicit interval gets its own ticker and still checkpoints after each
	// sweep, keeping journal growth observable even between vacuum ticks.
	var vacuumTicker *time.Ticker
	var vacuumC <-chan time.Time
	if s.opts.IncrementalVacuumInterval > 0 {
		vacuumTicker = time.NewTicker(s.opts.vacuumInterval())
		vacuumC = vacuumTicker.C
		defer vacuumTicker.Stop()
	}

	pending := make([]flowstore.Observation, 0, s.opts.BatchSize)

	for {
		select {
		case o := <-s.queue:
			pending = append(pending, o)
			if len(pending) >= s.opts.BatchSize {
				if retained := s.writeBatch(pending, false); retained {
					s.shutdownDrain(pending)
					return
				}
				pending = pending[:0]
			}
		case <-flushTicker.C:
			if retained := s.writeBatch(pending, false); retained {
				s.shutdownDrain(pending)
				return
			}
			pending = pending[:0]
		case <-sweepTicker.C:
			// Once shutdown has begun, spend the remaining budget on draining
			// accepted observations, not on maintenance.
			if s.closingBegun() {
				s.shutdownDrain(pending)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), s.opts.QueryTimeout)
			s.maintain(ctx, true, s.opts.IncrementalVacuumInterval <= 0)
			cancel()
		case <-vacuumC:
			if s.closingBegun() {
				s.shutdownDrain(pending)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), s.opts.QueryTimeout)
			s.maintain(ctx, false, true)
			cancel()
		case <-s.closing:
			s.shutdownDrain(pending)
			return
		}
	}
}

// closingBegun reports the shutdown boundary without blocking.
func (s *Store) closingBegun() bool {
	select {
	case <-s.closing:
		return true
	default:
		return false
	}
}

// shutdownDrain runs the ordered shutdown sequence:
//
//  1. Consume queued observations until Close signals finalDrain, which it
//     closes only after every producer that passed the gate has settled.
//  2. Drain whatever is already queued at that point — exhaustive, because no
//     producer can still be sending.
//  3. Make the final bounded write attempts against the shutdown deadline; a
//     batch still unwritten then is declared lost with a shutdown-budget
//     reason.
//  4. Persist the run_state=closed manifest so the next Open reconciles.
func (s *Store) shutdownDrain(pending []flowstore.Observation) {
	for {
		select {
		case o := <-s.queue:
			pending = append(pending, o)
		case <-s.finalDrain:
			for {
				select {
				case o := <-s.queue:
					pending = append(pending, o)
				default:
					if len(pending) > 0 {
						// writeBatch either commits the batch once or declares
						// its loss; it never returns retained here because the
						// retry waits are timer-only in shutdown mode.
						s.writeBatch(pending, true)
					}
					ctx, cancel := context.WithTimeout(context.Background(), s.opts.QueryTimeout)
					if err := s.persistSnapshot(ctx, runStateClosed); err != nil {
						s.fail(err)
					}
					cancel()
					return
				}
			}
		}
	}
}

// writeBatch drives one batch through the write-failure lifecycle.
//
// It returns true only when shutdown interrupted the retry backoff while
// running: the batch is RETAINED — untouched and uncounted — and the caller
// must hand it to shutdownDrain. Every other path accounts the batch exactly
// once: a successful commit increments committed by len(batch), or a declared
// loss increments writeLost by len(batch) with the cause.
//
// Retries are bounded two ways: while running, at most MaxWriteRetries
// additional attempts and no longer than MaxRetryElapsed; in shutdown, the
// ShutdownTimeout deadline is the bound. Backoff is deterministic exponential,
// capped, and is interrupted by the closing boundary except in shutdown mode.
func (s *Store) writeBatch(batch []flowstore.Observation, shutdown bool) bool {
	if len(batch) == 0 {
		return false
	}
	deadline := s.writeDeadline(shutdown)

	for {
		err := s.flushOnce(batch)
		if err == nil {
			s.afterCommit()
			return false
		}

		if !classifyWriteError(err) {
			s.declareLossWithCtx(shutdown, deadline, batch,
				fmt.Errorf("unrecoverable write error after %d attempt(s): %w", s.writeAttempt, err))
			return false
		}

		// The failure may clear on the next attempt. Decide whether another
		// attempt fits the bounded policy BEFORE counting it.
		now := s.opts.Now()
		d := s.retryBackoff(s.writeAttempt)
		if s.retriesExhausted(shutdown, now, deadline) || !now.Add(d).Before(deadline) {
			s.declareLossWithCtx(shutdown, deadline, batch,
				fmt.Errorf("%s after %d attempt(s): %w", giveUpReason(shutdown), s.writeAttempt, err))
			return false
		}

		s.mu.Lock()
		s.retries++
		s.mu.Unlock()

		if shutdown {
			sleepFor(d)
		} else if interrupted := s.waitRetry(d); interrupted {
			// closing became visible mid-backoff: stop normal retries. The
			// batch is retained and shutdownDrain retries it under the
			// shutdown budget.
			return true
		}
	}
}

func (s *Store) writeDeadline(shutdown bool) time.Time {
	if shutdown {
		return s.opts.Now().Add(s.opts.ShutdownTimeout)
	}
	return s.opts.Now().Add(s.opts.MaxRetryElapsed)
}

// retriesExhausted combines the attempt cap (running only; shutdown uses the
// deadline as its real bound, with a high safety cap) with the elapsed
// deadline.
func (s *Store) retriesExhausted(shutdown bool, now, deadline time.Time) bool {
	if !now.Before(deadline) {
		return true
	}
	if shutdown {
		return s.writeAttempt >= 1000
	}
	return s.writeAttempt > s.opts.MaxWriteRetries
}

// retryBackoff returns the wait after a failed attempt: Min*2^(attempt-1),
// capped at Max. Deterministic, no randomness, so behavior is reproducible.
func (s *Store) retryBackoff(attempt int) time.Duration {
	d := s.opts.RetryMinBackoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= s.opts.RetryMaxBackoff {
			return s.opts.RetryMaxBackoff
		}
	}
	if d > s.opts.RetryMaxBackoff {
		return s.opts.RetryMaxBackoff
	}
	return d
}

func giveUpReason(shutdown bool) string {
	if shutdown {
		return "shutdown write budget exhausted"
	}
	return "write retry budget exhausted"
}

// lossContext bounds the metadata write that records a declared loss.
func (s *Store) lossContext(shutdown bool, deadline time.Time) (context.Context, context.CancelFunc) {
	if shutdown {
		if remaining := deadline.Sub(s.opts.Now()); remaining > 0 {
			return context.WithTimeout(context.Background(), remaining)
		}
	}
	return s.queryCtx()
}

// waitRetry sleeps with one eye on the shutdown boundary, reporting whether
// closing interrupted the wait.
func (s *Store) waitRetry(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-s.closing:
		return true
	case <-timer.C:
		return false
	}
}

// sleepFor is an uninterruptible timer wait, used in shutdown where the
// closing channel is already closed and therefore unselectable.
func sleepFor(d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	<-timer.C
}

// flushOnce makes exactly one transactional write attempt. It does NOT record
// the failure: classification and loss declaration belong to writeBatch, so a
// transient failure leaves the batch untouched and retryable.
//
// The writer manifest is upserted inside the same transaction, after the row
// inserts, so persisted rows and counters always commit atomically.
func (s *Store) flushOnce(batch []flowstore.Observation) error {
	s.writeAttempt++
	if s.writeFault != nil {
		if err := s.writeFault(s.writeAttempt); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.QueryTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, o := range batch {
		if _, err := stmt.ExecContext(ctx,
			timeToDB(o.Time),
			o.TrafficType,
			o.Transport,
			o.SrcAddr,
			o.DstAddr,
			o.SrcNode,
			o.DstNode,
			o.DstPort,
			o.DstService,
			o.SrcUser,
			o.DstUser,
			o.SrcTags,
			o.DstTags,
			o.SrcOS,
			o.DstOS,
			o.ReporterNodeID,
			o.ReporterTrust,
			o.ReporterConsistency,
			o.Verdict,
			boolToDB(o.Reversed),
			o.Rule,
			o.PolicyVersion,
			o.Path,
			o.DERPRegion,
			o.Counts.TxBytes,
			o.Counts.RxBytes,
			o.Counts.TxPkts,
			o.Counts.RxPkts,
			o.Counts.Flows,
		); err != nil {
			return err
		}
	}

	// Advance the in-memory counters BEFORE Commit: once the committed rows
	// become visible to readers, the counters must already account for them.
	// The previous values are saved so any failure after this point restores
	// them; the transaction itself — rows and manifest row — rolls back
	// atomically.
	now := s.opts.Now().UTC()
	s.mu.Lock()
	prevCommitted := s.committed
	prevSuccess := s.lastSuccessAt
	prevWriteFailure := s.writeFailure
	s.committed += int64(len(batch))
	s.writeFailure = nil
	s.lastSuccessAt = now

	// The manifest row in the SAME transaction reflects the same post-commit
	// totals, so rows and counters are consistent when the next process opens
	// the file.
	m := s.buildManifestLocked(runStateOpen)
	s.mu.Unlock()

	raw, err := json.Marshal(m)
	if err != nil {
		s.restoreCommitCounters(prevCommitted, prevSuccess, prevWriteFailure)
		return fmt.Errorf("encode writer manifest: %w", err)
	}
	if _, err := tx.ExecContext(ctx, upsertManifestSQL, manifestKey, string(raw)); err != nil {
		s.restoreCommitCounters(prevCommitted, prevSuccess, prevWriteFailure)
		return err
	}

	if err := tx.Commit(); err != nil {
		s.restoreCommitCounters(prevCommitted, prevSuccess, prevWriteFailure)
		return err
	}

	s.mu.Lock()
	s.writeAttempt = 0
	s.mu.Unlock()
	return nil
}

// restoreCommitCounters undoes the pre-commit counter advance after a failed
// or abandoned commit attempt.
func (s *Store) restoreCommitCounters(committed int64, successAt time.Time, writeFailure error) {
	s.mu.Lock()
	s.committed = committed
	s.lastSuccessAt = successAt
	s.writeFailure = writeFailure
	s.mu.Unlock()
}

// afterCommit runs the post-commit maintenance: the passive checkpoint that
// keeps the WAL bounded (as before) and a manifest write carrying the
// checkpoint time. Counters themselves were advanced before Commit.
func (s *Store) afterCommit() {
	checkpointCtx, checkpointCancel := s.queryCtx()
	defer checkpointCancel()
	if err := s.checkpoint(checkpointCtx); err != nil {
		return
	}
	if err := s.persistSnapshot(checkpointCtx, runStateOpen); err != nil {
		s.fail(err)
	}
}

// declareLoss records observations that are genuinely not going to be written:
// writeLost advances by exactly the batch size, the cause is carried as the
// current write failure and persisted best-effort. It is never folded into
// QueueDrops.
func (s *Store) declareLoss(ctx context.Context, batch []flowstore.Observation, cause error) {
	now := s.opts.Now().UTC()
	s.mu.Lock()
	s.writeLost += int64(len(batch))
	s.writeFailure = cause
	s.lastLostAt = now
	s.lastLostReason = cause.Error()
	s.writeAttempt = 0
	s.mu.Unlock()

	if err := s.persistSnapshot(ctx, runStateOpen); err != nil {
		s.fail(err)
	}
}

// declareLossWithCtx pairs loss declaration with a bounded metadata context,
// derived from the shutdown deadline or the query timeout while running.
func (s *Store) declareLossWithCtx(shutdown bool, deadline time.Time, batch []flowstore.Observation, cause error) {
	ctx, cancel := s.lossContext(shutdown, deadline)
	defer cancel()
	s.declareLoss(ctx, batch, cause)
}

// persistSnapshot writes the current counters and lifecycle state to disk.
func (s *Store) persistSnapshot(ctx context.Context, runState string) error {
	s.mu.Lock()
	m := s.buildManifestLocked(runState)
	s.mu.Unlock()
	return persistManifest(ctx, s.db, m)
}

// buildManifestLocked assembles the manifest from the counters under mu. For a
// closed manifest it stamps ClosedAt from the configured clock.
func (s *Store) buildManifestLocked(runState string) *writerManifest {
	pointerTime := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		utc := t.UTC()
		return &utc
	}
	m := &writerManifest{
		Schema:   manifestSchema,
		RunState: runState,
		OpenedAt: pointerTime(s.openedAt),
		Counters: storedCounters{
			Admitted:      s.admitted,
			Committed:     s.committed,
			WriteLost:     s.writeLost,
			QueueDrops:    s.queueDrops,
			ShutdownDrops: s.shutdownDrops,
			Retries:       s.retries,
		},
		LastSuccessAt:    pointerTime(s.lastSuccessAt),
		LastLostAt:       pointerTime(s.lastLostAt),
		LastLostReason:   s.lastLostReason,
		LastCheckpointAt: pointerTime(s.lastCheckpointAt),
	}
	if runState == runStateClosed {
		closed := s.opts.Now().UTC()
		m.ClosedAt = &closed
	}
	return m
}

// maintain runs one bounded writer-maintenance pass. The sweep is optional
// because an explicit vacuum interval may fall between retention sweeps. A
// checkpoint precedes incremental_vacuum: SQLite can only reclaim pages that
// are no longer pinned by the WAL, and both operations are best-effort with
// failures recorded on the backend rather than sent to the caller.
func (s *Store) maintain(ctx context.Context, sweep, reclaim bool) {
	if sweep {
		_ = s.sweep(ctx)
	}
	if err := s.checkpoint(ctx); err == nil {
		if err := s.persistSnapshot(ctx, runStateOpen); err != nil {
			s.fail(err)
		}
	}
	if reclaim {
		_ = s.incrementalVacuum(ctx)
	}
}

// checkpoint records a successful passive WAL checkpoint. A busy result is
// expected when a reader is holding a snapshot; it is not a backend failure and
// the next flush or maintenance pass will retry it.
func (s *Store) checkpoint(ctx context.Context) error {
	var busy, logFrames, checkpointedFrames int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		s.fail(err)
		return err
	}
	if !checkpointCompleted(busy, logFrames, checkpointedFrames) {
		return nil
	}

	s.mu.Lock()
	s.lastCheckpointAt = s.opts.Now().UTC()
	s.mu.Unlock()
	return nil
}

func checkpointCompleted(busy, logFrames, checkpointedFrames int) bool {
	return busy == 0 && logFrames >= 0 && checkpointedFrames >= 0 && logFrames == checkpointedFrames
}

// incrementalVacuum reclaims at most the configured number of pages. The
// numeric pragma argument cannot be bound through database/sql, but it is an
// integer resolved from validated configuration, never request data.
func (s *Store) incrementalVacuum(ctx context.Context) error {
	pages := s.opts.IncrementalVacuumPages
	if pages <= 0 {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", pages)); err != nil { //nolint:gosec // G201: pages is an internal validated integer
		s.fail(err)
		return err
	}
	return nil
}

// sweep enforces both retention bounds: rows older than Retention are deleted
// first, then, independently, any excess over MaxRows is deleted oldest-first.
// The two are independent because MaxRows exists specifically to bound the
// disk even when a traffic flood would keep every row inside the retention
// window (see schema.go's migration comment on why seq is the stable
// oldest-first tiebreaker).
func (s *Store) sweep(ctx context.Context) error {
	cutoff := timeToDB(s.opts.Now().Add(-s.opts.Retention))
	if _, err := s.db.ExecContext(ctx, "DELETE FROM flows WHERE time < ?", cutoff); err != nil {
		s.fail(err)
		return err
	}

	if s.opts.MaxRows > 0 {
		var count int64
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM flows").Scan(&count); err != nil {
			s.fail(err)
			return err
		}
		if excess := count - s.opts.MaxRows; excess > 0 {
			if _, err := s.db.ExecContext(ctx,
				"DELETE FROM flows WHERE seq IN (SELECT seq FROM flows ORDER BY time ASC, seq ASC LIMIT ?)",
				excess,
			); err != nil {
				s.fail(err)
				return err
			}
		}
	}
	return nil
}

// Stats implements flowstore.Store. It must never panic: a read failure here
// degrades to an unhealthy Backend rather than propagating an error, because
// the admin status page must still render around a broken backend.
//
// Snapshot order matters and is deliberate: the on-disk row view is read
// FIRST, and counters are read AFTER. flushOnce advances the committed
// counter strictly before Commit makes rows visible, so a committed row count
// can never be paired with a stale counter; the reverse — counters a hair
// ahead of the row view — is bounded by one commit's duration and fails in
// the honest direction for the "are all accepted rows on disk" question.
func (s *Store) Stats() flowstore.Stats {
	var st flowstore.Stats
	var backend flowstore.Backend

	ctx, cancel := s.queryCtx()

	// readsOK tracks the on-disk read portion of the snapshot.
	readsOK := true
	var rows int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM flows").Scan(&rows); err != nil {
		readsOK = false
		backend.Error = err.Error()
	} else {
		backend.Rows = rows
	}

	var minTime, maxTime sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT MIN(time), MAX(time) FROM flows").Scan(&minTime, &maxTime); err != nil {
		readsOK = false
		if backend.Error == "" {
			backend.Error = err.Error()
		}
	} else {
		if minTime.Valid {
			st.Earliest = dbToTime(minTime.Int64)
		}
		if maxTime.Valid {
			st.Latest = dbToTime(maxTime.Int64)
		}
	}
	cancel()

	// Counters after the row view.
	s.mu.Lock()
	admittedN := s.admitted
	committedN := s.committed
	writeLostN := s.writeLost
	queueDropsN := s.queueDrops
	shutdownDropsN := s.shutdownDrops
	retriesN := s.retries
	failure := s.failure
	batchFailure := s.writeFailure
	lastSuccess := s.lastSuccessAt
	lostReason := s.lastLostReason
	lastCheckpoint := s.lastCheckpointAt
	previousRun := s.previousRun
	s.mu.Unlock()

	if failure != nil || batchFailure != nil || !readsOK {
		backend.Healthy = false
	} else {
		backend.Healthy = true
	}
	switch {
	case failure != nil:
		// A sticky failure takes precedence in the displayed error.
		backend.Error = failure.Error()
	case batchFailure != nil:
		backend.Error = batchFailure.Error()
	}

	backend.Kind = flowstore.BackendSQLite
	backend.Path = s.path
	backend.Queued = len(s.queue)
	backend.QueueDrops = queueDropsN
	backend.WrittenRows = committedN
	backend.LostRows = writeLostN
	backend.LostReason = lostReason
	backend.ShutdownDrops = shutdownDropsN
	backend.WriteRetries = retriesN
	backend.LastSuccessAt = lastSuccess
	backend.PreviousRun = previousRun
	backend.LastCheckpointAt = lastCheckpoint

	st.Observations = admittedN
	// Every unrecovered loss, with its nature broken out on Backend rather
	// than disguised as an ordinary queue drop.
	st.Truncated = queueDropsN + shutdownDropsN + writeLostN

	if fi, err := os.Stat(s.path); err == nil {
		backend.SizeBytes = fi.Size()
	}
	if fi, err := os.Stat(s.path + "-wal"); err == nil {
		backend.JournalSizeBytes = fi.Size()
	}

	st.Backend = backend
	return st
}
