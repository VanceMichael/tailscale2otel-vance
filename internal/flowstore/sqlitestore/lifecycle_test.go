package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/tailscale2otel/v5/internal/flowstore"
)

// waitForStats polls Stats until the predicate holds or timeout elapses.
func waitForStats(t *testing.T, s *Store, timeout time.Duration, pred func(flowstore.Stats) bool) flowstore.Stats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var st flowstore.Stats
	for {
		st = s.Stats()
		if pred(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for stats condition; last stats: %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func busyError() error { return errors.New("database is locked (5) (SQLITE_BUSY)") }
func ioErr() error    { return errors.New("disk I/O error (10) (SQLITE_IOERR)") }

// (1) A transient failure on the first attempt must keep the SAME batch and
// retry it; on commit the observations land once and once only.
func TestWriteBatch_TransientFailureRetriesSameBatchAndCommitsOnce(t *testing.T) {
	opts := testOpts(t)
	now := time.Now().UTC()
	opts.Now = func() time.Time { return now }
	s := openTestStore(t, opts)
	s.writeFault = func(attempt int) error {
		if attempt == 1 {
			return busyError()
		}
		return nil
	}

	const n = 8 // BatchSize
	for i := 0; i < n; i++ {
		if adm := s.RecordResult(obs(now.Add(time.Duration(i)))); adm != flowstore.AdmissionAccepted {
			t.Fatalf("observation %d admission = %v", i, adm)
		}
	}

	st := waitForStats(t, s, 2*time.Second, func(st flowstore.Stats) bool {
		return st.Backend.Rows >= n
	})

	if got := rowCount(t, s.db); got != n {
		t.Fatalf("row count = %d, want exactly %d (no double counting, no loss)", got, n)
	}
	if st.Backend.WrittenRows != n {
		t.Errorf("WrittenRows = %d, want %d", st.Backend.WrittenRows, n)
	}
	if st.Backend.LostRows != 0 {
		t.Errorf("LostRows = %d, want 0 (retry succeeded)", st.Backend.LostRows)
	}
	if st.Backend.WriteRetries < 1 {
		t.Errorf("WriteRetries = %d, want at least 1", st.Backend.WriteRetries)
	}
	if !st.Backend.Healthy {
		t.Errorf("Healthy = false, want true after recovery (err=%q)", st.Backend.Error)
	}
	if len(s.queue) != 0 {
		t.Errorf("queue len = %d, want 0 after commit", len(s.queue))
	}
}

// (2) An unrecoverable error is a declared loss: exact count and cause, never
// a queue drop.
func TestWriteBatch_UnrecoverableErrorDeclaresLossWithReason(t *testing.T) {
	opts := testOpts(t)
	now := time.Now().UTC()
	opts.Now = func() time.Time { return now }
	s := openTestStore(t, opts)
	s.writeFault = func(int) error { return ioErr() }

	const n = 8
	for i := 0; i < n; i++ {
		if adm := s.RecordResult(obs(now.Add(time.Duration(i)))); adm != flowstore.AdmissionAccepted {
			t.Fatalf("observation %d admission = %v", i, adm)
		}
	}

	st := waitForStats(t, s, 2*time.Second, func(st flowstore.Stats) bool {
		return st.Backend.LostRows >= n
	})

	if st.Backend.LostRows != n {
		t.Fatalf("LostRows = %d, want %d", st.Backend.LostRows, n)
	}
	if !strings.Contains(st.Backend.LostReason, "SQLITE_IOERR") ||
		!strings.Contains(st.Backend.LostReason, "unrecoverable write error") {
		t.Errorf("LostReason = %q, want the unrecoverable cause carried explicitly", st.Backend.LostReason)
	}
	if st.Backend.QueueDrops != 0 {
		t.Errorf("QueueDrops = %d, want 0: a failed write must not be disguised as a queue drop", st.Backend.QueueDrops)
	}
	if st.Backend.WrittenRows != 0 {
		t.Errorf("WrittenRows = %d, want 0", st.Backend.WrittenRows)
	}
	if st.Backend.Healthy {
		t.Error("Healthy = true, want false after a declared loss")
	}
	if got := rowCount(t, s.db); got != 0 {
		t.Errorf("row count = %d, want 0", got)
	}
}

// (3) Retry budget exhaustion while running is a declared loss with its
// reason, after the bounded number of attempts.
func TestWriteBatch_RetryBudgetExhaustionDeclaresLoss(t *testing.T) {
	opts := testOpts(t)
	opts.MaxWriteRetries = 2
	now := time.Now().UTC()
	opts.Now = func() time.Time { return now }
	s := openTestStore(t, opts)
	s.writeFault = func(int) error { return busyError() }

	const n = 8
	for i := 0; i < n; i++ {
		_ = s.RecordResult(obs(now.Add(time.Duration(i))))
	}

	st := waitForStats(t, s, 5*time.Second, func(st flowstore.Stats) bool {
		return st.Backend.LostRows >= n
	})

	if st.Backend.LostRows != n {
		t.Fatalf("LostRows = %d, want %d", st.Backend.LostRows, n)
	}
	if !strings.Contains(st.Backend.LostReason, "write retry budget exhausted") {
		t.Errorf("LostReason = %q, want retry-budget reason", st.Backend.LostReason)
	}
	if st.Backend.WriteRetries != 2 {
		t.Errorf("WriteRetries = %d, want exactly 2 additional attempts", st.Backend.WriteRetries)
	}
}

// (4) Shutdown linearization under concurrent producers: after Close, every
// observation is reconciled (committed or declared lost), the queue is empty,
// and the reopened database's rows equal the committed counter.
func TestClose_ConcurrentRecordsDrainedOrCounted(t *testing.T) {
	opts := testOpts(t)
	opts.QueueSize = 128
	base := time.Now().UTC()
	opts.Now = func() time.Time { return base }
	s := openTestStore(t, opts)

	const producers = 4
	const perProducer = 500
	var stop atomicFlag
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				if stop.get() {
					return
				}
				_ = s.RecordResult(obs(base.Add(time.Duration(p*perProducer+i) * time.Nanosecond)))
			}
		}(p)
	}

	// Let the queue build, then close while producers may still be active.
	time.Sleep(50 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stop.set(true)
	wg.Wait()

	if len(s.queue) != 0 {
		t.Fatalf("queue len after Close = %d, want 0 (no stranded batch)", len(s.queue))
	}

	// Reopen and reconcile the persisted manifest with the durable rows.
	s2, err := Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st := s2.Stats()
	defer func() { _ = s2.Close() }()

	c := st.PreviousRun.Counters
	if c.Admitted != c.Committed+c.LostRows {
		t.Errorf("reconciliation failed: admitted=%d committed=%d lost=%d (must balance, no unconsumed batch)",
			c.Admitted, c.Committed, c.LostRows)
	}
	if st.Backend.Rows != c.Committed {
		t.Errorf("rows on disk = %d, want committed counter %d", st.Backend.Rows, c.Committed)
	}
}

// (5) When the shutdown write budget is exhausted, the batch is declared lost
// with a shutdown-budget reason; the closed manifest carries it and the next
// Open explains the partial failure.
func TestClose_ShutdownBudgetLossPersistedAndExplained(t *testing.T) {
	opts := testOpts(t)
	opts.ShutdownTimeout = 100 * time.Millisecond
	opts.FlushInterval = time.Hour
	opts.BatchSize = 100
	now := time.Now().UTC()
	opts.Now = func() time.Time { return now }
	s := openTestStore(t, opts)
	s.writeFault = func(int) error { return busyError() }

	const n = 3
	for i := 0; i < n; i++ {
		_ = s.RecordResult(obs(now.Add(time.Duration(i))))
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()

	st := s2.Stats()
	if st.PreviousRun == nil || st.PreviousRun.State != flowstore.PreviousRunClean {
		t.Fatalf("PreviousRun = %+v, want a clean (fully accounted) close", st.PreviousRun)
	}
	c := st.PreviousRun.Counters
	if c.Admitted != n || c.LostRows != n || c.Committed != 0 {
		t.Errorf("counters = admitted %d committed %d lost %d, want admitted=lost=%d",
			c.Admitted, c.Committed, c.LostRows, n)
	}
	if !strings.Contains(st.PreviousRun.LastLostReason, "shutdown write budget exhausted") {
		t.Errorf("LastLostReason = %q, want shutdown-budget cause", st.PreviousRun.LastLostReason)
	}
	if st.Backend.Rows != 0 {
		t.Errorf("rows = %d, want 0", st.Backend.Rows)
	}
}

// (6) An interrupted run — an open manifest at Open — is explained: unresolved
// admitted observations counted, committed rows intact, health degraded.
func TestOpen_InterruptedRunIsExplained(t *testing.T) {
	opts := testOpts(t)
	opts.applyDefaults()
	path := opts.Dir + "/" + dbFileName(opts.Tailnet)

	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := ensureTailnetIdentity(ctx, db, opts.Tailnet, true); err != nil {
		t.Fatalf("identity: %v", err)
	}
	o := obs(time.Now().UTC())
	if _, err := db.ExecContext(ctx,
		"INSERT INTO flows (time, traffic_type, transport) VALUES (?, ?, ?)",
		timeToDB(o.Time), o.TrafficType, o.Transport); err != nil {
		t.Fatalf("insert flow: %v", err)
	}
	// Manifest as of the crash: two admitted, one committed, run never closed.
	m := writerManifest{
		Schema:   manifestSchema,
		RunState: runStateOpen,
		OpenedAt: timePtr(opts.Now().Add(-time.Hour)),
		Counters: storedCounters{Admitted: 2, Committed: 1},
		LastSuccessAt: timePtr(o.Time),
	}
	if err := persistManifest(ctx, db, &m); err != nil {
		t.Fatalf("persist manifest: %v", err)
	}
	cancel()
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	s, err := Open(opts)
	if err != nil {
		t.Fatalf("Open must succeed with committed rows intact: %v", err)
	}
	defer func() { _ = s.Close() }()

	st := s.Stats()
	if st.PreviousRun == nil || st.PreviousRun.State != flowstore.PreviousRunInterrupted {
		t.Fatalf("PreviousRun = %+v, want interrupted", st.PreviousRun)
	}
	if st.PreviousRun.Unresolved != 1 {
		t.Errorf("Unresolved = %d, want 1", st.PreviousRun.Unresolved)
	}
	if st.Backend.Rows != 1 {
		t.Errorf("Rows = %d, want the committed row intact", st.Backend.Rows)
	}
	if st.Backend.Healthy || !strings.Contains(st.Backend.Error, "without a clean close") {
		t.Errorf("Healthy=%v Error=%q, want degraded with the interrupted-run explanation",
			st.Backend.Healthy, st.Backend.Error)
	}
}

// (7) Clean restart continues cumulative counters, explaining prior success.
func TestReopen_CumulativeCountersContinue(t *testing.T) {
	opts := testOpts(t)
	now := time.Now().UTC()
	opts.Now = func() time.Time { return now }
	s := openTestStore(t, opts)

	const first = 8
	for i := 0; i < first; i++ {
		_ = s.RecordResult(obs(now.Add(time.Duration(i))))
	}
	waitForRows(t, s.db, first, 2*time.Second)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st := s2.Stats()
	if st.PreviousRun == nil || st.PreviousRun.State != flowstore.PreviousRunClean {
		t.Fatalf("PreviousRun = %+v, want clean", st.PreviousRun)
	}
	if st.Backend.WrittenRows != first {
		t.Errorf("WrittenRows carried = %d, want %d", st.Backend.WrittenRows, first)
	}

	const second = 8
	for i := 0; i < second; i++ {
		_ = s2.RecordResult(obs(now.Add(time.Duration(first + i))))
	}
	waitForRows(t, s2.db, first+second, 2*time.Second)

	st = s2.Stats()
	if st.Backend.WrittenRows != first+second {
		t.Errorf("WrittenRows = %d, want %d cumulative", st.Backend.WrittenRows, first+second)
	}
	if st.Backend.LostRows != 0 {
		t.Errorf("LostRows = %d, want 0", st.Backend.LostRows)
	}
	if err := s2.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// (8) Error classification and backoff bounds.
func TestClassifyWriteError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "busy message", err: busyError(), want: true},
		{name: "locked message", err: errors.New("table locked (6) (SQLITE_LOCKED)"), want: true},
		{name: "interrupt message", err: errors.New("(SQLITE_INTERRUPT)"), want: true},
		{name: "deadline", err: context.DeadlineExceeded, want: true},
		{name: "canceled", err: context.Canceled, want: false},
		{name: "io error", err: ioErr(), want: false},
		{name: "full disk", err: errors.New("database or disk full (13) (SQLITE_FULL)"), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyWriteError(tc.err); got != tc.want {
				t.Errorf("classifyWriteError(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}

	// A real driver error against a directory path: CANTOPEN, not transient.
	db, err := sql.Open("sqlite", t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err == nil {
		t.Fatal("ping against a directory unexpectedly succeeded")
	} else if classifyWriteError(err) {
		t.Errorf("CANTOPEN error %q classified transient", err)
	}
}

func TestRetryBackoffBoundedExponential(t *testing.T) {
	opts := testOpts(t)
	opts.applyDefaults()
	s := &Store{opts: opts}

	want := []time.Duration{20, 40, 80, 160, 320, 500, 500}
	for attempt := 1; attempt <= len(want); attempt++ {
		if got := s.retryBackoff(attempt); got != want[attempt-1]*time.Millisecond {
			t.Errorf("retryBackoff(%d) = %v, want %v", attempt, got, want[attempt-1]*time.Millisecond)
		}
	}
}

// --- tiny test helpers (avoid new dependency imports) ---

type atomicFlag struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicFlag) set(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicFlag) get() bool   { a.mu.Lock(); defer a.mu.Unlock(); return a.v }

func timePtr(t time.Time) *time.Time { return &t }
