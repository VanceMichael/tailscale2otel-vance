package rdns

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rknightion/tailscale2otel/v5/internal/telemetrytest"
)

// readonlySnapshotDir hands back a directory made unwritable for non-root
// callers, plus the deterministic snapshot path inside it. The writable bit is
// restored in a cleanup that runs BEFORE t.TempDir's own removal, so a failed
// assertion can never leave the temp tree unremovable.
func readonlySnapshotDir(t *testing.T) (dir, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("directory write permission is bypassed when running as root")
	}
	dir = filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, snapshotFileName)
}

// TestSnapshot_FailedPersistStaysDegradedButRetries is the core regression: a
// write to a briefly-unwritable directory must NOT switch persistence off for
// the process lifetime. The failure is visible (failure count, last error,
// pending generations), and the next report tick's dirty-check retries once
// storage recovers, lands a complete file, and resets the degraded state.
func TestSnapshot_FailedPersistStaysDegradedButRetries(t *testing.T) {
	_, path := readonlySnapshotDir(t)
	clock := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	c := New(Options{
		ReportInterval: testNoTick,
		SnapshotPath:   path,
		Now:            func() time.Time { return clock },
		Lookup:         okLookup("host.example.com."),
	})
	t.Cleanup(c.Close)

	// Purge marks dirty and flushes synchronously; the first write fails.
	c.Purge()
	st := c.Stats()
	if st.SnapshotFailures != 1 || st.SnapshotPendingGenerations != 1 || st.SnapshotLastError == "" {
		t.Fatalf("after first failed write: failures=%d pending=%d lastError=%q, want 1/1/non-empty",
			st.SnapshotFailures, st.SnapshotPendingGenerations, st.SnapshotLastError)
	}
	if st.SnapshotLastSuccess != (time.Time{}) {
		t.Fatalf("SnapshotLastSuccess = %v, want zero with no successful write", st.SnapshotLastSuccess)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("snapshot file exists after a failed first write (or Stat errored: %v)", err)
	}

	// The old behavior switched persistence off here. A second dirty tick must
	// fail again while the directory is still unwritable rather than no-op.
	c.Purge()
	if st := c.Stats(); st.SnapshotFailures != 2 {
		t.Fatalf("consecutive failures = %d, want 2", st.SnapshotFailures)
	}

	// Storage recovers. The report-tick path (persistSnapshotIfDirty) retries
	// with no restart and lands the snapshot.
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	c.persistSnapshotIfDirty()
	st = c.Stats()
	if st.SnapshotFailures != 0 || st.SnapshotLastError != "" {
		t.Fatalf("after recovery: failures=%d lastError=%q, want 0/\"\"", st.SnapshotFailures, st.SnapshotLastError)
	}
	if st.SnapshotPendingGenerations != 0 {
		t.Fatalf("pending generations after recovery = %d, want 0", st.SnapshotPendingGenerations)
	}
	if !st.SnapshotLastSuccess.Equal(clock) {
		t.Fatalf("SnapshotLastSuccess = %v, want %v", st.SnapshotLastSuccess, clock)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("snapshot not written after recovery: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", info.Mode().Perm())
	}

	// A restart loads the complete recovered snapshot state (an empty purge
	// snapshot here) and reports itself durable from the file's mtime.
	restarted := New(Options{
		ReportInterval: testNoTick,
		SnapshotPath:   path,
		Now:            func() time.Time { return clock },
		Lookup:         okLookup("host.example.com."),
	})
	defer restarted.Close()
	rs := restarted.Stats()
	if !rs.SnapshotEnabled || rs.SnapshotLastSuccess.IsZero() || rs.SnapshotPendingGenerations != 0 {
		t.Fatalf("warm status = %+v, want enabled, lastSuccess from mtime, 0 pending", rs)
	}
}

// TestSnapshot_PurgeAndCloseRetryAfterRecovery covers the other two retry
// triggers: Purge flushes synchronously itself, and Close performs one last
// flush after the workers drain. Both must succeed after the directory comes
// back even though the earlier attempt failed.
func TestSnapshot_PurgeAndCloseRetryAfterRecovery(t *testing.T) {
	t.Run("purge retries", func(t *testing.T) {
		_, path := readonlySnapshotDir(t)
		c := New(Options{ReportInterval: testNoTick, SnapshotPath: path,
			Lookup: okLookup("host.example.com.")})
		c.Purge() // fails: directory unwritable
		if st := c.Stats(); st.SnapshotFailures != 1 {
			t.Fatalf("failures = %d, want 1", st.SnapshotFailures)
		}
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if n := c.Purge(); n != 0 {
			t.Fatalf("Purge returned %d, want 0", n)
		}
		if st := c.Stats(); st.SnapshotFailures != 0 || st.SnapshotPendingGenerations != 0 {
			t.Fatalf("after recovering purge: %+v", st)
		}
		c.Close()
	})

	t.Run("close retries", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			dir, path := readonlySnapshotDir(t)
			var calls int
			c := New(Options{
				ReportInterval: testNoTick,
				SnapshotPath:   path,
				Lookup: func(context.Context, netip.Addr) ([]string, error) {
					calls++
					return []string{"late.example.com."}, nil
				},
			})
			c.LookupName(addr("203.0.113.90"))
			synctest.Wait()
			c.persistSnapshotIfDirty() // fails while the directory is read-only
			if st := c.Stats(); st.SnapshotFailures != 1 || st.SnapshotPendingGenerations == 0 {
				t.Fatalf("failed write status = %+v", st)
			}
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			c.Close() // last-chance flush must retry and land
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("Close did not land the snapshot after recovery: %v", err)
			}
			var snap diskSnapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				t.Fatalf("Close wrote an unreadable snapshot: %v", err)
			}
			if len(snap.Entries) != 1 || snap.Entries[0].Name != "late.example.com" {
				t.Fatalf("snapshot entries = %+v, want late.example.com", snap.Entries)
			}
		})
	})
}

// TestSnapshot_StaleWriteCannotMarkNewerStateDurable proves the generation
// rule: the write marks only the generation it CAPTURED. A resolution arriving
// while a write is in flight keeps the cache dirty and gets its own write, so
// its name can never be lost to an older capture.
func TestSnapshot_StaleWriteCannotMarkNewerStateDurable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), snapshotFileName)
		c := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup:         okLookup("first.example.com."),
		})
		t.Cleanup(c.Close)

		c.LookupName(addr("203.0.113.10"))
		synctest.Wait()
		c.persistSnapshot() // captures/persists generation 1
		if st := c.Stats(); st.SnapshotPendingGenerations != 0 {
			t.Fatalf("pending after first write = %d, want 0", st.SnapshotPendingGenerations)
		}

		// A second resolution bumps the generation while no write is running.
		c.LookupName(addr("203.0.113.11"))
		synctest.Wait()
		if st := c.Stats(); st.SnapshotPendingGenerations != 1 {
			t.Fatalf("pending after second resolve = %d, want 1", st.SnapshotPendingGenerations)
		}

		// Simulate the generation-1 write completing only now (delayed under
		// snapshotMu): it must advance nothing past the newer generation.
		c.snapshotMu.Lock()
		c.noteSnapshotSuccess(1)
		c.snapshotMu.Unlock()
		if st := c.Stats(); st.SnapshotPendingGenerations != 1 {
			t.Fatalf("a stale capture cleared pending: %d, want still 1", st.SnapshotPendingGenerations)
		}
		c.persistSnapshotIfDirty() // the newer state's own write
		if st := c.Stats(); st.SnapshotPendingGenerations != 0 {
			t.Fatalf("pending after current write = %d, want 0", st.SnapshotPendingGenerations)
		}

		// Restart: the file the newer state wrote carries both names.
		restarted := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup: func(context.Context, netip.Addr) ([]string, error) {
				t.Fatal("unexpected lookup for a warm-started name")
				return nil, context.Canceled
			},
		})
		defer restarted.Close()
		for _, want := range []string{"203.0.113.10", "203.0.113.11"} {
			if name, ok := restarted.LookupName(addr(want)); !ok || name == "" {
				t.Errorf("warm lookup %s = (%q,%v), want a cached name", want, name, ok)
			}
		}
	})
}

// TestSnapshot_FailedWriteKeepsLastCompleteFile proves the atomic boundary:
// a failed write removes its temp file and never touches the last complete
// snapshot, so (a) a restart during the outage warm-starts the previous file,
// and (b) no staging junk is left behind or mistaken for a snapshot.
func TestSnapshot_FailedWriteKeepsLastCompleteFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir, path := readonlySnapshotDir(t)
		// First make the directory writable long enough to seed a good file.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		seed := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup:         okLookup("good.example.com."),
		})
		seed.LookupName(addr("203.0.113.20"))
		synctest.Wait()
		seed.Close()
		good, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		// Directory goes unwritable and a newer resolution fails to persist.
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		live := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup:         okLookup("new.example.com."),
		})
		t.Cleanup(func() {
			_ = os.Chmod(dir, 0o755)
			live.Close()
		})
		live.LookupName(addr("203.0.113.21"))
		synctest.Wait()
		live.persistSnapshotIfDirty()
		if st := live.Stats(); st.SnapshotFailures != 1 {
			t.Fatalf("expected a degraded snapshot, got %+v", st)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("last complete snapshot disappeared: %v", err)
		}
		if string(after) != string(good) {
			t.Fatal("the failed write changed the last complete snapshot file")
		}
		if leftovers, _ := filepath.Glob(filepath.Join(dir, "."+snapshotFileName+".*.tmp")); len(leftovers) != 0 {
			t.Fatalf("failed write left staging files behind: %v", leftovers)
		}

		// A restart while the outage lasts warm-starts the PREVIOUS complete
		// snapshot rather than a half-written file.
		warm := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup: func(context.Context, netip.Addr) ([]string, error) {
				t.Fatal("expected the previous complete snapshot to warm-start")
				return nil, context.Canceled
			},
		})
		defer warm.Close()
		if name, ok := warm.LookupName(addr("203.0.113.20")); !ok || name != "good.example.com" {
			t.Fatalf("previous-snapshot lookup = (%q,%v), want (good.example.com,true)", name, ok)
		}
	})
}

// TestSnapshot_LeftoverTempFileNeverLoads pins the fixed load path: a staging
// file left by a hard kill is never mistaken for the snapshot.
func TestSnapshot_LeftoverTempFileNeverLoads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, snapshotFileName)
		seed := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup:         okLookup("warm.example.com."),
		})
		seed.LookupName(addr("203.0.113.30"))
		synctest.Wait()
		seed.Close()
		if err := os.WriteFile(filepath.Join(dir, "."+snapshotFileName+".deadbeef.tmp"),
			[]byte(`{not json`), 0o600); err != nil {
			t.Fatal(err)
		}

		warm := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Lookup: func(context.Context, netip.Addr) ([]string, error) {
				t.Fatal("the garbage temp file must not force a cold start")
				return nil, context.Canceled
			},
		})
		defer warm.Close()
		if name, ok := warm.LookupName(addr("203.0.113.30")); !ok || name != "warm.example.com" {
			t.Fatalf("lookup with a stray temp file = (%q,%v), want warm start", name, ok)
		}
	})
}

// TestSnapshot_ReportEmitsDurabilitySignals checks the self-monitoring signals
// through the same OTEL recorder the rest of the metrics use: failure delta,
// the current consecutive-failure/pending gauges, and the last-success
// timestamp (absent until the first success).
func TestSnapshot_ReportEmitsDurabilitySignals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir, path := readonlySnapshotDir(t)
		rec := telemetrytest.New()
		clock := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		c := New(Options{
			ReportInterval: testNoTick,
			SnapshotPath:   path,
			Emitter:        rec.Emitter(),
			Now:            func() time.Time { return clock },
			Lookup:         okLookup("host.example.com."),
		})
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755); c.Close() })

		// Before any write: no timestamp series and nothing failed.
		c.report()
		if pts := rec.MetricPoints(MetricSnapshotLastSuccess); len(pts) != 0 {
			t.Fatalf("last-success emitted before the first success: %v", pts)
		}
		if pts := rec.MetricPoints(MetricSnapshotPersistFailures); len(pts) != 0 {
			t.Fatalf("persist-failures counter emitted with no failure: %v", pts)
		}

		// One failed attempt: counter delta, consecutive-failure and pending gauges.
		c.Purge()
		c.report()
		assertGauge(t, rec, MetricSnapshotConsecutiveFailures, 1)
		assertGauge(t, rec, MetricSnapshotPendingGenerations, 1)
		assertCounter(t, rec, MetricSnapshotPersistFailures, "", "", 1)

		// Recovery: the heals gauges, emits the timestamp, and adds no failure delta.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		c.persistSnapshotIfDirty()
		c.report()
		assertGauge(t, rec, MetricSnapshotConsecutiveFailures, 0)
		assertGauge(t, rec, MetricSnapshotPendingGenerations, 0)
		assertGauge(t, rec, MetricSnapshotLastSuccess, float64(clock.Unix()))
		assertCounter(t, rec, MetricSnapshotPersistFailures, "", "", 1) // still 1, no new delta
	})
}

// TestSnapshot_MemoryOnlyEmitsNoDurabilitySignals pins the memory-only
// contract: with no checkpoint-adjacent path the snapshot signals stay absent
// however many mutations and reports happen.
func TestSnapshot_MemoryOnlyEmitsNoDurabilitySignals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := telemetrytest.New()
		c := New(Options{
			ReportInterval: testNoTick,
			Emitter:        rec.Emitter(),
			Lookup:         okLookup("host.example.com."),
		})
		t.Cleanup(c.Close)
		c.LookupName(addr("203.0.113.40"))
		synctest.Wait()
		c.Purge()
		c.report()
		for _, name := range []string{
			MetricSnapshotPersistFailures,
			MetricSnapshotConsecutiveFailures,
			MetricSnapshotPendingGenerations,
			MetricSnapshotLastSuccess,
		} {
			if pts := rec.MetricPoints(name); len(pts) != 0 {
				t.Errorf("memory-only cache emitted %s: %v", name, pts)
			}
		}
		if st := c.Stats(); st.SnapshotEnabled || st.SnapshotPendingGenerations != 0 {
			t.Errorf("memory-only Stats snapshot fields = enabled:%v pending:%d, want false/0",
				st.SnapshotEnabled, st.SnapshotPendingGenerations)
		}
	})
}
