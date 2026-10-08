package geoip

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rknightion/tailscale2otel/v5/internal/telemetrytest"
)

// sharedAddr is present in BOTH fixtures with the same answer, so it is the
// address whose country and ASN must always be observed together: a lookup
// while a withheld update is in play must still return BOTH facts.
const sharedAddr = "89.160.20.128"

func wantSharedPair(t *testing.T, db *DB) {
	t.Helper()
	if got, ok := db.Lookup(netip.MustParseAddr(sharedAddr)); !ok ||
		got.CountryISO != "SE" || got.ContinentCode != "EU" || got.ASN != 29518 || got.ASOrg != "Bredband2 AB" {
		t.Fatalf("Lookup(%s) = %+v, ok = %v; want the complete SE + ASN 29518 pair", sharedAddr, got, ok)
	}
}

// openPair copies both fixtures into dir and opens them as a configured pair.
func openPair(t *testing.T) (db *DB, countryPath, asnPath string) {
	t.Helper()
	dir := t.TempDir()
	countryPath = filepath.Join(dir, "country.mmdb")
	asnPath = filepath.Join(dir, "asn.mmdb")
	copyFile(t, countryDB, countryPath)
	copyFile(t, asnDB, asnPath)
	db = mustOpen(t, Options{CountryPath: countryPath, ASNPath: asnPath})
	return db, countryPath, asnPath
}

// Both files present and valid at startup publish together as generation 1.
func TestPair_StartupLoadsCompletePair(t *testing.T) {
	db, _, _ := openPair(t)

	s := db.Stats()
	if !s.Paired || s.Generation != 1 {
		t.Fatalf("Stats = paired %v generation %d; want paired gen 1", s.Paired, s.Generation)
	}
	if s.LastResult != ReloadPublished || s.PublishedAt.IsZero() {
		t.Errorf("startup disposition = %q at %v; want published", s.LastResult, s.PublishedAt)
	}
	if s.CountryType != "GeoIP2-Country" || s.ASNType != "GeoLite2-ASN" {
		t.Errorf("types = %q/%q", s.CountryType, s.ASNType)
	}
	// The startup load is not a reload tick: cumulative reload counters stay 0.
	if s.PairReloads != 0 || s.CountryReloads != 0 || s.ASNReloads != 0 || s.PendingReloads != 0 {
		t.Errorf("startup moved reload counters: %+v", s)
	}
	wantSharedPair(t, db)
}

// One file present and the other not yet landed at startup is a PENDING pair,
// not a half-loaded database: no error (nothing is wrong), nothing serves, and
// completing the pair on the next scan publishes it as generation 1.
func TestPair_StartupOneMissingIsPending(t *testing.T) {
	dir := t.TempDir()
	cpath := filepath.Join(dir, "country.mmdb")
	apath := filepath.Join(dir, "asn.mmdb")
	copyFile(t, countryDB, cpath)

	db, err := Open(Options{CountryPath: cpath, ASNPath: apath})
	if err != nil {
		t.Fatalf("Open with a missing partner returned an error: %v", err)
	}
	t.Cleanup(db.Close)
	if !db.Empty() {
		t.Error("one half present at startup published alone")
	}
	s := db.Stats()
	if s.Generation != 0 || s.LastResult != ReloadPending || s.Pending == nil {
		t.Fatalf("Stats = gen %d result %q pending %+v; want gen 0 pending", s.Generation, s.LastResult, s.Pending)
	}
	if s.Pending.WaitingFor != databaseASN || s.Pending.Reason != pendingMissing || !s.Pending.ReadyCountry {
		t.Errorf("Pending = %+v; want waiting for missing asn with country ready", s.Pending)
	}
	if s.Pending.CountryType != "GeoIP2-Country" || s.Pending.CountryBuildTime.IsZero() {
		t.Errorf("pending country identity = %q built %v; want the held candidate's metadata",
			s.Pending.CountryType, s.Pending.CountryBuildTime)
	}
	// Startup pending does not move the cumulative pending counter either.
	if s.PendingReloads != 0 {
		t.Errorf("startup pending moved PendingReloads = %d", s.PendingReloads)
	}

	copyFile(t, asnDB, apath)
	out := db.Reload()
	if !out.Changed || out.Result != ReloadPublished || out.Generation != 1 {
		t.Fatalf("Reload after the partner landed = %+v; want published gen 1", out)
	}
	wantSharedPair(t, db)
}

// Both files absent is an ordinary cold start, not a pending update: there is
// nothing newer waiting to commit.
func TestPair_BothAbsentIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	db := mustOpen(t, Options{
		CountryPath: filepath.Join(dir, "country.mmdb"),
		ASNPath:     filepath.Join(dir, "asn.mmdb"),
	})
	if s := db.Stats(); s.LastResult != ReloadUnchanged || s.Pending != nil {
		t.Errorf("both absent: result %q pending %+v; want unchanged", s.LastResult, s.Pending)
	}
}

// Rotating both files publishes both in one generation: one generation bump,
// one per-database swap each.
func TestPair_RotatedTogetherPublishes(t *testing.T) {
	db, cpath, apath := openPair(t)

	copyFile(t, countryDB, cpath)
	copyFile(t, asnDB, apath)
	bumpMtime(t, cpath)
	bumpMtime(t, apath)
	out := db.Reload()
	if !out.Changed || out.Result != ReloadPublished || out.Generation != 2 {
		t.Fatalf("Reload = %+v; want published gen 2", out)
	}
	s := db.Stats()
	if s.PairReloads != 1 || s.CountryReloads != 1 || s.ASNReloads != 1 ||
		s.PendingReloads != 0 || s.ReloadFailures != 0 {
		t.Errorf("counters after one pair publish: %+v", s)
	}
	wantSharedPair(t, db)
}

// THE core defect: a newer valid country file next to a CORRUPT asn file must
// not publish the country alone. The whole commit fails and the complete old
// pair keeps serving. Once the asn file is repaired, both halves commit
// together on the next scan.
func TestPair_CorruptHalfFailsWholeCommit(t *testing.T) {
	db, cpath, apath := openPair(t)

	// New country valid, new asn corrupt.
	copyFile(t, countryDB, cpath)
	bumpMtime(t, cpath)
	if err := os.WriteFile(apath, []byte("truncated mid-write"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := db.Reload()
	if out.Result != ReloadFailed || out.Err == nil || out.Generation != 1 {
		t.Fatalf("Reload = %+v; want failed, gen still 1", out)
	}
	s := db.Stats()
	if s.Generation != 1 || s.PairReloads != 0 || s.CountryReloads != 0 || s.ASNReloads != 0 {
		t.Errorf("a failed scan published something: %+v", s)
	}
	if s.ReloadFailures != 1 || s.LastError == "" || s.LastResult != ReloadFailed {
		t.Errorf("failure not recorded: %+v", s)
	}
	// The complete OLD pair still answers both facts.
	wantSharedPair(t, db)
	if got, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); !ok || got.CountryISO != "GB" {
		t.Fatalf("country lookup after a failed commit = %+v, ok = %v; want old GB", got, ok)
	}
	if got, ok := db.Lookup(netip.MustParseAddr("1.0.0.1")); !ok || got.ASN != 15169 {
		t.Fatalf("asn lookup after a failed commit = %+v, ok = %v; want old AS15169", got, ok)
	}

	// Repair the asn file; the pair commits together.
	copyFile(t, asnDB, apath)
	bumpMtime(t, apath)
	out = db.Reload()
	if !out.Changed || out.Result != ReloadPublished || out.Generation != 2 {
		t.Fatalf("Reload after repair = %+v; want published gen 2", out)
	}
	s = db.Stats()
	if s.PairReloads != 1 || s.CountryReloads != 1 || s.ASNReloads != 1 {
		t.Errorf("counters after repair: %+v", s)
	}
	wantSharedPair(t, db)
}

// The same defect with the roles swapped: a corrupt country file blocks a new
// ASN file.
func TestPair_CorruptCountryBlocksNewASN(t *testing.T) {
	db, cpath, apath := openPair(t)

	if err := os.WriteFile(cpath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyFile(t, asnDB, apath)
	bumpMtime(t, apath)
	out := db.Reload()
	if out.Result != ReloadFailed || out.Generation != 1 {
		t.Fatalf("Reload = %+v; want failed at gen 1", out)
	}
	wantSharedPair(t, db)
}

// A rotation that replaces one file and DELETES the other mid-way must not
// publish: the missing partner withholds the new file, and the complete old
// pair — including the deleted side's already-loaded reader — keeps serving
// until the partner file returns.
func TestPair_MissingHalfMidRotationPending(t *testing.T) {
	db, cpath, apath := openPair(t)

	copyFile(t, countryDB, cpath)
	bumpMtime(t, cpath)
	if err := os.Remove(apath); err != nil {
		t.Fatal(err)
	}
	out := db.Reload()
	if out.Result != ReloadPending || out.Generation != 1 {
		t.Fatalf("Reload = %+v; want pending at gen 1", out)
	}
	s := db.Stats()
	if s.Pending == nil || s.Pending.WaitingFor != databaseASN || s.Pending.Reason != pendingMissing || !s.Pending.ReadyCountry {
		t.Fatalf("Pending = %+v; want a held country waiting for a missing asn", s.Pending)
	}
	if s.PendingReloads != 1 || s.PairReloads != 0 {
		t.Errorf("counters = pair %d pending %d; want 0/1", s.PairReloads, s.PendingReloads)
	}
	// Old pair still answers both facts even though the asn file is gone.
	wantSharedPair(t, db)

	// Partner lands: both files validate in one scan and the pair commits.
	copyFile(t, asnDB, apath)
	bumpMtime(t, apath)
	out = db.Reload()
	if !out.Changed || out.Result != ReloadPublished || out.Generation != 2 {
		t.Fatalf("Reload after the partner returned = %+v; want published gen 2", out)
	}
	wantSharedPair(t, db)
}

// A one-sided rotation (new country, asn file present but untouched) is also
// withheld: publishing it would be exactly the new-country/old-asn stitch the
// generation boundary exists to prevent. The held country commits the moment
// the asn file is rotated too.
func TestPair_OneSidedRotationWaitsForPartner(t *testing.T) {
	db, cpath, apath := openPair(t)

	copyFile(t, countryDB, cpath)
	bumpMtime(t, cpath)
	out := db.Reload()
	if out.Result != ReloadPending || out.Generation != 1 {
		t.Fatalf("Reload = %+v; want pending at gen 1", out)
	}
	if p := db.Stats().Pending; p == nil || p.WaitingFor != databaseASN || p.Reason != pendingUnchanged {
		t.Fatalf("Pending = %+v; want waiting for an unchanged asn", p)
	}
	wantSharedPair(t, db)

	copyFile(t, asnDB, apath)
	bumpMtime(t, apath)
	out = db.Reload()
	if !out.Changed || out.Generation != 2 {
		t.Fatalf("Reload = %+v; want published gen 2 once both halves rotated", out)
	}
	wantSharedPair(t, db)
}

// Deleting a file WITHOUT any partner update does not unload the published
// reader and is not an error: fail-open treats a vanished path as "no
// instruction", preserving today's behavior.
func TestPair_DeletionAloneKeepsPublishedPair(t *testing.T) {
	db, _, apath := openPair(t)

	if err := os.Remove(apath); err != nil {
		t.Fatal(err)
	}
	out := db.Reload()
	if out.Result != ReloadUnchanged || out.Generation != 1 || out.Err != nil {
		t.Fatalf("Reload after deleting one file = %+v; want unchanged, gen 1, no error", out)
	}
	wantSharedPair(t, db)
}

// A withheld scan keeps its retry opportunity: the next tick re-validates the
// held file and records another pending outcome, then commits once the partner
// catches up.
func TestPair_PendingRetriesEachScan(t *testing.T) {
	db, cpath, _ := openPair(t)

	copyFile(t, countryDB, cpath)
	bumpMtime(t, cpath)
	for range 3 {
		out := db.Reload()
		if out.Result != ReloadPending || out.Generation != 1 {
			t.Fatalf("Reload = %+v; want still pending at gen 1", out)
		}
	}
	if got := db.Stats().PendingReloads; got != 3 {
		t.Errorf("PendingReloads = %d, want 3", got)
	}
	wantSharedPair(t, db)
}

// With a single database configured the pair machinery never engages: a swap
// publishes immediately and no pair/pending metrics exist.
func TestPair_SingleDatabaseKeepsIndependentSwaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	copyFile(t, countryDB, path)
	db := mustOpen(t, Options{CountryPath: path})

	if s := db.Stats(); s.Paired {
		t.Error("single database reports Paired")
	}
	copyFile(t, countryDB, path)
	bumpMtime(t, path)
	out := db.Reload()
	if !out.Changed || out.Result != ReloadPublished {
		t.Fatalf("Reload = %+v; want an immediate single-database publish", out)
	}
	s := db.Stats()
	if s.PendingReloads != 0 || s.Pending != nil || s.PairReloads != 1 {
		t.Errorf("single-database swap left pair state: %+v", s)
	}
}

// Report emits the pair-level outcomes (committed generation, withheld pair)
// alongside per-database swaps, and attributes failures to the failing file —
// never under the old aggregate "skipped" label.
func TestReport_PairOutcomeMetrics(t *testing.T) {
	db, cpath, apath := openPair(t)

	// Gen 2: both rotated together.
	copyFile(t, countryDB, cpath)
	copyFile(t, asnDB, apath)
	bumpMtime(t, cpath)
	bumpMtime(t, apath)
	if out := db.Reload(); !out.Changed {
		t.Fatal(out.Err)
	}
	// Pending: country newer, asn missing.
	copyFile(t, countryDB, cpath)
	bumpMtime(t, cpath)
	if err := os.Remove(apath); err != nil {
		t.Fatal(err)
	}
	if out := db.Reload(); out.Result != ReloadPending {
		t.Fatalf("Reload = %+v; want pending", out)
	}
	// Failed: country still newer, asn corrupt.
	if err := os.WriteFile(apath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := db.Reload(); out.Result != ReloadFailed {
		t.Fatalf("Reload = %+v; want failed", out)
	}

	rec := telemetrytest.New()
	db.Report(rec.Emitter())

	points := map[string]float64{}
	for _, p := range rec.MetricPoints(MetricReloads) {
		points[p.Attrs[attrDatabase]+"/"+p.Attrs[attrResult]] += p.Value
	}
	want := map[string]float64{
		"country/success": 1,
		"asn/success":     1,
		"pair/success":    1,
		"pair/pending":    1,
		"asn/failure":     1,
	}
	for k, v := range want {
		if points[k] != v {
			t.Errorf("reloads{%s} = %v, want %v", k, points[k], v)
		}
	}
	if points["skipped/failure"] != 0 {
		t.Errorf("reloads still emit the aggregate skipped/failure = %v", points["skipped/failure"])
	}
	if points["country/failure"] != 0 {
		t.Errorf("country/failure = %v, want 0 (the asn file failed)", points["country/failure"])
	}

	// A second report emits only deltas.
	rec2 := telemetrytest.New()
	db.Report(rec2.Emitter())
	if pts := rec2.MetricPoints(MetricReloads); len(pts) != 0 {
		t.Errorf("second Report emitted %d reload points, want 0", len(pts))
	}
}

// A one-database configuration never emits pair-level series.
func TestReport_SingleDatabaseHasNoPairSeries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	copyFile(t, countryDB, path)
	db := mustOpen(t, Options{CountryPath: path})
	copyFile(t, countryDB, path)
	bumpMtime(t, path)
	if out := db.Reload(); !out.Changed {
		t.Fatal(out.Err)
	}

	rec := telemetrytest.New()
	db.Report(rec.Emitter())
	for _, p := range rec.MetricPoints(MetricReloads) {
		if p.Attrs[attrDatabase] == databasePair {
			t.Errorf("single-database mode emitted a pair series: %+v", p.Attrs)
		}
	}
}

// ObserveDownload keeps a per-edition tally even with no emitter, so the status
// page can correlate a pending pair with the edition whose fetch failed.
func TestObserveDownload_Tally(t *testing.T) {
	db := mustOpen(t, Options{CountryPath: countryDB})

	db.ObserveDownload(nil, "GeoLite2-Country", DownloadResult{Updated: false}, nil)
	db.ObserveDownload(nil, "GeoLite2-Country", DownloadResult{Updated: true}, nil)
	db.ObserveDownload(nil, "GeoLite2-ASN", DownloadResult{}, errors.New("HTTP 401 Unauthorized"))

	s := db.Stats()
	c := s.Downloads["GeoLite2-Country"]
	if c.Updated != 1 || c.Unmodified != 1 || c.Failures != 0 || c.LastResult != "updated" {
		t.Errorf("country tally = %+v", c)
	}
	a := s.Downloads["GeoLite2-ASN"]
	if a.Failures != 1 || a.LastResult != "failure" || a.LastError != "HTTP 401 Unauthorized" || a.LastAt.IsZero() {
		t.Errorf("asn tally = %+v", a)
	}
}

// Pair reloads swapping readers while lookups walk them: the generation commit
// is one write lock over both pointer swaps, so no lookup can observe a split
// pair. Run under -race (CI always does).
func TestPair_ReloadConcurrentWithLookup(t *testing.T) {
	db, cpath, apath := openPair(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					got, ok := db.Lookup(netip.MustParseAddr(sharedAddr))
					if ok && (got.CountryISO != "SE" || got.ASN != 29518) {
						t.Errorf("split pair observed: %+v", got)
						return
					}
				}
			}
		}()
	}
	for i := range 45 {
		// Baseline: a healthy rotation of both files always publishes.
		copyFile(t, countryDB, cpath)
		copyFile(t, asnDB, apath)
		bumpMtime(t, cpath)
		bumpMtime(t, apath)
		if out := db.Reload(); !out.Changed {
			t.Errorf("valid pair rotation did not publish: %+v", out)
		}
		// Interleave the three torn-rotation shapes. Every one must withhold
		// the update and keep the complete prior pair answering lookups.
		switch i % 5 {
		case 1:
			// New country, corrupt asn: whole commit fails.
			copyFile(t, countryDB, cpath)
			bumpMtime(t, cpath)
			if err := os.WriteFile(apath, []byte("corrupt"), 0o600); err != nil {
				t.Fatal(err)
			}
			if out := db.Reload(); out.Result != ReloadFailed {
				t.Errorf("torn (new country, corrupt asn) = %+v; want failed", out)
			}
		case 2:
			// New country, asn deleted mid-rotation: pending (missing).
			copyFile(t, countryDB, cpath)
			bumpMtime(t, cpath)
			if err := os.Remove(apath); err != nil {
				t.Fatal(err)
			}
			if out := db.Reload(); out.Result != ReloadPending {
				t.Errorf("torn (new country, missing asn) = %+v; want pending", out)
			}
		case 3:
			// New country, asn present but untouched: pending (unchanged).
			copyFile(t, countryDB, cpath)
			bumpMtime(t, cpath)
			if out := db.Reload(); out.Result != ReloadPending {
				t.Errorf("one-sided rotation = %+v; want pending", out)
			}
		}
	}
	close(stop)
	wg.Wait()
}

// The built-in downloader fetches editions ONE AT A TIME and then runs the same
// generation scan. A round where one edition lands and the other fails must not
// take the landed half live; the next successful round commits the pair.
func TestUpdater_PairCommitsAfterPartialDownloadRound(t *testing.T) {
	dir := t.TempDir()
	cpath := filepath.Join(dir, "country.mmdb")
	apath := filepath.Join(dir, "asn.mmdb")
	db := mustOpen(t, Options{CountryPath: cpath, ASNPath: apath})

	var round atomic.Int32
	fetch := fetchFunc(func(_ context.Context, edition string) (DownloadResult, error) {
		if edition == "GeoLite2-Country" {
			copyFile(t, countryDB, cpath)
			return DownloadResult{Edition: edition, Path: cpath, Updated: true}, nil
		}
		if round.Load() == 0 {
			return DownloadResult{Edition: edition}, errors.New("HTTP 401 Unauthorized")
		}
		copyFile(t, asnDB, apath)
		return DownloadResult{Edition: edition, Path: apath, Updated: true}, nil
	})

	synctest.Test(t, func(t *testing.T) {
		u := NewUpdater(UpdaterOptions{
			DB:               db,
			Fetcher:          fetch,
			Editions:         []string{"GeoLite2-Country", "GeoLite2-ASN"},
			DownloadInterval: time.Hour,
			ReloadInterval:   time.Hour,
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go u.Run(ctx)
		synctest.Wait()

		// Round 1: country downloaded, asn failed — pending, nothing serves.
		if !db.Empty() {
			t.Fatal("the landed country half published alone after a partial download round")
		}
		s := db.Stats()
		if s.LastResult != ReloadPending || s.Pending == nil || s.Pending.WaitingFor != databaseASN {
			t.Fatalf("post-round-1 state = %q %+v; want pending asn", s.LastResult, s.Pending)
		}
		if d := s.Downloads["GeoLite2-ASN"]; d.Failures != 1 || d.LastError == "" {
			t.Errorf("asn download tally = %+v; want the failure recorded", d)
		}

		// Round 2: both editions fetched; asn lands and the held country
		// re-validates, so the complete pair commits.
		round.Store(1)
		time.Sleep(time.Hour)
		synctest.Wait()

		if out := db.Stats(); out.Generation < 1 || out.LastResult != ReloadPublished {
			t.Fatalf("post-round-2 state = gen %d %q; want a published generation", out.Generation, out.LastResult)
		}
		wantSharedPair(t, db)
	})
}

// When one edition is updated and the other answers 304 (its file genuinely
// unchanged on disk), the pair still waits: serving new-country + old-asn is
// the stitch this boundary forbids. It commits when the other edition is
// updated in a later round.
func TestUpdater_OneUpdatedOneUnmodifiedWithholds(t *testing.T) {
	db, cpath, apath := openPair(t)

	var round atomic.Int32
	fetch := fetchFunc(func(_ context.Context, edition string) (DownloadResult, error) {
		switch {
		case edition == "GeoLite2-Country":
			copyFile(t, countryDB, cpath)
			bumpMtime(t, cpath)
			return DownloadResult{Edition: edition, Path: cpath, Updated: true}, nil
		case round.Load() == 0:
			// 304: file untouched.
			return DownloadResult{Edition: edition, Path: apath, Updated: false}, nil
		default:
			copyFile(t, asnDB, apath)
			bumpMtime(t, apath)
			return DownloadResult{Edition: edition, Path: apath, Updated: true}, nil
		}
	})

	synctest.Test(t, func(t *testing.T) {
		u := NewUpdater(UpdaterOptions{
			DB:               db,
			Fetcher:          fetch,
			Editions:         []string{"GeoLite2-Country", "GeoLite2-ASN"},
			DownloadInterval: time.Hour,
			ReloadInterval:   2 * time.Hour,
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go u.Run(ctx)
		synctest.Wait()

		s := db.Stats()
		if s.LastResult != ReloadPending || s.Generation != 1 || s.Pending == nil ||
			s.Pending.Reason != pendingUnchanged {
			t.Fatalf("after updated+304 round: %q gen %d pending %+v; want pending(unchanged) at gen 1",
				s.LastResult, s.Generation, s.Pending)
		}
		wantSharedPair(t, db)

		round.Store(1)
		time.Sleep(time.Hour)
		synctest.Wait()
		if out := db.Stats(); out.Generation != 2 || out.LastResult != ReloadPublished {
			t.Fatalf("after the asn update round: gen %d %q; want published gen 2", out.Generation, out.LastResult)
		}
		wantSharedPair(t, db)
	})
}
