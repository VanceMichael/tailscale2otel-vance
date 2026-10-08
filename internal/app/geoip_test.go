package app

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/tailscale2otel/v5/internal/config"
	"github.com/rknightion/tailscale2otel/v5/internal/geoip"
)

// testLogger discards output: these tests assert behavior, and buildGeoIP is
// deliberately chatty about degraded states.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A missing database must not stop the app from building the GeoIP set: the
// scheduled download may not have landed on a cold start, and refusing to come
// up would turn an opt-in enrichment nicety into an outage.
func TestBuildGeoIP_MissingDatabaseStillBuilds(t *testing.T) {
	a := &App{cfg: config.Default(), logger: testLogger()}
	a.cfg.Enrichment.GeoIP.Enabled = true
	a.cfg.Enrichment.GeoIP.CountryDatabase = filepath.Join(t.TempDir(), "absent.mmdb")

	a.buildGeoIP()

	if a.geoDB == nil {
		t.Fatal("geoDB is nil after buildGeoIP with a missing database")
	}
	t.Cleanup(a.geoDB.Close)
	if !a.geoDB.Empty() {
		t.Error("geoDB reports a loaded database when the file does not exist")
	}
	if a.geoUpdater == nil {
		t.Error("geoUpdater is nil; the reload loop is what picks the file up later")
	}
}

// Disabled means nothing is built at all, so every consumer sees the nil *DB
// that reports a miss for every address.
func TestBuildGeoIP_DisabledBuildsNothing(t *testing.T) {
	a := &App{cfg: config.Default(), logger: testLogger()}
	a.buildGeoIP()
	if a.geoDB != nil || a.geoUpdater != nil {
		t.Fatalf("geoip disabled but geoDB=%v geoUpdater=%v", a.geoDB != nil, a.geoUpdater != nil)
	}
	// The nil DB must still be safe for every consumer to call.
	if !a.geoDB.Empty() {
		t.Error("nil geoDB Empty() = false")
	}
}

// The status snapshot has to work off Stats() directly, so it shows real numbers
// whether or not self-observability (which gates the OTEL metrics) is on.
func TestGeoipInfo(t *testing.T) {
	a := &App{cfg: config.Default(), logger: testLogger()}

	if got := a.geoipInfo(); got.Enabled {
		t.Error("geoipInfo reports enabled with no database set")
	}

	a.cfg.Enrichment.GeoIP.Enabled = true
	a.cfg.Enrichment.GeoIP.CountryDatabase = "../geoip/testdata/GeoIP2-Country-Test.mmdb"
	a.cfg.Cardinality.Flow.GeoDims = true
	a.buildGeoIP()
	t.Cleanup(a.geoDB.Close)

	info := a.geoipInfo()
	if !info.Enabled {
		t.Fatal("geoipInfo reports disabled after buildGeoIP")
	}
	if info.CountryType != "GeoIP2-Country" {
		t.Errorf("CountryType = %q, want GeoIP2-Country", info.CountryType)
	}
	// The build time is the staleness signal an operator reads, so it must be a
	// real date rather than the zero value dressed up as one.
	if info.CountryBuildTime == "" || strings.HasPrefix(info.CountryBuildTime, "1970") {
		t.Errorf("CountryBuildTime = %q, want the database's build date", info.CountryBuildTime)
	}
	if info.ASNType != "" {
		t.Errorf("ASNType = %q, want empty (no ASN database configured)", info.ASNType)
	}
	if !info.GeoDims {
		t.Error("GeoDims = false; the status page must show that country labels are on flow metrics")
	}
}

// The status snapshot distinguishes the published pair from a withheld update
// and its reason, and carries the per-edition download tally, so an operator
// can see all three states without self-observability.
func TestGeoipInfo_PairGenerationStates(t *testing.T) {
	dir := t.TempDir()
	cpath := filepath.Join(dir, "country.mmdb")
	apath := filepath.Join(dir, "asn.mmdb")
	writeCopy := func(dst, src string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCopy(cpath, "../geoip/testdata/GeoIP2-Country-Test.mmdb")
	writeCopy(apath, "../geoip/testdata/GeoLite2-ASN-Test.mmdb")

	a := &App{cfg: config.Default(), logger: testLogger()}
	a.cfg.Enrichment.GeoIP.Enabled = true
	a.cfg.Enrichment.GeoIP.CountryDatabase = cpath
	a.cfg.Enrichment.GeoIP.ASNDatabase = apath
	a.buildGeoIP()
	t.Cleanup(a.geoDB.Close)

	info := a.geoipInfo()
	if !info.Paired || info.Generation != 1 || info.LastResult != "published" || info.PublishedAt == "" {
		t.Fatalf("initial info = paired %v gen %d result %q publishedAt %q; want paired published gen 1",
			info.Paired, info.Generation, info.LastResult, info.PublishedAt)
	}
	if info.CountryBuildTime == "" || info.ASNBuildTime == "" {
		t.Fatal("both published build times must be shown")
	}

	// Half rotation: newer country, asn deleted → pending, and the published
	// build times must still describe generation 1 (what lookups use).
	writeCopy(cpath, "../geoip/testdata/GeoIP2-Country-Test.mmdb")
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(cpath, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(apath); err != nil {
		t.Fatal(err)
	}
	if r := a.geoDB.Reload(); r.Result != geoip.ReloadPending {
		t.Fatalf("Reload = %+v; want pending", r)
	}
	info = a.geoipInfo()
	if info.LastResult != "pending" || info.Pending == nil {
		t.Fatalf("info result %q pending %+v; want pending detail", info.LastResult, info.Pending)
	}
	if info.Pending.WaitingFor != "asn" || info.Pending.Reason != "missing" || !info.Pending.ReadyCountry {
		t.Errorf("Pending = %+v; want a held country waiting for a missing asn", info.Pending)
	}
	if info.Pending.CountryType != "GeoIP2-Country" || info.Pending.CountryBuildTime == "" {
		t.Errorf("held candidate identity = %q %q", info.Pending.CountryType, info.Pending.CountryBuildTime)
	}
	if info.Generation != 1 || info.PendingReloads != 1 || info.PairReloads != 0 {
		t.Errorf("generation/counters = gen %d pending %d pair %d; want gen 1, 1, 0",
			info.Generation, info.PendingReloads, info.PairReloads)
	}
	if info.CountryBuildTime == "" || info.ASNBuildTime == "" {
		t.Error("published build times vanished while an update is pending")
	}

	// A failed edition on the download side shows up per edition, ready to
	// correlate with the pending pair.
	a.geoDB.ObserveDownload(nil, "GeoLite2-ASN", geoip.DownloadResult{}, errors.New("HTTP 401 Unauthorized"))
	info = a.geoipInfo()
	if len(info.Downloads) != 1 {
		t.Fatalf("Downloads = %+v; want one edition row", info.Downloads)
	}
	d := info.Downloads[0]
	if d.Edition != "GeoLite2-ASN" || d.Failures != 1 || d.LastResult != "failure" || d.LastError != "HTTP 401 Unauthorized" {
		t.Errorf("download row = %+v", d)
	}
}

// geoDownloadClientTimeout must stay looser than the per-fetch context deadline,
// or the client timeout fires first and reports a limit the operator never set.
func TestGeoDownloadClientTimeout(t *testing.T) {
	if got := geoDownloadClientTimeout(0); got <= 0 {
		t.Errorf("geoDownloadClientTimeout(0) = %v, want a positive fallback", got)
	}
	cfg := config.Default().Enrichment.GeoIP.Download.Timeout.D()
	if got := geoDownloadClientTimeout(cfg); got <= cfg {
		t.Errorf("geoDownloadClientTimeout(%v) = %v, want it strictly looser than the fetch deadline", cfg, got)
	}
}

// The app hands *geoip.DB straight to the flow processor and the devices
// collector, so it has to satisfy the narrow interface both depend on.
func TestGeoDBSatisfiesLookup(t *testing.T) {
	var _ geoip.Lookup = (*geoip.DB)(nil)
}
