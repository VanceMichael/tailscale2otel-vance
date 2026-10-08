// Package geoip provides optional, purely LOCAL geolocation and autonomous-system
// enrichment of external (non-Tailscale) IP addresses, backed by MaxMind DB
// (.mmdb) files on disk.
//
// The hot path never touches the network. A lookup is a radix-tree walk costing
// well under a microsecond; decoding into the fixed structs below allocates
// nothing. That is why this package — deliberately, unlike its sibling
// internal/rdns — has NO result cache. rdns caches because a PTR lookup is a
// network round trip that must never block flow processing; here there is
// nothing slow to hide, and an LRU in front would add locking, memory and a
// whole TTL surface for no gain. Do not add one.
//
// # Databases are read into memory, NOT memory-mapped
//
// maxminddb.Open mmaps the file, which is faster to load and cheaper in RSS
// (the pages are evictable page cache). It is also a way to crash the process:
// if anything TRUNCATES the file while a lookup is walking the mapping — a
// plain `curl -o db.mmdb`, an editor, a rsync without --inplace — every
// in-flight read faults with SIGBUS and takes the whole exporter down. That is
// not hypothetical; it is what the first version of this package did, and the
// reload test reproduced it immediately.
//
// So Open reads each file fully into the heap and uses maxminddb.OpenBytes. The
// cost is real and worth stating: roughly 9 MB resident for GeoLite2-Country and
// 12 MB for GeoLite2-ASN, held for the process lifetime, and a City database is
// several times larger again. That is the price of a feature that is off by
// default and must never be able to kill a running exporter. Do not "optimize"
// this back to mmap.
//
// The databases commit as GENERATIONS through one boundary shared by the
// initial Open, the scheduled Reload (see updater.go), the operator-managed
// file path and this package's own MaxMind downloader (maxmind.go). When BOTH
// a country and an ASN path are configured, a scan publishes a new generation
// only when BOTH files are present and validate in that same scan: one newer
// file next to a partner that is missing, half-replaced, corrupt or simply not
// rotated in the same round is withheld (pending), and the previously
// published PAIR keeps serving until both halves are ready. A lookup can
// therefore see only old-country+old-ASN or new-country+new-ASN, never a
// stitched-together half-generation. With a single path configured the one
// database swaps independently exactly as it always has.
//
// Everything here is fail-open. A missing, unreadable or stale database means
// the geo attributes are simply absent from the emitted telemetry; it is never
// a startup failure and never blocks a lookup. A failed or withheld update
// costs freshness, never availability.
package geoip

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/rknightion/tailscale2otel/v5/internal/enrich"
	"github.com/rknightion/tailscale2otel/v5/internal/metricdoc"
	"github.com/rknightion/tailscale2otel/v5/internal/safefile"
	"github.com/rknightion/tailscale2otel/v5/internal/telemetry"
)

// Lookup is the narrow, fakeable interface consumers depend on. A nil *DB
// satisfies it and reports a miss for every address, which is the value the app
// hands out when enrichment.geoip is disabled.
type Lookup interface {
	Lookup(addr netip.Addr) (Result, bool)
}

// Result is everything this package reports about an address.
//
// The fields split into two very different cardinality classes, and callers must
// respect the split:
//
//   - CountryISO and ContinentCode are BOUNDED (~250 and 7 values). They are the
//     only fields that may go on a metric, and only when the operator opts in
//     via cardinality.flow.geo_dims.
//   - ASN, ASOrg, City, RegionISO and the coordinates are NOT usefully bounded.
//     They are confined to LOG records, which are not series and carry the
//     full-fidelity view by design.
//
// The city fields require a City database (GeoLite2-City / GeoIP2-City). A
// Country database is a strict subset and simply leaves them empty, so the same
// configuration key accepts either.
type Result struct {
	// CountryISO is the ISO 3166-1 alpha-2 code, e.g. "US". Empty when unknown.
	CountryISO string
	// ContinentCode is the two-letter continent code, e.g. "NA". Empty when unknown.
	ContinentCode string
	// City is the English city name, e.g. "London". City database only.
	City string
	// RegionISO is the ISO 3166-2 subdivision code of the most specific
	// subdivision, e.g. "ENG" for England or "CA" for California. City database
	// only. MaxMind orders subdivisions least- to most-specific, so this is the
	// LAST entry, not the first.
	RegionISO string
	// Latitude and Longitude are the WGS84 coordinates of the record's location.
	// City database only, and meaningful only when HasLocation is set: (0, 0) is
	// a real point in the Gulf of Guinea, so a zero pair cannot be read as
	// "unknown".
	Latitude, Longitude float64
	// HasLocation reports whether Latitude/Longitude were present in the record.
	HasLocation bool
	// ASN is the autonomous-system number, e.g. 15169. Zero when unknown.
	ASN uint
	// ASOrg is the autonomous-system organization, e.g. "Google LLC". Empty when
	// unknown — the ASN database genuinely carries records with a number and no
	// organization name.
	ASOrg string
}

// Empty reports whether the result carries no usable fact at all.
func (r Result) Empty() bool { return r == Result{} }

// countryRecord is the subset of a GeoLite2/GeoIP2 Country (or City) record this
// package reads.
//
// The three country objects are not redundant. `country` is where the address is
// physically located and is the field to prefer — but MaxMind genuinely omits it
// for a large slice of the internet, carrying only `registered_country` (the
// country of the registering ISP). 1.1.1.1 is the canonical example, verified
// against the live database: no `country` object at all. Without the fallback in
// countryFrom, every Cloudflare-fronted address reads as unknown.
type countryRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	RepresentedCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"represented_country"`

	// City-database-only fields. A Country database omits them entirely and they
	// decode to their zero values, which is exactly the intended behavior: the
	// same configured path accepts either edition.
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// asnRecord is the whole of a GeoLite2-ASN record.
type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// countryFrom picks the best country code available in a record, preferring the
// physical location over the registering ISP's country over the represented
// country (embassies, military bases). See the countryRecord doc for why the
// fallback chain is load-bearing rather than defensive.
func countryFrom(rec countryRecord) (iso, continent string) {
	iso = rec.Country.ISOCode
	if iso == "" {
		iso = rec.RegisteredCountry.ISOCode
	}
	if iso == "" {
		iso = rec.RepresentedCountry.ISOCode
	}
	return iso, rec.Continent.Code
}

// cityFrom extracts the City-database-only fields, all of which are empty when a
// Country database is loaded instead.
//
// Only the English name is read. MaxMind ships eight localisations of every
// place name, and mixing them would split what should be one value ("London" vs
// "Londres") across a log corpus for no benefit.
func cityFrom(rec countryRecord) (city, regionISO string, lat, lon float64, hasLocation bool) {
	city = rec.City.Names["en"]
	// Subdivisions run least- to most-specific ("England" then a county), so the
	// LAST entry is the one worth carrying. Taking the first would report the
	// coarsest division under a name that says region.
	if n := len(rec.Subdivisions); n > 0 {
		regionISO = rec.Subdivisions[n-1].ISOCode
	}
	// A record with no location object decodes to (0, 0) — which is a real point
	// in the Gulf of Guinea, not a sentinel. Presence is inferred from the city
	// record having any location-bearing content at all, so a genuine (0, 0) is
	// never confused with an absent one.
	if rec.Location.Latitude != 0 || rec.Location.Longitude != 0 {
		lat, lon, hasLocation = rec.Location.Latitude, rec.Location.Longitude, true
	}
	return city, regionISO, lat, lon, hasLocation
}

// Options configures a DB. Both paths are optional and independent: an operator
// may ship only a Country database, only an ASN database, or neither (the app
// builds the DB before the first download has necessarily landed).
type Options struct {
	CountryPath string
	ASNPath     string
}

// reader pairs an open maxminddb reader with the (mtime, size) it was opened at,
// so Reload can skip an untouched file without re-reading it.
type reader struct {
	db    *maxminddb.Reader
	mtime time.Time
	size  int64
}

// maxDatabaseBytes caps how large a file this package will load. It is not a
// security boundary — the operator names the path — but it turns "pointed at the
// wrong file" and "the download wrote a 40 GB sparse file" into a clear error
// instead of an OOM kill. 512 MiB is far above any real MaxMind database
// (GeoIP2-City, the largest MaxMind publishes, is well under 200 MB).
const maxDatabaseBytes = 512 << 20

// stats holds the cumulative counters surfaced by Stats and flushed as OTEL
// counter deltas by report(). Guarded by DB.mu.
type stats struct {
	countryHits, countryMisses   int64
	asnHits, asnMisses           int64
	skipped                      int64
	countryReloads, asnReloads   int64
	countryFailures, asnFailures int64
	reloadFailures               int64
	// pairPublishes counts committed generations; pendingReloads counts scans
	// that validated a newer file but withheld it because the pair was not yet
	// complete. In a one-database configuration pairPublishes counts that
	// database's swaps; pendingReloads never moves.
	pairPublishes  int64
	pendingReloads int64

	// downloads is the per-edition outcome tally of the built-in downloader,
	// so the status page can show it with self-observability off. Keyed by
	// edition (the operator's short configured list — bounded).
	downloads map[string]*downloadStats
}

// downloadStats is one edition's cumulative download tally and last attempt.
type downloadStats struct {
	updated, unmodified, failures int64
	lastResult                    string // resultUpdated | resultUnmodified | resultFailure
	lastError                     string
	lastAt                        time.Time
}

// DownloadStatus is one edition's download tally for the admin status page.
type DownloadStatus struct {
	Updated, Unmodified, Failures int64
	LastResult                    string
	LastError                     string
	LastAt                        time.Time
}

// Reload result values for Stats.LastResult and ReloadOutcome.Result.
const (
	// ReloadUnchanged: no configured file differed from the published generation.
	ReloadUnchanged = "unchanged"
	// ReloadPublished: a new generation was committed (ReloadOutcome.Changed).
	ReloadPublished = "published"
	// ReloadPending: a newer file validated but its pair was incomplete, so the
	// previously published generation keeps serving.
	ReloadPending = "pending"
	// ReloadFailed: a present file failed to stat/read/parse; the previously
	// published generation keeps serving.
	ReloadFailed = "failed"
)

// PendingState describes a validated newer database that is being withheld
// because the configured pair cannot yet be published as one generation. It is
// set while Stats.LastResult == ReloadPending.
type PendingState struct {
	// At is when the pending condition was most recently observed.
	At time.Time
	// WaitingFor names the slot that blocks the commit: databaseCountry or
	// databaseASN.
	WaitingFor string
	// Reason is "missing" (the waiting database's file does not exist yet — a
	// download has not landed or the rotation is halfway through) or
	// "unchanged" (the partner was replaced this round but this file was not).
	Reason string
	// ReadyCountry/ReadyASN report which slot's NEW file validated and is held
	// back. In a two-database configuration exactly one is set.
	ReadyCountry bool
	ReadyASN     bool
	// Identity of the held-back candidate, so an operator can see what is
	// waiting without it ever being published.
	CountryType, ASNType           string
	CountryBuildTime, ASNBuildTime time.Time
}

// Pending reasons carried by PendingState.
const (
	pendingMissing   = "missing"
	pendingUnchanged = "unchanged"
)

// Stats is an absolute snapshot for the admin status page. report() emits the
// same counters as OTEL metrics.
type Stats struct {
	CountryHits, CountryMisses int64
	ASNHits, ASNMisses         int64
	Skipped                    int64
	CountryReloads, ASNReloads int64
	ReloadFailures             int64

	// Pair-generation accounting. PairReloads counts committed generations and
	// PendingReloads the scans that withheld an incomplete pair; Generation is
	// the committed generation number (0 before the first successful load).
	PairReloads    int64
	PendingReloads int64
	Generation     uint64
	Paired         bool
	PublishedAt    time.Time
	LastScanAt     time.Time
	// LastResult is one of the Reload* constants; empty before the first scan.
	LastResult  string
	LastError   string
	LastErrorAt time.Time
	// Pending describes the waiting update while LastResult == ReloadPending.
	Pending *PendingState

	// Downloads is the per-edition built-in downloader tally; empty when the
	// downloader is off.
	Downloads map[string]DownloadStatus

	// Loaded database identity, for the status page and the build-time gauge. A
	// zero build time means the database is not loaded. These always describe
	// the PUBLISHED generation, never a withheld candidate.
	CountryPath, ASNPath           string
	CountryType, ASNType           string
	CountryBuildTime, ASNBuildTime time.Time
}

// ReloadOutcome reports what one scan (an initial Open or a scheduled Reload)
// did.
type ReloadOutcome struct {
	// Changed reports whether a new generation was committed.
	Changed bool
	// Result is one of the Reload* constants.
	Result string
	// Generation is the committed generation after the scan.
	Generation uint64
	// Err joins the stat/read/parse errors when Result == ReloadFailed.
	Err error
}

// DB holds the loaded databases and swaps them atomically on Reload.
//
// The lock is a plain RWMutex rather than an atomic pointer pair. A lookup
// consults both databases and must see a consistent pair; the counters need
// guarding anyway; and an uncontended RLock is a couple of atomics, negligible
// beside the tree walk it guards. Correctness beats the nanosecond.
type DB struct {
	countryPath string
	asnPath     string

	mu      sync.RWMutex
	country *reader
	asn     *reader
	stats   stats

	// generation is the number of committed pairs; a publish of either slot
	// advances it. The rest is the latest scan's disposition, surfaced on the
	// status page so an operator can tell a published pair from a withheld
	// update and read why it was withheld. All guarded by mu.
	generation  uint64
	publishedAt time.Time
	lastScanAt  time.Time
	lastResult  string
	lastError   string
	lastErrorAt time.Time
	pending     *PendingState

	// reported is report()'s delta baseline; single-writer (the updater's
	// goroutine), guarded by mu like everything else.
	reported stats
}

// Open builds a DB from the configured paths and runs the SAME generation scan
// Reload runs, so startup loading has exactly the commit boundary a later tick
// has (and a process restart can never publish a half pair that a running
// process would have withheld):
//
//   - With both paths configured, both present files must validate together or
//     neither publishes. One present file next to a missing partner is a
//     pending pair (no error — a cold start's scheduled download may simply not
//     have landed yet); a present but unreadable partner is an error. In both
//     cases nothing serves until a later scan completes the pair.
//   - With one path configured, that database loads independently, as it
//     always has.
//
// A path that exists but is not a usable MaxMind database IS reported as an
// error rather than silently treated as "not downloaded yet": the operator
// pointed at something real and wrong, and hiding that would mask the mistake
// forever.
//
// The returned *DB is ALWAYS usable, even alongside a non-nil error: whatever
// generation published is serving, the configured paths are retained, and a
// later Reload picks corrected files up. A caller that wants to be strict can
// still treat the error as fatal; the app deliberately does not, because
// degraded enrichment must not become a failed startup.
func Open(opts Options) (*DB, error) {
	db := &DB{
		countryPath: opts.CountryPath,
		asnPath:     opts.ASNPath,
		stats:       stats{downloads: map[string]*downloadStats{}},
	}
	// The initial scan records its disposition for the status page but moves no
	// cumulative RELOAD counters — those count scans after startup.
	out := db.evaluate(db.scan(), false)
	return db, out.Err
}

// slotKind identifies one position in the pair.
type slotKind int

const (
	slotCountry slotKind = iota
	slotASN
)

func (k slotKind) name() string {
	if k == slotASN {
		return databaseASN
	}
	return databaseCountry
}

// slotDisposition is what one scan found at one configured path.
type slotDisposition int

const (
	// slotInactive: no path configured for this slot.
	slotInactive slotDisposition = iota
	// slotUnchanged: the file is present and its (mtime, size) matches the
	// reader the published generation holds — nothing to do.
	slotUnchanged
	// slotCandidate: the file is present, differs from what is published, and
	// has been read and parsed successfully THIS scan.
	slotCandidate
	// slotAbsent: the configured path does not exist (yet, or any more — a
	// deletion never unloads a published reader).
	slotAbsent
	// slotErrored: stat, read or parse failed; err says why.
	slotErrored
)

// slotPlan is one slot's scan result.
type slotPlan struct {
	kind slotKind
	disp slotDisposition
	next *reader // slotCandidate only
	err  error   // slotErrored only
}

// scan stats every configured path and validates each changed file. The slow
// reads and parses happen WITHOUT d.mu held; only the snapshot of the two
// committed pointers takes the lock, and the eventual commit takes the write
// lock once.
func (d *DB) scan() [2]slotPlan {
	d.mu.RLock()
	paths := [2]string{d.countryPath, d.asnPath}
	current := [2]*reader{d.country, d.asn}
	d.mu.RUnlock()
	return [2]slotPlan{
		planSlot(slotCountry, paths[0], current[0]),
		planSlot(slotASN, paths[1], current[1]),
	}
}

// planSlot stats path and, when it differs from the committed reader cur,
// reads and parses it into a validated candidate.
func planSlot(kind slotKind, path string, cur *reader) slotPlan {
	p := slotPlan{kind: kind}
	if path == "" {
		return p
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			p.disp = slotAbsent
			return p
		}
		p.disp = slotErrored
		p.err = fmt.Errorf("stat geoip database %s: %w", path, err)
		return p
	}
	if cur != nil && cur.mtime.Equal(fi.ModTime()) && cur.size == fi.Size() {
		p.disp = slotUnchanged
		return p
	}
	r, err := openAt(path, fi)
	if err != nil {
		p.disp = slotErrored
		p.err = err
		return p
	}
	p.disp = slotCandidate
	p.next = r
	return p
}

// evaluate is the single commit boundary shared by Open and Reload. count
// gates the cumulative reload counters (true for a scheduled scan, false for
// the startup load).
func (d *DB) evaluate(plans [2]slotPlan, count bool) ReloadOutcome {
	now := time.Now()
	active, candidates := 0, 0
	var errs []error
	var failedSlots []slotKind
	for i := range plans {
		p := &plans[i]
		if p.disp == slotInactive {
			continue
		}
		active++
		switch p.disp {
		case slotCandidate:
			candidates++
		case slotErrored:
			errs = append(errs, p.err)
			failedSlots = append(failedSlots, p.kind)
		}
	}

	// Any stat/read/parse error anywhere aborts the whole commit, regardless of
	// what else changed: the published pair is the fail-open fallback, and a
	// validated candidate on the sibling slot is closed rather than published
	// alone.
	if len(errs) > 0 {
		d.recordFailure(plans, failedSlots, now, errs, count)
		return ReloadOutcome{Result: ReloadFailed, Generation: d.generationValue(), Err: errors.Join(errs...)}
	}

	// No file differed: a pure stat tick. A stale pending/error disposition
	// clears, since the files that caused it are no longer offering an update.
	if candidates == 0 {
		d.recordUnchanged(now)
		return ReloadOutcome{Result: ReloadUnchanged, Generation: d.generationValue()}
	}

	// Paired mode: a generation publishes only when BOTH files validate in THIS
	// scan. One candidate next to a partner that is absent (a download not
	// landed, a rotation halfway through) or unchanged (only one half rotated
	// this round) is withheld as pending, and the published pair keeps serving.
	// The scan repeats on the next tick, so the withheld half gets another
	// chance and commits the moment the partner catches up.
	if active == 2 {
		for i := range plans {
			if plans[i].disp != slotCandidate {
				d.recordPending(plans, &plans[i], now, count)
				return ReloadOutcome{Result: ReloadPending, Generation: d.generationValue()}
			}
		}
	}

	// All clear: publish the candidates as one generation under a single write
	// lock. A lookup holding the RLock across both tree walks can never see one
	// swapped reader and one old reader.
	d.mu.Lock()
	old := [2]*reader{d.country, d.asn}
	for i := range plans {
		if plans[i].disp != slotCandidate {
			continue
		}
		switch plans[i].kind {
		case slotCountry:
			d.country = plans[i].next
			if count {
				d.stats.countryReloads++
			}
		case slotASN:
			d.asn = plans[i].next
			if count {
				d.stats.asnReloads++
			}
		}
	}
	d.generation++
	gen := d.generation
	d.publishedAt = now
	d.lastScanAt = now
	d.lastResult = ReloadPublished
	d.pending = nil
	d.lastError = ""
	if count {
		d.stats.pairPublishes++
	}
	// Close the displaced readers while the write lock is held: every lookup
	// walking one finished before the lock was acquired, and a reader created
	// afterwards sees the new pointer. OpenBytes owns a heap slice rather than
	// a mapping, and Close on it cannot fail.
	for i := range old {
		if plans[i].disp == slotCandidate && old[i] != nil {
			_ = old[i].db.Close()
		}
	}
	d.mu.Unlock()

	return ReloadOutcome{Changed: true, Result: ReloadPublished, Generation: gen}
}

// recordUnchanged marks a scan that found no differing file.
func (d *DB) recordUnchanged(now time.Time) {
	d.mu.Lock()
	d.lastScanAt = now
	d.lastResult = ReloadUnchanged
	d.pending = nil
	d.lastError = ""
	d.mu.Unlock()
}

// recordFailure rejects a scan: candidates validated this round are released
// unpublished, the failure is recorded per slot, and the published generation
// stays exactly where it was.
func (d *DB) recordFailure(plans [2]slotPlan, failedSlots []slotKind, now time.Time, errs []error, count bool) {
	for i := range plans {
		if plans[i].disp == slotCandidate {
			_ = plans[i].next.db.Close()
		}
	}
	failBySlot := map[slotKind]int64{}
	for _, k := range failedSlots {
		failBySlot[k]++
	}
	d.mu.Lock()
	d.lastScanAt = now
	d.lastResult = ReloadFailed
	d.lastError = errors.Join(errs...).Error()
	d.lastErrorAt = now
	d.pending = nil
	if count {
		d.stats.reloadFailures += int64(len(errs))
		d.stats.countryFailures += failBySlot[slotCountry]
		d.stats.asnFailures += failBySlot[slotASN]
	}
	d.mu.Unlock()
}

// recordPending withholds a scan whose candidate set is one half short of a
// pair. The validated candidate readers are closed after their identity is
// captured for the status page — they are re-validated from scratch on the next
// scan rather than cached, so a replaced file can never be missed.
func (d *DB) recordPending(plans [2]slotPlan, waiter *slotPlan, now time.Time, count bool) {
	st := &PendingState{
		At:         now,
		WaitingFor: waiter.kind.name(),
		Reason:     pendingUnchanged,
	}
	if waiter.disp == slotAbsent {
		st.Reason = pendingMissing
	}
	for i := range plans {
		p := &plans[i]
		if p.disp != slotCandidate {
			continue
		}
		md := p.next.db.Metadata
		switch p.kind {
		case slotCountry:
			st.ReadyCountry = true
			st.CountryType = md.DatabaseType
			st.CountryBuildTime = buildTime(md.BuildEpoch)
		case slotASN:
			st.ReadyASN = true
			st.ASNType = md.DatabaseType
			st.ASNBuildTime = buildTime(md.BuildEpoch)
		}
		_ = p.next.db.Close()
	}
	d.mu.Lock()
	d.lastScanAt = now
	d.lastResult = ReloadPending
	d.pending = st
	d.lastError = ""
	if count {
		d.stats.pendingReloads++
	}
	d.mu.Unlock()
}

func (d *DB) generationValue() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.generation
}

// openAt loads the database at path, whose already-taken stat result is fi (the
// callers all need it anyway, for the change check). See the package doc for why
// this reads the whole file rather than mapping it.
func openAt(path string, fi os.FileInfo) (*reader, error) {
	if fi.Size() > maxDatabaseBytes {
		return nil, fmt.Errorf("geoip database %s is %d bytes, above the %d-byte limit", path, fi.Size(), int64(maxDatabaseBytes))
	}
	b, err := safefile.ReadRegular(path, safefile.MaxDatabaseBytes, safefile.AllowSymlink)
	if err != nil {
		return nil, fmt.Errorf("read geoip database %s: %w", path, err)
	}
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, fmt.Errorf("open geoip database %s: %w", path, err)
	}
	return &reader{db: r, mtime: fi.ModTime(), size: fi.Size()}, nil
}

// Empty reports whether no database at all is loaded, so callers can skip work
// (and the app can log a startup notice) without probing with a lookup.
func (d *DB) Empty() bool {
	if d == nil {
		return true
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.country == nil && d.asn == nil
}

// Lookup returns what the loaded databases know about addr. The boolean reports
// whether any record was found — distinct from a found record whose fields are
// blank, so the caller can count a genuine miss.
//
// Addresses that are not globally routable (loopback, RFC 1918, link-local,
// multicast, and in particular the Tailscale CGNAT range and ULA) are skipped
// without consulting the databases. The MMDBs happen to hold no records for
// them, but making the contract depend on MaxMind's data rather than on our own
// code is exactly the kind of accident that turns into a tailnet-address leak
// when the data changes.
func (d *DB) Lookup(addr netip.Addr) (Result, bool) {
	if d == nil {
		return Result{}, false
	}
	if !Enrichable(addr) {
		d.mu.Lock()
		d.stats.skipped++
		d.mu.Unlock()
		return Result{}, false
	}

	d.mu.RLock()
	var (
		res   Result
		found bool
		crec  countryRecord
		arec  asnRecord
		chit  bool
		ahit  bool
	)
	if d.country != nil {
		if r := d.country.db.Lookup(addr); r.Found() {
			if err := r.Decode(&crec); err == nil {
				chit = true
			}
		}
	}
	if d.asn != nil {
		if r := d.asn.db.Lookup(addr); r.Found() {
			if err := r.Decode(&arec); err == nil {
				ahit = true
			}
		}
	}
	d.mu.RUnlock()

	if chit {
		res.CountryISO, res.ContinentCode = countryFrom(crec)
		res.City, res.RegionISO, res.Latitude, res.Longitude, res.HasLocation = cityFrom(crec)
		found = true
	}
	if ahit {
		res.ASN, res.ASOrg = arec.Number, arec.Org
		found = true
	}

	d.mu.Lock()
	if d.country != nil {
		if chit {
			d.stats.countryHits++
		} else {
			d.stats.countryMisses++
		}
	}
	if d.asn != nil {
		if ahit {
			d.stats.asnHits++
		} else {
			d.stats.asnMisses++
		}
	}
	d.mu.Unlock()

	return res, found
}

// Reload re-stats each configured path and runs the generation commit
// boundary: with both databases configured the two files publish together only
// when both validate in this scan (see evaluate), so an operator's geoipupdate
// cron, a non-atomic two-file rotation, or this package's own per-edition
// downloader can never leave lookups stitching a new country to an old ASN.
//
// Change detection is (mtime, size) rather than a content hash so the common
// case (nothing changed) costs one stat per file instead of re-reading tens of
// megabytes on every tick. A rewrite that preserves both within the filesystem's
// timestamp granularity would be missed until the next genuine change; the
// downloader renames a freshly-written file into place, so in practice mtime
// always moves.
//
// Every failure mode is fail-open: a pending (incomplete pair) or failed
// (unreadable file) scan leaves the published generation serving and retries on
// the next tick. A failed scan's errors are joined so one bad file does not
// hide the other.
func (d *DB) Reload() ReloadOutcome {
	if d == nil {
		return ReloadOutcome{Result: ReloadUnchanged}
	}
	out := d.evaluate(d.scan(), true)
	if out.Err != nil {
		out.Err = fmt.Errorf("reload geoip databases: %w", out.Err)
	}
	return out
}

// Stats returns an absolute snapshot of the counters and the loaded databases'
// identity, for the admin status page.
func (d *DB) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	s := Stats{
		CountryHits:    d.stats.countryHits,
		CountryMisses:  d.stats.countryMisses,
		ASNHits:        d.stats.asnHits,
		ASNMisses:      d.stats.asnMisses,
		Skipped:        d.stats.skipped,
		CountryReloads: d.stats.countryReloads,
		ASNReloads:     d.stats.asnReloads,
		ReloadFailures: d.stats.reloadFailures,
		PairReloads:    d.stats.pairPublishes,
		PendingReloads: d.stats.pendingReloads,
		Generation:     d.generation,
		Paired:         d.countryPath != "" && d.asnPath != "",
		PublishedAt:    d.publishedAt,
		LastScanAt:     d.lastScanAt,
		LastResult:     d.lastResult,
		LastError:      d.lastError,
		LastErrorAt:    d.lastErrorAt,
		CountryPath:    d.countryPath,
		ASNPath:        d.asnPath,
	}
	if d.pending != nil {
		pc := *d.pending
		s.Pending = &pc
	}
	if len(d.stats.downloads) > 0 {
		s.Downloads = make(map[string]DownloadStatus, len(d.stats.downloads))
		for edition, ds := range d.stats.downloads {
			s.Downloads[edition] = DownloadStatus{
				Updated:    ds.updated,
				Unmodified: ds.unmodified,
				Failures:   ds.failures,
				LastResult: ds.lastResult,
				LastError:  ds.lastError,
				LastAt:     ds.lastAt,
			}
		}
	}
	if d.country != nil {
		md := d.country.db.Metadata
		s.CountryType = md.DatabaseType
		s.CountryBuildTime = buildTime(md.BuildEpoch)
	}
	if d.asn != nil {
		md := d.asn.db.Metadata
		s.ASNType = md.DatabaseType
		s.ASNBuildTime = buildTime(md.BuildEpoch)
	}
	return s
}

// Report flushes the cumulative counters as OTEL counter DELTAS (since the last
// report) plus the current build-time gauges. It is a no-op for a nil emitter or
// a nil DB. Only the updater's single goroutine calls it in production, so the
// delta baseline has one writer.
func (d *DB) Report(e telemetry.Emitter) {
	if d == nil || e == nil {
		return
	}
	d.mu.Lock()
	cur := d.stats
	prev := d.reported
	d.reported = cur
	paired := d.countryPath != "" && d.asnPath != ""
	countryLoaded, asnLoaded := d.country != nil, d.asn != nil
	var countryBuild, asnBuild time.Time
	if countryLoaded {
		countryBuild = buildTime(d.country.db.Metadata.BuildEpoch)
	}
	if asnLoaded {
		asnBuild = buildTime(d.asn.db.Metadata.BuildEpoch)
	}
	d.mu.Unlock()

	delta := func(metric string, doc metricdoc.Metric, attrs telemetry.Attrs, now, before int64) {
		if n := now - before; n > 0 {
			e.Counter(metric, doc.Unit, doc.Description, float64(n), attrs)
		}
	}
	delta(MetricLookups, docLookups, telemetry.Attrs{attrDatabase: databaseCountry, attrResult: resultHit}, cur.countryHits, prev.countryHits)
	delta(MetricLookups, docLookups, telemetry.Attrs{attrDatabase: databaseCountry, attrResult: resultMiss}, cur.countryMisses, prev.countryMisses)
	delta(MetricLookups, docLookups, telemetry.Attrs{attrDatabase: databaseASN, attrResult: resultHit}, cur.asnHits, prev.asnHits)
	delta(MetricLookups, docLookups, telemetry.Attrs{attrDatabase: databaseASN, attrResult: resultMiss}, cur.asnMisses, prev.asnMisses)
	delta(MetricLookups, docLookups, telemetry.Attrs{attrDatabase: databaseSkipped, attrResult: resultSkipped}, cur.skipped, prev.skipped)

	// Per-database swaps inside committed generations.
	delta(MetricReloads, docReloads, telemetry.Attrs{attrDatabase: databaseCountry, attrResult: resultSuccess}, cur.countryReloads, prev.countryReloads)
	delta(MetricReloads, docReloads, telemetry.Attrs{attrDatabase: databaseASN, attrResult: resultSuccess}, cur.asnReloads, prev.asnReloads)
	// Failures are attributed to the file that failed to stat/read/parse.
	delta(MetricReloads, docReloads, telemetry.Attrs{attrDatabase: databaseCountry, attrResult: resultFailure}, cur.countryFailures, prev.countryFailures)
	delta(MetricReloads, docReloads, telemetry.Attrs{attrDatabase: databaseASN, attrResult: resultFailure}, cur.asnFailures, prev.asnFailures)
	// Pair-level outcomes exist only with both databases configured: one
	// generation committed, or one withheld until the pair completes.
	if paired {
		delta(MetricReloads, docReloads, telemetry.Attrs{attrDatabase: databasePair, attrResult: resultSuccess}, cur.pairPublishes, prev.pairPublishes)
		delta(MetricReloads, docReloads, telemetry.Attrs{attrDatabase: databasePair, attrResult: resultPending}, cur.pendingReloads, prev.pendingReloads)
	}

	// Build time is a gauge of MaxMind's build date, not the download time, so
	// it is the correct staleness signal. It follows the PUBLISHED generation:
	// a withheld (pending or failed) update never moves it, so an alert fires
	// against what lookups actually use, never against a file that is waiting
	// to be committed. Omitted entirely for a database that is not loaded — a
	// zero would read as "built in 1970" and fire every staleness alert ever
	// written against it.
	if countryLoaded {
		e.Gauge(MetricBuildTime, docBuildTime.Unit, docBuildTime.Description,
			float64(countryBuild.Unix()), telemetry.Attrs{attrDatabase: databaseCountry})
	}
	if asnLoaded {
		e.Gauge(MetricBuildTime, docBuildTime.Unit, docBuildTime.Description,
			float64(asnBuild.Unix()), telemetry.Attrs{attrDatabase: databaseASN})
	}
}

// ObserveDownload records the outcome of one edition's download attempt in the
// per-edition tally (so the status page shows it with self-observability off)
// and, with a non-nil emitter, as one downloads counter point. It is safe on a
// nil DB, so the updater can call it unconditionally.
func (d *DB) ObserveDownload(e telemetry.Emitter, edition string, res DownloadResult, err error) {
	result := resultUpdated
	switch {
	case err != nil:
		result = resultFailure
	case !res.Updated:
		result = resultUnmodified
	}
	if d != nil {
		d.mu.Lock()
		ds := d.stats.downloads[edition]
		if ds == nil {
			ds = &downloadStats{}
			d.stats.downloads[edition] = ds
		}
		ds.lastAt = time.Now()
		ds.lastResult = result
		switch result {
		case resultUpdated:
			ds.updated++
		case resultUnmodified:
			ds.unmodified++
		default:
			// The fetch error carries no credential or response body by
			// construction (see Downloader.get); it is local operator evidence
			// of the same class as a collector's last error on this page.
			ds.failures++
			ds.lastError = err.Error()
		}
		d.mu.Unlock()
	}
	if e == nil {
		return
	}
	e.Counter(MetricDownloads, docDownloads.Unit, docDownloads.Description, 1,
		telemetry.Attrs{attrEdition: edition, attrResult: result})
}

// Close releases the loaded databases.
func (d *DB) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeReadersLocked()
}

func (d *DB) closeReadersLocked() {
	if d.country != nil {
		_ = d.country.db.Close() // see the Reload comment: cannot fail for OpenBytes
		d.country = nil
	}
	if d.asn != nil {
		_ = d.asn.db.Close()
		d.asn = nil
	}
}

// buildTime converts an mmdb metadata build epoch to a time.
//
// BuildEpoch is a uint the database file supplies, so a corrupt or hostile file
// could carry a value past math.MaxInt64. Converting that unchecked wraps to a
// negative, which would surface as a build date in 1901 and fire the staleness
// alert permanently. Anything that absurd is treated as "unknown" (zero), which
// callers already handle by omitting the gauge entirely.
func buildTime(epoch uint) time.Time {
	if epoch > math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(int64(epoch), 0).UTC()
}

// Enrichable reports whether addr is a globally routable unicast address worth
// looking up. Everything else — loopback, unspecified, link-local, multicast,
// RFC 1918 / unique-local, and the RFC 6598 CGNAT range Tailscale carves tailnet
// IPv4 addresses out of — is skipped.
//
// An IPv4-mapped IPv6 address is unwrapped first: ::ffff:192.168.1.1 is a
// private address wearing a v6 costume, and netip's predicates would not see
// through it.
func Enrichable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	switch {
	case addr.IsUnspecified(), addr.IsLoopback(), addr.IsMulticast(),
		addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(), addr.IsPrivate():
		return false
	case enrich.IsTailscaleAddr(addr):
		// The shared default set keeps "never geolocate a tailnet address"
		// explicit. Its ULA is already covered by IsPrivate, while CGNAT is not.
		return false
	}
	return addr.IsGlobalUnicast()
}
