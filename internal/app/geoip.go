package app

import (
	"net/http"
	"time"

	"github.com/rknightion/tailscale2otel/v5/internal/geoip"
)

// buildGeoIP loads the configured MaxMind databases and, when the built-in
// downloader is enabled, wires the update loop that keeps them current.
//
// It never fails startup. Enrichment is a nicety: a missing database, an
// unreadable path or a MaxMind outage all degrade to "no geo attributes", which
// is exactly what running without the feature looks like. The only case that is
// worth shouting about is a file that exists and is not a database, and even
// that is a WARN here — Config.Validate has already rejected the configurations
// that are wrong on their face.
func (a *App) buildGeoIP() {
	g := a.cfg.Enrichment.GeoIP
	if !g.Enabled {
		return
	}
	logger := withComponent(a.logger, compGeoIP)

	db, err := geoip.Open(geoip.Options{
		CountryPath: g.CountryDatabase,
		ASNPath:     g.ASNDatabase,
	})
	if err != nil {
		// Open only reports a present, unusable file, and it still returns a
		// working DB. With both paths configured the bad half blocks the good
		// one too (one commit boundary); the paths are retained so the reload
		// tick publishes the complete pair once the bad file is replaced.
		logger.Warn("a geoip database could not be loaded; no half-loaded pair is serving, and the reload tick will publish both databases once the bad file is replaced",
			"error", err)
	}
	a.geoDB = db

	var fetcher geoip.Fetcher
	if g.Download.Enabled {
		fetcher = &geoip.Downloader{
			AccountID:  g.Download.AccountID,
			LicenseKey: g.Download.LicenseKey.Reveal(),
			Endpoint:   g.Download.Endpoint,
			Dir:        g.Download.Directory,
			Timeout:    g.Download.Timeout.D(),
			Client:     &http.Client{Timeout: geoDownloadClientTimeout(g.Download.Timeout.D())},
		}
	}
	opts := geoip.UpdaterOptions{
		DB:               a.geoDB,
		Fetcher:          fetcher,
		Editions:         g.Download.Editions,
		DownloadInterval: g.Download.Interval.D(),
		ReloadInterval:   g.ReloadInterval.D(),
		Logger:           logger,
	}
	// GeoIP is shared infra across tailnets, so its self-obs rides the process
	// provider — same treatment as the reverse-DNS cache. The status page reads
	// Stats() directly and shows the same numbers either way.
	if a.cfg.SelfObservability.Enabled {
		opts.Emitter = a.procEmitter
	}
	a.geoUpdater = geoip.NewUpdater(opts)

	if a.geoDB.Empty() && !g.Download.Enabled {
		args := []any{
			"country_database", g.CountryDatabase, "asn_database", g.ASNDatabase,
			"reload_interval", g.ReloadInterval.D(),
		}
		// With both paths configured one present file next to a missing partner
		// is withheld as a pending pair rather than half-loaded; say which half
		// the operator still owes the process.
		if s := a.geoDB.Stats(); s.Pending != nil {
			logger.Warn("geoip is enabled but the database pair is not complete; flow records will carry no geo attributes until both files validate in one scan",
				append(args, "waiting_for", s.Pending.WaitingFor, "reason", s.Pending.Reason)...)
		} else {
			logger.Warn("geoip is enabled but no database is loaded yet; flow records will carry no geo attributes", args...)
		}
	}
}

// geoDownloadClientTimeout bounds the whole HTTP exchange as a backstop to the
// per-fetch context deadline. It is deliberately looser than the configured
// timeout: the context is the real limit, and a client timeout that fired first
// would report a confusing error for a limit the operator never set.
func geoDownloadClientTimeout(fetchTimeout time.Duration) time.Duration {
	if fetchTimeout <= 0 {
		return 10 * time.Minute
	}
	return fetchTimeout + time.Minute
}
