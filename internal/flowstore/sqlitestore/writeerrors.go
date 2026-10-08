package sqlitestore

import (
	"context"
	"errors"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// classifyWriteError decides whether a failed write attempt is transient —
// worth another attempt with the same batch: SQLITE_BUSY, SQLITE_LOCKED,
// SQLITE_INTERRUPT, a lock-protocol error, a stale prepared statement, or the
// attempt's own context deadline. Everything else (I/O error, full disk or
// quota, corruption, read-only database, constraint) is treated as not
// recoverable by retrying and is recorded as a declared loss.
//
// Classification prefers the concrete *sqlite.Error code (the extended code's
// primary byte) and falls back to bounded message markers for errors that do
// not carry the type (wrapped driver errors, test faults).
func classifyWriteError(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() & 0xff {
		case sqlite3.SQLITE_BUSY,
			sqlite3.SQLITE_LOCKED,
			sqlite3.SQLITE_INTERRUPT,
			sqlite3.SQLITE_PROTOCOL,
			sqlite3.SQLITE_SCHEMA:
			return true
		default:
			return false
		}
	}
	// A context timeout on the attempt is rebuilt on retry; an explicit cancel
	// (shutdown) is not.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, marker := range transientMessageMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

var transientMessageMarkers = []string{
	"SQLITE_BUSY",
	"SQLITE_LOCKED",
	"SQLITE_INTERRUPT",
	"SQLITE_PROTOCOL",
	"SQLITE_SCHEMA",
	"database is locked",
	"deadlock",
}
