package sqlitestore

import (
	"context"
	"database/sql"
	_ "embed" // schema.sql is embedded into schema
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// TimePrecision is the resolution of every stored time. A time is truncated
// to it on the way in, toward the past, so a flow can only expire earlier than
// asked, never later; it is read back as the same instant in UTC.
const TimePrecision = time.Microsecond

// busyTimeout is how long a connection waits for SQLite's write lock before
// failing with SQLITE_BUSY.
const busyTimeout = 5 * time.Second

//go:embed schema.sql
var schema string

// Config configures the stores.
type Config struct {
	// DB is the database, migrated with [Migrate]. Required. Open it with
	// [Open], or with the connection settings Open documents.
	DB *sql.DB
	// Now is the clock [FlowStore] checks expiry against; nil means
	// [time.Now]. [WebAuthnStore] reads no clock: it stores the times the
	// library passes it.
	Now func() time.Time
}

// Open opens the SQLite database file at path, creating it when missing, with
// the connection settings the stores rely on. The settings travel in the DSN,
// so database/sql applies them to every connection in its pool; a PRAGMA run
// once through db.Exec reaches only the connection that happened to run it.
//
//   - busy_timeout: a writer waits up to five seconds for the write lock
//     instead of failing at once with SQLITE_BUSY, which concurrent Takes,
//     Inserts and Ensures would otherwise see.
//   - journal_mode=WAL: readers do not block the writer, nor it them.
//   - synchronous=FULL: a commit is on disk before it returns. A consumed
//     flow lost to a power cut could be taken a second time.
//   - _txlock=immediate: a transaction takes the write lock at BEGIN, where
//     the busy timeout covers it. A deferred transaction that reads and then
//     writes fails with SQLITE_BUSY, without waiting, when another
//     connection wrote in between. The stores use single statements; this is
//     for [Migrate] and for transactions an application adds.
//   - foreign_keys: on, for an application whose tables reference its users.
//
// path must name a file. An empty path or ":memory:" is refused: each
// connection in the pool would open a database of its own.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" || path == ":memory:" {
		return nil, fmt.Errorf("sqlitestore: open %q: a database file is required", path)
	}
	q := url.Values{}
	q.Set("_busy_timeout", strconv.FormatInt(busyTimeout.Milliseconds(), 10))
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "FULL")
	q.Set("_txlock", "immediate")
	q.Set("_foreign_keys", "1")
	// A file: URI with an escaped path, so a '?' or '#' in path stays part of
	// the file name instead of starting the parameters.
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open %s: %w", path, err)
	}
	// Connect once now, so a bad path or setting fails here rather than at
	// the first query.
	if pingErr := db.PingContext(ctx); pingErr != nil {
		return nil, fmt.Errorf("sqlitestore: open %s: %w", path, errors.Join(pingErr, db.Close()))
	}
	return db, nil
}

// Migrate applies schema.sql to db in one transaction. Applying it to a
// migrated database changes nothing.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: migrate: %w", err)
	}
	if _, execErr := tx.ExecContext(ctx, schema); execErr != nil {
		return fmt.Errorf("sqlitestore: migrate: %w", errors.Join(execErr, tx.Rollback()))
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: migrate: commit: %w", err)
	}
	return nil
}

// primaryKeyViolation and uniqueViolation tell the two constraint failures
// the stores map to [store.ErrDuplicate] apart by extended result code
// (modernc.org/sqlite enables extended codes on every connection), never by
// message. SQLite words both "UNIQUE constraint failed", but a primary key
// reports SQLITE_CONSTRAINT_PRIMARYKEY, so each statement maps exactly the key
// it means. A CHECK or NOT NULL failure, or a unique index an application
// adds, stays an ordinary error. They and [Open] are the driver-specific code
// a port replaces; on PostgreSQL, compare the error's constraint name.
func primaryKeyViolation(err error) bool {
	return resultCode(err) == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

func uniqueViolation(err error) bool {
	return resultCode(err) == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

// resultCode returns the extended result code of a SQLite error, or 0.
func resultCode(err error) int {
	if e, ok := errors.AsType[*sqlite.Error](err); ok {
		return e.Code()
	}
	return 0
}

// timeArg encodes t for a time column: Unix microseconds, or NULL for the
// zero time. A NOT NULL column refuses the zero time.
func timeArg(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMicro(), Valid: true}
}

// timeOf decodes a time column: the instant in UTC, or the zero time for NULL.
func timeOf(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMicro(v.Int64).UTC()
}
