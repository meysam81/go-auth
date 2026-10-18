package sqlitestore_test

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/examples/sqlitestore"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

// warmConns is how many connections newDB opens before a test runs: the
// callers of the suites' largest concurrent subtest.
const warmConns = 32

// newDB returns a migrated database in a file of its own, with warmConns
// connections already open in its pool. The suites' concurrency subtests
// prove something only when their callers run on separate SQLite connections
// at the same time, contending for the write lock as an application's pool
// does:
//
//   - A temporary file in WAL mode, not a shared-cache in-memory database,
//     whose connections serialize on table locks and fail with SQLITE_LOCKED,
//     which busy_timeout does not wait out.
//   - Connections opened in advance and kept idle. database/sql keeps two idle
//     connections by default, so each caller of a race would open a fresh
//     one, and opening one takes longer than a Take does: the first caller
//     finishes before the next starts, and a SELECT-then-UPDATE Take passes
//     ConcurrentTake_OneWinner.
func newDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()
	db, err := sqlitestore.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})
	if err = sqlitestore.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	db.SetMaxIdleConns(warmConns)
	conns := make([]*sql.Conn, 0, warmConns)
	for range warmConns {
		c, connErr := db.Conn(ctx) // held, so each call opens another connection
		if connErr != nil {
			t.Fatalf("open connection: %v", connErr)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		if closeErr := c.Close(); closeErr != nil { // back to the idle pool
			t.Fatalf("release connection: %v", closeErr)
		}
	}
	return db
}

func newFlowStore(t *testing.T, cfg sqlitestore.Config) *sqlitestore.FlowStore {
	t.Helper()
	if cfg.DB == nil {
		cfg.DB = newDB(t)
	}
	s, err := sqlitestore.NewFlowStore(cfg)
	if err != nil {
		t.Fatalf("NewFlowStore: %v", err)
	}
	return s
}

func newWebAuthnStore(t *testing.T, db *sql.DB) *sqlitestore.WebAuthnStore {
	t.Helper()
	if db == nil {
		db = newDB(t)
	}
	s, err := sqlitestore.NewWebAuthnStore(sqlitestore.Config{DB: db})
	if err != nil {
		t.Fatalf("NewWebAuthnStore: %v", err)
	}
	return s
}

var subjectSeq atomic.Int64

func newSubject(*testing.T) string { return fmt.Sprintf("subject-%d", subjectSeq.Add(1)) }

func TestFlowStore_PassesSuite(t *testing.T) {
	t.Parallel()
	authtest.FlowStoreSuite(func(t *testing.T) store.FlowStore {
		return newFlowStore(t, sqlitestore.Config{})
	})(t)
}

func TestWebAuthnStore_PassesSuite(t *testing.T) {
	t.Parallel()
	authtest.WebAuthnStoreSuite(authtest.WebAuthnHarness{
		NewStores: func(t *testing.T) (webauthn.CredentialStore, webauthn.HandleStore) {
			s := newWebAuthnStore(t, nil)
			return s, s
		},
		NewSubject: newSubject,
	})(t)
}

// registered is a credential shaped as webauthn.FinishRegistration stores it:
// never used, no transports reported, no credProps, a zero counter.
func registered(subject string) webauthn.Credential {
	return webauthn.Credential{
		Version:   webauthn.CurrentVersion,
		ID:        []byte{0x01, 0x02, 0x03, 0x04},
		Subject:   subject,
		RPID:      "example.test",
		PublicKey: []byte{0xa5, 0x01, 0x02},
		Algorithm: -7,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// sameCredential reports whether a and b match field for field, comparing
// times as instants.
func sameCredential(a, b webauthn.Credential) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) || !a.LastUsedAt.Equal(b.LastUsedAt) || !a.CloneSuspectedAt.Equal(b.CloneSuspectedAt) {
		return false
	}
	a.CreatedAt, a.LastUsedAt, a.CloneSuspectedAt = time.Time{}, time.Time{}, time.Time{}
	b.CreatedAt, b.LastUsedAt, b.CloneSuspectedAt = time.Time{}, time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

func listOne(t *testing.T, s *sqlitestore.WebAuthnStore, subject string) webauthn.Credential {
	t.Helper()
	got, err := s.List(t.Context(), subject, "example.test")
	if err != nil || len(got) != 1 {
		t.Fatalf("List = (%d credentials, %v), want (1, nil)", len(got), err)
	}
	return got[0]
}

// The suites fill every field, so they never store what a registration does:
// a zero LastUsedAt (NULL) and nil Transports, which json.Marshal writes as
// null, not an array.
func TestCredential_AsRegisteredRoundTrips(t *testing.T) {
	t.Parallel()
	s := newWebAuthnStore(t, nil)
	want := registered(newSubject(t))
	if err := s.Insert(t.Context(), want); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if got := listOne(t, s, want.Subject); !sameCredential(got, want) {
		t.Fatalf("List = %+v, want %+v", got, want)
	}
}

// The suites use whole-second UTC-equivalent instants; a real clock carries
// nanoseconds and the caller's zone.
func TestTimes_TruncatedToPrecisionAndReadInUTC(t *testing.T) {
	t.Parallel()
	zone := time.FixedZone("+05:45", 5*3600+45*60)
	at := func(h int) time.Time { return time.Date(2026, 1, 2, h, 4, 5, 123456789, zone) }
	want := func(in time.Time) time.Time { return in.Truncate(sqlitestore.TimePrecision).UTC() }
	check := func(t *testing.T, field string, got, in time.Time) {
		t.Helper()
		if !got.Equal(want(in)) || got.Location() != time.UTC {
			t.Errorf("%s = %v, want %v (%s precision, in UTC)", field, got, want(in), sqlitestore.TimePrecision)
		}
	}

	t.Run("Flow", func(t *testing.T) {
		t.Parallel()
		s := newFlowStore(t, sqlitestore.Config{Now: func() time.Time { return at(1) }})
		if err := s.Put(t.Context(), "flow", store.Flow{Kind: "k", Payload: []byte("p"), ExpiresAt: at(2)}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Take(t.Context(), "flow")
		if err != nil {
			t.Fatalf("Take: %v", err)
		}
		check(t, "ExpiresAt", got.ExpiresAt, at(2))
	})

	t.Run("Credential", func(t *testing.T) {
		t.Parallel()
		s := newWebAuthnStore(t, nil)
		c := registered(newSubject(t))
		c.CreatedAt, c.LastUsedAt, c.CloneSuspectedAt = at(1), at(2), at(3)
		if err := s.Insert(t.Context(), c); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		got := listOne(t, s, c.Subject)
		check(t, "CreatedAt", got.CreatedAt, c.CreatedAt)
		check(t, "LastUsedAt", got.LastUsedAt, c.LastUsedAt)
		check(t, "CloneSuspectedAt", got.CloneSuspectedAt, c.CloneSuspectedAt)
	})
}

// Expiry is exclusive and decided at the stored precision: a sub-microsecond
// remainder is truncated away, so a flow expires early, never late.
func TestTake_ExpiryAtStoredPrecision(t *testing.T) {
	t.Parallel()
	// 999 ns past the stored microsecond, and off the whole second, so a store
	// that compares in seconds keeps the flow alive past its expiry and fails.
	expires := time.Date(2026, 1, 2, 3, 4, 5, 123456999, time.UTC)
	for name, tc := range map[string]struct {
		now   time.Time
		found bool
	}{
		"one microsecond before":        {expires.Add(-time.Microsecond), true},
		"inside the truncated fraction": {expires.Add(-time.Nanosecond), false},
		"at expiry":                     {expires, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newFlowStore(t, sqlitestore.Config{Now: func() time.Time { return tc.now }})
			if err := s.Put(t.Context(), "flow", store.Flow{Kind: "k", ExpiresAt: expires}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			_, err := s.Take(t.Context(), "flow")
			if found := err == nil; found != tc.found || (!found && !errors.Is(err, store.ErrNotFound)) {
				t.Fatalf("Take at %v of a flow expiring %v: error = %v, want found = %v", tc.now, expires, err, tc.found)
			}
		})
	}
}

// A nil []byte binds as SQL NULL; the payload column is NOT NULL.
func TestFlow_EmptyPayloadRoundTrips(t *testing.T) {
	t.Parallel()
	s := newFlowStore(t, sqlitestore.Config{})
	if err := s.Put(t.Context(), "flow", store.Flow{Kind: "k", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Put of a nil payload: %v", err)
	}
	got, err := s.Take(t.Context(), "flow")
	if err != nil || len(got.Payload) != 0 {
		t.Fatalf("Take = (%d-byte payload, %v), want (0, nil)", len(got.Payload), err)
	}
}

// Only the key a statement means maps to store.ErrDuplicate. SQLite words a
// PRIMARY KEY and a UNIQUE index violation alike ("UNIQUE constraint
// failed"), so a store that matched the message would report an
// application's own unique index, or a CHECK, as a credential ID already
// registered.
func TestErrDuplicate_OnlyForTheKey(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := newDB(t)
	s := newWebAuthnStore(t, db)
	flows := newFlowStore(t, sqlitestore.Config{DB: db})
	notDuplicate := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil || errors.Is(err, store.ErrDuplicate) {
			t.Errorf("%s: error = %v, want a non-nil error that is not store.ErrDuplicate", what, err)
		}
	}

	if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX app_one_key_per_subject ON webauthn_credentials (subject, public_key)`); err != nil {
		t.Fatalf("create the application's index: %v", err)
	}
	c := registered(newSubject(t))
	if err := s.Insert(ctx, c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	sameKey := c
	sameKey.ID = []byte{0x09}
	notDuplicate(t, "Insert against an application's unique index", s.Insert(ctx, sameKey))

	tooLong := registered(newSubject(t))
	tooLong.ID = make([]byte, 1024)
	notDuplicate(t, "Insert of a 1024-byte credential ID (CHECK)", s.Insert(ctx, tooLong))

	unset := registered(newSubject(t))
	unset.ID = []byte{0x0a}
	unset.CreatedAt = time.Time{}
	notDuplicate(t, "Insert with a zero CreatedAt (NOT NULL)", s.Insert(ctx, unset))

	notDuplicate(t, "Put with a zero ExpiresAt (NOT NULL)", flows.Put(ctx, "flow", store.Flow{Kind: "k"}))

	// The handle's own unique index, which Ensure's upsert on the subject does
	// not cover, is a duplicate.
	owner, other := newSubject(t), newSubject(t)
	handle := []byte("handle-of-the-owner")
	if _, err := s.Ensure(ctx, owner, handle); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := s.Ensure(ctx, other, handle); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("Ensure of a handle another subject holds: error = %v, want store.ErrDuplicate", err)
	}
	if got, err := s.Subject(ctx, handle); err != nil || got != owner {
		t.Errorf("Subject after the refused Ensure = (%q, %v), want %q", got, err, owner)
	}
}

// The suites mark only a credential that exists.
func TestMarkCloneSuspected_RefusesUnknownAndZero(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := newWebAuthnStore(t, nil)
	c := registered(newSubject(t))
	if err := s.Insert(ctx, c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := s.MarkCloneSuspected(ctx, newSubject(t), c.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("MarkCloneSuspected under another subject: error = %v, want store.ErrNotFound", err)
	}
	if err := s.MarkCloneSuspected(ctx, c.Subject, c.ID, time.Time{}); err == nil {
		t.Errorf("MarkCloneSuspected with a zero time: error = nil, want a refusal")
	}
	if got := listOne(t, s, c.Subject); !got.CloneSuspectedAt.IsZero() {
		t.Errorf("CloneSuspectedAt = %v after refused marks, want zero", got.CloneSuspectedAt)
	}
}

// Every connection of the pool opens the path; these would each get a
// database of their own, and miss the tables Migrate created on another.
func TestOpen_RefusesPerConnectionDatabases(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", ":memory:"} {
		if db, err := sqlitestore.Open(t.Context(), path); err == nil {
			t.Errorf("Open(%q) error = nil, want a refusal", path)
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("Close: %v", closeErr)
			}
		}
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	t.Parallel()
	if err := sqlitestore.Migrate(t.Context(), newDB(t)); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}
