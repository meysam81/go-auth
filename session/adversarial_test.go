package session

import (
	"context"
	"encoding/base64"
	"errors"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meysam81/go-auth/storage"
)

// This file is the adversarial half of the session test program
// (docs/security-hardening.md section 6, "Session"). Every test here names the
// attack it defends against and is written to fail if the corresponding fix is
// reverted. The happy path is tested elsewhere.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// laxSessionStore is a SessionStore that never enforces its own TTL, hands out
// whatever it was given, and can be told to fail a delete.
//
// Every one of those behaviors occurs in production stores: a Redis key whose
// EXPIRE was lost to a failed replication, a SQL row a cleanup job has not
// reached, a cache serving a stale entry under memory pressure, a replica that
// accepts reads while refusing writes. The Manager therefore may not delegate
// the expiry verdict to the store, and may not treat a failed delete as success.
type laxSessionStore struct {
	mu sync.Mutex

	entries map[string]*storage.SessionData
	// graveyard keeps what DeleteSession removed, so a test can prove that a
	// rotated session shares no memory with the entry it replaced.
	graveyard map[string]*storage.SessionData
	deletes   []string

	createErr    error
	deleteErrFor func(sessionID string) error
	// aliasReads makes the store hand back its own pointer instead of a copy --
	// the behavior cloneSessionData exists to survive.
	aliasReads bool
}

func newLaxSessionStore() *laxSessionStore {
	return &laxSessionStore{
		entries:   make(map[string]*storage.SessionData),
		graveyard: make(map[string]*storage.SessionData),
	}
}

// seed writes an entry directly, bypassing the Manager, so a test can present a
// session the store considers live and the clock does not.
func (s *laxSessionStore) seed(sessionID string, data *storage.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[sessionID] = data
}

func (s *laxSessionStore) entry(sessionID string) *storage.SessionData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[sessionID]
}

func (s *laxSessionStore) buried(sessionID string) *storage.SessionData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.graveyard[sessionID]
}

func (s *laxSessionStore) live() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return ids
}

func (s *laxSessionStore) deleteCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deletes...)
}

func (s *laxSessionStore) CreateSession(_ context.Context, sessionID string, data *storage.SessionData, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.createErr != nil {
		return s.createErr
	}

	stored := data
	if !s.aliasReads {
		copied := *data
		stored = &copied
	}
	s.entries[sessionID] = stored

	return nil
}

func (s *laxSessionStore) GetSession(_ context.Context, sessionID string) (*storage.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.entries[sessionID]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// Deliberately no expiry check: that is the whole point of this fixture.
	if s.aliasReads {
		return data, nil
	}
	copied := *data

	return &copied, nil
}

func (s *laxSessionStore) UpdateSession(_ context.Context, sessionID string, data *storage.SessionData, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.entries[sessionID]; !ok {
		return storage.ErrNotFound
	}
	copied := *data
	s.entries[sessionID] = &copied

	return nil
}

func (s *laxSessionStore) DeleteSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deletes = append(s.deletes, sessionID)

	if s.deleteErrFor != nil {
		if err := s.deleteErrFor(sessionID); err != nil {
			return err
		}
	}

	if data, ok := s.entries[sessionID]; ok {
		s.graveyard[sessionID] = data
		delete(s.entries, sessionID)
	}

	return nil
}

func (s *laxSessionStore) RefreshSession(_ context.Context, sessionID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.entries[sessionID]
	if !ok {
		return storage.ErrNotFound
	}
	data.ExpiresAt = time.Now().Add(ttl)

	return nil
}

// newAdversarialManager builds a Manager over an arbitrary store.
func newAdversarialManager(t *testing.T, cfg Config) *Manager {
	t.Helper()

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	return mgr
}

// ---------------------------------------------------------------------------
// F-14 -- session fixation (CWE-384)
// ---------------------------------------------------------------------------

// TestSession_FixatedIdentifierIsDeadAfterRotation covers the session fixation
// class described in OWASP's "Session fixation" (CWE-384) and finding F-14: an
// attacker plants a session identifier in the victim's user agent before
// authentication -- through a subdomain-scoped cookie, a URL parameter or an
// XSS write -- and keeps using it afterwards, because nothing about the
// identifier changed when the identity behind it did.
//
// Rotation is only a defense if the OLD identifier stops working on every path
// that accepts one, not merely on Get. Reverting Rotate's delete of the previous
// entry, or having it return the identifier it was handed, fails this test.
func TestSession_FixatedIdentifierIsDeadAfterRotation(t *testing.T) {
	t.Parallel()

	store := storage.NewInMemorySessionStore()
	mgr := newAdversarialManager(t, Config{Store: store, SessionTTL: time.Hour})
	ctx := context.Background()

	preAuth, err := mgr.Create(ctx, CreateSessionRequest{
		UserID:   "anonymous",
		Metadata: map[string]interface{}{"cart": "abc"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fixated := preAuth.ID

	rotated, err := mgr.Rotate(ctx, fixated)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.ID == fixated {
		t.Fatal("Rotate reused the identifier it was given; the fixated ID still authenticates")
	}
	if rotated.Data.Metadata["cart"] != "abc" {
		t.Fatalf("rotation lost the session data: %+v", rotated.Data)
	}

	// Every entry point that accepts a session identifier must refuse the old
	// one. A revocation that covers only the read path is not a revocation.
	paths := []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := mgr.Get(ctx, fixated); return err }},
		{"Validate", func() error { _, err := mgr.Validate(ctx, fixated); return err }},
		{"Rotate", func() error { _, err := mgr.Rotate(ctx, fixated); return err }},
		{"Refresh", func() error { return mgr.Refresh(ctx, fixated) }},
		{"Update", func() error {
			return mgr.Update(ctx, fixated, &storage.SessionData{UserID: "attacker"})
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			t.Parallel()

			if err := path.call(); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("%s with the pre-rotation ID: err = %v, want ErrSessionNotFound", path.name, err)
			}
		})
	}

	// The store must not be holding the old entry either: a Manager that stopped
	// serving it while the row lived on would leave the credential valid for any
	// other process sharing the store.
	if _, err := store.GetSession(ctx, fixated); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("store still holds the pre-rotation session: err = %v", err)
	}
	if _, err := mgr.Get(ctx, rotated.ID); err != nil {
		t.Fatalf("rotated session must be live: %v", err)
	}
}

// TestSession_RotationCannotExtendLifetimeIndefinitely: rotation is mandatory at
// every privilege change, so an endpoint an attacker can trigger repeatedly
// (a re-authentication, an MFA step-up) would be an unbounded session extension
// if each rotation restarted the clock -- the absolute-timeout bypass of
// CWE-613. The replacement must inherit the REMAINING lifetime of the original,
// not a fresh TTL.
//
// The session is created with a lifetime far shorter than the manager's default
// so the two behaviors are distinguishable: inheriting the remainder keeps the
// deadline where it was, while restarting the clock would push it out by the
// manager's TTL. Reverting Rotate to m.sessionTTL fails this test by an hour.
func TestSession_RotationCannotExtendLifetimeIndefinitely(t *testing.T) {
	t.Parallel()

	store := storage.NewInMemorySessionStore()
	mgr := newAdversarialManager(t, Config{Store: store, SessionTTL: time.Hour})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "u1", TTL: 5 * time.Second})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The store recomputes ExpiresAt from its own clock reading, so each hop
	// costs a few microseconds of scheduling. The tolerance absorbs that and
	// nothing else: it is four orders of magnitude below the manager TTL a
	// clock-restarting rotation would apply.
	const drift = 250 * time.Millisecond

	deadline := created.Data.ExpiresAt
	id := created.ID

	for i := 0; i < 8; i++ {
		rotated, err := mgr.Rotate(ctx, id)
		if err != nil {
			t.Fatalf("Rotate %d: %v", i, err)
		}
		if rotated.Data.ExpiresAt.After(deadline.Add(drift)) {
			t.Fatalf("rotation %d pushed the deadline out: %v > %v", i, rotated.Data.ExpiresAt, deadline)
		}
		if rotated.Data.ExpiresAt.Before(deadline.Add(-drift)) {
			t.Fatalf("rotation %d shortened the session: %v < %v", i, rotated.Data.ExpiresAt, deadline)
		}
		if rotated.Data.UserID != "u1" {
			t.Fatalf("rotation %d lost the subject: %+v", i, rotated.Data)
		}
		id = rotated.ID
	}
}

// TestSession_RotationNeverLeavesTwoLiveSessions is the "failure partway"
// requirement of F-14. A rotation that creates the replacement and then fails to
// delete the original has doubled the number of credentials that authenticate
// one subject, which is worse than not rotating at all: the fixated identifier
// survives AND the victim believes it did not.
//
// The compensating delete and the two distinct sentinels are the fix. Remove the
// rollback and the "delete of the previous entry fails" row reports two live
// sessions; collapse the sentinels and the caller can no longer tell the case it
// must force a logout for from the case it may retry.
func TestSession_RotationNeverLeavesTwoLiveSessions(t *testing.T) {
	t.Parallel()

	failing := errors.New("store is down")

	tests := []struct {
		name string
		// arrange configures the fixture, given the identifier that is about to
		// be rotated.
		arrange   func(store *laxSessionStore, oldID string)
		wantErr   error
		notErr    error
		wantLive  int
		oldIsLive bool
	}{
		{
			name:      "rotation succeeds",
			arrange:   func(*laxSessionStore, string) {},
			wantLive:  1,
			oldIsLive: false,
		},
		{
			name: "replacement cannot be created",
			arrange: func(store *laxSessionStore, _ string) {
				store.createErr = failing
			},
			wantErr:   failing,
			notErr:    ErrOrphanedSession,
			wantLive:  1,
			oldIsLive: true,
		},
		{
			name: "delete of the previous entry fails",
			arrange: func(store *laxSessionStore, oldID string) {
				store.deleteErrFor = func(id string) error {
					if id == oldID {
						return failing
					}
					return nil
				}
			},
			wantErr:   ErrRotationRolledBack,
			notErr:    ErrOrphanedSession,
			wantLive:  1,
			oldIsLive: true,
		},
		{
			name: "delete and its compensation both fail",
			arrange: func(store *laxSessionStore, _ string) {
				store.deleteErrFor = func(string) error { return failing }
			},
			wantErr:   ErrOrphanedSession,
			notErr:    ErrRotationRolledBack,
			wantLive:  2,
			oldIsLive: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newLaxSessionStore()
			mgr := newAdversarialManager(t, Config{Store: store, SessionTTL: time.Hour})
			ctx := context.Background()

			created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "victim"})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			tc.arrange(store, created.ID)

			rotated, err := mgr.Rotate(ctx, created.ID)

			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Rotate: %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Rotate err = %v, want %v", err, tc.wantErr)
			}
			if tc.notErr != nil && errors.Is(err, tc.notErr) {
				t.Fatalf("Rotate err = %v, must not be reported as %v", err, tc.notErr)
			}
			if tc.wantErr != nil && rotated != nil {
				t.Fatalf("a failed rotation returned a session: %+v", rotated)
			}

			live := store.live()
			if len(live) != tc.wantLive {
				t.Fatalf("live sessions = %v (%d), want %d", live, len(live), tc.wantLive)
			}

			_, oldLive := indexOf(live, created.ID)
			if oldLive != tc.oldIsLive {
				t.Fatalf("previous identifier live = %v, want %v (live: %v)", oldLive, tc.oldIsLive, live)
			}
		})
	}
}

// indexOf reports the position of want in ids and whether it is present.
func indexOf(ids []string, want string) (int, bool) {
	for i, id := range ids {
		if id == want {
			return i, true
		}
	}
	return -1, false
}

// TestSession_RotationDoesNotAliasThePreviousSessionsData: a store that returns
// a pointer into its own state -- which the in-memory store used to do, and
// which any store returning a cached object still does -- would otherwise leave
// the replacement session and the entry it replaced sharing one metadata map.
// Writing a privilege into the new session would then write it into the old one,
// and vice versa, so a revoked session could still be edited into a live one.
func TestSession_RotationDoesNotAliasThePreviousSessionsData(t *testing.T) {
	t.Parallel()

	store := newLaxSessionStore()
	store.aliasReads = true
	mgr := newAdversarialManager(t, Config{Store: store, SessionTTL: time.Hour})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{
		UserID:   "u1",
		Metadata: map[string]interface{}{"role": "user"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	previous := store.entry(created.ID)

	rotated, err := mgr.Rotate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.Data == previous {
		t.Fatal("rotated session shares its struct with the entry it replaced")
	}

	rotated.Data.Metadata["role"] = "admin"
	rotated.Data.UserID = "attacker"

	buried := store.buried(created.ID)
	if buried == nil {
		t.Fatal("fixture lost the previous entry")
	}
	if buried.Metadata["role"] != "user" {
		t.Fatalf("writing to the rotated session mutated the previous one: %+v", buried.Metadata)
	}
	if buried.UserID != "u1" {
		t.Fatalf("writing to the rotated session mutated the previous subject: %q", buried.UserID)
	}
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

// TestSession_ExpiredEntryIsRefusedEvenWhenTheStoreServesIt covers the
// belt-and-braces expiry check in Get. Session expiry is an authorization
// decision (CWE-613, insufficient session expiration); delegating it to the
// store means the credential's lifetime is decided by whichever component last
// ran a cleanup job. A Redis key that lost its EXPIRE, a SQL row awaiting a
// nightly sweep and a cache serving a stale entry all present the Manager with a
// live-looking session whose own ExpiresAt has passed.
//
// Delete the re-check in Get and both subtests fail: this fixture is a store
// that never expires anything.
func TestSession_ExpiredEntryIsRefusedEvenWhenTheStoreServesIt(t *testing.T) {
	t.Parallel()

	store := newLaxSessionStore()
	mgr := newAdversarialManager(t, Config{Store: store})
	ctx := context.Background()

	// Two identifiers, because refusing an expired session also sweeps it: the
	// second read would otherwise be testing eviction rather than the expiry
	// verdict.
	stale := func(id string) {
		store.seed(id, &storage.SessionData{
			UserID:    "u1",
			Email:     "victim@example.com",
			CreatedAt: time.Now().Add(-48 * time.Hour),
			ExpiresAt: time.Now().Add(-24 * time.Hour),
		})
	}
	const sessionID = "stale-but-present"
	stale(sessionID)
	stale("stale-for-validate")

	if _, err := mgr.Get(ctx, sessionID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Get err = %v, want ErrSessionExpired", err)
	}

	// Validate is the middleware's entry point: it must not hand back session
	// data alongside the refusal, or a caller that checks the data before the
	// error authenticates an expired subject.
	data, err := mgr.Validate(ctx, "stale-for-validate")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Validate err = %v, want ErrSessionExpired", err)
	}
	if data != nil {
		t.Fatalf("Validate returned data for an expired session: %+v", data)
	}

	// The stale entry must also be swept, or an unauthenticated caller replaying
	// a dead identifier keeps it resident forever.
	if calls := store.deleteCalls(); len(calls) == 0 {
		t.Fatal("expired session was refused but never swept from the store")
	}
	if store.entry(sessionID) != nil {
		t.Fatal("expired session is still present after being refused")
	}
}

// TestSession_ExpiryBoundary probes the instant the verdict flips. Off-by-one
// handling of a deadline is how a "15 minute" credential becomes valid for
// 15 minutes plus one clock tick; the comparison is time.Now().After(ExpiresAt),
// so the refusal must hold for any instant strictly past the deadline, including
// one nanosecond past it.
//
// The deadline instant itself is observed by a clock that has already advanced
// past it -- Get reads the clock after the store has returned -- so it lands on
// the refusal side too. The still-live case is given a wide margin on purpose:
// the assertion under test is the refusal, and a tight positive margin would
// only measure the scheduler.
func TestSession_ExpiryBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		offset  time.Duration
		wantErr error
	}{
		{"one nanosecond past the deadline", -time.Nanosecond, ErrSessionExpired},
		{"the deadline instant itself, judged later", 0, ErrSessionExpired},
		{"an hour past the deadline", -time.Hour, ErrSessionExpired},
		{"a minute short of the deadline", time.Minute, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newLaxSessionStore()
			mgr := newAdversarialManager(t, Config{Store: store})
			ctx := context.Background()

			const sessionID = "boundary"
			store.seed(sessionID, &storage.SessionData{
				UserID:    "u1",
				CreatedAt: time.Now().Add(-time.Hour),
				ExpiresAt: time.Now().Add(tc.offset),
			})

			session, err := mgr.Get(ctx, sessionID)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Get err = %v, want a live session", err)
				}
				if session == nil || session.Data.UserID != "u1" {
					t.Fatalf("Get returned %+v, want the seeded session", session)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Get err = %v, want %v", err, tc.wantErr)
			}
			if session != nil {
				t.Fatalf("Get returned a session past its deadline: %+v", session)
			}
		})
	}
}

// TestSession_SweepFailureIsReportedAndNeverNamesTheCredential: a store that
// cannot delete cannot revoke, so an expired-but-undeletable session is a signal
// the caller needs. It is reported by joining ErrSessionSweepFailed onto the
// expiry verdict rather than by discarding it -- and the identifier, which is a
// bearer credential, must not travel into the error text on its way to a log
// aggregator (CWE-532).
func TestSession_SweepFailureIsReportedAndNeverNamesTheCredential(t *testing.T) {
	t.Parallel()

	store := newLaxSessionStore()
	store.deleteErrFor = func(string) error { return errors.New("store is read-only") }
	mgr := newAdversarialManager(t, Config{Store: store})
	ctx := context.Background()

	sessionID := "Ax9-secret-bearer-value_0123456789"
	store.seed(sessionID, &storage.SessionData{
		UserID:    "u1",
		ExpiresAt: time.Now().Add(-time.Second),
	})

	session, err := mgr.Get(ctx, sessionID)
	if session != nil {
		t.Fatalf("Get returned a session despite the expiry: %+v", session)
	}
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want it to carry ErrSessionExpired", err)
	}
	if !errors.Is(err, ErrSessionSweepFailed) {
		t.Fatalf("err = %v, want it to carry ErrSessionSweepFailed", err)
	}
	if strings.Contains(err.Error(), sessionID) {
		t.Fatalf("the session identifier leaked into the error text: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Identifier entropy
// ---------------------------------------------------------------------------

// TestSession_IdentifierEntropy: a session identifier is a bearer credential, so
// a predictable one is a forgeable one (CWE-330 / CWE-340, "use of insufficiently
// random values"). The properties asserted are the ones an attacker attacks:
// identifiers never repeat, they carry the full configured number of random
// bytes, they are canonically encoded so two spellings of one identifier cannot
// exist, and the underlying bytes are balanced rather than sparse -- a counter,
// a timestamp or a zeroed buffer would satisfy uniqueness and fail the balance.
//
// Reverting the configured length to a hardcoded one fails the 16- and 64-byte
// rows; swapping crypto/rand for a counter fails the balance check.
func TestSession_IdentifierEntropy(t *testing.T) {
	t.Parallel()

	const samples = 256

	tests := []struct {
		name      string
		configure int
		wantBytes int
	}{
		{"default length", 0, DefaultSessionIDLength},
		{"16 bytes", 16, 16},
		{"32 bytes", 32, 32},
		{"64 bytes", 64, 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mgr := newAdversarialManager(t, Config{
				Store:          storage.NewInMemorySessionStore(),
				SessionIDBytes: tc.configure,
			})
			ctx := context.Background()

			seen := make(map[string]struct{}, samples)
			var setBits, totalBits int

			for i := 0; i < samples; i++ {
				// Identical requests: nothing about the identifier may be derived
				// from the subject, or one user's identifier predicts another's.
				created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "same-user"})
				if err != nil {
					t.Fatalf("Create %d: %v", i, err)
				}

				if _, dup := seen[created.ID]; dup {
					t.Fatalf("Create %d minted a duplicate identifier %q", i, created.ID)
				}
				seen[created.ID] = struct{}{}

				raw, err := base64.RawURLEncoding.DecodeString(created.ID)
				if err != nil {
					t.Fatalf("identifier %q is not raw base64url: %v", created.ID, err)
				}
				if len(raw) != tc.wantBytes {
					t.Fatalf("identifier carries %d random bytes, want %d", len(raw), tc.wantBytes)
				}
				// A non-canonical encoding means one identifier has two spellings,
				// and a store keyed by the string would hold both.
				if again := base64.RawURLEncoding.EncodeToString(raw); again != created.ID {
					t.Fatalf("identifier %q is not canonically encoded (re-encodes to %q)", created.ID, again)
				}
				if strings.ContainsAny(created.ID, "=+/") {
					t.Fatalf("identifier %q is not URL-safe", created.ID)
				}

				for _, b := range raw {
					setBits += bits.OnesCount8(b)
				}
				totalBits += len(raw) * 8
			}

			ratio := float64(setBits) / float64(totalBits)
			if ratio < 0.45 || ratio > 0.55 {
				t.Fatalf("set-bit ratio %.4f over %d bits: identifiers are not random", ratio, totalBits)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestSession_ConcurrentLifecycleUnderRace runs create, read, rotate and delete
// against one store from many goroutines. Two failures are being hunted: a data
// race (which -race reports), and cross-talk -- one caller observing another
// caller's session data, which is what a shared buffer or a pointer into store
// state produces under load and which reads as an authentication mix-up rather
// than as a crash.
func TestSession_ConcurrentLifecycleUnderRace(t *testing.T) {
	t.Parallel()

	store := storage.NewInMemorySessionStore()
	mgr := newAdversarialManager(t, Config{Store: store, SessionTTL: time.Hour})
	ctx := context.Background()

	const workers = 32
	const rounds = 8

	errCh := make(chan error, workers*rounds)
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(worker int) {
			defer wg.Done()

			owner := "user-" + strconv.Itoa(worker)
			for r := 0; r < rounds; r++ {
				created, err := mgr.Create(ctx, CreateSessionRequest{
					UserID:   owner,
					Metadata: map[string]interface{}{"worker": worker},
				})
				if err != nil {
					errCh <- err
					return
				}

				got, err := mgr.Get(ctx, created.ID)
				if err != nil {
					errCh <- err
					return
				}
				if got.Data.UserID != owner {
					errCh <- errors.New("read another worker's session: " + got.Data.UserID + " != " + owner)
					return
				}

				rotated, err := mgr.Rotate(ctx, created.ID)
				if err != nil {
					errCh <- err
					return
				}
				if rotated.Data.UserID != owner {
					errCh <- errors.New("rotation returned another worker's session: " + rotated.Data.UserID)
					return
				}
				if _, err := mgr.Get(ctx, created.ID); !errors.Is(err, ErrSessionNotFound) {
					errCh <- errors.New("pre-rotation identifier survived a concurrent rotation")
					return
				}

				if err := mgr.Delete(ctx, rotated.ID); err != nil {
					errCh <- err
					return
				}
				if _, err := mgr.Get(ctx, rotated.ID); !errors.Is(err, ErrSessionNotFound) {
					errCh <- errors.New("deleted session still authenticates")
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent lifecycle: %v", err)
	}
}

// TestSession_ConcurrentDeleteAndReadOfOneSession hammers a single identifier
// with simultaneous reads and deletes: the logout-while-in-flight case. A read
// may succeed or report ErrSessionNotFound, but it may never return a session
// alongside an error, nor a nil session alongside a nil error -- either would
// have a caller dereference a session that was revoked mid-request.
func TestSession_ConcurrentDeleteAndReadOfOneSession(t *testing.T) {
	t.Parallel()

	store := storage.NewInMemorySessionStore()
	mgr := newAdversarialManager(t, Config{Store: store, SessionTTL: time.Hour})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "u1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const readers = 24
	errCh := make(chan error, readers+1)
	start := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(readers + 1)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			<-start

			session, err := mgr.Get(ctx, created.ID)
			switch {
			case err == nil && session == nil:
				errCh <- errors.New("Get reported success with no session")
			case err != nil && session != nil:
				errCh <- errors.New("Get returned a session alongside an error")
			case err != nil && !errors.Is(err, ErrSessionNotFound):
				errCh <- err
			}
		}()
	}
	go func() {
		defer wg.Done()
		<-start

		if err := mgr.Delete(ctx, created.ID); err != nil {
			errCh <- err
		}
	}()

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent delete/read: %v", err)
	}

	if _, err := mgr.Get(ctx, created.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("after the delete settled, Get err = %v, want ErrSessionNotFound", err)
	}
}
