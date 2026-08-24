// Package storage_test holds the storage CONTRACT SUITE.
//
// The interfaces in storage.go are the seam between this library and whatever
// database a consumer runs. Every security property the library claims -- a
// session that stops authenticating when it expires, a state parameter that can
// be consumed once, a backup code that works once -- is only as true as the
// store's implementation of it, and a doc comment cannot enforce any of them.
//
// RunConformance is therefore written against the exported interfaces only, so
// it can be pointed at a PostgreSQL, Redis or DynamoDB implementation exactly as
// it is pointed at the in-memory ones here. In v2, when storage/memory.go leaves
// the public API, this file becomes the storagetest package the security
// hardening plan calls for (docs/security-hardening.md section 6) and moves
// verbatim; nothing in it reaches into package internals.
//
// The suite is hostile on purpose. It asserts what an implementation must refuse
// (an expired entry, a consumed state, a second use of a backup code, a
// credential ID that belongs to somebody else), not what it must return on the
// happy path.
package storage_test

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meysam81/go-auth/storage"
)

// shortTTL is long enough to observe an entry alive and short enough that
// waiting it out costs a few milliseconds.
const shortTTL = 3 * time.Millisecond

// waitPastDeadline blocks until an entry created with shortTTL has certainly
// lapsed. A sleep only ever overshoots, so this cannot expire early.
func waitPastDeadline() { time.Sleep(15 * time.Millisecond) }

// past is a deadline that has already gone by, for the interfaces that take an
// absolute expiry rather than a TTL.
func past() time.Time { return time.Now().Add(-time.Hour) }

// ConformanceSuite names the constructors an implementation supplies. Each one
// must return a store with no state carried over from a previous call: the suite
// takes a fresh store per case so an assertion cannot be satisfied by residue.
type ConformanceSuite struct {
	// Name identifies the implementation in test output.
	Name string

	NewUserStore       func() storage.UserStore
	NewCredentialStore func() storage.CredentialStore
	NewSessionStore    func() storage.SessionStore
	NewTokenStore      func() storage.TokenStore
	NewOIDCStateStore  func() storage.OIDCStateStore
}

// RunConformance runs the storage contract against one implementation. A store
// that passes has proved the properties the library's security controls rest on;
// a store that fails has a hole the library cannot compensate for.
func RunConformance(t *testing.T, suite ConformanceSuite) {
	t.Helper()

	t.Run(suite.Name+"/SentinelErrors", func(t *testing.T) { conformSentinels(t) })
	t.Run(suite.Name+"/SessionStore", func(t *testing.T) { conformSessionStore(t, suite.NewSessionStore) })
	t.Run(suite.Name+"/TokenStore", func(t *testing.T) { conformTokenStore(t, suite.NewTokenStore) })
	t.Run(suite.Name+"/OIDCStateStore", func(t *testing.T) { conformOIDCStateStore(t, suite.NewOIDCStateStore) })
	t.Run(suite.Name+"/CredentialStore", func(t *testing.T) { conformCredentialStore(t, suite.NewCredentialStore) })
	t.Run(suite.Name+"/UserStore", func(t *testing.T) { conformUserStore(t, suite.NewUserStore) })
	t.Run(suite.Name+"/DeleteOfAbsentKeys", func(t *testing.T) { conformAbsentDeletes(t, suite) })
}

// TestInMemoryStores_Conformance applies the contract to the reference
// implementations shipped in this package.
func TestInMemoryStores_Conformance(t *testing.T) {
	t.Parallel()

	RunConformance(t, ConformanceSuite{
		Name:               "InMemory",
		NewUserStore:       func() storage.UserStore { return storage.NewInMemoryUserStore() },
		NewCredentialStore: func() storage.CredentialStore { return storage.NewInMemoryCredentialStore() },
		NewSessionStore:    func() storage.SessionStore { return storage.NewInMemorySessionStore() },
		NewTokenStore:      func() storage.TokenStore { return storage.NewInMemoryTokenStore() },
		NewOIDCStateStore:  func() storage.OIDCStateStore { return storage.NewInMemoryOIDCStateStore() },
	})
}

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

// conformSentinels: the library branches on these errors to tell "this
// credential does not exist" from "this credential has lapsed" from "the backend
// is broken". Collapse any two of them into one and a backend outage becomes a
// failed authentication, or -- the direction that matters -- a lapsed credential
// becomes an accepted one. errors.Is must therefore distinguish every pair.
func conformSentinels(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"ErrNotFound":          storage.ErrNotFound,
		"ErrAlreadyExists":     storage.ErrAlreadyExists,
		"ErrExpired":           storage.ErrExpired,
		"ErrTokenRevoked":      storage.ErrTokenRevoked,
		"ErrInvalidBackupCode": storage.ErrInvalidBackupCode,
		"ErrBackupCodeUsed":    storage.ErrBackupCodeUsed,
	}

	for nameA, errA := range sentinels {
		for nameB, errB := range sentinels {
			if nameA == nameB {
				continue
			}
			if errors.Is(errA, errB) {
				t.Errorf("%s is indistinguishable from %s", nameA, nameB)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

func conformSessionStore(t *testing.T, newStore func() storage.SessionStore) {
	ctx := context.Background()

	// An unknown identifier is the commonest input to this store, because it is
	// what an attacker guessing session IDs produces. It must be reported as
	// absent on every entry point, never as an empty-but-valid session.
	t.Run("unknown identifier is reported absent", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		data, err := store.GetSession(ctx, "nope")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("GetSession err = %v, want ErrNotFound", err)
		}
		if data != nil {
			t.Fatalf("GetSession returned data for an unknown identifier: %+v", data)
		}
		if err := store.UpdateSession(ctx, "nope", &storage.SessionData{UserID: "u1"}, time.Hour); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("UpdateSession err = %v, want ErrNotFound", err)
		}
		if err := store.RefreshSession(ctx, "nope", time.Hour); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("RefreshSession err = %v, want ErrNotFound", err)
		}
	})

	// Expiry is an authorization decision (CWE-613). A store that hands back a
	// lapsed session -- or hands back data alongside the expiry error, which a
	// caller checking the data first would use -- has silently extended every
	// credential it holds.
	t.Run("an expired session is refused, distinguishably", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		for _, id := range []string{"get", "update", "refresh"} {
			if err := store.CreateSession(ctx, id, &storage.SessionData{UserID: "u1"}, shortTTL); err != nil {
				t.Fatalf("CreateSession(%s): %v", id, err)
			}
		}
		waitPastDeadline()

		data, err := store.GetSession(ctx, "get")
		if !errors.Is(err, storage.ErrExpired) {
			t.Fatalf("GetSession err = %v, want ErrExpired", err)
		}
		if errors.Is(err, storage.ErrNotFound) {
			t.Fatal("ErrExpired must be distinguishable from ErrNotFound")
		}
		if data != nil {
			t.Fatalf("GetSession returned data for an expired session: %+v", data)
		}

		// Neither mutation may resurrect it: an expired credential that a refresh
		// brings back is a credential with no lifetime at all.
		if err := store.UpdateSession(ctx, "update", &storage.SessionData{UserID: "u1"}, time.Hour); !errors.Is(err, storage.ErrExpired) {
			t.Fatalf("UpdateSession on an expired session: err = %v, want ErrExpired", err)
		}
		if err := store.RefreshSession(ctx, "refresh", time.Hour); !errors.Is(err, storage.ErrExpired) {
			t.Fatalf("RefreshSession on an expired session: err = %v, want ErrExpired", err)
		}
		if _, err := store.GetSession(ctx, "refresh"); err == nil {
			t.Fatal("a refused RefreshSession left the expired session readable")
		}
	})

	// Two 256-bit identifiers do not collide by chance, so a repeat is either a
	// defect or an identifier that did not come from session.Manager -- the shape
	// of a session fixation attempt (F-14, CWE-384). Replacing the live entry
	// would hand the attacker's data to the victim's identifier.
	t.Run("a live identifier is never silently replaced", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.CreateSession(ctx, "s1", &storage.SessionData{UserID: "victim"}, time.Hour); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if err := store.CreateSession(ctx, "s1", &storage.SessionData{UserID: "attacker"}, time.Hour); !errors.Is(err, storage.ErrAlreadyExists) {
			t.Fatalf("CreateSession over a live identifier: err = %v, want ErrAlreadyExists", err)
		}

		data, err := store.GetSession(ctx, "s1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if data.UserID != "victim" {
			t.Fatalf("the rejected create still overwrote the session: %+v", data)
		}
	})

	// A store that returns a pointer into its own state lets a caller edit a live
	// session without going through UpdateSession, and races every concurrent
	// reader.
	t.Run("reads do not alias stored state", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		original := &storage.SessionData{UserID: "u1", Metadata: map[string]interface{}{"role": "user"}}
		if err := store.CreateSession(ctx, "s1", original, time.Hour); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// Mutating the caller's struct after the write must not reach the store.
		original.UserID = "attacker"
		original.Metadata["role"] = "admin"

		first, err := store.GetSession(ctx, "s1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if first.UserID != "u1" || first.Metadata["role"] != "user" {
			t.Fatalf("the store aliased the caller's struct: %+v", first)
		}

		first.UserID = "attacker"
		first.Metadata["role"] = "admin"

		second, err := store.GetSession(ctx, "s1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if second.UserID != "u1" || second.Metadata["role"] != "user" {
			t.Fatalf("writing to a returned session mutated the store: %+v", second)
		}
	})

	// Delete is the revocation path. It must actually revoke, and it must not
	// punish a caller who deletes twice -- a logout retried after a timeout is
	// the normal case, not an error.
	t.Run("delete revokes and is idempotent", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.CreateSession(ctx, "s1", &storage.SessionData{UserID: "u1"}, time.Hour); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if err := store.DeleteSession(ctx, "s1"); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if _, err := store.GetSession(ctx, "s1"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("GetSession after delete: err = %v, want ErrNotFound", err)
		}
		if err := store.DeleteSession(ctx, "s1"); err != nil {
			t.Fatalf("second DeleteSession: %v, want nil", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

func conformTokenStore(t *testing.T, newStore func() storage.TokenStore) {
	ctx := context.Background()

	// Three refusals with three different meanings. A refresh token that is
	// unknown, revoked or lapsed must never resolve to a user ID, and the reason
	// must survive to the caller: revocation is a decision somebody made and an
	// audit trail records it as such.
	t.Run("refusals are distinguishable and yield no subject", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name    string
			arrange func(store storage.TokenStore) string
			wantErr error
		}{
			{
				name:    "unknown token ID",
				arrange: func(storage.TokenStore) string { return "never-issued" },
				wantErr: storage.ErrNotFound,
			},
			{
				name: "revoked token",
				arrange: func(store storage.TokenStore) string {
					if err := store.StoreRefreshToken(ctx, "u1", "jti-revoked", time.Now().Add(time.Hour)); err != nil {
						t.Fatalf("StoreRefreshToken: %v", err)
					}
					if err := store.RevokeRefreshToken(ctx, "jti-revoked"); err != nil {
						t.Fatalf("RevokeRefreshToken: %v", err)
					}
					return "jti-revoked"
				},
				wantErr: storage.ErrTokenRevoked,
			},
			{
				name: "expired token",
				arrange: func(store storage.TokenStore) string {
					if err := store.StoreRefreshToken(ctx, "u1", "jti-expired", past()); err != nil {
						t.Fatalf("StoreRefreshToken: %v", err)
					}
					return "jti-expired"
				},
				wantErr: storage.ErrExpired,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				store := newStore()

				tokenID := tc.arrange(store)
				userID, err := store.ValidateRefreshToken(ctx, tokenID)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ValidateRefreshToken err = %v, want %v", err, tc.wantErr)
				}
				if userID != "" {
					t.Fatalf("a refused token still resolved to user %q", userID)
				}
			})
		}
	})

	// The sweep a password change or a compromise report triggers (F-13). It must
	// reach every token the subject holds and stop at the boundary: revoking
	// another tenant's credentials is as much a defect as missing one's own.
	t.Run("revoking a user's tokens does not cross to another user", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		expiry := time.Now().Add(time.Hour)
		for _, jti := range []string{"a1", "a2", "a3"} {
			if err := store.StoreRefreshToken(ctx, "victim", jti, expiry); err != nil {
				t.Fatalf("StoreRefreshToken: %v", err)
			}
		}
		if err := store.StoreRefreshToken(ctx, "bystander", "b1", expiry); err != nil {
			t.Fatalf("StoreRefreshToken: %v", err)
		}

		if err := store.RevokeAllUserTokens(ctx, "victim"); err != nil {
			t.Fatalf("RevokeAllUserTokens: %v", err)
		}

		for _, jti := range []string{"a1", "a2", "a3"} {
			if _, err := store.ValidateRefreshToken(ctx, jti); !errors.Is(err, storage.ErrTokenRevoked) {
				t.Fatalf("token %s survived the sweep: err = %v", jti, err)
			}
		}
		if _, err := store.ValidateRefreshToken(ctx, "b1"); err != nil {
			t.Fatalf("another user's token was revoked by the sweep: %v", err)
		}

		// Sweeping a user who holds nothing satisfies the postcondition already.
		if err := store.RevokeAllUserTokens(ctx, "stranger"); err != nil {
			t.Fatalf("RevokeAllUserTokens for an unknown user: %v, want nil", err)
		}
	})

	t.Run("revocation is idempotent and unknown tokens cannot be revoked", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.RevokeRefreshToken(ctx, "never-issued"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("RevokeRefreshToken on an unknown ID: err = %v, want ErrNotFound", err)
		}
		if err := store.StoreRefreshToken(ctx, "u1", "jti", time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("StoreRefreshToken: %v", err)
		}
		for i := 0; i < 2; i++ {
			if err := store.RevokeRefreshToken(ctx, "jti"); err != nil {
				t.Fatalf("RevokeRefreshToken call %d: %v", i, err)
			}
		}
		if _, err := store.ValidateRefreshToken(ctx, "jti"); !errors.Is(err, storage.ErrTokenRevoked) {
			t.Fatalf("token is live after two revocations: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// OIDCStateStore
// ---------------------------------------------------------------------------

func conformOIDCStateStore(t *testing.T, newStore func() storage.OIDCStateStore) {
	ctx := context.Background()

	// GetState is documented as retrieve-AND-DELETE, and that delete is the whole
	// anti-replay value of the state parameter (RFC 6749 section 10.12, RFC 9700
	// section 4.7). A state that survives its first read can be replayed into a
	// second callback, which is authorization-code injection with the CSRF token
	// helpfully reusable.
	t.Run("GetState consumes the state", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.StoreState(ctx, "s1", &storage.OIDCState{Provider: "google", Nonce: "n1"}, time.Hour); err != nil {
			t.Fatalf("StoreState: %v", err)
		}

		first, err := store.GetState(ctx, "s1")
		if err != nil {
			t.Fatalf("first GetState: %v", err)
		}
		if first.Nonce != "n1" {
			t.Fatalf("first GetState returned %+v", first)
		}

		second, err := store.GetState(ctx, "s1")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second GetState err = %v, want ErrNotFound: the state is replayable", err)
		}
		if second != nil {
			t.Fatalf("second GetState returned data: %+v", second)
		}
	})

	// Consumption is not conditional on validity. A state whose TTL has passed
	// must be destroyed by the read that discovered it, or an attacker who can
	// make one read fail keeps the state alive for another attempt.
	t.Run("an expired state is refused and still consumed", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.StoreState(ctx, "s1", &storage.OIDCState{Provider: "google"}, shortTTL); err != nil {
			t.Fatalf("StoreState: %v", err)
		}
		waitPastDeadline()

		if _, err := store.GetState(ctx, "s1"); !errors.Is(err, storage.ErrExpired) {
			t.Fatalf("GetState err = %v, want ErrExpired", err)
		}
		if _, err := store.GetState(ctx, "s1"); err == nil {
			t.Fatal("an expired state survived the read that refused it")
		}
	})

	// The race is real: a victim's browser and an attacker's replay can arrive at
	// the callback endpoint at the same instant. Read and delete must be one
	// operation, or both are handed the same state and the single-use property is
	// gone.
	t.Run("concurrent callbacks consume the state exactly once", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.StoreState(ctx, "s1", &storage.OIDCState{Provider: "google", Nonce: "n1"}, time.Hour); err != nil {
			t.Fatalf("StoreState: %v", err)
		}

		const callers = 32
		var wg sync.WaitGroup
		var mu sync.Mutex
		winners := 0
		start := make(chan struct{})

		wg.Add(callers)
		for i := 0; i < callers; i++ {
			go func() {
				defer wg.Done()
				<-start

				state, err := store.GetState(ctx, "s1")
				if err == nil && state != nil {
					mu.Lock()
					winners++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()

		if winners != 1 {
			t.Fatalf("%d concurrent callbacks consumed one state, want exactly 1", winners)
		}
	})

	// Nonce, code verifier and binding hash are the values that tie the two legs
	// of the flow together. A store that keeps the caller's struct rather than a
	// copy lets a later mutation -- or a caller reusing one struct across flows --
	// rewrite the bindings of a flow already in progress.
	t.Run("stored state does not alias the caller's struct", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		original := &storage.OIDCState{
			Provider:     "google",
			Nonce:        "nonce-1",
			CodeVerifier: "verifier-1",
			BindingHash:  "hash-1",
			Metadata:     map[string]interface{}{"tenant": "acme"},
		}
		if err := store.StoreState(ctx, "s1", original, time.Hour); err != nil {
			t.Fatalf("StoreState: %v", err)
		}

		original.Nonce = "nonce-2"
		original.CodeVerifier = "verifier-2"
		original.BindingHash = "hash-2"
		original.Metadata["tenant"] = "attacker"

		got, err := store.GetState(ctx, "s1")
		if err != nil {
			t.Fatalf("GetState: %v", err)
		}
		if got.Nonce != "nonce-1" || got.CodeVerifier != "verifier-1" || got.BindingHash != "hash-1" {
			t.Fatalf("the store aliased the caller's struct: %+v", got)
		}
		if got.Metadata["tenant"] != "acme" {
			t.Fatalf("the store aliased the caller's metadata map: %+v", got.Metadata)
		}
	})

	t.Run("an unknown state is reported absent", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		state, err := store.GetState(ctx, "never-issued")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("GetState err = %v, want ErrNotFound", err)
		}
		if state != nil {
			t.Fatalf("GetState returned %+v for an unknown state", state)
		}
	})
}

// ---------------------------------------------------------------------------
// CredentialStore
// ---------------------------------------------------------------------------

func conformCredentialStore(t *testing.T, newStore func() storage.CredentialStore) {
	ctx := context.Background()

	t.Run("BackupCodes", func(t *testing.T) { conformBackupCodes(t, newStore) })
	t.Run("TOTPMaterial", func(t *testing.T) { conformTOTPMaterial(t, newStore) })
	t.Run("SingleUseTokens", func(t *testing.T) { conformSingleUseTokens(t, newStore) })
	t.Run("WebAuthnCredentials", func(t *testing.T) { conformWebAuthnCredentials(t, newStore) })

	// A bcrypt digest is bytes, not text. A store that round-trips it through a
	// text column, trims it, or hands out a slice that aliases its own state
	// breaks verification in a way that looks like a wrong password.
	t.Run("password hashes round-trip verbatim", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if _, err := store.GetPasswordHash(ctx, "nobody"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("GetPasswordHash for an unknown user: err = %v, want ErrNotFound", err)
		}

		hash := []byte{0x00, 0x24, 0x32, 0x61, 0xff, 0xfe, ' ', '\n', 0x7f}
		if err := store.StorePasswordHash(ctx, "u1", hash); err != nil {
			t.Fatalf("StorePasswordHash: %v", err)
		}

		got, err := store.GetPasswordHash(ctx, "u1")
		if err != nil {
			t.Fatalf("GetPasswordHash: %v", err)
		}
		if !bytes.Equal(got, hash) {
			t.Fatalf("hash = %v, want %v", got, hash)
		}

		// Overwriting the returned slice must not corrupt the credential.
		for i := range got {
			got[i] = 'x'
		}
		again, err := store.GetPasswordHash(ctx, "u1")
		if err != nil {
			t.Fatalf("GetPasswordHash: %v", err)
		}
		if !bytes.Equal(again, hash) {
			t.Fatalf("writing to a returned hash corrupted the stored one: %v", again)
		}
	})
}

// conformBackupCodes: a backup code is the credential a user writes on paper and
// keeps in a drawer, so single use is the only thing that makes it safe. The
// check and the consume must be one atomic operation -- CWE-367, a
// time-of-check/time-of-use race -- because two submissions of the same code
// arriving together is exactly what a user double-clicking a form produces, and
// exactly what an attacker replaying an observed code produces.
func conformBackupCodes(t *testing.T, newStore func() storage.CredentialStore) {
	ctx := context.Background()

	t.Run("single use survives concurrent callers", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		// The callers are held at a barrier and released together, and the whole
		// experiment is repeated: a store whose check-and-consume window is short
		// would otherwise be a flaky pass rather than a failure.
		const callers = 64
		const rounds = 8

		for round := 0; round < rounds; round++ {
			code := "hash-round-" + strconv.Itoa(round)
			if err := store.StoreTOTPSecret(ctx, "u1", "secret", []string{code, "hash-spare"}); err != nil {
				t.Fatalf("StoreTOTPSecret: %v", err)
			}

			var wg sync.WaitGroup
			var mu sync.Mutex
			accepted := 0
			unexpected := make([]error, 0, callers)
			start := make(chan struct{})

			wg.Add(callers)
			for i := 0; i < callers; i++ {
				go func() {
					defer wg.Done()
					<-start

					err := store.UseBackupCode(ctx, "u1", code)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						accepted++
					case errors.Is(err, storage.ErrBackupCodeUsed):
					default:
						unexpected = append(unexpected, err)
					}
				}()
			}
			close(start)
			wg.Wait()

			if accepted != 1 {
				t.Fatalf("round %d: %d of %d concurrent callers consumed one backup code, want exactly 1", round, accepted, callers)
			}
			for _, err := range unexpected {
				t.Errorf("round %d: a losing caller got %v, want ErrBackupCodeUsed", round, err)
			}

			// The consumed code is gone; the untouched one is not.
			_, codes, err := store.GetTOTPSecret(ctx, "u1")
			if err != nil {
				t.Fatalf("GetTOTPSecret: %v", err)
			}
			if len(codes) != 1 || codes[0] != "hash-spare" {
				t.Fatalf("round %d: unused codes = %v, want [hash-spare]", round, codes)
			}
		}
	})

	// The three outcomes must stay distinct for the library and identical for the
	// user: "already used" tells an unauthenticated caller that the code they
	// hold was genuinely issued, which is why the interface documents that a
	// caller must not surface the distinction.
	t.Run("outcomes are distinguishable", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.UseBackupCode(ctx, "nobody", "hash-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("UseBackupCode for an unenrolled user: err = %v, want ErrNotFound", err)
		}
		if err := store.StoreTOTPSecret(ctx, "u1", "secret", []string{"hash-a"}); err != nil {
			t.Fatalf("StoreTOTPSecret: %v", err)
		}
		if err := store.UseBackupCode(ctx, "u1", "hash-zzz"); !errors.Is(err, storage.ErrInvalidBackupCode) {
			t.Fatalf("UseBackupCode with an unknown code: err = %v, want ErrInvalidBackupCode", err)
		}
		if err := store.UseBackupCode(ctx, "u1", "hash-a"); err != nil {
			t.Fatalf("UseBackupCode with a good code: %v", err)
		}
		if err := store.UseBackupCode(ctx, "u1", "hash-a"); !errors.Is(err, storage.ErrBackupCodeUsed) {
			t.Fatalf("second use: err = %v, want ErrBackupCodeUsed", err)
		}
	})

	// The stored value is a hash. Matching it loosely -- case-folded, trimmed,
	// by prefix -- widens every code into a family of codes, which is a smaller
	// search space than the one the code was minted from.
	t.Run("codes are matched exactly", func(t *testing.T) {
		t.Parallel()

		nearMisses := []struct {
			name string
			code string
		}{
			{"upper case", "HASH-A"},
			{"leading space", " hash-a"},
			{"trailing space", "hash-a "},
			{"trailing newline", "hash-a\n"},
			{"prefix", "hash-"},
			{"prefix plus NUL", "hash-a\x00"},
			{"empty", ""},
		}

		for _, tc := range nearMisses {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				store := newStore()

				if err := store.StoreTOTPSecret(ctx, "u1", "secret", []string{"hash-a"}); err != nil {
					t.Fatalf("StoreTOTPSecret: %v", err)
				}
				if err := store.UseBackupCode(ctx, "u1", tc.code); !errors.Is(err, storage.ErrInvalidBackupCode) {
					t.Fatalf("UseBackupCode(%q): err = %v, want ErrInvalidBackupCode", tc.code, err)
				}
				// The genuine code must be untouched by the near miss.
				if err := store.UseBackupCode(ctx, "u1", "hash-a"); err != nil {
					t.Fatalf("the near miss consumed the genuine code: %v", err)
				}
			})
		}
	})
}

// conformTOTPMaterial: the secret may be ciphertext and the codes are hashes, so
// the store holds opaque bytes it must not interpret. Normalising any of it --
// trimming, case-folding, re-encoding -- silently destroys the ability to
// decrypt the secret or compare a code, and the symptom is a second factor that
// rejects every valid code.
func conformTOTPMaterial(t *testing.T, newStore func() storage.CredentialStore) {
	ctx := context.Background()

	t.Run("material is returned verbatim", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if _, _, err := store.GetTOTPSecret(ctx, "nobody"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("GetTOTPSecret for an unenrolled user: err = %v, want ErrNotFound", err)
		}

		// G101 fires on the word below; this is fixture data, not a credential.
		secret := "\x00\xff base32-or-ciphertext \t\n" //nolint:gosec // fixture bytes, not a secret
		codes := []string{"  padded  ", "MiXeD", "\x00nul", "ünïcödé"}
		if err := store.StoreTOTPSecret(ctx, "u1", secret, codes); err != nil {
			t.Fatalf("StoreTOTPSecret: %v", err)
		}

		gotSecret, gotCodes, err := store.GetTOTPSecret(ctx, "u1")
		if err != nil {
			t.Fatalf("GetTOTPSecret: %v", err)
		}
		if gotSecret != secret {
			t.Fatalf("secret = %q, want %q verbatim", gotSecret, secret)
		}
		if len(gotCodes) != len(codes) {
			t.Fatalf("codes = %q, want %q", gotCodes, codes)
		}
		for i := range codes {
			if gotCodes[i] != codes[i] {
				t.Fatalf("code %d = %q, want %q verbatim", i, gotCodes[i], codes[i])
			}
		}
	})

	// Re-enrolment replaces the whole factor, including which codes have been
	// spent. A store that merged instead would leave a re-enrolling user with
	// codes their previous device had already consumed.
	t.Run("re-enrolment replaces the previous factor", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.StoreTOTPSecret(ctx, "u1", "secret-1", []string{"hash-a", "hash-b"}); err != nil {
			t.Fatalf("StoreTOTPSecret: %v", err)
		}
		if err := store.UseBackupCode(ctx, "u1", "hash-a"); err != nil {
			t.Fatalf("UseBackupCode: %v", err)
		}
		if err := store.StoreTOTPSecret(ctx, "u1", "secret-2", []string{"hash-c"}); err != nil {
			t.Fatalf("re-enrolment: %v", err)
		}

		secret, codes, err := store.GetTOTPSecret(ctx, "u1")
		if err != nil {
			t.Fatalf("GetTOTPSecret: %v", err)
		}
		if secret != "secret-2" {
			t.Fatalf("secret = %q, want the re-enrolled one", secret)
		}
		if len(codes) != 1 || codes[0] != "hash-c" {
			t.Fatalf("codes = %v, want only the re-enrolled one", codes)
		}
		// A code from the replaced enrolment must not be accepted.
		if err := store.UseBackupCode(ctx, "u1", "hash-b"); !errors.Is(err, storage.ErrInvalidBackupCode) {
			t.Fatalf("a code from the replaced factor: err = %v, want ErrInvalidBackupCode", err)
		}
	})

	t.Run("deleting the factor removes it", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.StoreTOTPSecret(ctx, "u1", "secret", []string{"hash-a"}); err != nil {
			t.Fatalf("StoreTOTPSecret: %v", err)
		}
		if err := store.DeleteTOTPSecret(ctx, "u1"); err != nil {
			t.Fatalf("DeleteTOTPSecret: %v", err)
		}
		if _, _, err := store.GetTOTPSecret(ctx, "u1"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("GetTOTPSecret after delete: err = %v, want ErrNotFound", err)
		}
		if err := store.UseBackupCode(ctx, "u1", "hash-a"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("a backup code survived the factor being deleted: err = %v", err)
		}
	})
}

// tokenFamily is one of the two single-use token families the library persists
// as HASHES (F-05): password reset and email verification. They are exercised
// identically because they have identical security properties, and because a
// store that implements one correctly and the other by copy-paste is the normal
// failure.
type tokenFamily struct {
	name     string
	store    func(ctx context.Context, s storage.CredentialStore, userID, token string, expiresAt time.Time) error
	validate func(ctx context.Context, s storage.CredentialStore, token string) (string, error)
	delete   func(ctx context.Context, s storage.CredentialStore, token string) error
	// crossValidate looks the token up in the OTHER family's namespace.
	crossValidate func(ctx context.Context, s storage.CredentialStore, token string) (string, error)
}

func tokenFamilies() []tokenFamily {
	return []tokenFamily{
		{
			name: "password reset",
			store: func(ctx context.Context, s storage.CredentialStore, userID, token string, expiresAt time.Time) error {
				return s.StorePasswordResetToken(ctx, userID, token, expiresAt)
			},
			validate: func(ctx context.Context, s storage.CredentialStore, token string) (string, error) {
				return s.ValidatePasswordResetToken(ctx, token)
			},
			delete: func(ctx context.Context, s storage.CredentialStore, token string) error {
				return s.DeletePasswordResetToken(ctx, token)
			},
			crossValidate: func(ctx context.Context, s storage.CredentialStore, token string) (string, error) {
				return s.ValidateEmailVerificationToken(ctx, token)
			},
		},
		{
			name: "email verification",
			store: func(ctx context.Context, s storage.CredentialStore, userID, token string, expiresAt time.Time) error {
				return s.StoreEmailVerificationToken(ctx, userID, token, expiresAt)
			},
			validate: func(ctx context.Context, s storage.CredentialStore, token string) (string, error) {
				return s.ValidateEmailVerificationToken(ctx, token)
			},
			delete: func(ctx context.Context, s storage.CredentialStore, token string) error {
				return s.DeleteEmailVerificationToken(ctx, token)
			},
			crossValidate: func(ctx context.Context, s storage.CredentialStore, token string) (string, error) {
				return s.ValidatePasswordResetToken(ctx, token)
			},
		},
	}
}

// conformSingleUseTokens: whoever holds one of these tokens can take over the
// account it names, so an expired one resolving to a user ID, a loosely matched
// one, or one that works in the other family's namespace is account takeover.
func conformSingleUseTokens(t *testing.T, newStore func() storage.CredentialStore) {
	ctx := context.Background()

	for _, family := range tokenFamilies() {
		t.Run(family.name, func(t *testing.T) {
			t.Parallel()

			t.Run("unknown token yields no subject", func(t *testing.T) {
				t.Parallel()
				store := newStore()

				userID, err := family.validate(ctx, store, "never-issued")
				if !errors.Is(err, storage.ErrNotFound) {
					t.Fatalf("validate err = %v, want ErrNotFound", err)
				}
				if userID != "" {
					t.Fatalf("an unknown token resolved to user %q", userID)
				}
			})

			t.Run("expired token yields no subject", func(t *testing.T) {
				t.Parallel()
				store := newStore()

				if err := family.store(ctx, store, "u1", "hash-expired", past()); err != nil {
					t.Fatalf("store: %v", err)
				}

				userID, err := family.validate(ctx, store, "hash-expired")
				if !errors.Is(err, storage.ErrExpired) {
					t.Fatalf("validate err = %v, want ErrExpired", err)
				}
				if errors.Is(err, storage.ErrNotFound) {
					t.Fatal("ErrExpired must be distinguishable from ErrNotFound")
				}
				if userID != "" {
					t.Fatalf("an expired token resolved to user %q", userID)
				}
			})

			t.Run("tokens are matched exactly", func(t *testing.T) {
				t.Parallel()
				store := newStore()

				if err := family.store(ctx, store, "u1", "hash-abc", time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("store: %v", err)
				}

				for _, near := range []string{"HASH-ABC", " hash-abc", "hash-abc ", "hash-ab", "hash-abcd", ""} {
					if userID, err := family.validate(ctx, store, near); err == nil {
						t.Fatalf("near miss %q validated as user %q", near, userID)
					}
				}
				if userID, err := family.validate(ctx, store, "hash-abc"); err != nil || userID != "u1" {
					t.Fatalf("the genuine token: user %q, err %v", userID, err)
				}
			})

			// The two families are separate namespaces. A verification token that
			// validates on the reset path would let a link sent to prove an address
			// change a password instead.
			t.Run("a token does not cross into the other family", func(t *testing.T) {
				t.Parallel()
				store := newStore()

				if err := family.store(ctx, store, "u1", "hash-shared", time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("store: %v", err)
				}
				if userID, err := family.crossValidate(ctx, store, "hash-shared"); err == nil {
					t.Fatalf("the token validated in the other family as user %q", userID)
				}
			})

			t.Run("delete revokes and is idempotent", func(t *testing.T) {
				t.Parallel()
				store := newStore()

				if err := family.store(ctx, store, "u1", "hash-abc", time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("store: %v", err)
				}
				if err := family.delete(ctx, store, "hash-abc"); err != nil {
					t.Fatalf("delete: %v", err)
				}
				if _, err := family.validate(ctx, store, "hash-abc"); !errors.Is(err, storage.ErrNotFound) {
					t.Fatalf("validate after delete: err = %v, want ErrNotFound", err)
				}
				if err := family.delete(ctx, store, "hash-abc"); err != nil {
					t.Fatalf("second delete: %v, want nil", err)
				}
				if err := family.delete(ctx, store, "never-issued"); err != nil {
					t.Fatalf("delete of an absent token: %v, want nil", err)
				}
			})
		})
	}
}

// conformWebAuthnCredentials: a credential ID is globally unique by
// construction, so a second registration claiming an existing ID is either a
// replay or an authenticator claiming somebody else's credential. Reassigning it
// hands over the account behind it. The signature counter matters for the same
// reason in reverse: it is the only signal a cloned authenticator produces, so a
// store that declines to persist an update destroys the detection.
func conformWebAuthnCredentials(t *testing.T, newStore func() storage.CredentialStore) {
	ctx := context.Background()

	t.Run("a credential ID cannot be claimed twice", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		id := []byte{0x01, 0x02, 0x03}
		if err := store.StoreWebAuthnCredential(ctx, "victim", &storage.WebAuthnCredential{ID: id, PublicKey: []byte("pk-victim")}); err != nil {
			t.Fatalf("StoreWebAuthnCredential: %v", err)
		}

		err := store.StoreWebAuthnCredential(ctx, "attacker", &storage.WebAuthnCredential{ID: id, PublicKey: []byte("pk-attacker")})
		if !errors.Is(err, storage.ErrAlreadyExists) {
			t.Fatalf("re-registering a known credential ID: err = %v, want ErrAlreadyExists", err)
		}

		attackerCreds, err := store.GetWebAuthnCredentials(ctx, "attacker")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(attackerCreds) != 0 {
			t.Fatalf("the credential was reassigned to the attacker: %+v", attackerCreds)
		}

		victimCreds, err := store.GetWebAuthnCredentials(ctx, "victim")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(victimCreds) != 1 || !bytes.Equal(victimCreds[0].PublicKey, []byte("pk-victim")) {
			t.Fatalf("the victim's credential was altered: %+v", victimCreds)
		}
	})

	t.Run("a user with no credentials is not an error", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		creds, err := store.GetWebAuthnCredentials(ctx, "nobody")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v, want nil for a user with none", err)
		}
		if len(creds) != 0 {
			t.Fatalf("credentials = %+v, want none", creds)
		}
	})

	t.Run("the signature counter is persisted", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		id := []byte{0xaa, 0xbb}
		if err := store.StoreWebAuthnCredential(ctx, "u1", &storage.WebAuthnCredential{ID: id, SignCount: 1}); err != nil {
			t.Fatalf("StoreWebAuthnCredential: %v", err)
		}
		if err := store.UpdateWebAuthnCredential(ctx, &storage.WebAuthnCredential{ID: id, UserID: "u1", SignCount: 42}); err != nil {
			t.Fatalf("UpdateWebAuthnCredential: %v", err)
		}

		creds, err := store.GetWebAuthnCredentials(ctx, "u1")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 1 || creds[0].SignCount != 42 {
			t.Fatalf("sign counter was not persisted: %+v", creds)
		}
	})

	t.Run("an update cannot move a credential to another user", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		id := []byte{0xcc, 0xdd}
		if err := store.StoreWebAuthnCredential(ctx, "victim", &storage.WebAuthnCredential{ID: id, SignCount: 1}); err != nil {
			t.Fatalf("StoreWebAuthnCredential: %v", err)
		}

		// Refusing outright and ignoring the ownership change are both
		// contract-legal; inventing a third error is not, and neither is
		// succeeding. What matters is the postcondition below.
		if err := store.UpdateWebAuthnCredential(ctx, &storage.WebAuthnCredential{ID: id, UserID: "attacker", SignCount: 99}); err != nil && !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("re-owning update returned %v, want nil or ErrNotFound", err)
		}

		attackerCreds, err := store.GetWebAuthnCredentials(ctx, "attacker")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(attackerCreds) != 0 {
			t.Fatalf("an update re-owned the credential: %+v", attackerCreds)
		}
		victimCreds, err := store.GetWebAuthnCredentials(ctx, "victim")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(victimCreds) != 1 {
			t.Fatalf("the victim lost the credential: %+v", victimCreds)
		}
	})

	t.Run("updating an unknown credential is refused", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		err := store.UpdateWebAuthnCredential(ctx, &storage.WebAuthnCredential{ID: []byte{0x99}, UserID: "u1", SignCount: 5})
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("UpdateWebAuthnCredential on an unknown ID: err = %v, want ErrNotFound", err)
		}
	})

	t.Run("reads do not alias stored state", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		id := []byte{0x11, 0x22}
		if err := store.StoreWebAuthnCredential(ctx, "u1", &storage.WebAuthnCredential{ID: id, PublicKey: []byte("pk")}); err != nil {
			t.Fatalf("StoreWebAuthnCredential: %v", err)
		}

		creds, err := store.GetWebAuthnCredentials(ctx, "u1")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		creds[0].PublicKey[0] = 'X'
		creds[0].SignCount = 4242

		again, err := store.GetWebAuthnCredentials(ctx, "u1")
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if !bytes.Equal(again[0].PublicKey, []byte("pk")) || again[0].SignCount != 0 {
			t.Fatalf("writing to a returned credential mutated the store: %+v", again[0])
		}
	})
}

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

func conformUserStore(t *testing.T, newStore func() storage.UserStore) {
	ctx := context.Background()

	t.Run("unknown users are reported absent", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		lookups := map[string]func() (*storage.User, error){
			"by ID":       func() (*storage.User, error) { return store.GetUserByID(ctx, "nobody") },
			"by email":    func() (*storage.User, error) { return store.GetUserByEmail(ctx, "nobody@example.test") },
			"by username": func() (*storage.User, error) { return store.GetUserByUsername(ctx, "nobody") },
		}
		for name, lookup := range lookups {
			user, err := lookup()
			if !errors.Is(err, storage.ErrNotFound) {
				t.Errorf("%s: err = %v, want ErrNotFound", name, err)
			}
			if user != nil {
				t.Errorf("%s returned a user: %+v", name, user)
			}
		}
	})

	// Identity fields are unique or they are not identity fields. A store that
	// lets a second row claim an address already on file makes every lookup by
	// that address ambiguous, and one of the two answers belongs to whoever
	// registered second.
	t.Run("identity fields cannot be claimed twice", func(t *testing.T) {
		t.Parallel()

		existing := &storage.User{ID: "u1", Email: "victim@example.test", Username: "victim"}

		clashes := []struct {
			name string
			user *storage.User
		}{
			{"same ID", &storage.User{ID: "u1", Email: "other@example.test", Username: "other"}},
			{"same email", &storage.User{ID: "u2", Email: "victim@example.test", Username: "other"}},
			{"same username", &storage.User{ID: "u3", Email: "other@example.test", Username: "victim"}},
		}

		for _, tc := range clashes {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				store := newStore()

				seed := *existing
				if err := store.CreateUser(ctx, &seed); err != nil {
					t.Fatalf("CreateUser: %v", err)
				}
				candidate := *tc.user
				if err := store.CreateUser(ctx, &candidate); !errors.Is(err, storage.ErrAlreadyExists) {
					t.Fatalf("CreateUser: err = %v, want ErrAlreadyExists", err)
				}

				user, err := store.GetUserByEmail(ctx, "victim@example.test")
				if err != nil {
					t.Fatalf("GetUserByEmail: %v", err)
				}
				if user.ID != "u1" {
					t.Fatalf("the rejected create still moved the address to %q", user.ID)
				}
			})
		}
	})

	// The same guard on the update path: an account takeover by re-pointing an
	// existing address at a different row is the same defect with a different
	// verb.
	t.Run("an update cannot steal another user's address", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		for _, u := range []*storage.User{
			{ID: "victim", Email: "victim@example.test", Username: "victim"},
			{ID: "attacker", Email: "attacker@example.test", Username: "attacker"},
		} {
			if err := store.CreateUser(ctx, u); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
		}

		err := store.UpdateUser(ctx, &storage.User{ID: "attacker", Email: "victim@example.test", Username: "attacker"})
		if !errors.Is(err, storage.ErrAlreadyExists) {
			t.Fatalf("UpdateUser onto a taken address: err = %v, want ErrAlreadyExists", err)
		}

		user, err := store.GetUserByEmail(ctx, "victim@example.test")
		if err != nil {
			t.Fatalf("GetUserByEmail: %v", err)
		}
		if user.ID != "victim" {
			t.Fatalf("the address now resolves to %q", user.ID)
		}
	})

	// The library requires addresses to be normalised before they arrive. A store
	// that case-folds on its own would make "Victim@Example.test" and
	// "victim@example.test" the same row here and different rows in whatever
	// index the application keeps -- and a federated login matching on email is
	// already the takeover path of finding F-01.
	t.Run("lookups are byte-exact", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.CreateUser(ctx, &storage.User{ID: "u1", Email: "victim@example.test", Username: "victim"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		for _, variant := range []string{"Victim@example.test", "VICTIM@EXAMPLE.TEST", " victim@example.test", "victim@example.test "} {
			if user, err := store.GetUserByEmail(ctx, variant); err == nil {
				t.Fatalf("GetUserByEmail(%q) resolved to %q; the store is normalising", variant, user.ID)
			}
		}
		for _, variant := range []string{"Victim", "VICTIM", "victim "} {
			if user, err := store.GetUserByUsername(ctx, variant); err == nil {
				t.Fatalf("GetUserByUsername(%q) resolved to %q; the store is normalising", variant, user.ID)
			}
		}
	})

	t.Run("reads do not alias stored state", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.CreateUser(ctx, &storage.User{
			ID:       "u1",
			Email:    "victim@example.test",
			Metadata: map[string]interface{}{"role": "user"},
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		user, err := store.GetUserByID(ctx, "u1")
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		user.Email = "attacker@example.test"
		user.Metadata["role"] = "admin"

		again, err := store.GetUserByID(ctx, "u1")
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if again.Email != "victim@example.test" || again.Metadata["role"] != "user" {
			t.Fatalf("writing to a returned user mutated the store: %+v", again)
		}
	})

	t.Run("delete removes every index entry", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		if err := store.CreateUser(ctx, &storage.User{ID: "u1", Email: "victim@example.test", Username: "victim"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := store.DeleteUser(ctx, "u1"); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}

		if _, err := store.GetUserByID(ctx, "u1"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetUserByID after delete: err = %v, want ErrNotFound", err)
		}
		// A stale index entry pointing at a deleted row is how a lookup returns a
		// nil user with a nil error, which the caller then dereferences.
		if _, err := store.GetUserByEmail(ctx, "victim@example.test"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetUserByEmail after delete: err = %v, want ErrNotFound", err)
		}
		if _, err := store.GetUserByUsername(ctx, "victim"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetUserByUsername after delete: err = %v, want ErrNotFound", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Deleting what is not there
// ---------------------------------------------------------------------------

// conformAbsentDeletes: deleting something that is not there happens constantly
// in an auth system -- a logout retried after a timeout, a reset link consumed
// twice, a cleanup job racing a TTL. Two properties are required of every store.
//
// The outcome must be one of the two the contract allows: nil (the ephemeral
// stores, where the postcondition "it is gone" already holds) or ErrNotFound
// (the identity stores, where the caller asked to remove a specific record). A
// third, store-specific error would force callers to special-case a backend.
//
// And it must be STABLE: the same call twice must answer the same way, so a
// retry cannot be reported as a failure the first time and a success the second.
func conformAbsentDeletes(t *testing.T, suite ConformanceSuite) {
	t.Parallel()

	ctx := context.Background()

	deletes := []struct {
		name string
		call func() error
	}{
		{"SessionStore.DeleteSession", func() error { return suite.NewSessionStore().DeleteSession(ctx, "absent") }},
		{"OIDCStateStore.DeleteState", func() error { return suite.NewOIDCStateStore().DeleteState(ctx, "absent") }},
		{"UserStore.DeleteUser", func() error { return suite.NewUserStore().DeleteUser(ctx, "absent") }},
		{"TokenStore.RevokeRefreshToken", func() error { return suite.NewTokenStore().RevokeRefreshToken(ctx, "absent") }},
		{"TokenStore.RevokeAllUserTokens", func() error { return suite.NewTokenStore().RevokeAllUserTokens(ctx, "absent") }},
		{"CredentialStore.DeletePasswordResetToken", func() error {
			return suite.NewCredentialStore().DeletePasswordResetToken(ctx, "absent")
		}},
		{"CredentialStore.DeleteEmailVerificationToken", func() error {
			return suite.NewCredentialStore().DeleteEmailVerificationToken(ctx, "absent")
		}},
		{"CredentialStore.DeleteTOTPSecret", func() error { return suite.NewCredentialStore().DeleteTOTPSecret(ctx, "absent") }},
		{"CredentialStore.DeleteWebAuthnCredential", func() error {
			return suite.NewCredentialStore().DeleteWebAuthnCredential(ctx, []byte("absent"))
		}},
	}

	for _, tc := range deletes {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			first := tc.call()
			if first != nil && !errors.Is(first, storage.ErrNotFound) {
				t.Fatalf("deleting an absent key returned %v, want nil or ErrNotFound", first)
			}

			second := tc.call()
			if (first == nil) != (second == nil) {
				t.Fatalf("deleting an absent key is not stable: first %v, second %v", first, second)
			}
			if first != nil && !errors.Is(second, storage.ErrNotFound) {
				t.Fatalf("deleting an absent key returned %v then %v", first, second)
			}
		})
	}
}

// TestStorage_SentinelMessagesCarryNoDetail guards the sentinel texts: they
// travel into logs and, in a careless handler, into responses, so they must not
// read as instructions to an attacker probing which of several failures they hit.
func TestStorage_SentinelMessagesCarryNoDetail(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		storage.ErrNotFound,
		storage.ErrAlreadyExists,
		storage.ErrExpired,
		storage.ErrTokenRevoked,
		storage.ErrInvalidBackupCode,
		storage.ErrBackupCodeUsed,
	} {
		msg := err.Error()
		if msg == "" {
			t.Errorf("sentinel has an empty message")
		}
		if strings.ContainsAny(msg, "%:") {
			t.Errorf("sentinel message %q looks like a format string or a wrapped error", msg)
		}
		if strings.ToLower(msg) != msg {
			t.Errorf("sentinel message %q is not lower-case as the Go style guide requires", msg)
		}
	}
}
