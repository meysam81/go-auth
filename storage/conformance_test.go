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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	// The suite asserts the metadata keys the library ACTUALLY reads and writes,
	// so it takes them from the package that defines them rather than retyping
	// the strings. A copy here would keep passing after auth/oidc moved on, which
	// is the failure this import exists to prevent. An external test package may
	// import a package that imports the package under test, so this is not a
	// cycle.
	authoidc "github.com/meysam81/go-auth/auth/oidc"
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

// ---------------------------------------------------------------------------
// Whole-record round trip
// ---------------------------------------------------------------------------
//
// storage.go states the property these helpers enforce: "A store must round-trip
// a WHOLE record, not the fields it recognizes." A backend that maps one column
// per field it knows about and rebuilds the struct from that list does not fail
// visibly. The record comes back looking valid with a security control quietly
// missing from it -- no error, no log line, and a sign-in that proceeds without
// PKCE or without a browser binding.
//
// The two helpers below walk a record REFLECTIVELY rather than naming its
// fields, so a field added to storage.OIDCState or storage.User in a later
// release is asserted without anybody remembering to come back here. That is the
// only shape of assertion that can catch the backend written against an older
// release of this library, which is the case the contract is actually worried
// about.

// storeManagedFields names the fields a store stamps from its own clock rather
// than preserving. Every interface that carries one takes a TTL or an absolute
// expiry as a separate argument, so the caller's value in the struct is not a
// fact the store was asked to keep.
//
// Nothing else may be skipped. A timestamp added later is checked rather than
// ignored, which fails in the safe direction: the suite reports it and somebody
// decides which side owns the field, instead of a new field being certified by
// never having been looked at.
var storeManagedFields = map[string]bool{
	"CreatedAt": true,
	"UpdatedAt": true,
	"ExpiresAt": true,
}

// fillRecord sets every exported, non-store-managed field of the struct pointed
// to by record to a distinctive non-zero value derived from the field's name.
//
// The values are deterministic, so calling it twice yields two independent
// records that compare equal -- which is how a test gets an untouched "want"
// alongside the struct it hands to the store.
//
// A field whose type this suite cannot fill is a FAILURE rather than a skip. A
// silently unfilled field is a field the round-trip assertion below can never
// catch a store dropping, which would rebuild the very hole this suite exists to
// close.
func fillRecord(t *testing.T, record any) {
	t.Helper()

	value := reflect.ValueOf(record).Elem()
	recordType := value.Type()

	for i := 0; i < recordType.NumField(); i++ {
		field := recordType.Field(i)
		if !field.IsExported() || storeManagedFields[field.Name] {
			continue
		}

		filled, ok := distinctFieldValue(field)
		if !ok {
			t.Fatalf("%s.%s is of type %s, which fillRecord cannot fill: teach it that type, "+
				"or the field is certified by never being tested",
				recordType.Name(), field.Name, field.Type)
		}
		value.Field(i).Set(filled)
	}
}

// distinctFieldValue returns a non-zero value for one field, derived from the
// field's NAME so that two fields of the same type carry different values and a
// store that swaps them is caught alongside one that drops them.
//
// A bool is the exception: it has one non-zero value and cannot carry that
// signal. The round-trip assertion still catches a bool the store discarded,
// which is the failure the contract is about.
func distinctFieldValue(field reflect.StructField) (reflect.Value, bool) {
	switch field.Type {
	case reflect.TypeOf(""):
		return reflect.ValueOf("conformance-" + field.Name), true
	case reflect.TypeOf(false):
		return reflect.ValueOf(true), true
	case reflect.TypeOf(uint32(0)):
		return reflect.ValueOf(uint32(len(field.Name)) + 1), true
	case reflect.TypeOf([]byte(nil)):
		// A NUL and a high byte up front: a store that routes this through a
		// text column, trims it or re-encodes it corrupts it HERE, in a named
		// assertion, rather than later inside somebody's signature check.
		return reflect.ValueOf(append([]byte{0x00, 0xff}, field.Name...)), true
	case reflect.TypeOf([]string(nil)):
		return reflect.ValueOf([]string{field.Name + "-a", field.Name + "-b"}), true
	case reflect.TypeOf(map[string]interface{}(nil)):
		return reflect.ValueOf(map[string]interface{}{"conformance/" + field.Name: field.Name}), true
	}
	return reflect.Value{}, false
}

// recordDiff reports the exported fields of want that got did not preserve.
//
// It returns names instead of failing, so the suite can point it in both
// directions: at a store that must keep everything, and at a deliberately lossy
// store that must be CAUGHT. An assertion nobody has ever seen fail is not
// evidence that it can.
func recordDiff(want, got any) []string {
	wantValue := reflect.ValueOf(want).Elem()
	gotValue := reflect.ValueOf(got).Elem()
	recordType := wantValue.Type()

	var dropped []string
	for i := 0; i < recordType.NumField(); i++ {
		field := recordType.Field(i)
		if !field.IsExported() || storeManagedFields[field.Name] {
			continue
		}
		if !reflect.DeepEqual(wantValue.Field(i).Interface(), gotValue.Field(i).Interface()) {
			dropped = append(dropped, field.Name)
		}
	}
	return dropped
}

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

	// The whole session record, field by field, including fields this suite was
	// not written for. Every authenticated request reads back through here, so a
	// field this store declines to keep is a fact the application loses on every
	// request rather than once.
	t.Run("every field of session data survives the round trip", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		stored := &storage.SessionData{}
		fillRecord(t, stored)
		want := &storage.SessionData{}
		fillRecord(t, want)

		if err := store.CreateSession(ctx, "s1", stored, time.Hour); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		got, err := store.GetSession(ctx, "s1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if dropped := recordDiff(want, got); len(dropped) > 0 {
			t.Fatalf("the store did not round-trip %v\n got: %+v\nwant: %+v", dropped, got, want)
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
	// of the flow together, and the client mirrors each of them into Metadata as
	// well. A store that keeps the caller's struct rather than a copy lets a later
	// mutation -- or a caller reusing one struct across flows -- rewrite the
	// bindings of a flow already in progress, through either copy.
	t.Run("stored state does not alias the caller's struct", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		original := &storage.OIDCState{
			Provider:     "google",
			Nonce:        "nonce-1",
			CodeVerifier: "verifier-1",
			BindingHash:  "hash-1",
			Metadata: map[string]interface{}{
				"tenant":                              "acme",
				authoidc.StateMetadataKeyPKCEVerifier: "verifier-1",
				authoidc.StateMetadataKeyBinding:      "hash-1",
				authoidc.StateMetadataKeyNonce:        "nonce-1",
			},
		}
		if err := store.StoreState(ctx, "s1", original, time.Hour); err != nil {
			t.Fatalf("StoreState: %v", err)
		}

		original.Nonce = "nonce-2"
		original.CodeVerifier = "verifier-2"
		original.BindingHash = "hash-2"
		original.Metadata["tenant"] = "attacker"
		original.Metadata[authoidc.StateMetadataKeyPKCEVerifier] = "verifier-2"
		original.Metadata[authoidc.StateMetadataKeyBinding] = "hash-2"
		original.Metadata[authoidc.StateMetadataKeyNonce] = "nonce-2"

		got, err := store.GetState(ctx, "s1")
		if err != nil {
			t.Fatalf("GetState: %v", err)
		}
		if got.Nonce != "nonce-1" || got.CodeVerifier != "verifier-1" || got.BindingHash != "hash-1" {
			t.Fatalf("the store aliased the caller's struct: %+v", got)
		}
		for key, want := range map[string]string{
			"tenant":                              "acme",
			authoidc.StateMetadataKeyPKCEVerifier: "verifier-1",
			authoidc.StateMetadataKeyBinding:      "hash-1",
			authoidc.StateMetadataKeyNonce:        "nonce-1",
		} {
			if got.Metadata[key] != want {
				t.Errorf("the store aliased metadata key %q: got %v, want %q", key, got.Metadata[key], want)
			}
		}
	})

	// The whole record, field by field, including fields this suite was not
	// written for. See the fillRecord comment: a backend that rebuilds the struct
	// from a fixed column list is the failure mode the OIDC controls were lost to,
	// and it is invisible from the happy path.
	t.Run("every field of a state record survives the round trip", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		stored := &storage.OIDCState{}
		fillRecord(t, stored)
		stored.Metadata = flowStateMetadata()

		// Filled from the same deterministic rule, so it is the record as handed
		// over -- untouched by whatever StoreState does to the struct it is given.
		want := &storage.OIDCState{}
		fillRecord(t, want)
		want.Metadata = flowStateMetadata()

		if err := store.StoreState(ctx, "s1", stored, time.Hour); err != nil {
			t.Fatalf("StoreState: %v", err)
		}
		got, err := store.GetState(ctx, "s1")
		if err != nil {
			t.Fatalf("GetState: %v", err)
		}
		if dropped := recordDiff(want, got); len(dropped) > 0 {
			t.Fatalf("the store did not round-trip %v\n got: %+v\nwant: %+v", dropped, got, want)
		}
	})

	// The three flow controls, asserted at BOTH addresses the OIDC client writes
	// them to and reads them from. This is the assertion the suite was missing:
	// auth/oidc reads each control from its typed field and falls back to the
	// mirrored key, and readStateControls refuses the callback when both copies
	// are gone. A store that keeps one location is survivable; a store that keeps
	// neither stops every sign-in; a store that keeps the typed field and drops
	// Metadata has silently spent the library's whole tolerance for the NEXT
	// field it does not know about.
	t.Run("the flow controls survive in both places the client writes them", func(t *testing.T) {
		t.Parallel()

		const (
			verifier = "H1yYQ0d5cQ1eJ2Yq0wV8Zl3nB7tG4sK9pR6xM2cA0uE"
			digest   = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
			nonce    = "aG9sZC1teS1ub25jZS12YWx1ZS1mb3ItdGhpcy10ZXN0"
		)

		// binding is either a digest or the explicit "unbound" marker. They are
		// not interchangeable and neither may become the empty string: an empty
		// BindingHash is how "the store dropped the digest" is told apart from
		// "this flow was deliberately started without a browser binding", and
		// collapsing the two silently reopens the login CSRF of finding F-16.
		for _, binding := range []string{digest, authoidc.StateBindingUnbound} {
			t.Run("binding="+binding, func(t *testing.T) {
				t.Parallel()
				store := newStore()

				if err := store.StoreState(ctx, "s1", &storage.OIDCState{
					RedirectURL:  "https://app.example.test/after-login",
					Provider:     "google",
					Nonce:        nonce,
					CodeVerifier: verifier,
					BindingHash:  binding,
					Metadata: map[string]interface{}{
						authoidc.StateMetadataKeyPKCEVerifier: verifier,
						authoidc.StateMetadataKeyBinding:      binding,
						authoidc.StateMetadataKeyNonce:        nonce,
						"tenant":                              "acme",
					},
				}, time.Hour); err != nil {
					t.Fatalf("StoreState: %v", err)
				}

				got, err := store.GetState(ctx, "s1")
				if err != nil {
					t.Fatalf("GetState: %v", err)
				}

				controls := []struct {
					name     string
					typed    string
					key      string
					want     string
					protects string
				}{
					{"PKCE code verifier", got.CodeVerifier, authoidc.StateMetadataKeyPKCEVerifier, verifier,
						"F-17: without it an intercepted authorization code is redeemable by whoever holds it"},
					{"browser-binding marker", got.BindingHash, authoidc.StateMetadataKeyBinding, binding,
						"F-16: without it the callback cannot tell the victim's browser from the attacker's"},
					{"nonce", got.Nonce, authoidc.StateMetadataKeyNonce, nonce,
						"F-18: without it an ID token captured from one authentication is replayable into another"},
				}
				for _, control := range controls {
					if control.typed != control.want {
						t.Errorf("%s: typed field = %q, want %q (%s)",
							control.name, control.typed, control.want, control.protects)
					}
					raw, ok := got.Metadata[control.key]
					if !ok {
						t.Errorf("%s: metadata key %q is absent (%s)", control.name, control.key, control.protects)
						continue
					}
					// auth/oidc reports a mirrored control of any other type as
					// corrupt state and refuses the callback, so a store that
					// re-encodes the value -- []byte, json.Number -- fails the
					// sign-in as surely as one that dropped it.
					mirrored, ok := raw.(string)
					if !ok {
						t.Errorf("%s: metadata key %q came back as %T, want string (%s)",
							control.name, control.key, raw, control.protects)
						continue
					}
					if mirrored != control.want {
						t.Errorf("%s: metadata key %q = %q, want %q (%s)",
							control.name, control.key, mirrored, control.want, control.protects)
					}
				}

				// The two fields that decide what the callback does with the
				// record at all: an unknown provider is refused outright, and the
				// redirect URL is where the user lands afterwards.
				if got.Provider != "google" {
					t.Errorf("Provider = %q, want %q: the callback cannot resolve the flow's provider", got.Provider, "google")
				}
				if got.RedirectURL != "https://app.example.test/after-login" {
					t.Errorf("RedirectURL = %q, want the URL the flow started with", got.RedirectURL)
				}
				if got.Metadata["tenant"] != "acme" {
					t.Errorf("the application's own metadata key did not survive: %+v", got.Metadata)
				}
			})
		}
	})

	// The suite's own mutation check. recordDiff is the assertion every
	// round-trip case above rests on, and an assertion nobody has watched fail is
	// not evidence that it can: a store built the ordinary way -- a column per
	// field its author knew about -- must be CAUGHT here, naming the fields it
	// silently discarded.
	t.Run("a store that keeps only the fields it recognizes is caught", func(t *testing.T) {
		t.Parallel()
		store := &columnMappedStateStore{inner: newStore()}

		stored := &storage.OIDCState{}
		fillRecord(t, stored)
		stored.Metadata = flowStateMetadata()

		want := &storage.OIDCState{}
		fillRecord(t, want)
		want.Metadata = flowStateMetadata()

		if err := store.StoreState(ctx, "s1", stored, time.Hour); err != nil {
			t.Fatalf("StoreState: %v", err)
		}
		got, err := store.GetState(ctx, "s1")
		if err != nil {
			t.Fatalf("GetState: %v", err)
		}

		dropped := recordDiff(want, got)
		for _, field := range []string{"CodeVerifier", "BindingHash", "Metadata"} {
			if !slices.Contains(dropped, field) {
				t.Errorf("recordDiff did not report %s as dropped; it reported %v. "+
					"The round-trip cases above are certifying nothing.", field, dropped)
			}
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

// flowStateMetadata is the metadata map the OIDC client actually writes onto a
// state record: one mirrored copy of each flow control under the reserved
// prefix, the application's own key, and a reserved key from no release that
// exists yet.
//
// The last one is the point. storage.go asks a store to persist "any field added
// by a later release rather than reconstructing the struct from a known column
// list", and a metadata key is where that promise is cheapest to break -- a
// backend that filters the map to the keys its author had heard of drops
// tomorrow's control while passing every test written today.
func flowStateMetadata() map[string]interface{} {
	return map[string]interface{}{
		authoidc.StateMetadataKeyPKCEVerifier:    "conformance-pkce-verifier",
		authoidc.StateMetadataKeyBinding:         "conformance-binding-digest",
		authoidc.StateMetadataKeyNonce:           "conformance-nonce",
		"tenant":                                 "acme",
		authoidc.StateMetadataPrefix + "unknown": "a control from a release this store has never seen",
	}
}

// columnMappedStateStore is a store written the way backends usually are: a
// column per field its author knew about, and a metadata map filtered to the
// keys its author recognized.
//
// It is not a strawman. It is exactly what storage.OIDCStateStore looked like to
// anyone who implemented it before the PKCE verifier and the browser-binding
// digest existed, and the record it hands back is indistinguishable from a valid
// one until the callback tries to enforce a control that is no longer there. The
// suite uses it to prove recordDiff can fail.
type columnMappedStateStore struct {
	inner storage.OIDCStateStore
}

// StoreState delegates: the loss is on the way out, which is what makes it hard
// to see.
func (s *columnMappedStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	return s.inner.StoreState(ctx, state, data, ttl)
}

// GetState rebuilds the record from the columns this backend was written for.
func (s *columnMappedStateStore) GetState(ctx context.Context, state string) (*storage.OIDCState, error) {
	full, err := s.inner.GetState(ctx, state)
	if err != nil {
		return nil, err
	}

	rebuilt := &storage.OIDCState{
		RedirectURL: full.RedirectURL,
		Provider:    full.Provider,
		Nonce:       full.Nonce,
		CreatedAt:   full.CreatedAt,
	}
	for key, value := range full.Metadata {
		if key != "tenant" { // the one key this backend has a column for
			continue
		}
		if rebuilt.Metadata == nil {
			rebuilt.Metadata = make(map[string]interface{}, 1)
		}
		rebuilt.Metadata[key] = value
	}
	return rebuilt, nil
}

// DeleteState delegates.
func (s *columnMappedStateStore) DeleteState(ctx context.Context, state string) error {
	return s.inner.DeleteState(ctx, state)
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

	// The whole credential, field by field, including fields this suite was not
	// written for. AAGUID and Transports are the ones a backend is most likely to
	// have no column for, and both are inputs to an authenticator policy the
	// application may enforce later.
	t.Run("every field of a credential survives the round trip", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		stored := &storage.WebAuthnCredential{}
		fillRecord(t, stored)
		want := &storage.WebAuthnCredential{}
		fillRecord(t, want)

		if err := store.StoreWebAuthnCredential(ctx, want.UserID, stored); err != nil {
			t.Fatalf("StoreWebAuthnCredential: %v", err)
		}
		creds, err := store.GetWebAuthnCredentials(ctx, want.UserID)
		if err != nil {
			t.Fatalf("GetWebAuthnCredentials: %v", err)
		}
		if len(creds) != 1 {
			t.Fatalf("GetWebAuthnCredentials returned %d credentials, want 1", len(creds))
		}
		if dropped := recordDiff(want, creds[0]); len(dropped) > 0 {
			t.Fatalf("the store did not round-trip %v\n got: %+v\nwant: %+v", dropped, creds[0], want)
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

	// The whole user record, field by field, including fields this suite was not
	// written for. ProviderSubject is the one that matters most and the one a
	// backend written against an older release has no column for: without it a
	// federated account has nothing to check the next assertion against.
	t.Run("every field of a user survives the round trip", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		stored := &storage.User{}
		fillRecord(t, stored)
		stored.Metadata = map[string]interface{}{
			authoidc.UserMetadataKeyProviderSubject: "conformance-ProviderSubject",
			"department":                            "engineering",
		}

		want := &storage.User{}
		fillRecord(t, want)
		want.Metadata = map[string]interface{}{
			authoidc.UserMetadataKeyProviderSubject: "conformance-ProviderSubject",
			"department":                            "engineering",
		}

		if err := store.CreateUser(ctx, stored); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := store.GetUserByID(ctx, want.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if dropped := recordDiff(want, got); len(dropped) > 0 {
			t.Fatalf("the store did not round-trip %v\n got: %+v\nwant: %+v", dropped, got, want)
		}
	})

	// F-01. The provider's subject identifier is the only stable join key a
	// federated identity offers, and the OIDC client writes it twice: to
	// User.ProviderSubject and to the mirrored metadata key. It writes it on
	// CREATE for a new account and, for an account that predates subject
	// recording, through UPDATE -- a write the interface doc calls out because a
	// store that ignores changes to those two leaves such accounts permanently
	// unpinned, refusing their owners on every sign-in with no way to clear it.
	//
	// The re-read is by EMAIL as well as by ID because that is the lookup the
	// client performs: a store that writes the row but leaves a stale copy behind
	// the email index answers the next sign-in with the un-backfilled record.
	t.Run("a backfilled provider subject survives in both places", func(t *testing.T) {
		t.Parallel()
		store := newStore()

		const (
			email   = "federated@example.test"
			subject = "104291849132384795121"
		)

		// An account from a release that recorded no subject at all.
		if err := store.CreateUser(ctx, &storage.User{
			ID:       "u1",
			Email:    email,
			Provider: "google",
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		existing, err := store.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatalf("GetUserByEmail: %v", err)
		}
		if existing.ProviderSubject != "" {
			t.Fatalf("ProviderSubject = %q on an account created without one", existing.ProviderSubject)
		}

		// Exactly what auth/oidc does when it adopts such an account.
		existing.ProviderSubject = subject
		if existing.Metadata == nil {
			existing.Metadata = make(map[string]interface{}, 1)
		}
		existing.Metadata[authoidc.UserMetadataKeyProviderSubject] = subject
		if err := store.UpdateUser(ctx, existing); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}

		lookups := map[string]func() (*storage.User, error){
			"by ID":    func() (*storage.User, error) { return store.GetUserByID(ctx, "u1") },
			"by email": func() (*storage.User, error) { return store.GetUserByEmail(ctx, email) },
		}
		for name, lookup := range lookups {
			user, err := lookup()
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			if user.ProviderSubject != subject {
				t.Errorf("%s: ProviderSubject = %q, want %q: the backfill was dropped and the account "+
					"is unpinned again (F-01)", name, user.ProviderSubject, subject)
			}
			raw, ok := user.Metadata[authoidc.UserMetadataKeyProviderSubject]
			if !ok {
				t.Errorf("%s: metadata key %q is absent after the backfill (F-01)",
					name, authoidc.UserMetadataKeyProviderSubject)
				continue
			}
			// A present value of the wrong type is reported by auth/oidc as a
			// damaged record and fails the sign-in closed, so it is no better
			// than an absent one.
			mirrored, ok := raw.(string)
			if !ok {
				t.Errorf("%s: metadata key %q came back as %T, want string (F-01)",
					name, authoidc.UserMetadataKeyProviderSubject, raw)
				continue
			}
			if mirrored != subject {
				t.Errorf("%s: metadata key %q = %q, want %q (F-01)",
					name, authoidc.UserMetadataKeyProviderSubject, mirrored, subject)
			}
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
