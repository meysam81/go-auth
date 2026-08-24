package basic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/meysam81/go-auth/auth/totp"
	"github.com/meysam81/go-auth/storage"
	totpLib "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// This file is the adversarial suite for auth/basic. Every test here is written
// to FAIL if the fix it guards is reverted, and each one names the attack rather
// than the function it happens to call. Findings referenced are those in
// docs/security-hardening.md.
//
// It is deliberately self-contained: it shares no fixture with basic_test.go, so
// a change that quietly weakens a shared helper there cannot weaken the evidence
// here.

// errAdvStoreDown is what an instrumented store reports when its backend is
// unreachable. The rollback (F-11) and revocation (F-12) findings are only
// observable when a store fails halfway through a multi-write operation, which
// the in-memory stores never do on their own.
var errAdvStoreDown = errors.New("adversarial: store backend unreachable")

// advCredentialStore is an InMemoryCredentialStore that records every value the
// library hands it and can be told to fail individual writes.
//
// The recording half is the F-05 probe: the argument to StorePasswordResetToken
// is exactly what an attacker with read access to the credential table would see
// (threat model adversary 3), so capturing it is capturing the attacker's view.
type advCredentialStore struct {
	*storage.InMemoryCredentialStore

	mu            sync.Mutex
	storedResets  []string
	storedVerifis []string
	deletedResets []string

	failStorePasswordHash       bool
	failDeleteResetToken        bool
	failDeleteVerificationToken bool
}

func newAdvCredentialStore() *advCredentialStore {
	return &advCredentialStore{InMemoryCredentialStore: storage.NewInMemoryCredentialStore()}
}

func (s *advCredentialStore) StorePasswordHash(ctx context.Context, userID string, hash []byte) error {
	if s.failStorePasswordHash {
		return errAdvStoreDown
	}
	return s.InMemoryCredentialStore.StorePasswordHash(ctx, userID, hash)
}

func (s *advCredentialStore) StorePasswordResetToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	s.mu.Lock()
	s.storedResets = append(s.storedResets, token)
	s.mu.Unlock()
	return s.InMemoryCredentialStore.StorePasswordResetToken(ctx, userID, token, expiresAt)
}

func (s *advCredentialStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	s.mu.Lock()
	s.deletedResets = append(s.deletedResets, token)
	s.mu.Unlock()
	if s.failDeleteResetToken {
		return errAdvStoreDown
	}
	return s.InMemoryCredentialStore.DeletePasswordResetToken(ctx, token)
}

func (s *advCredentialStore) StoreEmailVerificationToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	s.mu.Lock()
	s.storedVerifis = append(s.storedVerifis, token)
	s.mu.Unlock()
	return s.InMemoryCredentialStore.StoreEmailVerificationToken(ctx, userID, token, expiresAt)
}

func (s *advCredentialStore) DeleteEmailVerificationToken(ctx context.Context, token string) error {
	if s.failDeleteVerificationToken {
		return errAdvStoreDown
	}
	return s.InMemoryCredentialStore.DeleteEmailVerificationToken(ctx, token)
}

func (s *advCredentialStore) snapshotResets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.storedResets)
}

func (s *advCredentialStore) snapshotVerifications() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.storedVerifis)
}

// advUserStore is an InMemoryUserStore whose DeleteUser can be made to fail. That
// is the second half of the F-11 scenario: the rollback of a half-written
// registration failing in its turn.
type advUserStore struct {
	*storage.InMemoryUserStore

	mu      sync.Mutex
	lookups int

	failDeleteUser bool
}

// GetUserByEmail and GetUserByUsername count the reads an operation performs
// against the user store. That count is the "shape" half of the F-09 evidence:
// two code paths that draw the same key material but consult the store a
// different number of times are still told apart by a stopwatch.
func (s *advUserStore) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	s.mu.Lock()
	s.lookups++
	s.mu.Unlock()
	return s.InMemoryUserStore.GetUserByEmail(ctx, email)
}

func (s *advUserStore) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	s.mu.Lock()
	s.lookups++
	s.mu.Unlock()
	return s.InMemoryUserStore.GetUserByUsername(ctx, username)
}

func (s *advUserStore) resetLookups() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups = 0
}

func (s *advUserStore) lookupCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookups
}

func newAdvUserStore() *advUserStore {
	return &advUserStore{InMemoryUserStore: storage.NewInMemoryUserStore()}
}

func (s *advUserStore) DeleteUser(ctx context.Context, id string) error {
	if s.failDeleteUser {
		return errAdvStoreDown
	}
	return s.InMemoryUserStore.DeleteUser(ctx, id)
}

// advPermissiveGuard accepts every code. Replay defense (F-08) belongs to
// auth/totp and is asserted there; where this file needs several codes inside one
// 30-second step, the real guard would make the flow untestable rather than
// insecure. The one test that must see the real guard builds it explicitly.
type advPermissiveGuard struct{}

func (advPermissiveGuard) Seen(context.Context, string, string) (bool, error) { return false, nil }

// advEnrollFactor starts a TOTP enrollment for user. The factor is PENDING on
// return: it gates nothing until advConfirmFactor arms it (F-07).
func advEnrollFactor(ctx context.Context, t *testing.T, f *advFixture, user *storage.User) *totp.Secret {
	t.Helper()

	secret, err := f.auth.EnableTOTP(ctx, user.ID, "mfa@example.com")
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	return secret
}

// advConfirmFactor arms a pending enrollment and returns the code that armed it.
// That code is what an attacker who watched the enrollment holds, so the caller
// needs it to mount the replay.
func advConfirmFactor(ctx context.Context, t *testing.T, f *advFixture, user *storage.User, secret *totp.Secret) string {
	t.Helper()

	code, err := totpLib.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("generating a TOTP code: %v", err)
	}
	if err := f.auth.ConfirmTOTP(ctx, user.ID, code); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	return code
}

// advNextCode returns the code for the NEXT time step. pquerna accepts one step
// of skew either side, so a future code stays valid even if the clock crosses a
// boundary mid-test, while a past code would fall out of the window.
func advNextCode(t *testing.T, secret *totp.Secret) string {
	t.Helper()

	code, err := totpLib.GenerateCode(secret.Secret, time.Now().Add(totp.TimeStep))
	if err != nil {
		t.Fatalf("generating the next TOTP code: %v", err)
	}
	return code
}

// advDigest recomputes the documented storage form of a token independently of
// the library's own hashToken, so the F-05 assertions test the contract rather
// than agreeing with whatever the implementation currently does.
func advDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// advEntropyMeter counts what a code path takes from crypto/rand. It is a
// pass-through onto the reader it displaced, so the bytes an assertion observes
// are the same operating-system bytes the library would otherwise have received
// -- the meter measures the draw, it does not replace the source.
//
// It exists because key material is the one part of a "did this work actually
// happen" question that a test can answer by counting instead of timing. See
// TestGeneratePasswordResetToken_UnknownAccountPaysForTheSameCeremony.
type advEntropyMeter struct {
	inner io.Reader

	mu    sync.Mutex
	bytes int
	draws int
}

func (m *advEntropyMeter) Read(p []byte) (int, error) {
	n, err := m.inner.Read(p)

	m.mu.Lock()
	m.bytes += n
	m.draws++
	m.mu.Unlock()

	return n, err
}

func (m *advEntropyMeter) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytes, m.draws = 0, 0
}

// drawn reports the bytes taken since the last reset and the number of reads
// they arrived in.
func (m *advEntropyMeter) drawn() (bytes, draws int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bytes, m.draws
}

// advInstallEntropyMeter swaps the process-global crypto/rand.Reader for a meter
// and restores it when the test ends.
//
// The caller must NOT be parallel. Go releases a package's parallel tests only
// once every serial test has returned, so a serial test owns the global for its
// whole run; a parallel one would race every other test that hashes a password.
func advInstallEntropyMeter(t *testing.T) *advEntropyMeter {
	t.Helper()

	meter := &advEntropyMeter{inner: rand.Reader}
	rand.Reader = meter
	t.Cleanup(func() { rand.Reader = meter.inner })

	return meter
}

// advAuth builds an Authenticator at bcrypt.MinCost unless the caller set a cost.
// Cost 4 keeps a suite that performs dozens of hashes inside a few seconds under
// -race; the tests that depend on the cost set it themselves.
func advAuth(t *testing.T, cfg Config) *Authenticator {
	t.Helper()

	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcrypt.MinCost
	}
	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth
}

// advFixture is the common arrangement: instrumented stores plus an authenticator
// wired to them.
type advFixture struct {
	auth  *Authenticator
	users *advUserStore
	creds *advCredentialStore
}

func newAdvFixture(t *testing.T) *advFixture {
	t.Helper()

	users := newAdvUserStore()
	creds := newAdvCredentialStore()
	return &advFixture{
		auth:  advAuth(t, Config{UserStore: users, CredentialStore: creds}),
		users: users,
		creds: creds,
	}
}

func (f *advFixture) register(ctx context.Context, t *testing.T, email, password string) *storage.User {
	t.Helper()

	user, err := f.auth.Register(ctx, RegisterRequest{Email: email, Password: password})
	if err != nil {
		t.Fatalf("Register(%q): %v", email, err)
	}
	return user
}

// advSignInWorks reports whether the credential pair currently authenticates. It
// distinguishes "wrong password" from a store or wiring failure, because a test
// that reads a broken backend as a rejected password proves nothing.
func advSignInWorks(ctx context.Context, t *testing.T, auth *Authenticator, identifier, password string) bool {
	t.Helper()

	_, err := auth.Authenticate(ctx, identifier, password)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrInvalidCredentials):
		return false
	default:
		t.Fatalf("Authenticate(%q): unexpected error %v", identifier, err)
		return false
	}
}

// ---------------------------------------------------------------------------
// F-10 — bcrypt's 72-byte ceiling
// ---------------------------------------------------------------------------

// TestPassword_SeventyTwoBytePrefixSiblingsCannotBothExist proves the library
// refuses to mint a credential that bcrypt cannot tell apart from another one.
//
// Class: CWE-916, and specifically the bcrypt input ceiling. OpenBSD bcrypt feeds
// the password through the Blowfish key schedule, which consumes at most 72
// bytes; golang.org/x/crypto/bcrypt therefore ignores everything past byte 72 on
// the comparison path. Two passphrases that agree on their first 72 bytes are the
// same credential. This is the same defect class as the 2015 "Okta bcrypt
// truncation" family of advisories -- a long input silently reduced to a prefix
// that a password manager, or an attacker who knows the scheme, can reproduce.
//
// The first subtest establishes that the collision is real in the bcrypt this
// module links, not a hypothetical; the rest assert that no write path in the
// library will create one of the colliding pair.
func TestPassword_SeventyTwoBytePrefixSiblingsCannotBothExist(t *testing.T) {
	t.Parallel()

	const prefixLen = MaxPasswordLength // 72
	prefix := strings.Repeat("correct-horse-battery-staple-", 4)[:prefixLen]
	siblingA := prefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	siblingB := prefix + "BBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	t.Run("bcrypt_itself_conflates_the_siblings", func(t *testing.T) {
		t.Parallel()

		// A digest of the shared 72-byte prefix verifies against BOTH siblings,
		// which is the whole reason the ceiling has to be enforced above bcrypt
		// rather than left to it.
		digest, err := bcrypt.GenerateFromPassword([]byte(prefix), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hashing the shared prefix: %v", err)
		}
		for name, sibling := range map[string]string{"A": siblingA, "B": siblingB} {
			if err := bcrypt.CompareHashAndPassword(digest, []byte(sibling)); err != nil {
				t.Fatalf("sibling %s no longer collides with the prefix digest (%v); "+
					"the premise of this test changed and the assertions below need review", name, err)
			}
		}
	})

	t.Run("no_write_path_accepts_an_over_length_password", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		tests := []struct {
			name  string
			write func(f *advFixture, user *storage.User, password string) error
		}{
			{
				name: "Register",
				write: func(f *advFixture, _ *storage.User, password string) error {
					_, err := f.auth.Register(ctx, RegisterRequest{Email: "sibling@example.com", Password: password})
					return err
				},
			},
			{
				name: "ChangePassword",
				write: func(f *advFixture, user *storage.User, password string) error {
					return f.auth.ChangePassword(ctx, user.ID, "incumbent-password", password)
				},
			},
			{
				name: "ResetPassword",
				write: func(f *advFixture, user *storage.User, password string) error {
					return f.auth.ResetPassword(ctx, user.ID, password)
				},
			},
			{
				name: "CompletePasswordReset",
				write: func(f *advFixture, _ *storage.User, password string) error {
					token, err := f.auth.GeneratePasswordResetToken(ctx, "victim@example.com")
					if err != nil {
						t.Fatalf("GeneratePasswordResetToken: %v", err)
					}
					return f.auth.CompletePasswordReset(ctx, token, password)
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				f := newAdvFixture(t)
				user := f.register(ctx, t, "victim@example.com", "incumbent-password")

				for _, sibling := range []string{siblingA, siblingB} {
					if err := tc.write(f, user, sibling); !errors.Is(err, ErrPasswordTooLong) {
						t.Fatalf("%s accepted a %d-byte password (err = %v); bcrypt would have "+
							"stored only its first %d bytes and the sibling would authenticate it",
							tc.name, len(sibling), err, MaxPasswordLength)
					}
				}

				// The incumbent credential is untouched by the rejected writes.
				if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "incumbent-password") {
					t.Fatal("a rejected over-length write disturbed the existing credential")
				}
				// And neither sibling authenticates.
				for _, sibling := range []string{siblingA, siblingB} {
					if advSignInWorks(ctx, t, f.auth, "victim@example.com", sibling) {
						t.Fatalf("an over-length sibling authenticated after %s refused it", tc.name)
					}
				}
			})
		}
	})

	t.Run("ceiling_boundary_is_exactly_72_bytes", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		tests := []struct {
			name     string
			password string
			wantErr  error
		}{
			{name: "one_below_minimum", password: strings.Repeat("x", MinPasswordLength-1), wantErr: ErrWeakPassword},
			{name: "at_minimum", password: strings.Repeat("x", MinPasswordLength), wantErr: nil},
			{name: "one_below_ceiling", password: strings.Repeat("x", MaxPasswordLength-1), wantErr: nil},
			{name: "at_ceiling", password: strings.Repeat("x", MaxPasswordLength), wantErr: nil},
			{name: "one_above_ceiling", password: strings.Repeat("x", MaxPasswordLength+1), wantErr: ErrPasswordTooLong},
			{name: "far_above_ceiling", password: strings.Repeat("x", 4096), wantErr: ErrPasswordTooLong},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				f := newAdvFixture(t)
				_, err := f.auth.Register(ctx, RegisterRequest{Email: tc.name + "@example.com", Password: tc.password})
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Register with a %d-byte password: got %v, want %v", len(tc.password), err, tc.wantErr)
				}
			})
		}
	})
}

// TestPassword_EmbeddedNULRejected asserts that a password carrying a NUL byte
// never reaches a hash function.
//
// Class: CWE-916 / CWE-158 (improper neutralization of null bytes). Go's bcrypt
// hashes the whole byte slice, but the OpenBSD and PHP implementations a
// deployment may migrate to, or verify against during a migration, treat the
// password as a C string and stop at the NUL. The same stored digest would then
// verify against the prefix alone, so "hunter2\x00<anything>" becomes "hunter2".
// Refusing the byte at the door is what keeps the meaning of a stored digest from
// changing under a future verifier.
func TestPassword_EmbeddedNULRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	passwords := []struct {
		name  string
		input string
	}{
		{name: "leading_nul", input: "\x00truncate-me-here"},
		{name: "interior_nul", input: "hunter2-strong\x00trailing-garbage"},
		{name: "trailing_nul", input: "hunter2-strong\x00"},
		{name: "only_nuls", input: strings.Repeat("\x00", 16)},
		{name: "nul_at_byte_72", input: strings.Repeat("y", MaxPasswordLength-1) + "\x00"},
	}

	writes := []struct {
		name  string
		write func(f *advFixture, user *storage.User, password string) error
	}{
		{
			name: "Register",
			write: func(f *advFixture, _ *storage.User, password string) error {
				_, err := f.auth.Register(ctx, RegisterRequest{Email: "nul@example.com", Password: password})
				return err
			},
		},
		{
			name: "ChangePassword",
			write: func(f *advFixture, user *storage.User, password string) error {
				return f.auth.ChangePassword(ctx, user.ID, "incumbent-password", password)
			},
		},
		{
			name: "ResetPassword",
			write: func(f *advFixture, user *storage.User, password string) error {
				return f.auth.ResetPassword(ctx, user.ID, password)
			},
		},
	}

	for _, w := range writes {
		for _, p := range passwords {
			t.Run(w.name+"/"+p.name, func(t *testing.T) {
				t.Parallel()

				f := newAdvFixture(t)
				user := f.register(ctx, t, "victim@example.com", "incumbent-password")

				err := w.write(f, user, p.input)
				// A NUL-bearing password that is also too short is refused for the
				// length first; either sentinel means it never reached bcrypt, but the
				// NUL cases long enough to pass the length gate must name the NUL.
				if len(p.input) >= MinPasswordLength {
					if !errors.Is(err, ErrPasswordContainsNUL) {
						t.Fatalf("%s accepted a password containing a NUL byte: %v", w.name, err)
					}
				} else if err == nil {
					t.Fatalf("%s accepted a password containing a NUL byte", w.name)
				}

				if advSignInWorks(ctx, t, f.auth, "victim@example.com", p.input) {
					t.Fatal("a NUL-bearing password authenticated")
				}
				if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "incumbent-password") {
					t.Fatal("the rejected write disturbed the existing credential")
				}
			})
		}
	}
}

// TestPassword_CeilingIsMeasuredInBytesNotRunes asserts that the 72-byte limit is
// applied to the UTF-8 encoding.
//
// Class: CWE-916. bcrypt's ceiling is a byte count, so a length check written in
// runes -- utf8.RuneCountInString, or a JavaScript String.length that arrived via
// an API contract -- lets a 25-character CJK passphrase (75 bytes) through, and
// bcrypt then stores 72 of those bytes. The passphrase is silently truncated
// mid-codepoint and the last character of what the user typed is not part of
// their credential.
func TestPassword_CeilingIsMeasuredInBytesNotRunes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Three bytes per rune.
	atCeiling := strings.Repeat("日", MaxPasswordLength/3)     // 24 runes, 72 bytes
	overCeiling := strings.Repeat("日", MaxPasswordLength/3+1) // 25 runes, 75 bytes

	if got := len(atCeiling); got != MaxPasswordLength {
		t.Fatalf("fixture: at-ceiling passphrase is %d bytes, want %d", got, MaxPasswordLength)
	}
	if got := utf8.RuneCountInString(overCeiling); got >= MaxPasswordLength {
		t.Fatalf("fixture: over-ceiling passphrase is %d runes, which a rune-based check "+
			"would also reject -- the test cannot distinguish the two implementations", got)
	}
	if len(overCeiling) <= MaxPasswordLength {
		t.Fatalf("fixture: over-ceiling passphrase is only %d bytes", len(overCeiling))
	}

	f := newAdvFixture(t)

	// 72 bytes is accepted and round-trips: the ceiling is not off by one in the
	// safe direction either, which would be a silent availability bug.
	user, err := f.auth.Register(ctx, RegisterRequest{Email: "cjk@example.com", Password: atCeiling})
	if err != nil {
		t.Fatalf("Register with a 72-byte multi-byte passphrase: %v", err)
	}
	if !advSignInWorks(ctx, t, f.auth, "cjk@example.com", atCeiling) {
		t.Fatal("a 72-byte multi-byte passphrase did not authenticate")
	}

	// 75 bytes -- 25 runes -- is refused. A rune-based check would accept it.
	if _, err := f.auth.Register(ctx, RegisterRequest{Email: "cjk2@example.com", Password: overCeiling}); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Register with a %d-byte / %d-rune passphrase: got %v, want ErrPasswordTooLong",
			len(overCeiling), utf8.RuneCountInString(overCeiling), err)
	}
	if err := f.auth.ChangePassword(ctx, user.ID, atCeiling, overCeiling); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("ChangePassword to a %d-byte passphrase: got %v, want ErrPasswordTooLong", len(overCeiling), err)
	}
	if err := f.auth.ResetPassword(ctx, user.ID, overCeiling); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("ResetPassword to a %d-byte passphrase: got %v, want ErrPasswordTooLong", len(overCeiling), err)
	}

	// The hazard itself, made explicit. bcrypt truncates on the COMPARISON path
	// too, so the 75-byte passphrase verifies against the digest of its own
	// 72-byte prefix. Authenticate is documented not to enforce the ceiling --
	// a credential set before the fix has to keep working -- so the only place
	// the collision can be stopped is where a password is SET. That is what the
	// assertions above are guarding, and this is why they matter.
	if !advSignInWorks(ctx, t, f.auth, "cjk@example.com", overCeiling) {
		t.Fatal("premise check: bcrypt no longer conflates a passphrase with its 72-byte " +
			"prefix on the comparison path, so the reasoning behind the write-path assertions " +
			"above needs review")
	}
}

// ---------------------------------------------------------------------------
// F-09 — account-existence oracles
// ---------------------------------------------------------------------------

// TestAuthenticate_UnknownAccountStillRunsAHashComparison is the STRUCTURAL half
// of the F-09 defense: it proves a bcrypt comparison happens on the not-found
// path, without measuring a clock.
//
// Class: CWE-208, observable timing discrepancy. The probe replaces the
// Authenticator's fixed dummy digest with a value bcrypt cannot parse. bcrypt
// answers a malformed digest with an error distinct from a password mismatch, and
// the library is documented to surface that rather than swallow it -- so the
// unknown-identifier path returns something OTHER than ErrInvalidCredentials
// exactly when the comparison it is supposed to perform is performed. Delete the
// dummy comparison and the path returns ErrInvalidCredentials directly, and this
// test fails with no dependence on machine load.
//
// The companion TestAuthenticate_AccountExistenceIsNotMeasurable makes the
// statistical claim; this one makes the claim that cannot flake.
func TestAuthenticate_UnknownAccountStillRunsAHashComparison(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name string
		// arrange returns the identifier to present.
		arrange func(t *testing.T, f *advFixture) string
	}{
		{
			name: "identifier_matches_no_account",
			arrange: func(t *testing.T, f *advFixture) string {
				t.Helper()
				f.register(ctx, t, "real@example.com", "incumbent-password")
				return "ghost@example.com"
			},
		},
		{
			name: "account_exists_with_no_password_credential",
			arrange: func(t *testing.T, f *advFixture) string {
				t.Helper()
				// An SSO account, or the orphan of a failed registration (F-11). It
				// must cost what a real verification costs too, or it is the same
				// oracle by another name.
				if err := f.users.CreateUser(ctx, &storage.User{
					ID:       "sso-user",
					Email:    "sso@example.com",
					Provider: "oidc",
				}); err != nil {
					t.Fatalf("seeding a credential-less user: %v", err)
				}
				return "sso@example.com"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFixture(t)
			identifier := tc.arrange(t, f)

			// Control: with the real digest in place the path is indistinguishable
			// from a wrong password.
			if _, err := f.auth.Authenticate(ctx, identifier, "whatever-password"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("control: got %v, want ErrInvalidCredentials", err)
			}

			// Probe: a digest bcrypt cannot parse. Only a path that actually calls
			// bcrypt can notice.
			f.auth.dummyHash = []byte("$2a$-not-a-bcrypt-digest")

			_, err := f.auth.Authenticate(ctx, identifier, "whatever-password")
			if err == nil {
				t.Fatal("authentication succeeded against a corrupted equalization digest")
			}
			if errors.Is(err, ErrInvalidCredentials) {
				t.Fatal("the not-found path returned ErrInvalidCredentials without consulting the " +
					"equalization digest: no bcrypt comparison happened, so an unknown account is " +
					"a database round trip while a known one is a full KDF evaluation (F-09, CWE-208)")
			}
			if !strings.Contains(err.Error(), "timing equalization") {
				t.Fatalf("expected the equalization compare to surface its failure, got %v", err)
			}
		})
	}
}

// TestAuthenticate_AccountExistenceIsNotMeasurable is the statistical half of the
// F-09 defense.
//
// Class: CWE-208. Before the fix, an unknown identifier cost two map lookups and
// a known one cost a full bcrypt evaluation -- hundreds of milliseconds apart at
// the default cost, and trivially separable across the internet. An attacker
// walks a list of addresses and keeps the slow ones.
//
// Tolerance, and why:
//
//   - The statistic is the MEDIAN of interleaved samples, not the mean. A median
//     is unmoved by the scheduler preempting a handful of iterations, which is the
//     failure mode that makes timing tests flaky on shared CI.
//   - Samples alternate known/unknown so that any drift in machine load over the
//     run -- a neighboring container waking up, thermal throttling -- lands on
//     both series equally.
//   - The accepted band is 0.4x .. 2.5x. With the fix both paths are one bcrypt
//     evaluation at the same cost and the ratio sits within a few percent of 1.0;
//     the band leaves an order of magnitude of headroom for a loaded box. Without
//     the fix the ratio is on the order of 0.001 -- roughly 400x below the floor
//     -- because the unknown path performs no key derivation at all. There is no
//     plausible amount of CI noise that lands a no-KDF path inside this band.
//   - The test is deliberately NOT parallel, so Go runs it while no other test in
//     this package is executing.
func TestAuthenticate_AccountExistenceIsNotMeasurable(t *testing.T) {
	const (
		// Cost 6 is ~4ms without -race and ~45ms with it: far enough above
		// scheduler granularity that a sample is dominated by the KDF, and cheap
		// enough that the whole test is a couple of seconds.
		measurementCost = 6
		samples         = 21
		warmups         = 3
		lowerBound      = 0.4
		upperBound      = 2.5
		// Below this the KDF plainly is not running and the measurement is
		// meaningless, so the test reports that rather than a ratio.
		implausiblyFast = 200 * time.Microsecond
	)

	ctx := context.Background()
	f := &advFixture{users: newAdvUserStore(), creds: newAdvCredentialStore()}
	f.auth = advAuth(t, Config{UserStore: f.users, CredentialStore: f.creds, BcryptCost: measurementCost})
	f.register(ctx, t, "known@example.com", "incumbent-password")

	measure := func(identifier string) time.Duration {
		start := time.Now()
		if _, err := f.auth.Authenticate(ctx, identifier, "a-wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Authenticate(%q): got %v, want ErrInvalidCredentials", identifier, err)
		}
		return time.Since(start)
	}

	for range warmups {
		measure("known@example.com")
		measure("ghost@example.com")
	}

	known := make([]time.Duration, 0, samples)
	unknown := make([]time.Duration, 0, samples)
	for i := range samples {
		// Alternate the order as well as the target, so a systematic cost paid by
		// whichever call runs first cannot accrue to one series.
		if i%2 == 0 {
			known = append(known, measure("known@example.com"))
			unknown = append(unknown, measure("ghost@example.com"))
		} else {
			unknown = append(unknown, measure("ghost@example.com"))
			known = append(known, measure("known@example.com"))
		}
	}

	median := func(d []time.Duration) time.Duration {
		s := slices.Clone(d)
		slices.Sort(s)
		return s[len(s)/2]
	}

	knownMedian, unknownMedian := median(known), median(unknown)
	if knownMedian < implausiblyFast {
		t.Fatalf("a known-account sign-in took a median of %v at bcrypt cost %d: no key "+
			"derivation is happening on the verification path at all", knownMedian, measurementCost)
	}

	ratio := float64(unknownMedian) / float64(knownMedian)
	t.Logf("median known=%v unknown=%v ratio=%.3f (accepted %.1f..%.1f)",
		knownMedian, unknownMedian, ratio, lowerBound, upperBound)

	if ratio < lowerBound || ratio > upperBound {
		t.Fatalf("sign-in latency reports whether the account exists: unknown identifier is "+
			"%.3fx a known one (median %v vs %v). An unknown account must cost the same key "+
			"derivation as a known one (F-09, CWE-208)", ratio, unknownMedian, knownMedian)
	}
}

// TestGeneratePasswordResetToken_UnknownAccountIsIndistinguishable asserts the
// reset endpoint answers identically whether or not the address is registered.
//
// Class: CWE-204, observable response discrepancy -- the account-enumeration
// oracle OWASP ASVS V2 requires a credential-recovery flow to close. A reset form
// that answers "no such user" for one address and "check your email" for another
// is a membership test for the entire user base, and the addresses it confirms
// are then targets for credential stuffing.
//
// The library's contract is ("", nil) for a miss: no sentinel, no wrapped store
// error, nothing the caller could accidentally render. This test pins that
// contract against hostile identifiers as well as ordinary ones.
func TestGeneratePasswordResetToken_UnknownAccountIsIndistinguishable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	f.register(ctx, t, "known@example.com", "incumbent-password")

	// The known address: a token is minted and exactly one row is written.
	token, err := f.auth.GeneratePasswordResetToken(ctx, "known@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken for a known address: %v", err)
	}
	if token == "" {
		t.Fatal("no token minted for a known address")
	}
	if got := len(f.creds.snapshotResets()); got != 1 {
		t.Fatalf("stored %d reset rows for one request, want 1", got)
	}

	unknowns := []struct {
		name       string
		identifier string
	}{
		{name: "plain_unknown_address", identifier: "ghost@example.com"},
		{name: "empty_identifier", identifier: ""},
		{name: "whitespace_only", identifier: "   "},
		{name: "case_variant_of_a_known_address", identifier: "KNOWN@EXAMPLE.COM"},
		{name: "sql_shaped", identifier: "known@example.com' OR '1'='1"},
		{name: "nul_bearing", identifier: "known@example.com\x00.evil"},
		{name: "newline_injection", identifier: "known@example.com\r\nBcc: attacker@example.net"},
		{name: "oversized", identifier: strings.Repeat("a", 1<<16) + "@example.com"},
		{name: "unicode_confusable", identifier: "knоwn@example.com"},
	}

	for _, tc := range unknowns {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.creds.snapshotResets())

			got, err := f.auth.GeneratePasswordResetToken(ctx, tc.identifier)
			if err != nil {
				t.Fatalf("an unregistered identifier produced an error the caller could render "+
					"back to an anonymous requester: %v (F-09: this is the enumeration oracle)", err)
			}
			if got != "" {
				t.Fatalf("a token was minted for an unregistered identifier: %q", got)
			}
			if after := len(f.creds.snapshotResets()); after != before {
				t.Fatalf("a reset row was written for an unregistered identifier (%d -> %d): "+
					"a store read then reports which addresses were probed", before, after)
			}
		})
	}

	// The genuine token is untouched by the probing.
	if _, err := f.auth.ValidatePasswordResetToken(ctx, token); err != nil {
		t.Fatalf("the legitimate reset token stopped validating after the probe sequence: %v", err)
	}
}

// TestGeneratePasswordResetToken_UnknownAccountPaysForTheSameCeremony is the
// STRUCTURAL half of the F-09 defense on the reset endpoint. The sibling above
// pins the RESPONSE -- "" and a nil error whether or not the address exists --
// and that is exactly the half that survives the defect: a uniform reply
// delivered early is still an oracle, because the attacker times it instead of
// reading it.
//
// Class: CWE-208, observable timing discrepancy. Before the fix an unregistered
// address cost two store reads, while a registered one additionally drew 256
// bits from crypto/rand, hashed them and wrote a row. The fix hoists the mint
// and the hash ABOVE the unknown-user return so both paths pay for the token
// ceremony, leaving only the write asymmetric -- an asymmetry the library cannot
// close without persisting junk rows on behalf of anonymous strangers.
//
// The signal, and why it cannot flake: minting the token is the ONLY draw on
// crypto/rand anywhere on this path, so entropy consumption IS the ceremony,
// counted rather than timed. The probe swaps the process-global
// crypto/rand.Reader for a meter that delegates to the reader it displaced --
// every byte is still crypto/rand's -- and reads the counter around each call.
// Put the early return back and the unknown path draws zero bytes against the
// known path's 32: an integer mismatch, not a duration measured on a loaded CI
// box.
//
// Scope, stated plainly: the SHA-256 that follows the mint leaves no trace a
// test can read. It digests 43 bytes, some three orders of magnitude cheaper
// than the getrandom(2) draw ahead of it, so it carries no network-observable
// signal by itself -- and no early return can skip it while still performing the
// draw this test counts.
func TestGeneratePasswordResetToken_UnknownAccountPaysForTheSameCeremony(t *testing.T) {
	// Deliberately NOT parallel: it swaps a process-global. Go releases a
	// package's parallel tests only after every serial test has returned, so
	// nothing else in this binary is drawing entropy while the meter is installed.

	ctx := context.Background()
	f := newAdvFixture(t)

	// One account, reachable two ways. The email form resolves on the first store
	// read; the username form misses on email and resolves on the second, which is
	// the read count an unknown identifier pays as well -- so against that form
	// the two paths are comparable read for read.
	if _, err := f.auth.Register(ctx, RegisterRequest{
		Email:    "known@example.com",
		Username: "known-by-name",
		Password: "incumbent-password",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Installed after the fixture is built, so the bcrypt salt draws of
	// NewAuthenticator and Register are not attributed to the endpoint.
	meter := advInstallEntropyMeter(t)

	// ceremony is everything an off-box attacker could hope to distinguish: the
	// key-material draw, the store reads and the store write.
	type ceremony struct {
		entropy int // bytes taken from crypto/rand
		draws   int // reads issued against crypto/rand
		reads   int // user-store lookups
		writes  int // reset rows persisted
	}

	measure := func(t *testing.T, identifier string, wantToken bool) ceremony {
		t.Helper()

		meter.reset()
		f.users.resetLookups()
		writesBefore := len(f.creds.snapshotResets())

		token, err := f.auth.GeneratePasswordResetToken(ctx, identifier)
		if err != nil {
			t.Fatalf("GeneratePasswordResetToken(%q): %v", identifier, err)
		}
		if minted := token != ""; minted != wantToken {
			t.Fatalf("GeneratePasswordResetToken(%q): returned a token = %t, want %t",
				identifier, minted, wantToken)
		}

		entropy, draws := meter.drawn()
		return ceremony{
			entropy: entropy,
			draws:   draws,
			reads:   f.users.lookupCount(),
			writes:  len(f.creds.snapshotResets()) - writesBefore,
		}
	}

	// The reference: what a request for a registered address costs.
	known := measure(t, "known@example.com", true)
	t.Logf("registered address: %+v", known)
	if known.entropy == 0 || known.draws == 0 {
		t.Fatalf("a request for a registered address drew no entropy at all (%+v): the meter is "+
			"not observing the token mint, so nothing this test asserts is evidence", known)
	}
	if known.writes != 1 {
		t.Fatalf("a request for a registered address wrote %d reset rows, want exactly 1 (%+v)",
			known.writes, known)
	}

	unknowns := []struct {
		name       string
		identifier string
	}{
		{name: "plain_unknown_address", identifier: "ghost@example.com"},
		{name: "empty_identifier", identifier: ""},
		{name: "whitespace_only", identifier: "   "},
		{name: "case_variant_of_a_known_address", identifier: "KNOWN@EXAMPLE.COM"},
		{name: "sql_shaped", identifier: "known@example.com' OR '1'='1"},
		{name: "oversized", identifier: strings.Repeat("a", 1<<16) + "@example.com"},
	}

	for _, tc := range unknowns {
		t.Run(tc.name, func(t *testing.T) {
			got := measure(t, tc.identifier, false)

			if got.entropy != known.entropy || got.draws != known.draws {
				t.Fatalf("an unregistered identifier drew %d bytes of entropy in %d reads, against "+
					"%d bytes in %d reads for a registered one: the unknown-account path returns "+
					"before minting the token it was never going to send, so the reset endpoint "+
					"still reports account existence in its latency however uniform its reply "+
					"reads (F-09, CWE-208)", got.entropy, got.draws, known.entropy, known.draws)
			}
			if got.writes != 0 {
				t.Fatalf("%d reset rows were written for an unregistered identifier: a read of the "+
					"table then reports which addresses were probed", got.writes)
			}
		})
	}

	// The residual asymmetry the library documents, pinned so it stays one write
	// and nothing else. Addressing the account by username equalizes the store
	// reads too, so any surviving difference between the two ceremonies shows up
	// here as a field that is not `writes`.
	t.Run("differs_from_a_hit_by_exactly_one_store_write", func(t *testing.T) {
		byName := measure(t, "known-by-name", true)
		ghost := measure(t, "ghost@example.com", false)
		t.Logf("username hit: %+v; miss: %+v", byName, ghost)

		if byName.reads != ghost.reads {
			t.Fatalf("a username hit reads the user store %d times against %d for a miss: the two "+
				"paths must be comparable read for read before the entropy claim means anything",
				byName.reads, ghost.reads)
		}
		if byName.entropy != ghost.entropy || byName.draws != ghost.draws {
			t.Fatalf("a username hit drew %d bytes in %d reads and a miss drew %d in %d: the token "+
				"ceremony is not paid on both paths (F-09, CWE-208)",
				byName.entropy, byName.draws, ghost.entropy, ghost.draws)
		}
		if diff := byName.writes - ghost.writes; diff != 1 {
			t.Fatalf("a hit and a miss differ by %d store writes, want exactly 1 (%+v vs %+v): the "+
				"documented residual has changed shape and F-09's analysis above needs review",
				diff, byName, ghost)
		}
	})
}

// ---------------------------------------------------------------------------
// F-05 — reset and verification tokens at rest
// ---------------------------------------------------------------------------

// TestPasswordResetToken_StoreContentsAreNotReplayable asserts that what reaches
// StorePasswordResetToken is not the value the caller emails.
//
// Class: CWE-522, insufficiently protected credentials, against threat model
// adversary 3 -- a leaked backup, a snapshot on shared storage, or a SQL
// injection elsewhere in the host application. A reset token stored verbatim is a
// bearer credential: one SELECT is account takeover for every user with a live
// token, and the takeover leaves no trace because the tokens used are the tokens
// issued.
//
// The decisive assertion is the last one: the exact bytes an attacker would read
// out of the table are presented back to the library and must be refused.
func TestPasswordResetToken_StoreContentsAreNotReplayable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	f.register(ctx, t, "victim@example.com", "incumbent-password")

	token, err := f.auth.GeneratePasswordResetToken(ctx, "victim@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken: %v", err)
	}

	stored := f.creds.snapshotResets()
	if len(stored) != 1 {
		t.Fatalf("stored %d reset rows, want 1", len(stored))
	}
	leaked := stored[0]

	if leaked == token {
		t.Fatal("the credential store received the emailed token verbatim: a read of the reset " +
			"table is account takeover for every user holding a live token (F-05, CWE-522)")
	}
	if strings.Contains(leaked, token) || strings.Contains(token, leaked) {
		t.Fatalf("the stored value and the emailed token share substance (%q vs %q)", leaked, token)
	}
	if want := advDigest(token); leaked != want {
		t.Fatalf("stored value is not the documented SHA-256 digest: got %q, want %q", leaked, want)
	}

	// The attacker's move: present the stolen table contents as the reset link.
	if _, err := f.auth.ValidatePasswordResetToken(ctx, leaked); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("the stored form validated as a reset token (%v): a store read is directly "+
			"replayable (F-05, CWE-522)", err)
	}
	if err := f.auth.CompletePasswordReset(ctx, leaked, "attacker-chosen-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("CompletePasswordReset accepted the stored form: %v", err)
	}
	if advSignInWorks(ctx, t, f.auth, "victim@example.com", "attacker-chosen-password") {
		t.Fatal("the account was taken over using the value read from the credential store")
	}
	if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "incumbent-password") {
		t.Fatal("the incumbent password stopped working after a refused takeover attempt")
	}

	// And the real token still works, so the defense is not simply "nothing validates".
	if _, err := f.auth.ValidatePasswordResetToken(ctx, token); err != nil {
		t.Fatalf("the genuine token did not validate: %v", err)
	}
}

// TestEmailVerificationToken_StoreContentsAreNotReplayable is the same F-05
// assertion for email verification.
//
// Class: CWE-522. A verification token stored verbatim lets an attacker who reads
// the table mark any pending address verified -- which, in a deployment where
// verification gates sign-in or grants entitlements tied to a domain, is the
// whole point of the check.
func TestEmailVerificationToken_StoreContentsAreNotReplayable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	user := f.register(ctx, t, "pending@example.com", "incumbent-password")

	token, mintErr := f.auth.GenerateEmailVerificationToken(ctx, user.ID)
	if mintErr != nil {
		t.Fatalf("GenerateEmailVerificationToken: %v", mintErr)
	}

	stored := f.creds.snapshotVerifications()
	if len(stored) != 1 {
		t.Fatalf("stored %d verification rows, want 1", len(stored))
	}
	leaked := stored[0]

	if leaked == token {
		t.Fatal("the credential store received the emailed verification token verbatim (F-05, CWE-522)")
	}
	if want := advDigest(token); leaked != want {
		t.Fatalf("stored value is not the documented SHA-256 digest: got %q, want %q", leaked, want)
	}

	if err := f.auth.VerifyEmail(ctx, leaked); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyEmail accepted the stored form (%v): a store read verifies any pending address", err)
	}
	after, lookupErr := f.users.GetUserByID(ctx, user.ID)
	if lookupErr != nil {
		t.Fatalf("GetUserByID: %v", lookupErr)
	}
	if after.EmailVerified {
		t.Fatal("the address was marked verified by replaying the stored token form")
	}

	if err := f.auth.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("the genuine verification token did not verify: %v", err)
	}
}

// TestPasswordResetToken_LegacyPlaintextRowDoesNotValidate asserts that a row
// written before the F-05 fix -- the bearer value itself, sitting in the token
// column -- is dead on arrival.
//
// Class: CWE-522. This is the migration property the fix depends on: if lookups
// still matched a plaintext row, an attacker holding a pre-upgrade table dump
// would keep their takeover for the full TTL and the fix would have bought
// nothing for exactly the population it was meant to protect.
func TestPasswordResetToken_LegacyPlaintextRowDoesNotValidate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	user := f.register(ctx, t, "legacy@example.com", "incumbent-password")

	plaintext, mintErr := GenerateResetToken()
	if mintErr != nil {
		t.Fatalf("GenerateResetToken: %v", mintErr)
	}
	expiry := time.Now().Add(time.Hour)

	// The pre-fix library wrote the bearer value here.
	if err := f.creds.StorePasswordResetToken(ctx, user.ID, plaintext, expiry); err != nil {
		t.Fatalf("seeding a legacy plaintext row: %v", err)
	}

	if _, err := f.auth.ValidatePasswordResetToken(ctx, plaintext); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a legacy plaintext row validated (%v): lookups are still matching the bearer "+
			"value, so a pre-upgrade table dump remains usable (F-05, CWE-522)", err)
	}
	if err := f.auth.CompletePasswordReset(ctx, plaintext, "attacker-chosen-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("CompletePasswordReset accepted a legacy plaintext row: %v", err)
	}
	if advSignInWorks(ctx, t, f.auth, "legacy@example.com", "attacker-chosen-password") {
		t.Fatal("a legacy plaintext row was used to take the account over")
	}

	// Control: a row in the NEW form, seeded the same way, does validate. Without
	// this the test above would also pass against a library that validates nothing.
	if err := f.creds.StorePasswordResetToken(ctx, user.ID, advDigest(plaintext), expiry); err != nil {
		t.Fatalf("seeding a hashed row: %v", err)
	}
	gotUser, validateErr := f.auth.ValidatePasswordResetToken(ctx, plaintext)
	if validateErr != nil {
		t.Fatalf("control: a correctly hashed row did not validate: %v", validateErr)
	}
	if gotUser != user.ID {
		t.Fatalf("control: resolved user %q, want %q", gotUser, user.ID)
	}
}

// TestPasswordResetToken_ReplayAfterUseIsRejected asserts a reset link is
// single-use.
//
// Class: CWE-294, authentication bypass by capture-replay, and CWE-613. A reset
// link survives in mailbox backups, in mail-scanner logs, and in the browser
// history of whatever machine opened it. If it stays live for the remainder of
// its TTL, anyone who later reads that mailbox re-takes the account -- after the
// legitimate owner has already used the link and believes the episode closed.
func TestPasswordResetToken_ReplayAfterUseIsRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	f.register(ctx, t, "victim@example.com", "first-password")

	token, err := f.auth.GeneratePasswordResetToken(ctx, "victim@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken: %v", err)
	}

	if err := f.auth.CompletePasswordReset(ctx, token, "second-password"); err != nil {
		t.Fatalf("CompletePasswordReset: %v", err)
	}
	if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "second-password") {
		t.Fatal("the reset did not take effect")
	}

	// The replay, twice, and through both entry points.
	if _, err := f.auth.ValidatePasswordResetToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a consumed reset token still validates (%v): the link is replayable for the "+
			"rest of its TTL (F-05/F-12, CWE-294)", err)
	}
	if err := f.auth.CompletePasswordReset(ctx, token, "attacker-chosen-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a consumed reset token completed a second reset: %v", err)
	}
	if err := f.auth.CompletePasswordReset(ctx, token, "attacker-chosen-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a consumed reset token completed a third reset: %v", err)
	}

	if advSignInWorks(ctx, t, f.auth, "victim@example.com", "attacker-chosen-password") {
		t.Fatal("a replayed reset link changed the password a second time")
	}
	if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "second-password") {
		t.Fatal("the legitimate reset was undone by the replay attempts")
	}
}

// TestPasswordResetToken_MalformedTokensAreRejected walks the mutations an
// attacker reaches for when they hold a near-miss of a real token: a truncated
// copy from a wrapped email line, a case-folded copy from a mail client that
// lowercased the link, a padded copy, a huge one.
//
// Class: CWE-20 / CWE-294. The property under test is that only the exact bearer
// value validates, that none of these inputs panics or resolves to a user, and
// that probing does not disturb the genuine token.
func TestPasswordResetToken_MalformedTokensAreRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	f.register(ctx, t, "victim@example.com", "incumbent-password")

	token, err := f.auth.GeneratePasswordResetToken(ctx, "victim@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken: %v", err)
	}
	if len(token) < 8 {
		t.Fatalf("fixture: token is implausibly short (%d chars)", len(token))
	}

	flipped := []byte(token)
	if flipped[0] == 'a' {
		flipped[0] = 'b'
	} else {
		flipped[0] = 'a'
	}

	mutations := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "truncated_by_one", token: token[:len(token)-1]},
		{name: "truncated_by_half", token: token[:len(token)/2]},
		{name: "first_character_flipped", token: string(flipped)},
		{name: "uppercased", token: strings.ToUpper(token)},
		{name: "lowercased", token: strings.ToLower(token)},
		{name: "leading_whitespace", token: " " + token},
		{name: "trailing_whitespace", token: token + " "},
		{name: "trailing_newline", token: token + "\n"},
		{name: "trailing_nul", token: token + "\x00"},
		{name: "doubled", token: token + token},
		{name: "its_own_digest", token: advDigest(token)},
		{name: "digest_of_its_digest", token: advDigest(advDigest(token))},
		{name: "one_mebibyte", token: strings.Repeat("A", 1<<20)},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			userID, err := f.auth.ValidatePasswordResetToken(ctx, tc.token)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("ValidatePasswordResetToken: got (%q, %v), want ErrInvalidToken", userID, err)
			}
			if userID != "" {
				t.Fatalf("a rejected token still resolved to user %q", userID)
			}
			if err := f.auth.CompletePasswordReset(ctx, tc.token, "attacker-chosen-password"); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("CompletePasswordReset: got %v, want ErrInvalidToken", err)
			}
		})
	}

	if advSignInWorks(ctx, t, f.auth, "victim@example.com", "attacker-chosen-password") {
		t.Fatal("a mutated token completed a password reset")
	}
	if _, err := f.auth.ValidatePasswordResetToken(ctx, token); err != nil {
		t.Fatalf("the genuine token stopped validating after the mutation sweep: %v", err)
	}
}

// TestCompletePasswordReset_OverLengthPasswordLeavesTokenUsable is the
// availability side of the F-10 guard on the reset path: refusing the new
// password must not also burn the link, or the user is left with a password they
// cannot change and a link that no longer works.
func TestCompletePasswordReset_OverLengthPasswordLeavesTokenUsable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	f.register(ctx, t, "victim@example.com", "incumbent-password")

	token, err := f.auth.GeneratePasswordResetToken(ctx, "victim@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken: %v", err)
	}

	if err := f.auth.CompletePasswordReset(ctx, token, strings.Repeat("z", MaxPasswordLength+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("CompletePasswordReset with an over-length password: got %v, want ErrPasswordTooLong", err)
	}
	if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "incumbent-password") {
		t.Fatal("a refused reset changed the password anyway")
	}
	if err := f.auth.CompletePasswordReset(ctx, token, "a-compliant-password"); err != nil {
		t.Fatalf("the token was consumed by a refused reset: %v", err)
	}
	if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "a-compliant-password") {
		t.Fatal("the retried reset did not take effect")
	}
}

// ---------------------------------------------------------------------------
// F-12 — a completed reset must not silently leave its token live
// ---------------------------------------------------------------------------

// TestCompletePasswordReset_TokenDeleteFailureIsNotReportedAsSuccess asserts that
// a failure to revoke the used token is surfaced.
//
// Class: CWE-613, insufficient session/token expiration. The pre-fix code caught
// the delete error, commented that it would be logged, had no logger in scope,
// and returned nil. The caller is then told the reset succeeded while the link
// stays live for the rest of its TTL -- and the caller cannot know to compensate,
// because nothing distinguishable ever reached it.
//
// The password change itself DID happen, so the error must be distinguishable:
// a caller that retries the reset, or reports failure to the user, is wrong in a
// different way.
func TestCompletePasswordReset_TokenDeleteFailureIsNotReportedAsSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	f.register(ctx, t, "victim@example.com", "first-password")

	token, err := f.auth.GeneratePasswordResetToken(ctx, "victim@example.com")
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken: %v", err)
	}

	f.creds.failDeleteResetToken = true

	err = f.auth.CompletePasswordReset(ctx, token, "second-password")
	if err == nil {
		t.Fatal("CompletePasswordReset reported success while the used reset token was still " +
			"live: the same link resets the password again for the rest of its TTL (F-12, CWE-613)")
	}
	if !errors.Is(err, ErrResetTokenNotRevoked) {
		t.Fatalf("the failure is not distinguishable as an un-revoked token: %v", err)
	}
	if !errors.Is(err, errAdvStoreDown) {
		t.Fatalf("the underlying store failure was not preserved for the caller: %v", err)
	}

	// The password change happened. A caller that treats this error as a failed
	// reset and asks the user to try again is telling them something false.
	if !advSignInWorks(ctx, t, f.auth, "victim@example.com", "second-password") {
		t.Fatal("the error was reported but the password was not actually changed")
	}
	if advSignInWorks(ctx, t, f.auth, "victim@example.com", "first-password") {
		t.Fatal("the old password still authenticates after a reported reset")
	}
}

// TestVerifyEmail_TokenDeleteFailureIsNotReportedAsSuccess is the F-12 shape on
// the email-verification path: the address was marked verified, the token could
// not be revoked, and the caller must be told rather than left to assume.
//
// Class: CWE-613.
func TestVerifyEmail_TokenDeleteFailureIsNotReportedAsSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newAdvFixture(t)
	user := f.register(ctx, t, "pending@example.com", "incumbent-password")

	token, err := f.auth.GenerateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateEmailVerificationToken: %v", err)
	}

	f.creds.failDeleteVerificationToken = true

	err = f.auth.VerifyEmail(ctx, token)
	if err == nil {
		t.Fatal("VerifyEmail reported success while the used verification token was still live (F-12, CWE-613)")
	}
	if !errors.Is(err, ErrVerificationTokenNotRevoked) {
		t.Fatalf("the failure is not distinguishable as an un-revoked token: %v", err)
	}
	if !errors.Is(err, errAdvStoreDown) {
		t.Fatalf("the underlying store failure was not preserved for the caller: %v", err)
	}

	after, err := f.users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !after.EmailVerified {
		t.Fatal("the error was reported but the address was not actually verified")
	}
}

// ---------------------------------------------------------------------------
// F-11 — registration rollback
// ---------------------------------------------------------------------------

// TestRegister_RollbackFailureIsSurfacedNotSwallowed asserts that a registration
// which creates a user row, fails to store the credential, and then fails to
// remove the row, reports BOTH failures.
//
// Class: CWE-460, improper cleanup on a thrown exception. The account exists with
// no credential: it can never authenticate, and the duplicate check at the top of
// Register blocks the address from being registered again. The user is locked out
// of their own email address with no self-service path, and the operator learns
// nothing, because the pre-fix code discarded the rollback result into `_`.
//
// This is a denial-of-service primitive as much as a hygiene defect: an attacker
// who can induce credential-store failures poisons chosen addresses.
func TestRegister_RollbackFailureIsSurfacedNotSwallowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("both_writes_fail", func(t *testing.T) {
		t.Parallel()

		f := newAdvFixture(t)
		f.creds.failStorePasswordHash = true
		f.users.failDeleteUser = true

		user, err := f.auth.Register(ctx, RegisterRequest{Email: "orphan@example.com", Password: "incumbent-password"})
		if user != nil {
			t.Fatalf("Register returned a user alongside its error: %+v", user)
		}
		if err == nil {
			t.Fatal("Register succeeded with a failing credential store")
		}
		if !errors.Is(err, ErrRegistrationRollbackFailed) {
			t.Fatalf("the orphaned account was not reported: got %v, want an error wrapping "+
				"ErrRegistrationRollbackFailed (F-11, CWE-460)", err)
		}
		if !errors.Is(err, errAdvStoreDown) {
			t.Fatalf("neither underlying store failure was preserved: %v", err)
		}

		// The operator needs the orphan's ID to clean up out of band, so the error
		// has to name it. Recover it from the store and require the message to
		// contain it.
		orphan, lookupErr := f.users.GetUserByEmail(ctx, "orphan@example.com")
		if lookupErr != nil {
			t.Fatalf("expected the orphaned row to still exist: %v", lookupErr)
		}
		if !strings.Contains(err.Error(), orphan.ID) {
			t.Fatalf("the error does not name the orphaned user ID %q: %v", orphan.ID, err)
		}

		// The consequences the caller has to be warned about are real: the address
		// is now unregistrable and unauthenticatable.
		f.creds.failStorePasswordHash = false
		if _, retryErr := f.auth.Register(ctx, RegisterRequest{Email: "orphan@example.com", Password: "another-password"}); !errors.Is(retryErr, ErrUserExists) {
			t.Fatalf("re-registration of the orphaned address: got %v, want ErrUserExists", retryErr)
		}
		if _, authErr := f.auth.Authenticate(ctx, "orphan@example.com", "incumbent-password"); !errors.Is(authErr, ErrInvalidCredentials) {
			t.Fatalf("authenticating the orphan: got %v, want ErrInvalidCredentials", authErr)
		}
	})

	t.Run("rollback_succeeds_so_no_orphan_is_reported", func(t *testing.T) {
		t.Parallel()

		f := newAdvFixture(t)
		f.creds.failStorePasswordHash = true

		_, err := f.auth.Register(ctx, RegisterRequest{Email: "clean@example.com", Password: "incumbent-password"})
		if err == nil {
			t.Fatal("Register succeeded with a failing credential store")
		}
		if errors.Is(err, ErrRegistrationRollbackFailed) {
			t.Fatalf("a successful rollback was reported as a failed one: %v", err)
		}
		if _, lookupErr := f.users.GetUserByEmail(ctx, "clean@example.com"); !errors.Is(lookupErr, storage.ErrNotFound) {
			t.Fatalf("the half-written user row survived a successful rollback: %v", lookupErr)
		}

		// The address is registrable again once the store recovers.
		f.creds.failStorePasswordHash = false
		if _, retryErr := f.auth.Register(ctx, RegisterRequest{Email: "clean@example.com", Password: "incumbent-password"}); retryErr != nil {
			t.Fatalf("re-registration after a clean rollback: %v", retryErr)
		}
		if !advSignInWorks(ctx, t, f.auth, "clean@example.com", "incumbent-password") {
			t.Fatal("the re-registered account cannot authenticate")
		}
	})
}

// ---------------------------------------------------------------------------
// MFA bypass
// ---------------------------------------------------------------------------

// TestAuthenticate_ConfirmedSecondFactorBlocksPasswordOnlySignIn asserts that a
// user holding a confirmed TOTP factor cannot be authenticated by the
// password-only entry point.
//
// Class: CWE-304, missing critical step in authentication. Before the fix the
// factor was consulted only by AuthenticateWithTOTP, so a call site that reached
// for Authenticate -- an admin console, a legacy handler, an HTTP Basic
// middleware -- silently bypassed the second factor for every enrolled user in
// the deployment. The user sees an enrolled factor in their settings and believes
// it protects them.
//
// The subtests also pin the boundaries that keep the gate from becoming a
// different oracle: a wrong password must not reveal that the account holds a
// factor, and an enrollment still awaiting confirmation must not gate anything
// (F-07, or the user is locked out of a factor they never finished setting up).
func TestAuthenticate_ConfirmedSecondFactorBlocksPasswordOnlySignIn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// newMFAFixture builds an authenticator whose TOTP manager uses the supplied
	// replay guard, registers a user, and returns the fixture plus the user.
	newMFAFixture := func(t *testing.T, guard totp.ReplayGuard) (*advFixture, *storage.User) {
		t.Helper()

		users := newAdvUserStore()
		creds := newAdvCredentialStore()
		mgr, mgrErr := totp.NewManager(totp.Config{
			CredentialStore: creds,
			Issuer:          "AdversarialTest",
			ReplayGuard:     guard,
		})
		if mgrErr != nil {
			t.Fatalf("totp.NewManager: %v", mgrErr)
		}
		f := &advFixture{users: users, creds: creds}
		f.auth = advAuth(t, Config{UserStore: users, CredentialStore: creds, TOTPManager: mgr})
		user := f.register(ctx, t, "mfa@example.com", "incumbent-password")
		return f, user
	}

	t.Run("confirmed_factor_refuses_the_password_only_path", func(t *testing.T) {
		t.Parallel()

		f, user := newMFAFixture(t, advPermissiveGuard{})

		secret := advEnrollFactor(ctx, t, f, user)
		if !secret.Pending {
			t.Fatal("a freshly generated factor is already armed; F-07 has regressed and this test's premise is void")
		}

		// While PENDING the factor gates nothing: the user has not proved the
		// secret reached their authenticator.
		if _, pendingErr := f.auth.Authenticate(ctx, "mfa@example.com", "incumbent-password"); pendingErr != nil {
			t.Fatalf("a pending enrollment blocked sign-in, locking the user out mid-setup (F-07): %v", pendingErr)
		}

		advConfirmFactor(ctx, t, f, user, secret)

		// The attack: correct password, no second factor, through the path that
		// does not ask for one.
		got, err := f.auth.Authenticate(ctx, "mfa@example.com", "incumbent-password")
		if err == nil {
			t.Fatal("a user with a confirmed second factor was authenticated by password alone: " +
				"the enrolled factor is bypassed by whichever call site uses Authenticate (CWE-304)")
		}
		if !errors.Is(err, ErrMFARequired) {
			t.Fatalf("got %v, want ErrMFARequired", err)
		}
		if got != nil {
			t.Fatalf("a principal was handed back alongside ErrMFARequired: %+v", got)
		}

		// Repeating the call does not wear the gate down.
		for range 3 {
			if _, repeatErr := f.auth.Authenticate(ctx, "mfa@example.com", "incumbent-password"); !errors.Is(repeatErr, ErrMFARequired) {
				t.Fatalf("a repeated password-only attempt got %v, want ErrMFARequired", repeatErr)
			}
		}

		// The supported path still works, with a code from the next step so the
		// confirming code is not simply re-presented.
		next := advNextCode(t, secret)
		if _, bothErr := f.auth.AuthenticateWithTOTP(ctx, "mfa@example.com", "incumbent-password", next); bothErr != nil {
			t.Fatalf("AuthenticateWithTOTP with both factors: %v", bothErr)
		}
	})

	t.Run("gate_does_not_leak_that_a_factor_exists", func(t *testing.T) {
		t.Parallel()

		f, user := newMFAFixture(t, advPermissiveGuard{})
		advConfirmFactor(ctx, t, f, user, advEnrollFactor(ctx, t, f, user))

		// ErrMFARequired means "the password was correct". Returning it before the
		// password is verified would turn the MFA gate into a password oracle.
		tests := []struct {
			name       string
			identifier string
			password   string
		}{
			{name: "wrong_password_for_an_enrolled_user", identifier: "mfa@example.com", password: "wrong-password"},
			{name: "unknown_identifier", identifier: "ghost@example.com", password: "incumbent-password"},
			{name: "empty_password", identifier: "mfa@example.com", password: ""},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := f.auth.Authenticate(ctx, tc.identifier, tc.password)
				if errors.Is(err, ErrMFARequired) {
					t.Fatal("ErrMFARequired was returned without a verified password: the MFA gate " +
						"now reports that a password was correct, or that an account is enrolled")
				}
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("got %v, want ErrInvalidCredentials", err)
				}
				if got != nil {
					t.Fatalf("a principal was returned for a failed sign-in: %+v", got)
				}
			})
		}
	})

	t.Run("second_factor_is_not_satisfied_by_a_replayed_confirmation_code", func(t *testing.T) {
		t.Parallel()

		// The real guard here, not the permissive one: the code that armed the
		// factor is the code an attacker shoulder-surfing the enrollment holds.
		f, user := newMFAFixture(t, nil)

		code := advConfirmFactor(ctx, t, f, user, advEnrollFactor(ctx, t, f, user))

		got, err := f.auth.AuthenticateWithTOTP(ctx, "mfa@example.com", "incumbent-password", code)
		if err == nil {
			t.Fatal("the code that armed the factor authenticated a sign-in: a code observed once " +
				"is usable for the rest of its window (RFC 6238 section 5.2, F-08)")
		}
		if got != nil {
			t.Fatalf("a principal was returned for a replayed code: %+v", got)
		}
		// Either sentinel is a rejection: if the step boundary was crossed between
		// the two calls the code is simply invalid, which is also a refusal.
		if !errors.Is(err, totp.ErrCodeReused) && !errors.Is(err, totp.ErrInvalidCode) {
			t.Fatalf("got %v, want ErrCodeReused (or ErrInvalidCode across a step boundary)", err)
		}
	})

	t.Run("wrong_password_with_a_valid_code_is_still_refused", func(t *testing.T) {
		t.Parallel()

		f, user := newMFAFixture(t, advPermissiveGuard{})
		secret := advEnrollFactor(ctx, t, f, user)
		advConfirmFactor(ctx, t, f, user, secret)

		next := advNextCode(t, secret)
		if _, err := f.auth.AuthenticateWithTOTP(ctx, "mfa@example.com", "wrong-password", next); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a valid code with a wrong password: got %v, want ErrInvalidCredentials", err)
		}
		if _, err := f.auth.AuthenticateWithTOTP(ctx, "mfa@example.com", "incumbent-password", "000000"); err == nil {
			t.Fatal("a correct password with an arbitrary code authenticated")
		}
	})
}

// TestNewAuthenticator_FailsClosedOnUnknownMFAEnforcement asserts that a
// MFAEnforcement value nobody defined is refused at construction rather than
// interpreted at the first sign-in.
//
// Class: CWE-1188 / CWE-304. The field decides whether an enrolled second factor
// is enforced. A value that arrived from a config file, an integer cast, or a
// future constant this build does not know must not be silently resolved to some
// behavior -- and a deployment must learn about it at startup, not from an
// incident.
func TestNewAuthenticator_FailsClosedOnUnknownMFAEnforcement(t *testing.T) {
	t.Parallel()

	for _, enforcement := range []MFAEnforcement{-1, 2, 7, 1 << 20} {
		t.Run(fmt.Sprintf("enforcement_%d", enforcement), func(t *testing.T) {
			t.Parallel()

			auth, err := NewAuthenticator(Config{
				UserStore:              storage.NewInMemoryUserStore(),
				CredentialStore:        storage.NewInMemoryCredentialStore(),
				BcryptCost:             bcrypt.MinCost,
				RequireMFAWhenEnrolled: enforcement,
			})
			if err == nil {
				t.Fatalf("NewAuthenticator accepted MFAEnforcement(%d): a value nobody defined "+
					"decides whether a second factor is enforced", enforcement)
			}
			if auth != nil {
				t.Fatal("NewAuthenticator returned an authenticator alongside its error")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// bcrypt cost boundary
// ---------------------------------------------------------------------------

// TestNewAuthenticator_BcryptCostOutsideRangeIsRefused asserts a cost outside
// bcrypt's own range fails at construction.
//
// Class: CWE-916, insufficient computational effort. The trap is specific and
// silent: golang.org/x/crypto/bcrypt substitutes its own DefaultCost (10) for any
// cost below MinCost instead of erroring, so a deployment that configures cost 2 —
// or 0 through an unmarshalled config, or a negative from a bad cast — gets
// hashes at a cost it never chose and never learns. Above MaxCost the failure
// surfaces instead at the first sign-in, in production. The constructor is the
// only place where either is visible before it matters.
//
// bcrypt.MaxCost itself is deliberately not exercised as an accepted value: a
// cost-31 hash is 2^31 key expansions and would not finish.
func TestNewAuthenticator_BcryptCostOutsideRangeIsRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cost    int
		wantErr bool
	}{
		{name: "negative", cost: -1, wantErr: true},
		{name: "large_negative", cost: -1 << 20, wantErr: true},
		{name: "one", cost: 1, wantErr: true},
		{name: "one_below_min", cost: bcrypt.MinCost - 1, wantErr: true},
		{name: "at_min", cost: bcrypt.MinCost, wantErr: false},
		{name: "one_above_max", cost: bcrypt.MaxCost + 1, wantErr: true},
		{name: "far_above_max", cost: 1 << 20, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			auth, err := NewAuthenticator(Config{
				UserStore:       storage.NewInMemoryUserStore(),
				CredentialStore: storage.NewInMemoryCredentialStore(),
				BcryptCost:      tc.cost,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewAuthenticator accepted bcrypt cost %d; bcrypt would silently "+
						"substitute cost %d below its minimum, or fail at the first sign-in above "+
						"its maximum (F-10 family, CWE-916)", tc.cost, bcrypt.DefaultCost)
				}
				if auth != nil {
					t.Fatal("NewAuthenticator returned an authenticator alongside its error")
				}
				return
			}

			if err != nil {
				t.Fatalf("NewAuthenticator rejected the in-range cost %d: %v", tc.cost, err)
			}
			// The accepted cost is the cost actually applied -- on the equalization
			// digest and on a stored credential alike.
			if got, costErr := bcrypt.Cost(auth.dummyHash); costErr != nil || got != tc.cost {
				t.Fatalf("equalization digest cost = %d (err %v), want %d", got, costErr, tc.cost)
			}
			user, regErr := auth.Register(context.Background(), RegisterRequest{
				Email:    "cost@example.com",
				Password: "incumbent-password",
			})
			if regErr != nil {
				t.Fatalf("Register: %v", regErr)
			}
			hash, hashErr := auth.credentialStore.GetPasswordHash(context.Background(), user.ID)
			if hashErr != nil {
				t.Fatalf("GetPasswordHash: %v", hashErr)
			}
			if got, costErr := bcrypt.Cost(hash); costErr != nil || got != tc.cost {
				t.Fatalf("stored credential cost = %d (err %v), want %d", got, costErr, tc.cost)
			}
		})
	}
}
