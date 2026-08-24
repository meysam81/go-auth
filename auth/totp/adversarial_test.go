package totp

// Adversarial suite for auth/totp.
//
// Every test in this file is written to fail if the hardening it covers is reverted. The
// findings referenced are those of docs/security-hardening.md:
//
//	F-06  TOTP secrets and backup codes are stored in plaintext (CWE-522)
//	F-07  TOTP enrollment activates before the user proves possession (CWE-693)
//	F-08  TOTP codes may be replayed inside their validity window (CWE-294)
//
// The adversary is the one the module's threat model puts third and fourth: someone holding a
// read of the credential store, and an authenticated user replaying their own one-time code.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meysam81/go-auth/storage"
	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
)

// --- fixtures -------------------------------------------------------------------------

// advManager builds a Manager over a fresh in-memory credential store and returns both, so a
// test can inspect exactly what reached persistence.
func advManager(t *testing.T, mutate func(*Config)) (*Manager, *storage.InMemoryCredentialStore) {
	t.Helper()

	store := storage.NewInMemoryCredentialStore()
	cfg := Config{CredentialStore: store, Issuer: "AdversaryApp"}
	if mutate != nil {
		mutate(&cfg)
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr, store
}

// advCodeAt renders the code for the time step `steps` away from now.
func advCodeAt(t *testing.T, secret string, steps int) string {
	t.Helper()

	code, err := otptotp.GenerateCode(secret, time.Now().Add(time.Duration(steps)*TimeStep))
	if err != nil {
		t.Fatalf("GenerateCode(%+d steps): %v", steps, err)
	}
	return code
}

// advEnroll runs the full enrollment: generate, then arm with a code from the PREVIOUS step so
// the current step's code is left unburned for the calling test. It returns the enrollment and
// the code that was spent confirming it.
func advEnroll(ctx context.Context, t *testing.T, mgr *Manager, userID string) (*Secret, string) {
	t.Helper()

	sec, err := mgr.GenerateSecret(ctx, userID, userID+"@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret(%s): %v", userID, err)
	}

	confirmCode := advCodeAt(t, sec.Secret, -1)
	if err := mgr.Confirm(ctx, userID, confirmCode); err != nil {
		t.Fatalf("Confirm(%s): %v", userID, err)
	}
	return sec, confirmCode
}

// advStepIndex is the RFC 6238 section 4.2 counter T for an instant.
func advStepIndex(ts time.Time) int64 {
	return ts.Unix() / int64(TimeStep/time.Second)
}

// advAESCipher is an authenticated AES-256-GCM Cipher, which is what Config.Cipher documents
// as acceptable. It is authenticated on purpose: a test that tampers with the stored
// ciphertext needs Decrypt to genuinely fail rather than return garbage.
type advAESCipher struct {
	aead cipher.AEAD
}

func newAdvAESCipher(t *testing.T) *advAESCipher {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return &advAESCipher{aead: aead}
}

func (c *advAESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *advAESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.aead.NonceSize() {
		return nil, errors.New("ciphertext shorter than nonce")
	}
	nonce, body := ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():]
	out, err := c.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return out, nil
}

// advBrokenCipher encrypts but never decrypts: it models a rotated-away or wrong key.
type advBrokenCipher struct{ inner Cipher }

func (c advBrokenCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(plaintext)
}

func (c advBrokenCipher) Decrypt([]byte) ([]byte, error) {
	return nil, errors.New("key unavailable")
}

// advEncryptFailsCipher fails on the way in, to prove nothing is persisted when it does.
type advEncryptFailsCipher struct{}

func (advEncryptFailsCipher) Encrypt([]byte) ([]byte, error) {
	return nil, errors.New("KMS unreachable")
}

func (advEncryptFailsCipher) Decrypt([]byte) ([]byte, error) {
	return nil, errors.New("KMS unreachable")
}

// advNoReplayGuard records nothing, so a test can isolate the skew window from the replay
// protection that would otherwise be the reason a code is refused.
type advNoReplayGuard struct{}

func (advNoReplayGuard) Seen(context.Context, string, string) (bool, error) { return false, nil }

// advHostileCodes are the shapes an attacker or a broken client actually submits. None of them
// is a live code for any secret in this file.
func advHostileCodes() []struct {
	name string
	code string
} {
	return []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"spaces only", "      "},
		{"tab and newline", "\t\n"},
		{"single zero", "0"},
		{"non numeric", "abcdef"},
		{"alphanumeric mix", "12ab56"},
		{"unicode digits", "１２３４５６"},
		{"embedded NUL", "12\x0034\x0056"},
		{"leading plus", "+123456"},
		{"negative", "-123456"},
		{"hex looking", "0x1234"},
		{"seven digits", "1234567"},
		{"five digits", "12345"},
		{"sql fragment", "' OR 1=1 --"},
		{"format verb", "%s%d%!"},
		{"dash separated", "123-456"},
		{"very long digits", strings.Repeat("9", 1<<16)},
		{"very long text", strings.Repeat("A", 1<<16)},
	}
}

// --- F-08: replay inside the validity window ------------------------------------------

// TestTOTP_CodeReplayedInsideWindowRejected covers F-08. RFC 6238 section 5.2 requires the
// verifier to refuse a one-time password that has already authenticated: the protocol's
// entire value is that an observed code is spent. pquerna/otp is stateless by design, so
// without the ReplayGuard an attacker who shoulder-surfs, phishes or proxies a code has the
// remainder of the step plus the skew window to present it again.
func TestTOTP_CodeReplayedInsideWindowRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)
	sec, confirmCode := advEnroll(ctx, t, mgr, "victim")

	code := advCodeAt(t, sec.Secret, 0)
	if code == confirmCode {
		t.Skip("current step's code collided with the confirmation code (1 in 10^6)")
	}

	valid, err := mgr.Validate(ctx, "victim", code)
	if err != nil || !valid {
		t.Fatalf("first presentation must authenticate: valid=%v err=%v", valid, err)
	}

	// The replay. Three attempts, because an attacker does not stop at one.
	for attempt := 1; attempt <= 3; attempt++ {
		valid, err = mgr.Validate(ctx, "victim", code)
		if valid {
			t.Fatalf("attempt %d: a spent code authenticated again (F-08)", attempt)
		}
		if !errors.Is(err, ErrCodeReused) {
			t.Fatalf("attempt %d: want ErrCodeReused, got %v", attempt, err)
		}
	}

	// Burning one code must not lock the user out of the next one, or the guard becomes a
	// denial-of-service against the legitimate user.
	next := advCodeAt(t, sec.Secret, 1)
	if next != code && next != confirmCode {
		valid, err = mgr.Validate(ctx, "victim", next)
		if err != nil || !valid {
			t.Fatalf("an unspent code must still authenticate: valid=%v err=%v", valid, err)
		}
	}

	// The guard is keyed per user: the same digits are a different fact for another account.
	otherSec, otherConfirm := advEnroll(ctx, t, mgr, "bystander")
	otherCode := advCodeAt(t, otherSec.Secret, 0)
	if otherCode != otherConfirm {
		if valid, err := mgr.Validate(ctx, "bystander", otherCode); err != nil || !valid {
			t.Fatalf("a second user must not inherit the first user's spent codes: valid=%v err=%v", valid, err)
		}
	}
}

// TestTOTP_ConfirmedCodeCannotBeReplayedAsSignIn covers F-07 crossed with F-08: the code the
// user submits to arm the factor is a live one-time password. If Confirm does not spend it,
// anyone who observed the enrollment form replays it as an authentication seconds later.
func TestTOTP_ConfirmedCodeCannotBeReplayedAsSignIn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	code := advCodeAt(t, sec.Secret, 0)
	if confirmErr := mgr.Confirm(ctx, "u", code); confirmErr != nil {
		t.Fatalf("Confirm: %v", confirmErr)
	}

	valid, err := mgr.Validate(ctx, "u", code)
	if valid {
		t.Fatal("the confirmation code authenticated a sign-in (F-08)")
	}
	if !errors.Is(err, ErrCodeReused) {
		t.Fatalf("want ErrCodeReused, got %v", err)
	}
}

// TestTOTP_ConcurrentReplayAdmitsExactlyOne covers the race that a check-then-record guard
// loses: two presentations of the same stolen code arriving together must not both observe
// "not seen". ReplayGuard.Seen documents the check and the record as one operation.
func TestTOTP_ConcurrentReplayAdmitsExactlyOne(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)
	sec, confirmCode := advEnroll(ctx, t, mgr, "u")

	code := advCodeAt(t, sec.Secret, 0)
	if code == confirmCode {
		t.Skip("current step's code collided with the confirmation code (1 in 10^6)")
	}

	const attackers = 24
	var (
		mu       sync.Mutex
		accepted int
		reused   int
		other    []error
		wg       sync.WaitGroup
		start    = make(chan struct{})
	)

	wg.Add(attackers)
	for i := 0; i < attackers; i++ {
		go func() {
			defer wg.Done()
			<-start
			valid, err := mgr.Validate(ctx, "u", code)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case valid && err == nil:
				accepted++
			case errors.Is(err, ErrCodeReused):
				reused++
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected outcomes: %v", other)
	}
	if accepted != 1 {
		t.Fatalf("a one-time code authenticated %d concurrent presentations, want exactly 1 (F-08)", accepted)
	}
	if reused != attackers-1 {
		t.Fatalf("want %d rejections, got %d", attackers-1, reused)
	}
}

// TestTOTP_SkewWindowBoundary pins the acceptance window to the +/-1 step that RFC 6238
// section 5.2 recommends ("at most one time step"). A window that silently widens is a
// window an attacker gets to replay inside of, and one that narrows locks out a user whose
// clock drifts by a few seconds.
func TestTOTP_SkewWindowBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		steps int
		want  bool
	}{
		{"two steps in the past", -2, false},
		{"previous step", -1, true},
		{"current step", 0, true},
		{"next step", 1, true},
		{"two steps in the future", 2, false},
		{"five steps in the future", 5, false},
		{"a full minute in the past", -10, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			// The replay guard is disabled here on purpose: arming the factor necessarily
			// spends a code from inside the window under test, and this case is about the
			// window, not about replay. F-08 is covered by its own tests.
			mgr, _ := advManager(t, func(c *Config) { c.ReplayGuard = advNoReplayGuard{} })
			sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
			if err != nil {
				t.Fatalf("GenerateSecret: %v", err)
			}
			if err := mgr.Confirm(ctx, "u", advCodeAt(t, sec.Secret, 0)); err != nil {
				t.Fatalf("Confirm: %v", err)
			}

			// The offsets are measured from the instant the code is minted; if the clock
			// crosses a step boundary between minting and validating, the window has moved
			// under the assertion. Retry rather than flake.
			for attempt := 0; attempt < 8; attempt++ {
				before := time.Now()
				code := advCodeAt(t, sec.Secret, tc.steps)
				valid, err := mgr.Validate(ctx, "u", code)
				after := time.Now()
				if advStepIndex(before) != advStepIndex(after) {
					continue
				}

				if tc.want && (!valid || err != nil) {
					t.Fatalf("code %+d steps away must be accepted: valid=%v err=%v", tc.steps, valid, err)
				}
				if !tc.want {
					if valid {
						t.Fatalf("code %+d steps away was accepted; the skew window is wider than documented", tc.steps)
					}
					if err != nil {
						t.Fatalf("an out-of-window code must be a plain rejection, got %v", err)
					}
				}
				return
			}
			t.Skip("could not observe a validation that did not straddle a step boundary")
		})
	}
}

// TestTOTP_ReplayGuardFailsClosed proves the guard denies rather than degrades. A guard that
// errors and is then ignored is worse than no guard: it reads as protection in the code and
// provides none.
func TestTOTP_ReplayGuardFailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("guard at capacity", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		guard := NewMemoryReplayGuard()
		mgr, _ := advManager(t, func(c *Config) { c.ReplayGuard = guard })
		sec, confirmCode := advEnroll(ctx, t, mgr, "u")

		guard.mu.Lock()
		guard.maxEntries = 0
		guard.mu.Unlock()

		code := advCodeAt(t, sec.Secret, 0)
		if code == confirmCode {
			t.Skip("code collision (1 in 10^6)")
		}

		valid, err := mgr.Validate(ctx, "u", code)
		if valid {
			t.Fatal("a code that could not be recorded was accepted; it is then replayable (F-08)")
		}
		if !errors.Is(err, ErrReplayGuardFull) {
			t.Fatalf("want ErrReplayGuardFull, got %v", err)
		}
	})

	t.Run("guard lookup canceled", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		mgr, _ := advManager(t, nil)
		sec, confirmCode := advEnroll(ctx, t, mgr, "u")

		code := advCodeAt(t, sec.Secret, 0)
		if code == confirmCode {
			t.Skip("code collision (1 in 10^6)")
		}

		canceled, cancel := context.WithCancel(ctx)
		cancel()

		valid, err := mgr.Validate(canceled, "u", code)
		if valid {
			t.Fatal("a code accepted while the guard was unreachable is a replayable code (F-08)")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want a cancellation error, got %v", err)
		}
	})
}

// TestTOTP_ReplayGuardKeyIsUnambiguous defends the guard's own key construction. Concatenating
// the user ID and the code without a separator makes ("ab","c") and ("a","bc") the same entry,
// which both loses replay protection and lets one account's traffic reject another's codes.
func TestTOTP_ReplayGuardKeyIsUnambiguous(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	guard := NewMemoryReplayGuard()

	seen, err := guard.Seen(ctx, "ab", "c")
	if err != nil || seen {
		t.Fatalf("first record: seen=%v err=%v", seen, err)
	}

	seen, err = guard.Seen(ctx, "a", "bc")
	if err != nil {
		t.Fatalf("second record: %v", err)
	}
	if seen {
		t.Fatal(`("a","bc") collided with ("ab","c"): the guard key is ambiguous`)
	}

	// And the record it did make is its own.
	seen, err = guard.Seen(ctx, "a", "bc")
	if err != nil || !seen {
		t.Fatalf("re-presentation must be seen: seen=%v err=%v", seen, err)
	}
}

// TestTOTP_ReplayGuardRetentionCoversWholeSkewWindow checks the eviction cadence against the
// property that matters: a recorded code must stay recorded for at least as long as the
// validator would still accept it. Evicting after a single step would hand the attacker the
// tail of the +/-1 window back.
func TestTOTP_ReplayGuardRetentionCoversWholeSkewWindow(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC) // exactly on a step boundary

	offsets := []time.Duration{0, time.Second, 15 * time.Second, 29 * time.Second, TimeStep - time.Millisecond}
	for _, offset := range offsets {
		t.Run(fmt.Sprintf("recorded %s into the step", offset), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			now := base.Add(offset)
			guard := NewMemoryReplayGuard()
			guard.now = func() time.Time { return now }

			if seen, err := guard.Seen(ctx, "u", "424242"); err != nil || seen {
				t.Fatalf("first record: seen=%v err=%v", seen, err)
			}

			// The last instant the validator would still accept a code first seen now.
			now = base.Add(offset).Add(2 * TimeStep)
			if seen, err := guard.Seen(ctx, "u", "424242"); err != nil || !seen {
				t.Fatalf("code forgotten while still inside its acceptance window: seen=%v err=%v", seen, err)
			}
		})
	}

	t.Run("evicted after the window closes", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		now := base
		guard := NewMemoryReplayGuard()
		guard.now = func() time.Time { return now }

		if seen, err := guard.Seen(ctx, "u", "424242"); err != nil || seen {
			t.Fatalf("first record: seen=%v err=%v", seen, err)
		}

		now = base.Add(replayRetentionSteps * TimeStep)
		if seen, err := guard.Seen(ctx, "u", "424242"); err != nil || seen {
			t.Fatalf("entry outlived its window; the guard is unbounded: seen=%v err=%v", seen, err)
		}
		guard.mu.Lock()
		entries := len(guard.entries)
		guard.mu.Unlock()
		if entries != 1 {
			t.Fatalf("expired entries were not purged: %d entries held", entries)
		}
	})
}

// --- F-07: enrollment must not arm before possession is proven --------------------------

// TestTOTP_PendingSecretDoesNotAuthenticate covers F-07 (CWE-693, protection mechanism
// failure). A factor that goes live the instant the QR code renders locks out any user who
// never scans it, and arms a credential the user has never demonstrated they hold.
func TestTOTP_PendingSecretDoesNotAuthenticate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if !sec.Pending {
		t.Fatal("a freshly generated factor must report Pending (F-07)")
	}

	// A live, correct code must not authenticate a factor that was never confirmed.
	for _, steps := range []int{-1, 0, 1} {
		valid, stepErr := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, steps))
		if valid {
			t.Fatalf("a pending factor authenticated a code from step %+d (F-07)", steps)
		}
		if !errors.Is(stepErr, ErrPendingConfirmation) {
			t.Fatalf("want ErrPendingConfirmation, got %v", stepErr)
		}
	}

	// Nor may the backup codes rescue it: they would be a standing bypass of confirmation.
	valid, err := mgr.ValidateBackupCode(ctx, "u", sec.BackupCodes[0])
	if valid {
		t.Fatal("a backup code authenticated a pending factor (F-07)")
	}
	if !errors.Is(err, ErrPendingConfirmation) {
		t.Fatalf("want ErrPendingConfirmation, got %v", err)
	}

	// Nor may new ones be minted for it.
	if _, regenErr := mgr.RegenerateBackupCodes(ctx, "u"); !errors.Is(regenErr, ErrPendingConfirmation) {
		t.Fatalf("RegenerateBackupCodes on a pending factor: want ErrPendingConfirmation, got %v", regenErr)
	}

	// The gate a sign-in flow reads must not claim the factor is live.
	enabled, err := mgr.IsEnabled(ctx, "u")
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if enabled {
		t.Fatal("IsEnabled reported true for an unconfirmed factor (F-07)")
	}
	pending, err := mgr.IsPending(ctx, "u")
	if err != nil || !pending {
		t.Fatalf("IsPending: pending=%v err=%v", pending, err)
	}

	// The stored row carries the pending marker, not a bare secret that an older reader
	// would treat as armed.
	stored, _, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	if !strings.HasPrefix(stored, secretPrefix+secretStatePending+"$") {
		t.Fatalf("stored payload is not marked pending: %q", stored)
	}
}

// TestTOTP_ConfirmWithWrongCodeDoesNotArmFactor covers F-07's other half: the confirmation
// step is only a control if it actually verifies. Every hostile submission must leave the
// factor pending and leave the user able to retry.
func TestTOTP_ConfirmWithWrongCodeDoesNotArmFactor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	otherKey, err := otptotp.Generate(otptotp.GenerateOpts{Issuer: "Other", AccountName: "o@example.test", SecretSize: 32})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	type hostileCode = struct {
		name string
		code string
	}
	cases := append(advHostileCodes(),
		// Correctly derived from the right secret, simply not live.
		hostileCode{"code from ten steps away", advCodeAt(t, sec.Secret, 10)},
		// Correctly derived from the wrong secret.
		hostileCode{"code from another user's secret", advCodeAt(t, otherKey.Secret(), 0)},
		// A backup code is not proof that the authenticator received the secret.
		hostileCode{"backup code instead of a TOTP code", sec.BackupCodes[0]},
	)

	for _, tc := range cases {
		if otptotp.Validate(tc.code, sec.Secret) {
			t.Fatalf("%s: fixture is a live code; the case proves nothing", tc.name)
		}

		if confirmErr := mgr.Confirm(ctx, "u", tc.code); !errors.Is(confirmErr, ErrInvalidCode) {
			t.Fatalf("Confirm(%s): want ErrInvalidCode, got %v", tc.name, confirmErr)
		}

		enabled, enabledErr := mgr.IsEnabled(ctx, "u")
		if enabledErr != nil {
			t.Fatalf("IsEnabled after %s: %v", tc.name, enabledErr)
		}
		if enabled {
			t.Fatalf("a failed Confirm(%s) armed the factor (F-07)", tc.name)
		}
	}

	// The failures must not have consumed the enrollment: the real code still arms it.
	if confirmErr := mgr.Confirm(ctx, "u", advCodeAt(t, sec.Secret, 0)); confirmErr != nil {
		t.Fatalf("Confirm with the correct code: %v", confirmErr)
	}
	enabled, err := mgr.IsEnabled(ctx, "u")
	if err != nil || !enabled {
		t.Fatalf("IsEnabled after a correct Confirm: enabled=%v err=%v", enabled, err)
	}
	pending, err := mgr.IsPending(ctx, "u")
	if err != nil || pending {
		t.Fatalf("IsPending after a correct Confirm: pending=%v err=%v", pending, err)
	}

	// Confirming again is not an authentication event, it is a caller bug.
	if err := mgr.Confirm(ctx, "u", advCodeAt(t, sec.Secret, 1)); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second Confirm: want ErrNotPending, got %v", err)
	}
}

// TestTOTP_ConfirmWithoutEnrollmentIsNotAnEnrollment closes the obvious shortcut around the
// pending state: Confirm must never create the factor it is supposed to be confirming.
func TestTOTP_ConfirmWithoutEnrollmentIsNotAnEnrollment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)

	if err := mgr.Confirm(ctx, "nobody", "123456"); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("want ErrNotEnabled, got %v", err)
	}
	if _, _, err := store.GetTOTPSecret(ctx, "nobody"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Confirm wrote a row for a user with no enrollment: %v", err)
	}
}

// TestTOTP_ReEnrollmentCannotSilentlyReplaceAFactor is the account-takeover shape of enrollment:
// an attacker holding a live session must not be able to swap the victim's second factor for
// one they control by simply calling the enrollment endpoint again.
func TestTOTP_ReEnrollmentCannotSilentlyReplaceAFactor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)
	sec, _ := advEnroll(ctx, t, mgr, "victim")

	before, beforeCodes, err := store.GetTOTPSecret(ctx, "victim")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}

	if _, genErr := mgr.GenerateSecret(ctx, "victim", "victim@example.test"); !errors.Is(genErr, ErrAlreadyEnabled) {
		t.Fatalf("want ErrAlreadyEnabled, got %v", genErr)
	}

	after, afterCodes, err := store.GetTOTPSecret(ctx, "victim")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	if after != before {
		t.Fatal("a refused re-enrollment rewrote the stored secret")
	}
	if len(afterCodes) != len(beforeCodes) {
		t.Fatalf("a refused re-enrollment rewrote the backup codes: %d -> %d", len(beforeCodes), len(afterCodes))
	}
	if _, err := mgr.ValidateBackupCode(ctx, "victim", sec.BackupCodes[0]); err != nil {
		t.Fatalf("the original backup codes must survive: %v", err)
	}

	// A pending enrollment is equally protected, and Disable is the documented way out.
	mgr2, _ := advManager(t, nil)
	if _, err := mgr2.GenerateSecret(ctx, "u", "u@example.test"); err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if _, err := mgr2.GenerateSecret(ctx, "u", "u@example.test"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("re-enrolling over a pending factor: want ErrAlreadyEnabled, got %v", err)
	}
	if err := mgr2.Disable(ctx, "u"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := mgr2.GenerateSecret(ctx, "u", "u@example.test"); err != nil {
		t.Fatalf("re-enrollment after Disable must succeed: %v", err)
	}
}

// --- F-06: nothing directly replayable reaches the store -------------------------------

// TestTOTP_BackupCodesUnrecoverableFromStore covers F-06 (CWE-522, insufficiently protected
// credentials) for the backup codes. The adversary here is threat-model adversary 3: a leaked
// backup, a snapshot, or a SQL injection elsewhere in the host application.
func TestTOTP_BackupCodesUnrecoverableFromStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	storedSecret, storedCodes, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	if len(storedCodes) != len(sec.BackupCodes) {
		t.Fatalf("stored %d codes for %d issued", len(storedCodes), len(sec.BackupCodes))
	}

	// Everything the store holds, concatenated: the attacker reads the row, not one column.
	leak := storedSecret + "\x00" + strings.Join(storedCodes, "\x00")
	for _, code := range sec.BackupCodes {
		for _, form := range []string{
			code,
			strings.ToLower(code),
			normalizeBackupCode(code),
			strings.ToLower(normalizeBackupCode(code)),
		} {
			if strings.Contains(leak, form) {
				t.Fatalf("a backup code is recoverable from the store in the form %q (F-06)", form)
			}
		}
	}

	for i, stored := range storedCodes {
		if !strings.HasPrefix(stored, backupCodeHashPrefix) {
			t.Fatalf("stored code %d is not a digest: %q", i, stored)
		}
	}

	// The digests are distinct, so the store does not reveal that two codes are equal.
	seen := make(map[string]struct{}, len(storedCodes))
	for _, stored := range storedCodes {
		if _, dup := seen[stored]; dup {
			t.Fatal("two stored digests are identical")
		}
		seen[stored] = struct{}{}
	}

	// And a digest lifted from the store is not itself a credential: presenting it is not
	// presenting the code.
	advConfirm(ctx, t, mgr, "u", sec.Secret)
	if valid, err := mgr.ValidateBackupCode(ctx, "u", storedCodes[0]); valid || err != nil {
		t.Fatalf("a stored digest authenticated as a backup code: valid=%v err=%v", valid, err)
	}
}

// advConfirm arms an already-generated enrollment.
func advConfirm(ctx context.Context, t *testing.T, mgr *Manager, userID, secret string) {
	t.Helper()

	if err := mgr.Confirm(ctx, userID, advCodeAt(t, secret, -1)); err != nil {
		t.Fatalf("Confirm(%s): %v", userID, err)
	}
}

// TestTOTP_BackupCodeComparisonIsExhaustive covers the constant-time requirement of F-06 in
// the only way a functional test honestly can: by observing the behavior that separates a
// branch-free scan from a short-circuiting one. matchBackupCode never returns early, so when
// two stored entries both match, the LAST one wins; a `for ... if stored == code { return }`
// loop returns the first. The timing property itself is not measured here — CWE-208 timing
// assertions are unstable in CI — but this fails the moment the loop learns to exit early.
func TestTOTP_BackupCodeComparisonIsExhaustive(t *testing.T) {
	t.Parallel()

	const userID = "u"
	const code = "ABCD-EFGH"

	digest, err := hashBackupCode(userID, code)
	if err != nil {
		t.Fatalf("hashBackupCode: %v", err)
	}

	// A legacy plaintext row and its digest both match the same submission. An exhaustive
	// scan reports the last.
	match, ok, err := matchBackupCode(nil, userID, code, []string{normalizeBackupCode(code), digest})
	if err != nil || !ok {
		t.Fatalf("match: ok=%v err=%v", ok, err)
	}
	if match != digest {
		t.Fatalf("the scan stopped at the first match (%q); it must examine every entry (F-06)", match)
	}

	// A match in the last slot of a long list is found, which an early `break` on a
	// non-match would miss.
	long := make([]string, 0, 64)
	for i := 0; i < 63; i++ {
		other, hashErr := hashBackupCode(userID, fmt.Sprintf("FILL-%04d", i))
		if hashErr != nil {
			t.Fatalf("hashBackupCode: %v", hashErr)
		}
		long = append(long, other)
	}
	long = append(long, digest)
	match, ok, err = matchBackupCode(nil, userID, code, long)
	if err != nil || !ok || match != digest {
		t.Fatalf("match in the last slot: match=%q ok=%v err=%v", match, ok, err)
	}

	// An empty or whitespace submission must never match, including against a store that
	// holds an empty entry — otherwise "" is a universal backup code.
	for _, presented := range []string{"", " ", "\t", "-", "--", "   \n"} {
		if _, ok, err := matchBackupCode(nil, userID, presented, []string{"", digest}); ok || err != nil {
			t.Fatalf("empty submission %q matched: ok=%v err=%v", presented, ok, err)
		}
	}
}

// TestTOTP_BackupCodeIsSingleUse covers F-06's replay half: a backup code is a one-time
// credential, and one that survives its first use is a static password printed on paper.
func TestTOTP_BackupCodeIsSingleUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)
	sec, _ := advEnroll(ctx, t, mgr, "u")

	code := sec.BackupCodes[0]
	valid, err := mgr.ValidateBackupCode(ctx, "u", code)
	if err != nil || !valid {
		t.Fatalf("first use must authenticate: valid=%v err=%v", valid, err)
	}

	// Every presentation shape of the spent code, through both entry points.
	for _, form := range []string{code, strings.ToLower(code), normalizeBackupCode(code), " " + code + " "} {
		valid, err = mgr.ValidateBackupCode(ctx, "u", form)
		if valid || err != nil {
			t.Fatalf("a spent backup code (%q) authenticated again: valid=%v err=%v", form, valid, err)
		}
		valid, err = mgr.Validate(ctx, "u", form)
		if valid || err != nil {
			t.Fatalf("a spent backup code (%q) authenticated through Validate: valid=%v err=%v", form, valid, err)
		}
	}

	// It is gone from the store's unused set, not merely refused by the manager.
	_, remaining, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	if len(remaining) != len(sec.BackupCodes)-1 {
		t.Fatalf("want %d unused codes, got %d", len(sec.BackupCodes)-1, len(remaining))
	}

	// The other codes are untouched: consuming one must not invalidate the sheet.
	if valid, err := mgr.ValidateBackupCode(ctx, "u", sec.BackupCodes[1]); err != nil || !valid {
		t.Fatalf("an unused code must still authenticate: valid=%v err=%v", valid, err)
	}
}

// TestTOTP_BackupCodeDoesNotCrossUserBoundary covers the per-user derivation of F-06. Without
// it, one precomputed table covers every account, and an identical digest appearing under two
// users tells the attacker holding the store that the same code was issued twice.
func TestTOTP_BackupCodeDoesNotCrossUserBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)

	alice, _ := advEnroll(ctx, t, mgr, "alice")
	bob, _ := advEnroll(ctx, t, mgr, "bob")

	// The obvious attempt.
	for _, code := range alice.BackupCodes {
		if valid, err := mgr.ValidateBackupCode(ctx, "bob", code); valid || err != nil {
			t.Fatalf("alice's backup code authenticated bob: valid=%v err=%v", valid, err)
		}
	}
	if valid, err := mgr.Validate(ctx, "alice", bob.BackupCodes[0]); valid || err != nil {
		t.Fatalf("bob's backup code authenticated alice: valid=%v err=%v", valid, err)
	}

	// The interesting attempt: the attacker has read alice's row and plants her digests into
	// bob's, then presents alice's plaintext code as bob. A digest that is not bound to the
	// user it was issued for makes that work.
	_, aliceDigests, err := store.GetTOTPSecret(ctx, "alice")
	if err != nil {
		t.Fatalf("GetTOTPSecret(alice): %v", err)
	}
	bobStored, _, err := store.GetTOTPSecret(ctx, "bob")
	if err != nil {
		t.Fatalf("GetTOTPSecret(bob): %v", err)
	}
	if storeErr := store.StoreTOTPSecret(ctx, "bob", bobStored, aliceDigests); storeErr != nil {
		t.Fatalf("StoreTOTPSecret: %v", storeErr)
	}
	for _, code := range alice.BackupCodes {
		if valid, plantErr := mgr.ValidateBackupCode(ctx, "bob", code); valid || plantErr != nil {
			t.Fatalf("a digest replanted under another account authenticated: valid=%v err=%v", valid, plantErr)
		}
	}

	// The same code under two users must not produce the same stored value.
	const shared = "ZZZZ-ZZZZ"
	da, err := hashBackupCode("alice", shared)
	if err != nil {
		t.Fatalf("hashBackupCode: %v", err)
	}
	db, err := hashBackupCode("bob", shared)
	if err != nil {
		t.Fatalf("hashBackupCode: %v", err)
	}
	if da == db {
		t.Fatal("the stored digest is not bound to the user; one table covers every account (F-06)")
	}
}

// TestTOTP_RegenerateBackupCodesInvalidatesPreviousSet is the "I think my codes leaked" path.
// If regeneration leaves the old sheet live, the control does nothing.
func TestTOTP_RegenerateBackupCodesInvalidatesPreviousSet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, nil)
	sec, _ := advEnroll(ctx, t, mgr, "u")

	_, oldDigests, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}

	fresh, err := mgr.RegenerateBackupCodes(ctx, "u")
	if err != nil {
		t.Fatalf("RegenerateBackupCodes: %v", err)
	}
	if len(fresh) != len(sec.BackupCodes) {
		t.Fatalf("want %d codes, got %d", len(sec.BackupCodes), len(fresh))
	}

	for i, old := range sec.BackupCodes {
		if valid, oldErr := mgr.ValidateBackupCode(ctx, "u", old); valid || oldErr != nil {
			t.Fatalf("superseded code %d still authenticates: valid=%v err=%v", i, valid, oldErr)
		}
		if valid, oldErr := mgr.Validate(ctx, "u", old); valid || oldErr != nil {
			t.Fatalf("superseded code %d still authenticates through Validate: valid=%v err=%v", i, valid, oldErr)
		}
		for _, newCode := range fresh {
			if newCode == old {
				t.Fatalf("regeneration reissued the same code %q", old)
			}
		}
	}

	_, newDigests, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	for _, old := range oldDigests {
		for _, current := range newDigests {
			if old == current {
				t.Fatal("a superseded digest survived regeneration in the store")
			}
		}
	}

	// The new sheet works, and the shared secret is untouched by the rotation.
	if valid, err := mgr.ValidateBackupCode(ctx, "u", fresh[0]); err != nil || !valid {
		t.Fatalf("a fresh code must authenticate: valid=%v err=%v", valid, err)
	}
	if valid, err := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, 1)); err != nil || !valid {
		t.Fatalf("rotating backup codes must not disturb the shared secret: valid=%v err=%v", valid, err)
	}
}

// --- F-06: the shared secret at rest ---------------------------------------------------

// TestTOTP_SecretNotPlaintextAtRestWithCipher covers F-06 for the shared secret. A store
// compromise that yields the seed yields a working second factor for every enrolled user,
// which is exactly the property the second factor exists to deny.
func TestTOTP_SecretNotPlaintextAtRestWithCipher(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	aead := newAdvAESCipher(t)
	mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	assertSealed := func(stage string) string {
		t.Helper()

		stored, storedCodes, getErr := store.GetTOTPSecret(ctx, "u")
		if getErr != nil {
			t.Fatalf("%s: GetTOTPSecret: %v", stage, getErr)
		}
		if stored == sec.Secret {
			t.Fatalf("%s: the plaintext secret reached the store (F-06)", stage)
		}
		leak := stored + "\x00" + strings.Join(storedCodes, "\x00")
		for _, form := range []string{sec.Secret, strings.ToLower(sec.Secret), strings.TrimRight(sec.Secret, "=")} {
			if strings.Contains(leak, form) {
				t.Fatalf("%s: the secret is recoverable from the store (F-06)", stage)
			}
		}
		if !strings.HasPrefix(stored, secretPrefix) {
			t.Fatalf("%s: encrypted payload is untagged: %q", stage, stored)
		}
		return stored
	}

	pendingPayload := assertSealed("pending")
	if !strings.HasPrefix(pendingPayload, secretPrefix+secretStatePending+"$"+secretEncodingEnc+"$") {
		t.Fatalf("pending encrypted payload has the wrong header: %q", pendingPayload)
	}

	advConfirm(ctx, t, mgr, "u", sec.Secret)
	armedPayload := assertSealed("armed")
	if !strings.HasPrefix(armedPayload, secretPrefix+secretStateActive+"$"+secretEncodingEnc+"$") {
		t.Fatalf("armed encrypted payload has the wrong header: %q", armedPayload)
	}

	// The round trip recovers the same seed: encryption at rest must not cost the user their
	// factor.
	valid, err := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, 0))
	if err != nil || !valid {
		t.Fatalf("round trip through the cipher failed: valid=%v err=%v", valid, err)
	}
	if valid, backupErr := mgr.ValidateBackupCode(ctx, "u", sec.BackupCodes[0]); backupErr != nil || !valid {
		t.Fatalf("backup codes must survive encryption: valid=%v err=%v", valid, backupErr)
	}

	// Two enrollments of the same seed must not produce the same ciphertext, or the store
	// reveals which users share a secret and the cipher is being used deterministically.
	body := strings.TrimPrefix(armedPayload, secretPrefix+secretStateActive+"$"+secretEncodingEnc+"$")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("stored payload is not base64: %v", err)
	}
	again, err := aead.Encrypt([]byte(sec.Secret))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(raw, again) {
		t.Fatal("the ciphertext is deterministic")
	}
}

// TestTOTP_CipherFailureIsAnErrorNotASilentRejection covers the failure mode that turns
// encryption-at-rest into a self-inflicted outage that reads like an attack: a secret that
// cannot be decrypted must surface as an error, never as "that code is wrong" or "you have no
// second factor".
func TestTOTP_CipherFailureIsAnErrorNotASilentRejection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Enroll under a working cipher, then read the row back for reuse below.
	aead := newAdvAESCipher(t)
	seed, seedStore := advManager(t, func(c *Config) { c.Cipher = aead })
	sec, err := seed.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	advConfirm(ctx, t, seed, "u", sec.Secret)
	sealed, digests, err := seedStore.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}

	tests := []struct {
		name    string
		cipher  Cipher
		payload string
		wantIs  error

		// unparseable marks a payload whose STRUCTURE is broken, as opposed to one that is
		// merely undecryptable. Only the former may not be read at all, so only the former
		// must also refuse the backup-code path: a key outage deliberately leaves backup
		// codes usable, which is the recovery path that outage needs.
		unparseable bool
	}{
		{
			name:    "decrypt always fails",
			cipher:  advBrokenCipher{inner: aead},
			payload: sealed,
		},
		{
			name:    "cipher removed after enrollment",
			cipher:  nil,
			payload: sealed,
			wantIs:  ErrCipherRequired,
		},
		{
			name:    "ciphertext tampered in the store",
			cipher:  aead,
			payload: advFlipStoredCiphertext(t, sealed),
		},
		{
			name:    "payload data is not base64",
			cipher:  aead,
			payload: secretPrefix + secretStateActive + "$" + secretEncodingEnc + "$!!!not-base64!!!",
			wantIs:  ErrCorruptSecret,
		},
		{
			name:        "unknown state marker",
			cipher:      aead,
			payload:     secretPrefix + "x$" + secretEncodingRaw + "$JBSWY3DPEHPK3PXP",
			wantIs:      ErrCorruptSecret,
			unparseable: true,
		},
		{
			name:        "unknown encoding marker",
			cipher:      aead,
			payload:     secretPrefix + secretStateActive + "$z$JBSWY3DPEHPK3PXP",
			wantIs:      ErrCorruptSecret,
			unparseable: true,
		},
		{
			name:        "truncated payload",
			cipher:      aead,
			payload:     secretPrefix + secretStateActive + "$",
			wantIs:      ErrCorruptSecret,
			unparseable: true,
		},
		{
			name:        "empty data field",
			cipher:      aead,
			payload:     secretPrefix + secretStateActive + "$" + secretEncodingRaw + "$",
			wantIs:      ErrCorruptSecret,
			unparseable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mgr, store := advManager(t, func(c *Config) { c.Cipher = tc.cipher })
			if err := store.StoreTOTPSecret(ctx, "u", tc.payload, digests); err != nil {
				t.Fatalf("StoreTOTPSecret: %v", err)
			}

			valid, err := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, 0))
			if valid {
				t.Fatal("an unreadable secret authenticated a code")
			}
			if err == nil {
				t.Fatal("an unreadable secret was reported as a plain invalid code, hiding the outage (F-06)")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("want %v, got %v", tc.wantIs, err)
			}

			// A structurally broken payload is never treated as a usable enrollment, not
			// even on the path that does not need the secret.
			if tc.unparseable {
				valid, err := mgr.ValidateBackupCode(ctx, "u", sec.BackupCodes[0])
				if valid {
					t.Fatal("a malformed payload authenticated a backup code")
				}
				if !errors.Is(err, ErrCorruptSecret) {
					t.Fatalf("ValidateBackupCode on a malformed payload: want ErrCorruptSecret, got %v", err)
				}
			}
			if err := mgr.Confirm(ctx, "u", advCodeAt(t, sec.Secret, 0)); err == nil {
				t.Fatal("Confirm accepted an unreadable secret")
			}
		})
	}
}

// advFlipStoredCiphertext flips one bit of the ciphertext inside a stored payload, which an
// authenticated cipher must refuse to open.
func advFlipStoredCiphertext(t *testing.T, payload string) string {
	t.Helper()

	prefix := secretPrefix + secretStateActive + "$" + secretEncodingEnc + "$"
	body := strings.TrimPrefix(payload, prefix)
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode stored ciphertext: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	return prefix + base64.StdEncoding.EncodeToString(raw)
}

// TestTOTP_EnrollmentIsNotPersistedWhenTheCipherFails guards the ordering: a row written before
// the secret was successfully sealed is a plaintext row, and the user would additionally hold
// backup codes for an enrollment the caller believes never happened.
func TestTOTP_EnrollmentIsNotPersistedWhenTheCipherFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, store := advManager(t, func(c *Config) { c.Cipher = advEncryptFailsCipher{} })

	if _, err := mgr.GenerateSecret(ctx, "u", "u@example.test"); err == nil {
		t.Fatal("GenerateSecret succeeded with a cipher that cannot encrypt")
	}
	if _, _, err := store.GetTOTPSecret(ctx, "u"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a failed enrollment left a row behind: %v", err)
	}
}

// TestTOTP_EnrollmentStateReadableWithoutTheKey pins a deliberate property of the payload
// format: whether a factor is armed is decided without touching the cipher, so a key outage
// cannot make every user's second factor silently vanish from the gate that reads IsEnabled.
func TestTOTP_EnrollmentStateReadableWithoutTheKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	aead := newAdvAESCipher(t)
	mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	advConfirm(ctx, t, mgr, "u", sec.Secret)
	sealed, digests, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}

	broken, brokenStore := advManager(t, func(c *Config) { c.Cipher = advBrokenCipher{inner: aead} })
	if storeErr := brokenStore.StoreTOTPSecret(ctx, "u", sealed, digests); storeErr != nil {
		t.Fatalf("StoreTOTPSecret: %v", storeErr)
	}

	enabled, err := broken.IsEnabled(ctx, "u")
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !enabled {
		t.Fatal("a key outage made an armed factor read as disabled; the second factor is silently bypassed")
	}
}

// --- secret entropy --------------------------------------------------------------------

// TestTOTP_SecretEntropy checks the seed against RFC 4226 section 4 R6, which requires a
// shared secret of at least 128 bits and recommends 160. This library mints 256, and a
// regression to a shorter or non-random seed is the kind of change no functional test notices.
func TestTOTP_SecretEntropy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)

	const enrollments = 12
	const wantBytes = 32 // documented as SecretSize: 32, i.e. 256 bits

	seen := make(map[string]struct{}, enrollments)
	backupSeen := make(map[string]struct{}, enrollments*DefaultBackupCodeCount)
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)

	for i := 0; i < enrollments; i++ {
		userID := fmt.Sprintf("u%02d", i)
		sec, err := mgr.GenerateSecret(ctx, userID, userID+"@example.test")
		if err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}

		raw, err := decoder.DecodeString(sec.Secret)
		if err != nil {
			t.Fatalf("secret is not unpadded RFC 4648 base32: %v", err)
		}
		if len(raw) != wantBytes {
			t.Fatalf("secret is %d bytes, want %d (RFC 4226 section 4 R6 requires at least 16)", len(raw), wantBytes)
		}
		if strings.Trim(sec.Secret, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			t.Fatalf("secret leaves the base32 alphabet: %q", sec.Secret)
		}

		allSame := true
		for _, b := range raw {
			if b != raw[0] {
				allSame = false
				break
			}
		}
		if allSame {
			t.Fatalf("secret is a constant byte pattern: %q", sec.Secret)
		}

		if _, dup := seen[sec.Secret]; dup {
			t.Fatal("two enrollments produced the same secret")
		}
		seen[sec.Secret] = struct{}{}

		if len(sec.BackupCodes) != DefaultBackupCodeCount {
			t.Fatalf("got %d backup codes, want %d", len(sec.BackupCodes), DefaultBackupCodeCount)
		}
		for _, code := range sec.BackupCodes {
			if problem := backupCodeShapeError(code); problem != "" {
				t.Fatalf("backup code %q has the wrong shape: %s", code, problem)
			}
			// RFC 4226 says nothing about backup codes, so the bar is set by what the
			// stored digest costs to invert: one unkeyed SHA-256 pass. 40 bits was
			// enumerable on one GPU in minutes, which is what made F-06's "hashed at
			// rest" claim hollow for the codes.
			if bits := len(normalizeBackupCode(code)) * 5; bits < 80 {
				t.Fatalf("backup code %q carries %d bits, want at least 80", code, bits)
			}
			if _, dup := backupSeen[code]; dup {
				t.Fatalf("backup code %q was issued twice", code)
			}
			backupSeen[code] = struct{}{}
		}
	}

	if len(seen) != enrollments {
		t.Fatalf("only %d distinct secrets across %d enrollments", len(seen), enrollments)
	}
}

// --- malformed input -------------------------------------------------------------------

// TestTOTP_MalformedCodesRejectedWithoutPanic is the fuzz-shaped floor: an unauthenticated
// attacker controls this string entirely, and a panic in a second-factor check is a denial of
// service on the sign-in path. Nothing here may authenticate, and nothing here may crash.
func TestTOTP_MalformedCodesRejectedWithoutPanic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)
	sec, _ := advEnroll(ctx, t, mgr, "u")

	for _, tc := range advHostileCodes() {
		t.Run(tc.name, func(t *testing.T) {
			if otptotp.Validate(tc.code, sec.Secret) {
				t.Skipf("%s is a live code by coincidence", tc.name)
			}

			valid, err := mgr.Validate(ctx, "u", tc.code)
			if valid {
				t.Fatalf("Validate authenticated %q", tc.name)
			}
			if err != nil {
				t.Fatalf("Validate(%s) must be a plain rejection, got %v", tc.name, err)
			}

			valid, err = mgr.ValidateBackupCode(ctx, "u", tc.code)
			if valid {
				t.Fatalf("ValidateBackupCode authenticated %q", tc.name)
			}
			if err != nil {
				t.Fatalf("ValidateBackupCode(%s) must be a plain rejection, got %v", tc.name, err)
			}
		})
	}

	// The factor is intact after the barrage.
	if valid, err := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, 0)); err != nil || !valid {
		t.Fatalf("a legitimate code must still authenticate: valid=%v err=%v", valid, err)
	}
}

// TestTOTP_OperationsOnAbsentEnrollmentAreRefused makes sure the unenrolled path is a refusal
// rather than an accidental success, in every direction an attacker can poke it.
func TestTOTP_OperationsOnAbsentEnrollmentAreRefused(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)

	if valid, err := mgr.Validate(ctx, "ghost", "123456"); valid || !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("Validate: valid=%v err=%v", valid, err)
	}
	if valid, err := mgr.ValidateBackupCode(ctx, "ghost", "ABCD-EFGH"); valid || !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("ValidateBackupCode: valid=%v err=%v", valid, err)
	}
	if _, err := mgr.RegenerateBackupCodes(ctx, "ghost"); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("RegenerateBackupCodes: %v", err)
	}
	if err := mgr.Disable(ctx, "ghost"); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("Disable: %v", err)
	}
	if enabled, err := mgr.IsEnabled(ctx, "ghost"); enabled || err != nil {
		t.Fatalf("IsEnabled: enabled=%v err=%v", enabled, err)
	}
	if pending, err := mgr.IsPending(ctx, "ghost"); pending || err != nil {
		t.Fatalf("IsPending: pending=%v err=%v", pending, err)
	}

	// An empty user ID is not a wildcard.
	if valid, err := mgr.Validate(ctx, "", "123456"); valid || !errors.Is(err, ErrNotEnabled) {
		t.Fatalf(`Validate(""): valid=%v err=%v`, valid, err)
	}
}

// --- F-08: the guard must key on what the validator compared ----------------------------

// advSpaceRunes are the code points strings.TrimSpace removes: the whole of unicode.IsSpace,
// which is the rule pquerna's hotp.ValidateCustom applies to a submitted passcode before
// comparing it, and therefore the exact set the replay guard has to fold. They are written as
// escapes rather than literals so that reading this file shows what is being tested.
//
// U+200B ZERO WIDTH SPACE is deliberately absent: it is not White_Space, so TrimSpace leaves
// it, and a guard that folded it would be normalizing MORE than the validator does -- which
// merges two codes the validator considers different.
var advSpaceRunes = []struct{ name, r string }{
	{"space", " "},
	{"tab", "\t"},
	{"newline", "\n"},
	{"carriage return", "\r"},
	{"vertical tab", "\v"},
	{"form feed", "\f"},
	{"next line", "\u0085"},
	{"no-break space", "\u00a0"},
	{"ogham space mark", "\u1680"},
	{"en quad", "\u2000"},
	{"em space", "\u2003"},
	{"line separator", "\u2028"},
	{"paragraph separator", "\u2029"},
	{"narrow no-break space", "\u202f"},
	{"medium mathematical space", "\u205f"},
	{"ideographic space", "\u3000"},
}

// advWhitespaceVariants dresses one code in every presentation the validator treats as that
// same code: each space rune as a prefix, as a suffix, on both ends, repeated, and all of them
// at once.
func advWhitespaceVariants(code string) []struct{ name, code string } {
	variants := make([]struct{ name, code string }, 0, len(advSpaceRunes)*4+2)
	for _, space := range advSpaceRunes {
		variants = append(variants,
			struct{ name, code string }{space.name + " prefix", space.r + code},
			struct{ name, code string }{space.name + " suffix", code + space.r},
			struct{ name, code string }{space.name + " both ends", space.r + code + space.r},
			struct{ name, code string }{space.name + " repeated", strings.Repeat(space.r, 4) + code},
		)
	}

	var every strings.Builder
	for _, space := range advSpaceRunes {
		every.WriteString(space.r)
	}
	variants = append(variants,
		struct{ name, code string }{"every space rune as a prefix", every.String() + code},
		struct{ name, code string }{"every space rune on both ends", every.String() + code + every.String()},
	)
	return variants
}

// TestTOTP_ReplayGuardIgnoresPresentationWhitespace covers the replay that walks through the
// F-08 guard by adding a space.
//
// hotp.ValidateCustom trims the submitted passcode before comparing it, so "170225" and
// " 170225" are one code to the validator and two keys to a guard keyed on the raw submission.
// The bypass alphabet is every Unicode space in any combination at either end, repeated, which
// is an unbounded key set for a code that has already been spent: the guard answered "never
// seen" and the code authenticated a second time.
func TestTOTP_ReplayGuardIgnoresPresentationWhitespace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)
	sec, confirmCode := advEnroll(ctx, t, mgr, "victim")

	code := advCodeAt(t, sec.Secret, 0)
	if code == confirmCode {
		t.Skip("current step's code collided with the confirmation code (1 in 10^6)")
	}
	if valid, err := mgr.Validate(ctx, "victim", code); err != nil || !valid {
		t.Fatalf("first presentation must authenticate: valid=%v err=%v", valid, err)
	}

	for _, variant := range advWhitespaceVariants(code) {
		t.Run(variant.name, func(t *testing.T) {
			valid, err := mgr.Validate(ctx, "victim", variant.code)
			if valid {
				t.Fatalf("a spent code re-presented as %q authenticated again (F-08)", variant.code)
			}
			if !errors.Is(err, ErrCodeReused) {
				t.Fatalf("want ErrCodeReused for %q, got %v", variant.code, err)
			}
		})
	}
}

// TestTOTP_ConfirmationCodeCannotBeReplayedWithWhitespace aims the same bypass at the other
// side of the enrollment. Confirm spends a live code; if the guard files it under the raw
// submission, whoever observed the enrollment form replays it as a sign-in by prepending a
// space. Padding is not exotic here -- it is what a copy-paste out of an authenticator app
// carries.
func TestTOTP_ConfirmationCodeCannotBeReplayedWithWhitespace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	code := advCodeAt(t, sec.Secret, 0)
	if err := mgr.Confirm(ctx, "u", " "+code+"\n"); err != nil {
		t.Fatalf("Confirm with a padded code: %v", err)
	}

	for _, presented := range []string{code, " " + code, code + "\t", "\u00a0" + code + "\u3000"} {
		valid, err := mgr.Validate(ctx, "u", presented)
		if valid {
			t.Fatalf("the confirmation code authenticated a sign-in as %q (F-07 x F-08)", presented)
		}
		if !errors.Is(err, ErrCodeReused) {
			t.Fatalf("want ErrCodeReused for %q, got %v", presented, err)
		}
	}
}

// TestTOTP_ReplayGuardCannotBeFloodedByOneAccount covers the consequence of the key bug. The
// entry budget is global and the guard fails closed, so an attacker able to mint unlimited
// keys for ONE spent code evicts nobody and takes the whole budget down with them: one account
// replaying one code with varying whitespace exhausted the 65536-entry budget in 24 seconds,
// after which a different user's fresh valid code was refused as "replay guard is full".
//
// The fix is upstream of the budget -- one accepted code is one key however it is dressed --
// so what is pinned here is that the flood occupies exactly one entry.
func TestTOTP_ReplayGuardCannotBeFloodedByOneAccount(t *testing.T) {
	t.Parallel()

	t.Run("the guard itself", func(t *testing.T) {
		ctx := context.Background()
		guard := NewMemoryReplayGuard()
		// A budget this small makes the amplification fatal inside the test: on the old key
		// construction the second presentation already took the second slot.
		guard.maxEntries = 4

		if seen, err := guard.Seen(ctx, "victim", "170225"); err != nil || seen {
			t.Fatalf("first record: seen=%v err=%v", seen, err)
		}
		// A guard is handed the folded code, never the raw submission: see ReplayGuard.Seen.
		// That is what collapses the attacker's unbounded key set into the one entry already
		// held, so the budget never moves.
		for _, variant := range advWhitespaceVariants("170225") {
			seen, err := guard.Seen(ctx, "victim", normalizeSubmittedCode(variant.code))
			if err != nil {
				t.Fatalf("presenting %q consumed budget: %v", variant.code, err)
			}
			if !seen {
				t.Fatalf("presenting %q was not recognized as the code already recorded", variant.code)
			}
		}

		guard.mu.Lock()
		held := len(guard.entries)
		guard.mu.Unlock()
		if held != 1 {
			t.Fatalf("one spent code occupies %d entries; the budget is an amplifier (F-08)", held)
		}

		// The budget is still there for everybody else, which is the whole point.
		if seen, err := guard.Seen(ctx, "bystander", "424242"); err != nil || seen {
			t.Fatalf("a bystander's fresh code was denied by the flood: seen=%v err=%v", seen, err)
		}
	})

	t.Run("through the manager", func(t *testing.T) {
		ctx := context.Background()
		guard := NewMemoryReplayGuard()
		mgr, _ := advManager(t, func(c *Config) { c.ReplayGuard = guard })

		attacker, attackerConfirm := advEnroll(ctx, t, mgr, "attacker")
		bystander, bystanderConfirm := advEnroll(ctx, t, mgr, "bystander")

		code := advCodeAt(t, attacker.Secret, 0)
		if code == attackerConfirm {
			t.Skip("code collision (1 in 10^6)")
		}
		if valid, err := mgr.Validate(ctx, "attacker", code); err != nil || !valid {
			t.Fatalf("first presentation must authenticate: valid=%v err=%v", valid, err)
		}

		// Two enrollments and one sign-in have spent three codes. Leave room for exactly one
		// more -- the bystander's -- so that a flood which grows the guard at all takes the
		// slot the bystander needs, which is the denial of service that was reproduced.
		guard.mu.Lock()
		guard.maxEntries = len(guard.entries) + 1
		guard.mu.Unlock()

		for _, variant := range advWhitespaceVariants(code) {
			if _, err := mgr.Validate(ctx, "attacker", variant.code); errors.Is(err, ErrReplayGuardFull) {
				t.Fatalf("replaying %q grew the guard; one account can starve every other (F-08)", variant.code)
			}
		}

		fresh := advCodeAt(t, bystander.Secret, 1)
		if fresh == bystanderConfirm {
			t.Skip("code collision (1 in 10^6)")
		}
		valid, err := mgr.Validate(ctx, "bystander", fresh)
		if errors.Is(err, ErrReplayGuardFull) {
			t.Fatal("a bystander's valid code was refused because another account flooded the guard")
		}
		if err != nil || !valid {
			t.Fatalf("a bystander's valid code must authenticate: valid=%v err=%v", valid, err)
		}
	})
}

// --- F-06: the payload tag is part of what the cipher protects --------------------------

// advPlantSecret replaces the stored secret for userID, keeping the backup codes, the way an
// attacker with write access to the credential store would.
func advPlantSecret(ctx context.Context, t *testing.T, store *storage.InMemoryCredentialStore, userID, payload string) {
	t.Helper()

	_, digests, err := store.GetTOTPSecret(ctx, userID)
	if err != nil {
		t.Fatalf("GetTOTPSecret(%s): %v", userID, err)
	}
	if err := store.StoreTOTPSecret(ctx, userID, payload, digests); err != nil {
		t.Fatalf("StoreTOTPSecret(%s): %v", userID, err)
	}
}

// advAttackerSecret is a valid base32 seed the attacker knows and the server never issued.
func advAttackerSecret(t *testing.T) string {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

// TestTOTP_StoredPayloadTagCannotBeDowngraded covers the hole the payload tag opened. The
// state and encoding markers sit OUTSIDE the ciphertext, because IsEnabled has to answer
// without key material -- which left them writable by exactly the adversary a Cipher is
// configured against. Honoring what they said turned a store write into a second-factor
// takeover:
//
//	$gat1$a$e$<ciphertext>  ->  $gat1$a$r$<attacker secret>   accepted, attacker's codes work
//	$gat1$p$r$<secret>      ->  <secret>                      pending flipped to active
//
// Both are now refused, because the markers are also sealed inside the authenticated
// plaintext and compared after decrypt.
func TestTOTP_StoredPayloadTagCannotBeDowngraded(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("encrypted downgraded to raw", func(t *testing.T) {
		aead := newAdvAESCipher(t)
		mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })
		sec, _ := advEnroll(ctx, t, mgr, "u")

		planted := advAttackerSecret(t)
		advPlantSecret(ctx, t, store, "u", secretPrefix+secretStateActive+"$"+secretEncodingRaw+"$"+planted)

		valid, err := mgr.Validate(ctx, "u", advCodeAt(t, planted, 0))
		if valid {
			t.Fatal("a secret the attacker wrote in the clear authenticated their own code (F-06)")
		}
		if !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("want ErrSecretNotEncrypted, got %v", err)
		}

		// The refusal covers the gate as well, not just the code path: a caller that asks
		// "does this user have a second factor?" must not be told yes about a downgraded row.
		if _, err := mgr.IsEnabled(ctx, "u"); !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("IsEnabled: want ErrSecretNotEncrypted, got %v", err)
		}
		if _, err := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, 0)); !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("the real secret must not be reachable through a downgraded row either: %v", err)
		}
	})

	t.Run("encrypted stripped to the bare legacy form", func(t *testing.T) {
		aead := newAdvAESCipher(t)
		mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })
		advEnroll(ctx, t, mgr, "u")

		planted := advAttackerSecret(t)
		advPlantSecret(ctx, t, store, "u", planted)

		valid, err := mgr.Validate(ctx, "u", advCodeAt(t, planted, 0))
		if valid {
			t.Fatal("stripping the payload tag downgraded an encrypted secret to plaintext (F-06)")
		}
		if !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("want ErrSecretNotEncrypted, got %v", err)
		}
	})

	t.Run("pending flipped to active", func(t *testing.T) {
		aead := newAdvAESCipher(t)
		mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })

		sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
		if err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}
		pending, _, err := store.GetTOTPSecret(ctx, "u")
		if err != nil {
			t.Fatalf("GetTOTPSecret: %v", err)
		}

		// The attacker rewrites only the state marker, leaving the ciphertext alone. Before
		// the marker was sealed, this armed a factor whose owner never proved possession.
		flipped := secretPrefix + secretStateActive + "$" + secretEncodingEnc + "$" +
			strings.TrimPrefix(pending, secretPrefix+secretStatePending+"$"+secretEncodingEnc+"$")
		advPlantSecret(ctx, t, store, "u", flipped)

		valid, err := mgr.Validate(ctx, "u", advCodeAt(t, sec.Secret, 0))
		if valid {
			t.Fatal("an unconfirmed enrollment was armed by rewriting its state marker (F-06 x F-07)")
		}
		if !errors.Is(err, ErrSecretTampered) {
			t.Fatalf("want ErrSecretTampered, got %v", err)
		}
	})

	t.Run("attacker's own sealed row planted on the victim", func(t *testing.T) {
		aead := newAdvAESCipher(t)
		mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })
		victim, _ := advEnroll(ctx, t, mgr, "victim")
		attacker, _ := advEnroll(ctx, t, mgr, "attacker")

		// The cheapest bypass available to a store writer, and the one that survives every
		// check on the markers alone: the attacker enrolls a factor of their own, entirely
		// legitimately, and copies that sealed row over the victim's. Nothing is downgraded,
		// the ciphertext is genuine and authenticates, every marker agrees -- and the
		// attacker's authenticator now passes the victim's second factor. The account binding
		// sealed alongside the markers is what refuses it.
		evil, _, err := store.GetTOTPSecret(ctx, "attacker")
		if err != nil {
			t.Fatalf("GetTOTPSecret: %v", err)
		}
		advPlantSecret(ctx, t, store, "victim", evil)

		valid, err := mgr.Validate(ctx, "victim", advCodeAt(t, attacker.Secret, 0))
		if valid {
			t.Fatal("the attacker's own factor authenticated as the victim (F-06)")
		}
		if !errors.Is(err, ErrSecretTampered) {
			t.Fatalf("want ErrSecretTampered, got %v", err)
		}

		// The same copy in the other direction is refused for the same reason. It gains the
		// attacker nothing either way -- they would still need the victim's authenticator --
		// but a payload that opens under the wrong account is a payload that was moved.
		sealed, _, err := store.GetTOTPSecret(ctx, "attacker")
		if err != nil {
			t.Fatalf("GetTOTPSecret: %v", err)
		}
		advPlantSecret(ctx, t, store, "attacker", sealed)
		if _, err := mgr.Validate(ctx, "attacker", advCodeAt(t, victim.Secret, 0)); errors.Is(err, ErrSecretTampered) {
			t.Fatal("an account's own sealed row must still open for that account")
		}
	})

	t.Run("tagged plaintext is refused even during migration", func(t *testing.T) {
		aead := newAdvAESCipher(t)
		mgr, store := advManager(t, func(c *Config) {
			c.Cipher = aead
			c.AllowLegacyPlaintextSecrets = true
		})
		advEnroll(ctx, t, mgr, "u")

		planted := advAttackerSecret(t)
		advPlantSecret(ctx, t, store, "u", secretPrefix+secretStateActive+"$"+secretEncodingRaw+"$"+planted)

		valid, err := mgr.Validate(ctx, "u", advCodeAt(t, planted, 0))
		if valid {
			t.Fatal("the migration shim accepted a tagged plaintext row; that shape is never written")
		}
		if !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("want ErrSecretNotEncrypted, got %v", err)
		}
	})
}

// TestTOTP_LegacyPlaintextMigrationIsOptIn pins the escape hatch to being an escape hatch. A
// deployment adopting a Cipher has rows that predate it, and refusing them all at once locks
// out every enrolled user -- but silently reading them is what let an attacker downgrade a
// sealed row. So the untagged legacy shape is refused by default and readable only when the
// caller has said so, and it migrates to ciphertext the first time the row is rewritten.
func TestTOTP_LegacyPlaintextMigrationIsOptIn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	aead := newAdvAESCipher(t)

	seed := func(t *testing.T, allow bool) (*Manager, *storage.InMemoryCredentialStore, string) {
		t.Helper()

		mgr, store := advManager(t, func(c *Config) {
			c.Cipher = aead
			c.AllowLegacyPlaintextSecrets = allow
		})
		key, err := otptotp.Generate(otptotp.GenerateOpts{Issuer: "AdversaryApp", AccountName: "u@example.test"})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if err := store.StoreTOTPSecret(ctx, "u", key.Secret(), []string{"ABCD-EFGH"}); err != nil {
			t.Fatalf("StoreTOTPSecret: %v", err)
		}
		return mgr, store, key.Secret()
	}

	t.Run("refused by default", func(t *testing.T) {
		mgr, _, secret := seed(t, false)

		valid, err := mgr.Validate(ctx, "u", advCodeAt(t, secret, 0))
		if valid {
			t.Fatal("a plaintext secret was read while a Cipher was configured (F-06)")
		}
		if !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("want ErrSecretNotEncrypted, got %v", err)
		}
		if _, err := mgr.IsEnabled(ctx, "u"); !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("IsEnabled: want ErrSecretNotEncrypted, got %v", err)
		}
		if valid, err := mgr.ValidateBackupCode(ctx, "u", "ABCD-EFGH"); valid || !errors.Is(err, ErrSecretNotEncrypted) {
			t.Fatalf("ValidateBackupCode: valid=%v err=%v", valid, err)
		}
	})

	t.Run("readable and migrated when opted in", func(t *testing.T) {
		mgr, store, secret := seed(t, true)

		if valid, err := mgr.Validate(ctx, "u", advCodeAt(t, secret, 0)); err != nil || !valid {
			t.Fatalf("a legacy row must keep working during migration: valid=%v err=%v", valid, err)
		}

		if _, err := mgr.RegenerateBackupCodes(ctx, "u"); err != nil {
			t.Fatalf("RegenerateBackupCodes: %v", err)
		}
		migrated, _, err := store.GetTOTPSecret(ctx, "u")
		if err != nil {
			t.Fatalf("GetTOTPSecret: %v", err)
		}
		if !strings.HasPrefix(migrated, secretPrefix+secretStateActive+"$"+secretEncodingEnc+"$") {
			t.Fatalf("rewriting the row did not migrate it to ciphertext: %q", migrated)
		}

		// And once migrated it no longer needs the shim, which is what makes the flag
		// clearable rather than permanent.
		strict, strictStore := advManager(t, func(c *Config) { c.Cipher = aead })
		if err := strictStore.StoreTOTPSecret(ctx, "u", migrated, nil); err != nil {
			t.Fatalf("StoreTOTPSecret: %v", err)
		}
		if valid, err := strict.Validate(ctx, "u", advCodeAt(t, secret, 1)); err != nil || !valid {
			t.Fatalf("a migrated row must validate without the shim: valid=%v err=%v", valid, err)
		}
	})
}

// TestTOTP_BackupCodesSealedWhenCipherConfigured covers the half of F-06 the digest cannot
// reach on its own. hashBackupCode's key is derived from the user ID, which is public, so an
// attacker holding the store can compute the digest of any candidate code themselves -- the
// digest is a speed bump proportional to the code's width, not a secret. A deployment that
// configures a Cipher and reads "F-06 fixed" was still handing a store reader ten working
// second factors, because the Cipher was never applied to them.
func TestTOTP_BackupCodesSealedWhenCipherConfigured(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	aead := newAdvAESCipher(t)
	mgr, store := advManager(t, func(c *Config) { c.Cipher = aead })

	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	advConfirm(ctx, t, mgr, "u", sec.Secret)

	_, stored, err := store.GetTOTPSecret(ctx, "u")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	leak := strings.Join(stored, "\x00")

	for i, entry := range stored {
		if !strings.HasPrefix(entry, backupCodeSealPrefix) {
			t.Fatalf("stored code %d is not sealed: %q", i, entry)
		}
	}
	for _, code := range sec.BackupCodes {
		// This is the attacker's own computation: the salt is derived from a public user ID,
		// so holding the store is enough to build the digest of a candidate code. Sealing is
		// what makes that computation useless.
		digest, hashErr := hashBackupCode("u", code)
		if hashErr != nil {
			t.Fatalf("hashBackupCode: %v", hashErr)
		}
		if strings.Contains(leak, digest) {
			t.Fatal("a digest an attacker can recompute from the public user ID is in the store (F-06)")
		}
		if strings.Contains(leak, normalizeBackupCode(code)) {
			t.Fatal("a backup code is recoverable from the store (F-06)")
		}
	}

	// Sealing must not cost the user the codes.
	if valid, useErr := mgr.ValidateBackupCode(ctx, "u", sec.BackupCodes[0]); useErr != nil || !valid {
		t.Fatalf("a sealed backup code must authenticate: valid=%v err=%v", valid, useErr)
	}
	if valid, useErr := mgr.ValidateBackupCode(ctx, "u", sec.BackupCodes[0]); valid || useErr != nil {
		t.Fatalf("a spent sealed code must not authenticate again: valid=%v err=%v", valid, useErr)
	}
	fresh, err := mgr.RegenerateBackupCodes(ctx, "u")
	if err != nil {
		t.Fatalf("RegenerateBackupCodes: %v", err)
	}
	if valid, freshErr := mgr.ValidateBackupCode(ctx, "u", fresh[0]); freshErr != nil || !valid {
		t.Fatalf("a regenerated sealed code must authenticate: valid=%v err=%v", valid, freshErr)
	}

	// A sealed entry that opens to something other than a digest was not written here: the
	// prefix travels inside the ciphertext precisely so that can be told apart.
	forged, err := aead.Encrypt([]byte("ABCDEFGH"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = openBackupCode(aead, backupCodeSealPrefix+base64.StdEncoding.EncodeToString(forged))
	if !errors.Is(err, ErrSecretTampered) {
		t.Fatalf("a sealed value that is not a digest must be refused, got %v", err)
	}
}

// --- otpauth URL construction ------------------------------------------------------------

// TestTOTP_QRCodeURLCannotBeHijackedByAccountName covers the enrollment takeover hiding in a
// format string. GenerateQRCodeURL interpolated the account name straight into the URI, so a
// name carrying "?secret=AAAA&issuer=Attacker&x=" closed the label and opened a query of its
// own -- and url.Values.Get returns the FIRST value of a repeated key, so the injected secret
// and issuer are the ones an authenticator enrolls. The user ends up holding a factor the
// server will never accept while the attacker holds one the user believes is theirs.
func TestTOTP_QRCodeURLCannotBeHijackedByAccountName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, _ := advManager(t, nil)
	sec, err := mgr.GenerateSecret(ctx, "u", "u@example.test")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	hostile := []struct{ name, accountName string }{
		{"query injection", "u@example.test?secret=AAAAAAAAAAAAAAAA&issuer=Attacker&x="},
		{"secret only", "u@example.test?secret=AAAAAAAAAAAAAAAA"},
		{"leading question mark", "?secret=AAAAAAAAAAAAAAAA&issuer=Attacker"},
		{"fragment", "u@example.test#secret=AAAAAAAAAAAAAAAA"},
		{"ampersand", "u@example.test&issuer=Attacker"},
		{"path traversal", "../../evil"},
		{"whitespace", "u name@example.test"},
		{"newline", "u@example.test\r\nX-Injected: 1"},
		{"percent encoded question mark", "u@example.test%3Fsecret=AAAAAAAAAAAAAAAA"},
		{"unicode", "üser@example.test"},
	}

	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := mgr.GenerateQRCodeURL(ctx, "u", tc.accountName)
			if err != nil {
				t.Fatalf("GenerateQRCodeURL: %v", err)
			}

			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("the URL handed to a QR encoder does not parse: %v (%q)", err, raw)
			}
			if got := parsed.Query().Get("secret"); got != sec.Secret {
				t.Fatalf("the QR code carries secret %q, want the enrolled %q", got, sec.Secret)
			}
			if got := parsed.Query().Get("issuer"); got != "AdversaryApp" {
				t.Fatalf("the QR code names issuer %q, want AdversaryApp", got)
			}

			// What an authenticator actually reads, through the same parser the library uses
			// when it accepts a URL back.
			key, err := otp.NewKeyFromURL(raw)
			if err != nil {
				t.Fatalf("NewKeyFromURL: %v", err)
			}
			if key.Secret() != sec.Secret {
				t.Fatalf("an authenticator would enroll %q, not the server's secret", key.Secret())
			}
			if key.Issuer() != "AdversaryApp" {
				t.Fatalf("an authenticator would show issuer %q", key.Issuer())
			}
			if key.Type() != "totp" {
				t.Fatalf("the URI is not a totp URI: %q", key.Type())
			}
		})
	}
}

// TestTOTP_QRCodeURLAgreesWithEnrollment pins the two paths together. GenerateSecret builds its
// URL through totp.Generate, which escapes correctly, while GenerateQRCodeURL built its own --
// and the account name that made them disagree was the one carrying the injection. Two URLs
// for one enrollment that name different secrets is the bug, whichever of them is wrong.
func TestTOTP_QRCodeURLAgreesWithEnrollment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, accountName := range []string{
		"u@example.test",
		"first last@example.test",
		"u@example.test?secret=AAAAAAAAAAAAAAAA&issuer=Attacker&x=",
		"üser@example.test",
	} {
		t.Run(accountName, func(t *testing.T) {
			mgr, _ := advManager(t, nil)
			sec, err := mgr.GenerateSecret(ctx, "u", accountName)
			if err != nil {
				t.Fatalf("GenerateSecret: %v", err)
			}

			enrolled, err := otp.NewKeyFromURL(sec.URL)
			if err != nil {
				t.Fatalf("the enrollment URL does not parse: %v", err)
			}
			raw, err := mgr.GenerateQRCodeURL(ctx, "u", accountName)
			if err != nil {
				t.Fatalf("GenerateQRCodeURL: %v", err)
			}
			rendered, err := otp.NewKeyFromURL(raw)
			if err != nil {
				t.Fatalf("the rendered URL does not parse: %v", err)
			}

			if enrolled.Secret() != rendered.Secret() {
				t.Fatalf("the two URLs name different secrets: %q vs %q", enrolled.Secret(), rendered.Secret())
			}
			if enrolled.Issuer() != rendered.Issuer() {
				t.Fatalf("the two URLs name different issuers: %q vs %q", enrolled.Issuer(), rendered.Issuer())
			}
			if enrolled.AccountName() != rendered.AccountName() {
				t.Fatalf("the two URLs name different accounts: %q vs %q", enrolled.AccountName(), rendered.AccountName())
			}
		})
	}
}
