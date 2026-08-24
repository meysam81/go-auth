package basic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/meysam81/go-auth/auth/totp"
	"github.com/meysam81/go-auth/storage"
	totpLib "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// errStoreDown is the failure a store reports when its backend is unreachable.
// The rollback and revocation findings (F-11, F-12) are only observable when a
// store fails midway, which the in-memory stores never do on their own.
var errStoreDown = errors.New("store is down")

// failingCredentialStore is an InMemoryCredentialStore with switchable failures on
// the two writes whose partial completion is a finding: the password hash whose
// absence orphans an account (F-11) and the reset-token delete whose absence
// leaves a used link live (F-12).
type failingCredentialStore struct {
	*storage.InMemoryCredentialStore

	failStorePasswordHash       bool
	failDeleteResetToken        bool
	failDeleteVerificationToken bool
}

func (s *failingCredentialStore) StorePasswordHash(ctx context.Context, userID string, hash []byte) error {
	if s.failStorePasswordHash {
		return errStoreDown
	}
	return s.InMemoryCredentialStore.StorePasswordHash(ctx, userID, hash)
}

func (s *failingCredentialStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	if s.failDeleteResetToken {
		return errStoreDown
	}
	return s.InMemoryCredentialStore.DeletePasswordResetToken(ctx, token)
}

func (s *failingCredentialStore) DeleteEmailVerificationToken(ctx context.Context, token string) error {
	if s.failDeleteVerificationToken {
		return errStoreDown
	}
	return s.InMemoryCredentialStore.DeleteEmailVerificationToken(ctx, token)
}

// failingUserStore is an InMemoryUserStore whose DeleteUser can be made to fail,
// which is the second half of the F-11 scenario: the rollback of a half-written
// registration itself failing.
type failingUserStore struct {
	*storage.InMemoryUserStore

	failDeleteUser bool
}

func (s *failingUserStore) DeleteUser(ctx context.Context, id string) error {
	if s.failDeleteUser {
		return errStoreDown
	}
	return s.InMemoryUserStore.DeleteUser(ctx, id)
}

// permissiveReplayGuard accepts every code. The F-08 replay defense belongs to
// auth/totp and is tested there; in this package it would only couple multi-step
// flows to wall-clock step boundaries, because a single 30-second window cannot
// supply as many distinct valid codes as a full enroll/sign-in/disable flow needs.
// TestAuthenticator_TOTPReplayGuardReachesTheWrapper keeps the real guard.
type permissiveReplayGuard struct{}

func (permissiveReplayGuard) Seen(context.Context, string, string) (bool, error) {
	return false, nil
}

// newTOTPManager builds a TOTP manager for the wrapper tests.
func newTOTPManager(t *testing.T, credStore storage.CredentialStore, guard totp.ReplayGuard) *totp.Manager {
	t.Helper()

	mgr, err := totp.NewManager(totp.Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		ReplayGuard:     guard,
	})
	if err != nil {
		t.Fatalf("failed to build TOTP manager: %v", err)
	}
	return mgr
}

// codeForStep returns the TOTP code for the step at offset from now.
//
// Only offsets of 0 and +TimeStep are safe: pquerna's default skew accepts one
// step either side, so a future code stays valid even if the clock crosses a step
// boundary mid-test, while a past code would fall out of the window.
func codeForStep(t *testing.T, secret string, offset time.Duration) string {
	t.Helper()

	code, err := totpLib.GenerateCode(secret, time.Now().Add(offset))
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}
	return code
}

// tokenDigest recomputes the storage form of a token independently of the
// library's own hashToken, so the F-05 tests assert the documented algorithm
// rather than agreeing with whatever the implementation happens to do.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newAuthenticator builds an Authenticator or fails the test. Keeping the error
// inside the helper is what lets the tests below write `if err := ...` without
// shadowing an outer one.
func newAuthenticator(t *testing.T, cfg Config) *Authenticator {
	t.Helper()

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to build authenticator: %v", err)
	}
	return auth
}

// mustRegister registers a user or fails the test.
func mustRegister(t *testing.T, auth *Authenticator, req RegisterRequest) *storage.User {
	t.Helper()

	user, err := auth.Register(t.Context(), req)
	if err != nil {
		t.Fatalf("failed to register %q: %v", req.Email, err)
	}
	return user
}

// mustHashPassword hashes a password or fails the test.
func mustHashPassword(t *testing.T, auth *Authenticator, password string) []byte {
	t.Helper()

	hash, err := auth.hashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	return hash
}

// mustResetToken mints a password reset token or fails the test.
func mustResetToken(t *testing.T, auth *Authenticator, identifier string) string {
	t.Helper()

	token, err := auth.GeneratePasswordResetToken(t.Context(), identifier)
	if err != nil {
		t.Fatalf("failed to generate a reset token for %q: %v", identifier, err)
	}
	return token
}

// mustVerificationToken mints an email verification token or fails the test.
func mustVerificationToken(t *testing.T, auth *Authenticator, userID string) string {
	t.Helper()

	token, err := auth.GenerateEmailVerificationToken(t.Context(), userID)
	if err != nil {
		t.Fatalf("failed to generate a verification token: %v", err)
	}
	return token
}

// mustEnableTOTP starts an enrollment or fails the test. The factor it returns is
// pending until mustConfirmTOTP arms it.
func mustEnableTOTP(t *testing.T, auth *Authenticator, userID, accountName string) *totp.Secret {
	t.Helper()

	secret, err := auth.EnableTOTP(t.Context(), userID, accountName)
	if err != nil {
		t.Fatalf("failed to enable TOTP: %v", err)
	}
	return secret
}

// mustConfirmTOTP arms a pending enrollment or fails the test.
func mustConfirmTOTP(t *testing.T, auth *Authenticator, userID, code string) {
	t.Helper()

	if err := auth.ConfirmTOTP(t.Context(), userID, code); err != nil {
		t.Fatalf("failed to confirm TOTP: %v", err)
	}
}

// totpEnabled reports whether the factor is armed, or fails the test.
func totpEnabled(t *testing.T, auth *Authenticator, userID string) bool {
	t.Helper()

	enabled, err := auth.IsTOTPEnabled(t.Context(), userID)
	if err != nil {
		t.Fatalf("failed to read TOTP status: %v", err)
	}
	return enabled
}

// totpPending reports whether the factor is awaiting confirmation, or fails the test.
func totpPending(t *testing.T, auth *Authenticator, userID string) bool {
	t.Helper()

	pending, err := auth.IsTOTPPending(t.Context(), userID)
	if err != nil {
		t.Fatalf("failed to read TOTP pending status: %v", err)
	}
	return pending
}

func TestNewAuthenticator(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	// Test with default config
	auth, err := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if auth.bcryptCost != DefaultBcryptCost {
		t.Errorf("Expected default bcrypt cost %d, got %d", DefaultBcryptCost, auth.bcryptCost)
	}

	// Test with custom bcrypt cost
	auth, err = NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      10,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if auth.bcryptCost != 10 {
		t.Errorf("Expected bcrypt cost 10, got %d", auth.bcryptCost)
	}

	// Test without user store
	_, err = NewAuthenticator(Config{
		CredentialStore: credStore,
	})
	if err == nil {
		t.Fatal("Expected error when user store is nil")
	}

	// Test without credential store
	_, err = NewAuthenticator(Config{
		UserStore: userStore,
	})
	if err == nil {
		t.Fatal("Expected error when credential store is nil")
	}

	// Test with invalid bcrypt cost (too low)
	_, err = NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      3, // Below MinCost (4)
	})
	if err == nil {
		t.Fatal("Expected error for bcrypt cost below minimum")
	}

	// Test with invalid bcrypt cost (too high)
	_, err = NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      32, // Above MaxCost (31)
	})
	if err == nil {
		t.Fatal("Expected error for bcrypt cost above maximum")
	}
}

// F-09: the dummy digest the not-found path compares against must carry the
// CONFIGURED cost. One minted at a different cost costs a different amount of
// time, which is the oracle wearing a disguise.
func TestNewAuthenticator_DummyHashUsesConfiguredCost(t *testing.T) {
	for _, cost := range []int{bcrypt.MinCost, 6, 8} {
		auth, err := NewAuthenticator(Config{
			UserStore:       storage.NewInMemoryUserStore(),
			CredentialStore: storage.NewInMemoryCredentialStore(),
			BcryptCost:      cost,
		})
		if err != nil {
			t.Fatalf("cost %d: expected no error, got %v", cost, err)
		}
		if len(auth.dummyHash) == 0 {
			t.Fatalf("cost %d: F-09 timing equalization hash was not minted", cost)
		}

		got, err := bcrypt.Cost(auth.dummyHash)
		if err != nil {
			t.Fatalf("cost %d: dummy hash is not a bcrypt digest: %v", cost, err)
		}
		if got != cost {
			t.Errorf("F-09: dummy hash cost is %d, want the configured %d", got, cost)
		}
	}
}

// The MFA gate is decided by a value the caller supplies. A value that names
// neither behavior must not be read as "do not enforce".
func TestNewAuthenticator_RejectsUnknownMFAEnforcement(t *testing.T) {
	_, err := NewAuthenticator(Config{
		UserStore:              storage.NewInMemoryUserStore(),
		CredentialStore:        storage.NewInMemoryCredentialStore(),
		RequireMFAWhenEnrolled: MFAEnforcement(42),
	})
	if err == nil {
		t.Fatal("Expected an error for an out-of-range MFAEnforcement value")
	}
}

func TestAuthenticator_Register(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost, // Use minimum cost for faster tests
	})
	ctx := context.Background()

	// Test successful registration
	req := RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
		Name:     "Test User",
		Metadata: map[string]interface{}{"role": "user"},
	}

	user, registerErr := auth.Register(ctx, req)
	if registerErr != nil {
		t.Fatalf("Expected no error, got %v", registerErr)
	}

	// Verify user fields
	if user.ID == "" {
		t.Error("User ID should be generated")
	}
	if user.Email != req.Email {
		t.Errorf("Expected email %s, got %s", req.Email, user.Email)
	}
	if user.Username != req.Username {
		t.Errorf("Expected username %s, got %s", req.Username, user.Username)
	}
	if user.Name != req.Name {
		t.Errorf("Expected name %s, got %s", req.Name, user.Name)
	}
	if user.Provider != "basic" {
		t.Errorf("Expected provider 'basic', got %s", user.Provider)
	}
	if user.Metadata["role"] != "user" {
		t.Error("Metadata should be set")
	}

	// Verify timestamps
	if user.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if user.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}

	// Verify password hash was stored
	hash, hashErr := credStore.GetPasswordHash(ctx, user.ID)
	if hashErr != nil {
		t.Fatalf("Password hash should be stored: %v", hashErr)
	}
	if len(hash) == 0 {
		t.Error("Password hash should not be empty")
	}

	// Verify password hash is correct
	if err := bcrypt.CompareHashAndPassword(hash, []byte(req.Password)); err != nil {
		t.Error("Stored hash should match password")
	}

	// Test duplicate email
	duplicateEmail := RegisterRequest{
		Email:    "test@example.com",
		Username: "different",
		Password: "password123",
	}
	if _, err := auth.Register(ctx, duplicateEmail); !errors.Is(err, ErrUserExists) {
		t.Fatalf("Expected ErrUserExists for duplicate email, got %v", err)
	}

	// Test duplicate username
	duplicateUsername := RegisterRequest{
		Email:    "different@example.com",
		Username: "testuser",
		Password: "password123",
	}
	if _, err := auth.Register(ctx, duplicateUsername); !errors.Is(err, ErrUserExists) {
		t.Fatalf("Expected ErrUserExists for duplicate username, got %v", err)
	}

	// Test weak password
	weakPassword := RegisterRequest{
		Email:    "weak@example.com",
		Password: "short",
	}
	if _, err := auth.Register(ctx, weakPassword); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Expected ErrWeakPassword, got %v", err)
	}

	// Test registration without username
	noUsername := RegisterRequest{
		Email:    "nouser@example.com",
		Password: "password123",
	}
	user2, err := auth.Register(ctx, noUsername)
	if err != nil {
		t.Fatalf("Should allow registration without username, got %v", err)
	}
	if user2.Username != "" {
		t.Error("Username should be empty")
	}
}

// F-11 (CWE-460): when the credential write fails, the user row must go with it,
// so the address is registrable again.
func TestAuthenticator_Register_RollsBackOnCredentialFailure(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := &failingCredentialStore{
		InMemoryCredentialStore: storage.NewInMemoryCredentialStore(),
		failStorePasswordHash:   true,
	}
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	req := RegisterRequest{Email: "orphan@example.com", Password: "password123"}
	if _, err := auth.Register(ctx, req); err == nil {
		t.Fatal("Expected registration to fail when the credential store fails")
	} else if errors.Is(err, ErrRegistrationRollbackFailed) {
		t.Fatalf("Rollback succeeded, so the error must not claim otherwise: %v", err)
	} else if !errors.Is(err, errStoreDown) {
		t.Errorf("Expected the store failure to be wrapped, got %v", err)
	}

	// The address must be free again: an orphaned row would block re-registration
	// forever through Register's own duplicate check.
	if _, err := userStore.GetUserByEmail(ctx, "orphan@example.com"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("F-11: user row survived the rollback, got %v", err)
	}

	credStore.failStorePasswordHash = false
	if _, err := auth.Register(ctx, req); err != nil {
		t.Fatalf("Address should be registrable again after a rolled-back attempt, got %v", err)
	}
}

// F-11 (CWE-460): when the rollback ALSO fails the account exists with no
// credential. That fact must reach the caller, not a discarded error value.
func TestAuthenticator_Register_SurfacesRollbackFailure(t *testing.T) {
	userStore := &failingUserStore{
		InMemoryUserStore: storage.NewInMemoryUserStore(),
		failDeleteUser:    true,
	}
	credStore := &failingCredentialStore{
		InMemoryCredentialStore: storage.NewInMemoryCredentialStore(),
		failStorePasswordHash:   true,
	}
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	_, err := auth.Register(ctx, RegisterRequest{Email: "stuck@example.com", Password: "password123"})
	if err == nil {
		t.Fatal("Expected registration to fail")
	}
	if !errors.Is(err, ErrRegistrationRollbackFailed) {
		t.Fatalf("F-11: rollback failure was not surfaced, got %v", err)
	}
	if !errors.Is(err, errStoreDown) {
		t.Errorf("Expected the underlying store failures to be wrapped, got %v", err)
	}

	// The operator has to be able to find the row that now blocks the address.
	orphan, lookupErr := userStore.GetUserByEmail(ctx, "stuck@example.com")
	if lookupErr != nil {
		t.Fatalf("Expected the orphaned user to still exist: %v", lookupErr)
	}
	if !strings.Contains(err.Error(), orphan.ID) {
		t.Errorf("F-11: error must name the orphaned user id %q, got %q", orphan.ID, err.Error())
	}
}

func TestAuthenticator_Authenticate(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
		Name:     "Test User",
	}
	registeredUser, err := auth.Register(ctx, req)
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	// Test authentication with email
	user, err := auth.Authenticate(ctx, "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if user.ID != registeredUser.ID {
		t.Errorf("Expected user ID %s, got %s", registeredUser.ID, user.ID)
	}

	// Test authentication with username
	user, err = auth.Authenticate(ctx, "testuser", "password123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if user.ID != registeredUser.ID {
		t.Errorf("Expected user ID %s, got %s", registeredUser.ID, user.ID)
	}

	// Test wrong password
	if _, err := auth.Authenticate(ctx, "test@example.com", "wrongpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test non-existent user
	if _, err := auth.Authenticate(ctx, "nonexistent@example.com", "password123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test non-existent username
	if _, err := auth.Authenticate(ctx, "nonexistent", "password123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test empty password
	if _, err := auth.Authenticate(ctx, "test@example.com", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Expected ErrInvalidCredentials for empty password, got %v", err)
	}

	// A user row with no password credential must be indistinguishable from an
	// unknown one -- it is the orphan shape of F-11.
	if err := userStore.CreateUser(ctx, &storage.User{ID: "no-credential", Email: "nocred@example.com"}); err != nil {
		t.Fatalf("Failed to seed credential-less user: %v", err)
	}
	if _, err := auth.Authenticate(ctx, "nocred@example.com", "password123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Expected ErrInvalidCredentials for a user with no credential, got %v", err)
	}
}

// F-09 (CWE-208): a sign-in for an unknown identifier must cost what a sign-in
// for a known one costs. Without the dummy comparison the unknown path skips
// bcrypt entirely and returns in microseconds.
//
// The tolerance is deliberately wide -- this runs on shared CI hardware -- but a
// missing bcrypt evaluation is a two-orders-of-magnitude difference, not a 2x one.
func TestAuthenticate_AccountExistenceTimingIsEqualized(t *testing.T) {
	const cost = 10 // ~50-100ms per evaluation: far above any in-memory store lookup.

	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      cost,
	})
	ctx := context.Background()

	if _, err := auth.Register(ctx, RegisterRequest{Email: "known@example.com", Password: "password123"}); err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	measure := func(identifier string) time.Duration {
		const samples = 5
		durations := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			start := time.Now()
			if _, err := auth.Authenticate(ctx, identifier, "wrongpassword"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Expected ErrInvalidCredentials for %q, got %v", identifier, err)
			}
			durations = append(durations, time.Since(start))
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		return durations[len(durations)/2]
	}

	known := measure("known@example.com")
	unknown := measure("absent@example.com")

	if known <= 0 {
		t.Fatalf("Known-account measurement is not usable: %v", known)
	}
	ratio := float64(unknown) / float64(known)
	if ratio < 0.4 || ratio > 2.5 {
		t.Errorf("F-09: unknown-account sign-in took %v against %v for a known account (ratio %.2f); "+
			"the not-found path is not performing the dummy bcrypt comparison", unknown, known, ratio)
	}
}

func TestAuthenticator_ChangePassword(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "test@example.com",
		Password: "oldpassword123",
	})

	// Test successful password change
	if err := auth.ChangePassword(ctx, user.ID, "oldpassword123", "newpassword123"); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify old password no longer works
	if _, err := auth.Authenticate(ctx, "test@example.com", "oldpassword123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("Old password should not work")
	}

	// Verify new password works
	if _, err := auth.Authenticate(ctx, "test@example.com", "newpassword123"); err != nil {
		t.Fatalf("New password should work, got %v", err)
	}

	// Test change with wrong old password
	if err := auth.ChangePassword(ctx, user.ID, "wrongoldpassword", "anotherpassword123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Expected ErrInvalidCredentials for wrong old password, got %v", err)
	}

	// Test change with weak new password
	if err := auth.ChangePassword(ctx, user.ID, "newpassword123", "weak"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Expected ErrWeakPassword, got %v", err)
	}

	// Test change for non-existent user
	if err := auth.ChangePassword(ctx, "nonexistent", "password", "newpassword123"); err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}

func TestAuthenticator_ResetPassword(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "test@example.com",
		Password: "oldpassword123",
	})

	// Test successful password reset
	if err := auth.ResetPassword(ctx, user.ID, "resetpassword123"); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify old password no longer works
	if _, err := auth.Authenticate(ctx, "test@example.com", "oldpassword123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("Old password should not work")
	}

	// Verify new password works
	if _, err := auth.Authenticate(ctx, "test@example.com", "resetpassword123"); err != nil {
		t.Fatalf("Reset password should work, got %v", err)
	}

	// Test reset with weak password
	if err := auth.ResetPassword(ctx, user.ID, "weak"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Expected ErrWeakPassword, got %v", err)
	}
}

func TestValidatePassword(t *testing.T) {
	auth := newAuthenticator(t, Config{
		UserStore:       storage.NewInMemoryUserStore(),
		CredentialStore: storage.NewInMemoryCredentialStore(),
		BcryptCost:      bcrypt.MinCost,
	})

	// Test valid password
	if err := auth.validatePassword("password123"); err != nil {
		t.Fatalf("Expected no error for valid password, got %v", err)
	}

	// Test password at minimum length
	if err := auth.validatePassword("12345678"); err != nil {
		t.Fatalf("Expected no error for 8-char password, got %v", err)
	}

	// Test password below minimum length
	if err := auth.validatePassword("1234567"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Expected ErrWeakPassword for 7-char password, got %v", err)
	}

	// Test empty password
	if err := auth.validatePassword(""); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Expected ErrWeakPassword for empty password, got %v", err)
	}
}

// F-10 (CWE-916): bcrypt stops reading at 72 bytes. A longer password must be
// refused, not silently truncated to a prefix that a second passphrase shares.
func TestValidatePassword_LengthCeilingIsBytesNotRunes(t *testing.T) {
	auth := newAuthenticator(t, Config{
		UserStore:       storage.NewInMemoryUserStore(),
		CredentialStore: storage.NewInMemoryCredentialStore(),
		BcryptCost:      bcrypt.MinCost,
	})

	tests := []struct {
		name     string
		password string
		want     error
	}{
		{"exactly at the limit", strings.Repeat("a", MaxPasswordLength), nil},
		{"one byte over", strings.Repeat("a", MaxPasswordLength+1), ErrPasswordTooLong},
		{"long passphrase", strings.Repeat("correct horse battery staple ", 4), ErrPasswordTooLong},
		// 24 three-byte runes are 72 bytes: at the ceiling by bytes, nowhere near
		// it by character count.
		{"multibyte at the limit", strings.Repeat("あ", 24), nil},
		// 25 runes are 75 bytes. A rune-counting check would wave this through and
		// bcrypt would silently drop the tail.
		{"multibyte over the limit", strings.Repeat("あ", 25), ErrPasswordTooLong},
		{"embedded NUL", "abc\x00defghij", ErrPasswordContainsNUL},
		{"trailing NUL", "password123\x00", ErrPasswordContainsNUL},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.validatePassword(tc.password)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("%d bytes: expected acceptance, got %v", len(tc.password), err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("%d bytes: expected %v, got %v", len(tc.password), tc.want, err)
			}
		})
	}
}

// The ceiling has to hold on every path that sets a password, not just the one
// the reporter happened to look at.
func TestPasswordCeilingAppliesToEveryWritePath(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	tooLong := strings.Repeat("a", MaxPasswordLength+1)

	if _, err := auth.Register(ctx, RegisterRequest{Email: "long@example.com", Password: tooLong}); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Register: expected ErrPasswordTooLong, got %v", err)
	}

	user := mustRegister(t, auth, RegisterRequest{Email: "long@example.com", Password: "password123"})

	if err := auth.ChangePassword(ctx, user.ID, "password123", tooLong); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("ChangePassword: expected ErrPasswordTooLong, got %v", err)
	}
	if err := auth.ResetPassword(ctx, user.ID, tooLong); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("ResetPassword: expected ErrPasswordTooLong, got %v", err)
	}

	// Verification must NOT enforce the ceiling: a credential registered before
	// the fix was hashed from its first 72 bytes and still has to sign in.
	if _, err := auth.Authenticate(ctx, "long@example.com", tooLong); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate: expected ErrInvalidCredentials, got %v", err)
	}
}

func TestHashPassword(t *testing.T) {
	auth := newAuthenticator(t, Config{
		UserStore:       storage.NewInMemoryUserStore(),
		CredentialStore: storage.NewInMemoryCredentialStore(),
		BcryptCost:      bcrypt.MinCost,
	})

	password := "testpassword123"

	// Test hashing
	hash := mustHashPassword(t, auth, password)
	if len(hash) == 0 {
		t.Error("Hash should not be empty")
	}

	// Verify hash is valid bcrypt hash
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		t.Error("Hash should be verifiable")
	}

	// Test that same password produces different hashes (bcrypt salt)
	hash2 := mustHashPassword(t, auth, password)
	if bytes.Equal(hash, hash2) {
		t.Error("Same password should produce different hashes due to salt")
	}

	// Verify both hashes work
	if err := bcrypt.CompareHashAndPassword(hash2, []byte(password)); err != nil {
		t.Error("Second hash should also be verifiable")
	}

	// F-10 backstop: hashPassword refuses an over-length password on its own,
	// independently of validatePassword having run first.
	if _, err := auth.hashPassword(strings.Repeat("a", MaxPasswordLength+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("Expected ErrPasswordTooLong from hashPassword, got %v", err)
	}
}

func TestGenerateID(t *testing.T) {
	// Test ID generation
	id1, err := generateID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it's valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(id1)
	if err != nil {
		t.Errorf("ID should be valid base64: %v", err)
	}

	// Verify length (16 bytes)
	if len(decoded) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(decoded))
	}

	// Test uniqueness
	id2, err := generateID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if id1 == id2 {
		t.Error("IDs should be unique")
	}

	// Test entropy - generate many IDs and check for duplicates
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := generateID()
		if err != nil {
			t.Fatalf("Failed to generate ID: %v", err)
		}
		if ids[id] {
			t.Fatalf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestGenerateResetToken(t *testing.T) {
	// Test token generation
	token1, err := GenerateResetToken()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it's valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(token1)
	if err != nil {
		t.Errorf("Token should be valid base64: %v", err)
	}

	// Verify length (32 bytes)
	if len(decoded) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(decoded))
	}

	// Test uniqueness
	token2, err := GenerateResetToken()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token1 == token2 {
		t.Error("Tokens should be unique")
	}

	// Test entropy
	tokens := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		token, err := GenerateResetToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		if tokens[token] {
			t.Fatalf("Duplicate token generated: %s", token)
		}
		tokens[token] = true
	}
}

// F-05 (CWE-522): the digest is 43 base64url characters, the same width as the
// plaintext tokens it replaces, so an existing column holds it unchanged.
func TestHashToken(t *testing.T) {
	token, err := GenerateResetToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	digest := hashToken(token)
	if digest == token {
		t.Fatal("F-05: hashToken returned its input")
	}
	if want := tokenDigest(token); digest != want {
		t.Errorf("Expected base64url SHA-256 %q, got %q", want, digest)
	}
	if len(digest) != 43 {
		t.Errorf("Expected a 43-character digest, got %d characters", len(digest))
	}
	if hashToken(token) != digest {
		t.Error("hashToken must be deterministic; the store looks a token up by it")
	}
}

// Test registration cleanup on failure
func TestAuthenticator_Register_CleanupOnFailure(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	user, err := auth.Register(ctx, req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify both user and credential were created
	if _, err := userStore.GetUserByID(ctx, user.ID); err != nil {
		t.Error("User should exist in store")
	}

	if _, err := credStore.GetPasswordHash(ctx, user.ID); err != nil {
		t.Error("Password hash should exist in store")
	}
}

// Test that password hashes use configured bcrypt cost
func TestAuthenticator_BcryptCost(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	ctx := context.Background()

	// Create authenticator with specific cost
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      6,
	})

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	})

	// Get the hash
	hash, err := credStore.GetPasswordHash(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to read password hash: %v", err)
	}

	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Stored value is not a bcrypt digest: %v", err)
	}
	if cost != 6 {
		t.Errorf("Expected bcrypt cost 6, got %d", cost)
	}
}

// Test concurrent registrations
func TestAuthenticator_ConcurrentRegistrations(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Try to register the same email concurrently
	done := make(chan error, 2)
	email := "concurrent@example.com"

	for i := 0; i < 2; i++ {
		go func() {
			req := RegisterRequest{
				Email:    email,
				Password: "password123",
			}
			_, err := auth.Register(ctx, req)
			done <- err
		}()
	}

	// Collect results
	err1 := <-done
	err2 := <-done

	// One should succeed, one should fail with ErrUserExists
	if err1 == nil && err2 == nil {
		t.Error("Both registrations succeeded, expected one to fail")
	}
	if err1 != nil && err2 != nil {
		t.Error("Both registrations failed, expected one to succeed")
	}

	// The one that failed should be related to user already existing
	for _, err := range []error{err1, err2} {
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrUserExists) && !strings.Contains(err.Error(), "already exists") {
			t.Errorf("Expected ErrUserExists or 'already exists', got %v", err)
		}
	}
}

// Test password reset flow
func TestAuthenticator_PasswordResetFlow(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "reset@example.com",
		Username: "resetuser",
		Password: "oldpassword123",
	})

	// Test generating reset token by email
	token := mustResetToken(t, auth, "reset@example.com")
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Test generating reset token by username
	token2 := mustResetToken(t, auth, "resetuser")
	if token2 == "" {
		t.Error("Token should not be empty")
	}

	// Test validating valid token
	userID, err := auth.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if userID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, userID)
	}

	// Test completing password reset
	newPassword := "newpassword456"
	if err := auth.CompletePasswordReset(ctx, token, newPassword); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify old password no longer works
	if _, err := auth.Authenticate(ctx, "reset@example.com", "oldpassword123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("Old password should not work")
	}

	// Verify new password works
	if _, err := auth.Authenticate(ctx, "reset@example.com", newPassword); err != nil {
		t.Fatalf("New password should work, got %v", err)
	}

	// Test that token is deleted after use
	if _, err := auth.ValidatePasswordResetToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken for used token, got %v", err)
	}

	// Test validating invalid token
	if _, err := auth.ValidatePasswordResetToken(ctx, "invalid-token"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// Test generating token for non-existent user (should not error for security)
	absent := mustResetToken(t, auth, "nonexistent@example.com")
	if absent != "" {
		t.Error("Token should be empty for non-existent user")
	}

	// Test completing reset with weak password
	token3 := mustResetToken(t, auth, "reset@example.com")
	if err := auth.CompletePasswordReset(ctx, token3, "weak"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("Expected ErrWeakPassword, got %v", err)
	}
}

// F-05 (CWE-522): the value that goes in the email must not be the value in the
// table. An attacker who reads the credential store must hold nothing he can
// present back to the library.
func TestPasswordResetToken_StoreHoldsOnlyTheDigest(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "hash@example.com", Password: "password123"})

	token := mustResetToken(t, auth, "hash@example.com")

	// The emailed bearer value is not a key in the store.
	if _, err := credStore.ValidatePasswordResetToken(ctx, token); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("F-05: the emailed token is a live key in the credential store (err=%v)", err)
	}

	// What is in the store is its SHA-256 digest.
	storedFor, err := credStore.ValidatePasswordResetToken(ctx, tokenDigest(token))
	if err != nil {
		t.Fatalf("F-05: expected the digest to be the stored key, got %v", err)
	}
	if storedFor != user.ID {
		t.Errorf("Expected the digest to resolve to %s, got %s", user.ID, storedFor)
	}

	// And the library still accepts the plaintext from the link.
	gotUser, err := auth.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		t.Fatalf("Expected the plaintext token to validate, got %v", err)
	}
	if gotUser != user.ID {
		t.Errorf("Expected user %s, got %s", user.ID, gotUser)
	}

	// A token written to the store in the pre-hardening plaintext form no longer
	// validates: that is the documented, TTL-bounded migration cost of F-05.
	legacy, err := GenerateResetToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	if err := credStore.StorePasswordResetToken(ctx, user.ID, legacy, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Failed to seed legacy token: %v", err)
	}
	if _, err := auth.ValidatePasswordResetToken(ctx, legacy); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Expected a pre-upgrade plaintext token to stop validating, got %v", err)
	}
}

// F-05 for the verification token, which has the same shape and a 24-hour TTL.
func TestEmailVerificationToken_StoreHoldsOnlyTheDigest(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "verifyhash@example.com", Password: "password123"})

	token := mustVerificationToken(t, auth, user.ID)

	if _, err := credStore.ValidateEmailVerificationToken(ctx, token); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("F-05: the emailed token is a live key in the credential store (err=%v)", err)
	}

	storedFor, err := credStore.ValidateEmailVerificationToken(ctx, tokenDigest(token))
	if err != nil {
		t.Fatalf("F-05: expected the digest to be the stored key, got %v", err)
	}
	if storedFor != user.ID {
		t.Errorf("Expected the digest to resolve to %s, got %s", user.ID, storedFor)
	}

	if err := auth.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("Expected the plaintext token to verify, got %v", err)
	}
}

// F-12 (CWE-613): the password changed and the token did not die with it. The
// caller has to be told, and told which of the two happened.
func TestCompletePasswordReset_ReportsUnrevokedToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := &failingCredentialStore{
		InMemoryCredentialStore: storage.NewInMemoryCredentialStore(),
	}
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	if _, err := auth.Register(ctx, RegisterRequest{Email: "stale@example.com", Password: "oldpassword123"}); err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	token := mustResetToken(t, auth, "stale@example.com")

	credStore.failDeleteResetToken = true
	err := auth.CompletePasswordReset(ctx, token, "newpassword456")
	if err == nil {
		t.Fatal("F-12: a reset that left its token live reported success")
	}
	if !errors.Is(err, ErrResetTokenNotRevoked) {
		t.Fatalf("Expected ErrResetTokenNotRevoked, got %v", err)
	}
	if !errors.Is(err, errStoreDown) {
		t.Errorf("Expected the store failure to be wrapped, got %v", err)
	}

	// The error must not be read as "the reset failed": it did not.
	if _, err := auth.Authenticate(ctx, "stale@example.com", "newpassword456"); err != nil {
		t.Fatalf("The password change should have taken effect, got %v", err)
	}
	if _, err := auth.Authenticate(ctx, "stale@example.com", "oldpassword123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("The old password should be dead")
	}
}

// The same swallow existed on the verification path and is closed the same way.
func TestVerifyEmail_ReportsUnrevokedToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := &failingCredentialStore{
		InMemoryCredentialStore: storage.NewInMemoryCredentialStore(),
	}
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "staleverify@example.com", Password: "password123"})

	token := mustVerificationToken(t, auth, user.ID)

	credStore.failDeleteVerificationToken = true
	err := auth.VerifyEmail(ctx, token)
	if err == nil {
		t.Fatal("A verification that left its token live reported success")
	}
	if !errors.Is(err, ErrVerificationTokenNotRevoked) {
		t.Fatalf("Expected ErrVerificationTokenNotRevoked, got %v", err)
	}

	verified, err := userStore.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to read user: %v", err)
	}
	if !verified.EmailVerified {
		t.Error("The verification itself should have taken effect")
	}
}

// Test email verification flow
func TestAuthenticator_EmailVerificationFlow(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:                userStore,
		CredentialStore:          credStore,
		BcryptCost:               bcrypt.MinCost,
		RequireEmailVerification: true,
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "verify@example.com",
		Username: "verifyuser",
		Password: "password123",
	})

	// User should not be verified initially
	if user.EmailVerified {
		t.Error("User should not be verified initially")
	}

	// Test that unverified user cannot authenticate
	if _, err := auth.Authenticate(ctx, "verify@example.com", "password123"); !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("Expected ErrEmailNotVerified, got %v", err)
	}

	// A wrong password must not be told that the address exists but is
	// unverified: the verification state is only disclosed to whoever holds the
	// credential.
	if _, err := auth.Authenticate(ctx, "verify@example.com", "wrongpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Expected ErrInvalidCredentials for a wrong password, got %v", err)
	}

	// Generate verification token
	token := mustVerificationToken(t, auth, user.ID)
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Verify email
	if err := auth.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check that user is now verified
	verifiedUser, err := userStore.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to read user: %v", err)
	}
	if !verifiedUser.EmailVerified {
		t.Error("User should be verified after verification")
	}

	// Test that verified user can now authenticate
	if _, err := auth.Authenticate(ctx, "verify@example.com", "password123"); err != nil {
		t.Fatalf("Verified user should be able to authenticate, got %v", err)
	}

	// Test that token is deleted after use
	if err := auth.VerifyEmail(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken for used token, got %v", err)
	}

	// Test verifying with invalid token
	if err := auth.VerifyEmail(ctx, "invalid-token"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// Test generating token for already verified user
	if _, err := auth.GenerateEmailVerificationToken(ctx, user.ID); !errors.Is(err, ErrEmailAlreadyVerified) {
		t.Errorf("Expected ErrEmailAlreadyVerified, got %v", err)
	}

	// Test generating token for non-existent user
	if _, err := auth.GenerateEmailVerificationToken(ctx, "nonexistent-id"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

// Test resending email verification token
func TestAuthenticator_ResendEmailVerification(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "resend@example.com",
		Username: "resenduser",
		Password: "password123",
	})

	// Test resending by email
	token, resendErr := auth.ResendEmailVerificationToken(ctx, "resend@example.com")
	if resendErr != nil {
		t.Fatalf("Expected no error, got %v", resendErr)
	}
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Verify the token works
	if err := auth.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("Token should be valid, got %v", err)
	}

	// Check user is verified
	verifiedUser, err := userStore.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to read user: %v", err)
	}
	if !verifiedUser.EmailVerified {
		t.Error("User should be verified")
	}

	// Test resending for non-existent user
	if _, err := auth.ResendEmailVerificationToken(ctx, "nonexistent@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

// Test generateVerificationToken
func TestGenerateVerificationToken(t *testing.T) {
	// Test token generation
	token1, err := generateVerificationToken()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it's valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(token1)
	if err != nil {
		t.Errorf("Token should be valid base64: %v", err)
	}

	// Verify length (32 bytes)
	if len(decoded) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(decoded))
	}

	// Test uniqueness
	token2, err := generateVerificationToken()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token1 == token2 {
		t.Error("Tokens should be unique")
	}

	// Test entropy
	tokens := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		token, err := generateVerificationToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		if tokens[token] {
			t.Fatalf("Duplicate token generated: %s", token)
		}
		tokens[token] = true
	}
}

// Test TOTP integration with basic auth
func TestAuthenticator_TOTPIntegration(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, permissiveReplayGuard{})
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "totp@example.com",
		Password: "password123",
	})

	// Test that TOTP is not enabled initially
	if totpEnabled(t, auth, user.ID) {
		t.Error("TOTP should not be enabled initially")
	}

	// Enable TOTP
	secret := mustEnableTOTP(t, auth, user.ID, "totp@example.com")
	if secret.Secret == "" {
		t.Error("Secret should not be empty")
	}
	if len(secret.BackupCodes) == 0 {
		t.Error("Backup codes should be generated")
	}

	// F-07: the factor is pending, not live.
	if !secret.Pending {
		t.Error("A freshly generated secret should be pending confirmation")
	}
	if totpEnabled(t, auth, user.ID) {
		t.Error("F-07: TOTP must not count as enabled before confirmation")
	}
	if !totpPending(t, auth, user.ID) {
		t.Error("The enrollment should report as pending")
	}

	// Confirm the enrollment
	mustConfirmTOTP(t, auth, user.ID, codeForStep(t, secret.Secret, 0))

	// Verify TOTP is now enabled
	if !totpEnabled(t, auth, user.ID) {
		t.Error("TOTP should be enabled")
	}

	// Test authenticating with TOTP
	code := codeForStep(t, secret.Secret, 0)
	authenticatedUser, signInErr := auth.AuthenticateWithTOTP(ctx, "totp@example.com", "password123", code)
	if signInErr != nil {
		t.Fatalf("Expected no error, got %v", signInErr)
	}
	if authenticatedUser.ID != user.ID {
		t.Error("Should return the same user")
	}

	// Test authenticating with invalid TOTP code
	if _, err := auth.AuthenticateWithTOTP(ctx, "totp@example.com", "password123", "000000"); !errors.Is(err, totp.ErrInvalidCode) {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// Test authenticating with wrong password
	if _, err := auth.AuthenticateWithTOTP(ctx, "totp@example.com", "wrongpassword", code); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test authenticating with backup code
	backupCode := secret.BackupCodes[0]
	if _, err := auth.AuthenticateWithTOTP(ctx, "totp@example.com", "password123", backupCode); err != nil {
		t.Fatalf("Backup code should work, got %v", err)
	}

	// Test regenerating backup codes
	newBackupCodes, err := auth.RegenerateTOTPBackupCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(newBackupCodes) == 0 {
		t.Error("New backup codes should be generated")
	}

	// Test disabling TOTP with valid code
	if err := auth.DisableTOTP(ctx, user.ID, codeForStep(t, secret.Secret, 0)); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify TOTP is disabled
	if totpEnabled(t, auth, user.ID) {
		t.Error("TOTP should be disabled")
	}
}

// Test TOTP operations without TOTP manager configured
func TestAuthenticator_TOTPWithoutManager(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		// No TOTP manager configured
	})
	ctx := context.Background()

	// Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "nototp@example.com",
		Password: "password123",
	})

	// Test that TOTP operations fail gracefully
	if totpEnabled(t, auth, user.ID) {
		t.Error("TOTP should not be enabled when manager not configured")
	}

	if totpPending(t, auth, user.ID) {
		t.Error("TOTP should not be pending when manager not configured")
	}

	if _, err := auth.EnableTOTP(ctx, user.ID, "nototp@example.com"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Errorf("Expected ErrTOTPNotConfigured, got %v", err)
	}

	if err := auth.ConfirmTOTP(ctx, user.ID, "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Errorf("Expected ErrTOTPNotConfigured, got %v", err)
	}

	if err := auth.DisableTOTP(ctx, user.ID, "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Errorf("Expected ErrTOTPNotConfigured, got %v", err)
	}

	if _, err := auth.AuthenticateWithTOTP(ctx, "nototp@example.com", "password123", "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Errorf("Expected ErrTOTPNotConfigured, got %v", err)
	}

	if _, err := auth.RegenerateTOTPBackupCodes(ctx, user.ID); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Errorf("Expected ErrTOTPNotConfigured, got %v", err)
	}

	// With no second factor in play, the MFA gate cannot fire.
	if _, err := auth.Authenticate(ctx, "nototp@example.com", "password123"); err != nil {
		t.Fatalf("Password-only sign-in should succeed, got %v", err)
	}
}

// Test disabling TOTP with invalid code
func TestAuthenticator_DisableTOTPWithInvalidCode(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, permissiveReplayGuard{})
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	// Register and enable TOTP
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "disable@example.com",
		Password: "password123",
	})
	secret := mustEnableTOTP(t, auth, user.ID, "disable@example.com")
	mustConfirmTOTP(t, auth, user.ID, codeForStep(t, secret.Secret, 0))

	// Try to disable with invalid code
	if err := auth.DisableTOTP(ctx, user.ID, "000000"); !errors.Is(err, totp.ErrInvalidCode) {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// Verify TOTP is still enabled
	if !totpEnabled(t, auth, user.ID) {
		t.Error("TOTP should still be enabled after failed disable attempt")
	}
}

// F-07: a user who never reached their authenticator must be able to abandon the
// enrollment. Demanding a code to cancel a factor that has never gated anything
// is the lockout itself.
func TestAuthenticator_DisableTOTPCancelsPendingEnrollment(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, permissiveReplayGuard{})
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "abandon@example.com", Password: "password123"})
	if _, err := auth.EnableTOTP(ctx, user.ID, "abandon@example.com"); err != nil {
		t.Fatalf("Failed to enable TOTP: %v", err)
	}

	if err := auth.DisableTOTP(ctx, user.ID, ""); err != nil {
		t.Fatalf("A pending enrollment should be cancellable without a code, got %v", err)
	}

	if totpPending(t, auth, user.ID) {
		t.Error("The pending enrollment should be gone")
	}

	// And enrollment can start again.
	if _, err := auth.EnableTOTP(ctx, user.ID, "abandon@example.com"); err != nil {
		t.Fatalf("Re-enrollment should be possible, got %v", err)
	}
}

// The replay guard lives in auth/totp, but a wrapper that swallowed its verdict
// would reopen F-08 from this package. This is the seam test.
func TestAuthenticator_TOTPReplayGuardReachesTheWrapper(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, nil) // nil installs the real in-memory guard
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "replay@example.com", Password: "password123"})
	secret := mustEnableTOTP(t, auth, user.ID, "replay@example.com")

	// The confirming code is consumed by the confirmation, so presenting it again
	// as a sign-in must be refused for the rest of its window.
	code := codeForStep(t, secret.Secret, 0)
	if err := auth.ConfirmTOTP(ctx, user.ID, code); err != nil {
		t.Fatalf("Failed to confirm TOTP: %v", err)
	}

	if _, err := auth.AuthenticateWithTOTP(ctx, "replay@example.com", "password123", code); !errors.Is(err, totp.ErrCodeReused) {
		t.Fatalf("F-08: a consumed code was accepted again, got %v", err)
	}
}

// MFA must not be bypassable by calling the wrong method: before this fix
// Authenticate succeeded on the password alone for a user with a live factor,
// and only AuthenticateWithTOTP consulted it.
func TestAuthenticate_RefusesPasswordOnlyWhenFactorConfirmed(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, permissiveReplayGuard{})
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "mfa@example.com", Password: "password123"})

	// No factor yet: the password alone is the whole credential.
	if _, err := auth.Authenticate(ctx, "mfa@example.com", "password123"); err != nil {
		t.Fatalf("Expected password-only sign-in before enrollment, got %v", err)
	}

	secret := mustEnableTOTP(t, auth, user.ID, "mfa@example.com")

	// F-07: a pending factor must not gate sign-in, or the user is locked out by
	// their own half-finished enrollment.
	if _, err := auth.Authenticate(ctx, "mfa@example.com", "password123"); err != nil {
		t.Fatalf("A pending enrollment must not gate sign-in, got %v", err)
	}

	mustConfirmTOTP(t, auth, user.ID, codeForStep(t, secret.Secret, 0))

	if _, err := auth.Authenticate(ctx, "mfa@example.com", "password123"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("MFA bypass: password-only sign-in returned %v, want ErrMFARequired", err)
	}

	// A wrong password must still look like a wrong password: ErrMFARequired
	// after a failed first factor would report that the account exists and is
	// enrolled.
	if _, err := auth.Authenticate(ctx, "mfa@example.com", "wrongpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Expected ErrInvalidCredentials for a wrong password, got %v", err)
	}

	// The documented way through.
	signedIn, err := auth.AuthenticateWithTOTP(ctx, "mfa@example.com", "password123", codeForStep(t, secret.Secret, 0))
	if err != nil {
		t.Fatalf("AuthenticateWithTOTP should succeed, got %v", err)
	}
	if signedIn.ID != user.ID {
		t.Errorf("Expected user %s, got %s", user.ID, signedIn.ID)
	}
}

// The opt-out exists for callers whose flow runs its own second-factor step. It
// has to actually restore the old behavior, or the migration note is wrong.
func TestAuthenticate_AllowPasswordOnlyRestoresLegacyBehavior(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, permissiveReplayGuard{})
	auth := newAuthenticator(t, Config{
		UserStore:              userStore,
		CredentialStore:        credStore,
		BcryptCost:             bcrypt.MinCost,
		TOTPManager:            totpMgr,
		RequireMFAWhenEnrolled: AllowPasswordOnly,
	})
	ctx := context.Background()

	user := mustRegister(t, auth, RegisterRequest{Email: "legacy@example.com", Password: "password123"})
	secret := mustEnableTOTP(t, auth, user.ID, "legacy@example.com")
	mustConfirmTOTP(t, auth, user.ID, codeForStep(t, secret.Secret, 0))

	if _, err := auth.Authenticate(ctx, "legacy@example.com", "password123"); err != nil {
		t.Fatalf("AllowPasswordOnly should permit a password-only sign-in, got %v", err)
	}
}

// Test full authentication flow with TOTP
func TestAuthenticator_FullTOTPWorkflow(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr := newTOTPManager(t, credStore, permissiveReplayGuard{})
	auth := newAuthenticator(t, Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	// Step 1: Register a user
	user := mustRegister(t, auth, RegisterRequest{
		Email:    "workflow@example.com",
		Username: "workflowuser",
		Password: "password123",
	})

	// Step 2: User can authenticate with just password
	if _, err := auth.Authenticate(ctx, "workflow@example.com", "password123"); err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}

	// Step 3: Enroll and confirm TOTP
	secret := mustEnableTOTP(t, auth, user.ID, "workflow@example.com")
	mustConfirmTOTP(t, auth, user.ID, codeForStep(t, secret.Secret, 0))

	// Step 4: Now the password alone is refused, and both factors are required
	if _, err := auth.Authenticate(ctx, "workflow@example.com", "password123"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("Expected ErrMFARequired after enrollment, got %v", err)
	}
	if _, err := auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", codeForStep(t, secret.Secret, 0)); err != nil {
		t.Fatalf("Failed to authenticate with TOTP: %v", err)
	}

	// Step 5: User loses device, uses backup code
	backupCode := secret.BackupCodes[0]
	if _, err := auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", backupCode); err != nil {
		t.Fatalf("Failed to authenticate with backup code: %v", err)
	}

	// Step 6: Backup codes are single-use
	if _, err := auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", backupCode); !errors.Is(err, totp.ErrInvalidCode) {
		t.Errorf("A consumed backup code must not work twice, got %v", err)
	}

	// Step 7: User regenerates backup codes
	newBackupCodes, err := auth.RegenerateTOTPBackupCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to regenerate backup codes: %v", err)
	}
	if len(newBackupCodes) == 0 {
		t.Error("Should have new backup codes")
	}

	// Step 8: Old backup code doesn't work
	if _, err := auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", secret.BackupCodes[1]); !errors.Is(err, totp.ErrInvalidCode) {
		t.Errorf("Old backup code should not work, got %v", err)
	}

	// Step 9: User disables TOTP
	if err := auth.DisableTOTP(ctx, user.ID, codeForStep(t, secret.Secret, 0)); err != nil {
		t.Fatalf("Failed to disable TOTP: %v", err)
	}

	// Step 10: User can authenticate with just password again
	if _, err := auth.Authenticate(ctx, "workflow@example.com", "password123"); err != nil {
		t.Fatalf("Should be able to authenticate without TOTP: %v", err)
	}
}
