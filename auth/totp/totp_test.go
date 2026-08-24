package totp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meysam81/go-auth/storage"
	"github.com/pquerna/otp/totp"
)

func TestNewManager(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()

	// Test with valid config
	mgr, err := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if mgr.issuer != "TestApp" {
		t.Errorf("Expected issuer TestApp, got %s", mgr.issuer)
	}
	if mgr.backupCodeCount != DefaultBackupCodeCount {
		t.Errorf("Expected default backup code count %d, got %d", DefaultBackupCodeCount, mgr.backupCodeCount)
	}

	// Test with custom backup code count
	mgr, err = NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		BackupCodeCount: 5,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if mgr.backupCodeCount != 5 {
		t.Errorf("Expected backup code count 5, got %d", mgr.backupCodeCount)
	}

	// Test without credential store
	_, err = NewManager(Config{
		Issuer: "TestApp",
	})
	if err == nil {
		t.Fatal("Expected error when credential store is nil")
	}

	// Test without issuer
	_, err = NewManager(Config{
		CredentialStore: credStore,
	})
	if err == nil {
		t.Fatal("Expected error when issuer is empty")
	}
}

func TestManager_GenerateSecret(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		BackupCodeCount: 10,
	})
	ctx := context.Background()

	// Test generating secret
	secret, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if secret.Secret == "" {
		t.Error("Secret should not be empty")
	}

	if secret.URL == "" {
		t.Error("URL should not be empty")
	}

	if !strings.Contains(secret.URL, "otpauth://totp/") {
		t.Errorf("URL should be otpauth URL, got %s", secret.URL)
	}

	if !strings.Contains(secret.URL, "TestApp") {
		t.Errorf("URL should contain issuer, got %s", secret.URL)
	}

	if !strings.Contains(secret.URL, "test@example.com") {
		t.Errorf("URL should contain account name, got %s", secret.URL)
	}

	if len(secret.BackupCodes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(secret.BackupCodes))
	}

	// F-07: the enrollment is stored pending until the user proves possession.
	if !secret.Pending {
		t.Error("Newly generated secret should be pending confirmation")
	}

	// Verify backup code format (XXXX-XXXX)
	for _, code := range secret.BackupCodes {
		if len(code) != 9 || code[4] != '-' {
			t.Errorf("Invalid backup code format: %s", code)
		}
	}

	// Test generating secret for user who already has one
	_, err = mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if !errors.Is(err, ErrAlreadyEnabled) {
		t.Errorf("Expected ErrAlreadyEnabled, got %v", err)
	}
}

func TestManager_Validate(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	secret, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "user123", secret.Secret)

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	// Test validating valid TOTP code
	valid, err := mgr.Validate(ctx, "user123", code)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !valid {
		t.Error("Valid TOTP code should be accepted")
	}

	// Test validating invalid TOTP code
	valid, err = mgr.Validate(ctx, "user123", "000000")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("Invalid TOTP code should be rejected")
	}

	// Test validating backup code
	backupCode := secret.BackupCodes[0]
	valid, err = mgr.Validate(ctx, "user123", backupCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !valid {
		t.Error("Valid backup code should be accepted")
	}

	// Test that backup code can only be used once
	valid, err = mgr.Validate(ctx, "user123", backupCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("Used backup code should be rejected")
	}

	// Test validating backup code with different formatting
	backupCode2 := secret.BackupCodes[1]
	// Remove dash and make lowercase
	normalizedCode := strings.ToLower(strings.ReplaceAll(backupCode2, "-", ""))
	valid, err = mgr.Validate(ctx, "user123", normalizedCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !valid {
		t.Error("Normalized backup code should be accepted")
	}

	// Test validating for user without TOTP enabled
	valid, err = mgr.Validate(ctx, "user-no-totp", "123456")
	if !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
	if valid {
		t.Error("Should not validate for user without TOTP")
	}
}

func TestManager_ValidateBackupCode(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	secret, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "user123", secret.Secret)

	// Test validating valid backup code
	backupCode := secret.BackupCodes[0]
	valid, err := mgr.ValidateBackupCode(ctx, "user123", backupCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !valid {
		t.Error("Valid backup code should be accepted")
	}

	// Test that code is marked as used
	valid, err = mgr.ValidateBackupCode(ctx, "user123", backupCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("Used backup code should be rejected")
	}

	// Test invalid backup code
	valid, err = mgr.ValidateBackupCode(ctx, "user123", "INVALID-CODE")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("Invalid backup code should be rejected")
	}

	_, err = mgr.ValidateBackupCode(ctx, "user-no-totp", "CODE-HERE")
	if !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_Disable(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	_, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Test disabling TOTP
	err = mgr.Disable(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify TOTP is disabled
	enabled, err := mgr.IsEnabled(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("TOTP should be disabled")
	}

	// Test disabling for user without TOTP
	err = mgr.Disable(ctx, "user-no-totp")
	if !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_IsEnabled(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Test user without TOTP
	enabled, err := mgr.IsEnabled(ctx, "user-no-totp")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("TOTP should not be enabled")
	}

	// Generate secret
	secret, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// F-07: a pending enrollment is not an enabled factor.
	enabled, err = mgr.IsEnabled(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("TOTP should not report enabled while confirmation is pending")
	}
	confirmEnrollment(ctx, t, mgr, "user123", secret.Secret)

	// Test user with TOTP
	enabled, err = mgr.IsEnabled(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !enabled {
		t.Error("TOTP should be enabled")
	}
}

func TestManager_RegenerateBackupCodes(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		BackupCodeCount: 10,
	})
	ctx := context.Background()

	// Generate secret
	secret, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "user123", secret.Secret)
	oldBackupCodes := secret.BackupCodes

	// Regenerate backup codes
	newBackupCodes, err := mgr.RegenerateBackupCodes(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(newBackupCodes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(newBackupCodes))
	}

	// Verify codes are different
	same := true
	for i := 0; i < len(oldBackupCodes); i++ {
		if oldBackupCodes[i] != newBackupCodes[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("New backup codes should be different from old ones")
	}

	// Verify old codes don't work
	valid, err := mgr.ValidateBackupCode(ctx, "user123", oldBackupCodes[0])
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("Old backup codes should not work after regeneration")
	}

	// Verify new codes work
	valid, err = mgr.ValidateBackupCode(ctx, "user123", newBackupCodes[0])
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !valid {
		t.Error("New backup codes should work")
	}

	// Test regenerating for user without TOTP
	_, err = mgr.RegenerateBackupCodes(ctx, "user-no-totp")
	if !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_GenerateQRCodeURL(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	_, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Generate QR code URL
	url, err := mgr.GenerateQRCodeURL(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(url, "otpauth://totp/") {
		t.Errorf("URL should be otpauth URL, got %s", url)
	}

	if !strings.Contains(url, "TestApp") {
		t.Errorf("URL should contain issuer, got %s", url)
	}

	// Test for user without TOTP
	_, err = mgr.GenerateQRCodeURL(ctx, "user-no-totp", "test@example.com")
	if !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_GenerateCurrentCode(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	secret, err := mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Generate current code
	code, err := mgr.GenerateCurrentCode(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6-digit code, got %s", code)
	}

	// Verify the code is valid
	expectedCode, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate expected code: %v", err)
	}
	if code != expectedCode {
		t.Errorf("Generated code %s doesn't match expected code %s", code, expectedCode)
	}

	// Test for user without TOTP
	_, err = mgr.GenerateCurrentCode(ctx, "user-no-totp")
	if !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestGenerateBackupCode(t *testing.T) {
	// Test backup code generation
	code1, err := generateBackupCode()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify format (XXXX-XXXX)
	if len(code1) != 9 {
		t.Errorf("Expected 9 characters, got %d", len(code1))
	}
	if code1[4] != '-' {
		t.Error("Expected dash at position 4")
	}

	// Verify characters are uppercase alphanumeric (base32 chars)
	normalized := strings.ReplaceAll(code1, "-", "")
	for _, ch := range normalized {
		if (ch < 'A' || ch > 'Z') && (ch < '2' || ch > '7') {
			t.Errorf("Invalid character in backup code: %c", ch)
		}
	}

	// Test uniqueness
	code2, err := generateBackupCode()
	if err != nil {
		t.Fatalf("Failed to generate second code: %v", err)
	}
	if code1 == code2 {
		t.Error("Codes should be unique")
	}

	// Test entropy
	codes := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		code, err := generateBackupCode()
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if codes[code] {
			t.Fatalf("Duplicate code generated: %s", code)
		}
		codes[code] = true
	}
}

func TestTOTPWorkflow(t *testing.T) {
	// Integration test: Full TOTP workflow
	credStore := storage.NewInMemoryCredentialStore()
	mgr := newTestManager(t, Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		BackupCodeCount: 10,
	})
	ctx := context.Background()

	userID := "workflow-user"
	accountName := "workflow@example.com"

	// Step 1: Check TOTP is not enabled
	enabled, err := mgr.IsEnabled(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if enabled {
		t.Error("TOTP should not be enabled initially")
	}

	// Step 2: Generate secret
	secret, err := mgr.GenerateSecret(ctx, userID, accountName)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Step 3: the factor is pending, not enabled, until it is confirmed (F-07)
	enabled, err = mgr.IsEnabled(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if enabled {
		t.Error("TOTP should not be enabled before confirmation")
	}
	pending, err := mgr.IsPending(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to read pending state: %v", err)
	}
	if !pending {
		t.Error("TOTP should be pending after generating secret")
	}
	confirmEnrollment(ctx, t, mgr, userID, secret.Secret)
	enabled, err = mgr.IsEnabled(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if !enabled {
		t.Error("TOTP should be enabled after confirmation")
	}

	// Step 4: Generate and validate TOTP code
	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	valid, err := mgr.Validate(ctx, userID, code)
	if err != nil || !valid {
		t.Error("Generated TOTP code should be valid")
	}

	// Step 5: Use a backup code
	backupCode := secret.BackupCodes[0]
	valid, err = mgr.Validate(ctx, userID, backupCode)
	if err != nil || !valid {
		t.Error("Backup code should be valid")
	}

	// Step 6: Verify backup code can't be reused
	valid, err = mgr.Validate(ctx, userID, backupCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("Used backup code should not be valid again")
	}

	// Step 7: Regenerate backup codes
	newBackupCodes, err := mgr.RegenerateBackupCodes(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to regenerate backup codes: %v", err)
	}

	// Step 8: Verify new backup code works
	valid, err = mgr.Validate(ctx, userID, newBackupCodes[0])
	if err != nil || !valid {
		t.Error("New backup code should be valid")
	}

	// Step 9: Disable TOTP
	err = mgr.Disable(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to disable TOTP: %v", err)
	}

	// Step 10: Verify TOTP is disabled
	enabled, err = mgr.IsEnabled(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if enabled {
		t.Error("TOTP should be disabled")
	}
}

// --- Hardening suite: F-06 (secrets at rest), F-07 (enroll/confirm), F-08 (replay) ---

// confirmEnrollment arms a freshly generated factor.
//
// It confirms with the PREVIOUS time step's code, which is still inside the +/-1 skew the
// validator accepts, so that the current step's code remains unused and the replay guard does
// not (correctly) reject the sign-in the calling test performs next.
func confirmEnrollment(ctx context.Context, t *testing.T, mgr *Manager, userID, secret string) {
	t.Helper()

	code, err := totp.GenerateCode(secret, time.Now().Add(-TimeStep))
	if err != nil {
		t.Fatalf("Failed to generate confirmation code: %v", err)
	}
	if err := mgr.Confirm(ctx, userID, code); err != nil {
		t.Fatalf("Failed to confirm enrollment: %v", err)
	}
}

// newTestManager builds a Manager or fails the test. A suite that ignored the constructor's
// error would surface a configuration mistake as a nil-pointer panic.
func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	return mgr
}

// testCipher is a stand-in for a real authenticated cipher. It is not one, and exists only to
// prove that the plaintext secret never reaches the store.
type testCipher struct{ key byte }

func (c testCipher) Encrypt(plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext)+1)
	out[0] = '#'
	for i, b := range plaintext {
		out[i+1] = b ^ c.key
	}
	return out, nil
}

func (c testCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || ciphertext[0] != '#' {
		return nil, errors.New("ciphertext is not authentic")
	}
	out := make([]byte, len(ciphertext)-1)
	for i, b := range ciphertext[1:] {
		out[i] = b ^ c.key
	}
	return out, nil
}

// countingGuard records how often the replay guard is consulted.
type countingGuard struct {
	calls int
	inner ReplayGuard
}

func (g *countingGuard) Seen(ctx context.Context, userID, code string) (bool, error) {
	g.calls++
	return g.inner.Seen(ctx, userID, code)
}

// TestConfirmArmsPendingFactor covers F-07: the factor must not authenticate anything until
// the user has proven the secret reached their authenticator.
func TestConfirmArmsPendingFactor(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, err := NewManager(Config{CredentialStore: credStore, Issuer: "TestApp"})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	pending, err := mgr.IsPending(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read pending state: %v", err)
	}
	if !pending {
		t.Fatal("Enrollment should be pending")
	}

	enabled, err := mgr.IsEnabled(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if enabled {
		t.Error("IsEnabled must report false for an unconfirmed factor")
	}

	// A valid code must not authenticate while the factor is pending.
	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	valid, err := mgr.Validate(ctx, "u1", code)
	if !errors.Is(err, ErrPendingConfirmation) {
		t.Errorf("Expected ErrPendingConfirmation, got %v", err)
	}
	if valid {
		t.Error("A pending factor must not validate a code")
	}

	// Backup codes must not rescue an unconfirmed factor either.
	valid, err = mgr.ValidateBackupCode(ctx, "u1", secret.BackupCodes[0])
	if !errors.Is(err, ErrPendingConfirmation) {
		t.Errorf("Expected ErrPendingConfirmation for backup code, got %v", err)
	}
	if valid {
		t.Error("A pending factor must not validate a backup code")
	}

	// Regenerating backup codes for an unconfirmed factor would bypass confirmation.
	if _, regenErr := mgr.RegenerateBackupCodes(ctx, "u1"); !errors.Is(regenErr, ErrPendingConfirmation) {
		t.Errorf("Expected ErrPendingConfirmation from RegenerateBackupCodes, got %v", regenErr)
	}

	// A wrong code leaves the enrollment pending so the user may retry.
	if confirmErr := mgr.Confirm(ctx, "u1", "000000"); !errors.Is(confirmErr, ErrInvalidCode) {
		t.Errorf("Expected ErrInvalidCode, got %v", confirmErr)
	}
	pending, err = mgr.IsPending(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read pending state: %v", err)
	}
	if !pending {
		t.Error("A failed confirmation must leave the enrollment pending")
	}

	confirmEnrollment(ctx, t, mgr, "u1", secret.Secret)

	enabled, err = mgr.IsEnabled(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if !enabled {
		t.Error("Factor should be enabled after confirmation")
	}

	valid, err = mgr.Validate(ctx, "u1", code)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !valid {
		t.Error("Confirmed factor should validate a current code")
	}

	// Confirming twice is a caller bug, not a second authentication.
	if err := mgr.Confirm(ctx, "u1", code); !errors.Is(err, ErrNotPending) {
		t.Errorf("Expected ErrNotPending, got %v", err)
	}

	// Confirm on an unknown user is not an enrollment.
	if err := mgr.Confirm(ctx, "nobody", "123456"); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

// TestConfirmCodeCannotBeReplayedAsSignIn covers the seam between F-07 and F-08.
func TestConfirmCodeCannotBeReplayedAsSignIn(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, err := NewManager(Config{CredentialStore: credStore, Issuer: "TestApp"})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	if confirmErr := mgr.Confirm(ctx, "u1", code); confirmErr != nil {
		t.Fatalf("Failed to confirm: %v", confirmErr)
	}

	valid, err := mgr.Validate(ctx, "u1", code)
	if !errors.Is(err, ErrCodeReused) {
		t.Errorf("Expected ErrCodeReused, got %v", err)
	}
	if valid {
		t.Error("The confirming code must not authenticate a sign-in")
	}
}

// TestActivateOnGenerateOptOut covers the documented migration shim for F-07, and the
// byte-identical legacy payload that keeps a rollback possible.
func TestActivateOnGenerateOptOut(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, err := NewManager(Config{
		CredentialStore:    credStore,
		Issuer:             "TestApp",
		ActivateOnGenerate: true,
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	if secret.Pending {
		t.Error("ActivateOnGenerate should arm the factor immediately")
	}

	enabled, err := mgr.IsEnabled(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read enabled state: %v", err)
	}
	if !enabled {
		t.Error("Factor should be enabled immediately under the opt-out")
	}

	stored, _, err := credStore.GetTOTPSecret(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read stored secret: %v", err)
	}
	if stored != secret.Secret {
		t.Errorf("Active unencrypted secret should be stored bare for rollback, got %q", stored)
	}

	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	valid, err := mgr.Validate(ctx, "u1", code)
	if err != nil || !valid {
		t.Errorf("Expected the code to validate, got valid=%v err=%v", valid, err)
	}
}

// TestCodeReplayRejected covers F-08 (CWE-294, RFC 6238 section 5.2): an observed code must
// not be usable a second time inside its window.
func TestCodeReplayRejected(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	guard := &countingGuard{inner: NewMemoryReplayGuard()}
	mgr, err := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		ReplayGuard:     guard,
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "u1", secret.Secret)

	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	valid, err := mgr.Validate(ctx, "u1", code)
	if err != nil || !valid {
		t.Fatalf("First use should succeed, got valid=%v err=%v", valid, err)
	}

	valid, err = mgr.Validate(ctx, "u1", code)
	if !errors.Is(err, ErrCodeReused) {
		t.Errorf("Expected ErrCodeReused on replay, got %v", err)
	}
	if valid {
		t.Error("A replayed code must be rejected")
	}

	// The same code is a different fact for a different user.
	other, err := mgr.GenerateSecret(ctx, "u2", "u2@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "u2", other.Secret)

	// An invalid code must never reach the guard: recording unverified input would make the
	// guard the memory-exhaustion vector it exists to prevent.
	before := guard.calls
	if _, invalidErr := mgr.Validate(ctx, "u2", "000000"); invalidErr != nil {
		t.Fatalf("Expected no error for an invalid code, got %v", invalidErr)
	}
	if guard.calls != before {
		t.Errorf("Replay guard consulted for an invalid code: %d -> %d", before, guard.calls)
	}

	// Backup codes are exempt: they are single-use by their own mechanism.
	before = guard.calls
	valid, err = mgr.Validate(ctx, "u2", other.BackupCodes[0])
	if err != nil || !valid {
		t.Fatalf("Backup code should validate, got valid=%v err=%v", valid, err)
	}
	if guard.calls != before {
		t.Errorf("Replay guard should not be consulted for backup codes: %d -> %d", before, guard.calls)
	}
}

// TestReplayGuardFailureDeniesTheCode proves the guard fails closed.
func TestReplayGuardFailureDeniesTheCode(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	guard := NewMemoryReplayGuard()
	mgr, err := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		ReplayGuard:     guard,
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "u1", secret.Secret)

	guard.maxEntries = 1 // already holding the confirmation code

	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	valid, err := mgr.Validate(ctx, "u1", code)
	if !errors.Is(err, ErrReplayGuardFull) {
		t.Errorf("Expected ErrReplayGuardFull, got %v", err)
	}
	if valid {
		t.Error("A code that cannot be recorded must not be accepted")
	}
}

// TestMemoryReplayGuardEvictsOnStepBoundary pins the eviction cadence: an entry must outlive
// the whole acceptance window (three RFC 6238 steps, given the +/-1 skew) and no longer.
func TestMemoryReplayGuardEvictsOnStepBoundary(t *testing.T) {
	guard := NewMemoryReplayGuard()
	now := time.Date(2026, 8, 24, 12, 0, 5, 0, time.UTC)
	guard.now = func() time.Time { return now }
	ctx := context.Background()

	seen, err := guard.Seen(ctx, "u1", "123456")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if seen {
		t.Error("First sighting should not report seen")
	}

	// Still inside the window the validator would accept the code in.
	now = now.Add(2 * TimeStep)
	seen, err = guard.Seen(ctx, "u1", "123456")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !seen {
		t.Error("Code must stay recorded for the whole acceptance window")
	}

	// Past the window: the code can no longer validate, so holding it only wastes memory.
	now = now.Add(4 * TimeStep)
	seen, err = guard.Seen(ctx, "u1", "123456")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if seen {
		t.Error("Entry should have been evicted past the acceptance window")
	}

	guard.mu.Lock()
	entries := len(guard.entries)
	guard.mu.Unlock()
	if entries != 1 {
		t.Errorf("Expected expired entries to be purged, holding %d", entries)
	}
}

// TestMemoryReplayGuardBounded proves the guard cannot grow without bound.
func TestMemoryReplayGuardBounded(t *testing.T) {
	guard := NewMemoryReplayGuard()
	guard.maxEntries = 2
	ctx := context.Background()

	for i, code := range []string{"111111", "222222"} {
		seen, err := guard.Seen(ctx, "u1", code)
		if err != nil {
			t.Fatalf("Entry %d: expected no error, got %v", i, err)
		}
		if seen {
			t.Errorf("Entry %d should not report seen", i)
		}
	}

	if _, err := guard.Seen(ctx, "u1", "333333"); !errors.Is(err, ErrReplayGuardFull) {
		t.Errorf("Expected ErrReplayGuardFull once the budget is exhausted, got %v", err)
	}
}

// TestMemoryReplayGuardConcurrent proves the check and the record are one operation: two
// simultaneous presentations of the same code must not both be accepted.
func TestMemoryReplayGuardConcurrent(t *testing.T) {
	guard := NewMemoryReplayGuard()
	ctx := context.Background()

	const workers = 64
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		firsts int
	)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			seen, err := guard.Seen(ctx, "u1", "123456")
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}
			if !seen {
				mu.Lock()
				firsts++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if firsts != 1 {
		t.Errorf("Exactly one caller may observe an unseen code, got %d", firsts)
	}
}

// TestBackupCodesHashedAtRest covers F-06 (CWE-522) for backup codes.
func TestBackupCodesHashedAtRest(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, err := NewManager(Config{CredentialStore: credStore, Issuer: "TestApp"})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "u1", secret.Secret)

	_, storedCodes, err := credStore.GetTOTPSecret(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read stored codes: %v", err)
	}
	if len(storedCodes) != DefaultBackupCodeCount {
		t.Fatalf("Expected %d stored codes, got %d", DefaultBackupCodeCount, len(storedCodes))
	}

	for _, stored := range storedCodes {
		if !strings.HasPrefix(stored, backupCodeHashPrefix) {
			t.Errorf("Stored backup code is not hashed: %q", stored)
		}
		for _, plain := range secret.BackupCodes {
			if strings.Contains(stored, normalizeBackupCode(plain)) {
				t.Errorf("Stored value %q leaks plaintext backup code", stored)
			}
		}
	}

	// The plaintext code still validates against its digest.
	valid, err := mgr.ValidateBackupCode(ctx, "u1", secret.BackupCodes[0])
	if err != nil || !valid {
		t.Errorf("Plaintext backup code should validate, got valid=%v err=%v", valid, err)
	}
	// And is single use.
	valid, err = mgr.ValidateBackupCode(ctx, "u1", secret.BackupCodes[0])
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("A used backup code must not validate again")
	}

	// Regenerated codes are hashed too.
	fresh, err := mgr.RegenerateBackupCodes(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to regenerate: %v", err)
	}
	_, storedCodes, err = credStore.GetTOTPSecret(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read stored codes: %v", err)
	}
	for _, stored := range storedCodes {
		if !strings.HasPrefix(stored, backupCodeHashPrefix) {
			t.Errorf("Regenerated backup code is not hashed: %q", stored)
		}
	}
	valid, err = mgr.ValidateBackupCode(ctx, "u1", fresh[0])
	if err != nil || !valid {
		t.Errorf("Regenerated backup code should validate, got valid=%v err=%v", valid, err)
	}
}

// TestBackupCodeDigestIsPerUser proves the salt derivation stops one precomputed table from
// covering every account.
func TestBackupCodeDigestIsPerUser(t *testing.T) {
	first, err := hashBackupCode("u1", "ABCD-EFGH")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	second, err := hashBackupCode("u2", "ABCD-EFGH")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if first == second {
		t.Error("The same code must digest differently for different users")
	}

	// Normalisation is part of the digest, not of the comparison.
	loose, err := hashBackupCode("u1", "  abcdefgh ")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if loose != first {
		t.Error("Presentation differences must not change the digest")
	}
}

// TestSecretEncryptedAtRest covers F-06 (CWE-522) for the shared secret.
func TestSecretEncryptedAtRest(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	cipher := testCipher{key: 0x5a}
	mgr, err := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		Cipher:          cipher,
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	stored, _, err := credStore.GetTOTPSecret(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read stored secret: %v", err)
	}
	if strings.Contains(stored, secret.Secret) {
		t.Fatal("Stored payload leaks the plaintext shared secret")
	}
	if !strings.HasPrefix(stored, secretPrefix+secretStatePending+"$"+secretEncodingEnc+"$") {
		t.Errorf("Unexpected pending payload shape: %q", stored)
	}

	confirmEnrollment(ctx, t, mgr, "u1", secret.Secret)

	stored, _, err = credStore.GetTOTPSecret(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read stored secret: %v", err)
	}
	if !strings.HasPrefix(stored, secretPrefix+secretStateActive+"$"+secretEncodingEnc+"$") {
		t.Errorf("Unexpected active payload shape: %q", stored)
	}
	if strings.Contains(stored, secret.Secret) {
		t.Fatal("Stored payload leaks the plaintext shared secret after confirmation")
	}

	code, err := totp.GenerateCode(secret.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	valid, err := mgr.Validate(ctx, "u1", code)
	if err != nil || !valid {
		t.Errorf("Encrypted secret should still validate, got valid=%v err=%v", valid, err)
	}

	url, err := mgr.GenerateQRCodeURL(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to build QR URL: %v", err)
	}
	if !strings.Contains(url, secret.Secret) {
		t.Error("QR URL should carry the decrypted secret")
	}

	// Losing the cipher must be loud, not silent.
	blind, err := NewManager(Config{CredentialStore: credStore, Issuer: "TestApp"})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	if _, blindErr := blind.Validate(ctx, "u1", code); !errors.Is(blindErr, ErrCipherRequired) {
		t.Errorf("Expected ErrCipherRequired, got %v", blindErr)
	}
	// The enrollment state is readable without key material.
	enabled, err := blind.IsEnabled(ctx, "u1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !enabled {
		t.Error("IsEnabled must not depend on the cipher")
	}
}

// TestCipherMigratesLegacyRow proves a deployment can adopt a Cipher without re-enrolling.
func TestCipherMigratesLegacyRow(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	ctx := context.Background()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "TestApp", AccountName: "u1@example.com"})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if seedErr := credStore.StoreTOTPSecret(ctx, "u1", key.Secret(), []string{"ABCD-EFGH"}); seedErr != nil {
		t.Fatalf("Failed to seed legacy row: %v", seedErr)
	}

	mgr, err := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		Cipher:          testCipher{key: 0x5a},
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}

	// A legacy row reads as active + raw, so it keeps working immediately.
	enabled, err := mgr.IsEnabled(ctx, "u1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !enabled {
		t.Error("A legacy row must remain enabled")
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	valid, err := mgr.Validate(ctx, "u1", code)
	if err != nil || !valid {
		t.Fatalf("Legacy row should validate, got valid=%v err=%v", valid, err)
	}

	// A legacy plaintext backup code still compares, in constant time, against itself.
	valid, err = mgr.ValidateBackupCode(ctx, "u1", "abcd-efgh")
	if err != nil || !valid {
		t.Fatalf("Legacy plaintext backup code should validate, got valid=%v err=%v", valid, err)
	}

	// Rewriting the row migrates it to ciphertext.
	if _, regenErr := mgr.RegenerateBackupCodes(ctx, "u1"); regenErr != nil {
		t.Fatalf("Failed to regenerate: %v", regenErr)
	}
	stored, _, err := credStore.GetTOTPSecret(ctx, "u1")
	if err != nil {
		t.Fatalf("Failed to read stored secret: %v", err)
	}
	if !strings.HasPrefix(stored, secretPrefix+secretStateActive+"$"+secretEncodingEnc+"$") {
		t.Errorf("Legacy row was not migrated to ciphertext: %q", stored)
	}
}

// TestCorruptSecretPayloadRejected proves a malformed payload is never treated as a secret.
func TestCorruptSecretPayloadRejected(t *testing.T) {
	ctx := context.Background()

	for name, payload := range map[string]string{
		"unknown state":    secretPrefix + "x$" + secretEncodingRaw + "$ABCDEF",
		"unknown encoding": secretPrefix + secretStateActive + "$z$ABCDEF",
		"empty data":       secretPrefix + secretStateActive + "$" + secretEncodingRaw + "$",
		"truncated":        secretPrefix + secretStateActive,
	} {
		credStore := storage.NewInMemoryCredentialStore()
		if err := credStore.StoreTOTPSecret(ctx, "u1", payload, nil); err != nil {
			t.Fatalf("%s: failed to seed: %v", name, err)
		}
		mgr, err := NewManager(Config{CredentialStore: credStore, Issuer: "TestApp"})
		if err != nil {
			t.Fatalf("%s: failed to build manager: %v", name, err)
		}

		if _, err := mgr.IsEnabled(ctx, "u1"); !errors.Is(err, ErrCorruptSecret) {
			t.Errorf("%s: expected ErrCorruptSecret from IsEnabled, got %v", name, err)
		}
		if _, err := mgr.Validate(ctx, "u1", "123456"); !errors.Is(err, ErrCorruptSecret) {
			t.Errorf("%s: expected ErrCorruptSecret from Validate, got %v", name, err)
		}
	}
}

// TestBackupCodeMatchIsExhaustive pins the constant-time scan: it must find a match wherever it
// sits in the slice, and report nothing for a miss.
func TestBackupCodeMatchIsExhaustive(t *testing.T) {
	codes := []string{"AAAA-AAAA", "BBBB-BBBB", "CCCC-CCCC"}
	hashed, err := hashBackupCodes("u1", codes)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	for i, code := range codes {
		match, ok, err := matchBackupCode("u1", code, hashed)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !ok {
			t.Fatalf("Code at index %d should match", i)
		}
		if match != hashed[i] {
			t.Errorf("Expected the stored digest at index %d, got %q", i, match)
		}
	}

	if _, ok, err := matchBackupCode("u1", "ZZZZ-ZZZZ", hashed); err != nil || ok {
		t.Errorf("Unknown code must not match, got ok=%v err=%v", ok, err)
	}
	// The digests belong to a user; another user's codes must not match them.
	if _, ok, err := matchBackupCode("u2", codes[0], hashed); err != nil || ok {
		t.Errorf("Another user's code must not match, got ok=%v err=%v", ok, err)
	}
}

// brokenCipher fails on demand so the error paths around Config.Cipher are exercised.
type brokenCipher struct{ failEncrypt bool }

func (c brokenCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c.failEncrypt {
		return nil, errors.New("kms unavailable")
	}
	return append([]byte{'#'}, plaintext...), nil
}

func (c brokenCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return nil, errors.New("authentication failed")
}

// TestCipherFailuresSurface proves a cipher outage is reported, never degraded into a silent
// "not enabled" or a plaintext write.
func TestCipherFailuresSurface(t *testing.T) {
	ctx := context.Background()

	credStore := storage.NewInMemoryCredentialStore()
	mgr, err := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		Cipher:          brokenCipher{failEncrypt: true},
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	if _, genErr := mgr.GenerateSecret(ctx, "u1", "u1@example.com"); genErr == nil {
		t.Error("A failing Encrypt must fail enrollment rather than store plaintext")
	}
	if _, _, readErr := credStore.GetTOTPSecret(ctx, "u1"); !errors.Is(readErr, storage.ErrNotFound) {
		t.Errorf("Nothing should have been stored, got %v", readErr)
	}

	credStore = storage.NewInMemoryCredentialStore()
	mgr, err = NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		Cipher:          brokenCipher{},
	})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	if _, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com"); err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	if _, err := mgr.Validate(ctx, "u1", "123456"); err == nil {
		t.Error("A failing Decrypt must be reported")
	}

	// A payload whose base64 is corrupt is a malformed payload, not a decryption failure.
	if err := credStore.StoreTOTPSecret(ctx, "u2", secretPrefix+secretStateActive+"$"+secretEncodingEnc+"$not!base64", nil); err != nil {
		t.Fatalf("Failed to seed: %v", err)
	}
	if _, err := mgr.Validate(ctx, "u2", "123456"); !errors.Is(err, ErrCorruptSecret) {
		t.Errorf("Expected ErrCorruptSecret, got %v", err)
	}
}

// TestEmptyBackupCodeNeverMatches guards the degenerate comparison: an empty submission must
// not authenticate, whatever the store happens to hold.
func TestEmptyBackupCodeNeverMatches(t *testing.T) {
	if _, ok, err := matchBackupCode("u1", "   ", []string{"", "$gab1$"}); err != nil || ok {
		t.Errorf("Empty backup code must not match, got ok=%v err=%v", ok, err)
	}

	credStore := storage.NewInMemoryCredentialStore()
	mgr, err := NewManager(Config{CredentialStore: credStore, Issuer: "TestApp"})
	if err != nil {
		t.Fatalf("Failed to build manager: %v", err)
	}
	ctx := context.Background()

	secret, err := mgr.GenerateSecret(ctx, "u1", "u1@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	confirmEnrollment(ctx, t, mgr, "u1", secret.Secret)

	valid, err := mgr.ValidateBackupCode(ctx, "u1", "")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if valid {
		t.Error("An empty backup code must be rejected")
	}
}
