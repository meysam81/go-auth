package totp

import (
	"context"
	"strings"
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
	mgr, _ := NewManager(Config{
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

	// Verify backup code format (XXXX-XXXX)
	for _, code := range secret.BackupCodes {
		if len(code) != 9 || code[4] != '-' {
			t.Errorf("Invalid backup code format: %s", code)
		}
	}

	// Test generating secret for user who already has one
	_, err = mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != ErrAlreadyEnabled {
		t.Errorf("Expected ErrAlreadyEnabled, got %v", err)
	}
}

func TestManager_Validate(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, _ := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	secret, _ := mgr.GenerateSecret(ctx, "user123", "test@example.com")

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
	if err != ErrNotEnabled {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
	if valid {
		t.Error("Should not validate for user without TOTP")
	}
}

func TestManager_ValidateBackupCode(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, _ := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	secret, _ := mgr.GenerateSecret(ctx, "user123", "test@example.com")

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
	if err != ErrNotEnabled {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_Disable(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, _ := NewManager(Config{
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
	if err != ErrNotEnabled {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_IsEnabled(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, _ := NewManager(Config{
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
	_, err = mgr.GenerateSecret(ctx, "user123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

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
	mgr, _ := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		BackupCodeCount: 10,
	})
	ctx := context.Background()

	// Generate secret
	secret, _ := mgr.GenerateSecret(ctx, "user123", "test@example.com")
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
	if err != ErrNotEnabled {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_GenerateQRCodeURL(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, _ := NewManager(Config{
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
	if err != ErrNotEnabled {
		t.Errorf("Expected ErrNotEnabled, got %v", err)
	}
}

func TestManager_GenerateCurrentCode(t *testing.T) {
	credStore := storage.NewInMemoryCredentialStore()
	mgr, _ := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	ctx := context.Background()

	// Generate secret
	secret, _ := mgr.GenerateSecret(ctx, "user123", "test@example.com")

	// Generate current code
	code, err := mgr.GenerateCurrentCode(ctx, "user123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6-digit code, got %s", code)
	}

	// Verify the code is valid
	expectedCode, _ := totp.GenerateCode(secret.Secret, time.Now())
	if code != expectedCode {
		t.Errorf("Generated code %s doesn't match expected code %s", code, expectedCode)
	}

	// Test for user without TOTP
	_, err = mgr.GenerateCurrentCode(ctx, "user-no-totp")
	if err != ErrNotEnabled {
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
	code2, _ := generateBackupCode()
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
	mgr, _ := NewManager(Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
		BackupCodeCount: 10,
	})
	ctx := context.Background()

	userID := "workflow-user"
	accountName := "workflow@example.com"

	// Step 1: Check TOTP is not enabled
	enabled, _ := mgr.IsEnabled(ctx, userID)
	if enabled {
		t.Error("TOTP should not be enabled initially")
	}

	// Step 2: Generate secret
	secret, err := mgr.GenerateSecret(ctx, userID, accountName)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Step 3: Verify TOTP is now enabled
	enabled, _ = mgr.IsEnabled(ctx, userID)
	if !enabled {
		t.Error("TOTP should be enabled after generating secret")
	}

	// Step 4: Generate and validate TOTP code
	code, _ := totp.GenerateCode(secret.Secret, time.Now())
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
	valid, _ = mgr.Validate(ctx, userID, backupCode)
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
	enabled, _ = mgr.IsEnabled(ctx, userID)
	if enabled {
		t.Error("TOTP should be disabled")
	}
}
