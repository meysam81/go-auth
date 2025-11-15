// Package totp provides Time-based One-Time Password (TOTP) authentication
// implementing RFC 6238 for two-factor authentication (2FA).
package totp

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/meysam81/go-auth/storage"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	// ErrInvalidCode is returned when a TOTP code is invalid.
	ErrInvalidCode = errors.New("invalid TOTP code")

	// ErrAlreadyEnabled is returned when attempting to enable TOTP for a user who already has it enabled.
	ErrAlreadyEnabled = errors.New("TOTP already enabled")

	// ErrNotEnabled is returned when attempting TOTP operations for a user who doesn't have it enabled.
	ErrNotEnabled = errors.New("TOTP not enabled")
)

const (
	// DefaultBackupCodeCount is the default number of backup codes to generate.
	DefaultBackupCodeCount = 10

	// DefaultBackupCodeLength is the default length of each backup code.
	DefaultBackupCodeLength = 8
)

// Manager handles TOTP operations.
type Manager struct {
	credentialStore storage.CredentialStore
	issuer          string
	backupCodeCount int
}

// Config configures the TOTP manager.
type Config struct {
	CredentialStore storage.CredentialStore
	Issuer          string // The name of your application (e.g., "MyApp")
	BackupCodeCount int    // Optional: defaults to DefaultBackupCodeCount
}

// NewManager creates a new TOTP manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.CredentialStore == nil {
		return nil, errors.New("credential store is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}

	backupCodeCount := cfg.BackupCodeCount
	if backupCodeCount == 0 {
		backupCodeCount = DefaultBackupCodeCount
	}

	return &Manager{
		credentialStore: cfg.CredentialStore,
		issuer:          cfg.Issuer,
		backupCodeCount: backupCodeCount,
	}, nil
}

// Secret represents a TOTP secret with associated metadata.
type Secret struct {
	Secret      string   // Base32-encoded secret
	URL         string   // otpauth:// URL for QR code generation
	QRCode      string   // Base64-encoded PNG QR code image
	BackupCodes []string // One-time use backup codes
}

// GenerateSecret generates a new TOTP secret for a user.
// Returns the secret, backup codes, and a QR code URL.
func (m *Manager) GenerateSecret(ctx context.Context, userID, accountName string) (*Secret, error) {
	// Check if TOTP is already enabled
	_, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err == nil {
		return nil, ErrAlreadyEnabled
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing secret: %w", err)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: accountName,
		SecretSize:  32, // 256 bits
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate backup codes
	backupCodes, err := m.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store the secret and backup codes
	if err := m.credentialStore.StoreTOTPSecret(ctx, userID, key.Secret(), backupCodes); err != nil {
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return &Secret{
		Secret:      key.Secret(),
		URL:         key.URL(),
		QRCode:      key.URL(), // Client should generate QR code from this URL
		BackupCodes: backupCodes,
	}, nil
}

// Validate verifies a TOTP code for a user.
// Returns true if the code is valid (either TOTP or backup code).
func (m *Manager) Validate(ctx context.Context, userID, code string) (bool, error) {
	secret, backupCodes, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, ErrNotEnabled
		}
		return false, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	// Try TOTP validation first
	valid := totp.Validate(code, secret)
	if valid {
		return true, nil
	}

	// Try backup codes
	normalizedCode := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	for _, backupCode := range backupCodes {
		normalizedBackupCode := strings.ToUpper(strings.ReplaceAll(backupCode, "-", ""))
		if normalizedCode == normalizedBackupCode {
			// Use the backup code (mark as used)
			if err := m.credentialStore.UseBackupCode(ctx, userID, backupCode); err != nil {
				return false, fmt.Errorf("failed to use backup code: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

// ValidateBackupCode validates a backup code for a user.
// This is useful when you want to explicitly validate a backup code.
func (m *Manager) ValidateBackupCode(ctx context.Context, userID, code string) (bool, error) {
	_, backupCodes, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, ErrNotEnabled
		}
		return false, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	normalizedCode := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	for _, backupCode := range backupCodes {
		normalizedBackupCode := strings.ToUpper(strings.ReplaceAll(backupCode, "-", ""))
		if normalizedCode == normalizedBackupCode {
			// Use the backup code
			if err := m.credentialStore.UseBackupCode(ctx, userID, backupCode); err != nil {
				return false, fmt.Errorf("failed to use backup code: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

// Disable disables TOTP for a user.
func (m *Manager) Disable(ctx context.Context, userID string) error {
	// Check if TOTP is enabled
	_, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotEnabled
		}
		return fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	if err := m.credentialStore.DeleteTOTPSecret(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete TOTP secret: %w", err)
	}

	return nil
}

// IsEnabled checks if TOTP is enabled for a user.
func (m *Manager) IsEnabled(ctx context.Context, userID string) (bool, error) {
	_, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check TOTP status: %w", err)
	}
	return true, nil
}

// RegenerateBackupCodes generates new backup codes for a user, replacing the old ones.
func (m *Manager) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// Get existing secret
	secret, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotEnabled
		}
		return nil, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	// Generate new backup codes
	backupCodes, err := m.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store with new backup codes
	if err := m.credentialStore.StoreTOTPSecret(ctx, userID, secret, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	return backupCodes, nil
}

// GenerateQRCodeURL generates an otpauth:// URL for QR code generation.
// This is a convenience method for getting the URL without generating a new secret.
func (m *Manager) GenerateQRCodeURL(ctx context.Context, userID, accountName string) (string, error) {
	secret, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrNotEnabled
		}
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		m.issuer, accountName, secret, m.issuer))
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}

	return key.URL(), nil
}

// generateBackupCodes generates cryptographically secure backup codes.
func (m *Manager) generateBackupCodes() ([]string, error) {
	codes := make([]string, m.backupCodeCount)
	for i := 0; i < m.backupCodeCount; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// generateBackupCode generates a single backup code.
// Format: XXXX-XXXX (8 characters, uppercase alphanumeric, dash-separated)
func generateBackupCode() (string, error) {
	// Generate 5 random bytes
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base32 without padding and take first 8 characters
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if len(code) < 8 {
		// This should never happen, but handle it just in case
		return generateBackupCode()
	}
	code = code[:8]

	// Format: XXXX-XXXX
	return code[:4] + "-" + code[4:8], nil
}

// GenerateCurrentCode generates the current TOTP code for a user.
// This is primarily useful for testing and debugging.
func (m *Manager) GenerateCurrentCode(ctx context.Context, userID string) (string, error) {
	secret, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrNotEnabled
		}
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{})
	if err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}

	return code, nil
}
