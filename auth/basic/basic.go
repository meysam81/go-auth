// Package basic provides username/password authentication with secure password hashing.
package basic

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/meysam81/go-auth/auth/totp"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidCredentials is returned when authentication fails.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrUserExists is returned when attempting to register a user that already exists.
	ErrUserExists = errors.New("user already exists")

	// ErrWeakPassword is returned when a password doesn't meet minimum requirements.
	ErrWeakPassword = errors.New("password does not meet minimum requirements")

	// ErrEmailNotVerified is returned when a user attempts to authenticate without verifying their email.
	ErrEmailNotVerified = errors.New("email not verified")

	// ErrInvalidToken is returned when a token is invalid or expired.
	ErrInvalidToken = errors.New("invalid or expired token")
)

const (
	// MinPasswordLength is the minimum required password length.
	MinPasswordLength = 8

	// DefaultBcryptCost is the default bcrypt cost factor.
	DefaultBcryptCost = 12

	// DefaultPasswordResetTTL is the default password reset token TTL.
	DefaultPasswordResetTTL = 1 * time.Hour

	// DefaultEmailVerificationTTL is the default email verification token TTL.
	DefaultEmailVerificationTTL = 24 * time.Hour
)

// Authenticator handles basic username/password authentication.
type Authenticator struct {
	userStore                storage.UserStore
	credentialStore          storage.CredentialStore
	bcryptCost               int
	requireEmailVerification bool
	passwordResetTTL         time.Duration
	emailVerificationTTL     time.Duration
	totpManager              *totp.Manager
}

// Config configures the basic authenticator.
type Config struct {
	UserStore                storage.UserStore
	CredentialStore          storage.CredentialStore
	BcryptCost               int           // Optional: defaults to DefaultBcryptCost
	RequireEmailVerification bool          // Optional: defaults to false
	PasswordResetTTL         time.Duration // Optional: defaults to DefaultPasswordResetTTL
	EmailVerificationTTL     time.Duration // Optional: defaults to DefaultEmailVerificationTTL
	TOTPManager              *totp.Manager // Optional: if provided, enables TOTP support
}

// NewAuthenticator creates a new basic authenticator.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if cfg.UserStore == nil {
		return nil, errors.New("user store is required")
	}
	if cfg.CredentialStore == nil {
		return nil, errors.New("credential store is required")
	}

	cost := cfg.BcryptCost
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	passwordResetTTL := cfg.PasswordResetTTL
	if passwordResetTTL == 0 {
		passwordResetTTL = DefaultPasswordResetTTL
	}

	emailVerificationTTL := cfg.EmailVerificationTTL
	if emailVerificationTTL == 0 {
		emailVerificationTTL = DefaultEmailVerificationTTL
	}

	return &Authenticator{
		userStore:                cfg.UserStore,
		credentialStore:          cfg.CredentialStore,
		bcryptCost:               cost,
		requireEmailVerification: cfg.RequireEmailVerification,
		passwordResetTTL:         passwordResetTTL,
		emailVerificationTTL:     emailVerificationTTL,
		totpManager:              cfg.TOTPManager,
	}, nil
}

// RegisterRequest contains user registration information.
type RegisterRequest struct {
	Email    string                 `json:"email"`
	Username string                 `json:"username,omitempty"`
	Password string                 `json:"password"`
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Register creates a new user account with the provided credentials.
func (a *Authenticator) Register(ctx context.Context, req RegisterRequest) (*storage.User, error) {
	// Validate password strength
	if err := a.validatePassword(req.Password); err != nil {
		return nil, err
	}

	// Check if user already exists by email
	if req.Email != "" {
		if _, err := a.userStore.GetUserByEmail(ctx, req.Email); err == nil {
			return nil, ErrUserExists
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed to check existing user: %w", err)
		}
	}

	// Check if username is taken
	if req.Username != "" {
		if _, err := a.userStore.GetUserByUsername(ctx, req.Username); err == nil {
			return nil, ErrUserExists
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed to check existing username: %w", err)
		}
	}

	// Generate user ID
	userID, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	// Hash password
	hash, err := a.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &storage.User{
		ID:       userID,
		Email:    req.Email,
		Username: req.Username,
		Name:     req.Name,
		Provider: "basic",
		Metadata: req.Metadata,
	}

	if err := a.userStore.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Store password hash
	if err := a.credentialStore.StorePasswordHash(ctx, user.ID, hash); err != nil {
		// Attempt to clean up user if credential storage fails
		_ = a.userStore.DeleteUser(ctx, user.ID)
		return nil, fmt.Errorf("failed to store password: %w", err)
	}

	return user, nil
}

// Authenticate verifies user credentials and returns the user if valid.
// The identifier can be either email or username.
func (a *Authenticator) Authenticate(ctx context.Context, identifier, password string) (*storage.User, error) {
	// Try to find user by email first
	user, err := a.userStore.GetUserByEmail(ctx, identifier)
	if err != nil {
		// If not found by email, try username
		if errors.Is(err, storage.ErrNotFound) {
			user, err = a.userStore.GetUserByUsername(ctx, identifier)
		}

		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrInvalidCredentials
			}
			return nil, fmt.Errorf("failed to find user: %w", err)
		}
	}

	// Check email verification if required (only for non-SSO users)
	if a.requireEmailVerification && user.Provider == "basic" && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	// Get stored password hash
	hash, err := a.credentialStore.GetPasswordHash(ctx, user.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get password hash: %w", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// ChangePassword changes a user's password.
func (a *Authenticator) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	// Verify old password
	hash, err := a.credentialStore.GetPasswordHash(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Validate new password
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	// Hash and store new password
	newHash, err := a.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := a.credentialStore.StorePasswordHash(ctx, userID, newHash); err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	return nil
}

// ResetPassword resets a user's password (without requiring old password).
// This should be used with additional verification (e.g., email token).
func (a *Authenticator) ResetPassword(ctx context.Context, userID, newPassword string) error {
	// Validate new password
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	// Hash and store new password
	hash, err := a.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := a.credentialStore.StorePasswordHash(ctx, userID, hash); err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	return nil
}

// validatePassword checks if a password meets minimum requirements.
func (a *Authenticator) validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return ErrWeakPassword
	}
	// Add more validation rules as needed (uppercase, numbers, special chars, etc.)
	return nil
}

// hashPassword hashes a password using bcrypt.
func (a *Authenticator) hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), a.bcryptCost)
}

// generateID generates a cryptographically secure random ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateResetToken generates a secure password reset token.
// This token should be stored temporarily and sent to the user's email.
func GenerateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PasswordResetToken represents a stored password reset token.
type PasswordResetToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
}

// GeneratePasswordResetToken generates and stores a password reset token for a user.
// The token should be sent to the user's email for verification.
// Returns the generated token which should be included in the password reset link.
func (a *Authenticator) GeneratePasswordResetToken(ctx context.Context, emailOrUsername string) (string, error) {
	// Find user by email or username
	user, err := a.userStore.GetUserByEmail(ctx, emailOrUsername)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			user, err = a.userStore.GetUserByUsername(ctx, emailOrUsername)
		}
		if err != nil {
			// Don't leak that user doesn't exist
			if errors.Is(err, storage.ErrNotFound) {
				return "", nil // Return success but don't generate token
			}
			return "", fmt.Errorf("failed to find user: %w", err)
		}
	}

	// Generate token
	token, err := GenerateResetToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Store token with expiration
	expiresAt := time.Now().Add(a.passwordResetTTL)
	if err := a.credentialStore.StorePasswordResetToken(ctx, user.ID, token, expiresAt); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	return token, nil
}

// ValidatePasswordResetToken validates a password reset token and returns the associated user ID.
func (a *Authenticator) ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	userID, err := a.credentialStore.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("failed to validate token: %w", err)
	}

	return userID, nil
}

// CompletePasswordReset validates a password reset token and resets the user's password.
// This is a convenience method that combines token validation and password reset.
func (a *Authenticator) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	// Validate token
	userID, err := a.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return err
	}

	// Reset password
	if err := a.ResetPassword(ctx, userID, newPassword); err != nil {
		return err
	}

	// Delete the used token
	if err := a.credentialStore.DeletePasswordResetToken(ctx, token); err != nil {
		// Log error but don't fail the operation
		return nil
	}

	return nil
}

// GenerateEmailVerificationToken generates and stores an email verification token for a user.
// The token should be sent to the user's email for verification.
// Returns the generated token which should be included in the verification link.
func (a *Authenticator) GenerateEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	// Verify user exists
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", fmt.Errorf("user not found")
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Check if already verified
	if user.EmailVerified {
		return "", errors.New("email already verified")
	}

	// Generate token
	token, err := generateVerificationToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Store token with expiration
	expiresAt := time.Now().Add(a.emailVerificationTTL)
	if err := a.credentialStore.StoreEmailVerificationToken(ctx, userID, token, expiresAt); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	return token, nil
}

// VerifyEmail verifies a user's email address using a verification token.
func (a *Authenticator) VerifyEmail(ctx context.Context, token string) error {
	// Validate token
	userID, err := a.credentialStore.ValidateEmailVerificationToken(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return ErrInvalidToken
		}
		return fmt.Errorf("failed to validate token: %w", err)
	}

	// Get user
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Mark email as verified
	user.EmailVerified = true
	if err := a.userStore.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Delete the used token
	if err := a.credentialStore.DeleteEmailVerificationToken(ctx, token); err != nil {
		// Log error but don't fail the operation
		return nil
	}

	return nil
}

// ResendEmailVerificationToken generates a new email verification token for a user.
// This is useful when the original token has expired or was lost.
func (a *Authenticator) ResendEmailVerificationToken(ctx context.Context, emailOrUsername string) (string, error) {
	// Find user by email or username
	user, err := a.userStore.GetUserByEmail(ctx, emailOrUsername)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			user, err = a.userStore.GetUserByUsername(ctx, emailOrUsername)
		}
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return "", fmt.Errorf("user not found")
			}
			return "", fmt.Errorf("failed to find user: %w", err)
		}
	}

	return a.GenerateEmailVerificationToken(ctx, user.ID)
}

// generateVerificationToken generates a secure email verification token.
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TOTP Integration Methods
// These methods provide convenient integration between basic auth and TOTP.

// EnableTOTP enables TOTP for a user and returns the secret and backup codes.
// This is a convenience wrapper around totp.Manager.GenerateSecret.
func (a *Authenticator) EnableTOTP(ctx context.Context, userID, accountName string) (*totp.Secret, error) {
	if a.totpManager == nil {
		return nil, errors.New("TOTP manager not configured")
	}

	return a.totpManager.GenerateSecret(ctx, userID, accountName)
}

// DisableTOTP disables TOTP for a user.
// Requires a valid TOTP code to prevent accidental or malicious disabling.
func (a *Authenticator) DisableTOTP(ctx context.Context, userID, totpCode string) error {
	if a.totpManager == nil {
		return errors.New("TOTP manager not configured")
	}

	// Verify TOTP code before disabling
	valid, err := a.totpManager.Validate(ctx, userID, totpCode)
	if err != nil {
		return err
	}
	if !valid {
		return totp.ErrInvalidCode
	}

	return a.totpManager.Disable(ctx, userID)
}

// AuthenticateWithTOTP authenticates a user with email/username, password, and TOTP code.
// This is a convenience method that combines password and TOTP authentication.
func (a *Authenticator) AuthenticateWithTOTP(ctx context.Context, identifier, password, totpCode string) (*storage.User, error) {
	// First authenticate with password
	user, err := a.Authenticate(ctx, identifier, password)
	if err != nil {
		return nil, err
	}

	// Then validate TOTP
	if a.totpManager == nil {
		return nil, errors.New("TOTP manager not configured")
	}

	valid, err := a.totpManager.Validate(ctx, user.ID, totpCode)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, totp.ErrInvalidCode
	}

	return user, nil
}

// IsTOTPEnabled checks if TOTP is enabled for a user.
func (a *Authenticator) IsTOTPEnabled(ctx context.Context, userID string) (bool, error) {
	if a.totpManager == nil {
		return false, nil
	}

	return a.totpManager.IsEnabled(ctx, userID)
}

// RegenerateTOTPBackupCodes generates new backup codes for a user.
func (a *Authenticator) RegenerateTOTPBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if a.totpManager == nil {
		return nil, errors.New("TOTP manager not configured")
	}

	return a.totpManager.RegenerateBackupCodes(ctx, userID)
}
