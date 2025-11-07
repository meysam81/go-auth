// Package basic provides username/password authentication with secure password hashing.
package basic

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

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
)

const (
	// MinPasswordLength is the minimum required password length.
	MinPasswordLength = 8

	// DefaultBcryptCost is the default bcrypt cost factor.
	DefaultBcryptCost = 12
)

// Authenticator handles basic username/password authentication.
type Authenticator struct {
	userStore       storage.UserStore
	credentialStore storage.CredentialStore
	bcryptCost      int
}

// Config configures the basic authenticator.
type Config struct {
	UserStore       storage.UserStore
	CredentialStore storage.CredentialStore
	BcryptCost      int // Optional: defaults to DefaultBcryptCost
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

	return &Authenticator{
		userStore:       cfg.UserStore,
		credentialStore: cfg.CredentialStore,
		bcryptCost:      cost,
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
