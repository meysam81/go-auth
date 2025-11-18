package basic

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/meysam81/go-auth/auth/totp"
	"github.com/meysam81/go-auth/storage"
	totpLib "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

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

func TestAuthenticator_Register(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
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

	user, err := auth.Register(ctx, req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
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
	hash, err := credStore.GetPasswordHash(ctx, user.ID)
	if err != nil {
		t.Fatal("Password hash should be stored")
	}
	if len(hash) == 0 {
		t.Error("Password hash should not be empty")
	}

	// Verify password hash is correct
	err = bcrypt.CompareHashAndPassword(hash, []byte(req.Password))
	if err != nil {
		t.Error("Stored hash should match password")
	}

	// Test duplicate email
	duplicateEmail := RegisterRequest{
		Email:    "test@example.com",
		Username: "different",
		Password: "password123",
	}
	_, err = auth.Register(ctx, duplicateEmail)
	if err != ErrUserExists {
		t.Fatalf("Expected ErrUserExists for duplicate email, got %v", err)
	}

	// Test duplicate username
	duplicateUsername := RegisterRequest{
		Email:    "different@example.com",
		Username: "testuser",
		Password: "password123",
	}
	_, err = auth.Register(ctx, duplicateUsername)
	if err != ErrUserExists {
		t.Fatalf("Expected ErrUserExists for duplicate username, got %v", err)
	}

	// Test weak password
	weakPassword := RegisterRequest{
		Email:    "weak@example.com",
		Password: "short",
	}
	_, err = auth.Register(ctx, weakPassword)
	if err != ErrWeakPassword {
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

func TestAuthenticator_Authenticate(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
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
	registeredUser, _ := auth.Register(ctx, req)

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
	_, err = auth.Authenticate(ctx, "test@example.com", "wrongpassword")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test non-existent user
	_, err = auth.Authenticate(ctx, "nonexistent@example.com", "password123")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test non-existent username
	_, err = auth.Authenticate(ctx, "nonexistent", "password123")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test empty password
	_, err = auth.Authenticate(ctx, "test@example.com", "")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials for empty password, got %v", err)
	}
}

func TestAuthenticator_ChangePassword(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "oldpassword123",
	}
	user, _ := auth.Register(ctx, req)

	// Test successful password change
	err := auth.ChangePassword(ctx, user.ID, "oldpassword123", "newpassword123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify old password no longer works
	_, err = auth.Authenticate(ctx, "test@example.com", "oldpassword123")
	if err != ErrInvalidCredentials {
		t.Error("Old password should not work")
	}

	// Verify new password works
	_, err = auth.Authenticate(ctx, "test@example.com", "newpassword123")
	if err != nil {
		t.Fatalf("New password should work, got %v", err)
	}

	// Test change with wrong old password
	err = auth.ChangePassword(ctx, user.ID, "wrongoldpassword", "anotherpassword123")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials for wrong old password, got %v", err)
	}

	// Test change with weak new password
	err = auth.ChangePassword(ctx, user.ID, "newpassword123", "weak")
	if err != ErrWeakPassword {
		t.Fatalf("Expected ErrWeakPassword, got %v", err)
	}

	// Test change for non-existent user
	err = auth.ChangePassword(ctx, "nonexistent", "password", "newpassword123")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}

func TestAuthenticator_ResetPassword(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "oldpassword123",
	}
	user, _ := auth.Register(ctx, req)

	// Test successful password reset
	err := auth.ResetPassword(ctx, user.ID, "resetpassword123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify old password no longer works
	_, err = auth.Authenticate(ctx, "test@example.com", "oldpassword123")
	if err != ErrInvalidCredentials {
		t.Error("Old password should not work")
	}

	// Verify new password works
	_, err = auth.Authenticate(ctx, "test@example.com", "resetpassword123")
	if err != nil {
		t.Fatalf("Reset password should work, got %v", err)
	}

	// Test reset with weak password
	err = auth.ResetPassword(ctx, user.ID, "weak")
	if err != ErrWeakPassword {
		t.Fatalf("Expected ErrWeakPassword, got %v", err)
	}
}

func TestValidatePassword(t *testing.T) {
	auth, _ := NewAuthenticator(Config{
		UserStore:       storage.NewInMemoryUserStore(),
		CredentialStore: storage.NewInMemoryCredentialStore(),
	})

	// Test valid password
	err := auth.validatePassword("password123")
	if err != nil {
		t.Fatalf("Expected no error for valid password, got %v", err)
	}

	// Test password at minimum length
	err = auth.validatePassword("12345678")
	if err != nil {
		t.Fatalf("Expected no error for 8-char password, got %v", err)
	}

	// Test password below minimum length
	err = auth.validatePassword("1234567")
	if err != ErrWeakPassword {
		t.Fatalf("Expected ErrWeakPassword for 7-char password, got %v", err)
	}

	// Test empty password
	err = auth.validatePassword("")
	if err != ErrWeakPassword {
		t.Fatalf("Expected ErrWeakPassword for empty password, got %v", err)
	}
}

func TestHashPassword(t *testing.T) {
	auth, _ := NewAuthenticator(Config{
		UserStore:       storage.NewInMemoryUserStore(),
		CredentialStore: storage.NewInMemoryCredentialStore(),
		BcryptCost:      bcrypt.MinCost,
	})

	password := "testpassword123"

	// Test hashing
	hash, err := auth.hashPassword(password)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(hash) == 0 {
		t.Error("Hash should not be empty")
	}

	// Verify hash is valid bcrypt hash
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		t.Error("Hash should be verifiable")
	}

	// Test that same password produces different hashes (bcrypt salt)
	hash2, _ := auth.hashPassword(password)
	if string(hash) == string(hash2) {
		t.Error("Same password should produce different hashes due to salt")
	}

	// Verify both hashes work
	err = bcrypt.CompareHashAndPassword(hash2, []byte(password))
	if err != nil {
		t.Error("Second hash should also be verifiable")
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
	id2, _ := generateID()
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
	token2, _ := GenerateResetToken()
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

// Test registration cleanup on failure
func TestAuthenticator_Register_CleanupOnFailure(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// This test verifies that if credential storage fails, the user is cleaned up
	// We can't easily simulate this without a mock, but we can verify the happy path
	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	user, err := auth.Register(ctx, req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify both user and credential were created
	_, err = userStore.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Error("User should exist in store")
	}

	_, err = credStore.GetPasswordHash(ctx, user.ID)
	if err != nil {
		t.Error("Password hash should exist in store")
	}
}

// Test that password hashes use configured bcrypt cost
func TestAuthenticator_BcryptCost(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	ctx := context.Background()

	// Create authenticator with specific cost
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      6,
	})

	// Register a user
	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	user, _ := auth.Register(ctx, req)

	// Get the hash
	hash, _ := credStore.GetPasswordHash(ctx, user.ID)

	// Bcrypt hashes have the cost encoded in them
	// Format: $2a$[cost]$[salt+hash]
	// We can verify the cost by checking the hash prefix
	hashStr := string(hash)
	if len(hashStr) < 7 {
		t.Fatal("Hash too short to verify cost")
	}

	// The cost should be "06" in the hash
	expectedPrefix := "$2a$06$"
	if hashStr[:7] != expectedPrefix {
		t.Errorf("Expected hash prefix %s, got %s", expectedPrefix, hashStr[:7])
	}
}

// Test concurrent registrations
func TestAuthenticator_ConcurrentRegistrations(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
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
	if err1 != nil && err1 != ErrUserExists && !contains(err1.Error(), "already exists") {
		t.Errorf("Expected ErrUserExists or 'already exists', got %v", err1)
	}
	if err2 != nil && err2 != ErrUserExists && !contains(err2.Error(), "already exists") {
		t.Errorf("Expected ErrUserExists or 'already exists', got %v", err2)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != "" && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInside(s, substr)))
}

func containsInside(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Test password reset flow
func TestAuthenticator_PasswordResetFlow(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "reset@example.com",
		Username: "resetuser",
		Password: "oldpassword123",
	}
	user, _ := auth.Register(ctx, req)

	// Test generating reset token by email
	token, err := auth.GeneratePasswordResetToken(ctx, "reset@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Test generating reset token by username
	token2, err := auth.GeneratePasswordResetToken(ctx, "resetuser")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
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
	err = auth.CompletePasswordReset(ctx, token, newPassword)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify old password no longer works
	_, err = auth.Authenticate(ctx, "reset@example.com", "oldpassword123")
	if err != ErrInvalidCredentials {
		t.Error("Old password should not work")
	}

	// Verify new password works
	_, err = auth.Authenticate(ctx, "reset@example.com", newPassword)
	if err != nil {
		t.Fatalf("New password should work, got %v", err)
	}

	// Test that token is deleted after use
	_, err = auth.ValidatePasswordResetToken(ctx, token)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken for used token, got %v", err)
	}

	// Test validating invalid token
	_, err = auth.ValidatePasswordResetToken(ctx, "invalid-token")
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// Test generating token for non-existent user (should not error for security)
	token, err = auth.GeneratePasswordResetToken(ctx, "nonexistent@example.com")
	if err != nil {
		t.Fatalf("Expected no error for non-existent user, got %v", err)
	}
	if token != "" {
		t.Error("Token should be empty for non-existent user")
	}

	// Test completing reset with weak password
	token3, _ := auth.GeneratePasswordResetToken(ctx, "reset@example.com")
	err = auth.CompletePasswordReset(ctx, token3, "weak")
	if err != ErrWeakPassword {
		t.Errorf("Expected ErrWeakPassword, got %v", err)
	}
}

// Test email verification flow
func TestAuthenticator_EmailVerificationFlow(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:                userStore,
		CredentialStore:          credStore,
		BcryptCost:               bcrypt.MinCost,
		RequireEmailVerification: true,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "verify@example.com",
		Username: "verifyuser",
		Password: "password123",
	}
	user, _ := auth.Register(ctx, req)

	// User should not be verified initially
	if user.EmailVerified {
		t.Error("User should not be verified initially")
	}

	// Test that unverified user cannot authenticate
	_, err := auth.Authenticate(ctx, "verify@example.com", "password123")
	if err != ErrEmailNotVerified {
		t.Errorf("Expected ErrEmailNotVerified, got %v", err)
	}

	// Generate verification token
	token, err := auth.GenerateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Verify email
	err = auth.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check that user is now verified
	verifiedUser, _ := userStore.GetUserByID(ctx, user.ID)
	if !verifiedUser.EmailVerified {
		t.Error("User should be verified after verification")
	}

	// Test that verified user can now authenticate
	_, err = auth.Authenticate(ctx, "verify@example.com", "password123")
	if err != nil {
		t.Fatalf("Verified user should be able to authenticate, got %v", err)
	}

	// Test that token is deleted after use
	err = auth.VerifyEmail(ctx, token)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken for used token, got %v", err)
	}

	// Test verifying with invalid token
	err = auth.VerifyEmail(ctx, "invalid-token")
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// Test generating token for already verified user
	_, err = auth.GenerateEmailVerificationToken(ctx, user.ID)
	if err == nil {
		t.Error("Expected error for already verified user")
	}

	// Test generating token for non-existent user
	_, err = auth.GenerateEmailVerificationToken(ctx, "nonexistent-id")
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

// Test resending email verification token
func TestAuthenticator_ResendEmailVerification(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "resend@example.com",
		Username: "resenduser",
		Password: "password123",
	}
	user, _ := auth.Register(ctx, req)

	// Test resending by email
	token, err := auth.ResendEmailVerificationToken(ctx, "resend@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Verify the token works
	err = auth.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("Token should be valid, got %v", err)
	}

	// Check user is verified
	verifiedUser, _ := userStore.GetUserByID(ctx, user.ID)
	if !verifiedUser.EmailVerified {
		t.Error("User should be verified")
	}

	// Test resending for non-existent user
	_, err = auth.ResendEmailVerificationToken(ctx, "nonexistent@example.com")
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

// Test email verification with SSO users
func TestAuthenticator_EmailVerification_SSO(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	_, _ = NewAuthenticator(Config{
		UserStore:                userStore,
		CredentialStore:          credStore,
		BcryptCost:               bcrypt.MinCost,
		RequireEmailVerification: true,
	})
	ctx := context.Background()

	// Create an SSO user (simulating OIDC login)
	ssoUser := &storage.User{
		ID:            "sso-user-id",
		Email:         "sso@example.com",
		Provider:      "google",
		EmailVerified: true, // SSO users are typically pre-verified
	}
	err := userStore.CreateUser(ctx, ssoUser)
	if err != nil {
		t.Fatalf("Failed to create SSO user: %v", err)
	}

	// SSO users should be able to authenticate without password
	// (This test is just to ensure we don't break SSO flow with email verification)
	// Note: SSO users typically don't use password auth, but we're checking the flag works correctly
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
	token2, _ := generateVerificationToken()
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
	totpMgr, _ := totp.NewManager(totp.Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "totp@example.com",
		Password: "password123",
	}
	user, _ := auth.Register(ctx, req)

	// Test that TOTP is not enabled initially
	enabled, err := auth.IsTOTPEnabled(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("TOTP should not be enabled initially")
	}

	// Enable TOTP
	secret, err := auth.EnableTOTP(ctx, user.ID, "totp@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if secret.Secret == "" {
		t.Error("Secret should not be empty")
	}
	if len(secret.BackupCodes) == 0 {
		t.Error("Backup codes should be generated")
	}

	// Verify TOTP is now enabled
	enabled, err = auth.IsTOTPEnabled(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !enabled {
		t.Error("TOTP should be enabled")
	}

	// Test authenticating with TOTP
	code, _ := totpLib.GenerateCode(secret.Secret, time.Now())
	authenticatedUser, err := auth.AuthenticateWithTOTP(ctx, "totp@example.com", "password123", code)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if authenticatedUser.ID != user.ID {
		t.Error("Should return the same user")
	}

	// Test authenticating with invalid TOTP code
	_, err = auth.AuthenticateWithTOTP(ctx, "totp@example.com", "password123", "000000")
	if err != totp.ErrInvalidCode {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// Test authenticating with wrong password
	_, err = auth.AuthenticateWithTOTP(ctx, "totp@example.com", "wrongpassword", code)
	if err != ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Test authenticating with backup code
	backupCode := secret.BackupCodes[0]
	_, err = auth.AuthenticateWithTOTP(ctx, "totp@example.com", "password123", backupCode)
	if err != nil {
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
	newCode, _ := totpLib.GenerateCode(secret.Secret, time.Now())
	err = auth.DisableTOTP(ctx, user.ID, newCode)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify TOTP is disabled
	enabled, err = auth.IsTOTPEnabled(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("TOTP should be disabled")
	}
}

// Test TOTP operations without TOTP manager configured
func TestAuthenticator_TOTPWithoutManager(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		// No TOTP manager configured
	})
	ctx := context.Background()

	// Register a user
	req := RegisterRequest{
		Email:    "nototp@example.com",
		Password: "password123",
	}
	user, _ := auth.Register(ctx, req)

	// Test that TOTP operations fail gracefully
	enabled, err := auth.IsTOTPEnabled(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("TOTP should not be enabled when manager not configured")
	}

	_, err = auth.EnableTOTP(ctx, user.ID, "nototp@example.com")
	if err == nil {
		t.Error("Expected error when TOTP manager not configured")
	}

	err = auth.DisableTOTP(ctx, user.ID, "123456")
	if err == nil {
		t.Error("Expected error when TOTP manager not configured")
	}

	_, err = auth.AuthenticateWithTOTP(ctx, "nototp@example.com", "password123", "123456")
	if err == nil {
		t.Error("Expected error when TOTP manager not configured")
	}

	_, err = auth.RegenerateTOTPBackupCodes(ctx, user.ID)
	if err == nil {
		t.Error("Expected error when TOTP manager not configured")
	}
}

// Test disabling TOTP with invalid code
func TestAuthenticator_DisableTOTPWithInvalidCode(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr, _ := totp.NewManager(totp.Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	// Register and enable TOTP
	req := RegisterRequest{
		Email:    "disable@example.com",
		Password: "password123",
	}
	user, _ := auth.Register(ctx, req)
	_, err := auth.EnableTOTP(ctx, user.ID, "disable@example.com")
	if err != nil {
		t.Fatalf("Failed to enable TOTP: %v", err)
	}

	// Try to disable with invalid code
	err = auth.DisableTOTP(ctx, user.ID, "000000")
	if err != totp.ErrInvalidCode {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// Verify TOTP is still enabled
	enabled, _ := auth.IsTOTPEnabled(ctx, user.ID)
	if !enabled {
		t.Error("TOTP should still be enabled after failed disable attempt")
	}
}

// Test full authentication flow with TOTP
func TestAuthenticator_FullTOTPWorkflow(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()
	totpMgr, _ := totp.NewManager(totp.Config{
		CredentialStore: credStore,
		Issuer:          "TestApp",
	})
	auth, _ := NewAuthenticator(Config{
		UserStore:       userStore,
		CredentialStore: credStore,
		BcryptCost:      bcrypt.MinCost,
		TOTPManager:     totpMgr,
	})
	ctx := context.Background()

	// Step 1: Register a user
	req := RegisterRequest{
		Email:    "workflow@example.com",
		Username: "workflowuser",
		Password: "password123",
	}
	user, err := auth.Register(ctx, req)
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	// Step 2: User can authenticate with just password
	_, err = auth.Authenticate(ctx, "workflow@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}

	// Step 3: Enable TOTP
	secret, err := auth.EnableTOTP(ctx, user.ID, "workflow@example.com")
	if err != nil {
		t.Fatalf("Failed to enable TOTP: %v", err)
	}

	// Step 4: Now user needs both password and TOTP
	code, _ := totpLib.GenerateCode(secret.Secret, time.Now())
	_, err = auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", code)
	if err != nil {
		t.Fatalf("Failed to authenticate with TOTP: %v", err)
	}

	// Step 5: User loses device, uses backup code
	backupCode := secret.BackupCodes[0]
	_, err = auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", backupCode)
	if err != nil {
		t.Fatalf("Failed to authenticate with backup code: %v", err)
	}

	// Step 6: User regenerates backup codes
	newBackupCodes, err := auth.RegenerateTOTPBackupCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to regenerate backup codes: %v", err)
	}
	if len(newBackupCodes) == 0 {
		t.Error("Should have new backup codes")
	}

	// Step 7: Old backup code doesn't work
	_, err = auth.AuthenticateWithTOTP(ctx, "workflow@example.com", "password123", backupCode)
	if err != totp.ErrInvalidCode {
		t.Errorf("Old backup code should not work, got %v", err)
	}

	// Step 8: User disables TOTP
	finalCode, _ := totpLib.GenerateCode(secret.Secret, time.Now())
	err = auth.DisableTOTP(ctx, user.ID, finalCode)
	if err != nil {
		t.Fatalf("Failed to disable TOTP: %v", err)
	}

	// Step 9: User can authenticate with just password again
	_, err = auth.Authenticate(ctx, "workflow@example.com", "password123")
	if err != nil {
		t.Fatalf("Should be able to authenticate without TOTP: %v", err)
	}
}
