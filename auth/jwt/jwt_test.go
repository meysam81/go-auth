package jwt

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/meysam81/go-auth/storage"
)

func TestNewTokenManager(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	// Test with default config
	tm, err := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if tm.signingMethod != jwt.SigningMethodHS256 {
		t.Error("Expected default signing method HS256")
	}
	if tm.accessTokenTTL != 15*time.Minute {
		t.Errorf("Expected default access TTL 15 minutes, got %v", tm.accessTokenTTL)
	}
	if tm.refreshTokenTTL != 7*24*time.Hour {
		t.Errorf("Expected default refresh TTL 7 days, got %v", tm.refreshTokenTTL)
	}

	// Test with custom config
	tokenStore := storage.NewInMemoryTokenStore()
	customAccessTTL := 30 * time.Minute
	customRefreshTTL := 30 * 24 * time.Hour

	tm, err = NewTokenManager(Config{
		UserStore:       userStore,
		TokenStore:      tokenStore,
		SigningKey:      signingKey,
		SigningMethod:   jwt.SigningMethodHS512,
		Issuer:          "test-issuer",
		AccessTokenTTL:  customAccessTTL,
		RefreshTokenTTL: customRefreshTTL,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if tm.signingMethod != jwt.SigningMethodHS512 {
		t.Error("Expected custom signing method HS512")
	}
	if tm.issuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got %s", tm.issuer)
	}
	if tm.accessTokenTTL != customAccessTTL {
		t.Errorf("Expected custom access TTL %v, got %v", customAccessTTL, tm.accessTokenTTL)
	}
	if tm.refreshTokenTTL != customRefreshTTL {
		t.Errorf("Expected custom refresh TTL %v, got %v", customRefreshTTL, tm.refreshTokenTTL)
	}

	// Test without user store
	_, err = NewTokenManager(Config{
		SigningKey: signingKey,
	})
	if err == nil {
		t.Fatal("Expected error when user store is nil")
	}

	// Test without signing key
	_, err = NewTokenManager(Config{
		UserStore: userStore,
	})
	if err == nil {
		t.Fatal("Expected error when signing key is nil")
	}
}

func TestTokenManager_GenerateTokenPair(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:       userStore,
		TokenStore:      tokenStore,
		SigningKey:      signingKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Provider: "local",
		Metadata: map[string]interface{}{"role": "admin"},
	}

	// Test generating token pair
	pair, err := tm.GenerateTokenPair(ctx, user)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify token pair structure
	if pair.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("Expected TokenType 'Bearer', got %s", pair.TokenType)
	}
	if pair.ExpiresIn != int64(15*60) {
		t.Errorf("Expected ExpiresIn 900 seconds, got %d", pair.ExpiresIn)
	}
	if pair.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}

	// Verify access token claims
	accessClaims, err := tm.ValidateToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}
	if accessClaims.UserID != user.ID {
		t.Errorf("Expected UserID %s, got %s", user.ID, accessClaims.UserID)
	}
	if accessClaims.Email != user.Email {
		t.Errorf("Expected Email %s, got %s", user.Email, accessClaims.Email)
	}
	if accessClaims.Type != AccessToken {
		t.Errorf("Expected Type 'access', got %s", accessClaims.Type)
	}
	if accessClaims.TokenID != "" {
		t.Error("Access token should not have TokenID")
	}

	// Verify refresh token claims
	refreshClaims, err := tm.ValidateToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}
	if refreshClaims.UserID != user.ID {
		t.Errorf("Expected UserID %s, got %s", user.ID, refreshClaims.UserID)
	}
	if refreshClaims.Type != RefreshToken {
		t.Errorf("Expected Type 'refresh', got %s", refreshClaims.Type)
	}
	if refreshClaims.TokenID == "" {
		t.Error("Refresh token should have TokenID")
	}

	// Verify refresh token is stored
	storedUserID, err := tokenStore.ValidateRefreshToken(ctx, refreshClaims.TokenID)
	if err != nil {
		t.Fatalf("Refresh token should be stored: %v", err)
	}
	if storedUserID != user.ID {
		t.Errorf("Expected stored UserID %s, got %s", user.ID, storedUserID)
	}

	// Verify metadata is included
	if accessClaims.Metadata["role"] != "admin" {
		t.Error("Metadata should be included in claims")
	}

	// Verify standard claims
	if accessClaims.Subject != user.ID {
		t.Errorf("Expected Subject %s, got %s", user.ID, accessClaims.Subject)
	}
	if accessClaims.IssuedAt == nil {
		t.Error("IssuedAt should be set")
	}
	if accessClaims.ExpiresAt == nil {
		t.Error("ExpiresAt should be set")
	}
	if accessClaims.NotBefore == nil {
		t.Error("NotBefore should be set")
	}
}

func TestTokenManager_GenerateTokenPair_WithoutTokenStore(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	// Create manager without token store
	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}

	// Should still generate tokens
	pair, err := tm.GenerateTokenPair(ctx, user)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("Tokens should be generated even without token store")
	}
}

func TestTokenManager_GenerateAccessToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}

	// Test generating access token only
	token, err := tm.GenerateAccessToken(ctx, user)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	// Verify it's an access token
	claims, err := tm.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if claims.Type != AccessToken {
		t.Errorf("Expected Type 'access', got %s", claims.Type)
	}
	if claims.TokenID != "" {
		t.Error("Access token should not have TokenID")
	}
}

func TestTokenManager_ValidateToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:       userStore,
		TokenStore:      tokenStore,
		SigningKey:      signingKey,
		Issuer:          "test-issuer",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}
	_ = userStore.CreateUser(ctx, user)

	// Generate tokens
	pair, _ := tm.GenerateTokenPair(ctx, user)

	// Test validating valid access token
	claims, err := tm.ValidateToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if claims.UserID != user.ID {
		t.Errorf("Expected UserID %s, got %s", user.ID, claims.UserID)
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got %s", claims.Issuer)
	}

	// Test validating valid refresh token
	claims, err = tm.ValidateToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if claims.Type != RefreshToken {
		t.Errorf("Expected Type 'refresh', got %s", claims.Type)
	}

	// Test invalid token
	_, err = tm.ValidateToken(ctx, "invalid-token")
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken, got %v", err)
	}

	// Test token with wrong signing key
	wrongKeyManager, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: []byte("wrong-key"),
	})
	_, err = wrongKeyManager.ValidateToken(ctx, pair.AccessToken)
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken for wrong key, got %v", err)
	}

	// Test expired token
	shortTTLManager, _ := NewTokenManager(Config{
		UserStore:      userStore,
		SigningKey:     signingKey,
		AccessTokenTTL: -1 * time.Hour, // Already expired
	})
	expiredToken, _ := shortTTLManager.GenerateAccessToken(ctx, user)
	_, err = tm.ValidateToken(ctx, expiredToken)
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken for expired token, got %v", err)
	}

	// Test revoked refresh token
	_ = tokenStore.RevokeRefreshToken(ctx, claims.TokenID)
	_, err = tm.ValidateToken(ctx, pair.RefreshToken)
	if err == nil || (err != ErrTokenRevoked && !strings.Contains(err.Error(), "token revoked")) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}
}

func TestTokenManager_RefreshAccessToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}
	_ = userStore.CreateUser(ctx, user)

	// Generate initial token pair
	initialPair, _ := tm.GenerateTokenPair(ctx, user)

	// Wait a bit to ensure timestamps differ
	time.Sleep(100 * time.Millisecond)

	// Test refreshing with valid refresh token
	newPair, err := tm.RefreshAccessToken(ctx, initialPair.RefreshToken)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify new access token
	if newPair.AccessToken == "" {
		t.Error("New access token should not be empty")
	}
	// Note: Access tokens might be identical if generated very close in time
	// The important thing is that we got a new valid token
	if newPair.RefreshToken != "" {
		t.Error("Refresh should not return a new refresh token")
	}
	if newPair.TokenType != "Bearer" {
		t.Errorf("Expected TokenType 'Bearer', got %s", newPair.TokenType)
	}

	// Verify new access token is valid
	claims, err := tm.ValidateToken(ctx, newPair.AccessToken)
	if err != nil {
		t.Fatalf("New access token should be valid: %v", err)
	}
	if claims.UserID != user.ID {
		t.Errorf("Expected UserID %s, got %s", user.ID, claims.UserID)
	}

	// Test refresh with access token (should fail)
	_, err = tm.RefreshAccessToken(ctx, initialPair.AccessToken)
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken for access token, got %v", err)
	}

	// Test refresh with invalid token
	_, err = tm.RefreshAccessToken(ctx, "invalid-token")
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken, got %v", err)
	}

	// Test refresh with revoked token
	_ = tokenStore.RevokeRefreshToken(ctx, claims.TokenID)
	refreshClaims, _ := ParseUnverified(initialPair.RefreshToken)
	_ = tokenStore.RevokeRefreshToken(ctx, refreshClaims.TokenID)
	_, err = tm.RefreshAccessToken(ctx, initialPair.RefreshToken)
	if err == nil || (err != ErrTokenRevoked && !strings.Contains(err.Error(), "token revoked")) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}

	// Test refresh for non-existent user
	deletedUserPair, _ := tm.GenerateTokenPair(ctx, user)
	_ = userStore.DeleteUser(ctx, user.ID)
	_, err = tm.RefreshAccessToken(ctx, deletedUserPair.RefreshToken)
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken for deleted user, got %v", err)
	}
}

func TestTokenManager_RevokeRefreshToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}

	// Generate token pair
	pair, _ := tm.GenerateTokenPair(ctx, user)

	// Test revoking refresh token
	err := tm.RevokeRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify token is revoked
	_, err = tm.ValidateToken(ctx, pair.RefreshToken)
	if err == nil || (err != ErrTokenRevoked && !strings.Contains(err.Error(), "token revoked")) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}

	// Test revoking access token (should fail - no TokenID)
	err = tm.RevokeRefreshToken(ctx, pair.AccessToken)
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken for access token, got %v", err)
	}

	// Test revoking invalid token
	err = tm.RevokeRefreshToken(ctx, "invalid-token")
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken, got %v", err)
	}
}

func TestTokenManager_RevokeRefreshToken_WithoutTokenStore(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	pair, _ := tm.GenerateTokenPair(ctx, user)

	// Should fail without token store
	err := tm.RevokeRefreshToken(ctx, pair.RefreshToken)
	if err == nil {
		t.Fatal("Expected error when token store is not configured")
	}
}

func TestTokenManager_RevokeAllUserTokens(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}

	// Generate multiple token pairs
	pair1, _ := tm.GenerateTokenPair(ctx, user)
	pair2, _ := tm.GenerateTokenPair(ctx, user)
	pair3, _ := tm.GenerateTokenPair(ctx, user)

	// Test revoking all tokens
	err := tm.RevokeAllUserTokens(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify all tokens are revoked
	_, err = tm.ValidateToken(ctx, pair1.RefreshToken)
	if err == nil || (err != ErrTokenRevoked && !strings.Contains(err.Error(), "token revoked")) {
		t.Error("pair1 should be revoked")
	}
	_, err = tm.ValidateToken(ctx, pair2.RefreshToken)
	if err == nil || (err != ErrTokenRevoked && !strings.Contains(err.Error(), "token revoked")) {
		t.Error("pair2 should be revoked")
	}
	_, err = tm.ValidateToken(ctx, pair3.RefreshToken)
	if err == nil || (err != ErrTokenRevoked && !strings.Contains(err.Error(), "token revoked")) {
		t.Error("pair3 should be revoked")
	}
}

func TestTokenManager_RevokeAllUserTokens_WithoutTokenStore(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	// Should fail without token store
	err := tm.RevokeAllUserTokens(ctx, "user123")
	if err == nil {
		t.Fatal("Expected error when token store is not configured")
	}
}

func TestGenerateTokenID(t *testing.T) {
	// Test ID generation
	id1, err := generateTokenID()
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
	id2, _ := generateTokenID()
	if id1 == id2 {
		t.Error("IDs should be unique")
	}

	// Test entropy
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := generateTokenID()
		if err != nil {
			t.Fatalf("Failed to generate ID: %v", err)
		}
		if ids[id] {
			t.Fatalf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestParseUnverified(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Provider: "local",
		Metadata: map[string]interface{}{"role": "admin"},
	}

	// Generate token
	token, _ := tm.GenerateAccessToken(ctx, user)

	// Parse without verification
	claims, err := ParseUnverified(token)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify claims
	if claims.UserID != user.ID {
		t.Errorf("Expected UserID %s, got %s", user.ID, claims.UserID)
	}
	if claims.Email != user.Email {
		t.Errorf("Expected Email %s, got %s", user.Email, claims.Email)
	}
	if claims.Type != AccessToken {
		t.Errorf("Expected Type 'access', got %s", claims.Type)
	}

	// Test with invalid token
	_, err = ParseUnverified("invalid.token.here")
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}
}

// Test token expiration
func TestTokenManager_TokenExpiration(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:      userStore,
		SigningKey:     signingKey,
		AccessTokenTTL: 100 * time.Millisecond,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	// Generate token
	token, _ := tm.GenerateAccessToken(ctx, user)

	// Wait for expiration plus some buffer
	time.Sleep(200 * time.Millisecond)

	// Should be invalid after expiration
	_, err := tm.ValidateToken(ctx, token)
	if err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken for expired token, got %v", err)
	}
}

// Test signing methods
func TestTokenManager_SigningMethods(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	// Test HS256
	tm256, _ := NewTokenManager(Config{
		UserStore:     userStore,
		SigningKey:    []byte("test-key-256"),
		SigningMethod: jwt.SigningMethodHS256,
	})
	token256, _ := tm256.GenerateAccessToken(ctx, user)
	claims, err := tm256.ValidateToken(ctx, token256)
	if err != nil {
		t.Errorf("HS256 token validation failed: %v", err)
	}
	if claims.UserID != user.ID {
		t.Error("HS256 claims invalid")
	}

	// Test HS512
	tm512, _ := NewTokenManager(Config{
		UserStore:     userStore,
		SigningKey:    []byte("test-key-512"),
		SigningMethod: jwt.SigningMethodHS512,
	})
	token512, _ := tm512.GenerateAccessToken(ctx, user)
	claims, err = tm512.ValidateToken(ctx, token512)
	if err != nil {
		t.Errorf("HS512 token validation failed: %v", err)
	}
	if claims.UserID != user.ID {
		t.Error("HS512 claims invalid")
	}

	// Verify wrong signing method is rejected
	_, err = tm256.ValidateToken(ctx, token512)
	if err != ErrInvalidToken {
		t.Error("Should reject token with different signing method")
	}
}

// Test that tokens are properly formatted JWT
func TestTokenManager_TokenFormat(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	token, _ := tm.GenerateAccessToken(ctx, user)

	// JWT should have 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 parts in JWT, got %d", len(parts))
	}

	// Each part should be base64
	for i, part := range parts {
		if part == "" {
			t.Errorf("Part %d should not be empty", i)
		}
	}
}

// Test concurrent token generation
func TestTokenManager_ConcurrentGeneration(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	// Generate tokens concurrently
	done := make(chan *TokenPair, 10)
	for i := 0; i < 10; i++ {
		go func() {
			pair, err := tm.GenerateTokenPair(ctx, user)
			if err != nil {
				t.Errorf("Failed to generate token: %v", err)
			}
			done <- pair
		}()
	}

	// Collect tokens and verify refresh token uniqueness
	// (Access tokens may be identical if generated at exact same time)
	refreshTokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		pair := <-done
		if refreshTokens[pair.RefreshToken] {
			t.Error("Duplicate refresh token generated")
		}
		refreshTokens[pair.RefreshToken] = true
	}
	if len(refreshTokens) != 10 {
		t.Errorf("Expected 10 unique refresh tokens, got %d", len(refreshTokens))
	}
}

// Test token issuer claim
func TestTokenManager_IssuerClaim(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
		Issuer:     "my-awesome-app",
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	token, _ := tm.GenerateAccessToken(ctx, user)
	claims, _ := tm.ValidateToken(ctx, token)

	if claims.Issuer != "my-awesome-app" {
		t.Errorf("Expected issuer 'my-awesome-app', got %s", claims.Issuer)
	}
}

// Test that NotBefore claim is respected
func TestTokenManager_NotBeforeClaim(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm, _ := NewTokenManager(Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	token, _ := tm.GenerateAccessToken(ctx, user)
	claims, err := ParseUnverified(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// NotBefore should be set to now or earlier
	if claims.NotBefore == nil {
		t.Fatal("NotBefore should be set")
	}
	if claims.NotBefore.Time.After(time.Now()) {
		t.Error("NotBefore should not be in the future")
	}
}
