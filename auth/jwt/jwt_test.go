package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

	tm := mustManager(t, Config{
		UserStore:         userStore,
		TokenStore:        tokenStore,
		SigningKey:        signingKey,
		MetadataAllowlist: []string{"role"},
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
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
	refreshClaims, err := tm.ValidateRefreshToken(ctx, pair.RefreshToken)
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

	// Verify allow-listed metadata is included (F-21)
	if accessClaims.Metadata["role"] != "admin" {
		t.Error("Allow-listed metadata should be included in claims")
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
	tm := mustManager(t, Config{
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

	tm := mustManager(t, Config{
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

	tm := mustManager(t, Config{
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
	if err := userStore.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Generate tokens
	pair := mustPair(ctx, t, tm, user)

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
	claims, err = tm.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if claims.Type != RefreshToken {
		t.Errorf("Expected Type 'refresh', got %s", claims.Type)
	}

	// Test invalid token
	_, err = tm.ValidateToken(ctx, "invalid-token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken, got %v", err)
	}

	// Test token with wrong signing key
	wrongKeyManager := mustManager(t, Config{
		UserStore:  userStore,
		SigningKey: []byte("wrong-key"),
	})
	_, err = wrongKeyManager.ValidateToken(ctx, pair.AccessToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for wrong key, got %v", err)
	}

	// Test expired token
	shortTTLManager := mustManager(t, Config{
		UserStore:      userStore,
		SigningKey:     signingKey,
		AccessTokenTTL: -1 * time.Hour, // Already expired
	})
	expiredToken := mustAccessToken(ctx, t, shortTTLManager, user)
	_, err = tm.ValidateToken(ctx, expiredToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for expired token, got %v", err)
	}

	// Test revoked refresh token
	if revokeErr := tokenStore.RevokeRefreshToken(ctx, claims.TokenID); revokeErr != nil {
		t.Fatalf("RevokeRefreshToken: %v", revokeErr)
	}
	_, err = tm.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err == nil || (!errors.Is(err, ErrTokenRevoked) && !strings.Contains(err.Error(), "token revoked")) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}
}

func TestTokenManager_RefreshAccessToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm := mustManager(t, Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
	}
	if err := userStore.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Generate initial token pair
	initialPair := mustPair(ctx, t, tm, user)

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
	if !errors.Is(err, ErrUnexpectedTokenType) {
		t.Fatalf("Expected ErrUnexpectedTokenType for access token, got %v", err)
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ErrUnexpectedTokenType must stay compatible with ErrInvalidToken, got %v", err)
	}

	// Test refresh with invalid token
	_, err = tm.RefreshAccessToken(ctx, "invalid-token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken, got %v", err)
	}

	// Test refresh with revoked token. claims came from an access token, which
	// carries no jti, so only the refresh token's own ID identifies the grant.
	refreshClaims, err := ParseUnverified(initialPair.RefreshToken)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if revokeErr := tokenStore.RevokeRefreshToken(ctx, refreshClaims.TokenID); revokeErr != nil {
		t.Fatalf("RevokeRefreshToken: %v", revokeErr)
	}
	_, err = tm.RefreshAccessToken(ctx, initialPair.RefreshToken)
	if err == nil || (!errors.Is(err, ErrTokenRevoked) && !strings.Contains(err.Error(), "token revoked")) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}

	// Test refresh for non-existent user
	deletedUserPair := mustPair(ctx, t, tm, user)
	if deleteErr := userStore.DeleteUser(ctx, user.ID); deleteErr != nil {
		t.Fatalf("DeleteUser: %v", deleteErr)
	}
	_, err = tm.RefreshAccessToken(ctx, deletedUserPair.RefreshToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for deleted user, got %v", err)
	}
}

func TestTokenManager_RevokeRefreshToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	signingKey := []byte("test-secret-key")

	tm := mustManager(t, Config{
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
	pair := mustPair(ctx, t, tm, user)

	// Test revoking refresh token
	err := tm.RevokeRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify token is revoked
	_, err = tm.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err == nil || (!errors.Is(err, ErrTokenRevoked) && !strings.Contains(err.Error(), "token revoked")) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}

	// Test revoking access token (should fail - no TokenID)
	err = tm.RevokeRefreshToken(ctx, pair.AccessToken)
	if !errors.Is(err, ErrUnexpectedTokenType) {
		t.Fatalf("Expected ErrUnexpectedTokenType for access token, got %v", err)
	}

	// Test revoking invalid token
	err = tm.RevokeRefreshToken(ctx, "invalid-token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken, got %v", err)
	}
}

func TestTokenManager_RevokeRefreshToken_WithoutTokenStore(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm := mustManager(t, Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	pair := mustPair(ctx, t, tm, user)

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

	tm := mustManager(t, Config{
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
	pair1 := mustPair(ctx, t, tm, user)
	pair2 := mustPair(ctx, t, tm, user)
	pair3 := mustPair(ctx, t, tm, user)

	// Test revoking all tokens
	err := tm.RevokeAllUserTokens(ctx, user.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify all tokens are revoked
	_, err = tm.ValidateRefreshToken(ctx, pair1.RefreshToken)
	if err == nil || (!errors.Is(err, ErrTokenRevoked) && !strings.Contains(err.Error(), "token revoked")) {
		t.Error("pair1 should be revoked")
	}
	_, err = tm.ValidateRefreshToken(ctx, pair2.RefreshToken)
	if err == nil || (!errors.Is(err, ErrTokenRevoked) && !strings.Contains(err.Error(), "token revoked")) {
		t.Error("pair2 should be revoked")
	}
	_, err = tm.ValidateRefreshToken(ctx, pair3.RefreshToken)
	if err == nil || (!errors.Is(err, ErrTokenRevoked) && !strings.Contains(err.Error(), "token revoked")) {
		t.Error("pair3 should be revoked")
	}
}

func TestTokenManager_RevokeAllUserTokens_WithoutTokenStore(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm := mustManager(t, Config{
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
	id2, err := generateTokenID()
	if err != nil {
		t.Fatalf("generateTokenID: %v", err)
	}
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

	tm := mustManager(t, Config{
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
	token := mustAccessToken(ctx, t, tm, user)

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

	tm := mustManager(t, Config{
		UserStore:      userStore,
		SigningKey:     signingKey,
		AccessTokenTTL: 100 * time.Millisecond,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	// Generate token
	token := mustAccessToken(ctx, t, tm, user)

	// Wait for expiration plus some buffer
	time.Sleep(200 * time.Millisecond)

	// Should be invalid after expiration
	_, err := tm.ValidateToken(ctx, token)
	if !errors.Is(err, ErrInvalidToken) {
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
	tm256 := mustManager(t, Config{
		UserStore:     userStore,
		SigningKey:    []byte("test-key-256"),
		SigningMethod: jwt.SigningMethodHS256,
	})
	token256 := mustAccessToken(ctx, t, tm256, user)
	claims, err := tm256.ValidateToken(ctx, token256)
	if err != nil {
		t.Errorf("HS256 token validation failed: %v", err)
	}
	if claims.UserID != user.ID {
		t.Error("HS256 claims invalid")
	}

	// Test HS512
	tm512 := mustManager(t, Config{
		UserStore:     userStore,
		SigningKey:    []byte("test-key-512"),
		SigningMethod: jwt.SigningMethodHS512,
	})
	token512 := mustAccessToken(ctx, t, tm512, user)
	claims, err = tm512.ValidateToken(ctx, token512)
	if err != nil {
		t.Errorf("HS512 token validation failed: %v", err)
	}
	if claims.UserID != user.ID {
		t.Error("HS512 claims invalid")
	}

	// Verify wrong signing method is rejected
	_, err = tm256.ValidateToken(ctx, token512)
	if !errors.Is(err, ErrInvalidToken) {
		t.Error("Should reject token with different signing method")
	}
}

// Test that tokens are properly formatted JWT
func TestTokenManager_TokenFormat(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm := mustManager(t, Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	token := mustAccessToken(ctx, t, tm, user)

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

	tm := mustManager(t, Config{
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

	tm := mustManager(t, Config{
		UserStore:  userStore,
		SigningKey: signingKey,
		Issuer:     "my-awesome-app",
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	token := mustAccessToken(ctx, t, tm, user)
	claims, err := tm.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if claims.Issuer != "my-awesome-app" {
		t.Errorf("Expected issuer 'my-awesome-app', got %s", claims.Issuer)
	}
}

// Test that NotBefore claim is respected
func TestTokenManager_NotBeforeClaim(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	signingKey := []byte("test-secret-key")

	tm := mustManager(t, Config{
		UserStore:  userStore,
		SigningKey: signingKey,
	})
	ctx := context.Background()

	user := &storage.User{
		ID: "user123",
	}

	token := mustAccessToken(ctx, t, tm, user)
	claims, err := ParseUnverified(token)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// NotBefore should be set to now or earlier
	if claims.NotBefore == nil {
		t.Fatal("NotBefore should be set")
	}
	if claims.NotBefore.After(time.Now()) {
		t.Error("NotBefore should not be in the future")
	}
}

// mustManager builds a manager or fails the test. NewTokenManager now rejects a
// key/method mismatch at construction (F-04), so a discarded error would surface
// as a nil-pointer panic several lines away from its cause.
func mustManager(t *testing.T, cfg Config) *TokenManager {
	t.Helper()

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

func mustPair(ctx context.Context, t *testing.T, tm *TokenManager, user *storage.User) *TokenPair {
	t.Helper()

	pair, err := tm.GenerateTokenPair(ctx, user)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	return pair
}

func mustAccessToken(ctx context.Context, t *testing.T, tm *TokenManager, user *storage.User) string {
	t.Helper()

	token, err := tm.GenerateAccessToken(ctx, user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	return token
}

// mintRaw signs an arbitrary claim set with the given method and key, which is
// how a test forges the shapes a well-behaved minter never produces.
func mintRaw(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()

	signed, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	return key
}

func mustECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

func mustEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv
}

// TestValidateToken_RejectsRefreshTokenAsBearer covers F-02 (CWE-863). Before
// the fix, ValidateToken -- the function a bearer-token middleware calls --
// never looked at claims.Type, so a seven-day refresh token authorized every
// route guarded by a fifteen-minute access token.
func TestValidateToken_RejectsRefreshTokenAsBearer(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	tm := mustManager(t, Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: []byte("test-secret-key"),
	})
	ctx := context.Background()

	user := &storage.User{ID: "user123", Email: "test@example.com"}
	pair := mustPair(ctx, t, tm, user)

	tests := []struct {
		name     string
		validate func(context.Context, string) (*Claims, error)
		token    string
	}{
		{"refresh token as a bearer credential", tm.ValidateToken, pair.RefreshToken},
		{"refresh token on the access entry point", tm.ValidateAccessToken, pair.RefreshToken},
		{"access token on the refresh entry point", tm.ValidateRefreshToken, pair.AccessToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := tc.validate(ctx, tc.token)
			if claims != nil {
				t.Errorf("Expected no claims, got %+v", claims)
			}
			if !errors.Is(err, ErrUnexpectedTokenType) {
				t.Fatalf("Expected ErrUnexpectedTokenType, got %v", err)
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Expected the error to stay compatible with ErrInvalidToken, got %v", err)
			}
		})
	}

	// Each token is still valid in the role it was minted for.
	if _, err := tm.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("Access token should validate on the access path: %v", err)
	}
	if _, err := tm.ValidateRefreshToken(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("Refresh token should validate on the refresh path: %v", err)
	}
}

// TestValidateToken_RejectsForeignIssuer covers F-03 (CWE-347): two services
// rotating one signing secret through their environment used to accept each
// other's tokens, because iss was minted and never read.
func TestValidateToken_RejectsForeignIssuer(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	shared := []byte("one-secret-rotated-through-the-deployment")
	ctx := context.Background()
	user := &storage.User{ID: "user123", Email: "test@example.com"}

	billing := mustManager(t, Config{UserStore: userStore, SigningKey: shared, Issuer: "billing"})
	admin := mustManager(t, Config{UserStore: userStore, SigningKey: shared, Issuer: "admin"})

	billingToken := mustAccessToken(ctx, t, billing, user)
	if _, err := billing.ValidateToken(ctx, billingToken); err != nil {
		t.Fatalf("A service must accept its own token: %v", err)
	}
	if _, err := admin.ValidateToken(ctx, billingToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for a foreign issuer, got %v", err)
	}

	// A pinned issuer also rejects a token that carries no iss at all.
	anonymous := mustManager(t, Config{UserStore: userStore, SigningKey: shared})
	if _, err := billing.ValidateToken(ctx, mustAccessToken(ctx, t, anonymous, user)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for a missing issuer, got %v", err)
	}
}

// TestValidateToken_RejectsForeignAudience covers the aud half of F-03,
// including the string-vs-array shape that RFC 7519 section 4.1.3 permits (the
// GHSA-mh63-6h87-95cp type-confusion class).
func TestValidateToken_RejectsForeignAudience(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	shared := []byte("one-secret-rotated-through-the-deployment")
	ctx := context.Background()
	user := &storage.User{ID: "user123", Email: "test@example.com"}

	api := mustManager(t, Config{UserStore: userStore, SigningKey: shared, Issuer: "idp", Audience: []string{"api"}})
	jobs := mustManager(t, Config{UserStore: userStore, SigningKey: shared, Issuer: "idp", Audience: []string{"jobs"}})

	jobsToken := mustAccessToken(ctx, t, jobs, user)
	if _, err := jobs.ValidateToken(ctx, jobsToken); err != nil {
		t.Fatalf("A service must accept its own audience: %v", err)
	}
	if _, err := api.ValidateToken(ctx, jobsToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for a foreign audience, got %v", err)
	}

	// A token with no aud at all is rejected once an audience is configured.
	noAudience := mustManager(t, Config{UserStore: userStore, SigningKey: shared, Issuer: "idp"})
	if _, err := api.ValidateToken(ctx, mustAccessToken(ctx, t, noAudience, user)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for a missing audience, got %v", err)
	}

	now := time.Now()
	rawClaims := func(aud any) jwt.MapClaims {
		return jwt.MapClaims{
			"uid":  user.ID,
			"type": string(AccessToken),
			"iss":  "idp",
			"aud":  aud,
			"iat":  jwt.NewNumericDate(now),
			"nbf":  jwt.NewNumericDate(now),
			"exp":  jwt.NewNumericDate(now.Add(time.Hour)),
		}
	}
	if _, err := api.ValidateToken(ctx, mintRaw(t, jwt.SigningMethodHS256, shared, rawClaims("api"))); err != nil {
		t.Fatalf("A single-string aud naming us must be accepted: %v", err)
	}
	if _, err := api.ValidateToken(ctx, mintRaw(t, jwt.SigningMethodHS256, shared, rawClaims("jobs"))); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for a single-string foreign aud, got %v", err)
	}
}

// TestRevokeRefreshToken_PinsIssuerAndMethod covers the RevokeRefreshToken half
// of F-03: that path used a key function that checked nothing at all.
func TestRevokeRefreshToken_PinsIssuerAndMethod(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	shared := []byte("one-secret-rotated-through-the-deployment")
	ctx := context.Background()
	user := &storage.User{ID: "user123", Email: "test@example.com"}

	billing := mustManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: shared,
		Issuer:     "billing",
	})
	admin := mustManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: shared,
		Issuer:     "admin",
	})

	pair := mustPair(ctx, t, billing, user)
	if err := admin.RevokeRefreshToken(ctx, pair.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken revoking a foreign issuer's token, got %v", err)
	}
	if err := billing.RevokeRefreshToken(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("The minting service must be able to revoke its own token: %v", err)
	}
}

// customSigningMethod stands in for a jwt.SigningMethod registered outside this
// package: the key pairing cannot be inspected, so both halves must be supplied.
type customSigningMethod struct{}

func (customSigningMethod) Alg() string { return "CUSTOM" }

func (customSigningMethod) Sign(signingString string, key any) ([]byte, error) {
	return nil, errors.New("not used in these tests")
}

func (customSigningMethod) Verify(signingString string, sig []byte, key any) error {
	return errors.New("not used in these tests")
}

// TestNewTokenManager_KeyMethodPairing covers F-04 (CWE-1188): an asymmetric
// signing method with only a []byte SigningKey used to be accepted by the
// constructor and fail on the first token minted, in production.
func TestNewTokenManager_KeyMethodPairing(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	rsaKey := mustRSAKey(t, 2048)
	otherRSAKey := mustRSAKey(t, 2048)
	ecKey := mustECDSAKey(t, elliptic.P256())
	edKey := mustEd25519Key(t)

	tests := []struct {
		name string
		cfg  Config
		want bool // want a construction error
	}{
		{"HS256 with a shared secret", Config{SigningKey: []byte("test-secret-key")}, false},
		{"HS256 with no key at all", Config{}, true},
		{"HS256 with an asymmetric private key", Config{SigningKey: []byte("k"), PrivateKey: rsaKey}, true},
		{"HS256 with a public key", Config{SigningKey: []byte("k"), PublicKey: rsaKey.Public()}, true},
		{"RS256 with a []byte key", Config{SigningKey: []byte("not-an-rsa-key"), SigningMethod: jwt.SigningMethodRS256}, true},
		{"RS256 with no key at all", Config{SigningMethod: jwt.SigningMethodRS256}, true},
		{"RS256 with an RSA private key", Config{PrivateKey: rsaKey, SigningMethod: jwt.SigningMethodRS256}, false},
		{"PS256 with an RSA private key", Config{PrivateKey: rsaKey, SigningMethod: jwt.SigningMethodPS256}, false},
		{"RS256 with an undersized RSA key", Config{PrivateKey: mustRSAKey(t, 1024), SigningMethod: jwt.SigningMethodRS256}, true},
		{"RS256 with an unrelated public key", Config{PrivateKey: rsaKey, PublicKey: otherRSAKey.Public(), SigningMethod: jwt.SigningMethodRS256}, true},
		{"RS256 with its own public key", Config{PrivateKey: rsaKey, PublicKey: rsaKey.Public(), SigningMethod: jwt.SigningMethodRS256}, false},
		{"RS256 with an ECDSA key", Config{PrivateKey: ecKey, SigningMethod: jwt.SigningMethodRS256}, true},
		{"ES256 with a P-256 key", Config{PrivateKey: ecKey, SigningMethod: jwt.SigningMethodES256}, false},
		{"ES256 with a P-384 key", Config{PrivateKey: mustECDSAKey(t, elliptic.P384()), SigningMethod: jwt.SigningMethodES256}, true},
		{"ES384 with a P-384 key", Config{PrivateKey: mustECDSAKey(t, elliptic.P384()), SigningMethod: jwt.SigningMethodES384}, false},
		{"EdDSA with an ed25519 key", Config{PrivateKey: edKey, SigningMethod: jwt.SigningMethodEdDSA}, false},
		{"EdDSA with an RSA key", Config{PrivateKey: rsaKey, SigningMethod: jwt.SigningMethodEdDSA}, true},
		{"the none signing method", Config{SigningKey: []byte("k"), SigningMethod: jwt.SigningMethodNone}, true},
		{"an empty audience entry", Config{SigningKey: []byte("k"), Audience: []string{""}}, true},
		{"a custom method with a shared secret", Config{SigningKey: []byte("k"), SigningMethod: customSigningMethod{}}, false},
		{"a custom method with a full key pair", Config{PrivateKey: rsaKey, PublicKey: rsaKey.Public(), SigningMethod: customSigningMethod{}}, false},
		{"a custom method missing the public half", Config{PrivateKey: rsaKey, SigningMethod: customSigningMethod{}}, true},
		{"a custom method with no key at all", Config{SigningMethod: customSigningMethod{}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.UserStore = userStore

			tm, err := NewTokenManager(cfg)
			switch {
			case tc.want && err == nil:
				t.Fatal("Expected a construction error, got none")
			case tc.want && !errors.Is(err, ErrInvalidKeyConfig):
				t.Fatalf("Expected ErrInvalidKeyConfig, got %v", err)
			case !tc.want && err != nil:
				t.Fatalf("Expected no error, got %v", err)
			case !tc.want && tm == nil:
				t.Fatal("Expected a manager, got nil")
			}
		})
	}
}

// TestTokenManager_AsymmetricRoundTrip covers F-04: RS256 and ES256 were
// documented and could not mint a single token.
func TestTokenManager_AsymmetricRoundTrip(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	ctx := context.Background()
	user := &storage.User{ID: "user123", Email: "test@example.com"}

	tests := []struct {
		name   string
		method jwt.SigningMethod
		key    crypto.Signer
	}{
		{"RS256", jwt.SigningMethodRS256, mustRSAKey(t, 2048)},
		{"PS512", jwt.SigningMethodPS512, mustRSAKey(t, 2048)},
		{"ES256", jwt.SigningMethodES256, mustECDSAKey(t, elliptic.P256())},
		{"ES512", jwt.SigningMethodES512, mustECDSAKey(t, elliptic.P521())},
		{"EdDSA", jwt.SigningMethodEdDSA, mustEd25519Key(t)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tm := mustManager(t, Config{
				UserStore:     userStore,
				TokenStore:    storage.NewInMemoryTokenStore(),
				PrivateKey:    tc.key,
				SigningMethod: tc.method,
				Issuer:        "idp",
				Audience:      []string{"api"},
			})

			pair := mustPair(ctx, t, tm, user)
			claims, err := tm.ValidateAccessToken(ctx, pair.AccessToken)
			if err != nil {
				t.Fatalf("ValidateAccessToken: %v", err)
			}
			if claims.UserID != user.ID {
				t.Errorf("Expected UserID %s, got %s", user.ID, claims.UserID)
			}
			if _, refreshErr := tm.ValidateRefreshToken(ctx, pair.RefreshToken); refreshErr != nil {
				t.Fatalf("ValidateRefreshToken: %v", refreshErr)
			}

			header, _, _ := strings.Cut(pair.AccessToken, ".")
			decoded, err := base64.RawURLEncoding.DecodeString(header)
			if err != nil {
				t.Fatalf("Failed to decode the JOSE header: %v", err)
			}
			if !strings.Contains(string(decoded), tc.method.Alg()) {
				t.Errorf("Expected alg %s in the header, got %s", tc.method.Alg(), decoded)
			}
		})
	}
}

// TestValidateToken_RejectsAlgorithmConfusion covers the classic attack an
// asymmetric deployment is exposed to once F-04 makes one possible: the
// verification key is public, so an attacker signs HS256 with it and hopes the
// verifier picks the algorithm out of the token's own header.
func TestValidateToken_RejectsAlgorithmConfusion(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	rsaKey := mustRSAKey(t, 2048)
	tm := mustManager(t, Config{
		UserStore:     userStore,
		PrivateKey:    rsaKey,
		SigningMethod: jwt.SigningMethodRS256,
		Issuer:        "idp",
	})
	ctx := context.Background()

	now := time.Now()
	claims := jwt.MapClaims{
		"uid":  "attacker",
		"type": string(AccessToken),
		"iss":  "idp",
		"iat":  jwt.NewNumericDate(now),
		"nbf":  jwt.NewNumericDate(now),
		"exp":  jwt.NewNumericDate(now.Add(time.Hour)),
	}

	der, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	if _, err := tm.ValidateToken(ctx, mintRaw(t, jwt.SigningMethodHS256, publicPEM, claims)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for an HS256 token signed with the public key, got %v", err)
	}

	unsigned := mintRaw(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claims)
	if _, err := tm.ValidateToken(ctx, unsigned); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for an alg=none token, got %v", err)
	}

	hmacManager := mustManager(t, Config{UserStore: userStore, SigningKey: []byte("test-secret-key"), Issuer: "idp"})
	if _, err := hmacManager.ValidateToken(ctx, unsigned); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Expected ErrInvalidToken for an alg=none token, got %v", err)
	}
}

// TestGenerateToken_MetadataAllowlist covers F-21 (CWE-200): the whole of
// user.Metadata -- including an identity provider's raw claim set -- used to be
// copied into a token the browser holds and anyone who sees it can decode.
func TestGenerateToken_MetadataAllowlist(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	ctx := context.Background()
	signingKey := []byte("test-secret-key")

	user := &storage.User{
		ID:    "user123",
		Email: "test@example.com",
		Metadata: map[string]interface{}{
			"role": "admin",
			"raw_claims": map[string]interface{}{
				"national_id": "sensitive-idp-claim",
				"groups":      []string{"finance", "payroll"},
			},
		},
	}

	t.Run("no allow-list emits no metadata", func(t *testing.T) {
		tm := mustManager(t, Config{UserStore: userStore, SigningKey: signingKey})
		token := mustAccessToken(ctx, t, tm, user)

		claims, err := tm.ValidateToken(ctx, token)
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if len(claims.Metadata) != 0 {
			t.Errorf("Expected no metadata, got %v", claims.Metadata)
		}
		assertPayloadExcludes(t, token, "raw_claims", "national_id", "payroll", "admin")
	})

	t.Run("only allow-listed keys are copied", func(t *testing.T) {
		tm := mustManager(t, Config{
			UserStore:         userStore,
			SigningKey:        signingKey,
			MetadataAllowlist: []string{"role", "never_present"},
		})
		token := mustAccessToken(ctx, t, tm, user)

		claims, err := tm.ValidateToken(ctx, token)
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if len(claims.Metadata) != 1 {
			t.Fatalf("Expected exactly one metadata key, got %v", claims.Metadata)
		}
		if claims.Metadata["role"] != "admin" {
			t.Errorf("Expected role 'admin', got %v", claims.Metadata["role"])
		}
		assertPayloadExcludes(t, token, "raw_claims", "national_id", "payroll")
	})

	t.Run("a mutated user map cannot reach an issued token", func(t *testing.T) {
		tm := mustManager(t, Config{
			UserStore:         userStore,
			SigningKey:        signingKey,
			MetadataAllowlist: []string{"role"},
		})
		empty := &storage.User{ID: "user123", Metadata: map[string]interface{}{"raw_claims": "leak"}}
		token := mustAccessToken(ctx, t, tm, empty)

		claims, err := tm.ValidateToken(ctx, token)
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if claims.Metadata != nil {
			t.Errorf("Expected no metadata claim, got %v", claims.Metadata)
		}
		assertPayloadExcludes(t, token, "leak", "metadata")
	})
}

// assertPayloadExcludes decodes the token's payload the way anyone holding the
// token can, and fails if a forbidden substring survived into it.
func assertPayloadExcludes(t *testing.T, token string, forbidden ...string) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 parts in JWT, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode the payload: %v", err)
	}
	for _, needle := range forbidden {
		if strings.Contains(string(payload), needle) {
			t.Errorf("Payload must not contain %q, got %s", needle, payload)
		}
	}
}
