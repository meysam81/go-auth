// Package jwt provides JSON Web Token authentication with access and refresh tokens.
package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/meysam81/go-auth/storage"
)

var (
	// ErrInvalidToken is returned when a token is invalid or expired.
	ErrInvalidToken = errors.New("invalid or expired token")

	// ErrTokenRevoked is returned when a refresh token has been revoked.
	ErrTokenRevoked = errors.New("token has been revoked")
)

// TokenType represents the type of JWT token.
type TokenType string

const (
	// AccessToken is a short-lived token for API authentication.
	AccessToken TokenType = "access"

	// RefreshToken is a long-lived token for obtaining new access tokens.
	RefreshToken TokenType = "refresh"
)

// Claims represents JWT claims with standard and custom fields.
type Claims struct {
	UserID   string                 `json:"uid"`
	Email    string                 `json:"email,omitempty"`
	Provider string                 `json:"provider,omitempty"`
	Type     TokenType              `json:"type"`
	TokenID  string                 `json:"jti,omitempty"` // JWT ID for refresh tokens
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	jwt.RegisteredClaims
}

// TokenManager handles JWT creation, validation, and refresh.
type TokenManager struct {
	userStore       storage.UserStore
	tokenStore      storage.TokenStore
	signingKey      []byte
	signingMethod   jwt.SigningMethod
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// Config configures the JWT token manager.
type Config struct {
	UserStore       storage.UserStore
	TokenStore      storage.TokenStore // Optional: for refresh token revocation
	SigningKey      []byte             // Secret key for HS256 or private key for RS256
	SigningMethod   jwt.SigningMethod  // Optional: defaults to HS256
	Issuer          string             // Optional: token issuer
	AccessTokenTTL  time.Duration      // Optional: defaults to 15 minutes
	RefreshTokenTTL time.Duration      // Optional: defaults to 7 days
}

// NewTokenManager creates a new JWT token manager.
func NewTokenManager(cfg Config) (*TokenManager, error) {
	if cfg.UserStore == nil {
		return nil, errors.New("user store is required")
	}
	if len(cfg.SigningKey) == 0 {
		return nil, errors.New("signing key is required")
	}

	signingMethod := cfg.SigningMethod
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodHS256
	}

	accessTTL := cfg.AccessTokenTTL
	if accessTTL == 0 {
		accessTTL = 15 * time.Minute
	}

	refreshTTL := cfg.RefreshTokenTTL
	if refreshTTL == 0 {
		refreshTTL = 7 * 24 * time.Hour
	}

	return &TokenManager{
		userStore:       cfg.UserStore,
		tokenStore:      cfg.TokenStore,
		signingKey:      cfg.SigningKey,
		signingMethod:   signingMethod,
		issuer:          cfg.Issuer,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}, nil
}

// TokenPair represents an access token and refresh token pair.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"` // Access token TTL in seconds
	ExpiresAt    time.Time `json:"expires_at"`
}

// GenerateTokenPair creates a new access and refresh token pair for a user.
func (m *TokenManager) GenerateTokenPair(ctx context.Context, user *storage.User) (*TokenPair, error) {
	now := time.Now()

	// Generate access token
	accessToken, err := m.generateToken(user, AccessToken, "", now, m.accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token with unique ID
	tokenID, err := generateTokenID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	refreshToken, err := m.generateToken(user, RefreshToken, tokenID, now, m.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token if token store is available
	if m.tokenStore != nil {
		expiresAt := now.Add(m.refreshTokenTTL)
		if err := m.tokenStore.StoreRefreshToken(ctx, user.ID, tokenID, expiresAt); err != nil {
			return nil, fmt.Errorf("failed to store refresh token: %w", err)
		}
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(m.accessTokenTTL.Seconds()),
		ExpiresAt:    now.Add(m.accessTokenTTL),
	}, nil
}

// GenerateAccessToken creates only an access token (no refresh token).
func (m *TokenManager) GenerateAccessToken(ctx context.Context, user *storage.User) (string, error) {
	return m.generateToken(user, AccessToken, "", time.Now(), m.accessTokenTTL)
}

// ValidateToken validates a JWT token and returns its claims.
func (m *TokenManager) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if token.Method != m.signingMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.signingKey, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// For refresh tokens, check revocation status
	if claims.Type == RefreshToken && m.tokenStore != nil && claims.TokenID != "" {
		userID, err := m.tokenStore.ValidateRefreshToken(ctx, claims.TokenID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrTokenRevoked
			}
			return nil, fmt.Errorf("failed to validate refresh token: %w", err)
		}
		if userID != claims.UserID {
			return nil, ErrInvalidToken
		}
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token.
func (m *TokenManager) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := m.ValidateToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
	}

	if claims.Type != RefreshToken {
		return nil, ErrInvalidToken
	}

	// Get user
	user, err := m.userStore.GetUserByID(ctx, claims.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new access token
	now := time.Now()
	accessToken, err := m.generateToken(user, AccessToken, "", now, m.accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(m.accessTokenTTL.Seconds()),
		ExpiresAt:   now.Add(m.accessTokenTTL),
	}, nil
}

// RevokeRefreshToken revokes a specific refresh token.
func (m *TokenManager) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	if m.tokenStore == nil {
		return errors.New("token store not configured")
	}

	claims, err := jwt.ParseWithClaims(refreshTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return m.signingKey, nil
	})

	if err != nil {
		return ErrInvalidToken
	}

	claimsData, ok := claims.Claims.(*Claims)
	if !ok || claimsData.TokenID == "" {
		return ErrInvalidToken
	}

	return m.tokenStore.RevokeRefreshToken(ctx, claimsData.TokenID)
}

// RevokeAllUserTokens revokes all refresh tokens for a user.
func (m *TokenManager) RevokeAllUserTokens(ctx context.Context, userID string) error {
	if m.tokenStore == nil {
		return errors.New("token store not configured")
	}

	return m.tokenStore.RevokeAllUserTokens(ctx, userID)
}

// generateToken creates a signed JWT token.
func (m *TokenManager) generateToken(user *storage.User, tokenType TokenType, tokenID string, now time.Time, ttl time.Duration) (string, error) {
	expiresAt := now.Add(ttl)

	claims := &Claims{
		UserID:   user.ID,
		Email:    user.Email,
		Provider: user.Provider,
		Type:     tokenType,
		TokenID:  tokenID,
		Metadata: user.Metadata,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(m.signingMethod, claims)
	return token.SignedString(m.signingKey)
}

// generateTokenID generates a cryptographically secure token ID.
func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseUnverified parses a token without verifying the signature (for debugging).
// WARNING: Do not use for authentication - this is unsafe!
func ParseUnverified(tokenString string) (*Claims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}
