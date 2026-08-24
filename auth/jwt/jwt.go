// Package jwt provides JSON Web Token authentication with access and refresh tokens.
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/meysam81/go-auth/storage"
)

// minRSAKeyBits is the smallest RSA modulus RFC 7518 section 3.3 permits for the
// RS* and PS* families. Enforced at construction (F-04) because asymmetric
// signing is only reachable from this release onwards, so there is no existing
// deployment with a weaker key to keep compiling.
const minRSAKeyBits = 2048

var (
	// ErrInvalidToken is returned when a token is invalid or expired.
	//
	// The underlying cause is deliberately not wrapped: an error that lets a
	// caller distinguish "expired" from "wrong issuer" from "bad signature"
	// turns the verifier into an oracle for an attacker probing a forged token.
	ErrInvalidToken = errors.New("invalid or expired token")

	// ErrTokenRevoked is returned when a refresh token has been revoked.
	ErrTokenRevoked = errors.New("token has been revoked")

	// ErrUnexpectedTokenType is returned when a token is presented in a role it
	// was not minted for: a refresh token used as a bearer credential, or an
	// access token handed to the refresh or revoke path (F-02, CWE-863).
	//
	// It wraps ErrInvalidToken, so code written against v1.1 that tested for
	// ErrInvalidToken with errors.Is keeps behaving as before.
	ErrUnexpectedTokenType = fmt.Errorf("%w: unexpected token type", ErrInvalidToken)

	// ErrInvalidKeyConfig is returned by NewTokenManager when the configured key
	// material does not match the configured signing method (F-04, CWE-1188).
	ErrInvalidKeyConfig = errors.New("invalid signing key configuration")

	// ErrUserStoreRequired is returned by NewTokenManager when Config.UserStore
	// is nil.
	ErrUserStoreRequired = errors.New("user store is required")

	// ErrTokenStoreRequired is returned by the revocation methods when the
	// manager was built without a storage.TokenStore.
	ErrTokenStoreRequired = errors.New("token store not configured")
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
	signKey         any
	verifyKey       any
	signingMethod   jwt.SigningMethod
	issuer          string
	audience        []string
	metadataAllow   map[string]struct{}
	parserOptions   []jwt.ParserOption
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// Config configures the JWT token manager.
type Config struct {
	// UserStore resolves the user behind a refresh token.
	//
	// Deprecated: v2 removes the identity store from this package's
	// dependencies; RefreshAccessToken will mint from the verified refresh-token
	// claims instead of reloading a row. The field remains required in v1.
	UserStore storage.UserStore

	TokenStore storage.TokenStore // Optional: for refresh token revocation

	// SigningKey is the shared secret for the HMAC family (HS256/384/512).
	//
	// It cannot carry an asymmetric private key: golang-jwt type-asserts
	// *rsa.PrivateKey or *ecdsa.PrivateKey when signing, so a []byte here with
	// an RS*/ES*/PS* method is a configuration error and NewTokenManager now
	// rejects it rather than failing on the first token minted (F-04). Use
	// PrivateKey for those. RFC 7518 section 3.2 requires a secret at least as
	// long as the hash output: 32 bytes for HS256.
	SigningKey []byte

	// PrivateKey is the signer for an asymmetric SigningMethod (F-04).
	//
	// golang-jwt asserts the concrete key type when signing, so this must be an
	// *rsa.PrivateKey for RS*/PS*, an *ecdsa.PrivateKey on the curve matching
	// ES*, or any crypto.Signer with an ed25519 public key for EdDSA. An
	// external signer (HSM, KMS) is therefore only usable with EdDSA today.
	PrivateKey crypto.Signer

	// PublicKey verifies tokens when SigningMethod is asymmetric. Optional: it
	// defaults to PrivateKey.Public(). When set it must match PrivateKey, which
	// is checked at construction so a mismatched pair cannot mint tokens the
	// same process then rejects.
	PublicKey crypto.PublicKey

	SigningMethod jwt.SigningMethod // Optional: defaults to HS256

	// Issuer is written to the iss claim and, when non-empty, REQUIRED at
	// validation (F-03). Two services sharing one signing secret accept each
	// other's tokens without it.
	Issuer string

	// Audience is written to the aud claim and, when non-empty, required at
	// validation: the token's aud must carry at least one of these values, per
	// RFC 7519 section 4.1.3 (F-03).
	Audience []string

	// MetadataAllowlist names the storage.User.Metadata keys that may be copied
	// into a token's metadata claim (F-21, CWE-200).
	//
	// Empty means no metadata is emitted at all. A JWT is base64, not
	// encrypted: copying an identity provider's raw claim set into it hands the
	// browser every group membership and internal identifier the directory
	// happened to release, and charges it to every subsequent request's header
	// budget.
	MetadataAllowlist []string

	AccessTokenTTL  time.Duration // Optional: defaults to 15 minutes
	RefreshTokenTTL time.Duration // Optional: defaults to 7 days
}

// NewTokenManager creates a new JWT token manager.
//
// It fails closed on a key/method mismatch (F-04): an asymmetric SigningMethod
// carrying only a []byte SigningKey is a configuration error that used to
// surface as a signing failure in production, and is now reported here.
func NewTokenManager(cfg Config) (*TokenManager, error) {
	if cfg.UserStore == nil {
		return nil, ErrUserStoreRequired
	}

	signingMethod := cfg.SigningMethod
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodHS256
	}

	signKey, verifyKey, err := resolveKeys(cfg, signingMethod)
	if err != nil {
		return nil, err
	}

	audience := make([]string, 0, len(cfg.Audience))
	for _, aud := range cfg.Audience {
		if aud == "" {
			return nil, fmt.Errorf("%w: audience entries must be non-empty", ErrInvalidKeyConfig)
		}
		audience = append(audience, aud)
	}

	accessTTL := cfg.AccessTokenTTL
	if accessTTL == 0 {
		accessTTL = 15 * time.Minute
	}

	refreshTTL := cfg.RefreshTokenTTL
	if refreshTTL == 0 {
		refreshTTL = 7 * 24 * time.Hour
	}

	metadataAllow := make(map[string]struct{}, len(cfg.MetadataAllowlist))
	for _, key := range cfg.MetadataAllowlist {
		metadataAllow[key] = struct{}{}
	}

	// The alg pin is applied at the parser as well as in the key function so a
	// token claiming "none", or an HS256 token forged against a published RSA
	// public key, is rejected before any key material is selected.
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{signingMethod.Alg()}),
		jwt.WithExpirationRequired(),
	}
	if cfg.Issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(cfg.Issuer))
	}
	if len(audience) > 0 {
		parserOptions = append(parserOptions, jwt.WithAudience(audience...))
	}

	return &TokenManager{
		userStore:       cfg.UserStore,
		tokenStore:      cfg.TokenStore,
		signKey:         signKey,
		verifyKey:       verifyKey,
		signingMethod:   signingMethod,
		issuer:          cfg.Issuer,
		audience:        audience,
		metadataAllow:   metadataAllow,
		parserOptions:   parserOptions,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}, nil
}

// resolveKeys pairs the configured key material with the signing method and
// reports a mismatch as a construction error (F-04, CWE-1188).
func resolveKeys(cfg Config, method jwt.SigningMethod) (signKey, verifyKey any, err error) {
	// RFC 7519 section 6 "unsecured" tokens carry no signature at all, which is
	// the alg:none forgery this library exists to prevent. The method's concrete
	// type is unexported by golang-jwt, so it is matched by name.
	if method.Alg() == jwt.SigningMethodNone.Alg() {
		return nil, nil, fmt.Errorf("%w: the none signing method leaves tokens unauthenticated", ErrInvalidKeyConfig)
	}

	switch m := method.(type) {
	case *jwt.SigningMethodHMAC:
		return hmacKeys(cfg)
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		return rsaKeys(cfg)
	case *jwt.SigningMethodECDSA:
		return ecdsaKeys(cfg, m)
	case *jwt.SigningMethodEd25519:
		return ed25519Keys(cfg)
	default:
		return customKeys(cfg)
	}
}

func hmacKeys(cfg Config) (signKey, verifyKey any, err error) {
	if cfg.PrivateKey != nil || cfg.PublicKey != nil {
		return nil, nil, fmt.Errorf("%w: an HMAC signing method takes SigningKey; PrivateKey and PublicKey are for asymmetric methods", ErrInvalidKeyConfig)
	}
	if len(cfg.SigningKey) == 0 {
		return nil, nil, fmt.Errorf("%w: signing key is required", ErrInvalidKeyConfig)
	}
	return cfg.SigningKey, cfg.SigningKey, nil
}

func rsaKeys(cfg Config) (signKey, verifyKey any, err error) {
	priv, err := asymmetricSigner[*rsa.PrivateKey](cfg, "*rsa.PrivateKey")
	if err != nil {
		return nil, nil, err
	}
	if bits := priv.N.BitLen(); bits < minRSAKeyBits {
		return nil, nil, fmt.Errorf("%w: RSA key is %d bits, RFC 7518 section 3.3 requires at least %d", ErrInvalidKeyConfig, bits, minRSAKeyBits)
	}
	pub, ok := priv.Public().(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: RSA private key yielded a %T public key", ErrInvalidKeyConfig, priv.Public())
	}
	if err := matchConfiguredPublicKey(cfg, pub); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func ecdsaKeys(cfg Config, method *jwt.SigningMethodECDSA) (signKey, verifyKey any, err error) {
	priv, err := asymmetricSigner[*ecdsa.PrivateKey](cfg, "*ecdsa.PrivateKey")
	if err != nil {
		return nil, nil, err
	}
	// golang-jwt compares the curve size against the method only after signing,
	// so an ES256 manager holding a P-384 key would fail at the first mint.
	if bits := priv.Curve.Params().BitSize; bits != method.CurveBits {
		return nil, nil, fmt.Errorf("%w: %s requires a %d-bit curve, got %d", ErrInvalidKeyConfig, method.Alg(), method.CurveBits, bits)
	}
	pub, ok := priv.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: ECDSA private key yielded a %T public key", ErrInvalidKeyConfig, priv.Public())
	}
	if err := matchConfiguredPublicKey(cfg, pub); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func ed25519Keys(cfg Config) (signKey, verifyKey any, err error) {
	if err := requireAsymmetricConfig(cfg, "an ed25519 crypto.Signer"); err != nil {
		return nil, nil, err
	}
	// EdDSA is the one family golang-jwt signs through the crypto.Signer
	// interface, so an external signer (HSM, KMS) works here.
	pub, ok := cfg.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: EdDSA requires a signer with an ed25519 public key, got %T", ErrInvalidKeyConfig, cfg.PrivateKey.Public())
	}
	if err := matchConfiguredPublicKey(cfg, pub); err != nil {
		return nil, nil, err
	}
	return cfg.PrivateKey, pub, nil
}

// customKeys covers a SigningMethod registered outside this package. The pairing
// cannot be checked, so both halves must be supplied explicitly.
func customKeys(cfg Config) (signKey, verifyKey any, err error) {
	if cfg.PrivateKey != nil {
		if cfg.PublicKey == nil {
			return nil, nil, fmt.Errorf("%w: a custom asymmetric signing method requires PublicKey to verify with", ErrInvalidKeyConfig)
		}
		return cfg.PrivateKey, cfg.PublicKey, nil
	}
	if len(cfg.SigningKey) == 0 {
		return nil, nil, fmt.Errorf("%w: signing key is required", ErrInvalidKeyConfig)
	}
	return cfg.SigningKey, cfg.SigningKey, nil
}

// asymmetricSigner asserts the concrete private-key type golang-jwt's Sign
// requires for the configured family.
func asymmetricSigner[T crypto.Signer](cfg Config, want string) (T, error) {
	var zero T
	if err := requireAsymmetricConfig(cfg, want); err != nil {
		return zero, err
	}
	key, ok := cfg.PrivateKey.(T)
	if !ok {
		return zero, fmt.Errorf("%w: this signing method requires a %s, got %T", ErrInvalidKeyConfig, want, cfg.PrivateKey)
	}
	return key, nil
}

func requireAsymmetricConfig(cfg Config, want string) error {
	if len(cfg.SigningKey) > 0 {
		return fmt.Errorf("%w: SigningKey ([]byte) cannot carry an asymmetric key; set PrivateKey to %s", ErrInvalidKeyConfig, want)
	}
	if cfg.PrivateKey == nil {
		return fmt.Errorf("%w: this signing method requires PrivateKey (%s)", ErrInvalidKeyConfig, want)
	}
	return nil
}

// matchConfiguredPublicKey rejects a PublicKey that does not belong to the
// configured PrivateKey, which would otherwise mint tokens this same manager
// refuses to verify.
func matchConfiguredPublicKey(cfg Config, derived crypto.PublicKey) error {
	if cfg.PublicKey == nil {
		return nil
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := derived.(equaler)
	if !ok {
		return fmt.Errorf("%w: %T cannot be compared against the configured PublicKey", ErrInvalidKeyConfig, derived)
	}
	if !pub.Equal(cfg.PublicKey) {
		return fmt.Errorf("%w: PublicKey does not match PrivateKey", ErrInvalidKeyConfig)
	}
	return nil
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

// ValidateToken validates a bearer credential and returns its claims.
//
// It is equivalent to ValidateAccessToken and is kept so v1 callers keep
// compiling. Behavior changed in this release (F-02, CWE-863): a refresh token
// is no longer accepted here. A refresh token outlives an access token by orders
// of magnitude and is the credential most likely to be at rest in client
// storage; accepting it as a bearer token authorized it against every route the
// middleware guards. Code that deliberately presented a refresh token here was
// exploiting that defect and must call RefreshAccessToken or
// ValidateRefreshToken.
func (m *TokenManager) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	return m.ValidateAccessToken(ctx, tokenString)
}

// ValidateAccessToken validates a token and requires it to be an access token.
// It is the entry point a bearer-token middleware must use.
func (m *TokenManager) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return m.validate(ctx, tokenString, AccessToken)
}

// ValidateRefreshToken validates a token, requires it to be a refresh token, and
// consults the token store for revocation when one is configured.
func (m *TokenManager) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	return m.validate(ctx, tokenString, RefreshToken)
}

// validate parses a token under the pinned alg, issuer and audience, then
// requires it to be of the expected type.
func (m *TokenManager) validate(ctx context.Context, tokenString string, want TokenType) (*Claims, error) {
	claims, err := m.parseClaims(tokenString, want)
	if err != nil {
		return nil, err
	}

	if want == RefreshToken && m.tokenStore != nil && claims.TokenID != "" {
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

// parseClaims verifies the signature, the pinned signing method, iss and aud
// (F-03, CWE-347), and the token type (F-02, CWE-863).
func (m *TokenManager) parseClaims(tokenString string, want TokenType) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, m.keyFunc, m.parserOptions...)
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

	if claims.Type != want {
		return nil, ErrUnexpectedTokenType
	}

	return claims, nil
}

// keyFunc pins the signing method before handing over any key material, so a
// token whose header names a different algorithm can never be verified against
// the wrong key (the algorithm-confusion class).
func (m *TokenManager) keyFunc(token *jwt.Token) (any, error) {
	if token.Method != m.signingMethod {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return m.verifyKey, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token.
func (m *TokenManager) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	// Validate refresh token on the refresh path: an access token presented here
	// is rejected as the wrong type (F-02).
	claims, err := m.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
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
//
// The token is parsed under the same signing-method, issuer and audience pins as
// ValidateRefreshToken (F-03): this path used to accept a bare key function that
// checked no algorithm at all, so a token from another issuer sharing the secret
// could name a jti here.
func (m *TokenManager) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	if m.tokenStore == nil {
		return ErrTokenStoreRequired
	}

	claims, err := m.parseClaims(refreshTokenString, RefreshToken)
	if err != nil {
		return err
	}

	if claims.TokenID == "" {
		return ErrInvalidToken
	}

	return m.tokenStore.RevokeRefreshToken(ctx, claims.TokenID)
}

// RevokeAllUserTokens revokes all refresh tokens for a user.
func (m *TokenManager) RevokeAllUserTokens(ctx context.Context, userID string) error {
	if m.tokenStore == nil {
		return ErrTokenStoreRequired
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
		Metadata: m.allowedMetadata(user.Metadata),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   user.ID,
			Audience:  m.audienceClaim(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(m.signingMethod, claims)
	signed, err := token.SignedString(m.signKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return signed, nil
}

// audienceClaim returns a copy so a caller holding the returned claims cannot
// reach back into the manager's configuration.
func (m *TokenManager) audienceClaim() jwt.ClaimStrings {
	if len(m.audience) == 0 {
		return nil
	}
	aud := make(jwt.ClaimStrings, len(m.audience))
	copy(aud, m.audience)
	return aud
}

// allowedMetadata copies only the allow-listed keys of a user's metadata into a
// token (F-21, CWE-200). With no allow-list, nothing is copied.
func (m *TokenManager) allowedMetadata(metadata map[string]interface{}) map[string]interface{} {
	if len(m.metadataAllow) == 0 || len(metadata) == 0 {
		return nil
	}

	allowed := make(map[string]interface{}, len(m.metadataAllow))
	for key := range m.metadataAllow {
		if value, ok := metadata[key]; ok {
			allowed[key] = value
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

// generateTokenID generates a cryptographically secure token ID.
func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseUnverified parses a token without verifying the signature (for debugging).
// WARNING: Do not use for authentication - this is unsafe!
func ParseUnverified(tokenString string) (*Claims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}
