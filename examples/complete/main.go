// Package main demonstrates a complete authentication system using go-auth.
//
// This example includes:
//   - Basic authentication (username/password)
//   - JWT tokens (access + refresh)
//   - TOTP two-factor authentication
//   - WebAuthn/Passkeys
//   - Google SSO (OAuth2/OIDC)
//   - Password reset flow
//   - Session management
//   - Audit logging with stdlib log/slog
//   - PostgreSQL storage implementations
//
// Run with: go run main.go
// For in-memory mode (no PostgreSQL): go run main.go -memory
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/lib/pq"
	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/auth/jwt"
	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"github.com/meysam81/go-auth/auth/totp"
	"github.com/meysam81/go-auth/auth/webauthn"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/provider"
	"github.com/meysam81/go-auth/session"
	"github.com/meysam81/go-auth/storage"
)

// =============================================================================
// PostgreSQL Storage Implementations
// =============================================================================

// PostgresUserStore implements storage.UserStore for PostgreSQL.
type PostgresUserStore struct {
	db *sql.DB
}

func NewPostgresUserStore(db *sql.DB) *PostgresUserStore {
	return &PostgresUserStore{db: db}
}

func (s *PostgresUserStore) CreateUser(ctx context.Context, user *storage.User) error {
	metadata, _ := json.Marshal(user.Metadata)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, email_verified, username, name, provider, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		user.ID, user.Email, user.EmailVerified, user.Username, user.Name, user.Provider, metadata, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (s *PostgresUserStore) GetUserByID(ctx context.Context, id string) (*storage.User, error) {
	user := &storage.User{}
	var metadata []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, email_verified, username, name, provider, metadata, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.Username, &user.Name, &user.Provider, &metadata, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(metadata, &user.Metadata)
	return user, nil
}

func (s *PostgresUserStore) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	user := &storage.User{}
	var metadata []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, email_verified, username, name, provider, metadata, created_at, updated_at
		 FROM users WHERE email = $1`, email,
	).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.Username, &user.Name, &user.Provider, &metadata, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(metadata, &user.Metadata)
	return user, nil
}

func (s *PostgresUserStore) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	user := &storage.User{}
	var metadata []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, email_verified, username, name, provider, metadata, created_at, updated_at
		 FROM users WHERE username = $1`, username,
	).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.Username, &user.Name, &user.Provider, &metadata, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(metadata, &user.Metadata)
	return user, nil
}

func (s *PostgresUserStore) UpdateUser(ctx context.Context, user *storage.User) error {
	metadata, _ := json.Marshal(user.Metadata)
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = $2, email_verified = $3, username = $4, name = $5, provider = $6, metadata = $7, updated_at = $8
		 WHERE id = $1`,
		user.ID, user.Email, user.EmailVerified, user.Username, user.Name, user.Provider, metadata, time.Now(),
	)
	return err
}

func (s *PostgresUserStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// PostgresCredentialStore implements storage.CredentialStore for PostgreSQL.
type PostgresCredentialStore struct {
	db *sql.DB
}

func NewPostgresCredentialStore(db *sql.DB) *PostgresCredentialStore {
	return &PostgresCredentialStore{db: db}
}

func (s *PostgresCredentialStore) StorePasswordHash(ctx context.Context, userID string, hash []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO password_hashes (user_id, hash) VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE SET hash = $2, updated_at = NOW()`,
		userID, hash,
	)
	return err
}

func (s *PostgresCredentialStore) GetPasswordHash(ctx context.Context, userID string) ([]byte, error) {
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM password_hashes WHERE user_id = $1`, userID).Scan(&hash)
	if err == sql.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return hash, err
}

func (s *PostgresCredentialStore) StoreWebAuthnCredential(ctx context.Context, userID string, cred *storage.WebAuthnCredential) error {
	metadata, _ := json.Marshal(cred.Metadata)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, public_key, attestation_type, aaguid, sign_count, transports, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		cred.ID, userID, cred.PublicKey, cred.AttestationType, cred.AAGUID, cred.SignCount, pq.Array(cred.Transports), metadata, cred.CreatedAt, cred.UpdatedAt,
	)
	return err
}

func (s *PostgresCredentialStore) GetWebAuthnCredentials(ctx context.Context, userID string) ([]*storage.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, public_key, attestation_type, aaguid, sign_count, transports, metadata, created_at, updated_at
		 FROM webauthn_credentials WHERE user_id = $1`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var credentials []*storage.WebAuthnCredential
	for rows.Next() {
		cred := &storage.WebAuthnCredential{UserID: userID}
		var metadata []byte
		var transports []string
		err := rows.Scan(&cred.ID, &cred.PublicKey, &cred.AttestationType, &cred.AAGUID, &cred.SignCount, pq.Array(&transports), &metadata, &cred.CreatedAt, &cred.UpdatedAt)
		if err != nil {
			return nil, err
		}
		cred.Transports = transports
		json.Unmarshal(metadata, &cred.Metadata)
		credentials = append(credentials, cred)
	}
	return credentials, rows.Err()
}

func (s *PostgresCredentialStore) UpdateWebAuthnCredential(ctx context.Context, cred *storage.WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = $2, updated_at = NOW() WHERE id = $1`,
		cred.ID, cred.SignCount,
	)
	return err
}

func (s *PostgresCredentialStore) DeleteWebAuthnCredential(ctx context.Context, credentialID []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id = $1`, credentialID)
	return err
}

func (s *PostgresCredentialStore) StorePasswordResetToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)`,
		token, userID, expiresAt,
	)
	return err
}

func (s *PostgresCredentialStore) ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	var userID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM password_reset_tokens WHERE token = $1 AND expires_at > NOW()`, token,
	).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", storage.ErrNotFound
	}
	return userID, err
}

func (s *PostgresCredentialStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token = $1`, token)
	return err
}

func (s *PostgresCredentialStore) StoreEmailVerificationToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)`,
		token, userID, expiresAt,
	)
	return err
}

func (s *PostgresCredentialStore) ValidateEmailVerificationToken(ctx context.Context, token string) (string, error) {
	var userID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM email_verification_tokens WHERE token = $1 AND expires_at > NOW()`, token,
	).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", storage.ErrNotFound
	}
	return userID, err
}

func (s *PostgresCredentialStore) DeleteEmailVerificationToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM email_verification_tokens WHERE token = $1`, token)
	return err
}

func (s *PostgresCredentialStore) StoreTOTPSecret(ctx context.Context, userID string, secret string, backupCodes []string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO totp_secrets (user_id, secret, backup_codes) VALUES ($1, $2, $3)
		 ON CONFLICT (user_id) DO UPDATE SET secret = $2, backup_codes = $3, updated_at = NOW()`,
		userID, secret, pq.Array(backupCodes),
	)
	return err
}

func (s *PostgresCredentialStore) GetTOTPSecret(ctx context.Context, userID string) (string, []string, error) {
	var secret string
	var backupCodes []string
	err := s.db.QueryRowContext(ctx,
		`SELECT secret, backup_codes FROM totp_secrets WHERE user_id = $1`, userID,
	).Scan(&secret, pq.Array(&backupCodes))
	if err == sql.ErrNoRows {
		return "", nil, storage.ErrNotFound
	}
	return secret, backupCodes, err
}

func (s *PostgresCredentialStore) DeleteTOTPSecret(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_secrets WHERE user_id = $1`, userID)
	return err
}

func (s *PostgresCredentialStore) UseBackupCode(ctx context.Context, userID string, code string) error {
	_, backupCodes, err := s.GetTOTPSecret(ctx, userID)
	if err != nil {
		return err
	}
	newCodes := make([]string, 0, len(backupCodes)-1)
	found := false
	for _, c := range backupCodes {
		if strings.EqualFold(c, code) {
			found = true
			continue
		}
		newCodes = append(newCodes, c)
	}
	if !found {
		return errors.New("backup code not found")
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE totp_secrets SET backup_codes = $2, updated_at = NOW() WHERE user_id = $1`,
		userID, pq.Array(newCodes),
	)
	return err
}

// PostgresSessionStore implements storage.SessionStore for PostgreSQL.
type PostgresSessionStore struct {
	db *sql.DB
}

func NewPostgresSessionStore(db *sql.DB) *PostgresSessionStore {
	return &PostgresSessionStore{db: db}
}

func (s *PostgresSessionStore) CreateSession(ctx context.Context, sessionID string, data *storage.SessionData, ttl time.Duration) error {
	metadata, _ := json.Marshal(data.Metadata)
	expiresAt := time.Now().Add(ttl)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, email, provider, metadata, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sessionID, data.UserID, data.Email, data.Provider, metadata, data.CreatedAt, expiresAt,
	)
	return err
}

func (s *PostgresSessionStore) GetSession(ctx context.Context, sessionID string) (*storage.SessionData, error) {
	data := &storage.SessionData{}
	var metadata []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, email, provider, metadata, created_at, expires_at
		 FROM sessions WHERE id = $1 AND expires_at > NOW()`, sessionID,
	).Scan(&data.UserID, &data.Email, &data.Provider, &metadata, &data.CreatedAt, &data.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(metadata, &data.Metadata)
	return data, nil
}

func (s *PostgresSessionStore) UpdateSession(ctx context.Context, sessionID string, data *storage.SessionData, ttl time.Duration) error {
	metadata, _ := json.Marshal(data.Metadata)
	expiresAt := time.Now().Add(ttl)
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET email = $2, provider = $3, metadata = $4, expires_at = $5 WHERE id = $1`,
		sessionID, data.Email, data.Provider, metadata, expiresAt,
	)
	return err
}

func (s *PostgresSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}

func (s *PostgresSessionStore) RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	expiresAt := time.Now().Add(ttl)
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at = $2 WHERE id = $1`, sessionID, expiresAt)
	return err
}

// PostgresTokenStore implements storage.TokenStore for PostgreSQL.
type PostgresTokenStore struct {
	db *sql.DB
}

func NewPostgresTokenStore(db *sql.DB) *PostgresTokenStore {
	return &PostgresTokenStore{db: db}
}

func (s *PostgresTokenStore) StoreRefreshToken(ctx context.Context, userID string, tokenID string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (token_id, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenID, userID, expiresAt,
	)
	return err
}

func (s *PostgresTokenStore) ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) {
	var userID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM refresh_tokens WHERE token_id = $1 AND expires_at > NOW() AND revoked = FALSE`, tokenID,
	).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", storage.ErrNotFound
	}
	return userID, err
}

func (s *PostgresTokenStore) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = TRUE WHERE token_id = $1`, tokenID)
	return err
}

func (s *PostgresTokenStore) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1`, userID)
	return err
}

// PostgresOIDCStateStore implements storage.OIDCStateStore for PostgreSQL.
type PostgresOIDCStateStore struct {
	db *sql.DB
}

func NewPostgresOIDCStateStore(db *sql.DB) *PostgresOIDCStateStore {
	return &PostgresOIDCStateStore{db: db}
}

func (s *PostgresOIDCStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	metadata, _ := json.Marshal(data.Metadata)
	expiresAt := time.Now().Add(ttl)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_states (state, redirect_url, nonce, provider, metadata, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		state, data.RedirectURL, data.Nonce, data.Provider, metadata, data.CreatedAt, expiresAt,
	)
	return err
}

func (s *PostgresOIDCStateStore) GetState(ctx context.Context, state string) (*storage.OIDCState, error) {
	data := &storage.OIDCState{}
	var metadata []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT redirect_url, nonce, provider, metadata, created_at
		 FROM oidc_states WHERE state = $1 AND expires_at > NOW()`, state,
	).Scan(&data.RedirectURL, &data.Nonce, &data.Provider, &metadata, &data.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(metadata, &data.Metadata)
	// Delete after retrieval (one-time use)
	s.db.ExecContext(ctx, `DELETE FROM oidc_states WHERE state = $1`, state)
	return data, nil
}

func (s *PostgresOIDCStateStore) DeleteState(ctx context.Context, state string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_states WHERE state = $1`, state)
	return err
}

// =============================================================================
// Audit Logger using stdlib log/slog
// =============================================================================

// SlogAuditLogger implements audit logging using stdlib slog.
type SlogAuditLogger struct {
	logger *slog.Logger
}

func NewSlogAuditLogger() *SlogAuditLogger {
	return &SlogAuditLogger{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}
}

func (l *SlogAuditLogger) LogAuth(eventType, result, userID, email, provider, ip, userAgent string, err error) {
	attrs := []any{
		slog.String("event_type", eventType),
		slog.String("result", result),
		slog.String("user_id", userID),
		slog.String("email", email),
		slog.String("provider", provider),
		slog.String("ip", ip),
		slog.String("user_agent", userAgent),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	l.logger.Info("audit", attrs...)
}

// =============================================================================
// Application Server
// =============================================================================

// App holds all the components of the authentication system.
type App struct {
	basicAuth     *basic.Authenticator
	jwtManager    *jwt.TokenManager
	totpManager   *totp.Manager
	webauthnAuth  *webauthn.Authenticator
	oidcClient    *authoidc.Client
	sessionMgr    *session.Manager
	jwtMiddleware *middleware.JWTMiddleware
	userStore     storage.UserStore
	credStore     storage.CredentialStore
	auditLogger   *SlogAuditLogger
	signingKey    []byte
}

func main() {
	// Command line flags
	useMemory := flag.Bool("memory", false, "Use in-memory storage instead of PostgreSQL")
	dbURL := flag.String("db", os.Getenv("DATABASE_URL"), "PostgreSQL connection string")
	port := flag.String("port", "8080", "HTTP server port")
	flag.Parse()

	// Initialize storage
	var (
		userStore  storage.UserStore
		credStore  storage.CredentialStore
		sessionStr storage.SessionStore
		tokenStore storage.TokenStore
		stateStore storage.OIDCStateStore
	)

	if *useMemory || *dbURL == "" {
		log.Println("Using in-memory storage")
		userStore = storage.NewInMemoryUserStore()
		credStore = storage.NewInMemoryCredentialStore()
		sessionStr = storage.NewInMemorySessionStore()
		tokenStore = storage.NewInMemoryTokenStore()
		stateStore = storage.NewInMemoryOIDCStateStore()
	} else {
		log.Printf("Connecting to PostgreSQL: %s", *dbURL)
		db, err := sql.Open("postgres", *dbURL)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatalf("Failed to ping database: %v", err)
		}

		userStore = NewPostgresUserStore(db)
		credStore = NewPostgresCredentialStore(db)
		sessionStr = NewPostgresSessionStore(db)
		tokenStore = NewPostgresTokenStore(db)
		stateStore = NewPostgresOIDCStateStore(db)
	}

	// Generate signing key (in production, load from env)
	signingKey := []byte(os.Getenv("JWT_SIGNING_KEY"))
	if len(signingKey) == 0 {
		signingKey = make([]byte, 32)
		rand.Read(signingKey)
		log.Printf("Generated random signing key (use JWT_SIGNING_KEY env var in production)")
	}

	// Initialize audit logger
	auditLogger := NewSlogAuditLogger()

	// Create basic authenticator
	basicAuth, err := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})
	if err != nil {
		log.Fatalf("Failed to create basic authenticator: %v", err)
	}

	// Create JWT manager
	jwtManager, err := jwt.NewTokenManager(jwt.Config{
		UserStore:       userStore,
		TokenStore:      tokenStore,
		SigningKey:      signingKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "go-auth-complete-example",
	})
	if err != nil {
		log.Fatalf("Failed to create JWT manager: %v", err)
	}

	// Create TOTP manager
	totpManager, err := totp.NewManager(totp.Config{
		CredentialStore: credStore,
		Issuer:          "GoAuthExample",
	})
	if err != nil {
		log.Fatalf("Failed to create TOTP manager: %v", err)
	}

	// Create session manager
	sessionMgr, err := session.NewManager(session.Config{
		Store:      sessionStr,
		SessionTTL: 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create session manager: %v", err)
	}

	// Create JWT middleware
	jwtMiddleware := middleware.NewJWTMiddleware(middleware.JWTConfig{
		TokenManager: jwtManager,
	})

	// Create WebAuthn authenticator (optional - requires proper domain config)
	var webauthnAuth *webauthn.Authenticator
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	webauthnAuth, err = webauthn.NewAuthenticator(webauthn.Config{
		RPDisplayName:   "Go Auth Example",
		RPID:            rpID,
		RPOrigins:       []string{"http://localhost:" + *port},
		UserStore:       userStore,
		CredentialStore: credStore,
		SessionStore:    stateStore,
	})
	if err != nil {
		log.Printf("WebAuthn disabled: %v", err)
	}

	// Create OIDC client (optional - requires Google OAuth credentials)
	var oidcClient *authoidc.Client
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if googleClientID != "" && googleClientSecret != "" {
		ctx := context.Background()
		googleProvider, err := provider.NewGoogleProvider(
			ctx,
			googleClientID,
			googleClientSecret,
			fmt.Sprintf("http://localhost:%s/auth/google/callback", *port),
		)
		if err != nil {
			log.Printf("Failed to create Google provider: %v", err)
		} else {
			oidcClient, err = authoidc.NewClient(authoidc.Config{
				Providers:  []authoidc.Provider{googleProvider},
				UserStore:  userStore,
				StateStore: stateStore,
			})
			if err != nil {
				log.Printf("Failed to create OIDC client: %v", err)
			}
		}
	} else {
		log.Println("Google SSO disabled (set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)")
	}

	// Create app
	app := &App{
		basicAuth:     basicAuth,
		jwtManager:    jwtManager,
		totpManager:   totpManager,
		webauthnAuth:  webauthnAuth,
		oidcClient:    oidcClient,
		sessionMgr:    sessionMgr,
		jwtMiddleware: jwtMiddleware,
		userStore:     userStore,
		credStore:     credStore,
		auditLogger:   auditLogger,
		signingKey:    signingKey,
	}

	// Setup routes
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/", app.handleHome)
	mux.HandleFunc("/health", app.handleHealth)

	// Basic auth endpoints
	mux.HandleFunc("POST /auth/register", app.handleRegister)
	mux.HandleFunc("POST /auth/login", app.handleLogin)
	mux.HandleFunc("POST /auth/refresh", app.handleRefresh)
	mux.HandleFunc("POST /auth/logout", app.handleLogout)

	// Password reset
	mux.HandleFunc("POST /auth/password/reset/request", app.handlePasswordResetRequest)
	mux.HandleFunc("POST /auth/password/reset/confirm", app.handlePasswordResetConfirm)

	// TOTP endpoints
	mux.HandleFunc("POST /auth/totp/setup", app.handleTOTPSetup)
	mux.HandleFunc("POST /auth/totp/verify", app.handleTOTPVerify)
	mux.HandleFunc("POST /auth/totp/disable", app.handleTOTPDisable)

	// WebAuthn endpoints
	if webauthnAuth != nil {
		mux.HandleFunc("POST /auth/webauthn/register/begin", app.handleWebAuthnRegisterBegin)
		mux.HandleFunc("POST /auth/webauthn/register/finish", app.handleWebAuthnRegisterFinish)
		mux.HandleFunc("POST /auth/webauthn/login/begin", app.handleWebAuthnLoginBegin)
		mux.HandleFunc("POST /auth/webauthn/login/finish", app.handleWebAuthnLoginFinish)
	}

	// Google SSO endpoints
	if oidcClient != nil {
		mux.HandleFunc("/auth/google/login", app.handleGoogleLogin)
		mux.HandleFunc("/auth/google/callback", app.handleGoogleCallback)
	}

	// Protected endpoints
	mux.Handle("GET /api/me", app.jwtMiddleware.Middleware(http.HandlerFunc(app.handleMe)))
	mux.Handle("GET /api/protected", app.jwtMiddleware.Middleware(http.HandlerFunc(app.handleProtected)))

	// Start server
	addr := ":" + *port
	log.Printf("Server starting on %s", addr)
	log.Printf("Try: curl -X POST http://localhost:%s/auth/register -d '{\"email\":\"test@example.com\",\"password\":\"password123\",\"name\":\"Test User\"}'", *port)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// =============================================================================
// HTTP Handlers
// =============================================================================

func (app *App) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	endpoints := map[string]interface{}{
		"name":    "go-auth Complete Example",
		"version": "1.0.0",
		"endpoints": map[string]string{
			"POST /auth/register":               "Register new user",
			"POST /auth/login":                  "Login with email/password",
			"POST /auth/refresh":                "Refresh access token",
			"POST /auth/logout":                 "Logout (revoke tokens)",
			"POST /auth/password/reset/request": "Request password reset",
			"POST /auth/password/reset/confirm": "Confirm password reset",
			"POST /auth/totp/setup":             "Setup TOTP 2FA",
			"POST /auth/totp/verify":            "Verify TOTP code",
			"POST /auth/totp/disable":           "Disable TOTP 2FA",
			"GET /auth/google/login":            "Login with Google",
			"GET /api/me":                       "Get current user (requires JWT)",
			"GET /api/protected":                "Protected endpoint (requires JWT)",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoints)
}

func (app *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (app *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := app.basicAuth.Register(r.Context(), basic.RegisterRequest{
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
		Name:     req.Name,
	})

	app.auditLogger.LogAuth("auth.register", boolToResult(err == nil), "", req.Email, "local", r.RemoteAddr, r.UserAgent(), err)

	if err != nil {
		app.jsonError(w, fmt.Sprintf("Registration failed: %v", err), http.StatusBadRequest)
		return
	}

	// Generate tokens for the new user
	tokenPair, err := app.jwtManager.GenerateTokenPair(r.Context(), user)
	if err != nil {
		app.jsonError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":          user,
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := app.basicAuth.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		app.auditLogger.LogAuth("auth.login", "failure", "", req.Email, "local", r.RemoteAddr, r.UserAgent(), err)
		app.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check if TOTP is enabled
	totpEnabled, _ := app.totpManager.IsEnabled(r.Context(), user.ID)
	if totpEnabled {
		if req.TOTPCode == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"requires_2fa": true,
				"message":      "TOTP code required",
			})
			return
		}

		valid, err := app.totpManager.Validate(r.Context(), user.ID, req.TOTPCode)
		if err != nil || !valid {
			app.auditLogger.LogAuth("auth.login.2fa", "failure", user.ID, user.Email, "local", r.RemoteAddr, r.UserAgent(), err)
			app.jsonError(w, "Invalid TOTP code", http.StatusUnauthorized)
			return
		}
	}

	// Generate tokens
	tokenPair, err := app.jwtManager.GenerateTokenPair(r.Context(), user)
	if err != nil {
		app.jsonError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	app.auditLogger.LogAuth("auth.login", "success", user.ID, user.Email, "local", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":          user,
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

func (app *App) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tokenPair, err := app.jwtManager.RefreshAccessToken(r.Context(), req.RefreshToken)
	if err != nil {
		app.auditLogger.LogAuth("token.refresh", "failure", "", "", "", r.RemoteAddr, r.UserAgent(), err)
		app.jsonError(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	app.auditLogger.LogAuth("token.refresh", "success", "", "", "", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenPair)
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := app.jwtManager.RevokeRefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		app.auditLogger.LogAuth("auth.logout", "failure", "", "", "", r.RemoteAddr, r.UserAgent(), err)
		app.jsonError(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	app.auditLogger.LogAuth("auth.logout", "success", "", "", "", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (app *App) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Look up user
	user, err := app.userStore.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Don't reveal if user exists
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If the email exists, a reset link will be sent",
		})
		return
	}

	// Generate reset token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// Store token (expires in 1 hour)
	err = app.credStore.StorePasswordResetToken(r.Context(), user.ID, token, time.Now().Add(time.Hour))
	if err != nil {
		app.jsonError(w, "Failed to create reset token", http.StatusInternalServerError)
		return
	}

	app.auditLogger.LogAuth("auth.password_reset.request", "success", user.ID, user.Email, "local", r.RemoteAddr, r.UserAgent(), nil)

	// In production, send email with token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":     "If the email exists, a reset link will be sent",
		"reset_token": token, // Only for demo - don't return in production!
	})
}

func (app *App) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate token
	userID, err := app.credStore.ValidatePasswordResetToken(r.Context(), req.Token)
	if err != nil {
		app.jsonError(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	// Update password
	err = app.basicAuth.ResetPassword(r.Context(), userID, req.NewPassword)
	if err != nil {
		app.jsonError(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// Delete used token
	app.credStore.DeletePasswordResetToken(r.Context(), req.Token)

	app.auditLogger.LogAuth("auth.password_reset.confirm", "success", userID, "", "local", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully"})
}

func (app *App) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"user_id"`
		AccountName string `json:"account_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	secret, err := app.totpManager.GenerateSecret(r.Context(), req.UserID, req.AccountName)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to setup TOTP: %v", err), http.StatusBadRequest)
		return
	}

	app.auditLogger.LogAuth("auth.totp.setup", "success", req.UserID, "", "local", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secret":       secret.Secret,
		"qr_code_url":  secret.QRCode,
		"backup_codes": secret.BackupCodes,
	})
}

func (app *App) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	valid, err := app.totpManager.Validate(r.Context(), req.UserID, req.Code)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	result := "failure"
	if valid {
		result = "success"
	}
	app.auditLogger.LogAuth("auth.totp.verify", result, req.UserID, "", "local", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"valid": valid})
}

func (app *App) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := app.totpManager.Disable(r.Context(), req.UserID)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to disable TOTP: %v", err), http.StatusBadRequest)
		return
	}

	app.auditLogger.LogAuth("auth.totp.disable", "success", req.UserID, "", "local", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "TOTP disabled successfully"})
}

func (app *App) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	options, sessionID, err := app.webauthnAuth.BeginRegistration(r.Context(), req.UserID)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to begin registration: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"options":    options,
		"session_id": sessionID,
	})
}

func (app *App) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	// WebAuthn finish requires parsing the credential creation response from the browser
	// The client-side JavaScript calls navigator.credentials.create() and sends the response
	// Parse the WebAuthn response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to parse WebAuthn response: %v", err), http.StatusBadRequest)
		return
	}

	// Get session ID from header (set by client during begin)
	sessionID := r.Header.Get("X-WebAuthn-Session")
	if sessionID == "" {
		app.jsonError(w, "Missing X-WebAuthn-Session header", http.StatusBadRequest)
		return
	}

	credential, err := app.webauthnAuth.FinishRegistration(r.Context(), sessionID, parsedResponse)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to finish registration: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"credential_id": base64.URLEncoding.EncodeToString(credential.ID),
		"message":       "WebAuthn credential registered successfully",
	})
}

func (app *App) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	options, sessionID, err := app.webauthnAuth.BeginLogin(r.Context(), req.UserID)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to begin login: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"options":    options,
		"session_id": sessionID,
	})
}

func (app *App) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	// WebAuthn finish requires parsing the credential assertion response from the browser
	// The client-side JavaScript calls navigator.credentials.get() and sends the response
	// Parse the WebAuthn response
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to parse WebAuthn response: %v", err), http.StatusBadRequest)
		return
	}

	// Get session ID from header (set by client during begin)
	sessionID := r.Header.Get("X-WebAuthn-Session")
	if sessionID == "" {
		app.jsonError(w, "Missing X-WebAuthn-Session header", http.StatusBadRequest)
		return
	}

	user, err := app.webauthnAuth.FinishLogin(r.Context(), sessionID, parsedResponse)
	if err != nil {
		app.jsonError(w, fmt.Sprintf("Failed to finish login: %v", err), http.StatusBadRequest)
		return
	}

	// Generate JWT tokens for the user
	tokenPair, err := app.jwtManager.GenerateTokenPair(r.Context(), user)
	if err != nil {
		app.jsonError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":          user,
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

func (app *App) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	authURL, err := app.oidcClient.GetAuthorizationURL(r.Context(), authoidc.AuthURLOptions{
		Provider: "google",
	})
	if err != nil {
		app.jsonError(w, "Failed to get authorization URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (app *App) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		app.jsonError(w, fmt.Sprintf("OAuth error: %s", errParam), http.StatusBadRequest)
		return
	}

	result, err := app.oidcClient.HandleCallback(r.Context(), state, code)
	if err != nil {
		app.auditLogger.LogAuth("auth.sso.google", "failure", "", "", "google", r.RemoteAddr, r.UserAgent(), err)
		app.jsonError(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Generate JWT tokens
	tokenPair, err := app.jwtManager.GenerateTokenPair(r.Context(), result.User)
	if err != nil {
		app.jsonError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	app.auditLogger.LogAuth("auth.sso.google", "success", result.User.ID, result.User.Email, "google", r.RemoteAddr, r.UserAgent(), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":          result.User,
		"is_new_user":   result.IsNewUser,
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

func (app *App) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetClaims(r)
	if !ok {
		app.jsonError(w, "Claims not found", http.StatusInternalServerError)
		return
	}

	user, err := app.userStore.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		app.jsonError(w, "User not found", http.StatusNotFound)
		return
	}

	// Check TOTP status
	totpEnabled, _ := app.totpManager.IsEnabled(r.Context(), user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":         user,
		"totp_enabled": totpEnabled,
	})
}

func (app *App) handleProtected(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetClaims(r)
	if !ok {
		app.jsonError(w, "Claims not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "You have accessed a protected resource",
		"user_id":    claims.UserID,
		"email":      claims.Email,
		"issued_at":  claims.IssuedAt.Time,
		"expires_at": claims.ExpiresAt.Time,
	})
}

// =============================================================================
// Helpers
// =============================================================================

func (app *App) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func boolToResult(success bool) string {
	if success {
		return "success"
	}
	return "failure"
}
