// Package main demonstrates JWT authentication with access and refresh tokens.
//
// This example shows how to:
//   - Configure a token manager that pins the algorithm, issuer and audience
//   - Generate access and refresh token pairs for users
//   - Protect HTTP endpoints with JWT middleware
//   - Implement the token refresh flow for long-lived sessions
//   - Extract claims from authenticated JWT requests
//
// The example creates a simple HTTP server with the following endpoints:
//   - GET  /            (public)  API documentation and usage instructions
//   - POST /login       (public)  returns a JWT access and refresh token pair
//   - POST /refresh     (public)  exchanges a refresh token for a new pair
//   - POST /logout      (public)  revokes a refresh token
//   - GET  /protected   (JWT)     returns the caller's claims
//
// # Running the Example
//
//	go run main.go
//
// Get JWT tokens:
//
//	curl -X POST http://localhost:8080/login
//
// Access protected endpoint:
//
//	curl -H "Authorization: Bearer <access_token>" http://localhost:8080/protected
//
// Refresh the access token when it expires:
//
//	curl -X POST http://localhost:8080/refresh -d '{"refresh_token":"<refresh_token>"}'
//
// # A refresh token is not a bearer credential
//
// Presenting the refresh token to /protected returns 401. Until this release,
// middleware.JWTMiddleware validated the bearer token without inspecting its
// type claim, so a refresh token — seven days of validity against an access
// token's fifteen minutes, held at rest in client storage, and intended for
// exactly one endpoint — authorized every protected route (finding F-02,
// CWE-863). The middleware now calls jwt.TokenManager.ValidateAccessToken, which
// pins the type.
//
// # Issuer and audience
//
// Config.Issuer and Config.Audience are both set below, and both are therefore
// required at validation (finding F-03). Without them, two services that share
// one signing secret — the common case when a single secret is rotated through
// an environment — accept each other's tokens.
//
// # Production Usage
//
// This example uses in-memory storage. For production:
//   - Supply JWT_SIGNING_KEY from a secret manager; never ship a literal
//   - Prefer an asymmetric method (Config.PrivateKey) so verifiers need only the
//     public key and cannot mint tokens
//   - Implement persistent token storage so refresh tokens can be revoked
//   - Use HTTPS to prevent token interception
//   - Rotate the refresh token on every refresh
//   - Add rate limiting on the login and refresh endpoints
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/meysam81/go-auth/auth/jwt"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/storage"
)

const (
	// minHMACKeyBytes is the floor RFC 7518 section 3.2 sets for HS256: a key at
	// least as long as the hash output. A shorter secret is brute-forceable
	// offline by anyone holding one token.
	minHMACKeyBytes = 32

	// maxRefreshBodyBytes caps the JSON body of /refresh and /logout. Both carry
	// one token; anything larger is an unauthenticated caller asking the server
	// to buffer on its behalf.
	maxRefreshBodyBytes = 8 << 10

	tokenIssuer = "example-app"
)

// tokenAudience is the aud claim minted into every token and required at
// validation. It names the API these tokens are for.
var tokenAudience = []string{"example-app-api"}

// tokenRequest is the body of /refresh and /logout.
type tokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// protectedResponse is the body of /protected.
type protectedResponse struct {
	Message   string    `json:"message"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Provider  string    `json:"provider,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// messageResponse is a plain acknowledgement body.
type messageResponse struct {
	Message string `json:"message"`
}

// app holds the collaborators the handlers share.
type app struct {
	tokens *jwt.TokenManager
	user   *storage.User
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run wires the example and serves it.
func run() error {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()

	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Username: "testuser",
		Name:     "Test User",
		Provider: "local",
	}
	if err := userStore.CreateUser(context.Background(), user); err != nil {
		return fmt.Errorf("create demo user: %w", err)
	}

	signingKey, err := signingKey()
	if err != nil {
		return err
	}

	// MetadataAllowlist is deliberately left empty: no storage.User.Metadata key
	// is copied into a token. A JWT is base64, not encrypted, so copying an
	// identity provider's raw claim set into one hands the browser every group
	// membership and internal identifier the directory released (finding F-21,
	// CWE-200). Naming keys here is the opt-in.
	tokenManager, err := jwt.NewTokenManager(jwt.Config{
		UserStore:       userStore,
		TokenStore:      tokenStore,
		SigningKey:      signingKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          tokenIssuer,
		Audience:        tokenAudience,
	})
	if err != nil {
		return fmt.Errorf("create token manager: %w", err)
	}

	a := &app{tokens: tokenManager, user: user}

	authMiddleware := middleware.NewJWTMiddleware(middleware.JWTConfig{
		TokenManager: tokenManager,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.HandleFunc("POST /refresh", a.handleRefresh)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.Handle("GET /protected", authMiddleware.Middleware(http.HandlerFunc(a.handleProtected)))
	mux.HandleFunc("GET /", handleIndex)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Println("Server starting on :8080")
	fmt.Println("Try: curl -X POST http://localhost:8080/login")

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// signingKey resolves the HS256 secret.
//
// A literal in source is a published credential, so the key comes from the
// environment. For a throwaway demo run with nothing configured, an ephemeral
// key is minted with crypto/rand: tokens then die with the process, which is the
// correct failure mode for an unconfigured deployment.
func signingKey() ([]byte, error) {
	if env := os.Getenv("JWT_SIGNING_KEY"); env != "" {
		if len(env) < minHMACKeyBytes {
			return nil, fmt.Errorf("JWT_SIGNING_KEY is %d bytes; RFC 7518 section 3.2 requires at least %d for HS256", len(env), minHMACKeyBytes)
		}
		return []byte(env), nil
	}

	key := make([]byte, minHMACKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ephemeral signing key: %w", err)
	}
	log.Println("JWT_SIGNING_KEY is unset; using an ephemeral key. Tokens will not survive a restart.")
	return key, nil
}

// handleLogin issues a token pair.
//
// A real sign-in endpoint verifies a credential here — see the auth/basic
// example — and only reaches this point once the password, and any second
// factor, has been checked.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	tokenPair, err := a.tokens.GenerateTokenPair(r.Context(), a.user)
	if err != nil {
		log.Printf("login: generate token pair: %v", err)
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Failed to generate tokens"})
		return
	}
	writeJSON(w, http.StatusOK, tokenPair)
}

// handleRefresh exchanges a refresh token for a fresh pair.
func (a *app) handleRefresh(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeTokenRequest(w, r)
	if !ok {
		return
	}

	tokenPair, err := a.tokens.RefreshAccessToken(r.Context(), req.RefreshToken)
	if err != nil {
		// Every rejection reason collapses into one response. Distinguishing
		// "expired" from "revoked" from "wrong signature" tells an attacker
		// holding a stolen token which of those it is.
		if !errors.Is(err, jwt.ErrInvalidToken) && !errors.Is(err, jwt.ErrTokenRevoked) {
			log.Printf("refresh: %v", err)
		}
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid refresh token"})
		return
	}
	writeJSON(w, http.StatusOK, tokenPair)
}

// handleLogout revokes a refresh token.
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeTokenRequest(w, r)
	if !ok {
		return
	}

	if err := a.tokens.RevokeRefreshToken(r.Context(), req.RefreshToken); err != nil {
		if !errors.Is(err, jwt.ErrInvalidToken) {
			log.Printf("logout: revoke refresh token: %v", err)
		}
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid refresh token"})
		return
	}
	writeJSON(w, http.StatusOK, messageResponse{Message: "Refresh token revoked"})
}

// handleProtected renders the access token's claims.
func (a *app) handleProtected(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetClaims(r)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Claims not found in context"})
		return
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		// The parser is configured with jwt.WithExpirationRequired, so this is
		// unreachable for a token it accepted; it is checked rather than
		// dereferenced so a future config change cannot turn into a panic.
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Token is missing required time claims"})
		return
	}

	writeJSON(w, http.StatusOK, protectedResponse{
		Message:   "Hello from protected endpoint",
		UserID:    claims.UserID,
		Email:     claims.Email,
		Provider:  claims.Provider,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	})
}

// handleIndex documents the endpoints.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	const usage = `JWT Authentication Example

Endpoints:
  POST /login      - Get access and refresh tokens
  POST /refresh    - Exchange a refresh token for a new pair
  POST /logout     - Revoke a refresh token
  GET  /protected  - Protected endpoint (requires a Bearer ACCESS token)

Example usage:
  1. Login:  curl -X POST http://localhost:8080/login
  2. Access: curl -H 'Authorization: Bearer <access_token>' http://localhost:8080/protected

Presenting the refresh token to /protected returns 401 by design (finding F-02).
`
	if _, err := fmt.Fprint(w, usage); err != nil {
		log.Printf("index: write response: %v", err)
	}
}

// decodeTokenRequest reads a bounded JSON body carrying a refresh token. It
// writes the error response itself and reports whether the caller may proceed.
func decodeTokenRequest(w http.ResponseWriter, r *http.Request) (tokenRequest, bool) {
	var req tokenRequest

	r.Body = http.MaxBytesReader(w, r.Body, maxRefreshBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid request body"})
		return tokenRequest{}, false
	}
	if req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "refresh_token is required"})
		return tokenRequest{}, false
	}
	return req, true
}

// writeJSON encodes a response body.
//
// An encode failure after the status line has been written cannot be reported to
// the client — the header is already on the wire — so it is logged rather than
// discarded. A silently dropped error here is how a truncated body becomes an
// unexplained client-side parse failure.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}
