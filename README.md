# go-auth

[![Go Reference](https://pkg.go.dev/badge/github.com/meysam81/go-auth.svg)](https://pkg.go.dev/github.com/meysam81/go-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/meysam81/go-auth)](https://goreportcard.com/report/github.com/meysam81/go-auth)
[![codecov](https://codecov.io/github/meysam81/go-auth/graph/badge.svg?token=8WzFAwJa1Z)](https://codecov.io/github/meysam81/go-auth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/meysam81/go-auth)](https://github.com/meysam81/go-auth/blob/main/go.mod)
[![License](https://img.shields.io/github/license/meysam81/go-auth)](https://github.com/meysam81/go-auth/blob/main/LICENSE)
[![CI](https://github.com/meysam81/go-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/meysam81/go-auth/actions/workflows/ci.yml)

A comprehensive, modular, and production-ready authentication library for Go applications. Supports multiple authentication methods including Basic Auth, JWT, WebAuthn/Passkeys, and OIDC/OAuth2 SSO with 10+ popular providers.

## Features

- **Multiple Authentication Methods**
  - 🔐 Basic Authentication (username/password with bcrypt)
  - 🎫 JWT Authentication (access + refresh tokens)
  - 🔑 WebAuthn/Passkey Authentication
  - 🌐 OIDC/OAuth2 SSO (Single Sign-On)

- **10+ SSO Providers**
  - Google, GitHub, Microsoft, GitLab
  - Auth0, Okta, Apple Sign In
  - Discord, Slack, LinkedIn

- **Modular Architecture**
  - Framework-agnostic core
  - Storage-agnostic (bring your own DB)
  - Isolated HTTP middleware (stdlib compatible)
  - Interface-based design for easy testing

- **Production-Ready**
  - Secure password hashing (bcrypt)
  - Token revocation support
  - Session management
  - CSRF protection for OAuth flows
  - Follows Google Go Style Guide
  - Minimal dependencies

## Installation

```bash
go get github.com/meysam81/go-auth
```

## Quick Start

### Basic Authentication

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/meysam81/go-auth/auth/basic"
    "github.com/meysam81/go-auth/middleware"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    // Initialize storage
    userStore := storage.NewInMemoryUserStore()
    credentialStore := storage.NewInMemoryCredentialStore()

    // Create authenticator
    auth, err := basic.NewAuthenticator(basic.Config{
        UserStore:       userStore,
        CredentialStore: credentialStore,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Register a user
    user, err := auth.Register(context.Background(), basic.RegisterRequest{
        Email:    "user@example.com",
        Password: "securepassword123",
        Name:     "John Doe",
    })

    // Create middleware
    authMiddleware := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
        Authenticator: auth,
    })

    // Protected route
    http.Handle("/api/protected", authMiddleware.Middleware(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, _ := middleware.GetUser(r)
            w.Write([]byte("Hello, " + user.Name))
        }),
    ))

    http.ListenAndServe(":8080", nil)
}
```

### JWT Authentication

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/meysam81/go-auth/auth/jwt"
    "github.com/meysam81/go-auth/middleware"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    userStore := storage.NewInMemoryUserStore()
    tokenStore := storage.NewInMemoryTokenStore()

    // Create JWT manager
    tokenManager, err := jwt.NewTokenManager(jwt.Config{
        UserStore:       userStore,
        TokenStore:      tokenStore,
        SigningKey:      []byte("your-secret-key"),
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Login endpoint - generates tokens
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        user := &storage.User{
            ID:    "user123",
            Email: "user@example.com",
            Name:  "John Doe",
        }

        tokenPair, err := tokenManager.GenerateTokenPair(r.Context(), user)
        if err != nil {
            http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
            return
        }

        // Return tokens to client
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(tokenPair)
    })

    // Protected route with JWT middleware
    authMiddleware := middleware.NewJWTMiddleware(middleware.JWTConfig{
        TokenManager: tokenManager,
    })

    http.Handle("/api/protected", authMiddleware.Middleware(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, _ := middleware.GetClaims(r)
            w.Write([]byte("User ID: " + claims.UserID))
        }),
    ))

    http.ListenAndServe(":8080", nil)
}
```

### OIDC/SSO Authentication

```go
package main

import (
    "context"
    "log"
    "net/http"

    authoidc "github.com/meysam81/go-auth/auth/oidc"
    "github.com/meysam81/go-auth/provider"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    ctx := context.Background()
    userStore := storage.NewInMemoryUserStore()
    stateStore := storage.NewInMemoryOIDCStateStore()

    // Create providers
    googleProvider, _ := provider.NewGoogleProvider(
        ctx,
        "your-google-client-id",
        "your-google-client-secret",
        "http://localhost:8080/callback/google",
    )

    githubProvider := provider.NewGitHubProvider(
        "your-github-client-id",
        "your-github-client-secret",
        "http://localhost:8080/callback/github",
    )

    // Create OIDC client
    oidcClient, _ := authoidc.NewClient(authoidc.Config{
        Providers:  []authoidc.Provider{googleProvider, githubProvider},
        UserStore:  userStore,
        StateStore: stateStore,
    })

    // Login - redirects to provider
    http.HandleFunc("/login/google", func(w http.ResponseWriter, r *http.Request) {
        authURL, _ := oidcClient.GetAuthorizationURL(r.Context(), authoidc.AuthURLOptions{
            Provider: "google",
        })
        http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
    })

    // Callback - handles OAuth response
    http.HandleFunc("/callback/google", func(w http.ResponseWriter, r *http.Request) {
        state := r.URL.Query().Get("state")
        code := r.URL.Query().Get("code")

        result, err := oidcClient.HandleCallback(r.Context(), state, code)
        if err != nil {
            http.Error(w, "Authentication failed", http.StatusUnauthorized)
            return
        }

        // User is authenticated - create session or JWT
        w.Write([]byte("Welcome, " + result.User.Name))
    })

    http.ListenAndServe(":8080", nil)
}
```

## Architecture

### Storage Interfaces

The library is storage-agnostic. You implement the storage interfaces with your preferred database:

```go
type UserStore interface {
    CreateUser(ctx context.Context, user *User) error
    GetUserByID(ctx context.Context, id string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    UpdateUser(ctx context.Context, user *User) error
    DeleteUser(ctx context.Context, id string) error
}

type CredentialStore interface {
    StorePasswordHash(ctx context.Context, userID string, hash []byte) error
    GetPasswordHash(ctx context.Context, userID string) ([]byte, error)
    StoreWebAuthnCredential(ctx context.Context, userID string, credential *WebAuthnCredential) error
    GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
    // ...
}

type SessionStore interface {
    CreateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error
    GetSession(ctx context.Context, sessionID string) (*SessionData, error)
    DeleteSession(ctx context.Context, sessionID string) error
    // ...
}
```

In-memory implementations are provided for development/testing:
- `storage.NewInMemoryUserStore()`
- `storage.NewInMemoryCredentialStore()`
- `storage.NewInMemorySessionStore()`
- `storage.NewInMemoryTokenStore()`
- `storage.NewInMemoryOIDCStateStore()`

### Middleware

HTTP middleware is isolated in the `middleware` package and works with any framework that uses `http.Handler`:

```go
// Token extraction
extractor := &middleware.HeaderExtractor{
    HeaderName: "Authorization",
    Scheme:     "Bearer",
}

// Or use cookies
extractor := &middleware.CookieExtractor{
    CookieName: "session_id",
}

// Or try multiple sources
extractor := &middleware.MultiExtractor{
    Extractors: []middleware.SessionTokenExtractor{
        &middleware.CookieExtractor{CookieName: "session"},
        &middleware.HeaderExtractor{HeaderName: "Authorization", Scheme: "Bearer"},
    },
}
```

### Supported Providers

| Provider | Type | Constructor |
|----------|------|-------------|
| Google | OIDC | `provider.NewGoogleProvider()` |
| Microsoft | OIDC | `provider.NewMicrosoftProvider()` |
| GitLab | OIDC | `provider.NewGitLabProvider()` |
| Auth0 | OIDC | `provider.NewAuth0Provider()` |
| Okta | OIDC | `provider.NewOktaProvider()` |
| Apple | OIDC | `provider.NewAppleProvider()` |
| LinkedIn | OAuth2 | `provider.NewLinkedInProvider()` |
| GitHub | OAuth2 | `provider.NewGitHubProvider()` |
| Discord | OAuth2 | `provider.NewDiscordProvider()` |
| Slack | OAuth2 | `provider.NewSlackProvider()` |

### Custom Providers

Implement the `Provider` interface to add custom providers:

```go
type Provider interface {
    Name() string
    GetOAuth2Config() *oauth2.Config
    GetOIDCProvider() *oidc.Provider
    ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
}
```

## WebAuthn/Passkeys

```go
package main

import (
    "context"
    "log"

    "github.com/meysam81/go-auth/auth/webauthn"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    userStore := storage.NewInMemoryUserStore()
    credentialStore := storage.NewInMemoryCredentialStore()
    sessionStore := storage.NewInMemoryOIDCStateStore() // For challenge storage

    auth, err := webauthn.NewAuthenticator(webauthn.Config{
        RPDisplayName: "My App",
        RPID:          "example.com",
        RPOrigins:     []string{"https://example.com"},
        UserStore:     userStore,
        CredentialStore: credentialStore,
        SessionStore:    sessionStore,
    })

    // Registration flow
    options, sessionID, err := auth.BeginRegistration(context.Background(), "user123")
    // Send options to client for navigator.credentials.create()

    // After client response
    credential, err := auth.FinishRegistration(context.Background(), sessionID, response)

    // Authentication flow
    options, sessionID, err := auth.BeginLogin(context.Background(), "user123")
    // Send options to client for navigator.credentials.get()

    // After client response
    user, err := auth.FinishLogin(context.Background(), sessionID, response)
}
```

## Session Management

```go
package main

import (
    "time"

    "github.com/meysam81/go-auth/session"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    sessionStore := storage.NewInMemorySessionStore()

    sessionManager, _ := session.NewManager(session.Config{
        Store:      sessionStore,
        SessionTTL: 24 * time.Hour,
    })

    // Create session
    sess, _ := sessionManager.Create(context.Background(), session.CreateSessionRequest{
        UserID:   "user123",
        Email:    "user@example.com",
        Provider: "google",
    })

    // Validate session
    sessionData, _ := sessionManager.Validate(context.Background(), sess.ID)

    // Refresh session
    sessionManager.Refresh(context.Background(), sess.ID)

    // Delete session (logout)
    sessionManager.Delete(context.Background(), sess.ID)
}
```

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic/` - Basic authentication example
- `examples/jwt/` - JWT authentication example
- `examples/oidc/` - OIDC/SSO authentication example
- `examples/webauthn/` - WebAuthn/Passkey example (TODO)

Run an example:

```bash
cd examples/basic
go run main.go
```

## Production Deployment

### Security Best Practices

1. **Use strong signing keys**
   ```go
   // Generate a secure random key
   signingKey := make([]byte, 32)
   rand.Read(signingKey)
   ```

2. **Use HTTPS in production**
   - Set `Secure: true` on cookies
   - Configure proper CORS policies

3. **Store secrets in environment variables**
   ```go
   signingKey := []byte(os.Getenv("JWT_SIGNING_KEY"))
   ```

4. **Implement rate limiting**
   - Limit login attempts
   - Use exponential backoff

5. **Use persistent storage**
   - Implement storage interfaces with PostgreSQL, MySQL, etc.
   - Use Redis for sessions and ephemeral data

### Database Integration Example

```go
// PostgreSQL implementation example
type PostgresUserStore struct {
    db *sql.DB
}

func (s *PostgresUserStore) CreateUser(ctx context.Context, user *storage.User) error {
    _, err := s.db.ExecContext(ctx,
        "INSERT INTO users (id, email, username, name, provider, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        user.ID, user.Email, user.Username, user.Name, user.Provider, user.CreatedAt, user.UpdatedAt,
    )
    return err
}

func (s *PostgresUserStore) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
    user := &storage.User{}
    err := s.db.QueryRowContext(ctx,
        "SELECT id, email, username, name, provider, created_at, updated_at FROM users WHERE email = $1",
        email,
    ).Scan(&user.ID, &user.Email, &user.Username, &user.Name, &user.Provider, &user.CreatedAt, &user.UpdatedAt)

    if err == sql.ErrNoRows {
        return nil, storage.ErrNotFound
    }
    return user, err
}

// Implement remaining methods...
```

## Testing

The library is designed for easy testing with interface-based architecture:

```go
// Mock storage for testing
type MockUserStore struct {
    users map[string]*storage.User
}

func (m *MockUserStore) GetUserByID(ctx context.Context, id string) (*storage.User, error) {
    user, ok := m.users[id]
    if !ok {
        return nil, storage.ErrNotFound
    }
    return user, nil
}

// Use in tests
func TestAuthentication(t *testing.T) {
    mockStore := &MockUserStore{
        users: map[string]*storage.User{
            "user123": {ID: "user123", Email: "test@example.com"},
        },
    }

    auth, _ := basic.NewAuthenticator(basic.Config{
        UserStore: mockStore,
        // ...
    })

    // Test authentication
}
```

## Dependencies

- `golang.org/x/crypto` - Password hashing (bcrypt)
- `github.com/golang-jwt/jwt/v5` - JWT implementation
- `github.com/go-webauthn/webauthn` - WebAuthn/FIDO2
- `github.com/coreos/go-oidc/v3` - OIDC client
- `golang.org/x/oauth2` - OAuth2 flows

All dependencies are production-ready, well-maintained, and widely used.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Follow the Google Go Style Guide
2. Write tests for new features
3. Update documentation
4. Keep dependencies minimal

## License

MIT License - see LICENSE file for details

## Support

- GitHub Issues: [Report bugs or request features](https://github.com/meysam81/go-auth/issues)
- Documentation: See package documentation with `go doc`

## Roadmap

- [ ] Support for SAML (if requested)
- [ ] Built-in OIDC Provider/Server (nice to have)
- [ ] Additional SSO providers
- [ ] Rate limiting middleware
- [ ] Audit logging interface
- [ ] Password reset flow helpers
- [ ] Email verification flow helpers
- [ ] Two-factor authentication (TOTP)
