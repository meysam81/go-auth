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
  - Comprehensive audit logging (SOC2, GDPR, HIPAA compliant)
  - Follows Google Go Style Guide
  - Minimal dependencies

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Installation](#installation)
- [30-Second Quick Start](#30-second-quick-start)
- [Verify Installation](#verify-installation)
- [Quick Start](#quick-start)
  - [Basic Authentication](#basic-authentication)
  - [JWT Authentication](#jwt-authentication)
  - [TOTP Two-Factor Authentication](#totp-two-factor-authentication)
  - [OIDC/SSO Authentication](#oidcsso-authentication)
- [Architecture](#architecture)
  - [Storage Interfaces](#storage-interfaces)
  - [Middleware](#middleware)
  - [Supported Providers](#supported-providers)
  - [Custom Providers](#custom-providers)
- [WebAuthn/Passkeys](#webauthnpasskeys)
- [Session Management](#session-management)
- [Audit Logging](#audit-logging)
  - [Basic Usage](#basic-usage)
  - [Advanced: Custom Audit Logger](#advanced-custom-audit-logger)
  - [Extracting Request Context](#extracting-request-context)
  - [Audit Event Types](#audit-event-types)
  - [PII Redaction](#pii-redaction)
  - [Custom Audit Implementation](#custom-audit-implementation)
  - [Compliance Features](#compliance-features)
- [Examples](#examples)
- [Advanced Examples](#advanced-examples)
- [Production Deployment](#production-deployment)
  - [Security Best Practices](#security-best-practices)
  - [Database Integration Example](#database-integration-example)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Getting Help](#getting-help)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)
- [Roadmap](#roadmap)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installation

```bash
go get github.com/meysam81/go-auth
```

## 30-Second Quick Start

Copy this complete example into a file and run it:

```go
// main.go - Complete working example
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/storage"
)

func main() {
	// 1. Create storage (in-memory for demo)
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	// 2. Create authenticator
	auth, err := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})
	if err != nil {
		log.Fatal(err)
	}

	// 3. Register a user
	_, err = auth.Register(context.Background(), basic.RegisterRequest{
		Email:    "demo@example.com",
		Username: "demo",
		Password: "password123",
		Name:     "Demo User",
	})
	if err != nil {
		log.Fatal(err)
	}

	// 4. Create middleware
	mw := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
		Authenticator: auth,
	})

	// 5. Protected endpoint
	http.Handle("/protected", mw.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := middleware.GetUser(r)
		fmt.Fprintf(w, "Hello, %s!", user.Name)
	})))

	// 6. Start server
	fmt.Println("Server running on :8080")
	fmt.Println("Test: curl -u demo:password123 http://localhost:8080/protected")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

Run it:

```bash
go run main.go
```

Test it:

```bash
curl -u demo:password123 http://localhost:8080/protected
# Output: Hello, Demo User!
```

## Verify Installation

Create a simple test to verify go-auth is installed correctly:

```go
// verify.go
package main

import (
	"fmt"

	"github.com/meysam81/go-auth/storage"
)

func main() {
	store := storage.NewInMemoryUserStore()
	fmt.Printf("go-auth installed successfully! Store type: %T\n", store)
}
```

```bash
go run verify.go
# Output: go-auth installed successfully! Store type: *storage.InMemoryUserStore
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
    if err != nil {
        log.Fatal(err)
    }

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
    "encoding/json"
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

### TOTP Two-Factor Authentication

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/meysam81/go-auth/auth/totp"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    credentialStore := storage.NewInMemoryCredentialStore()

    // Create TOTP manager
    totpManager, err := totp.NewManager(totp.Config{
        CredentialStore: credentialStore,
        Issuer:          "MyApp",
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    userID := "user123"
    accountName := "user@example.com"

    // Generate secret for user (returns QR code URL and backup codes)
    secret, err := totpManager.GenerateSecret(ctx, userID, accountName)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Scan this QR code URL with your authenticator app:")
    fmt.Println(secret.QRCode)
    fmt.Println("\nBackup codes (save these!):")
    for _, code := range secret.BackupCodes {
        fmt.Println(" ", code)
    }

    // Validate a code from the authenticator app
    code := "123456" // User enters this from their app
    valid, err := totpManager.Validate(ctx, userID, code)
    if err != nil {
        log.Fatal(err)
    }

    if valid {
        fmt.Println("\n2FA verification successful!")
    } else {
        fmt.Println("\nInvalid code, please try again")
    }

    // Check if TOTP is enabled for a user
    enabled, _ := totpManager.IsEnabled(ctx, userID)
    fmt.Printf("TOTP enabled: %v\n", enabled)
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

| Provider  | Type   | Constructor                       |
| --------- | ------ | --------------------------------- |
| Google    | OIDC   | `provider.NewGoogleProvider()`    |
| Microsoft | OIDC   | `provider.NewMicrosoftProvider()` |
| GitLab    | OIDC   | `provider.NewGitLabProvider()`    |
| Auth0     | OIDC   | `provider.NewAuth0Provider()`     |
| Okta      | OIDC   | `provider.NewOktaProvider()`      |
| Apple     | OIDC   | `provider.NewAppleProvider()`     |
| LinkedIn  | OAuth2 | `provider.NewLinkedInProvider()`  |
| GitHub    | OAuth2 | `provider.NewGitHubProvider()`    |
| Discord   | OAuth2 | `provider.NewDiscordProvider()`   |
| Slack     | OAuth2 | `provider.NewSlackProvider()`     |

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

## Audit Logging

The library provides comprehensive audit logging for compliance with modern security standards (SOC2, GDPR, HIPAA, PCI-DSS). By default, audit logging is disabled (no-op) for zero overhead.

### Basic Usage

```go
package main

import (
    "context"
    "os"

    "github.com/meysam81/go-auth/audit"
    "github.com/meysam81/go-auth/auth/basic"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    // Create an audit logger
    auditor := audit.DefaultStdLogger()
    // Or for production with PII redaction:
    // auditor := audit.ProductionStdLogger()

    // Create authenticator
    userStore := storage.NewInMemoryUserStore()
    credStore := storage.NewInMemoryCredentialStore()

    auth, _ := basic.NewAuthenticator(basic.Config{
        UserStore:       userStore,
        CredentialStore: credStore,
    })

    // Wrap with audit logging
    auditedAuth := audit.NewBasicAuthWrapper(auth, auditor, nil)

    // Now all authentication operations are logged
    user, err := auditedAuth.Register(context.Background(), basic.RegisterRequest{
        Email:    "user@example.com",
        Password: "password123",
    })
    // Logs: {"timestamp":"2025-11-15T12:00:00Z","event_type":"auth.register","event_result":"success",...}

    user, err = auditedAuth.Authenticate(context.Background(), "user@example.com", "password123")
    // Logs: {"timestamp":"2025-11-15T12:00:01Z","event_type":"auth.login","event_result":"success",...}
}
```

### Advanced: Custom Audit Logger

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/meysam81/go-auth/audit"
)

func main() {
    // Create a custom logger with specific configuration
    auditor := audit.NewStdLogger(audit.StdLoggerConfig{
        Output: os.Stdout, // or a file, syslog, etc.
        RedactionConfig: &audit.RedactionConfig{
            RedactEmail:     true,
            RedactUsername:  true,
            RedactIPAddress: true,
            MetadataRedactionKeys: []string{"password", "secret"},
        },
    })

    // Use the auditor with wrappers
    // ... (wrap your auth components)
}
```

### Extracting Request Context

For web applications, you can extract client IP, user agent, and other request metadata:

```go
package main

import (
    "context"
    "net/http"

    "github.com/meysam81/go-auth/audit"
    "github.com/meysam81/go-auth/auth/basic"
)

// SourceExtractor extracts audit context from HTTP request
func sourceExtractorFromRequest(r *http.Request) audit.SourceExtractor {
    return func(ctx context.Context) *audit.Source {
        return &audit.Source{
            IPAddress: r.RemoteAddr,
            UserAgent: r.UserAgent(),
            RequestID: r.Header.Get("X-Request-ID"),
        }
    }
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    auditor := audit.ProductionStdLogger()
    auth := getAuthenticator() // your authenticator

    // Create wrapper with source extractor
    auditedAuth := audit.NewBasicAuthWrapper(
        auth,
        auditor,
        sourceExtractorFromRequest(r),
    )

    user, err := auditedAuth.Authenticate(
        r.Context(),
        r.FormValue("email"),
        r.FormValue("password"),
    )
    // Logs include IP address, user agent, and request ID
}
```

### Audit Event Types

The library logs the following security events:

**Authentication Events:**

- `auth.login` - User login attempts
- `auth.logout` - User logout
- `auth.register` - New user registration
- `auth.password_change` - Password changes
- `auth.password_reset` - Password resets

**Token Events:**

- `token.generate` - Token generation
- `token.validate` - Token validation
- `token.refresh` - Token refresh
- `token.revoke` - Token revocation

**Session Events:**

- `session.create` - Session creation
- `session.validate` - Session validation
- `session.refresh` - Session refresh
- `session.delete` - Session deletion (logout)

**User Management Events:**

- `user.create`, `user.read`, `user.update`, `user.delete`

### PII Redaction

For compliance with privacy regulations (GDPR, CCPA), enable PII redaction:

```go
config := &audit.RedactionConfig{
    RedactEmail:     true,  // user@example.com -> u***@example.com
    RedactUsername:  true,  // username -> u***e
    RedactIPAddress: true,  // 192.168.1.1 -> 192.168.*.*
    MetadataRedactionKeys: []string{"ssn", "phone", "address"},
}

auditor := audit.NewStdLogger(audit.StdLoggerConfig{
    RedactionConfig: config,
})
```

### Custom Audit Implementation

Implement the `AuditLogger` interface to integrate with your logging system:

```go
type CustomAuditor struct {
    // your logging backend (e.g., Elasticsearch, Splunk, DataDog)
}

func (c *CustomAuditor) Log(ctx context.Context, event *audit.AuditEvent) error {
    // Send event to your logging backend
    return c.backend.Send(event)
}

// Use with wrappers
auditor := &CustomAuditor{backend: myBackend}
auditedAuth := audit.NewBasicAuthWrapper(auth, auditor, nil)
```

### Compliance Features

The audit logging implementation follows industry best practices:

- **Tamper-proof**: Logs are append-only
- **Structured**: JSON format for machine parsing
- **Timestamped**: UTC timestamps in RFC3339 format
- **Contextual**: Includes actor, resource, source, and result
- **Privacy-aware**: Built-in PII redaction
- **Traceable**: Supports trace IDs for distributed tracing
- **Non-blocking**: Logging failures don't prevent operations

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic/` - Basic authentication example
- `examples/jwt/` - JWT authentication example
- `examples/oidc/` - OIDC/SSO authentication example
- `examples/complete/` - Full-featured example with all auth methods

Run an example:

```bash
cd examples/basic
go run main.go
```

## Advanced Examples

For production-ready patterns and comprehensive implementations, see the **complete example** at [`examples/complete/`](./examples/complete/).

This standalone example includes:

- **All authentication methods**: Basic auth, JWT, TOTP 2FA, WebAuthn/Passkeys, Google SSO
- **PostgreSQL integration**: Complete storage implementations with SQL schema
- **Password reset flow**: Token-based password recovery
- **Session management**: Secure session handling
- **Audit logging**: Using stdlib `log/slog` for compliance logging
- **Full HTTP API**: RESTful endpoints for all operations

The example is completely self-contained with its own `go.mod` and can be run immediately:

```bash
cd examples/complete
go run main.go
```

See [`examples/complete/README.md`](./examples/complete/README.md) for detailed setup instructions and API documentation.

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

## Troubleshooting

### Common Issues

**"cannot find module" error**

```bash
# Ensure you're using Go 1.21+ and modules are enabled
go version
go env GO111MODULE
# Should be "on" or empty (auto)

# Try cleaning module cache
go clean -modcache
go get github.com/meysam81/go-auth
```

**"storage.ErrNotFound" when authenticating**

This means the user doesn't exist. Ensure you've registered the user first:

```go
// Register before authenticating
_, err := auth.Register(ctx, basic.RegisterRequest{
    Email:    "user@example.com",
    Password: "password",
})
```

**JWT token validation fails**

- Ensure the signing key is the same for generation and validation
- Check that the token hasn't expired (default: 15 minutes for access tokens)
- Verify the token is being passed correctly in the `Authorization: Bearer <token>` header

**TOTP codes always invalid**

- Ensure server time is synchronized (TOTP is time-based)
- Check that the secret was stored correctly during setup
- Verify the user is using a compatible authenticator app (Google Authenticator, Authy, etc.)

**WebAuthn registration fails**

- WebAuthn requires HTTPS in production (localhost works for development)
- Ensure `RPID` matches your domain exactly
- Check that `RPOrigins` includes the full origin URL (e.g., `https://example.com`)

### Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/meysam81/go-auth/issues) for similar problems
2. Review the examples in `examples/` directory
3. Use `go doc` to explore package documentation

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Follow the Google Go Style Guide
2. Write tests for new features
3. Update documentation
4. Keep dependencies minimal

## License

Apache 2.0 License - see LICENSE file for details

## Support

- GitHub Issues: [Report bugs or request features](https://github.com/meysam81/go-auth/issues)
- Documentation: See package documentation with `go doc`

## Roadmap

- [ ] Support for SAML (if requested)
- [ ] Built-in OIDC Provider/Server (nice to have)
- [ ] Additional SSO providers
- [ ] Rate limiting middleware
- [x] Audit logging interface ✅
- [x] Password reset flow helpers ✅
- [x] Email verification flow helpers ✅
- [x] Two-factor authentication (TOTP) ✅
