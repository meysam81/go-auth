# go-auth

[![CI](https://img.shields.io/github/actions/workflow/status/meysam81/go-auth/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&style=flat-square)](https://github.com/meysam81/go-auth/actions/workflows/ci.yml)
[![Go Reference](https://img.shields.io/badge/pkg.go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/meysam81/go-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/meysam81/go-auth?style=flat-square)](https://goreportcard.com/report/github.com/meysam81/go-auth)
[![codecov](https://img.shields.io/codecov/c/github/meysam81/go-auth?logo=codecov&logoColor=white&style=flat-square)](https://codecov.io/github/meysam81/go-auth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/meysam81/go-auth?logo=go&logoColor=white&style=flat-square)](go.mod)
[![Latest Release](https://img.shields.io/github/v/release/meysam81/go-auth?logo=github&label=release&style=flat-square)](https://github.com/meysam81/go-auth/releases/latest)
[![License](https://img.shields.io/github/license/meysam81/go-auth?style=flat-square)](LICENSE)

[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white&style=flat-square)](https://www.conventionalcommits.org)
[![Renovate](https://img.shields.io/badge/renovate-enabled-1f8b4c?logo=renovatebot&logoColor=white&style=flat-square)](https://developer.mend.io/github/meysam81/go-auth)
[![Last Commit](https://img.shields.io/github/last-commit/meysam81/go-auth?logo=github&style=flat-square)](https://github.com/meysam81/go-auth/commits/main)

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
  - Secure password hashing (bcrypt, with the 72-byte limit enforced rather than
    silently truncated)
  - Token revocation, pinned `alg`/`iss`/`aud` and an access-token-only
    middleware path
  - Session management with identifier rotation
  - OAuth2/OIDC flows carry state, PKCE and a nonce; login-CSRF protection is
    available through the browser-binding entry points and is opt-in — see
    [OIDC/SSO Authentication](#oidcsso-authentication)
  - TOTP two-factor with confirm-before-arm, replay protection and hashed backup
    codes
  - Comprehensive audit logging (SOC2, GDPR, HIPAA compliant)
  - Follows Google Go Style Guide
  - Minimal dependencies

## Upgrading within v1.x

This release is the output of a security hardening pass. **Your code still
compiles, but several run-time behaviours changed on purpose** — a control that
is off by default protects nobody. The most likely to surprise you:

| Change                                       | What you will see                                   | What to do                             |
| -------------------------------------------- | --------------------------------------------------- | -------------------------------------- |
| OIDC no longer auto-provisions               | `ErrAccountCreationRefused` on a first-time sign-in | set `oidc.Config.CreatePolicy`         |
| Sign-in enforces an enrolled second factor   | `basic.ErrMFARequired`                              | use `AuthenticateWithTOTP`, or opt out |
| TOTP enrolment must be confirmed             | `totp.ErrPendingConfirmation`                       | call `Confirm` after `GenerateSecret`  |
| HMAC signing keys have a length floor        | `NewTokenManager` fails at startup                  | 32 bytes for HS256                     |
| Reset/verification tokens are hashed at rest | old links stop working                              | wait out the TTL                       |

The complete, ordered list with remediations is
[`docs/security-hardening.md` §7](docs/security-hardening.md), and the findings
behind each change are in the same document.

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Upgrading within v1.x](#upgrading-within-v1x)
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

> **Demo only.** `middleware.NewBasicAuthMiddleware` is deprecated: it runs one
> bcrypt verification on every request — roughly 250 ms of CPU, paid before the
> password is even known to be wrong — and HTTP Basic cannot carry a second
> factor, so mounting it on an otherwise MFA-protected route is an MFA bypass
> for that route. It is here because it is the shortest thing that runs. In a
> real service, authenticate once at a sign-in endpoint and protect the rest
> with `SessionMiddleware` or `JWTMiddleware`.

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
		user, ok := middleware.GetUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
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
    "fmt"
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
    if _, err := auth.Register(context.Background(), basic.RegisterRequest{
        Email:    "user@example.com",
        Password: "securepassword123",
        Name:     "John Doe",
    }); err != nil {
        log.Fatal(err)
    }

    // Create middleware
    authMiddleware := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
        Authenticator: auth,
    })

    // Protected route
    http.Handle("/api/protected", authMiddleware.Middleware(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, ok := middleware.GetUser(r)
            if !ok {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            fmt.Fprintf(w, "Hello, %s", user.Name)
        }),
    ))

    http.ListenAndServe(":8080", nil)
}
```

Three things to know before you call `Authenticate` in your own sign-in handler:

- **`ErrMFARequired` is not a failed sign-in.** If you wired a
  `Config.TOTPManager` and the user holds a _confirmed_ factor, `Authenticate`
  returns this instead of the user. Collect a code and call
  `AuthenticateWithTOTP(ctx, identifier, password, code)`, or set
  `Config.RequireMFAWhenEnrolled: basic.AllowPasswordOnly` if you run your own
  second-factor step. Treating any non-nil error as "wrong password" locks out
  every enrolled user. With no TOTP manager configured, nothing changes.
- **Passwords are capped at 72 bytes** (`ErrPasswordTooLong`) because bcrypt
  ignores everything past that. Show the message; a generic failure on a
  password the user just typed twice is a support ticket.
- **Every rejection costs one bcrypt evaluation**, including an unknown
  identifier, so account existence is not measurable from the response time.
  Build the `Authenticator` once at startup — the constructor pays for that
  guarantee up front.

### JWT Authentication

```go
package main

import (
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/meysam81/go-auth/auth/jwt"
    "github.com/meysam81/go-auth/middleware"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    userStore := storage.NewInMemoryUserStore()
    tokenStore := storage.NewInMemoryTokenStore()

    // HS256 requires a secret at least as long as its hash output: 32 bytes
    // (RFC 7518 section 3.2). NewTokenManager refuses a shorter one at startup
    // rather than signing tokens a laptop can crack offline. Generate it once
    // with `openssl rand -hex 32` and keep it in the environment.
    signingKey, err := hex.DecodeString(os.Getenv("JWT_SIGNING_KEY"))
    if err != nil {
        log.Fatal(err)
    }

    // Create JWT manager
    tokenManager, err := jwt.NewTokenManager(jwt.Config{
        UserStore:  userStore,
        TokenStore: tokenStore,
        SigningKey: signingKey,
        // Issuer and Audience are written at mint time AND required at
        // validation once set, so two services sharing one secret stop
        // accepting each other's tokens.
        Issuer:          "https://auth.example.com",
        Audience:        []string{"https://api.example.com"},
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
            claims, ok := middleware.GetClaims(r)
            if !ok {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            fmt.Fprintf(w, "User ID: %s", claims.UserID)
        }),
    ))

    http.ListenAndServe(":8080", nil)
}
```

`JWTMiddleware` accepts **access tokens only**. A refresh token presented as a
bearer credential is rejected — it lives seven days against an access token's
fifteen minutes and exists to be presented to exactly one endpoint. Use
`RefreshAccessToken` there, and `ValidateRefreshToken` if you need to inspect
one. `ValidateToken` is now equivalent to `ValidateAccessToken`.

`NewJWTMiddleware` panics on a nil `TokenManager`, at construction, so a wiring
mistake fails at startup instead of nil-dereferencing on the first
unauthenticated request. Use `NewJWTMiddlewareWithError` to handle it as a
value.

### TOTP Two-Factor Authentication

```go
package main

import (
    "context"
    "errors"
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

    // 1. ENROL. The factor is stored PENDING: it does not validate anything and
    //    IsEnabled reports false until the user proves they have the secret.
    secret, err := totpManager.GenerateSecret(ctx, userID, accountName)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Scan this QR code URL with your authenticator app:")
    fmt.Println(secret.QRCode)

    // These are the ONLY plaintext copy that will ever exist. The store
    // receives digests, so you cannot show them again later.
    fmt.Println("\nBackup codes (save these!):")
    for _, code := range secret.BackupCodes {
        fmt.Println(" ", code)
    }
    fmt.Printf("\nPending confirmation: %v\n", secret.Pending)

    // 2. CONFIRM. Ask for one code from the app and arm the factor. Skipping
    //    this step is how a user who never finished scanning ends up locked out
    //    of their own account with no self-service path.
    confirmationCode := "123456" // whatever the user typed in
    if err := totpManager.Confirm(ctx, userID, confirmationCode); err != nil {
        // ErrInvalidCode leaves the enrolment pending, so the user can retry.
        // Disable(ctx, userID) cancels it entirely and lets them start over.
        log.Fatalf("confirm: %v", err)
    }

    // 3. VALIDATE, on every later sign-in.
    valid, err := totpManager.Validate(ctx, userID, "654321")
    switch {
    case errors.Is(err, totp.ErrPendingConfirmation):
        fmt.Println("\nEnrolment was never confirmed")
    case errors.Is(err, totp.ErrCodeReused):
        // RFC 6238 section 5.2: a code authenticates once, not once per second.
        fmt.Println("\nThat code has already been used")
    case err != nil:
        log.Fatal(err)
    case valid:
        fmt.Println("\n2FA verification successful!")
    default:
        fmt.Println("\nInvalid code, please try again")
    }

    // IsEnabled reports false for a pending enrolment; IsPending tells
    // "never enrolled" apart from "enrolled, not confirmed".
    enabled, err := totpManager.IsEnabled(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("TOTP enabled: %v\n", enabled)
}
```

Two options worth setting in production:

- **`Config.Cipher`** encrypts the shared secret before it reaches your store.
  Without it the secret is persisted in a form that hands anyone who reads a
  backup a working second factor for every enrolled user. Backup codes are
  hashed either way. Once configured, treat the key as being as
  availability-critical as the store itself.
- **`Config.ReplayGuard`** defaults to an in-process guard, which is correct for
  a single process and insufficient for more than one. Supply a shared
  implementation (Redis, your database) if you run several instances.

`Config.ActivateOnGenerate` restores the pre-hardening "armed on generate"
behaviour for a caller that cannot add the confirmation step yet. It is
deprecated on arrival and re-opens the lockout it was added to close.

### OIDC/SSO Authentication

```go
package main

import (
    "context"
    "fmt"
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
    googleProvider, err := provider.NewGoogleProvider(
        ctx,
        "your-google-client-id",
        "your-google-client-secret",
        "http://localhost:8080/callback/google",
    )
    if err != nil {
        log.Fatal(err)
    }

    githubProvider := provider.NewGitHubProvider(
        "your-github-client-id",
        "your-github-client-secret",
        "http://localhost:8080/callback/github",
    )

    // Create OIDC client
    oidcClient, err := authoidc.NewClient(authoidc.Config{
        Providers:  []authoidc.Provider{googleProvider, githubProvider},
        UserStore:  userStore,
        StateStore: stateStore,

        // Provisioning is REFUSED unless you authorize it. The library cannot
        // tell whether the connection that asserted an address is entitled to
        // it, and in a bring-your-own-IdP deployment that flag belongs to the
        // tenant's administrator. AllowAccountCreation says "any verified
        // assertion may create an account"; a real policy checks the domain
        // against the connection.
        CreatePolicy: authoidc.AllowAccountCreation,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Login - redirects to provider, and hands the browser a binding cookie
    // that the callback will require. Without it there is nothing tying the
    // callback to the user agent that started the flow, which is login CSRF:
    // an attacker completes a flow against their own account and induces you
    // to visit the resulting callback URL.
    http.HandleFunc("/login/google", func(w http.ResponseWriter, r *http.Request) {
        authReq, err := oidcClient.GetAuthorizationURLWithBinding(r.Context(), authoidc.AuthURLOptions{
            Provider: "google",
        })
        if err != nil {
            http.Error(w, "Authentication failed", http.StatusInternalServerError)
            return
        }

        http.SetCookie(w, &http.Cookie{
            Name:     authoidc.BindingCookieName, // "__Host-go-auth-oidc-binding"
            Value:    authReq.Binding,
            Path:     "/",
            MaxAge:   int(authoidc.DefaultStateTTL.Seconds()),
            Secure:   true, // required by the __Host- prefix
            HttpOnly: true,
            SameSite: http.SameSiteLaxMode,
        })

        http.Redirect(w, r, authReq.URL, http.StatusTemporaryRedirect)
    })

    // Callback - handles OAuth response
    http.HandleFunc("/callback/google", func(w http.ResponseWriter, r *http.Request) {
        state := r.URL.Query().Get("state")
        code := r.URL.Query().Get("code")

        // An absent cookie is an empty binding, which a bound flow refuses.
        binding := ""
        if c, err := r.Cookie(authoidc.BindingCookieName); err == nil {
            binding = c.Value
        }

        result, err := oidcClient.HandleCallbackWithBinding(r.Context(), state, code, binding)
        if err != nil {
            // Do not echo err: it distinguishes "wrong binding" from "unknown
            // state" from "unverified email", which is free reconnaissance.
            http.Error(w, "Authentication failed", http.StatusUnauthorized)
            return
        }

        // User is authenticated - create session or JWT
        fmt.Fprintf(w, "Welcome, %s", result.User.Name)
    })

    http.ListenAndServe(":8080", nil)
}
```

**Use the `…WithBinding` pair.** `GetAuthorizationURL` and `HandleCallback` still
exist and still work, but `GetAuthorizationURL` returns a bare `string` and has
nowhere to hand you the binding value — so a flow started there has no
login-CSRF protection at all. Both are deprecated for that reason. Every flow
carries state, PKCE and (for an OIDC provider) a nonce regardless of which pair
you use.

**Errors your callback handler should expect**, all of them refusals the old
code did not make:

| Error                                      | Meaning                                                                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `ErrAccountCreationRefused`                | verified assertion, no matching account, no `CreatePolicy` said yes                                                                        |
| `ErrAccountLinkRequired`                   | an account exists for this email but was not created by this connection, or carries a different subject — set `LinkPolicy` to authorize it |
| `ErrEmailNotVerified` / `ErrMissingEmail`  | the provider asserted an unverified or absent address; believing it is the nOAuth defect                                                   |
| `ErrStateControlMissing`                   | your state store did not round-trip PKCE / binding / nonce — see the storage note below                                                    |
| `ErrMissingBinding` / `ErrBindingMismatch` | the callback did not reach the browser that started the flow                                                                               |

**You do not have to use the user store at all.** Leave `Config.UserStore` nil
and `HandleCallbackWithBinding` returns verified claims in
`CallbackResult.UserInfo` without touching a database. That is the shape v2
ships, and identity decisions stay where they belong — in your application.

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

They return **copies** on read, so mutating a `*User` you got from
`GetUserByID` changes nothing until you call `UpdateUser`. They are for
development, examples and tests; in v2 they move out of the public API into a
conformance harness you can point at your own backend.

#### What the library expects of your store

Four rules. Breaking any of them is silent, which is why they are stated here
and not only in the package docs:

1. **Store what you are given, byte for byte.** Password-reset and email
   verification tokens arrive already hashed, TOTP secrets may arrive encrypted
   and backup codes arrive hashed. Normalising, trimming, case-folding or
   re-hashing any of them breaks verification. Nothing the library persists is a
   value an attacker who reads your database can replay.
2. **Round-trip the whole record, not the fields you recognise.**
   `OIDCState.CodeVerifier`, `OIDCState.BindingHash`, `OIDCState.Nonce`,
   `User.ProviderSubject` and both `Metadata` maps each carry a security control
   the library later refuses to proceed without. A store that maps one column
   per known field and drops the rest fails every OIDC callback with
   `ErrStateControlMissing` — deliberately, because the alternative is running
   the flow with PKCE and the browser binding silently disarmed.
3. **Return the contract errors.** `ErrNotFound`, `ErrAlreadyExists`,
   `ErrExpired`, `ErrTokenRevoked`, `ErrInvalidBackupCode`, `ErrBackupCodeUsed`
   — directly or wrapped so `errors.Is` matches. Collapsing them into one opaque
   error forces the library to read a backend outage as a failed sign-in.
4. **Make single-use single-use.** `UseBackupCode` must check-and-consume
   atomically, `GetState` is one-time use, and `CreateSession` on a session ID
   that is still live must return `ErrAlreadyExists` rather than replacing it —
   256-bit IDs do not collide by chance.

`storage/conformance_test.go` is a hostile conformance suite that asserts all of
this against the in-memory stores. It is a `_test.go` file today, so you cannot
import it yet; read it as the specification, and in v2 it ships as a package you
can run against your own database.

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

Writing the cookie back out has a constructor, and you should use it: a
`CookieWriter` literal that omits `Secure` and `HttpOnly` compiles and ships a
session token readable by script over cleartext HTTP.

```go
// Secure and HttpOnly are not configurable here: they are always set. The
// __Host- prefix rules (no Domain, Path=/) are validated at construction
// rather than discovered when the browser silently drops the cookie.
writer, err := middleware.NewSecureCookieWriter(middleware.SecureCookieConfig{
    CookieName: "__Host-session",
    Path:       "/",
    MaxAge:     int((24 * time.Hour).Seconds()),
    // SameSite defaults to Lax.
})
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

**Every vendor constructor above is deprecated.** OIDC discovery configures any
OIDC-capable provider from its issuer URL alone, so these are configuration
rather than logic, and v2 removes them. Use `provider.NewOIDCProvider` (or
`NewOIDCProviderWithClient` to supply your own HTTP client) with the vendor's
issuer URL, and `NewOAuth2Provider` for a provider that issues no ID token.

Two vendor notes that affect security, not just style:

- **Microsoft.** `NewMicrosoftProvider` targets the multi-tenant `common`
  endpoint, which has no fixed issuer — every ID token carries the signing
  tenant's own GUID in `iss` — so it verifies the signature and audience but
  **not the issuer**. Any Entra ID tenant can therefore produce a token it
  accepts. Read `tid` out of `UserInfo.RawClaims` and check it against your own
  allow-list, or use `NewOIDCProvider` with
  `https://login.microsoftonline.com/<tenant-id>/v2.0`, which pins the issuer
  properly.
- **GitHub.** `GET /user` returns the _public profile_ email, which GitHub only
  lets you set to a verified address, and it is null for a user who publishes
  none. The extractor reports `EmailVerified` accordingly rather than asserting
  `true` unconditionally — so a user with no public email now arrives with no
  email and is refused by the OIDC client's verified-email requirement. For a
  hard guarantee, call `GET /user/emails` with the `user:email` scope in your
  own extract function and take the entry that is both `primary` and `verified`.

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
        RPDisplayName:   "My App",
        RPID:            "example.com",
        RPOrigins:       []string{"https://example.com"},
        UserStore:       userStore,
        CredentialStore: credentialStore,
        SessionStore:    sessionStore,

        // Milliseconds. Defaults to 300000 (five minutes) and is refused above
        // fifteen. It bounds three things at once so they cannot disagree: the
        // hint sent to the browser, the deadline inside the stored ceremony
        // record, and the TTL of the challenge itself.
        Timeout: 300000,
    })
    if err != nil {
        log.Fatal(err)
    }

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

Behaviour worth knowing before you wire this into a sign-in page:

- **A non-advancing signature counter is refused** with `ErrCredentialCloned`
  (which wraps `ErrAuthenticationFailed`, so an existing handler keeps refusing
  the sign-in). It is the only signal WebAuthn produces for a duplicated private
  key — everything else about a clone verifies perfectly. An authenticator that
  reports 0 on both sides is exempt, as the spec requires.
- **A failed counter write fails the ceremony** with `ErrSignCountNotPersisted`,
  which does _not_ wrap `ErrAuthenticationFailed`: the credential proved itself,
  your storage did not. Alert on it; a dropped counter write blinds the clone
  detector for that credential permanently.
- **`BeginLogin` discloses account existence.** It returns `ErrUserNotFound` for
  an unknown identifier and `ErrCredentialNotFound` for a known account with no
  passkey. That is an enumeration oracle on an unauthenticated endpoint, it is a
  known open issue (finding F-29 — the two sentinels are exported and callers
  branch on them, so collapsing them inside v1 would change behaviour
  invisibly), and until v2 closes it, rate-limit the endpoint and do not echo
  the distinction to the browser.

## Session Management

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/meysam81/go-auth/session"
    "github.com/meysam81/go-auth/storage"
)

func main() {
    sessionStore := storage.NewInMemorySessionStore()

    sessionManager, err := session.NewManager(session.Config{
        Store:      sessionStore,
        SessionTTL: 24 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Create session
    sess, err := sessionManager.Create(ctx, session.CreateSessionRequest{
        UserID:   "user123",
        Email:    "user@example.com",
        Provider: "google",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Rotate the identifier the moment the user's privileges change -- right
    // after sign-in, and after a password change. An attacker who fixed the
    // pre-authentication identifier in the victim's browser holds a dead one
    // afterwards; the old entry is deleted, not left to expire.
    rotated, err := sessionManager.Rotate(ctx, sess.ID)
    if err != nil {
        log.Fatal(err)
    }

    // Validate session
    sessionData, err := sessionManager.Validate(ctx, rotated.ID)
    if err != nil {
        log.Fatal(err)
    }
    _ = sessionData

    // Refresh session
    if err := sessionManager.Refresh(ctx, rotated.ID); err != nil {
        log.Fatal(err)
    }

    // Delete session (logout)
    if err := sessionManager.Delete(ctx, rotated.ID); err != nil {
        log.Fatal(err)
    }
}
```

Changing a password does **not** revoke sessions or refresh tokens — the library
does not know which of them belong to the user's other devices, and
`SessionStore` has no bulk delete until v2 (adding a method to a published
interface breaks every implementor). After a credential change, rotate the
current session and revoke refresh tokens yourself with
`jwt.TokenManager.RevokeAllUserTokens`.

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
- `examples/oidc/` - OIDC/SSO authentication example. It is the reference wiring
  for the hardened flow: browser binding on both legs, `Config.UserStore` left
  nil, and the application resolving verified claims to its own account record
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

The example is completely self-contained with its own `go.mod` and can be run
immediately, with no database and no external dependencies:

```bash
cd examples/complete
go run main.go -memory
```

Drop `-memory` to run against PostgreSQL (`-db`, or `DATABASE_URL`). Without
`JWT_SIGNING_KEY` it generates a 32-byte key from `crypto/rand` at startup and
says so — which means tokens do not survive a restart, and is exactly what you
must not do in production.

See [`examples/complete/README.md`](./examples/complete/README.md) for detailed setup instructions and API documentation.

## Production Deployment

### Security Best Practices

1. **Use strong signing keys.** `NewTokenManager` enforces the RFC 7518 §3.2
   floor — 32 bytes for HS256, 48 for HS384, 64 for HS512 — and refuses a
   shorter secret at startup.

   ```go
   import "crypto/rand" // never math/rand

   signingKey := make([]byte, 32)
   if _, err := rand.Read(signingKey); err != nil {
       return fmt.Errorf("generate signing key: %w", err)
   }
   ```

   For asymmetric signing, set `Config.PrivateKey` (a `crypto.Signer`) rather
   than `SigningKey`; the constructor validates the key against the signing
   method instead of failing on the first token you mint.

2. **Use HTTPS in production**
   - Build session cookies with `middleware.NewSecureCookieWriter`, which sets
     `Secure` and `HttpOnly` and validates `__Host-` prefix rules. The
     zero-value `CookieWriter` sets neither.
   - Configure proper CORS policies

3. **Store secrets in environment variables**

   ```go
   signingKey, err := hex.DecodeString(os.Getenv("JWT_SIGNING_KEY"))
   if err != nil {
       return fmt.Errorf("decode signing key: %w", err)
   }
   ```

4. **Implement rate limiting**
   - Limit login attempts
   - Use exponential backoff
   - `webauthn.BeginLogin` and any account-lookup endpoint need this
     particularly: see the enumeration note under
     [WebAuthn/Passkeys](#webauthnpasskeys)

5. **Use persistent storage**
   - Implement storage interfaces with PostgreSQL, MySQL, etc.
   - Use Redis for sessions and ephemeral data
   - Read [what the library expects of your store](#what-the-library-expects-of-your-store)
     first; two of the four rules are invisible when broken

6. **Encrypt TOTP secrets at rest.** Set `totp.Config.Cipher`. Without it, one
   read of your credential table is a working second factor for every enrolled
   user — which is exactly what the second factor exists to prevent. Backup
   codes are hashed either way.

7. **Enforce the second factor at the sign-in call.** The default
   (`basic.EnforceMFA`) makes `Authenticate` return `ErrMFARequired` for a user
   with a confirmed factor; handle it by collecting a code, not by treating it
   as a failed password.

8. **Bound outbound HTTP to identity providers.** The default client has a
   timeout and a response-size cap but no address policy. When the issuer URL is
   operator-supplied, pass an `HTTPClient` whose dialer refuses loopback,
   link-local and private ranges — otherwise the issuer URL is an SSRF primitive
   into your network. That policy is infrastructure's, not this library's.

9. **Use the bound OIDC entry points.** `GetAuthorizationURLWithBinding` +
   `HandleCallbackWithBinding`. The unbound pair still compiles and still leaves
   login CSRF open.

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
- `github.com/pquerna/otp` - TOTP (RFC 6238)

All dependencies are production-ready, well-maintained, and widely used. The set
is enforced by a `depguard` rule rather than by discipline: every module here is
either a cryptographic primitive we must not reimplement or a protocol
implementation, and anything else expands the attack surface of every consumer.

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

**`NewTokenManager` fails at startup with `ErrInvalidKeyConfig`**

- The HMAC secret is too short. HS256 needs 32 bytes, HS384 48, HS512 64
  (RFC 7518 §3.2). A passphrase that worked in v1.1.1 is now refused, on purpose
- Or an asymmetric `SigningMethod` was paired with a `[]byte` `SigningKey`. Use
  `Config.PrivateKey`; `SigningKey` is HMAC-only and cannot carry an RSA or
  ECDSA key

**JWT token validation fails**

- Ensure the signing key is the same for generation and validation
- Check that the token hasn't expired (default: 15 minutes for access tokens)
- Verify the token is being passed correctly in the `Authorization: Bearer <token>` header
- If `Config.Issuer` or `Config.Audience` is set, they are **required** at
  validation. A token minted before you set them will not verify
- A **refresh token is rejected** as a bearer credential. Use
  `RefreshAccessToken`; `ValidateToken` means `ValidateAccessToken` now

**Sign-in returns `basic.ErrMFARequired`**

Working as intended: the user holds a confirmed second factor and
`Authenticate` refuses a password-only sign-in. Collect a code and call
`AuthenticateWithTOTP`, or set
`Config.RequireMFAWhenEnrolled: basic.AllowPasswordOnly` if you run your own
second-factor step. Do not report it to the user as a bad password.

**`totp.ErrPendingConfirmation` after enrolling**

The factor is stored but not armed. Call `Confirm(ctx, userID, code)` with a
code from the user's app; `IsPending` tells you an enrolment is waiting.
`Disable` cancels it so the user can start over.

**TOTP codes always invalid**

- Ensure server time is synchronized (TOTP is time-based)
- Check that the enrolment was confirmed (above)
- If you configured a `Cipher` after users had already enrolled, existing rows
  are plaintext and a configured `Cipher` refuses to read them — open the
  migration window with `Config.AllowLegacyPlaintextSecrets`
- `ErrCodeReused` is not "invalid": that exact code already authenticated inside
  its window, which RFC 6238 §5.2 requires be refused
- Verify the user is using a compatible authenticator app (Google Authenticator, Authy, etc.)

**Backup codes come back as gibberish from the store**

They are digests. Backup codes are hashed unconditionally, so the plaintext
exists only in `Secret.BackupCodes` at enrolment and in the return of
`RegenerateBackupCodes`. Display them once; there is no way to recover them.

**Every OIDC sign-in fails with `ErrStateControlMissing`**

Your `OIDCStateStore` is not round-tripping the whole record. The library writes
PKCE, the browser binding and the nonce to both typed fields and mirrored
`Metadata` keys, and refuses a record that comes back without either copy rather
than proceeding with the control disarmed. Persist `Metadata` verbatim,
including keys you do not recognise.

**New OIDC users get `ErrAccountCreationRefused`**

`Config.CreatePolicy` is nil, and a nil policy refuses. Set
`authoidc.AllowAccountCreation` to restore the old behaviour, or supply a policy
that checks the asserted domain against the connection.

**An existing user gets `ErrAccountLinkRequired`**

An account with that email address exists but was not created by this
connection — most often a password account (`Provider: "basic"`) whose owner is
now using SSO. Matching on email alone is the nOAuth defect, so it is refused.
Authorize it deliberately with `Config.LinkPolicy`.

**WebAuthn registration fails**

- WebAuthn requires HTTPS in production (localhost works for development)
- Ensure `RPID` matches your domain exactly
- Check that `RPOrigins` includes the full origin URL (e.g., `https://example.com`)
- `Config.Timeout` is in **milliseconds** and is refused above 15 minutes. It
  used to be handed to the store as a raw `time.Duration`, which made the
  documented "5 min" 300 nanoseconds; if you were compensating for that, stop

**WebAuthn login fails with `ErrCredentialCloned`**

The assertion's signature counter did not advance past the stored value, which
is the only signal WebAuthn produces for a duplicated private key. Treat it as a
security event, not as a bad password. If it fires for every user of one
authenticator model that reports 0, that case is already exempt — check that
your store is persisting `SignCount` rather than discarding the update.

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
