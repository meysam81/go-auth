# CLAUDE.md

This file provides guidance for AI assistants working on the go-auth project.

## Project Overview

go-auth is a comprehensive, modular, and production-ready authentication library for Go applications. It provides multiple authentication methods with a storage-agnostic design following the Google Go Style Guide.

## Build & Test Commands

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests for a specific package
go test ./auth/jwt/...

# Run linter
golangci-lint run

# Build examples
go build ./examples/basic
go build ./examples/jwt
go build ./examples/oidc
```

## Project Structure

```
go-auth/
├── audit/          # Audit logging (SOC2/GDPR/HIPAA compliant)
├── auth/
│   ├── basic/      # Username/password authentication (bcrypt)
│   ├── jwt/        # JWT access + refresh tokens
│   ├── oidc/       # OIDC/OAuth2 SSO client
│   ├── totp/       # Two-factor authentication (RFC 6238)
│   └── webauthn/   # WebAuthn/Passkey authentication
├── examples/       # Working examples for each auth method
├── middleware/     # HTTP middleware (stdlib compatible)
├── provider/       # 10+ OAuth2/OIDC providers
├── session/        # Session management
└── storage/        # Storage interfaces and in-memory implementations
```

## Code Style Guidelines

### General
- Follow the Google Go Style Guide
- Minimal dependencies - prefer stdlib where possible
- Interface-based design for testability
- All public APIs must be documented

### Error Handling
- Define package-level sentinel errors (e.g., `ErrInvalidCode`, `ErrNotEnabled`)
- Wrap errors with context using `fmt.Errorf("context: %w", err)`
- Check for `storage.ErrNotFound` for missing resources

### Naming Conventions
- Packages: lowercase, single-word (e.g., `audit`, `totp`)
- Interfaces: descriptive names ending in `-er` where appropriate (e.g., `UserStore`, `AuditLogger`)
- Constructors: `NewXxx(config Config) (*Xxx, error)`
- Config structs: named `Config` within each package

### Configuration Pattern
```go
type Config struct {
    RequiredField SomeType
    OptionalField int // defaults in constructor
}

func NewManager(cfg Config) (*Manager, error) {
    if cfg.RequiredField == nil {
        return nil, errors.New("required field is required")
    }
    if cfg.OptionalField == 0 {
        cfg.OptionalField = DefaultValue
    }
    // ...
}
```

## Authentication Methods

### Basic Auth (`auth/basic`)
- Username/password with bcrypt hashing
- Registration and authentication flows

### JWT (`auth/jwt`)
- Access and refresh token pairs
- Configurable TTLs
- Token revocation support

### TOTP (`auth/totp`)
- RFC 6238 compliant
- Backup codes support
- QR code URL generation

### WebAuthn (`auth/webauthn`)
- Passkey/FIDO2 support
- Registration and login flows

### OIDC/OAuth2 (`auth/oidc`)
- 10+ providers: Google, GitHub, Microsoft, GitLab, Auth0, Okta, Apple, Discord, Slack, LinkedIn
- State management for CSRF protection

## Storage Interfaces

The library is storage-agnostic. Key interfaces in `storage/`:
- `UserStore` - User CRUD operations
- `CredentialStore` - Password hashes, WebAuthn credentials, TOTP secrets
- `SessionStore` - Session management
- `TokenStore` - JWT token storage/revocation
- `OIDCStateStore` - OAuth2 state management

In-memory implementations are provided for development/testing.

## Middleware

HTTP middleware in `middleware/` package:
- `BasicAuthMiddleware` - Basic auth validation
- `JWTMiddleware` - JWT token validation
- `SessionMiddleware` - Session validation

Token extractors:
- `HeaderExtractor` - Extract from Authorization header
- `CookieExtractor` - Extract from cookies
- `MultiExtractor` - Try multiple sources

## Audit Logging

The `audit/` package provides compliance-ready logging:
- Event types: auth, token, session, user operations
- PII redaction support
- Wrappers for auth components (e.g., `NewBasicAuthWrapper`)

## Testing

- Use in-memory storage implementations for tests
- Test files follow `*_test.go` naming
- Use table-driven tests where appropriate
- Mock interfaces for unit testing

## Dependencies

Core dependencies (keep minimal):
- `golang.org/x/crypto` - Password hashing
- `github.com/golang-jwt/jwt/v5` - JWT
- `github.com/go-webauthn/webauthn` - WebAuthn
- `github.com/coreos/go-oidc/v3` - OIDC
- `golang.org/x/oauth2` - OAuth2
- `github.com/pquerna/otp` - TOTP

## Version

- Go version: 1.24.7
- Current release: 1.0.1
