# go-auth - Claude Context

## Project Overview

`go-auth` is a comprehensive, modular, and production-ready authentication library for Go applications. It provides a unified interface for multiple authentication methods while remaining framework-agnostic and storage-agnostic.

**Key Philosophy**: Interface-based design for maximum flexibility and testability.

## Project Structure

```
go-auth/
├── auth/               # Authentication method implementations
│   ├── basic/         # Username/password authentication with bcrypt
│   ├── jwt/           # JWT token generation and validation
│   ├── oidc/          # OIDC/OAuth2 client implementation
│   └── webauthn/      # WebAuthn/Passkey authentication
├── provider/          # SSO/OAuth2 provider implementations
│   ├── google.go
│   ├── github.go
│   ├── microsoft.go
│   ├── gitlab.go
│   ├── auth0.go
│   ├── okta.go
│   ├── apple.go
│   ├── linkedin.go
│   ├── discord.go
│   └── slack.go
├── middleware/        # HTTP middleware (stdlib compatible)
│   ├── basic.go       # Basic auth middleware
│   ├── jwt.go         # JWT auth middleware
│   ├── session.go     # Session-based auth middleware
│   └── middleware.go  # Common utilities and extractors
├── session/           # Session management
│   └── session.go
├── storage/           # Storage interfaces and in-memory implementations
│   ├── storage.go     # Interface definitions
│   └── memory.go      # In-memory implementations for testing
└── examples/          # Working examples
    ├── basic/
    ├── jwt/
    └── oidc/
```

## Core Concepts

### 1. Storage Interfaces

The library is **storage-agnostic**. All data access is through interfaces defined in `storage/storage.go`:

- **UserStore**: Persistent user identity storage (CRUD operations)
- **CredentialStore**: Authentication credentials (password hashes, WebAuthn keys)
- **SessionStore**: Ephemeral session data (typically Redis/in-memory)
- **TokenStore**: JWT refresh token management (revocation, validation)
- **OIDCStateStore**: OIDC flow state (CSRF protection)

**In-memory implementations** are provided in `storage/memory.go` for development/testing. Production users should implement these interfaces with their preferred database.

### 2. Authentication Methods

Each auth method is self-contained and can be used independently:

#### Basic Authentication (`auth/basic/`)
- Username/password with bcrypt hashing
- Register, login, password verification
- Requires: `UserStore`, `CredentialStore`

#### JWT Authentication (`auth/jwt/`)
- Access + refresh token pattern
- Token generation, validation, refresh, revocation
- Configurable TTLs and signing algorithms
- Requires: `UserStore`, `TokenStore`

#### OIDC/OAuth2 (`auth/oidc/`)
- Support for 10+ providers (Google, GitHub, Microsoft, etc.)
- Authorization URL generation, callback handling
- User info extraction from provider tokens
- Requires: `UserStore`, `OIDCStateStore`

#### WebAuthn/Passkeys (`auth/webauthn/`)
- FIDO2 compliant passkey authentication
- Registration and authentication flows
- Requires: `UserStore`, `CredentialStore`, session storage for challenges

### 3. Middleware

HTTP middleware is isolated in the `middleware/` package and compatible with any framework using `http.Handler`.

**Token Extractors**:
- `HeaderExtractor`: Extract from Authorization header (Bearer tokens)
- `CookieExtractor`: Extract from cookies
- `MultiExtractor`: Try multiple sources in order

**Middleware Types**:
- `BasicAuthMiddleware`: Validates Basic Auth credentials
- `JWTMiddleware`: Validates JWT access tokens
- `SessionMiddleware`: Validates session tokens

**Context Helpers**:
- `GetUser(r *http.Request)`: Retrieve authenticated user from context
- `GetClaims(r *http.Request)`: Retrieve JWT claims from context

### 4. Providers

SSO provider implementations in `provider/` package implement the `Provider` interface:

```go
type Provider interface {
    Name() string
    GetOAuth2Config() *oauth2.Config
    GetOIDCProvider() *oidc.Provider
    ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
}
```

**OIDC Providers**: Google, Microsoft, GitLab, Auth0, Okta, Apple
**OAuth2 Providers**: GitHub, LinkedIn, Discord, Slack

## Development Guidelines

### Code Style
- Follow **Google Go Style Guide**
- Use meaningful variable names
- Document all exported types and functions
- Keep functions focused and testable

### Testing
- Use interface-based mocks for testing
- In-memory storage implementations are perfect for unit tests
- Test error cases and edge conditions
- Example test structure:

```go
func TestFeature(t *testing.T) {
    // Setup mock storage
    userStore := storage.NewInMemoryUserStore()

    // Create authenticator with test config
    auth, err := NewAuthenticator(Config{
        UserStore: userStore,
        // ...
    })

    // Test the feature
}
```

### Error Handling
- Return errors, don't panic
- Use `storage.ErrNotFound` for missing entities
- Wrap errors with context: `fmt.Errorf("operation failed: %w", err)`
- Validate inputs early

### Security Considerations
- **Never log sensitive data**: passwords, tokens, session IDs
- **Use bcrypt for passwords**: minimum cost factor 10
- **Validate all inputs**: email format, password strength
- **Use secure random for tokens**: `crypto/rand`
- **Set appropriate TTLs**: short for access tokens, longer for refresh tokens
- **HTTPS only in production**: secure cookies, proper CORS

## Common Patterns

### Creating an Authenticator

```go
// 1. Initialize storage
userStore := storage.NewInMemoryUserStore()
credStore := storage.NewInMemoryCredentialStore()

// 2. Create authenticator with config
auth, err := basic.NewAuthenticator(basic.Config{
    UserStore:       userStore,
    CredentialStore: credStore,
})

// 3. Use the authenticator
user, err := auth.Register(ctx, basic.RegisterRequest{
    Email:    "user@example.com",
    Password: "secure-password",
})
```

### Adding a New Provider

1. Create file in `provider/` directory
2. Implement the `Provider` interface
3. Handle provider-specific user info extraction
4. Add constructor function (e.g., `NewProviderName()`)
5. Update README with provider details

### Implementing Custom Storage

```go
type PostgresUserStore struct {
    db *sql.DB
}

func (s *PostgresUserStore) CreateUser(ctx context.Context, user *storage.User) error {
    _, err := s.db.ExecContext(ctx,
        "INSERT INTO users (id, email, name, ...) VALUES ($1, $2, $3, ...)",
        user.ID, user.Email, user.Name,
    )
    return err
}

// Implement all UserStore interface methods...
```

## Dependencies

- `golang.org/x/crypto`: Bcrypt password hashing
- `github.com/golang-jwt/jwt/v5`: JWT implementation
- `github.com/go-webauthn/webauthn`: WebAuthn/FIDO2
- `github.com/coreos/go-oidc/v3`: OIDC client
- `golang.org/x/oauth2`: OAuth2 flows

**Dependency Philosophy**: Minimal, well-maintained, production-ready libraries only.

## Testing Commands

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...

# Run linter (golangci-lint)
golangci-lint run

# Run specific package tests
go test ./auth/basic/
go test ./middleware/
```

## Common Tasks

### Running Examples

```bash
cd examples/basic && go run main.go
cd examples/jwt && go run main.go
cd examples/oidc && go run main.go
```

### Building

```bash
# Verify all packages compile
go build ./...

# Tidy dependencies
go mod tidy

# Vendor dependencies (if needed)
go mod vendor
```

### Adding Tests

1. Create `*_test.go` file alongside source
2. Use table-driven tests for multiple cases
3. Test success and error paths
4. Use in-memory storage for unit tests
5. Mock external dependencies (OAuth providers, etc.)

## Architecture Decisions

### Why Storage Interfaces?
- **Flexibility**: Users choose their own database
- **Testability**: Easy to mock for unit tests
- **No lock-in**: Can migrate databases without changing auth code
- **Performance**: Users can optimize storage for their use case

### Why Separate Middleware?
- **Framework-agnostic**: Works with stdlib, chi, gorilla, gin, echo, etc.
- **Optional**: Core auth logic doesn't depend on HTTP
- **Flexible**: Users can customize token extraction and error handling

### Why Multiple Auth Methods?
- **Different use cases**: APIs need JWT, web apps need sessions, modern apps use passkeys
- **Composable**: Can mix methods in same application
- **Progressive enhancement**: Start with basic, add SSO later

## Troubleshooting

### Common Issues

1. **Storage errors**: Ensure storage interface implementations handle context cancellation
2. **Token validation failures**: Check signing key consistency and expiration times
3. **OIDC flow errors**: Verify redirect URLs match provider configuration
4. **WebAuthn issues**: Ensure RPID matches domain and origins are correct

### Debug Tips

- Enable verbose logging in tests with `t.Log()`
- Check token contents with `jwt.io`
- Verify OIDC discovery: `curl https://provider/.well-known/openid-configuration`
- Use browser dev tools for WebAuthn debugging

## Contributing

1. **Read the code**: Understand the pattern before adding features
2. **Write tests first**: TDD ensures good interface design
3. **Keep it minimal**: Don't add dependencies without discussion
4. **Document changes**: Update README and godoc comments
5. **Follow conventions**: Match existing code style

## Future Enhancements

The project roadmap includes:
- SAML support (if requested)
- Built-in rate limiting middleware
- Audit logging interface
- Password reset flow helpers
- Email verification helpers
- TOTP two-factor authentication
- Built-in OIDC provider/server

When adding features, maintain the core principles:
- Storage-agnostic
- Framework-agnostic
- Interface-based
- Minimal dependencies
- Production-ready
