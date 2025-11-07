// Package storage provides interfaces for persistent and ephemeral data storage.
// Users of the go-auth library must implement these interfaces to provide
// their preferred storage backends (e.g., PostgreSQL, SQLite, Redis).
package storage

import (
	"context"
	"time"
)

// UserStore defines the interface for persistent user identity storage.
// Implementations should handle user CRUD operations and credential lookups.
type UserStore interface {
	// CreateUser creates a new user with the given identity.
	CreateUser(ctx context.Context, user *User) error

	// GetUserByID retrieves a user by their unique identifier.
	GetUserByID(ctx context.Context, id string) (*User, error)

	// GetUserByEmail retrieves a user by their email address.
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserByUsername retrieves a user by their username.
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// UpdateUser updates an existing user's information.
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser removes a user by their ID.
	DeleteUser(ctx context.Context, id string) error
}

// CredentialStore defines the interface for storing authentication credentials.
// Different auth methods may store different types of credentials.
type CredentialStore interface {
	// StorePasswordHash stores a password hash for a user.
	StorePasswordHash(ctx context.Context, userID string, hash []byte) error

	// GetPasswordHash retrieves the password hash for a user.
	GetPasswordHash(ctx context.Context, userID string) ([]byte, error)

	// StoreWebAuthnCredential stores a WebAuthn credential for a user.
	StoreWebAuthnCredential(ctx context.Context, userID string, credential *WebAuthnCredential) error

	// GetWebAuthnCredentials retrieves all WebAuthn credentials for a user.
	GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error)

	// UpdateWebAuthnCredential updates an existing WebAuthn credential (e.g., counter).
	UpdateWebAuthnCredential(ctx context.Context, credential *WebAuthnCredential) error

	// DeleteWebAuthnCredential removes a WebAuthn credential.
	DeleteWebAuthnCredential(ctx context.Context, credentialID []byte) error
}

// SessionStore defines the interface for ephemeral session storage.
// This is typically implemented using in-memory stores, Redis, or similar.
type SessionStore interface {
	// CreateSession creates a new session with the given ID and data.
	// The session should expire after the specified TTL.
	CreateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error

	// GetSession retrieves session data by session ID.
	GetSession(ctx context.Context, sessionID string) (*SessionData, error)

	// UpdateSession updates an existing session's data and optionally extends TTL.
	UpdateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error

	// DeleteSession removes a session by ID.
	DeleteSession(ctx context.Context, sessionID string) error

	// RefreshSession extends the TTL of an existing session.
	RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error
}

// TokenStore defines the interface for storing tokens (JWT refresh tokens, OIDC tokens).
// This can be ephemeral or persistent depending on requirements.
type TokenStore interface {
	// StoreRefreshToken stores a refresh token for a user.
	StoreRefreshToken(ctx context.Context, userID string, tokenID string, expiresAt time.Time) error

	// ValidateRefreshToken checks if a refresh token is valid and not revoked.
	ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) // Returns userID

	// RevokeRefreshToken revokes a refresh token.
	RevokeRefreshToken(ctx context.Context, tokenID string) error

	// RevokeAllUserTokens revokes all refresh tokens for a user.
	RevokeAllUserTokens(ctx context.Context, userID string) error
}

// OIDCStateStore defines the interface for storing OIDC flow state (ephemeral).
// Used to prevent CSRF attacks during OAuth2/OIDC flows.
type OIDCStateStore interface {
	// StoreState stores an OIDC state with associated data.
	StoreState(ctx context.Context, state string, data *OIDCState, ttl time.Duration) error

	// GetState retrieves and deletes the state (one-time use).
	GetState(ctx context.Context, state string) (*OIDCState, error)

	// DeleteState explicitly deletes a state.
	DeleteState(ctx context.Context, state string) error
}

// User represents a user identity in the system.
type User struct {
	ID        string                 `json:"id"`
	Email     string                 `json:"email"`
	Username  string                 `json:"username,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Provider  string                 `json:"provider,omitempty"` // e.g., "local", "google", "github"
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // Extensible user metadata
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// WebAuthnCredential represents a stored WebAuthn/Passkey credential.
type WebAuthnCredential struct {
	ID              []byte                 `json:"id"`                // Credential ID
	PublicKey       []byte                 `json:"public_key"`        // Public key
	AttestationType string                 `json:"attestation_type"`  // Attestation type
	AAGUID          []byte                 `json:"aaguid"`            // Authenticator AAGUID
	SignCount       uint32                 `json:"sign_count"`        // Signature counter
	UserID          string                 `json:"user_id"`           // Associated user ID
	Transports      []string               `json:"transports"`        // Authenticator transports
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// SessionData represents session information stored in ephemeral storage.
type SessionData struct {
	UserID    string                 `json:"user_id"`
	Email     string                 `json:"email,omitempty"`
	Provider  string                 `json:"provider,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// OIDCState represents state stored during an OIDC flow.
type OIDCState struct {
	RedirectURL string                 `json:"redirect_url,omitempty"` // Post-auth redirect
	Nonce       string                 `json:"nonce,omitempty"`        // OIDC nonce
	Provider    string                 `json:"provider"`               // Provider name
	Metadata    map[string]interface{} `json:"metadata,omitempty"`     // Additional state data
	CreatedAt   time.Time              `json:"created_at"`
}
