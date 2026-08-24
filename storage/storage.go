// Package storage provides interfaces for persistent and ephemeral data storage.
// Users of the go-auth library must implement these interfaces to provide
// their preferred storage backends (e.g., PostgreSQL, SQLite, Redis).
//
// # What the library hands an implementation
//
// The library never asks a store to hold a value that would be directly
// replayable by an attacker who reads the store. Password reset and email
// verification tokens arrive already hashed (finding F-05), TOTP secrets may
// arrive encrypted and backup codes arrive hashed (finding F-06), and password
// hashes are bcrypt digests. An implementation must persist and return the bytes
// it is given verbatim: interpreting, normalising, trimming, case-folding or
// re-encoding any of them breaks verification, and re-hashing an already-hashed
// token breaks it silently.
//
// # Every field is load-bearing
//
// A store must round-trip a WHOLE record, not the fields it recognizes. Several
// of the fields below are security controls: OIDCState.CodeVerifier,
// OIDCState.BindingHash, OIDCState.Nonce and User.ProviderSubject each carry a
// value the library will later refuse to proceed without, and Metadata carries
// the library's own reserved keys alongside the application's. A backend that
// maps a column per field it knows about, and drops the rest, does not fail
// visibly: the record comes back looking valid with a control quietly missing
// from it.
//
// The library defends what it can. It writes each OIDC flow control to both its
// typed field and a mirrored key in Metadata, and refuses a state record that
// comes back without either copy, so a partial store fails closed rather than
// authenticating without PKCE or without a browser binding. That defense only
// works if a store persists at least one of the two: a store that keeps neither
// stops every sign-in. A store must therefore persist Metadata verbatim,
// including keys it does not recognize, and must persist any field added by a
// later release rather than reconstructing the struct from a known column list.
//
// # In-memory implementations
//
// The InMemory* types in this package implement every interface below and exist
// for development, examples and tests. They are not production stores. In v2
// they move to a conformance-harness package that a downstream implementation
// can run against its own backend.
package storage

import (
	"context"
	"errors"
	"time"
)

// Contract errors. An implementation of any interface in this package is
// expected to return these (directly, or wrapped so that errors.Is matches) so
// the library can tell "absent" from "expired" from "broken backend". A store
// that collapses them into one opaque error forces the library to treat a
// backend outage as a failed authentication, or worse, the reverse.
var (
	// ErrNotFound is returned when a requested entity is not found in storage.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists is returned when attempting to create an entity that already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrExpired is returned when a session or token has expired.
	ErrExpired = errors.New("expired")

	// ErrTokenRevoked is returned when a refresh token exists but has been
	// revoked. It is distinct from ErrExpired because revocation is a decision
	// somebody made and an audit trail wants to record it as such.
	ErrTokenRevoked = errors.New("token revoked")

	// ErrInvalidBackupCode is returned when a submitted backup code matches no
	// code on record for the user.
	ErrInvalidBackupCode = errors.New("invalid backup code")

	// ErrBackupCodeUsed is returned when a submitted backup code matches a code
	// on record that has already been consumed. Callers must not surface the
	// distinction between this and ErrInvalidBackupCode to an unauthenticated
	// user: it reports whether a given code was ever issued.
	ErrBackupCodeUsed = errors.New("backup code already used")
)

// UserStore defines the interface for persistent user identity storage.
// Implementations should handle user CRUD operations and credential lookups.
//
// In v2 no go-auth constructor will require this interface. Creating, looking
// up and mutating user records is the application's decision, not a primitive;
// the four auth packages that reach for it today are the coupling behind
// finding F-01.
type UserStore interface {
	// CreateUser creates a new user with the given identity.
	//
	// ProviderSubject and Metadata must be persisted and returned as given. For
	// a federated account they are the two copies of the one value a later
	// assertion is checked against, and an account stored without either can
	// never be matched to the identity that created it.
	CreateUser(ctx context.Context, user *User) error

	// GetUserByID retrieves a user by their unique identifier.
	GetUserByID(ctx context.Context, id string) (*User, error)

	// GetUserByEmail retrieves a user by their email address.
	//
	// A match on email alone is not proof of identity. An implementation must not
	// treat this as an identity resolution primitive for federated sign-in; see
	// finding F-01 (the CVE-2023-28131 "nOAuth" class).
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserByUsername retrieves a user by their username.
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// UpdateUser updates an existing user's information.
	//
	// It is also the path the OIDC client uses to record a provider subject on
	// an account created before subjects were recorded at all, so an
	// implementation that ignores changes to ProviderSubject or Metadata leaves
	// those accounts permanently unpinned. A failure here fails the sign-in
	// rather than being absorbed, so it must be reported and not swallowed.
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser removes a user by their ID.
	DeleteUser(ctx context.Context, id string) error
}

// CredentialStore defines the interface for storing authentication credentials.
// Different auth methods may store different types of credentials.
//
// Every secret reaching this interface has already been hashed or encrypted by
// the library. Nothing an implementation persists is a bearer value that can be
// replayed against the library by whoever reads the table.
type CredentialStore interface {
	// StorePasswordHash stores a password hash for a user.
	// The value is a bcrypt digest and must be stored byte-for-byte.
	StorePasswordHash(ctx context.Context, userID string, hash []byte) error

	// GetPasswordHash retrieves the password hash for a user.
	// It returns ErrNotFound when the user has no password credential.
	GetPasswordHash(ctx context.Context, userID string) ([]byte, error)

	// StoreWebAuthnCredential stores a WebAuthn credential for a user.
	//
	// Credential IDs are globally unique by construction. An implementation must
	// reject a credential ID that is already on record for a different user
	// rather than reassigning it, since an authenticator that can claim an
	// existing credential ID can claim the account behind it.
	StoreWebAuthnCredential(ctx context.Context, userID string, credential *WebAuthnCredential) error

	// GetWebAuthnCredentials retrieves all WebAuthn credentials for a user.
	// It returns an empty slice, not ErrNotFound, for a user with none.
	GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error)

	// UpdateWebAuthnCredential updates an existing WebAuthn credential (e.g., counter).
	//
	// The signature counter is the only signal a cloned authenticator produces,
	// so an implementation must persist the value it is given rather than
	// discarding an update it considers uninteresting.
	UpdateWebAuthnCredential(ctx context.Context, credential *WebAuthnCredential) error

	// DeleteWebAuthnCredential removes a WebAuthn credential.
	DeleteWebAuthnCredential(ctx context.Context, credentialID []byte) error

	// StorePasswordResetToken stores a password reset token for a user.
	//
	// The token argument is a HASH of the value that was emailed to the user, not
	// the bearer value itself (finding F-05, CWE-522). The library hashes before
	// calling and hashes again before lookup, so a read of this table does not
	// yield anything an attacker can present. Store it verbatim and do not hash
	// it again.
	StorePasswordResetToken(ctx context.Context, userID string, token string, expiresAt time.Time) error

	// ValidatePasswordResetToken validates a password reset token and returns the associated user ID.
	//
	// The token argument is the same hash that StorePasswordResetToken received.
	// Implementations must return ErrNotFound for an unknown token and ErrExpired
	// for one past expiresAt, and must not return a user ID for an expired row.
	ValidatePasswordResetToken(ctx context.Context, token string) (string, error)

	// DeletePasswordResetToken deletes a password reset token, identified by the
	// same hash StorePasswordResetToken received. Deleting an absent token is not
	// an error.
	DeletePasswordResetToken(ctx context.Context, token string) error

	// StoreEmailVerificationToken stores an email verification token for a user.
	//
	// As with password reset tokens, the token argument is a HASH of the emailed
	// value (finding F-05). Store it verbatim.
	StoreEmailVerificationToken(ctx context.Context, userID string, token string, expiresAt time.Time) error

	// ValidateEmailVerificationToken validates an email verification token and returns the associated user ID.
	// The token argument is the same hash StoreEmailVerificationToken received.
	ValidateEmailVerificationToken(ctx context.Context, token string) (string, error)

	// DeleteEmailVerificationToken deletes an email verification token, identified
	// by the same hash StoreEmailVerificationToken received.
	DeleteEmailVerificationToken(ctx context.Context, token string) error

	// StoreTOTPSecret stores a TOTP secret and backup codes for a user.
	//
	// The secret may be CIPHERTEXT rather than the base32 shared secret: when the
	// TOTP manager is configured with a cipher it encrypts before calling
	// (finding F-06, CWE-522). The backup codes are hashes, never the codes shown
	// to the user. An implementation must treat both as opaque strings, store
	// them verbatim, and return them unchanged from GetTOTPSecret -- any
	// normalisation destroys the ability to decrypt or compare.
	//
	// Calling this again for a user replaces the whole enrolment, including the
	// used/unused state of every backup code.
	StoreTOTPSecret(ctx context.Context, userID string, secret string, backupCodes []string) error

	// GetTOTPSecret retrieves the TOTP secret and unused backup codes for a user.
	//
	// It returns exactly what StoreTOTPSecret was given -- ciphertext if the
	// secret was encrypted, hashes for the backup codes -- and only the codes not
	// yet consumed. It returns ErrNotFound when the user has no enrolment.
	GetTOTPSecret(ctx context.Context, userID string) (secret string, backupCodes []string, err error)

	// DeleteTOTPSecret deletes the TOTP secret and backup codes for a user.
	DeleteTOTPSecret(ctx context.Context, userID string) error

	// UseBackupCode marks a backup code as used. Returns an error if the code is invalid or already used.
	//
	// The code argument is the hash, in the same encoding StoreTOTPSecret
	// received. The check-and-consume must be ATOMIC: two concurrent callers
	// presenting the same code must not both succeed, or the single-use property
	// that makes a backup code safe to write on paper is gone. Return
	// ErrInvalidBackupCode for an unknown code, ErrBackupCodeUsed for a consumed
	// one, and ErrNotFound when the user has no enrolment.
	UseBackupCode(ctx context.Context, userID string, code string) error
}

// SessionStore defines the interface for ephemeral session storage.
// This is typically implemented using in-memory stores, Redis, or similar.
//
// Session IDs are unguessable values minted by session.Manager with 256 bits of
// entropy. An implementation must not truncate, case-fold or otherwise
// canonicalise them, and must not derive one itself.
type SessionStore interface {
	// CreateSession creates a new session with the given ID and data.
	// The session should expire after the specified TTL.
	//
	// An existing entry for the same session ID must be reported as
	// ErrAlreadyExists rather than silently replaced. Two 256-bit random IDs do
	// not collide, so a collision means either a defect or an ID that came from
	// somewhere other than session.Manager -- the shape of a session fixation
	// attempt (finding F-14, CWE-384).
	CreateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error

	// GetSession retrieves session data by session ID.
	//
	// It returns ErrNotFound for an unknown ID and ErrExpired for one whose TTL
	// has passed. Expired data must never be returned alongside a nil error.
	GetSession(ctx context.Context, sessionID string) (*SessionData, error)

	// UpdateSession updates an existing session's data and optionally extends TTL.
	// It must not resurrect an expired session; return ErrExpired instead.
	UpdateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error

	// DeleteSession removes a session by ID. Deleting an absent session is not an
	// error. This is the revocation path: an implementation that cannot delete
	// must report the failure rather than swallow it.
	DeleteSession(ctx context.Context, sessionID string) error

	// RefreshSession extends the TTL of an existing session.
	// It must not resurrect an expired session; return ErrExpired instead.
	RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error
}

// TokenStore defines the interface for storing tokens (JWT refresh tokens, OIDC tokens).
// This can be ephemeral or persistent depending on requirements.
//
// Only the token ID (the jti claim) is stored, never the signed token, so a read
// of this table yields nothing presentable.
type TokenStore interface {
	// StoreRefreshToken stores a refresh token for a user.
	StoreRefreshToken(ctx context.Context, userID string, tokenID string, expiresAt time.Time) error

	// ValidateRefreshToken checks if a refresh token is valid and not revoked.
	// It returns ErrNotFound for an unknown ID, ErrTokenRevoked for a revoked one
	// and ErrExpired for one past its expiry.
	ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) // Returns userID

	// RevokeRefreshToken revokes a refresh token. The revocation must outlive any
	// cached copy of the token, i.e. persist at least until the token's expiry.
	RevokeRefreshToken(ctx context.Context, tokenID string) error

	// RevokeAllUserTokens revokes all refresh tokens for a user. This is the sweep
	// a password change or a compromise report must trigger (finding F-13).
	RevokeAllUserTokens(ctx context.Context, userID string) error
}

// OIDCStateStore defines the interface for storing OIDC flow state (ephemeral).
// Used to prevent CSRF attacks during OAuth2/OIDC flows.
type OIDCStateStore interface {
	// StoreState stores an OIDC state with associated data.
	//
	// Every field of data must come back from GetState, Metadata included and
	// verbatim. The record is where three of the flow's four controls live
	// between the authorization request and the callback, so a field this store
	// declines to persist is a control the callback cannot enforce. The library
	// writes each of them twice — the typed field and a mirrored "go-auth/" key
	// in Metadata — and refuses a record that comes back with neither copy, so
	// dropping one column is survivable and dropping both fails every sign-in
	// rather than silently authenticating without the control.
	StoreState(ctx context.Context, state string, data *OIDCState, ttl time.Duration) error

	// GetState retrieves and deletes the state (one-time use).
	//
	// The delete is what makes the state single-use, and it must be atomic with
	// the read: two concurrent callbacks carrying the same state must not both
	// receive the data, or the anti-replay property of the state parameter is
	// gone. Return ErrNotFound once consumed, and ErrExpired past the TTL.
	GetState(ctx context.Context, state string) (*OIDCState, error)

	// DeleteState explicitly deletes a state.
	DeleteState(ctx context.Context, state string) error
}

// User represents a user identity in the system.
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Username      string `json:"username,omitempty"`
	Name          string `json:"name,omitempty"`
	Provider      string `json:"provider,omitempty"` // e.g., "local", "google", "github"

	// ProviderSubject is the immutable subject identifier ("sub") the identity
	// provider asserted the first time this account was seen. It is the only
	// stable join key a provider offers: an email address is re-assignable and an
	// unverified one is attacker-chosen, so matching on email alone is the
	// account-takeover path recorded as finding F-01 (the CVE-2023-28131
	// "nOAuth" class, RFC 9700 section 4). Empty for locally-registered users.
	//
	// The OIDC client writes it here and mirrors it in Metadata under
	// "provider_sub", and reads this field first. A store that persists neither
	// leaves the account with nothing to check a later assertion against: the
	// next sign-in is refused as needing an explicit link decision, every time,
	// with no way for its owner to clear it.
	ProviderSubject string `json:"provider_subject,omitempty"`

	Metadata  map[string]interface{} `json:"metadata,omitempty"` // Extensible user metadata
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// WebAuthnCredential represents a stored WebAuthn/Passkey credential.
type WebAuthnCredential struct {
	ID              []byte                 `json:"id"`               // Credential ID
	PublicKey       []byte                 `json:"public_key"`       // Public key
	AttestationType string                 `json:"attestation_type"` // Attestation type
	AAGUID          []byte                 `json:"aaguid"`           // Authenticator AAGUID
	SignCount       uint32                 `json:"sign_count"`       // Signature counter
	UserID          string                 `json:"user_id"`          // Associated user ID
	Transports      []string               `json:"transports"`       // Authenticator transports
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
//
// Every field except RedirectURL and Metadata exists to bind one leg of the
// flow to the other. A state parameter on its own proves only that somebody
// started a flow; it does not prove that the browser completing it is the
// browser that started it, nor that the ID token handed back belongs to this
// exchange.
//
// Nonce, CodeVerifier and BindingHash are each mirrored into Metadata under a
// "go-auth/" key by the OIDC client, which reads the typed field first and the
// mirror second. Persisting only the fields a given release happens to know
// about is therefore survivable; persisting neither copy of one of them is not,
// and the callback refuses such a record instead of running the flow without
// the control.
type OIDCState struct {
	RedirectURL string `json:"redirect_url,omitempty"` // Post-auth redirect

	// Nonce is the value the OIDC provider must echo in the ID token, which is
	// what makes a token captured from one authentication useless in another
	// (finding F-18, OIDC Core section 3.1.3.7). Empty for an OAuth2-only
	// provider, which issues no ID token to carry one.
	Nonce string `json:"nonce,omitempty"`

	Provider string `json:"provider"` // Provider name

	// CodeVerifier is the PKCE code_verifier whose S256 challenge was sent on the
	// authorization request, held server-side until the token exchange. Without
	// it an intercepted authorization code is redeemable by whoever holds it
	// (finding F-17, RFC 9700 section 2.1.1). It is a secret for the lifetime of
	// the flow and is never empty on a record this library wrote.
	CodeVerifier string `json:"code_verifier,omitempty"`

	// BindingHash is a SHA-256 digest of the single-use value written to the
	// user agent as a cookie when the flow started. The callback must present a
	// cookie hashing to this value, which is what ties the state to the browser
	// that began the flow and defeats the login-CSRF of finding F-16. The digest
	// rather than the value is stored so a read of the state store does not yield
	// something replayable.
	//
	// A flow deliberately started without a browser binding records the marker
	// "unbound" here instead. "No binding was ever issued" and "the binding went
	// missing" must not be the same empty string, or a store that drops this
	// field turns every bound flow into an unbound one and nothing reports it.
	BindingHash string `json:"binding_hash,omitempty"`

	Metadata  map[string]interface{} `json:"metadata,omitempty"` // Additional state data
	CreatedAt time.Time              `json:"created_at"`
}
