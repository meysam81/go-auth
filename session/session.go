// Package session provides session management with configurable storage backends.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/meysam81/go-auth/storage"
)

var (
	// ErrSessionNotFound is returned when a session doesn't exist.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")

	// ErrSessionSweepFailed is joined onto ErrSessionExpired when an expired
	// session was detected but the store refused to delete it. The credential is
	// still refused, so authentication is unaffected; the caller is told because
	// a store that cannot delete is a store that cannot revoke, and silently
	// discarding that signal is how an expired-but-present session survives.
	ErrSessionSweepFailed = errors.New("expired session could not be deleted")

	// ErrRotationRolledBack is returned by Rotate when the replacement session
	// could not be adopted and was removed again. Exactly one session is live:
	// the original identifier passed to Rotate.
	ErrRotationRolledBack = errors.New("session rotation rolled back; previous session ID is still live")

	// ErrOrphanedSession is returned by Rotate when the replacement session was
	// created, the old entry could not be deleted, and the compensating delete of
	// the replacement also failed. Two identifiers may now authenticate the same
	// user; the caller must force a logout rather than treat this as a retry.
	ErrOrphanedSession = errors.New("session rotation left two live session IDs")
)

const (
	// DefaultSessionTTL is the default session time-to-live.
	DefaultSessionTTL = 24 * time.Hour

	// DefaultSessionIDLength is the default length of session IDs in bytes.
	DefaultSessionIDLength = 32
)

// Manager handles session creation, validation, and lifecycle.
type Manager struct {
	store          storage.SessionStore
	sessionTTL     time.Duration
	sessionIDBytes int
}

// Config configures the session manager.
type Config struct {
	Store          storage.SessionStore
	SessionTTL     time.Duration // Optional: defaults to 24 hours
	SessionIDBytes int           // Optional: defaults to 32 bytes
}

// NewManager creates a new session manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("session store is required")
	}

	ttl := cfg.SessionTTL
	if ttl == 0 {
		ttl = DefaultSessionTTL
	}

	idBytes := cfg.SessionIDBytes
	if idBytes == 0 {
		idBytes = DefaultSessionIDLength
	}

	return &Manager{
		store:          cfg.Store,
		sessionTTL:     ttl,
		sessionIDBytes: idBytes,
	}, nil
}

// CreateSessionRequest contains information for creating a session.
type CreateSessionRequest struct {
	UserID   string
	Email    string
	Provider string
	Metadata map[string]interface{}
	TTL      time.Duration // Optional: overrides default TTL
}

// Session represents an active user session with its ID.
type Session struct {
	ID   string
	Data *storage.SessionData
}

// Create creates a new session for a user.
func (m *Manager) Create(ctx context.Context, req CreateSessionRequest) (*Session, error) {
	sessionID, err := m.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = m.sessionTTL
	}

	now := time.Now()
	data := &storage.SessionData{
		UserID:    req.UserID,
		Email:     req.Email,
		Provider:  req.Provider,
		Metadata:  req.Metadata,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	if err := m.store.CreateSession(ctx, sessionID, data, ttl); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Session{
		ID:   sessionID,
		Data: data,
	}, nil
}

// Get retrieves a session by ID and validates it hasn't expired.
func (m *Manager) Get(ctx context.Context, sessionID string) (*Session, error) {
	data, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		if errors.Is(err, storage.ErrExpired) {
			return nil, ErrSessionExpired
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// A store may hand back an entry whose TTL has passed (its own clock, its own
	// eviction cadence), so expiry is re-decided here and the stale entry swept.
	if time.Now().After(data.ExpiresAt) {
		if delErr := m.store.DeleteSession(ctx, sessionID); delErr != nil {
			// The expiry verdict still reaches the caller through errors.Is, but the
			// failed sweep is no longer discarded: it is the caller's only signal
			// that revocation on this store is not working. The session ID is never
			// named in the message -- it is a bearer credential and logs are not a
			// place to put one.
			return nil, errors.Join(ErrSessionExpired, fmt.Errorf("%w: %w", ErrSessionSweepFailed, delErr))
		}
		return nil, ErrSessionExpired
	}

	return &Session{
		ID:   sessionID,
		Data: data,
	}, nil
}

// Rotate mints a fresh identifier for an existing session, moves the session
// data onto it, deletes the old entry, and returns the new Session.
//
// Callers must rotate on every authentication and every privilege change.
// A session identifier that survives authentication is a session fixation
// vector (finding F-14, CWE-384): an attacker who plants a known identifier in
// the victim's browser before sign-in continues to hold a valid credential
// afterwards, because nothing about the identifier changed when the identity
// behind it did.
//
// The replacement inherits the remaining lifetime of the original rather than a
// fresh TTL, so repeated rotation cannot extend a session indefinitely. Call
// Refresh with the returned ID when the authentication event should also
// restart the clock.
//
// Ordering is deliberate: the replacement is created first and the old entry
// deleted second. A failure of that delete triggers a compensating delete of
// the replacement, so a failed rotation leaves exactly the original session
// live and reports ErrRotationRolledBack. Only if the compensating delete also
// fails can two identifiers be live, and that case is reported distinctly as
// ErrOrphanedSession so the caller forces a logout instead of retrying.
//
// Rotate is not atomic against another Rotate of the same session: SessionStore
// offers no compare-and-swap in v1, so two callers racing on one identifier can
// both succeed and leave two sessions where there was one. Rotate once, on the
// request that authenticated.
func (m *Manager) Rotate(ctx context.Context, oldID string) (*Session, error) {
	current, err := m.Get(ctx, oldID)
	if err != nil {
		return nil, err
	}

	remaining := time.Until(current.Data.ExpiresAt)
	if remaining <= 0 {
		return nil, ErrSessionExpired
	}

	newID, err := m.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// The clone keeps the replacement from aliasing whatever the store still
	// holds for oldID: a store that hands out its own entry (the in-memory one
	// used to) would otherwise leave the deleted session and the live one sharing
	// one metadata map.
	data := cloneSessionData(current.Data)

	if err := m.store.CreateSession(ctx, newID, data, remaining); err != nil {
		return nil, fmt.Errorf("failed to create rotated session: %w", err)
	}

	if delErr := m.store.DeleteSession(ctx, oldID); delErr != nil {
		if rollbackErr := m.store.DeleteSession(ctx, newID); rollbackErr != nil {
			return nil, errors.Join(
				ErrOrphanedSession,
				fmt.Errorf("delete previous session: %w", delErr),
				fmt.Errorf("delete replacement session: %w", rollbackErr),
			)
		}
		return nil, errors.Join(ErrRotationRolledBack, fmt.Errorf("delete previous session: %w", delErr))
	}

	return &Session{
		ID:   newID,
		Data: data,
	}, nil
}

// Update updates an existing session's data.
func (m *Manager) Update(ctx context.Context, sessionID string, data *storage.SessionData) error {
	if err := m.store.UpdateSession(ctx, sessionID, data, m.sessionTTL); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrSessionNotFound
		}
		if errors.Is(err, storage.ErrExpired) {
			return ErrSessionExpired
		}
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// Refresh extends the TTL of an existing session.
func (m *Manager) Refresh(ctx context.Context, sessionID string) error {
	if err := m.store.RefreshSession(ctx, sessionID, m.sessionTTL); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrSessionNotFound
		}
		if errors.Is(err, storage.ErrExpired) {
			return ErrSessionExpired
		}
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	return nil
}

// Delete removes a session (logout).
//
// Deleting one session revokes one credential. A password change or a suspected
// compromise must revoke every session and every refresh token the subject
// holds, which this library cannot do in v1: SessionStore has no
// DeleteAllForUser and adding one would break every implementor (finding F-13).
// Until v2 the caller owns that sweep.
func (m *Manager) Delete(ctx context.Context, sessionID string) error {
	if err := m.store.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// Validate checks if a session exists and is valid.
func (m *Manager) Validate(ctx context.Context, sessionID string) (*storage.SessionData, error) {
	session, err := m.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	return session.Data, nil
}

// cloneSessionData returns a copy that shares no mutable state with data.
func cloneSessionData(data *storage.SessionData) *storage.SessionData {
	if data == nil {
		return nil
	}

	clone := *data
	if data.Metadata != nil {
		clone.Metadata = make(map[string]interface{}, len(data.Metadata))
		for k, v := range data.Metadata {
			clone.Metadata[k] = v
		}
	}

	return &clone
}

// generateSessionID generates a cryptographically secure session ID.
func (m *Manager) generateSessionID() (string, error) {
	b := make([]byte, m.sessionIDBytes)
	// crypto/rand only: a predictable session ID is a forgeable one, and
	// rand.Read is documented never to return a short read without an error.
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SessionTokenLocation defines where session tokens should be stored.
//
// The name stutters, but renaming an exported type breaks every downstream
// implementation, so it stands until v2 renames it to TokenLocation.
//
//nolint:revive // Renaming an exported type is a breaking change; deferred to v2.
type SessionTokenLocation interface {
	// GetSessionID retrieves the session ID from the request.
	GetSessionID() (string, error)

	// SetSessionID stores the session ID in the response.
	SetSessionID(sessionID string) error

	// ClearSessionID removes the session ID.
	ClearSessionID() error
}

// NullSessionLocation is a no-op implementation (for stateless auth).
type NullSessionLocation struct{}

// GetSessionID always reports that no session ID is carried, because this
// location carries nothing.
func (n *NullSessionLocation) GetSessionID() (string, error) {
	return "", ErrSessionNotFound
}

// SetSessionID discards the session ID and reports success.
func (n *NullSessionLocation) SetSessionID(sessionID string) error {
	return nil
}

// ClearSessionID is a no-op and reports success.
func (n *NullSessionLocation) ClearSessionID() error {
	return nil
}
