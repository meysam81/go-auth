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

	// Double-check expiration
	if time.Now().After(data.ExpiresAt) {
		_ = m.store.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return &Session{
		ID:   sessionID,
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

// generateSessionID generates a cryptographically secure session ID.
func (m *Manager) generateSessionID() (string, error) {
	b := make([]byte, m.sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SessionTokenLocation defines where session tokens should be stored.
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

func (n *NullSessionLocation) GetSessionID() (string, error) {
	return "", ErrSessionNotFound
}

func (n *NullSessionLocation) SetSessionID(sessionID string) error {
	return nil
}

func (n *NullSessionLocation) ClearSessionID() error {
	return nil
}
