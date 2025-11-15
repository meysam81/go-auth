// Package middleware provides HTTP middleware for authentication.
// This package is isolated and only depends on net/http from the standard library,
// making it compatible with any Go HTTP framework.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// UserIDKey is the context key for storing the authenticated user ID.
	UserIDKey ContextKey = "user_id"

	// UserKey is the context key for storing the full user object.
	UserKey ContextKey = "user"

	// SessionIDKey is the context key for storing the session ID.
	SessionIDKey ContextKey = "session_id"

	// ClaimsKey is the context key for storing JWT claims.
	ClaimsKey ContextKey = "claims"
)

var (
	// ErrUnauthorized is returned when authentication fails.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden is returned when the user doesn't have permission.
	ErrForbidden = errors.New("forbidden")
)

// ErrorHandler is a function that handles authentication errors.
// The default behavior is to write a 401 or 403 status code.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultErrorHandler is the default error handler.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrForbidden) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// SessionTokenExtractor extracts session tokens from HTTP requests.
type SessionTokenExtractor interface {
	Extract(r *http.Request) (string, error)
}

// CookieExtractor extracts session tokens from cookies.
type CookieExtractor struct {
	CookieName string
}

// Extract extracts a session token from a cookie.
func (e *CookieExtractor) Extract(r *http.Request) (string, error) {
	cookie, err := r.Cookie(e.CookieName)
	if err != nil {
		return "", ErrUnauthorized
	}
	return cookie.Value, nil
}

// HeaderExtractor extracts bearer tokens from the Authorization header.
type HeaderExtractor struct {
	HeaderName string // e.g., "Authorization"
	Scheme     string // e.g., "Bearer"
}

// Extract extracts a bearer token from the Authorization header.
func (e *HeaderExtractor) Extract(r *http.Request) (string, error) {
	authHeader := r.Header.Get(e.HeaderName)
	if authHeader == "" {
		return "", ErrUnauthorized
	}

	if e.Scheme != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], e.Scheme) {
			return "", ErrUnauthorized
		}
		return parts[1], nil
	}

	return authHeader, nil
}

// MultiExtractor tries multiple extractors in order.
type MultiExtractor struct {
	Extractors []SessionTokenExtractor
}

// Extract tries each extractor until one succeeds.
func (e *MultiExtractor) Extract(r *http.Request) (string, error) {
	for _, extractor := range e.Extractors {
		token, err := extractor.Extract(r)
		if err == nil {
			return token, nil
		}
	}
	return "", ErrUnauthorized
}

// SessionTokenWriter writes session tokens to HTTP responses.
type SessionTokenWriter interface {
	Write(w http.ResponseWriter, token string)
	Clear(w http.ResponseWriter)
}

// CookieWriter writes session tokens as HTTP cookies.
type CookieWriter struct {
	CookieName string
	Path       string
	Domain     string
	MaxAge     int  // seconds
	Secure     bool
	HttpOnly   bool
	SameSite   http.SameSite
}

// Write writes a session token as a cookie.
func (w *CookieWriter) Write(rw http.ResponseWriter, token string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     w.CookieName,
		Value:    token,
		Path:     w.Path,
		Domain:   w.Domain,
		MaxAge:   w.MaxAge,
		Secure:   w.Secure,
		HttpOnly: w.HttpOnly,
		SameSite: w.SameSite,
	})
}

// Clear removes the session cookie.
func (w *CookieWriter) Clear(rw http.ResponseWriter) {
	http.SetCookie(rw, &http.Cookie{
		Name:     w.CookieName,
		Value:    "",
		Path:     w.Path,
		Domain:   w.Domain,
		MaxAge:   -1,
		Secure:   w.Secure,
		HttpOnly: w.HttpOnly,
		SameSite: w.SameSite,
	})
}

// GetUserID retrieves the user ID from the request context.
func GetUserID(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(UserIDKey).(string)
	return userID, ok
}

// GetSessionID retrieves the session ID from the request context.
func GetSessionID(r *http.Request) (string, bool) {
	sessionID, ok := r.Context().Value(SessionIDKey).(string)
	return sessionID, ok
}

// WithUserID adds a user ID to the request context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithSessionID adds a session ID to the request context.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, SessionIDKey, sessionID)
}
