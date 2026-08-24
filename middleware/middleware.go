// Package middleware provides HTTP middleware for authentication.
// This package is isolated and only depends on net/http from the standard library,
// making it compatible with any Go HTTP framework.
package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
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

	// SessionDataKey is the context key for storing session data.
	SessionDataKey ContextKey = "session_data"

	// ClaimsKey is the context key for storing JWT claims.
	ClaimsKey ContextKey = "claims"
)

var (
	// ErrUnauthorized is returned when authentication fails.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden is returned when the user doesn't have permission.
	ErrForbidden = errors.New("forbidden")

	// ErrMissingDependency is returned by the WithError constructors when the
	// configuration omits a collaborator the middleware cannot work without.
	//
	// The middleware types hold their dependency in an unexported field, so a
	// nil one is not something a request can recover from: the credential
	// cannot be verified, and a request whose credential cannot be verified is
	// not authenticated. The plain constructors panic on it (see
	// NewJWTMiddleware) because their v1 signatures return no error.
	ErrMissingDependency = errors.New("missing required dependency")

	// ErrInvalidCookieConfig is returned by NewSecureCookieWriter when the
	// requested cookie could not be emitted safely.
	//
	// It exists because net/http silently drops a cookie whose name is not a
	// valid token, and because the __Host- prefix imposes constraints a browser
	// enforces by discarding the cookie rather than by reporting anything. Both
	// failures are invisible at runtime, so they are caught at construction.
	ErrInvalidCookieConfig = errors.New("invalid cookie configuration")
)

// cookieDeletionTime is the expiry emitted alongside Max-Age=-1 when clearing a
// cookie. Any instant in the past works; the Unix epoch is the conventional
// choice and is within the range net/http will serialize.
var cookieDeletionTime = time.Unix(0, 0).UTC()

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
//
// Every failure reports ErrUnauthorized and nothing else. The error returned by
// (*http.Request).Cookie is deliberately not wrapped: it distinguishes "no such
// cookie" from "malformed Cookie header", which is information an
// unauthenticated caller probing the endpoint would like and a legitimate
// caller has no use for.
func (e *CookieExtractor) Extract(r *http.Request) (string, error) {
	cookie, err := r.Cookie(e.CookieName)
	if err != nil {
		return "", ErrUnauthorized
	}
	// A cleared cookie is a present cookie with an empty value. Treating it as a
	// credential sends an empty identifier into a store lookup, where a store
	// that happens to have an empty key would authenticate it.
	if cookie.Value == "" {
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
//
// As with CookieExtractor, an absent header, a wrong scheme and a malformed
// value are all reported as ErrUnauthorized so the response cannot be used to
// enumerate which credential shape the route accepts.
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
//
// The underlying errors are intentionally not joined into the result. At this
// boundary the only remaining decision is "authenticated or not", and an error
// naming the extractor that failed would tell an unauthenticated caller whether
// a cookie was present, whether a header was malformed, and which credentials
// this route accepts. A caller that needs to distinguish those cases must
// invoke the individual extractors itself.
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
//
// The zero value is unsafe. Secure, HttpOnly and SameSite are plain bool and
// http.SameSite fields, so a CookieWriter constructed with a literal that omits
// them emits a session identifier that travels over cleartext HTTP, is readable
// by any script on the page, and is attached to cross-site requests: the three
// properties a session cookie exists to deny. The field types are frozen by v1
// compatibility and their defaults therefore cannot be inverted, so use
// NewSecureCookieWriter, which sets them correctly and validates the rest.
type CookieWriter struct {
	CookieName string
	Path       string
	Domain     string
	MaxAge     int // seconds
	Secure     bool
	//nolint:revive,staticcheck // Renaming an exported field is a breaking change; deferred to v2.
	HttpOnly bool
	SameSite http.SameSite
}

// NewSecureCookieWriter returns a CookieWriter with secure attributes:
// Secure and HttpOnly set, and SameSite defaulting to Lax.
//
// There is no switch to turn those off. A deployment that genuinely needs a
// non-secure cookie can still build a CookieWriter literal, which is exactly
// the visibility that choice deserves.
func NewSecureCookieWriter(cfg SecureCookieConfig) (*CookieWriter, error) {
	if !isValidCookieName(cfg.CookieName) {
		// net/http drops a cookie with an invalid name without a word, so the
		// only symptom is a session that never sticks.
		return nil, fmt.Errorf("%w: cookie name %q is not a valid RFC 6265 token", ErrInvalidCookieConfig, cfg.CookieName)
	}

	path := cfg.Path
	if path == "" {
		path = "/"
	}

	sameSite := cfg.SameSite
	if sameSite == 0 {
		// The zero value of http.SameSite emits no attribute at all, which
		// leaves the browser default. Lax is the safe floor and is what a
		// modern browser applies anyway; naming it makes the choice explicit
		// rather than dependent on the user agent.
		sameSite = http.SameSiteLaxMode
	}

	// A browser silently rejects a __Host- cookie that is not host-only and
	// path-/, so a violation here would look like a cookie that is never
	// stored. The prefix is worth honoring: it is what stops a compromised
	// subdomain from overwriting the parent origin's session cookie.
	if strings.HasPrefix(cfg.CookieName, "__Host-") {
		if cfg.Domain != "" {
			return nil, fmt.Errorf("%w: a __Host- cookie must not set Domain", ErrInvalidCookieConfig)
		}
		if path != "/" {
			return nil, fmt.Errorf("%w: a __Host- cookie must use Path=/", ErrInvalidCookieConfig)
		}
	}

	return &CookieWriter{
		CookieName: cfg.CookieName,
		Path:       path,
		Domain:     cfg.Domain,
		MaxAge:     cfg.MaxAge,
		Secure:     true,
		HttpOnly:   true,
		SameSite:   sameSite,
	}, nil
}

// SecureCookieConfig configures NewSecureCookieWriter.
//
// Secure and HttpOnly are absent by design: they are not configurable.
type SecureCookieConfig struct {
	// CookieName is the cookie name and is required.
	//
	// Prefer the __Host- prefix for a session cookie. A browser accepts such a
	// cookie only when it is Secure, host-only and Path=/, which denies a
	// sibling subdomain the ability to plant or overwrite it.
	CookieName string

	// Path defaults to "/".
	Path string

	// Domain should normally stay empty, which yields a host-only cookie.
	// Setting it widens the cookie to every subdomain, so any host under that
	// domain — including one operated by someone else — receives the session
	// identifier.
	Domain string

	// MaxAge is the lifetime in seconds. Zero emits no Max-Age, making it a
	// session cookie that dies with the browser session.
	MaxAge int

	// SameSite defaults to http.SameSiteLaxMode when left at its zero value.
	// http.SameSiteNoneMode is only meaningful for a genuine cross-site flow
	// and removes the CSRF protection the attribute provides.
	SameSite http.SameSite
}

// Write writes a session token as a cookie.
func (w *CookieWriter) Write(rw http.ResponseWriter, token string) {
	http.SetCookie(rw, w.cookie(token, w.MaxAge, time.Time{}))
}

// Clear removes the session cookie.
//
// It mirrors every attribute Write emits. A browser identifies a cookie by
// (name, domain, path), so a Clear that dropped Path or Domain would create a
// second, differently scoped cookie and leave the live session identifier in
// place — a logout that reports success and revokes nothing. Both Max-Age=-1
// and a past Expires are sent because user agents have historically honored
// one or the other, and either alone leaves the cookie behind somewhere.
func (w *CookieWriter) Clear(rw http.ResponseWriter) {
	http.SetCookie(rw, w.cookie("", -1, cookieDeletionTime))
}

// cookie builds the cookie shared by Write and Clear so the attribute sets
// cannot drift apart.
func (w *CookieWriter) cookie(value string, maxAge int, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     w.CookieName,
		Value:    value,
		Path:     w.Path,
		Domain:   w.Domain,
		MaxAge:   maxAge,
		Expires:  expires,
		Secure:   w.Secure,
		HttpOnly: w.HttpOnly,
		SameSite: w.SameSite,
	}
}

// isValidCookieName reports whether name is a token per RFC 6265 section 4.1.1,
// which defers to the RFC 2616 token production: no control characters and no
// separators. net/http applies the same rule and discards the Set-Cookie header
// silently when it fails.
func isValidCookieName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isCookieNameByte(name[i]) {
			return false
		}
	}
	return true
}

// isCookieNameByte reports whether b may appear in a cookie name.
func isCookieNameByte(b byte) bool {
	if b <= 0x20 || b >= 0x7f {
		return false
	}
	return !strings.ContainsRune(`"(),/:;<=>?@[\]{}`, rune(b))
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
