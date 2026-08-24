package middleware

import (
	"context"
	"net/http"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/storage"
)

// BasicAuthMiddleware provides HTTP Basic Authentication middleware.
//
// Deprecated: this middleware runs one bcrypt evaluation per request and offers
// no second factor (F-15). At the library's cost of 12 a verification is
// roughly 250 ms of CPU, so a handful of concurrent clients saturates a core
// and an unauthenticated caller can hold a route down for the price of sending
// requests (CWE-400) — the credential need not even be valid, because the cost
// is paid before the comparison result is known. HTTP Basic also has no way to
// carry a TOTP or WebAuthn assertion, so mounting it on a route that is
// otherwise MFA-protected creates a silent MFA bypass for that route. v2
// removes it. Authenticate once at a sign-in endpoint and protect subsequent
// requests with SessionMiddleware or JWTMiddleware; if a machine client needs
// a static credential, issue it a token rather than a password.
type BasicAuthMiddleware struct {
	authenticator *basic.Authenticator
	errorHandler  ErrorHandler
	realm         string
}

// BasicAuthConfig configures the basic auth middleware.
//
// Deprecated: see BasicAuthMiddleware (F-15). v2 removes it.
type BasicAuthConfig struct {
	Authenticator *basic.Authenticator
	ErrorHandler  ErrorHandler // Optional: defaults to DefaultErrorHandler
	Realm         string       // Optional: defaults to "Restricted"
}

// NewBasicAuthMiddleware creates a new basic auth middleware.
//
// Deprecated: see BasicAuthMiddleware. It costs one bcrypt evaluation per
// request (F-15, CWE-400) and cannot carry a second factor, so it must not be
// mounted on any route reachable by an untrusted client. v2 removes it; use
// SessionMiddleware or JWTMiddleware.
func NewBasicAuthMiddleware(cfg BasicAuthConfig) *BasicAuthMiddleware {
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = DefaultErrorHandler
	}

	realm := cfg.Realm
	if realm == "" {
		realm = "Restricted"
	}

	return &BasicAuthMiddleware{
		authenticator: cfg.Authenticator,
		errorHandler:  errorHandler,
		realm:         realm,
	}
}

// Middleware returns an HTTP middleware function.
//
// Deprecated: see BasicAuthMiddleware (F-15). Every request, authenticated or
// not, pays for a bcrypt verification before the outcome is known.
func (m *BasicAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			m.sendAuthChallenge(w, r)
			return
		}

		user, err := m.authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			m.sendAuthChallenge(w, r)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), UserIDKey, user.ID)
		ctx = context.WithValue(ctx, UserKey, user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sendAuthChallenge sends a 401 with WWW-Authenticate header.
func (m *BasicAuthMiddleware) sendAuthChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+m.realm+`"`)
	m.errorHandler(w, r, ErrUnauthorized)
}

// GetUser retrieves the authenticated user from the request context.
func GetUser(r *http.Request) (*storage.User, bool) {
	user, ok := r.Context().Value(UserKey).(*storage.User)
	return user, ok
}
