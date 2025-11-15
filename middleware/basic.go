package middleware

import (
	"context"
	"net/http"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/storage"
)

// BasicAuthMiddleware provides HTTP Basic Authentication middleware.
type BasicAuthMiddleware struct {
	authenticator *basic.Authenticator
	errorHandler  ErrorHandler
	realm         string
}

// BasicAuthConfig configures the basic auth middleware.
type BasicAuthConfig struct {
	Authenticator *basic.Authenticator
	ErrorHandler  ErrorHandler // Optional: defaults to DefaultErrorHandler
	Realm         string       // Optional: defaults to "Restricted"
}

// NewBasicAuthMiddleware creates a new basic auth middleware.
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
