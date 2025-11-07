package middleware

import (
	"context"
	"net/http"

	"github.com/meysam81/go-auth/session"
	"github.com/meysam81/go-auth/storage"
)

// SessionMiddleware provides session-based authentication middleware.
type SessionMiddleware struct {
	sessionManager *session.Manager
	extractor      SessionTokenExtractor
	errorHandler   ErrorHandler
}

// SessionConfig configures the session middleware.
type SessionConfig struct {
	SessionManager *session.Manager
	Extractor      SessionTokenExtractor // Optional: defaults to cookie-based extraction
	ErrorHandler   ErrorHandler          // Optional: defaults to DefaultErrorHandler
}

// NewSessionMiddleware creates a new session middleware.
func NewSessionMiddleware(cfg SessionConfig) *SessionMiddleware {
	extractor := cfg.Extractor
	if extractor == nil {
		extractor = &CookieExtractor{
			CookieName: "session_id",
		}
	}

	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = DefaultErrorHandler
	}

	return &SessionMiddleware{
		sessionManager: cfg.SessionManager,
		extractor:      extractor,
		errorHandler:   errorHandler,
	}
}

// Middleware returns an HTTP middleware function.
func (m *SessionMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := m.extractor.Extract(r)
		if err != nil {
			m.errorHandler(w, r, ErrUnauthorized)
			return
		}

		sessionData, err := m.sessionManager.Validate(r.Context(), sessionID)
		if err != nil {
			m.errorHandler(w, r, ErrUnauthorized)
			return
		}

		// Add session data to context
		ctx := context.WithValue(r.Context(), UserIDKey, sessionData.UserID)
		ctx = context.WithValue(ctx, SessionIDKey, sessionID)
		ctx = context.WithValue(ctx, "session_data", sessionData)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSessionData retrieves session data from the request context.
func GetSessionData(r *http.Request) (*storage.SessionData, bool) {
	data, ok := r.Context().Value("session_data").(*storage.SessionData)
	return data, ok
}
