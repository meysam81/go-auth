package middleware

import (
	"context"
	"net/http"

	"github.com/meysam81/go-auth/auth/jwt"
)

// JWTMiddleware provides JWT authentication middleware.
type JWTMiddleware struct {
	tokenManager *jwt.TokenManager
	extractor    SessionTokenExtractor
	errorHandler ErrorHandler
}

// JWTConfig configures the JWT middleware.
type JWTConfig struct {
	TokenManager *jwt.TokenManager
	Extractor    SessionTokenExtractor // Optional: defaults to Bearer token from Authorization header
	ErrorHandler ErrorHandler          // Optional: defaults to DefaultErrorHandler
}

// NewJWTMiddleware creates a new JWT middleware.
func NewJWTMiddleware(cfg JWTConfig) *JWTMiddleware {
	extractor := cfg.Extractor
	if extractor == nil {
		extractor = &HeaderExtractor{
			HeaderName: "Authorization",
			Scheme:     "Bearer",
		}
	}

	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = DefaultErrorHandler
	}

	return &JWTMiddleware{
		tokenManager: cfg.TokenManager,
		extractor:    extractor,
		errorHandler: errorHandler,
	}
}

// Middleware returns an HTTP middleware function.
func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.extractor.Extract(r)
		if err != nil {
			m.errorHandler(w, r, ErrUnauthorized)
			return
		}

		claims, err := m.tokenManager.ValidateToken(r.Context(), token)
		if err != nil {
			m.errorHandler(w, r, ErrUnauthorized)
			return
		}

		// Add claims and user ID to context
		ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, ClaimsKey, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaims retrieves JWT claims from the request context.
func GetClaims(r *http.Request) (*jwt.Claims, bool) {
	claims, ok := r.Context().Value(ClaimsKey).(*jwt.Claims)
	return claims, ok
}
