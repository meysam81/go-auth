package audit

import (
	"context"
	"time"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/auth/jwt"
	"github.com/meysam81/go-auth/session"
	"github.com/meysam81/go-auth/storage"
)

// BasicAuthWrapper wraps a basic.Authenticator to add audit logging.
// It implements the same interface as basic.Authenticator and can be used as a drop-in replacement.
type BasicAuthWrapper struct {
	authenticator *basic.Authenticator
	auditor       AuditLogger
	sourceFunc    SourceExtractor
}

// SourceExtractor is a function that extracts source information from the context.
// This allows downstream users to inject request-specific data (IP, user agent, etc.).
type SourceExtractor func(ctx context.Context) *Source

// NewBasicAuthWrapper creates an audit-logging wrapper around a basic authenticator.
func NewBasicAuthWrapper(authenticator *basic.Authenticator, auditor AuditLogger, sourceFunc SourceExtractor) *BasicAuthWrapper {
	if auditor == nil {
		auditor = DefaultAuditor()
	}
	return &BasicAuthWrapper{
		authenticator: authenticator,
		auditor:       auditor,
		sourceFunc:    sourceFunc,
	}
}

// Register wraps the Register method with audit logging.
func (w *BasicAuthWrapper) Register(ctx context.Context, req basic.RegisterRequest) (*storage.User, error) {
	start := time.Now()
	user, err := w.authenticator.Register(ctx, req)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventAuthRegister,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			Email:    req.Email,
			Username: req.Username,
			Provider: "basic",
		},
		Resource: &Resource{
			Type: "user",
		},
		Metadata: map[string]interface{}{
			"name": req.Name,
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		event.Actor.UserID = user.ID
		event.Resource.ID = user.ID
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return user, err
}

// Authenticate wraps the Authenticate method with audit logging.
func (w *BasicAuthWrapper) Authenticate(ctx context.Context, identifier, password string) (*storage.User, error) {
	start := time.Now()
	user, err := w.authenticator.Authenticate(ctx, identifier, password)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			Provider: "basic",
		},
		Resource: &Resource{
			Type: "user",
		},
		Metadata: map[string]interface{}{
			"identifier": identifier, // Note: may be email or username
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
		// Still log the identifier for failed attempts
		event.Actor.Email = identifier
	} else {
		event.Actor.UserID = user.ID
		event.Actor.Email = user.Email
		event.Actor.Username = user.Username
		event.Resource.ID = user.ID
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return user, err
}

// ChangePassword wraps the ChangePassword method with audit logging.
func (w *BasicAuthWrapper) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	start := time.Now()
	err := w.authenticator.ChangePassword(ctx, userID, oldPassword, newPassword)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventAuthPasswordChange,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   userID,
			Provider: "basic",
		},
		Resource: &Resource{
			Type: "user",
			ID:   userID,
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// ResetPassword wraps the ResetPassword method with audit logging.
func (w *BasicAuthWrapper) ResetPassword(ctx context.Context, userID, newPassword string) error {
	start := time.Now()
	err := w.authenticator.ResetPassword(ctx, userID, newPassword)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventAuthPasswordReset,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   userID,
			Provider: "basic",
		},
		Resource: &Resource{
			Type: "user",
			ID:   userID,
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// TokenManagerWrapper wraps a jwt.TokenManager to add audit logging.
type TokenManagerWrapper struct {
	tokenManager *jwt.TokenManager
	auditor      AuditLogger
	sourceFunc   SourceExtractor
}

// NewTokenManagerWrapper creates an audit-logging wrapper around a token manager.
func NewTokenManagerWrapper(tokenManager *jwt.TokenManager, auditor AuditLogger, sourceFunc SourceExtractor) *TokenManagerWrapper {
	if auditor == nil {
		auditor = DefaultAuditor()
	}
	return &TokenManagerWrapper{
		tokenManager: tokenManager,
		auditor:      auditor,
		sourceFunc:   sourceFunc,
	}
}

// GenerateTokenPair wraps the GenerateTokenPair method with audit logging.
func (w *TokenManagerWrapper) GenerateTokenPair(ctx context.Context, user *storage.User) (*jwt.TokenPair, error) {
	start := time.Now()
	tokenPair, err := w.tokenManager.GenerateTokenPair(ctx, user)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventTokenGenerate,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   user.ID,
			Email:    user.Email,
			Username: user.Username,
			Provider: user.Provider,
		},
		Resource: &Resource{
			Type: "token",
		},
		Metadata: map[string]interface{}{
			"token_type": "access+refresh",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return tokenPair, err
}

// GenerateAccessToken wraps the GenerateAccessToken method with audit logging.
func (w *TokenManagerWrapper) GenerateAccessToken(ctx context.Context, user *storage.User) (string, error) {
	start := time.Now()
	token, err := w.tokenManager.GenerateAccessToken(ctx, user)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventTokenGenerate,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   user.ID,
			Email:    user.Email,
			Username: user.Username,
			Provider: user.Provider,
		},
		Resource: &Resource{
			Type: "token",
		},
		Metadata: map[string]interface{}{
			"token_type": "access",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return token, err
}

// ValidateToken wraps the ValidateToken method with audit logging.
func (w *TokenManagerWrapper) ValidateToken(ctx context.Context, tokenString string) (*jwt.Claims, error) {
	start := time.Now()
	claims, err := w.tokenManager.ValidateToken(ctx, tokenString)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventTokenValidate,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "token",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		event.Actor = &Actor{
			UserID:   claims.UserID,
			Email:    claims.Email,
			Provider: claims.Provider,
		}
		event.Metadata = map[string]interface{}{
			"token_type": string(claims.Type),
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return claims, err
}

// RefreshAccessToken wraps the RefreshAccessToken method with audit logging.
func (w *TokenManagerWrapper) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*jwt.TokenPair, error) {
	start := time.Now()
	tokenPair, err := w.tokenManager.RefreshAccessToken(ctx, refreshTokenString)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventTokenRefresh,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "token",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		// Extract user info from the refresh token (best effort)
		if claims, parseErr := w.tokenManager.ValidateToken(ctx, refreshTokenString); parseErr == nil {
			event.Actor = &Actor{
				UserID:   claims.UserID,
				Email:    claims.Email,
				Provider: claims.Provider,
			}
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return tokenPair, err
}

// RevokeRefreshToken wraps the RevokeRefreshToken method with audit logging.
func (w *TokenManagerWrapper) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	start := time.Now()
	err := w.tokenManager.RevokeRefreshToken(ctx, refreshTokenString)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventTokenRevoke,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "token",
		},
		Metadata: map[string]interface{}{
			"token_type": "refresh",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		// Extract user info from the token (best effort)
		if claims, parseErr := w.tokenManager.ValidateToken(ctx, refreshTokenString); parseErr == nil {
			event.Actor = &Actor{
				UserID:   claims.UserID,
				Email:    claims.Email,
				Provider: claims.Provider,
			}
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// RevokeAllUserTokens wraps the RevokeAllUserTokens method with audit logging.
func (w *TokenManagerWrapper) RevokeAllUserTokens(ctx context.Context, userID string) error {
	start := time.Now()
	err := w.tokenManager.RevokeAllUserTokens(ctx, userID)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventTokenRevoke,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID: userID,
		},
		Resource: &Resource{
			Type: "token",
		},
		Metadata: map[string]interface{}{
			"revoke_all": true,
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// SessionManagerWrapper wraps a session.Manager to add audit logging.
type SessionManagerWrapper struct {
	sessionManager *session.Manager
	auditor        AuditLogger
	sourceFunc     SourceExtractor
}

// NewSessionManagerWrapper creates an audit-logging wrapper around a session manager.
func NewSessionManagerWrapper(sessionManager *session.Manager, auditor AuditLogger, sourceFunc SourceExtractor) *SessionManagerWrapper {
	if auditor == nil {
		auditor = DefaultAuditor()
	}
	return &SessionManagerWrapper{
		sessionManager: sessionManager,
		auditor:        auditor,
		sourceFunc:     sourceFunc,
	}
}

// Create wraps the Create method with audit logging.
func (w *SessionManagerWrapper) Create(ctx context.Context, req session.CreateSessionRequest) (*session.Session, error) {
	start := time.Now()
	sess, err := w.sessionManager.Create(ctx, req)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventSessionCreate,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   req.UserID,
			Email:    req.Email,
			Provider: req.Provider,
		},
		Resource: &Resource{
			Type: "session",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		event.Resource.ID = sess.ID
		event.SessionID = sess.ID
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return sess, err
}

// Get wraps the Get method (typically used for validation) with audit logging.
func (w *SessionManagerWrapper) Get(ctx context.Context, sessionID string) (*session.Session, error) {
	start := time.Now()
	sess, err := w.sessionManager.Get(ctx, sessionID)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventSessionValidate,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "session",
			ID:   sessionID,
		},
		SessionID: sessionID,
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		event.Actor = &Actor{
			UserID:   sess.Data.UserID,
			Email:    sess.Data.Email,
			Provider: sess.Data.Provider,
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return sess, err
}

// Update wraps the Update method with audit logging.
func (w *SessionManagerWrapper) Update(ctx context.Context, sessionID string, data *storage.SessionData) error {
	start := time.Now()
	err := w.sessionManager.Update(ctx, sessionID, data)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventSessionRefresh,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   data.UserID,
			Email:    data.Email,
			Provider: data.Provider,
		},
		Resource: &Resource{
			Type: "session",
			ID:   sessionID,
		},
		SessionID: sessionID,
		Metadata: map[string]interface{}{
			"action": "update",
		},
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// Refresh wraps the Refresh method with audit logging.
func (w *SessionManagerWrapper) Refresh(ctx context.Context, sessionID string) error {
	start := time.Now()
	err := w.sessionManager.Refresh(ctx, sessionID)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventSessionRefresh,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "session",
			ID:   sessionID,
		},
		SessionID: sessionID,
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		// Try to get session data for actor info
		if sess, getErr := w.sessionManager.Get(ctx, sessionID); getErr == nil {
			event.Actor = &Actor{
				UserID:   sess.Data.UserID,
				Email:    sess.Data.Email,
				Provider: sess.Data.Provider,
			}
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// Delete wraps the Delete method with audit logging.
func (w *SessionManagerWrapper) Delete(ctx context.Context, sessionID string) error {
	start := time.Now()

	// Try to get session data before deletion for audit trail
	sess, _ := w.sessionManager.Get(ctx, sessionID)

	err := w.sessionManager.Delete(ctx, sessionID)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventSessionDelete,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "session",
			ID:   sessionID,
		},
		SessionID: sessionID,
	}

	if sess != nil {
		event.Actor = &Actor{
			UserID:   sess.Data.UserID,
			Email:    sess.Data.Email,
			Provider: sess.Data.Provider,
		}
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return err
}

// Validate wraps the Validate method with audit logging.
func (w *SessionManagerWrapper) Validate(ctx context.Context, sessionID string) (*storage.SessionData, error) {
	start := time.Now()
	data, err := w.sessionManager.Validate(ctx, sessionID)

	event := &AuditEvent{
		Timestamp:   start,
		EventType:   EventSessionValidate,
		EventResult: EventResultSuccess,
		Resource: &Resource{
			Type: "session",
			ID:   sessionID,
		},
		SessionID: sessionID,
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	} else {
		event.Actor = &Actor{
			UserID:   data.UserID,
			Email:    data.Email,
			Provider: data.Provider,
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	_ = w.auditor.Log(ctx, event)
	return data, err
}
