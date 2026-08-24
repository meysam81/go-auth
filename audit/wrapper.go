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
//
// Deprecated: the wrappers in this file mirror every method of three types by
// hand (F-22), and nothing makes them keep up. A method added to
// basic.Authenticator, jwt.TokenManager or session.Manager is simply not
// audited until someone remembers to write a matching wrapper, and the gap is
// invisible: the build passes, the calls work, and the evidence for those
// operations is absent. This release is itself the demonstration —
// jwt.TokenManager.ValidateAccessToken, jwt.TokenManager.ValidateRefreshToken
// and session.Manager.Rotate all landed upstream and none of them is audited
// here. For a package that exists to produce compliance evidence, silently
// incomplete is the worst available failure mode.
//
// v2 removes the wrappers and keeps AuditLogger and the event vocabulary, which
// are the actual primitive: the application decorates its own call sites, where
// it also holds the *http.Request and therefore the source address, user agent
// and request ID that a decorator reading only a context.Context cannot see
// unless the application put them there first.
type BasicAuthWrapper struct {
	authenticator *basic.Authenticator
	auditor       AuditLogger
	sourceFunc    SourceExtractor
	logErrHandler LogErrorHandler
}

// SetLogErrorHandler installs the handler notified when the AuditLogger rejects
// an event. Passing nil restores DefaultLogErrorHandler.
//
// A failed audit write used to be discarded outright, so a sink that was down
// produced a request that looked entirely normal and an audit trail with a hole
// in it. Install the handler at construction time: it is not safe to call
// concurrently with the wrapped methods.
func (w *BasicAuthWrapper) SetLogErrorHandler(h LogErrorHandler) {
	w.logErrHandler = h
}

// emit records the event and reports, rather than discards, a sink failure.
func (w *BasicAuthWrapper) emit(ctx context.Context, event *AuditEvent) {
	emitAudit(ctx, w.auditor, w.logErrHandler, event)
}

// SourceExtractor is a function that extracts source information from the context.
// This allows downstream users to inject request-specific data (IP, user agent, etc.).
type SourceExtractor func(ctx context.Context) *Source

// NewBasicAuthWrapper creates an audit-logging wrapper around a basic authenticator.
//
// Deprecated: see BasicAuthWrapper (F-22). v2 removes it; decorate the call
// sites in the application, where the request context is available.
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
	// This wrapper is itself Deprecated (F-22) and is removed in v2 alongside
	// basic.Authenticator.Register, so for as long as both exist the wrapper's
	// job is to forward to the deprecated primitive. Migrating the call would
	// change v1 behavior; the deprecation marker stays as advance notice.
	user, err := w.authenticator.Register(ctx, req) //nolint:staticcheck // SA1019: deprecated wrapper must keep calling the deprecated method it wraps until both are removed in v2.

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

	w.emit(ctx, event)
	return user, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
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

	w.emit(ctx, event)
	return user, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
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

	w.emit(ctx, event)
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

	w.emit(ctx, event)
	return err
}

// TokenManagerWrapper wraps a jwt.TokenManager to add audit logging.
//
// Deprecated: the wrappers in this file mirror every method of three types by
// hand (F-22), and nothing makes them keep up. A method added to
// basic.Authenticator, jwt.TokenManager or session.Manager is simply not
// audited until someone remembers to write a matching wrapper, and the gap is
// invisible: the build passes, the calls work, and the evidence for those
// operations is absent. This release is itself the demonstration —
// jwt.TokenManager.ValidateAccessToken, jwt.TokenManager.ValidateRefreshToken
// and session.Manager.Rotate all landed upstream and none of them is audited
// here. For a package that exists to produce compliance evidence, silently
// incomplete is the worst available failure mode.
//
// v2 removes the wrappers and keeps AuditLogger and the event vocabulary, which
// are the actual primitive: the application decorates its own call sites, where
// it also holds the *http.Request and therefore the source address, user agent
// and request ID that a decorator reading only a context.Context cannot see
// unless the application put them there first.
type TokenManagerWrapper struct {
	tokenManager  *jwt.TokenManager
	auditor       AuditLogger
	sourceFunc    SourceExtractor
	logErrHandler LogErrorHandler
}

// SetLogErrorHandler installs the handler notified when the AuditLogger rejects
// an event. Passing nil restores DefaultLogErrorHandler. Install it at
// construction time; it is not safe to call concurrently with the wrapped
// methods.
func (w *TokenManagerWrapper) SetLogErrorHandler(h LogErrorHandler) {
	w.logErrHandler = h
}

// emit records the event and reports, rather than discards, a sink failure.
func (w *TokenManagerWrapper) emit(ctx context.Context, event *AuditEvent) {
	emitAudit(ctx, w.auditor, w.logErrHandler, event)
}

// NewTokenManagerWrapper creates an audit-logging wrapper around a token manager.
//
// Deprecated: see TokenManagerWrapper (F-22). v2 removes it; decorate the call
// sites in the application, where the request context is available.
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

// refreshTokenActor resolves the subject of a refresh token so the audit record
// names who refreshed or revoked it.
//
// It calls ValidateRefreshToken deliberately. Since F-02, ValidateToken means
// ValidateAccessToken and rejects every refresh token on its type claim, so the
// two call sites that used it here could never produce an actor: each
// successful token.refresh and token.revoke event was written anonymously, and
// nothing failed to make that visible. Resolution costs one parse and one store
// lookup, and it emits no event of its own -- the event being enriched is the
// record of the operation.
func (w *TokenManagerWrapper) refreshTokenActor(ctx context.Context, refreshTokenString string) (*Actor, error) {
	claims, err := w.tokenManager.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
	}
	return &Actor{
		UserID:   claims.UserID,
		Email:    claims.Email,
		Provider: claims.Provider,
	}, nil
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

	w.emit(ctx, event)
	return tokenPair, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
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

	w.emit(ctx, event)
	return token, err
}

// ValidateToken wraps the ValidateToken method with audit logging.
//
// Since F-02 the wrapped call accepts access tokens only, so a refresh token
// presented as a bearer credential is now recorded as a failed token.validate
// event instead of a successful one. jwt.TokenManager.ValidateAccessToken and
// ValidateRefreshToken have no wrapper here and are therefore unaudited: see
// TokenManagerWrapper.
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

	w.emit(ctx, event)
	return claims, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
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
		// Read after the fact, which is safe here because refreshing does not
		// consume the token: it is still a live credential the store will
		// resolve. A failed refresh needs no second attempt at the same parse -
		// the wrapped call has already reported why the token did not verify.
		actor, lookupErr := w.refreshTokenActor(ctx, refreshTokenString)
		if lookupErr != nil {
			noteActorLookupError(event, lookupErr)
		} else {
			event.Actor = actor
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	w.emit(ctx, event)
	return tokenPair, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
}

// RevokeRefreshToken wraps the RevokeRefreshToken method with audit logging.
func (w *TokenManagerWrapper) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	start := time.Now()

	// Resolved before the revocation, not after: the resolution consults the
	// token store, and once the token is revoked that lookup fails by design.
	// Reading the actor afterwards would leave every successful token.revoke
	// event anonymous, which is what the revocation record most needs to name.
	// SessionManagerWrapper.Delete reads its actor before the delete for the
	// same reason.
	actor, lookupErr := w.refreshTokenActor(ctx, refreshTokenString)

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

	// The subject is recorded whether or not the revocation succeeded: a revoke
	// that failed is exactly the entry an investigator needs attributed.
	if lookupErr != nil {
		noteActorLookupError(event, lookupErr)
	} else {
		event.Actor = actor
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	w.emit(ctx, event)
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

	w.emit(ctx, event)
	return err
}

// SessionManagerWrapper wraps a session.Manager to add audit logging.
//
// Deprecated: the wrappers in this file mirror every method of three types by
// hand (F-22), and nothing makes them keep up. A method added to
// basic.Authenticator, jwt.TokenManager or session.Manager is simply not
// audited until someone remembers to write a matching wrapper, and the gap is
// invisible: the build passes, the calls work, and the evidence for those
// operations is absent. This release is itself the demonstration —
// jwt.TokenManager.ValidateAccessToken, jwt.TokenManager.ValidateRefreshToken
// and session.Manager.Rotate all landed upstream and none of them is audited
// here. For a package that exists to produce compliance evidence, silently
// incomplete is the worst available failure mode.
//
// v2 removes the wrappers and keeps AuditLogger and the event vocabulary, which
// are the actual primitive: the application decorates its own call sites, where
// it also holds the *http.Request and therefore the source address, user agent
// and request ID that a decorator reading only a context.Context cannot see
// unless the application put them there first.
type SessionManagerWrapper struct {
	sessionManager *session.Manager
	auditor        AuditLogger
	sourceFunc     SourceExtractor
	logErrHandler  LogErrorHandler
}

// SetLogErrorHandler installs the handler notified when the AuditLogger rejects
// an event. Passing nil restores DefaultLogErrorHandler. Install it at
// construction time; it is not safe to call concurrently with the wrapped
// methods.
func (w *SessionManagerWrapper) SetLogErrorHandler(h LogErrorHandler) {
	w.logErrHandler = h
}

// emit records the event and reports, rather than discards, a sink failure.
func (w *SessionManagerWrapper) emit(ctx context.Context, event *AuditEvent) {
	emitAudit(ctx, w.auditor, w.logErrHandler, event)
}

// NewSessionManagerWrapper creates an audit-logging wrapper around a session manager.
//
// Deprecated: see SessionManagerWrapper (F-22). v2 removes it; decorate the
// call sites in the application, where the request context is available.
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

	w.emit(ctx, event)
	return sess, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
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

	w.emit(ctx, event)
	return sess, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
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

	w.emit(ctx, event)
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
		// Best-effort actor enrichment. Get does not extend the session's TTL,
		// so reading it here cannot prolong the credential it describes.
		sess, getErr := w.sessionManager.Get(ctx, sessionID)
		switch {
		case sess != nil:
			event.Actor = &Actor{
				UserID:   sess.Data.UserID,
				Email:    sess.Data.Email,
				Provider: sess.Data.Provider,
			}
		case getErr != nil:
			noteActorLookupError(event, getErr)
		}
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	w.emit(ctx, event)
	return err
}

// Delete wraps the Delete method with audit logging.
func (w *SessionManagerWrapper) Delete(ctx context.Context, sessionID string) error {
	start := time.Now()

	// Best-effort enrichment: the actor is read before the row disappears so
	// the record names who was signed out. The lookup error is kept rather than
	// discarded — an audit entry with no actor and no explanation cannot be
	// told apart from a session that never had one, and "the evidence is
	// missing for a reason nobody recorded" is the failure mode this package
	// exists to avoid.
	sess, lookupErr := w.sessionManager.Get(ctx, sessionID)

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
	} else if lookupErr != nil {
		noteActorLookupError(event, lookupErr)
	}

	if err != nil {
		event.EventResult = EventResultFailure
		event.Error = err.Error()
	}

	if w.sourceFunc != nil {
		event.Source = w.sourceFunc(ctx)
	}

	w.emit(ctx, event)
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

	w.emit(ctx, event)
	return data, err //nolint:nilnil // Passthrough: the wrapped call already pairs a nil result with its error; the wrapper must not reshape it.
}

// noteActorLookupError records why an event carries no actor.
//
// An entry with a missing actor and no explanation cannot be told apart from an
// operation that never had one, so a best-effort lookup that fails is written
// down rather than dropped. It is added to Metadata rather than to Error, which
// belongs to the wrapped operation's own outcome: enrichment failing does not
// make a successful revocation a failed one.
func noteActorLookupError(event *AuditEvent, err error) {
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{}, 1)
	}
	event.Metadata["actor_lookup_error"] = err.Error()
}

// emitAudit writes an event and routes a sink failure to a handler.
//
// The wrapped operation's own outcome is never changed by an audit failure: a
// sign-in that succeeded did succeed, and turning a logging outage into an
// authentication outage is a denial of service with extra steps. The failure is
// surfaced instead, because the previous behavior - discarding the error -
// meant a sink that was down produced no signal anywhere (F-22).
func emitAudit(ctx context.Context, auditor AuditLogger, handler LogErrorHandler, event *AuditEvent) {
	if auditor == nil {
		return
	}
	err := auditor.Log(ctx, event)
	if err == nil {
		return
	}
	if handler == nil {
		handler = DefaultLogErrorHandler
	}
	handler(ctx, event, err)
}
