package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/auth/jwt"
	"github.com/meysam81/go-auth/session"
	"github.com/meysam81/go-auth/storage"
)

// MockAuditor for testing
type MockAuditor struct {
	events []*AuditEvent
}

func (m *MockAuditor) Log(ctx context.Context, event *AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *MockAuditor) LastEvent() *AuditEvent {
	if len(m.events) == 0 {
		return nil
	}
	return m.events[len(m.events)-1]
}

func (m *MockAuditor) EventCount() int {
	return len(m.events)
}

func (m *MockAuditor) Reset() {
	m.events = nil
}

// newTestAuthenticator builds a basic.Authenticator over in-memory stores and
// fails the test rather than returning a nil authenticator that would panic
// several lines later with an unrelated message.
func newTestAuthenticator(t *testing.T) *basic.Authenticator {
	t.Helper()

	auth, err := basic.NewAuthenticator(basic.Config{
		UserStore:       storage.NewInMemoryUserStore(),
		CredentialStore: storage.NewInMemoryCredentialStore(),
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth
}

// registerTestUser seeds a user through the primitive under test. It is the
// single place this package calls the deprecated basic.Register, so the
// suppression below is the only one needed in the test file.
func registerTestUser(t *testing.T, auth *basic.Authenticator, req basic.RegisterRequest) *storage.User {
	t.Helper()

	//nolint:staticcheck // SA1019: Register is the only v1 API that creates a credential, and these tests must exercise the v1 surface until v2 removes it.
	user, err := auth.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return user
}

func TestBasicAuthWrapper_Register(t *testing.T) {
	auth := newTestAuthenticator(t)

	mockAuditor := &MockAuditor{}
	wrapper := NewBasicAuthWrapper(auth, mockAuditor, nil)

	// Test successful registration
	req := basic.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
		Name:     "Test User",
	}

	user, err := wrapper.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Check audit event
	if mockAuditor.EventCount() != 1 {
		t.Fatalf("Expected 1 audit event, got %d", mockAuditor.EventCount())
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventAuthRegister {
		t.Errorf("EventType = %v, want %v", event.EventType, EventAuthRegister)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
	if event.Actor.Email != "test@example.com" {
		t.Errorf("Actor.Email = %v, want %v", event.Actor.Email, "test@example.com")
	}
	if event.Actor.UserID != user.ID {
		t.Errorf("Actor.UserID = %v, want %v", event.Actor.UserID, user.ID)
	}
}

func TestBasicAuthWrapper_Authenticate_Success(t *testing.T) {
	auth := newTestAuthenticator(t)

	// Register a user first
	registerTestUser(t, auth, basic.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	})

	mockAuditor := &MockAuditor{}
	wrapper := NewBasicAuthWrapper(auth, mockAuditor, nil)

	// Test successful authentication
	user, err := wrapper.Authenticate(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventAuthLogin {
		t.Errorf("EventType = %v, want %v", event.EventType, EventAuthLogin)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
	if event.Actor.UserID != user.ID {
		t.Errorf("Actor.UserID = %v, want %v", event.Actor.UserID, user.ID)
	}
}

func TestBasicAuthWrapper_Authenticate_Failure(t *testing.T) {
	auth := newTestAuthenticator(t)

	mockAuditor := &MockAuditor{}
	wrapper := NewBasicAuthWrapper(auth, mockAuditor, nil)

	// Test failed authentication
	_, err := wrapper.Authenticate(context.Background(), "nonexistent@example.com", "wrongpass")
	if err == nil {
		t.Fatal("Expected authentication to fail")
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventAuthLogin {
		t.Errorf("EventType = %v, want %v", event.EventType, EventAuthLogin)
	}
	if event.EventResult != EventResultFailure {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultFailure)
	}
	if event.Error == "" {
		t.Error("Expected error message in audit event")
	}
}

func TestBasicAuthWrapper_WithSourceExtractor(t *testing.T) {
	auth := newTestAuthenticator(t)

	mockAuditor := &MockAuditor{}
	sourceFunc := func(_ context.Context) *Source {
		return &Source{
			IPAddress: "192.168.1.1",
			UserAgent: "Test/1.0",
			RequestID: "req123",
		}
	}
	wrapper := NewBasicAuthWrapper(auth, mockAuditor, sourceFunc)

	// Register a user
	if _, err := wrapper.Register(context.Background(), basic.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.Source == nil {
		t.Fatal("Expected source to be set")
	}
	if event.Source.IPAddress != "192.168.1.1" {
		t.Errorf("Source.IPAddress = %v, want %v", event.Source.IPAddress, "192.168.1.1")
	}
	if event.Source.UserAgent != "Test/1.0" {
		t.Errorf("Source.UserAgent = %v, want %v", event.Source.UserAgent, "Test/1.0")
	}
}

// testSigningKey returns a 32-byte HS256 secret, the RFC 7518 section 3.2
// minimum jwt.NewTokenManager enforces. The literal it replaced announced
// itself as 32 bytes and was 30, which is the failure mode a construction-time
// check exists to catch.
func testSigningKey() []byte {
	return []byte("audit-test-signing-key-32-bytes!")
}

// newTestTokenManager builds a manager over in-memory stores with one user
// already present, so a refresh can resolve the subject it names.
func newTestTokenManager(t *testing.T, user *storage.User) *jwt.TokenManager {
	t.Helper()

	userStore := storage.NewInMemoryUserStore()
	if err := userStore.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tm, err := jwt.NewTokenManager(jwt.Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: testSigningKey(),
	})
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

// TestTokenManagerWrapper_RefreshAndRevokeRecordActor covers the regression the
// F-02 fix introduced here. Both call sites enriched their event by calling
// ValidateToken on the refresh token; once ValidateToken came to mean
// ValidateAccessToken, that call could only ever fail, and every successful
// token.refresh and token.revoke event was written with no actor at all. The
// build passed, the operations worked, and the evidence for who refreshed or
// revoked a credential was simply absent -- so the assertion that matters is
// not that an event was emitted, but that it names somebody.
func TestTokenManagerWrapper_RefreshAndRevokeRecordActor(t *testing.T) {
	ctx := context.Background()
	user := &storage.User{ID: "user123", Email: "test@example.com", Provider: "basic"}
	tm := newTestTokenManager(t, user)

	mockAuditor := &MockAuditor{}
	wrapper := NewTokenManagerWrapper(tm, mockAuditor, nil)

	pair, err := tm.GenerateTokenPair(ctx, user)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	requireActor := func(t *testing.T, event *AuditEvent, wantType EventType) {
		t.Helper()

		if event.EventType != wantType {
			t.Fatalf("EventType = %v, want %v", event.EventType, wantType)
		}
		if event.EventResult != EventResultSuccess {
			t.Fatalf("EventResult = %v, want %v (error %q)", event.EventResult, EventResultSuccess, event.Error)
		}
		if event.Actor == nil {
			t.Fatal("A successful token event was recorded with no actor: the audit trail cannot say who did this")
		}
		if event.Actor.UserID != user.ID {
			t.Errorf("Actor.UserID = %q, want %q", event.Actor.UserID, user.ID)
		}
		if event.Actor.Email != user.Email {
			t.Errorf("Actor.Email = %q, want %q", event.Actor.Email, user.Email)
		}
		if event.Actor.Provider != user.Provider {
			t.Errorf("Actor.Provider = %q, want %q", event.Actor.Provider, user.Provider)
		}
		if _, noted := event.Metadata["actor_lookup_error"]; noted {
			t.Errorf("Actor resolved, yet the event still carries actor_lookup_error = %v", event.Metadata["actor_lookup_error"])
		}
	}

	t.Run("token.refresh names the subject", func(t *testing.T) {
		mockAuditor.Reset()

		if _, err := wrapper.RefreshAccessToken(ctx, pair.RefreshToken); err != nil {
			t.Fatalf("RefreshAccessToken: %v", err)
		}
		requireActor(t, mockAuditor.LastEvent(), EventTokenRefresh)
	})

	t.Run("token.revoke names the subject", func(t *testing.T) {
		mockAuditor.Reset()

		if err := wrapper.RevokeRefreshToken(ctx, pair.RefreshToken); err != nil {
			t.Fatalf("RevokeRefreshToken: %v", err)
		}
		event := mockAuditor.LastEvent()
		requireActor(t, event, EventTokenRevoke)
		if event.Metadata["token_type"] != "refresh" {
			t.Errorf("Metadata[token_type] = %v, want %q", event.Metadata["token_type"], "refresh")
		}
	})

	t.Run("an unresolvable actor is explained rather than left blank", func(t *testing.T) {
		// The token was revoked by the subtest above, so the store now refuses
		// to resolve it. The operation still succeeds -- revoking twice is not
		// an error -- and the event has to say why it names nobody, otherwise it
		// is indistinguishable from the defect this test exists for.
		mockAuditor.Reset()

		if err := wrapper.RevokeRefreshToken(ctx, pair.RefreshToken); err != nil {
			t.Fatalf("RevokeRefreshToken (second call): %v", err)
		}

		event := mockAuditor.LastEvent()
		if event.Actor != nil {
			t.Fatalf("Expected no actor for a revoked token, got %+v", event.Actor)
		}
		if _, noted := event.Metadata["actor_lookup_error"]; !noted {
			t.Fatalf("An event with no actor and no explanation: metadata = %v", event.Metadata)
		}
	})
}

func TestTokenManagerWrapper_GenerateTokenPair(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()

	tm, err := jwt.NewTokenManager(jwt.Config{
		UserStore:      userStore,
		TokenStore:     tokenStore,
		SigningKey:     testSigningKey(),
		AccessTokenTTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	mockAuditor := &MockAuditor{}
	wrapper := NewTokenManagerWrapper(tm, mockAuditor, nil)

	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Provider: "basic",
	}

	_, err = wrapper.GenerateTokenPair(context.Background(), user)
	if err != nil {
		t.Fatalf("GenerateTokenPair failed: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventTokenGenerate {
		t.Errorf("EventType = %v, want %v", event.EventType, EventTokenGenerate)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
	if event.Actor.UserID != "user123" {
		t.Errorf("Actor.UserID = %v, want %v", event.Actor.UserID, "user123")
	}
}

func TestTokenManagerWrapper_ValidateToken(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()

	tm, err := jwt.NewTokenManager(jwt.Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: testSigningKey(),
	})
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	mockAuditor := &MockAuditor{}
	wrapper := NewTokenManagerWrapper(tm, mockAuditor, nil)

	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Provider: "basic",
	}

	// Generate token first
	tokenPair, err := tm.GenerateTokenPair(context.Background(), user)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	// Reset mock to clear generate event
	mockAuditor.Reset()

	// Validate token
	if _, err := wrapper.ValidateToken(context.Background(), tokenPair.AccessToken); err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventTokenValidate {
		t.Errorf("EventType = %v, want %v", event.EventType, EventTokenValidate)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
}

func TestSessionManagerWrapper_Create(t *testing.T) {
	sessionStore := storage.NewInMemorySessionStore()

	sm, err := session.NewManager(session.Config{
		Store:      sessionStore,
		SessionTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	mockAuditor := &MockAuditor{}
	wrapper := NewSessionManagerWrapper(sm, mockAuditor, nil)

	req := session.CreateSessionRequest{
		UserID:   "user123",
		Email:    "test@example.com",
		Provider: "basic",
	}

	sess, err := wrapper.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventSessionCreate {
		t.Errorf("EventType = %v, want %v", event.EventType, EventSessionCreate)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
	if event.SessionID != sess.ID {
		t.Errorf("SessionID = %v, want %v", event.SessionID, sess.ID)
	}
	if event.Actor.UserID != "user123" {
		t.Errorf("Actor.UserID = %v, want %v", event.Actor.UserID, "user123")
	}
}

func TestSessionManagerWrapper_Validate(t *testing.T) {
	sessionStore := storage.NewInMemorySessionStore()
	sm, err := session.NewManager(session.Config{
		Store:      sessionStore,
		SessionTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Create a session first
	sess, err := sm.Create(context.Background(), session.CreateSessionRequest{
		UserID:   "user123",
		Email:    "test@example.com",
		Provider: "basic",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mockAuditor := &MockAuditor{}
	wrapper := NewSessionManagerWrapper(sm, mockAuditor, nil)

	// Validate session
	data, err := wrapper.Validate(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventSessionValidate {
		t.Errorf("EventType = %v, want %v", event.EventType, EventSessionValidate)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
	if event.Actor.UserID != data.UserID {
		t.Errorf("Actor.UserID = %v, want %v", event.Actor.UserID, data.UserID)
	}
}

func TestSessionManagerWrapper_Delete(t *testing.T) {
	sessionStore := storage.NewInMemorySessionStore()
	sm, err := session.NewManager(session.Config{
		Store:      sessionStore,
		SessionTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Create a session first
	sess, err := sm.Create(context.Background(), session.CreateSessionRequest{
		UserID:   "user123",
		Email:    "test@example.com",
		Provider: "basic",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mockAuditor := &MockAuditor{}
	wrapper := NewSessionManagerWrapper(sm, mockAuditor, nil)

	// Delete session
	if err := wrapper.Delete(context.Background(), sess.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	event := mockAuditor.LastEvent()
	if event.EventType != EventSessionDelete {
		t.Errorf("EventType = %v, want %v", event.EventType, EventSessionDelete)
	}
	if event.EventResult != EventResultSuccess {
		t.Errorf("EventResult = %v, want %v", event.EventResult, EventResultSuccess)
	}
	if event.SessionID != sess.ID {
		t.Errorf("SessionID = %v, want %v", event.SessionID, sess.ID)
	}
}

func TestWrappers_WithNilAuditor(t *testing.T) {
	// Test that wrappers work with nil auditor (should use default)
	auth := newTestAuthenticator(t)

	wrapper := NewBasicAuthWrapper(auth, nil, nil)

	// Should not panic
	_, err := wrapper.Register(context.Background(), basic.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Errorf("Register with nil auditor failed: %v", err)
	}
}

// MockFailingAuditor for testing error handling
type MockFailingAuditor struct{}

func (m *MockFailingAuditor) Log(ctx context.Context, event *AuditEvent) error {
	return errors.New("audit logging failed")
}

func TestWrappers_AuditFailureDoesNotBlockOperation(t *testing.T) {
	auth := newTestAuthenticator(t)

	failingAuditor := &MockFailingAuditor{}
	wrapper := NewBasicAuthWrapper(auth, failingAuditor, nil)

	// Operation should succeed even if audit logging fails
	user, err := wrapper.Register(context.Background(), basic.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Errorf("Operation failed when audit logging failed: %v", err)
	}
	if user == nil {
		t.Error("Expected user to be created despite audit failure")
	}
}
