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

func TestBasicAuthWrapper_Register(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	auth, err := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

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
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	auth, _ := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})

	// Register a user first
	_, _ = auth.Register(context.Background(), basic.RegisterRequest{
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
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	auth, _ := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})

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
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	auth, _ := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})

	mockAuditor := &MockAuditor{}
	sourceFunc := func(ctx context.Context) *Source {
		return &Source{
			IPAddress: "192.168.1.1",
			UserAgent: "Test/1.0",
			RequestID: "req123",
		}
	}
	wrapper := NewBasicAuthWrapper(auth, mockAuditor, sourceFunc)

	// Register a user
	_, _ = wrapper.Register(context.Background(), basic.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	})

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

func TestTokenManagerWrapper_GenerateTokenPair(t *testing.T) {
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()

	tm, err := jwt.NewTokenManager(jwt.Config{
		UserStore:      userStore,
		TokenStore:     tokenStore,
		SigningKey:     []byte("test-key-32-bytes-long-secret!"),
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

	tm, _ := jwt.NewTokenManager(jwt.Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: []byte("test-key-32-bytes-long-secret!"),
	})

	mockAuditor := &MockAuditor{}
	wrapper := NewTokenManagerWrapper(tm, mockAuditor, nil)

	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Provider: "basic",
	}

	// Generate token first
	tokenPair, _ := tm.GenerateTokenPair(context.Background(), user)

	// Reset mock to clear generate event
	mockAuditor.Reset()

	// Validate token
	_, err := wrapper.ValidateToken(context.Background(), tokenPair.AccessToken)
	if err != nil {
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
	sm, _ := session.NewManager(session.Config{
		Store:      sessionStore,
		SessionTTL: 24 * time.Hour,
	})

	// Create a session first
	sess, _ := sm.Create(context.Background(), session.CreateSessionRequest{
		UserID:   "user123",
		Email:    "test@example.com",
		Provider: "basic",
	})

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
	sm, _ := session.NewManager(session.Config{
		Store:      sessionStore,
		SessionTTL: 24 * time.Hour,
	})

	// Create a session first
	sess, _ := sm.Create(context.Background(), session.CreateSessionRequest{
		UserID:   "user123",
		Email:    "test@example.com",
		Provider: "basic",
	})

	mockAuditor := &MockAuditor{}
	wrapper := NewSessionManagerWrapper(sm, mockAuditor, nil)

	// Delete session
	err := wrapper.Delete(context.Background(), sess.ID)
	if err != nil {
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
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	auth, _ := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})

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
	userStore := storage.NewInMemoryUserStore()
	credStore := storage.NewInMemoryCredentialStore()

	auth, _ := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credStore,
	})

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
