package session

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/meysam81/go-auth/storage"
)

func TestNewManager(t *testing.T) {
	store := storage.NewInMemorySessionStore()

	// Test with default config
	mgr, err := NewManager(Config{
		Store: store,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if mgr.sessionTTL != DefaultSessionTTL {
		t.Errorf("Expected default TTL %v, got %v", DefaultSessionTTL, mgr.sessionTTL)
	}
	if mgr.sessionIDBytes != DefaultSessionIDLength {
		t.Errorf("Expected default ID length %d, got %d", DefaultSessionIDLength, mgr.sessionIDBytes)
	}

	// Test with custom config
	customTTL := 2 * time.Hour
	customIDBytes := 16
	mgr, err = NewManager(Config{
		Store:          store,
		SessionTTL:     customTTL,
		SessionIDBytes: customIDBytes,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if mgr.sessionTTL != customTTL {
		t.Errorf("Expected custom TTL %v, got %v", customTTL, mgr.sessionTTL)
	}
	if mgr.sessionIDBytes != customIDBytes {
		t.Errorf("Expected custom ID length %d, got %d", customIDBytes, mgr.sessionIDBytes)
	}

	// Test without store (should fail)
	_, err = NewManager(Config{})
	if err == nil {
		t.Fatal("Expected error when store is nil")
	}
}

func TestManager_Create(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})
	ctx := context.Background()

	// Test creating session with default TTL
	req := CreateSessionRequest{
		UserID:   "user1",
		Email:    "test@example.com",
		Provider: "local",
		Metadata: map[string]interface{}{"role": "admin"},
	}

	session, err := mgr.Create(ctx, req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify session ID is generated
	if session.ID == "" {
		t.Error("Session ID should not be empty")
	}

	// Verify session ID is valid base64
	_, err = base64.RawURLEncoding.DecodeString(session.ID)
	if err != nil {
		t.Errorf("Session ID should be valid base64: %v", err)
	}

	// Verify session data
	if session.Data.UserID != req.UserID {
		t.Errorf("Expected UserID %s, got %s", req.UserID, session.Data.UserID)
	}
	if session.Data.Email != req.Email {
		t.Errorf("Expected Email %s, got %s", req.Email, session.Data.Email)
	}
	if session.Data.Provider != req.Provider {
		t.Errorf("Expected Provider %s, got %s", req.Provider, session.Data.Provider)
	}

	// Verify metadata
	if session.Data.Metadata["role"] != "admin" {
		t.Error("Metadata should be set")
	}

	// Verify timestamps
	if session.Data.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if session.Data.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}

	// Verify TTL
	expectedExpiry := session.Data.CreatedAt.Add(DefaultSessionTTL)
	if !session.Data.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("Expected expiry %v, got %v", expectedExpiry, session.Data.ExpiresAt)
	}

	// Test creating session with custom TTL
	customTTL := 30 * time.Minute
	reqCustomTTL := CreateSessionRequest{
		UserID: "user2",
		TTL:    customTTL,
	}

	sessionCustom, err := mgr.Create(ctx, reqCustomTTL)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expectedCustomExpiry := sessionCustom.Data.CreatedAt.Add(customTTL)
	if !sessionCustom.Data.ExpiresAt.Equal(expectedCustomExpiry) {
		t.Errorf("Expected custom expiry %v, got %v", expectedCustomExpiry, sessionCustom.Data.ExpiresAt)
	}
}

func TestManager_Get(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
		Email:  "test@example.com",
	}
	created, _ := mgr.Create(ctx, req)

	// Test getting existing session
	session, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session.ID != created.ID {
		t.Errorf("Expected session ID %s, got %s", created.ID, session.ID)
	}
	if session.Data.UserID != req.UserID {
		t.Errorf("Expected UserID %s, got %s", req.UserID, session.Data.UserID)
	}

	// Test getting non-existent session
	_, err = mgr.Get(ctx, "nonexistent")
	if err != ErrSessionNotFound {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test getting expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    1 * time.Millisecond, // Very short TTL
	}
	expiredSession, _ := mgr.Create(ctx, expiredReq)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	_, err = mgr.Get(ctx, expiredSession.ID)
	if err != ErrSessionExpired {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_Update(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
		Email:  "test@example.com",
	}
	created, _ := mgr.Create(ctx, req)

	// Test updating session
	newData := &storage.SessionData{
		UserID:   "user1",
		Email:    "updated@example.com",
		Metadata: map[string]interface{}{"updated": true},
	}
	err := mgr.Update(ctx, created.ID, newData)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify update
	session, _ := mgr.Get(ctx, created.ID)
	if session.Data.Email != "updated@example.com" {
		t.Errorf("Expected email 'updated@example.com', got %s", session.Data.Email)
	}
	if session.Data.Metadata["updated"] != true {
		t.Error("Metadata should be updated")
	}

	// Test updating non-existent session
	err = mgr.Update(ctx, "nonexistent", newData)
	if err != ErrSessionNotFound {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test updating expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    -1 * time.Hour,
	}
	expiredSession, _ := mgr.Create(ctx, expiredReq)
	err = mgr.Update(ctx, expiredSession.ID, newData)
	if err != ErrSessionExpired {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_Refresh(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store:      store,
		SessionTTL: 1 * time.Hour,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
	}
	created, _ := mgr.Create(ctx, req)

	originalExpiry := created.Data.ExpiresAt

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Test refreshing session
	err := mgr.Refresh(ctx, created.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify expiry was extended
	session, _ := mgr.Get(ctx, created.ID)
	if !session.Data.ExpiresAt.After(originalExpiry) {
		t.Error("ExpiresAt should be extended after refresh")
	}

	// Test refreshing non-existent session
	err = mgr.Refresh(ctx, "nonexistent")
	if err != ErrSessionNotFound {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test refreshing expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    -1 * time.Hour,
	}
	expiredSession, _ := mgr.Create(ctx, expiredReq)
	err = mgr.Refresh(ctx, expiredSession.ID)
	if err != ErrSessionExpired {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_Delete(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
	}
	created, _ := mgr.Create(ctx, req)

	// Test deleting session
	err := mgr.Delete(ctx, created.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify session is deleted
	_, err = mgr.Get(ctx, created.ID)
	if err != ErrSessionNotFound {
		t.Error("Session should be deleted")
	}

	// Test deleting non-existent session (should not error)
	err = mgr.Delete(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Expected no error for deleting non-existent session, got %v", err)
	}
}

func TestManager_Validate(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
		Email:  "test@example.com",
	}
	created, _ := mgr.Create(ctx, req)

	// Test validating existing session
	data, err := mgr.Validate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if data.UserID != req.UserID {
		t.Errorf("Expected UserID %s, got %s", req.UserID, data.UserID)
	}

	// Test validating non-existent session
	_, err = mgr.Validate(ctx, "nonexistent")
	if err != ErrSessionNotFound {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test validating expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    -1 * time.Hour,
	}
	expiredSession, _ := mgr.Create(ctx, expiredReq)
	_, err = mgr.Validate(ctx, expiredSession.ID)
	if err != ErrSessionExpired {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestGenerateSessionID(t *testing.T) {
	store := storage.NewInMemorySessionStore()

	// Test with default ID length
	mgr, _ := NewManager(Config{
		Store: store,
	})

	id1, err := mgr.generateSessionID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it's valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(id1)
	if err != nil {
		t.Errorf("Session ID should be valid base64: %v", err)
	}

	// Verify length
	if len(decoded) != DefaultSessionIDLength {
		t.Errorf("Expected %d bytes, got %d", DefaultSessionIDLength, len(decoded))
	}

	// Test uniqueness
	id2, _ := mgr.generateSessionID()
	if id1 == id2 {
		t.Error("Session IDs should be unique")
	}

	// Test with custom ID length
	customMgr, _ := NewManager(Config{
		Store:          store,
		SessionIDBytes: 16,
	})

	customID, err := customMgr.generateSessionID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	decodedCustom, _ := base64.RawURLEncoding.DecodeString(customID)
	if len(decodedCustom) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(decodedCustom))
	}
}

func TestNullSessionLocation(t *testing.T) {
	loc := &NullSessionLocation{}

	// Test GetSessionID
	_, err := loc.GetSessionID()
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test SetSessionID (should not error)
	err = loc.SetSessionID("session123")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test ClearSessionID (should not error)
	err = loc.ClearSessionID()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// Test session ID entropy
func TestSessionIDEntropy(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})

	// Generate many IDs and check for duplicates
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := mgr.generateSessionID()
		if err != nil {
			t.Fatalf("Failed to generate session ID: %v", err)
		}
		if ids[id] {
			t.Fatalf("Duplicate session ID generated: %s", id)
		}
		ids[id] = true
	}
}

// Test concurrent session operations
func TestManager_Concurrency(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr, _ := NewManager(Config{
		Store: store,
	})
	ctx := context.Background()

	// Create sessions concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			req := CreateSessionRequest{
				UserID: string(rune(id)),
			}
			_, err := mgr.Create(ctx, req)
			if err != nil {
				t.Errorf("Failed to create session: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
