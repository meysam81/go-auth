package session

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/meysam81/go-auth/storage"
)

// newTestManager builds a Manager or fails the test. A discarded constructor
// error leaves the test asserting against a nil manager.
func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

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
	mgr := newTestManager(t, Config{
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
	mgr := newTestManager(t, Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
		Email:  "test@example.com",
	}
	created, err := mgr.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test getting expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    1 * time.Millisecond, // Very short TTL
	}
	expiredSession, err := mgr.Create(ctx, expiredReq)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	_, err = mgr.Get(ctx, expiredSession.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_Update(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
		Email:  "test@example.com",
	}
	created, err := mgr.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Test updating session
	newData := &storage.SessionData{
		UserID:   "user1",
		Email:    "updated@example.com",
		Metadata: map[string]interface{}{"updated": true},
	}
	if err = mgr.Update(ctx, created.ID, newData); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify update
	session, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if session.Data.Email != "updated@example.com" {
		t.Errorf("Expected email 'updated@example.com', got %s", session.Data.Email)
	}
	if session.Data.Metadata["updated"] != true {
		t.Error("Metadata should be updated")
	}

	// Test updating non-existent session
	err = mgr.Update(ctx, "nonexistent", newData)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test updating expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    -1 * time.Hour,
	}
	expiredSession, err := mgr.Create(ctx, expiredReq)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = mgr.Update(ctx, expiredSession.ID, newData)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_Refresh(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{
		Store:      store,
		SessionTTL: 1 * time.Hour,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
	}
	created, err := mgr.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	originalExpiry := created.Data.ExpiresAt

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Test refreshing session
	if err = mgr.Refresh(ctx, created.ID); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify expiry was extended
	session, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !session.Data.ExpiresAt.After(originalExpiry) {
		t.Error("ExpiresAt should be extended after refresh")
	}

	// Test refreshing non-existent session
	err = mgr.Refresh(ctx, "nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test refreshing expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    -1 * time.Hour,
	}
	expiredSession, err := mgr.Create(ctx, expiredReq)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = mgr.Refresh(ctx, expiredSession.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_Delete(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
	}
	created, err := mgr.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Test deleting session
	if err = mgr.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify session is deleted
	_, err = mgr.Get(ctx, created.ID)
	if !errors.Is(err, ErrSessionNotFound) {
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
	mgr := newTestManager(t, Config{
		Store: store,
	})
	ctx := context.Background()

	// Create a session
	req := CreateSessionRequest{
		UserID: "user1",
		Email:  "test@example.com",
	}
	created, err := mgr.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	// Test validating expired session
	expiredReq := CreateSessionRequest{
		UserID: "user2",
		TTL:    -1 * time.Hour,
	}
	expiredSession, err := mgr.Create(ctx, expiredReq)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = mgr.Validate(ctx, expiredSession.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestGenerateSessionID(t *testing.T) {
	store := storage.NewInMemorySessionStore()

	// Test with default ID length
	mgr := newTestManager(t, Config{
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
	id2, err := mgr.generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID: %v", err)
	}
	if id1 == id2 {
		t.Error("Session IDs should be unique")
	}

	// Test with custom ID length
	customMgr := newTestManager(t, Config{
		Store:          store,
		SessionIDBytes: 16,
	})

	customID, err := customMgr.generateSessionID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	decodedCustom, err := base64.RawURLEncoding.DecodeString(customID)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if len(decodedCustom) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(decodedCustom))
	}
}

func TestNullSessionLocation(t *testing.T) {
	loc := &NullSessionLocation{}

	// Test GetSessionID
	_, err := loc.GetSessionID()
	if !errors.Is(err, ErrSessionNotFound) {
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
	mgr := newTestManager(t, Config{
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
	mgr := newTestManager(t, Config{
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

// stubSessionStore is a SessionStore whose failures can be aimed at a specific
// session ID. The in-memory store never fails a delete, so it cannot exercise
// the ordering guarantees Rotate makes when one does.
type stubSessionStore struct {
	mu         sync.Mutex
	sessions   map[string]*storage.SessionData
	createErr  error
	deleteErrs map[string]error
	deleteAll  error
}

func newStubSessionStore() *stubSessionStore {
	return &stubSessionStore{
		sessions:   make(map[string]*storage.SessionData),
		deleteErrs: make(map[string]error),
	}
}

func (s *stubSessionStore) CreateSession(ctx context.Context, sessionID string, data *storage.SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.createErr != nil {
		return s.createErr
	}

	now := time.Now()
	stored := *data
	stored.CreatedAt = now
	stored.ExpiresAt = now.Add(ttl)
	data.CreatedAt = stored.CreatedAt
	data.ExpiresAt = stored.ExpiresAt
	s.sessions[sessionID] = &stored

	return nil
}

func (s *stubSessionStore) GetSession(ctx context.Context, sessionID string) (*storage.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, storage.ErrNotFound
	}

	copied := *data

	return &copied, nil
}

func (s *stubSessionStore) UpdateSession(ctx context.Context, sessionID string, data *storage.SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[sessionID]; !ok {
		return storage.ErrNotFound
	}

	stored := *data
	stored.ExpiresAt = time.Now().Add(ttl)
	s.sessions[sessionID] = &stored

	return nil
}

func (s *stubSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.deleteAll != nil {
		return s.deleteAll
	}
	if err, ok := s.deleteErrs[sessionID]; ok {
		return err
	}

	delete(s.sessions, sessionID)

	return nil
}

func (s *stubSessionStore) RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.sessions[sessionID]
	if !ok {
		return storage.ErrNotFound
	}

	data.ExpiresAt = time.Now().Add(ttl)

	return nil
}

func (s *stubSessionStore) live() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}

	return ids
}

// TestManager_RotateDefeatsFixation is the F-14 regression test (CWE-384): an
// attacker plants an identifier in the victim's browser before sign-in, the
// application rotates at sign-in, and the planted identifier must stop
// authenticating. Delete Rotate's swap and this test fails.
func TestManager_RotateDefeatsFixation(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	preAuth, err := mgr.Create(ctx, CreateSessionRequest{UserID: "anonymous"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fixated := preAuth.ID

	rotated, err := mgr.Rotate(ctx, fixated)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if rotated.ID == fixated {
		t.Fatal("Rotate returned the same session ID; the fixated ID still authenticates")
	}

	if _, err := mgr.Get(ctx, fixated); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Expected the pre-rotation ID to be gone, got %v", err)
	}

	if _, err := mgr.Get(ctx, rotated.ID); err != nil {
		t.Fatalf("Expected the rotated ID to be live, got %v", err)
	}
}

func TestManager_RotatePreservesData(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{
		UserID:   "user1",
		Email:    "test@example.com",
		Provider: "local",
		Metadata: map[string]interface{}{"role": "admin"},
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rotated, err := mgr.Rotate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if rotated.Data.UserID != "user1" || rotated.Data.Email != "test@example.com" || rotated.Data.Provider != "local" {
		t.Fatalf("Rotated session lost its data: %+v", rotated.Data)
	}
	if rotated.Data.Metadata["role"] != "admin" {
		t.Fatalf("Rotated session lost its metadata: %+v", rotated.Data.Metadata)
	}

	// The new ID must carry the same entropy as a freshly minted one.
	raw, err := base64.RawURLEncoding.DecodeString(rotated.ID)
	if err != nil {
		t.Fatalf("Rotated ID is not valid base64: %v", err)
	}
	if len(raw) != DefaultSessionIDLength {
		t.Fatalf("Expected %d bytes of entropy, got %d", DefaultSessionIDLength, len(raw))
	}

	// Rotation moves a session, it does not extend one: an attacker who can
	// trigger rotation must not be able to keep a session alive forever.
	drift := rotated.Data.ExpiresAt.Sub(created.Data.ExpiresAt).Abs()
	if drift > time.Second {
		t.Fatalf("Rotation shifted expiry by %v; it should inherit the remaining lifetime", drift)
	}
}

// TestManager_RotateIsolatesMetadata guards the clone: the rotated session must
// not share a metadata map with whatever the store still holds.
func TestManager_RotateIsolatesMetadata(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{
		UserID:   "user1",
		Metadata: map[string]interface{}{"role": "user"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rotated, err := mgr.Rotate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	rotated.Data.Metadata["role"] = "admin"

	stored, err := mgr.Get(ctx, rotated.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Data.Metadata["role"] != "user" {
		t.Fatal("Mutating the returned session changed the stored session")
	}
}

// TestManager_RotateRollsBack proves the ordering guarantee: when the old entry
// cannot be deleted, the replacement is withdrawn so exactly the old session is
// live -- never both.
func TestManager_RotateRollsBack(t *testing.T) {
	store := newStubSessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "user1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	store.mu.Lock()
	store.deleteErrs[created.ID] = errors.New("backend down")
	store.mu.Unlock()

	rotated, err := mgr.Rotate(ctx, created.ID)
	if err == nil {
		t.Fatal("Expected an error when the previous session could not be deleted")
	}
	if rotated != nil {
		t.Fatal("Expected no session on a failed rotation")
	}
	if !errors.Is(err, ErrRotationRolledBack) {
		t.Fatalf("Expected ErrRotationRolledBack, got %v", err)
	}

	live := store.live()
	if len(live) != 1 || live[0] != created.ID {
		t.Fatalf("Expected only the original session to be live, got %v", live)
	}
}

// TestManager_RotateReportsOrphan covers the one case that can leave two live
// identifiers: the compensating delete failed too. It must be reported
// distinctly, because the caller has to force a logout rather than retry.
func TestManager_RotateReportsOrphan(t *testing.T) {
	store := newStubSessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "user1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	store.mu.Lock()
	store.deleteAll = errors.New("backend down")
	store.mu.Unlock()

	if _, err := mgr.Rotate(ctx, created.ID); !errors.Is(err, ErrOrphanedSession) {
		t.Fatalf("Expected ErrOrphanedSession, got %v", err)
	}
}

func TestManager_RotateRejectsUnknownAndExpired(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	if _, err := mgr.Rotate(ctx, "nonexistent"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Expected ErrSessionNotFound, got %v", err)
	}

	expired, err := mgr.Create(ctx, CreateSessionRequest{UserID: "user1", TTL: -time.Hour})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := mgr.Rotate(ctx, expired.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
}

// TestManager_RotateDoesNotCreateWhenSourceIsGone proves rotation cannot mint a
// session out of nothing: no entry may appear for an unknown source ID.
func TestManager_RotateDoesNotCreateWhenSourceIsGone(t *testing.T) {
	store := newStubSessionStore()
	mgr := newTestManager(t, Config{Store: store})

	if _, err := mgr.Rotate(context.Background(), "nonexistent"); err == nil {
		t.Fatal("Expected an error rotating an unknown session")
	}

	if live := store.live(); len(live) != 0 {
		t.Fatalf("Expected no sessions to exist, got %v", live)
	}
}

// TestManager_GetSurfacesSweepFailure covers the discarded error on Get's expiry
// path: the expiry verdict must still reach the caller, and the failed delete
// must no longer vanish. A store that cannot delete cannot revoke.
func TestManager_GetSurfacesSweepFailure(t *testing.T) {
	store := newStubSessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	const sessionID = "stale"
	store.mu.Lock()
	store.sessions[sessionID] = &storage.SessionData{
		UserID:    "user1",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	store.deleteErrs[sessionID] = errors.New("backend down")
	store.mu.Unlock()

	_, err := mgr.Get(ctx, sessionID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected the expiry verdict to survive, got %v", err)
	}
	if !errors.Is(err, ErrSessionSweepFailed) {
		t.Fatalf("Expected the delete failure to be reported, got %v", err)
	}
}

// TestManager_GetSweepsExpired is the other half: when the delete succeeds the
// caller gets a clean ErrSessionExpired and the entry is gone.
func TestManager_GetSweepsExpired(t *testing.T) {
	store := newStubSessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	const sessionID = "stale"
	store.mu.Lock()
	store.sessions[sessionID] = &storage.SessionData{
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	store.mu.Unlock()

	_, err := mgr.Get(ctx, sessionID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Expected ErrSessionExpired, got %v", err)
	}
	if errors.Is(err, ErrSessionSweepFailed) {
		t.Fatalf("Sweep succeeded but was reported as failed: %v", err)
	}
	if live := store.live(); len(live) != 0 {
		t.Fatalf("Expected the expired session to be swept, got %v", live)
	}
}

// TestManager_RotateConcurrent pins the documented concurrency behavior: v1
// has no compare-and-swap, so more than one racing caller may succeed, but no
// caller may ever receive the original identifier or an identifier another
// caller already received.
func TestManager_RotateConcurrent(t *testing.T) {
	store := storage.NewInMemorySessionStore()
	mgr := newTestManager(t, Config{Store: store})
	ctx := context.Background()

	created, err := mgr.Create(ctx, CreateSessionRequest{UserID: "user1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const goroutines = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := make(map[string]bool)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			rotated, err := mgr.Rotate(ctx, created.ID)
			if err != nil {
				return // Losing the race is a legitimate outcome.
			}
			mu.Lock()
			defer mu.Unlock()
			if ids[rotated.ID] {
				t.Errorf("Rotate handed out a duplicate session ID")
			}
			ids[rotated.ID] = true
		}()
	}
	wg.Wait()

	if len(ids) == 0 {
		t.Fatal("Expected at least one rotation to succeed")
	}
	for id := range ids {
		if id == created.ID {
			t.Fatal("A rotation returned the original identifier")
		}
	}
}
