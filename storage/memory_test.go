package storage

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mustNoErr fails the test when a store call that must succeed did not.
// Discarding the error instead is how a test ends up asserting against a store
// that never received the write.
func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestInMemoryUserStore tests all UserStore operations
func TestInMemoryUserStore_CreateUser(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{
		ID:       "user1",
		Email:    "test@example.com",
		Username: "testuser",
		Name:     "Test User",
		Provider: "local",
	}

	// Test successful user creation
	err := store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify timestamps were set
	if user.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if user.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}

	// Test duplicate ID
	duplicate := &User{
		ID:    "user1",
		Email: "different@example.com",
	}
	err = store.CreateUser(ctx, duplicate)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists, got %v", err)
	}

	// Test duplicate email
	duplicateEmail := &User{
		ID:    "user2",
		Email: "test@example.com",
	}
	err = store.CreateUser(ctx, duplicateEmail)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists for duplicate email, got %v", err)
	}

	// Test duplicate username
	duplicateUsername := &User{
		ID:       "user3",
		Email:    "another@example.com",
		Username: "testuser",
	}
	err = store.CreateUser(ctx, duplicateUsername)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists for duplicate username, got %v", err)
	}

	// Test user without email or username (should succeed)
	userNoEmail := &User{
		ID:   "user4",
		Name: "No Email User",
	}
	err = store.CreateUser(ctx, userNoEmail)
	if err != nil {
		t.Fatalf("Expected no error for user without email/username, got %v", err)
	}
}

func TestInMemoryUserStore_GetUserByID(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{
		ID:    "user1",
		Email: "test@example.com",
		Name:  "Test User",
	}
	mustNoErr(t, store.CreateUser(ctx, user))

	// Test successful retrieval
	retrieved, err := store.GetUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrieved.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, retrieved.ID)
	}
	if retrieved.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, retrieved.Email)
	}

	// Test non-existent user
	_, err = store.GetUserByID(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

func TestInMemoryUserStore_GetUserByEmail(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{
		ID:    "user1",
		Email: "test@example.com",
		Name:  "Test User",
	}
	mustNoErr(t, store.CreateUser(ctx, user))

	// Test successful retrieval
	retrieved, err := store.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrieved.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, retrieved.ID)
	}

	// Test non-existent email
	_, err = store.GetUserByEmail(ctx, "nonexistent@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

func TestInMemoryUserStore_GetUserByUsername(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{
		ID:       "user1",
		Email:    "test@example.com",
		Username: "testuser",
	}
	mustNoErr(t, store.CreateUser(ctx, user))

	// Test successful retrieval
	retrieved, err := store.GetUserByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrieved.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, retrieved.ID)
	}

	// Test non-existent username
	_, err = store.GetUserByUsername(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

func TestInMemoryUserStore_UpdateUser(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{
		ID:       "user1",
		Email:    "test@example.com",
		Username: "testuser",
		Name:     "Test User",
	}
	mustNoErr(t, store.CreateUser(ctx, user))

	// Test successful update
	updatedUser := &User{
		ID:       "user1",
		Email:    "updated@example.com",
		Username: "updateduser",
		Name:     "Updated Name",
	}
	err := store.UpdateUser(ctx, updatedUser)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify updates
	retrieved, err := store.GetUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if retrieved.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got %s", retrieved.Name)
	}
	if retrieved.Email != "updated@example.com" {
		t.Errorf("Expected email 'updated@example.com', got %s", retrieved.Email)
	}
	if retrieved.Username != "updateduser" {
		t.Errorf("Expected username 'updateduser', got %s", retrieved.Username)
	}

	// Verify UpdatedAt was changed
	if retrieved.UpdatedAt.IsZero() || retrieved.UpdatedAt.Before(retrieved.CreatedAt) {
		t.Error("UpdatedAt should be set and after CreatedAt")
	}

	// Create another user
	user2 := &User{
		ID:       "user2",
		Email:    "user2@example.com",
		Username: "user2name",
	}
	mustNoErr(t, store.CreateUser(ctx, user2))

	// Test update with email conflict
	user2EmailConflict := &User{
		ID:       "user2",
		Email:    "updated@example.com", // Already used by user1
		Username: "user2name",
	}
	err = store.UpdateUser(ctx, user2EmailConflict)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists for email conflict, got %v", err)
	}

	// Test update with username conflict
	user2UsernameConflict := &User{
		ID:       "user2",
		Email:    "user2@example.com",
		Username: "updateduser", // Already used by user1
	}
	err = store.UpdateUser(ctx, user2UsernameConflict)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists for username conflict, got %v", err)
	}

	// Test update non-existent user
	nonExistent := &User{
		ID:    "nonexistent",
		Email: "new@example.com",
	}
	err = store.UpdateUser(ctx, nonExistent)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test clearing email and username
	user1Cleared := &User{
		ID:       "user1",
		Email:    "",
		Username: "",
		Name:     "User 1",
	}
	err = store.UpdateUser(ctx, user1Cleared)
	if err != nil {
		t.Fatalf("Expected no error when clearing email/username, got %v", err)
	}

	// Verify they were cleared from indexes
	_, err = store.GetUserByEmail(ctx, "updated@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Error("Email should be removed from index")
	}
	_, err = store.GetUserByUsername(ctx, "updateduser")
	if !errors.Is(err, ErrNotFound) {
		t.Error("Username should be removed from index")
	}
}

func TestInMemoryUserStore_DeleteUser(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{
		ID:       "user1",
		Email:    "test@example.com",
		Username: "testuser",
	}
	mustNoErr(t, store.CreateUser(ctx, user))

	// Test successful deletion
	err := store.DeleteUser(ctx, "user1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify user is deleted
	_, err = store.GetUserByID(ctx, "user1")
	if !errors.Is(err, ErrNotFound) {
		t.Error("User should be deleted")
	}

	// Verify indexes are cleaned up
	_, err = store.GetUserByEmail(ctx, "test@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Error("Email index should be cleaned up")
	}
	_, err = store.GetUserByUsername(ctx, "testuser")
	if !errors.Is(err, ErrNotFound) {
		t.Error("Username index should be cleaned up")
	}

	// Test delete non-existent user
	err = store.DeleteUser(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

// TestInMemoryCredentialStore tests all CredentialStore operations
func TestInMemoryCredentialStore_PasswordHash(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	userID := "user1"
	hash := []byte("hashed_password")

	// Test storing password hash
	err := store.StorePasswordHash(ctx, userID, hash)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test retrieving password hash
	retrieved, err := store.GetPasswordHash(ctx, userID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !bytes.Equal(retrieved, hash) {
		t.Errorf("Expected hash %s, got %s", hash, retrieved)
	}

	// Test retrieving non-existent hash
	_, err = store.GetPasswordHash(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test overwriting hash
	newHash := []byte("new_hashed_password")
	err = store.StorePasswordHash(ctx, userID, newHash)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	retrieved, err = store.GetPasswordHash(ctx, userID)
	if err != nil {
		t.Fatalf("GetPasswordHash: %v", err)
	}
	if !bytes.Equal(retrieved, newHash) {
		t.Errorf("Expected hash %s, got %s", newHash, retrieved)
	}
}

func TestInMemoryCredentialStore_WebAuthnCredential(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	userID := "user1"
	cred1 := &WebAuthnCredential{
		ID:              []byte("cred1"),
		PublicKey:       []byte("publickey1"),
		AttestationType: "none",
		AAGUID:          []byte("aaguid1"),
		SignCount:       0,
	}

	// Test storing credential
	err := store.StoreWebAuthnCredential(ctx, userID, cred1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify timestamps and UserID are set
	if cred1.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if cred1.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
	if cred1.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, cred1.UserID)
	}

	// Test retrieving credentials
	creds, err := store.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("Expected 1 credential, got %d", len(creds))
	}
	if !bytes.Equal(creds[0].ID, cred1.ID) {
		t.Errorf("Expected credential ID %s, got %s", cred1.ID, creds[0].ID)
	}

	// Test storing multiple credentials for same user
	cred2 := &WebAuthnCredential{
		ID:        []byte("cred2"),
		PublicKey: []byte("publickey2"),
		SignCount: 0,
	}
	err = store.StoreWebAuthnCredential(ctx, userID, cred2)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	creds, err = store.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("Expected 2 credentials, got %d", len(creds))
	}

	// Test retrieving credentials for user with no credentials
	emptyCreds, err := store.GetWebAuthnCredentials(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(emptyCreds) != 0 {
		t.Errorf("Expected 0 credentials, got %d", len(emptyCreds))
	}

	// Test updating credential
	cred1.SignCount = 42
	err = store.UpdateWebAuthnCredential(ctx, cred1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	creds, err = store.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	found := false
	for _, c := range creds {
		if bytes.Equal(c.ID, cred1.ID) {
			if c.SignCount != 42 {
				t.Errorf("Expected SignCount 42, got %d", c.SignCount)
			}
			if c.UpdatedAt.Before(c.CreatedAt) {
				t.Error("UpdatedAt should be after CreatedAt")
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("Updated credential not found")
	}

	// Test updating non-existent credential
	nonExistent := &WebAuthnCredential{
		ID: []byte("nonexistent"),
	}
	err = store.UpdateWebAuthnCredential(ctx, nonExistent)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test deleting credential
	err = store.DeleteWebAuthnCredential(ctx, cred1.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	creds, err = store.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("Expected 1 credential after deletion, got %d", len(creds))
	}
	if bytes.Equal(creds[0].ID, cred1.ID) {
		t.Error("Deleted credential still exists")
	}

	// Test deleting non-existent credential
	err = store.DeleteWebAuthnCredential(ctx, []byte("nonexistent"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

// TestInMemorySessionStore tests all SessionStore operations
func TestInMemorySessionStore_CreateSession(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	sessionID := "session1"
	data := &SessionData{
		UserID:   "user1",
		Email:    "test@example.com",
		Provider: "local",
		Metadata: map[string]interface{}{"role": "admin"},
	}
	ttl := 1 * time.Hour

	// Test creating session
	err := store.CreateSession(ctx, sessionID, data, ttl)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify timestamps are set
	if data.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if data.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}

	// Verify TTL is correct
	expectedExpiry := data.CreatedAt.Add(ttl)
	if !data.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("Expected expiry %v, got %v", expectedExpiry, data.ExpiresAt)
	}
}

func TestInMemorySessionStore_GetSession(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	sessionID := "session1"
	data := &SessionData{
		UserID: "user1",
		Email:  "test@example.com",
	}
	ttl := 1 * time.Hour

	mustNoErr(t, store.CreateSession(ctx, sessionID, data, ttl))

	// Test getting valid session
	retrieved, err := store.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrieved.UserID != data.UserID {
		t.Errorf("Expected UserID %s, got %s", data.UserID, retrieved.UserID)
	}

	// Test getting non-existent session
	_, err = store.GetSession(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test getting expired session
	expiredSessionID := "expired"
	expiredData := &SessionData{UserID: "user2"}
	mustNoErr(t, store.CreateSession(ctx, expiredSessionID, expiredData, -1*time.Hour)) // Expired
	_, err = store.GetSession(ctx, expiredSessionID)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
}

func TestInMemorySessionStore_UpdateSession(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	sessionID := "session1"
	data := &SessionData{
		UserID: "user1",
		Email:  "test@example.com",
	}
	mustNoErr(t, store.CreateSession(ctx, sessionID, data, 1*time.Hour))

	// Test updating session
	newData := &SessionData{
		UserID: "user1",
		Email:  "updated@example.com",
	}
	err := store.UpdateSession(ctx, sessionID, newData, 2*time.Hour)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	retrieved, err := store.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if retrieved.Email != "updated@example.com" {
		t.Errorf("Expected email 'updated@example.com', got %s", retrieved.Email)
	}

	// Test updating non-existent session
	err = store.UpdateSession(ctx, "nonexistent", newData, 1*time.Hour)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test updating expired session
	expiredSessionID := "expired"
	expiredData := &SessionData{UserID: "user2"}
	mustNoErr(t, store.CreateSession(ctx, expiredSessionID, expiredData, -1*time.Hour))
	err = store.UpdateSession(ctx, expiredSessionID, newData, 1*time.Hour)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
}

func TestInMemorySessionStore_RefreshSession(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	sessionID := "session1"
	data := &SessionData{
		UserID: "user1",
		Email:  "test@example.com",
	}
	mustNoErr(t, store.CreateSession(ctx, sessionID, data, 1*time.Hour))

	// Wait a bit to ensure we can see the expiry change
	time.Sleep(10 * time.Millisecond)

	// Test refreshing session
	err := store.RefreshSession(ctx, sessionID, 3*time.Hour)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	retrieved, err := store.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	// The new expiry should be ~3 hours from now
	expectedExpiry := time.Now().Add(3 * time.Hour)
	timeDiff := retrieved.ExpiresAt.Sub(expectedExpiry).Abs()
	if timeDiff > 1*time.Second {
		t.Errorf("Expected expiry around %v, got %v", expectedExpiry, retrieved.ExpiresAt)
	}

	// Test refreshing non-existent session
	err = store.RefreshSession(ctx, "nonexistent", 1*time.Hour)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test refreshing expired session
	expiredSessionID := "expired"
	expiredData := &SessionData{UserID: "user2"}
	mustNoErr(t, store.CreateSession(ctx, expiredSessionID, expiredData, -1*time.Hour))
	err = store.RefreshSession(ctx, expiredSessionID, 1*time.Hour)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
}

func TestInMemorySessionStore_DeleteSession(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	sessionID := "session1"
	data := &SessionData{UserID: "user1"}
	mustNoErr(t, store.CreateSession(ctx, sessionID, data, 1*time.Hour))

	// Test deleting session
	err := store.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify session is deleted
	_, err = store.GetSession(ctx, sessionID)
	if !errors.Is(err, ErrNotFound) {
		t.Error("Session should be deleted")
	}

	// Test deleting non-existent session (should not error)
	err = store.DeleteSession(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Expected no error for non-existent session, got %v", err)
	}
}

// TestInMemoryTokenStore tests all TokenStore operations
func TestInMemoryTokenStore_StoreRefreshToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	userID := "user1"
	tokenID := "token1"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Test storing token
	err := store.StoreRefreshToken(ctx, userID, tokenID, expiresAt)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestInMemoryTokenStore_ValidateRefreshToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	userID := "user1"
	tokenID := "token1"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	mustNoErr(t, store.StoreRefreshToken(ctx, userID, tokenID, expiresAt))

	// Test validating valid token
	retrievedUserID, err := store.ValidateRefreshToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrievedUserID != userID {
		t.Errorf("Expected userID %s, got %s", userID, retrievedUserID)
	}

	// Test validating non-existent token
	_, err = store.ValidateRefreshToken(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test validating expired token
	expiredTokenID := "expired"
	expiredExpiresAt := time.Now().Add(-1 * time.Hour)
	mustNoErr(t, store.StoreRefreshToken(ctx, userID, expiredTokenID, expiredExpiresAt))
	_, err = store.ValidateRefreshToken(ctx, expiredTokenID)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}

	// Test validating revoked token
	revokedTokenID := "revoked"
	mustNoErr(t, store.StoreRefreshToken(ctx, userID, revokedTokenID, expiresAt))
	mustNoErr(t, store.RevokeRefreshToken(ctx, revokedTokenID))
	_, err = store.ValidateRefreshToken(ctx, revokedTokenID)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}
}

func TestInMemoryTokenStore_RevokeRefreshToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	userID := "user1"
	tokenID := "token1"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	mustNoErr(t, store.StoreRefreshToken(ctx, userID, tokenID, expiresAt))

	// Test revoking token
	err := store.RevokeRefreshToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify token is revoked
	_, err = store.ValidateRefreshToken(ctx, tokenID)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Expected ErrTokenRevoked, got %v", err)
	}

	// Test revoking non-existent token
	err = store.RevokeRefreshToken(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

func TestInMemoryTokenStore_RevokeAllUserTokens(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	userID := "user1"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Store multiple tokens for the user
	mustNoErr(t, store.StoreRefreshToken(ctx, userID, "token1", expiresAt))
	mustNoErr(t, store.StoreRefreshToken(ctx, userID, "token2", expiresAt))
	mustNoErr(t, store.StoreRefreshToken(ctx, userID, "token3", expiresAt))

	// Store token for different user
	mustNoErr(t, store.StoreRefreshToken(ctx, "user2", "token4", expiresAt))

	// Test revoking all user tokens
	err := store.RevokeAllUserTokens(ctx, userID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify all user1 tokens are revoked
	_, err = store.ValidateRefreshToken(ctx, "token1")
	if !errors.Is(err, ErrTokenRevoked) {
		t.Error("token1 should be revoked")
	}
	_, err = store.ValidateRefreshToken(ctx, "token2")
	if !errors.Is(err, ErrTokenRevoked) {
		t.Error("token2 should be revoked")
	}
	_, err = store.ValidateRefreshToken(ctx, "token3")
	if !errors.Is(err, ErrTokenRevoked) {
		t.Error("token3 should be revoked")
	}

	// Verify user2 token is still valid
	_, err = store.ValidateRefreshToken(ctx, "token4")
	if err != nil {
		t.Errorf("token4 should still be valid, got %v", err)
	}

	// Test revoking tokens for user with no tokens (should not error)
	err = store.RevokeAllUserTokens(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestInMemoryOIDCStateStore tests all OIDCStateStore operations
func TestInMemoryOIDCStateStore_StoreState(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	state := "state123"
	data := &OIDCState{
		RedirectURL: "https://example.com/callback",
		Nonce:       "nonce123",
		Provider:    "google",
		Metadata:    map[string]interface{}{"custom": "data"},
	}
	ttl := 10 * time.Minute

	// Test storing state
	err := store.StoreState(ctx, state, data, ttl)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify CreatedAt is set
	if data.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestInMemoryOIDCStateStore_GetState(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	state := "state123"
	data := &OIDCState{
		RedirectURL: "https://example.com/callback",
		Provider:    "google",
	}
	ttl := 10 * time.Minute

	mustNoErr(t, store.StoreState(ctx, state, data, ttl))

	// Test getting valid state
	retrieved, err := store.GetState(ctx, state)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrieved.RedirectURL != data.RedirectURL {
		t.Errorf("Expected RedirectURL %s, got %s", data.RedirectURL, retrieved.RedirectURL)
	}
	if retrieved.Provider != data.Provider {
		t.Errorf("Expected Provider %s, got %s", data.Provider, retrieved.Provider)
	}

	// Test one-time use - should be deleted after first retrieval
	_, err = store.GetState(ctx, state)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound (one-time use), got %v", err)
	}

	// Test getting non-existent state
	_, err = store.GetState(ctx, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test getting expired state
	expiredState := "expired"
	expiredData := &OIDCState{Provider: "github"}
	mustNoErr(t, store.StoreState(ctx, expiredState, expiredData, -1*time.Hour))
	_, err = store.GetState(ctx, expiredState)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}

	// Verify expired state is deleted
	_, err = store.GetState(ctx, expiredState)
	if !errors.Is(err, ErrNotFound) {
		t.Error("Expired state should be deleted")
	}
}

func TestInMemoryOIDCStateStore_DeleteState(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	state := "state123"
	data := &OIDCState{Provider: "google"}
	mustNoErr(t, store.StoreState(ctx, state, data, 10*time.Minute))

	// Test deleting state
	err := store.DeleteState(ctx, state)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify state is deleted
	_, err = store.GetState(ctx, state)
	if !errors.Is(err, ErrNotFound) {
		t.Error("State should be deleted")
	}

	// Test deleting non-existent state (should not error)
	err = store.DeleteState(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Expected no error for non-existent state, got %v", err)
	}
}

// TestConcurrency tests concurrent access to stores
func TestInMemoryUserStore_Concurrency(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	// Create users concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			user := &User{
				ID:    string(rune(id)),
				Email: string(rune(id)) + "@example.com",
			}
			if err := store.CreateUser(ctx, user); err != nil {
				t.Errorf("CreateUser: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no data corruption
	if len(store.users) > 10 {
		t.Errorf("Expected at most 10 users, got %d", len(store.users))
	}
}

func TestInMemorySessionStore_Concurrency(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	// Create sessions concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			sessionID := string(rune(id))
			data := &SessionData{UserID: string(rune(id))}
			if err := store.CreateSession(ctx, sessionID, data, 1*time.Hour); err != nil {
				t.Errorf("CreateSession: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no data corruption
	if len(store.sessions) > 10 {
		t.Errorf("Expected at most 10 sessions, got %d", len(store.sessions))
	}
}

// TestInMemoryUserStore_ReadsAreCopies guards the boundary: a caller must not be
// able to edit the store by holding on to what a read handed back. The stored
// pointer escaping the lock is both a data race and an unwritten write.
func TestInMemoryUserStore_ReadsAreCopies(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	mustNoErr(t, store.CreateUser(ctx, &User{
		ID:       "user1",
		Email:    "test@example.com",
		Metadata: map[string]interface{}{"role": "user"},
	}))

	first, err := store.GetUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	first.Email = "attacker@example.com"
	first.Metadata["role"] = "admin"

	second, err := store.GetUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if second.Email != "test@example.com" {
		t.Errorf("Stored email was mutated through a returned pointer: %s", second.Email)
	}
	if second.Metadata["role"] != "user" {
		t.Errorf("Stored metadata was mutated through a returned map: %v", second.Metadata)
	}

	// The struct handed to CreateUser must not stay wired to the store either.
	byEmail, err := store.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if byEmail.ID != "user1" {
		t.Errorf("Expected user1, got %s", byEmail.ID)
	}
}

// TestInMemoryUserStore_UpdateKeepsCreatedAt covers an update built from a
// partially populated struct, which used to silently zero the creation time.
func TestInMemoryUserStore_UpdateKeepsCreatedAt(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	user := &User{ID: "user1", Email: "test@example.com"}
	mustNoErr(t, store.CreateUser(ctx, user))
	created := user.CreatedAt

	mustNoErr(t, store.UpdateUser(ctx, &User{ID: "user1", Email: "test@example.com", Name: "Renamed"}))

	retrieved, err := store.GetUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !retrieved.CreatedAt.Equal(created) {
		t.Errorf("Expected CreatedAt %v to survive the update, got %v", created, retrieved.CreatedAt)
	}
}

// TestInMemoryCredentialStore_DuplicateWebAuthnCredentialID mirrors the
// credential-ID collision attack: a second registration claiming an existing
// credential ID must not silently take it over.
func TestInMemoryCredentialStore_DuplicateWebAuthnCredentialID(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	mustNoErr(t, store.StoreWebAuthnCredential(ctx, "victim", &WebAuthnCredential{
		ID:        []byte("cred1"),
		PublicKey: []byte("victim-key"),
	}))

	err := store.StoreWebAuthnCredential(ctx, "attacker", &WebAuthnCredential{
		ID:        []byte("cred1"),
		PublicKey: []byte("attacker-key"),
	})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists for a duplicate credential ID, got %v", err)
	}

	creds, err := store.GetWebAuthnCredentials(ctx, "victim")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 1 || string(creds[0].PublicKey) != "victim-key" {
		t.Fatalf("The victim's credential was replaced: %+v", creds)
	}

	attackerCreds, err := store.GetWebAuthnCredentials(ctx, "attacker")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(attackerCreds) != 0 {
		t.Fatalf("Expected the attacker to hold no credentials, got %d", len(attackerCreds))
	}
}

// TestInMemoryCredentialStore_UpdateWebAuthnCredentialWrongOwner proves an
// update cannot re-own a credential.
func TestInMemoryCredentialStore_UpdateWebAuthnCredentialWrongOwner(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	cred := &WebAuthnCredential{ID: []byte("cred1"), PublicKey: []byte("key")}
	mustNoErr(t, store.StoreWebAuthnCredential(ctx, "victim", cred))

	err := store.UpdateWebAuthnCredential(ctx, &WebAuthnCredential{
		ID:        []byte("cred1"),
		PublicKey: []byte("key"),
		UserID:    "attacker",
		SignCount: 99,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound for a credential owned by somebody else, got %v", err)
	}

	creds, err := store.GetWebAuthnCredentials(ctx, "victim")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(creds) != 1 || creds[0].SignCount != 0 {
		t.Fatalf("The credential was updated by the wrong owner: %+v", creds)
	}
}

// TestInMemoryCredentialStore_WebAuthnReadsAreCopies proves a returned
// credential cannot be used to edit the stored one, in particular its signature
// counter -- the only signal a cloned authenticator produces.
func TestInMemoryCredentialStore_WebAuthnReadsAreCopies(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	mustNoErr(t, store.StoreWebAuthnCredential(ctx, "user1", &WebAuthnCredential{
		ID:        []byte("cred1"),
		PublicKey: []byte("key"),
		SignCount: 10,
	}))

	creds, err := store.GetWebAuthnCredentials(ctx, "user1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	creds[0].SignCount = 0
	creds[0].PublicKey[0] = 'X'

	fresh, err := store.GetWebAuthnCredentials(ctx, "user1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if fresh[0].SignCount != 10 {
		t.Errorf("Sign counter was rolled back through a returned pointer: %d", fresh[0].SignCount)
	}
	if string(fresh[0].PublicKey) != "key" {
		t.Errorf("Public key was mutated through a returned slice: %s", fresh[0].PublicKey)
	}
}

func TestInMemoryCredentialStore_ResetTokenLifecycle(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	// The library hands the store a hash, never the emailed value (F-05).
	const hashed = "sha256-of-the-emailed-token"
	mustNoErr(t, store.StorePasswordResetToken(ctx, "user1", hashed, time.Now().Add(time.Hour)))

	userID, err := store.ValidatePasswordResetToken(ctx, hashed)
	if err != nil {
		t.Fatalf("ValidatePasswordResetToken: %v", err)
	}
	if userID != "user1" {
		t.Errorf("Expected user1, got %s", userID)
	}

	if _, err := store.ValidatePasswordResetToken(ctx, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	mustNoErr(t, store.DeletePasswordResetToken(ctx, hashed))
	if _, err := store.ValidatePasswordResetToken(ctx, hashed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected the consumed token to be gone, got %v", err)
	}

	// Deleting an absent token is not an error: a caller that already consumed it
	// must not be punished for saying so twice.
	mustNoErr(t, store.DeletePasswordResetToken(ctx, hashed))
}

// TestInMemoryCredentialStore_TokensEvictOnExpiry proves an expired token is
// both refused and dropped, so an unauthenticated endpoint cannot grow the map
// without bound.
func TestInMemoryCredentialStore_TokensEvictOnExpiry(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	mustNoErr(t, store.StorePasswordResetToken(ctx, "user1", "stale", time.Now().Add(-time.Hour)))
	if _, err := store.ValidatePasswordResetToken(ctx, "stale"); !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
	if len(store.passwordResetTokens) != 0 {
		t.Errorf("Expected the expired token to be evicted, %d remain", len(store.passwordResetTokens))
	}

	mustNoErr(t, store.StoreEmailVerificationToken(ctx, "user1", "stale", time.Now().Add(-time.Hour)))
	if _, err := store.ValidateEmailVerificationToken(ctx, "stale"); !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}

	// A token nobody ever comes back for is swept by the next write, so an
	// endpoint that mints them without authentication cannot grow the map.
	mustNoErr(t, store.StorePasswordResetToken(ctx, "user2", "abandoned", time.Now().Add(-time.Hour)))
	mustNoErr(t, store.StorePasswordResetToken(ctx, "user3", "fresh", time.Now().Add(time.Hour)))
	if _, exists := store.passwordResetTokens["abandoned"]; exists {
		t.Error("Expected the abandoned token to be swept by a later write")
	}
	if _, err := store.ValidatePasswordResetToken(ctx, "fresh"); err != nil {
		t.Errorf("The sweep removed a live token: %v", err)
	}
}

func TestInMemoryCredentialStore_TOTPSecret(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	// Ciphertext and hashed codes: the store must return them byte-for-byte
	// (F-06), because anything else destroys the ability to decrypt or compare.
	const ciphertext = "\x00\x01ciphertext-not-base32"
	codes := []string{"hash-a", "hash-b", "hash-c"}
	mustNoErr(t, store.StoreTOTPSecret(ctx, "user1", ciphertext, codes))

	secret, unused, err := store.GetTOTPSecret(ctx, "user1")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	if secret != ciphertext {
		t.Errorf("Secret was not returned verbatim: %q", secret)
	}
	if len(unused) != 3 {
		t.Fatalf("Expected 3 unused codes, got %d", len(unused))
	}

	mustNoErr(t, store.UseBackupCode(ctx, "user1", "hash-b"))

	_, unused, err = store.GetTOTPSecret(ctx, "user1")
	if err != nil {
		t.Fatalf("GetTOTPSecret: %v", err)
	}
	if len(unused) != 2 {
		t.Fatalf("Expected 2 unused codes after consuming one, got %d", len(unused))
	}
	for _, code := range unused {
		if code == "hash-b" {
			t.Error("A consumed backup code is still on offer")
		}
	}

	if err := store.UseBackupCode(ctx, "user1", "hash-b"); !errors.Is(err, ErrBackupCodeUsed) {
		t.Fatalf("Expected ErrBackupCodeUsed, got %v", err)
	}
	if err := store.UseBackupCode(ctx, "user1", "nope"); !errors.Is(err, ErrInvalidBackupCode) {
		t.Fatalf("Expected ErrInvalidBackupCode, got %v", err)
	}
	if err := store.UseBackupCode(ctx, "unknown", "hash-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	mustNoErr(t, store.DeleteTOTPSecret(ctx, "user1"))
	if _, _, err := store.GetTOTPSecret(ctx, "user1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound after deletion, got %v", err)
	}
}

// TestInMemoryCredentialStore_BackupCodeSingleUseUnderRace is the one that
// matters: a backup code is written on paper and may be submitted twice at once.
// Exactly one of N concurrent callers may consume it.
func TestInMemoryCredentialStore_BackupCodeSingleUseUnderRace(t *testing.T) {
	store := NewInMemoryCredentialStore()
	ctx := context.Background()

	mustNoErr(t, store.StoreTOTPSecret(ctx, "user1", "secret", []string{"hash-a"}))

	const goroutines = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := store.UseBackupCode(ctx, "user1", "hash-a"); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("Expected exactly one caller to consume the backup code, %d did", accepted)
	}
}

// TestInMemorySessionStore_CreateRejectsExistingID pins the contract Rotate
// depends on: a live session ID is never silently replaced, so a caller-supplied
// identifier cannot displace a session (F-14).
func TestInMemorySessionStore_CreateRejectsExistingID(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	mustNoErr(t, store.CreateSession(ctx, "session1", &SessionData{UserID: "victim"}, time.Hour))

	err := store.CreateSession(ctx, "session1", &SessionData{UserID: "attacker"}, time.Hour)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists, got %v", err)
	}

	data, err := store.GetSession(ctx, "session1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if data.UserID != "victim" {
		t.Fatalf("The live session was displaced: %+v", data)
	}

	// An expired entry is not a live session and may be reused.
	mustNoErr(t, store.CreateSession(ctx, "session2", &SessionData{UserID: "user1"}, -time.Hour))
	if err := store.CreateSession(ctx, "session2", &SessionData{UserID: "user2"}, time.Hour); err != nil {
		t.Fatalf("Expected an expired ID to be reusable, got %v", err)
	}
}

// TestInMemorySessionStore_ReadsAreCopies guards the same boundary as the user
// store: a returned session must not be a handle on the stored one.
func TestInMemorySessionStore_ReadsAreCopies(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	mustNoErr(t, store.CreateSession(ctx, "session1", &SessionData{
		UserID:   "user1",
		Metadata: map[string]interface{}{"role": "user"},
	}, time.Hour))

	first, err := store.GetSession(ctx, "session1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	first.UserID = "attacker"
	first.Metadata["role"] = "admin"
	first.ExpiresAt = time.Now().Add(100 * time.Hour)

	second, err := store.GetSession(ctx, "session1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if second.UserID != "user1" {
		t.Errorf("Stored session was mutated through a returned pointer: %s", second.UserID)
	}
	if second.Metadata["role"] != "user" {
		t.Errorf("Stored metadata was mutated through a returned map: %v", second.Metadata)
	}
	if second.ExpiresAt.After(time.Now().Add(2 * time.Hour)) {
		t.Error("Session lifetime was extended through a returned pointer")
	}
}

// TestInMemorySessionStore_ExpiredEntriesAreEvicted proves an expired session is
// dropped rather than left to accumulate.
func TestInMemorySessionStore_ExpiredEntriesAreEvicted(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	mustNoErr(t, store.CreateSession(ctx, "stale", &SessionData{UserID: "user1"}, -time.Hour))

	if _, err := store.GetSession(ctx, "stale"); !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
	if len(store.sessions) != 0 {
		t.Errorf("Expected the expired session to be evicted, %d remain", len(store.sessions))
	}

	mustNoErr(t, store.CreateSession(ctx, "stale2", &SessionData{UserID: "user1"}, -time.Hour))
	if err := store.RefreshSession(ctx, "stale2", time.Hour); !errors.Is(err, ErrExpired) {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
	if len(store.sessions) != 0 {
		t.Errorf("Refresh should not resurrect an expired session, %d remain", len(store.sessions))
	}
}

// TestInMemorySessionStore_UpdateKeepsCreatedAt proves an update does not erase
// the only evidence of a session's age.
func TestInMemorySessionStore_UpdateKeepsCreatedAt(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	data := &SessionData{UserID: "user1"}
	mustNoErr(t, store.CreateSession(ctx, "session1", data, time.Hour))
	created := data.CreatedAt

	mustNoErr(t, store.UpdateSession(ctx, "session1", &SessionData{UserID: "user1", Email: "new@example.com"}, time.Hour))

	retrieved, err := store.GetSession(ctx, "session1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !retrieved.CreatedAt.Equal(created) {
		t.Errorf("Expected CreatedAt %v to survive the update, got %v", created, retrieved.CreatedAt)
	}
}

// TestInMemoryOIDCStateStore_SingleUseUnderRace proves the state parameter stays
// single-use when two callbacks arrive at once. Two winners means the state
// stopped being an anti-replay control.
func TestInMemoryOIDCStateStore_SingleUseUnderRace(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	mustNoErr(t, store.StoreState(ctx, "state123", &OIDCState{Provider: "google"}, time.Minute))

	const goroutines = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := store.GetState(ctx, "state123"); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("Expected exactly one callback to consume the state, %d did", accepted)
	}
}

// TestInMemoryOIDCStateStore_SweepsAbandonedFlows proves an abandoned flow does
// not leak: starting a flow needs no authentication, so the map must not grow
// for as long as an attacker keeps hitting the authorization endpoint.
func TestInMemoryOIDCStateStore_SweepsAbandonedFlows(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		mustNoErr(t, store.StoreState(ctx, "abandoned"+string(rune('a'+i%26))+string(rune('a'+i/26)), &OIDCState{Provider: "google"}, -time.Second))
	}

	mustNoErr(t, store.StoreState(ctx, "live", &OIDCState{Provider: "google"}, time.Minute))

	if len(store.states) != 1 {
		t.Fatalf("Expected abandoned states to be swept, %d remain", len(store.states))
	}
	if _, err := store.GetState(ctx, "live"); err != nil {
		t.Fatalf("The sweep removed a live state: %v", err)
	}
}

// TestInMemoryOIDCStateStore_ReadsAreCopies guards against a caller editing an
// in-flight state -- the PKCE verifier and the browser binding among them.
func TestInMemoryOIDCStateStore_ReadsAreCopies(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	original := &OIDCState{
		Provider:     "google",
		Nonce:        "nonce123",
		CodeVerifier: "verifier",
		BindingHash:  "binding",
		Metadata:     map[string]interface{}{"tenant": "acme"},
	}
	mustNoErr(t, store.StoreState(ctx, "state123", original, time.Minute))

	original.Nonce = "tampered"
	original.CodeVerifier = "tampered"
	original.Metadata["tenant"] = "evil"

	retrieved, err := store.GetState(ctx, "state123")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if retrieved.Nonce != "nonce123" || retrieved.CodeVerifier != "verifier" || retrieved.BindingHash != "binding" {
		t.Fatalf("Stored state was mutated through the caller's struct: %+v", retrieved)
	}
	if retrieved.Metadata["tenant"] != "acme" {
		t.Errorf("Stored metadata was mutated through the caller's map: %v", retrieved.Metadata)
	}
}
