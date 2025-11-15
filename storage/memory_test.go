package storage

import (
	"context"
	"testing"
	"time"
)

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
	if err != ErrAlreadyExists {
		t.Fatalf("Expected ErrAlreadyExists, got %v", err)
	}

	// Test duplicate email
	duplicateEmail := &User{
		ID:    "user2",
		Email: "test@example.com",
	}
	err = store.CreateUser(ctx, duplicateEmail)
	if err != ErrAlreadyExists {
		t.Fatalf("Expected ErrAlreadyExists for duplicate email, got %v", err)
	}

	// Test duplicate username
	duplicateUsername := &User{
		ID:       "user3",
		Email:    "another@example.com",
		Username: "testuser",
	}
	err = store.CreateUser(ctx, duplicateUsername)
	if err != ErrAlreadyExists {
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
	store.CreateUser(ctx, user)

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
	if err != ErrNotFound {
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
	store.CreateUser(ctx, user)

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
	if err != ErrNotFound {
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
	store.CreateUser(ctx, user)

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
	if err != ErrNotFound {
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
	store.CreateUser(ctx, user)

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
	retrieved, _ := store.GetUserByID(ctx, "user1")
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
	store.CreateUser(ctx, user2)

	// Test update with email conflict
	user2EmailConflict := &User{
		ID:       "user2",
		Email:    "updated@example.com", // Already used by user1
		Username: "user2name",
	}
	err = store.UpdateUser(ctx, user2EmailConflict)
	if err != ErrAlreadyExists {
		t.Fatalf("Expected ErrAlreadyExists for email conflict, got %v", err)
	}

	// Test update with username conflict
	user2UsernameConflict := &User{
		ID:       "user2",
		Email:    "user2@example.com",
		Username: "updateduser", // Already used by user1
	}
	err = store.UpdateUser(ctx, user2UsernameConflict)
	if err != ErrAlreadyExists {
		t.Fatalf("Expected ErrAlreadyExists for username conflict, got %v", err)
	}

	// Test update non-existent user
	nonExistent := &User{
		ID:    "nonexistent",
		Email: "new@example.com",
	}
	err = store.UpdateUser(ctx, nonExistent)
	if err != ErrNotFound {
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
	if err != ErrNotFound {
		t.Error("Email should be removed from index")
	}
	_, err = store.GetUserByUsername(ctx, "updateduser")
	if err != ErrNotFound {
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
	store.CreateUser(ctx, user)

	// Test successful deletion
	err := store.DeleteUser(ctx, "user1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify user is deleted
	_, err = store.GetUserByID(ctx, "user1")
	if err != ErrNotFound {
		t.Error("User should be deleted")
	}

	// Verify indexes are cleaned up
	_, err = store.GetUserByEmail(ctx, "test@example.com")
	if err != ErrNotFound {
		t.Error("Email index should be cleaned up")
	}
	_, err = store.GetUserByUsername(ctx, "testuser")
	if err != ErrNotFound {
		t.Error("Username index should be cleaned up")
	}

	// Test delete non-existent user
	err = store.DeleteUser(ctx, "nonexistent")
	if err != ErrNotFound {
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
	if string(retrieved) != string(hash) {
		t.Errorf("Expected hash %s, got %s", hash, retrieved)
	}

	// Test retrieving non-existent hash
	_, err = store.GetPasswordHash(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test overwriting hash
	newHash := []byte("new_hashed_password")
	err = store.StorePasswordHash(ctx, userID, newHash)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	retrieved, _ = store.GetPasswordHash(ctx, userID)
	if string(retrieved) != string(newHash) {
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
	if string(creds[0].ID) != string(cred1.ID) {
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

	creds, _ = store.GetWebAuthnCredentials(ctx, userID)
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

	creds, _ = store.GetWebAuthnCredentials(ctx, userID)
	found := false
	for _, c := range creds {
		if string(c.ID) == string(cred1.ID) {
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
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test deleting credential
	err = store.DeleteWebAuthnCredential(ctx, cred1.ID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	creds, _ = store.GetWebAuthnCredentials(ctx, userID)
	if len(creds) != 1 {
		t.Fatalf("Expected 1 credential after deletion, got %d", len(creds))
	}
	if string(creds[0].ID) == string(cred1.ID) {
		t.Error("Deleted credential still exists")
	}

	// Test deleting non-existent credential
	err = store.DeleteWebAuthnCredential(ctx, []byte("nonexistent"))
	if err != ErrNotFound {
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

	store.CreateSession(ctx, sessionID, data, ttl)

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
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test getting expired session
	expiredSessionID := "expired"
	expiredData := &SessionData{UserID: "user2"}
	store.CreateSession(ctx, expiredSessionID, expiredData, -1*time.Hour) // Expired
	_, err = store.GetSession(ctx, expiredSessionID)
	if err != ErrExpired {
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
	store.CreateSession(ctx, sessionID, data, 1*time.Hour)

	// Test updating session
	newData := &SessionData{
		UserID: "user1",
		Email:  "updated@example.com",
	}
	err := store.UpdateSession(ctx, sessionID, newData, 2*time.Hour)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	retrieved, _ := store.GetSession(ctx, sessionID)
	if retrieved.Email != "updated@example.com" {
		t.Errorf("Expected email 'updated@example.com', got %s", retrieved.Email)
	}

	// Test updating non-existent session
	err = store.UpdateSession(ctx, "nonexistent", newData, 1*time.Hour)
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test updating expired session
	expiredSessionID := "expired"
	expiredData := &SessionData{UserID: "user2"}
	store.CreateSession(ctx, expiredSessionID, expiredData, -1*time.Hour)
	err = store.UpdateSession(ctx, expiredSessionID, newData, 1*time.Hour)
	if err != ErrExpired {
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
	store.CreateSession(ctx, sessionID, data, 1*time.Hour)

	// Wait a bit to ensure we can see the expiry change
	time.Sleep(10 * time.Millisecond)

	// Test refreshing session
	err := store.RefreshSession(ctx, sessionID, 3*time.Hour)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	retrieved, _ := store.GetSession(ctx, sessionID)
	// The new expiry should be ~3 hours from now
	expectedExpiry := time.Now().Add(3 * time.Hour)
	timeDiff := retrieved.ExpiresAt.Sub(expectedExpiry).Abs()
	if timeDiff > 1*time.Second {
		t.Errorf("Expected expiry around %v, got %v", expectedExpiry, retrieved.ExpiresAt)
	}

	// Test refreshing non-existent session
	err = store.RefreshSession(ctx, "nonexistent", 1*time.Hour)
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test refreshing expired session
	expiredSessionID := "expired"
	expiredData := &SessionData{UserID: "user2"}
	store.CreateSession(ctx, expiredSessionID, expiredData, -1*time.Hour)
	err = store.RefreshSession(ctx, expiredSessionID, 1*time.Hour)
	if err != ErrExpired {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}
}

func TestInMemorySessionStore_DeleteSession(t *testing.T) {
	store := NewInMemorySessionStore()
	ctx := context.Background()

	sessionID := "session1"
	data := &SessionData{UserID: "user1"}
	store.CreateSession(ctx, sessionID, data, 1*time.Hour)

	// Test deleting session
	err := store.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify session is deleted
	_, err = store.GetSession(ctx, sessionID)
	if err != ErrNotFound {
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

	store.StoreRefreshToken(ctx, userID, tokenID, expiresAt)

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
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test validating expired token
	expiredTokenID := "expired"
	expiredExpiresAt := time.Now().Add(-1 * time.Hour)
	store.StoreRefreshToken(ctx, userID, expiredTokenID, expiredExpiresAt)
	_, err = store.ValidateRefreshToken(ctx, expiredTokenID)
	if err != ErrExpired {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}

	// Test validating revoked token
	revokedTokenID := "revoked"
	store.StoreRefreshToken(ctx, userID, revokedTokenID, expiresAt)
	store.RevokeRefreshToken(ctx, revokedTokenID)
	_, err = store.ValidateRefreshToken(ctx, revokedTokenID)
	if err == nil || err.Error() != "token revoked" {
		t.Fatalf("Expected 'token revoked' error, got %v", err)
	}
}

func TestInMemoryTokenStore_RevokeRefreshToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	userID := "user1"
	tokenID := "token1"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	store.StoreRefreshToken(ctx, userID, tokenID, expiresAt)

	// Test revoking token
	err := store.RevokeRefreshToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify token is revoked
	_, err = store.ValidateRefreshToken(ctx, tokenID)
	if err == nil || err.Error() != "token revoked" {
		t.Fatalf("Expected 'token revoked' error, got %v", err)
	}

	// Test revoking non-existent token
	err = store.RevokeRefreshToken(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

func TestInMemoryTokenStore_RevokeAllUserTokens(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	userID := "user1"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Store multiple tokens for the user
	store.StoreRefreshToken(ctx, userID, "token1", expiresAt)
	store.StoreRefreshToken(ctx, userID, "token2", expiresAt)
	store.StoreRefreshToken(ctx, userID, "token3", expiresAt)

	// Store token for different user
	store.StoreRefreshToken(ctx, "user2", "token4", expiresAt)

	// Test revoking all user tokens
	err := store.RevokeAllUserTokens(ctx, userID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify all user1 tokens are revoked
	_, err = store.ValidateRefreshToken(ctx, "token1")
	if err == nil || err.Error() != "token revoked" {
		t.Error("token1 should be revoked")
	}
	_, err = store.ValidateRefreshToken(ctx, "token2")
	if err == nil || err.Error() != "token revoked" {
		t.Error("token2 should be revoked")
	}
	_, err = store.ValidateRefreshToken(ctx, "token3")
	if err == nil || err.Error() != "token revoked" {
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

	store.StoreState(ctx, state, data, ttl)

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
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound (one-time use), got %v", err)
	}

	// Test getting non-existent state
	_, err = store.GetState(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test getting expired state
	expiredState := "expired"
	expiredData := &OIDCState{Provider: "github"}
	store.StoreState(ctx, expiredState, expiredData, -1*time.Hour)
	_, err = store.GetState(ctx, expiredState)
	if err != ErrExpired {
		t.Fatalf("Expected ErrExpired, got %v", err)
	}

	// Verify expired state is deleted
	_, err = store.GetState(ctx, expiredState)
	if err != ErrNotFound {
		t.Error("Expired state should be deleted")
	}
}

func TestInMemoryOIDCStateStore_DeleteState(t *testing.T) {
	store := NewInMemoryOIDCStateStore()
	ctx := context.Background()

	state := "state123"
	data := &OIDCState{Provider: "google"}
	store.StoreState(ctx, state, data, 10*time.Minute)

	// Test deleting state
	err := store.DeleteState(ctx, state)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify state is deleted
	_, err = store.GetState(ctx, state)
	if err != ErrNotFound {
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
			store.CreateUser(ctx, user)
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
			store.CreateSession(ctx, sessionID, data, 1*time.Hour)
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
