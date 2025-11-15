package storage

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrNotFound is returned when a requested entity is not found in storage.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists is returned when attempting to create an entity that already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrExpired is returned when a session or token has expired.
	ErrExpired = errors.New("expired")
)

// InMemoryUserStore provides an in-memory implementation of UserStore.
// Suitable for testing and development. NOT recommended for production.
type InMemoryUserStore struct {
	mu            sync.RWMutex
	users         map[string]*User
	emailIndex    map[string]string // email -> userID
	usernameIndex map[string]string // username -> userID
}

// NewInMemoryUserStore creates a new in-memory user store.
func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users:         make(map[string]*User),
		emailIndex:    make(map[string]string),
		usernameIndex: make(map[string]string),
	}
}

func (s *InMemoryUserStore) CreateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return ErrAlreadyExists
	}

	if user.Email != "" {
		if _, exists := s.emailIndex[user.Email]; exists {
			return ErrAlreadyExists
		}
	}

	if user.Username != "" {
		if _, exists := s.usernameIndex[user.Username]; exists {
			return ErrAlreadyExists
		}
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	s.users[user.ID] = user
	if user.Email != "" {
		s.emailIndex[user.Email] = user.ID
	}
	if user.Username != "" {
		s.usernameIndex[user.Username] = user.ID
	}

	return nil
}

func (s *InMemoryUserStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrNotFound
	}

	return user, nil
}

func (s *InMemoryUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, exists := s.emailIndex[email]
	if !exists {
		return nil, ErrNotFound
	}

	return s.users[userID], nil
}

func (s *InMemoryUserStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, exists := s.usernameIndex[username]
	if !exists {
		return nil, ErrNotFound
	}

	return s.users[userID], nil
}

func (s *InMemoryUserStore) UpdateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.users[user.ID]
	if !exists {
		return ErrNotFound
	}

	// Update indexes if email or username changed
	if existing.Email != user.Email {
		// Check if new email is already taken by another user
		if user.Email != "" {
			if existingUserID, exists := s.emailIndex[user.Email]; exists && existingUserID != user.ID {
				return ErrAlreadyExists
			}
		}
		delete(s.emailIndex, existing.Email)
		if user.Email != "" {
			s.emailIndex[user.Email] = user.ID
		}
	}

	if existing.Username != user.Username {
		// Check if new username is already taken by another user
		if user.Username != "" {
			if existingUserID, exists := s.usernameIndex[user.Username]; exists && existingUserID != user.ID {
				return ErrAlreadyExists
			}
		}
		delete(s.usernameIndex, existing.Username)
		if user.Username != "" {
			s.usernameIndex[user.Username] = user.ID
		}
	}

	user.UpdatedAt = time.Now()
	s.users[user.ID] = user

	return nil
}

func (s *InMemoryUserStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	delete(s.users, id)
	if user.Email != "" {
		delete(s.emailIndex, user.Email)
	}
	if user.Username != "" {
		delete(s.usernameIndex, user.Username)
	}

	return nil
}

// InMemoryCredentialStore provides an in-memory implementation of CredentialStore.
type InMemoryCredentialStore struct {
	mu                   sync.RWMutex
	passwordHashes       map[string][]byte                // userID -> hash
	webauthnCreds        map[string][]*WebAuthnCredential // userID -> credentials
	webauthnCredsById    map[string]*WebAuthnCredential   // credentialID (hex) -> credential
	passwordResetTokens  map[string]*tokenData            // token -> data
	emailVerifyTokens    map[string]*tokenData            // token -> data
	totpSecrets          map[string]*totpData             // userID -> TOTP data
}

type tokenData struct {
	userID    string
	expiresAt time.Time
}

type totpData struct {
	secret      string
	backupCodes map[string]bool // code -> used (true if used, false if available)
}

// NewInMemoryCredentialStore creates a new in-memory credential store.
func NewInMemoryCredentialStore() *InMemoryCredentialStore {
	return &InMemoryCredentialStore{
		passwordHashes:      make(map[string][]byte),
		webauthnCreds:       make(map[string][]*WebAuthnCredential),
		webauthnCredsById:   make(map[string]*WebAuthnCredential),
		passwordResetTokens: make(map[string]*tokenData),
		emailVerifyTokens:   make(map[string]*tokenData),
		totpSecrets:         make(map[string]*totpData),
	}
}

func (s *InMemoryCredentialStore) StorePasswordHash(ctx context.Context, userID string, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.passwordHashes[userID] = hash
	return nil
}

func (s *InMemoryCredentialStore) GetPasswordHash(ctx context.Context, userID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash, exists := s.passwordHashes[userID]
	if !exists {
		return nil, ErrNotFound
	}

	return hash, nil
}

func (s *InMemoryCredentialStore) StoreWebAuthnCredential(ctx context.Context, userID string, credential *WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	credential.UserID = userID
	credential.CreatedAt = time.Now()
	credential.UpdatedAt = time.Now()

	s.webauthnCreds[userID] = append(s.webauthnCreds[userID], credential)
	s.webauthnCredsById[string(credential.ID)] = credential

	return nil
}

func (s *InMemoryCredentialStore) GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, exists := s.webauthnCreds[userID]
	if !exists {
		return []*WebAuthnCredential{}, nil
	}

	return creds, nil
}

func (s *InMemoryCredentialStore) UpdateWebAuthnCredential(ctx context.Context, credential *WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.webauthnCredsById[string(credential.ID)]
	if !exists {
		return ErrNotFound
	}

	credential.UpdatedAt = time.Now()
	*existing = *credential

	return nil
}

func (s *InMemoryCredentialStore) DeleteWebAuthnCredential(ctx context.Context, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.webauthnCredsById[string(credentialID)]
	if !exists {
		return ErrNotFound
	}

	// Remove from user's credential list
	userCreds := s.webauthnCreds[cred.UserID]
	for i, c := range userCreds {
		if string(c.ID) == string(credentialID) {
			s.webauthnCreds[cred.UserID] = append(userCreds[:i], userCreds[i+1:]...)
			break
		}
	}

	delete(s.webauthnCredsById, string(credentialID))

	return nil
}

func (s *InMemoryCredentialStore) StorePasswordResetToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.passwordResetTokens[token] = &tokenData{
		userID:    userID,
		expiresAt: expiresAt,
	}

	return nil
}

func (s *InMemoryCredentialStore) ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.passwordResetTokens[token]
	if !exists {
		return "", ErrNotFound
	}

	if time.Now().After(data.expiresAt) {
		return "", ErrExpired
	}

	return data.userID, nil
}

func (s *InMemoryCredentialStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.passwordResetTokens, token)
	return nil
}

func (s *InMemoryCredentialStore) StoreEmailVerificationToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.emailVerifyTokens[token] = &tokenData{
		userID:    userID,
		expiresAt: expiresAt,
	}

	return nil
}

func (s *InMemoryCredentialStore) ValidateEmailVerificationToken(ctx context.Context, token string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.emailVerifyTokens[token]
	if !exists {
		return "", ErrNotFound
	}

	if time.Now().After(data.expiresAt) {
		return "", ErrExpired
	}

	return data.userID, nil
}

func (s *InMemoryCredentialStore) DeleteEmailVerificationToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.emailVerifyTokens, token)
	return nil
}

func (s *InMemoryCredentialStore) StoreTOTPSecret(ctx context.Context, userID string, secret string, backupCodes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	codes := make(map[string]bool)
	for _, code := range backupCodes {
		codes[code] = false // false = unused
	}

	s.totpSecrets[userID] = &totpData{
		secret:      secret,
		backupCodes: codes,
	}

	return nil
}

func (s *InMemoryCredentialStore) GetTOTPSecret(ctx context.Context, userID string) (string, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.totpSecrets[userID]
	if !exists {
		return "", nil, ErrNotFound
	}

	// Return only unused backup codes
	unusedCodes := make([]string, 0)
	for code, used := range data.backupCodes {
		if !used {
			unusedCodes = append(unusedCodes, code)
		}
	}

	return data.secret, unusedCodes, nil
}

func (s *InMemoryCredentialStore) DeleteTOTPSecret(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.totpSecrets, userID)
	return nil
}

func (s *InMemoryCredentialStore) UseBackupCode(ctx context.Context, userID string, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, exists := s.totpSecrets[userID]
	if !exists {
		return ErrNotFound
	}

	used, exists := data.backupCodes[code]
	if !exists {
		return errors.New("invalid backup code")
	}

	if used {
		return errors.New("backup code already used")
	}

	data.backupCodes[code] = true
	return nil
}

// InMemorySessionStore provides an in-memory implementation of SessionStore.
type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
}

type sessionEntry struct {
	data      *SessionData
	expiresAt time.Time
}

// NewInMemorySessionStore creates a new in-memory session store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]*sessionEntry),
	}
}

func (s *InMemorySessionStore) CreateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	data.CreatedAt = now
	data.ExpiresAt = now.Add(ttl)

	s.sessions[sessionID] = &sessionEntry{
		data:      data,
		expiresAt: data.ExpiresAt,
	}

	return nil
}

func (s *InMemorySessionStore) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		return nil, ErrExpired
	}

	return entry.data, nil
}

func (s *InMemorySessionStore) UpdateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		return ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		return ErrExpired
	}

	expiresAt := time.Now().Add(ttl)
	data.ExpiresAt = expiresAt

	s.sessions[sessionID] = &sessionEntry{
		data:      data,
		expiresAt: expiresAt,
	}

	return nil
}

func (s *InMemorySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

func (s *InMemorySessionStore) RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		return ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		return ErrExpired
	}

	expiresAt := time.Now().Add(ttl)
	entry.expiresAt = expiresAt
	entry.data.ExpiresAt = expiresAt

	return nil
}

// InMemoryTokenStore provides an in-memory implementation of TokenStore.
type InMemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*tokenEntry // tokenID -> entry
}

type tokenEntry struct {
	userID    string
	expiresAt time.Time
	revoked   bool
}

// NewInMemoryTokenStore creates a new in-memory token store.
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make(map[string]*tokenEntry),
	}
}

func (s *InMemoryTokenStore) StoreRefreshToken(ctx context.Context, userID string, tokenID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[tokenID] = &tokenEntry{
		userID:    userID,
		expiresAt: expiresAt,
		revoked:   false,
	}

	return nil
}

func (s *InMemoryTokenStore) ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.tokens[tokenID]
	if !exists {
		return "", ErrNotFound
	}

	if entry.revoked {
		return "", errors.New("token revoked")
	}

	if time.Now().After(entry.expiresAt) {
		return "", ErrExpired
	}

	return entry.userID, nil
}

func (s *InMemoryTokenStore) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.tokens[tokenID]
	if !exists {
		return ErrNotFound
	}

	entry.revoked = true
	return nil
}

func (s *InMemoryTokenStore) RevokeAllUserTokens(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.tokens {
		if entry.userID == userID {
			entry.revoked = true
		}
	}

	return nil
}

// InMemoryOIDCStateStore provides an in-memory implementation of OIDCStateStore.
type InMemoryOIDCStateStore struct {
	mu     sync.RWMutex
	states map[string]*stateEntry
}

type stateEntry struct {
	data      *OIDCState
	expiresAt time.Time
}

// NewInMemoryOIDCStateStore creates a new in-memory OIDC state store.
func NewInMemoryOIDCStateStore() *InMemoryOIDCStateStore {
	return &InMemoryOIDCStateStore{
		states: make(map[string]*stateEntry),
	}
}

func (s *InMemoryOIDCStateStore) StoreState(ctx context.Context, state string, data *OIDCState, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data.CreatedAt = time.Now()

	s.states[state] = &stateEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

func (s *InMemoryOIDCStateStore) GetState(ctx context.Context, state string) (*OIDCState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.states[state]
	if !exists {
		return nil, ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		delete(s.states, state)
		return nil, ErrExpired
	}

	data := entry.data
	delete(s.states, state) // One-time use

	return data, nil
}

func (s *InMemoryOIDCStateStore) DeleteState(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.states, state)
	return nil
}
