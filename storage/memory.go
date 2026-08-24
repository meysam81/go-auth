package storage

import (
	"bytes"
	"context"
	"crypto/subtle"
	"sync"
	"time"
)

// The InMemory* types below are the reference implementations of the interfaces
// in storage.go. They exist so the examples run, so the test suite has a store
// that behaves, and so a downstream implementor has something to read. They are
// NOT production stores: everything is lost on restart, nothing is shared
// between processes, and eviction is opportunistic rather than scheduled.
//
// In v2 this file moves out of the public API into a conformance-harness
// package, where its real value lies -- letting an implementor run their own
// PostgreSQL or Redis store against the same expectations (see the v2 removal
// list in docs/security-hardening.md).
//
// Two properties are load-bearing wherever these types are used as a model:
//
//  1. Nothing hands out a pointer into its own state. Returning the stored
//     struct lets a caller mutate the store without holding the lock, which is
//     both a data race and a way to edit a session that was never written back.
//  2. Every read that can observe an expired entry evicts it. An in-memory map
//     with no eviction is an unbounded allocation driven by unauthenticated
//     traffic.

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

// CreateUser creates a new user, rejecting a duplicate ID, email or username.
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

	s.users[user.ID] = cloneUser(user)
	if user.Email != "" {
		s.emailIndex[user.Email] = user.ID
	}
	if user.Username != "" {
		s.usernameIndex[user.Username] = user.ID
	}

	return nil
}

// GetUserByID retrieves a user by ID, or ErrNotFound.
func (s *InMemoryUserStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrNotFound
	}

	return cloneUser(user), nil
}

// GetUserByEmail retrieves a user by email, or ErrNotFound.
func (s *InMemoryUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, exists := s.emailIndex[email]
	if !exists {
		return nil, ErrNotFound
	}

	// An index entry pointing at a missing user is a defect in this store, not an
	// invitation to return a nil *User to a caller that will dereference it.
	user, exists := s.users[userID]
	if !exists {
		return nil, ErrNotFound
	}

	return cloneUser(user), nil
}

// GetUserByUsername retrieves a user by username, or ErrNotFound.
func (s *InMemoryUserStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, exists := s.usernameIndex[username]
	if !exists {
		return nil, ErrNotFound
	}

	user, exists := s.users[userID]
	if !exists {
		return nil, ErrNotFound
	}

	return cloneUser(user), nil
}

// UpdateUser updates an existing user and reindexes a changed email or username.
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

	updated := cloneUser(user)
	// Creation time is a property of the record, not of the caller's copy: an
	// update built from a partially populated struct used to silently zero it.
	updated.CreatedAt = existing.CreatedAt
	s.users[user.ID] = updated

	return nil
}

// DeleteUser removes a user and its index entries, or returns ErrNotFound.
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
	mu                  sync.RWMutex
	passwordHashes      map[string][]byte                // userID -> hash
	webauthnCreds       map[string][]*WebAuthnCredential // userID -> credentials
	webauthnCredsByID   map[string]*WebAuthnCredential   // credentialID (raw bytes as key) -> credential
	passwordResetTokens map[string]*tokenData            // token hash -> data
	emailVerifyTokens   map[string]*tokenData            // token hash -> data
	totpSecrets         map[string]*totpData             // userID -> TOTP data
}

type tokenData struct {
	userID    string
	expiresAt time.Time
}

// backupCode is one hashed backup code and whether it has been consumed. A
// slice rather than a map because consumption is decided by a constant-time
// scan over every entry (see UseBackupCode), which a map lookup cannot give.
type backupCode struct {
	value string
	used  bool
}

type totpData struct {
	secret      string
	backupCodes []backupCode
}

// NewInMemoryCredentialStore creates a new in-memory credential store.
func NewInMemoryCredentialStore() *InMemoryCredentialStore {
	return &InMemoryCredentialStore{
		passwordHashes:      make(map[string][]byte),
		webauthnCreds:       make(map[string][]*WebAuthnCredential),
		webauthnCredsByID:   make(map[string]*WebAuthnCredential),
		passwordResetTokens: make(map[string]*tokenData),
		emailVerifyTokens:   make(map[string]*tokenData),
		totpSecrets:         make(map[string]*totpData),
	}
}

// StorePasswordHash stores a bcrypt digest for a user.
func (s *InMemoryCredentialStore) StorePasswordHash(ctx context.Context, userID string, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.passwordHashes[userID] = append([]byte(nil), hash...)
	return nil
}

// GetPasswordHash retrieves the bcrypt digest for a user, or ErrNotFound.
func (s *InMemoryCredentialStore) GetPasswordHash(ctx context.Context, userID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash, exists := s.passwordHashes[userID]
	if !exists {
		return nil, ErrNotFound
	}

	return append([]byte(nil), hash...), nil
}

// StoreWebAuthnCredential stores a credential for a user.
//
// A credential ID already on record is rejected with ErrAlreadyExists: WebAuthn
// credential IDs are unique by construction, so a repeat is either a replayed
// registration or an authenticator claiming somebody else's credential, and
// overwriting would move the credential to the new user.
func (s *InMemoryCredentialStore) StoreWebAuthnCredential(ctx context.Context, userID string, credential *WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.webauthnCredsByID[string(credential.ID)]; exists {
		return ErrAlreadyExists
	}

	now := time.Now()
	credential.UserID = userID
	credential.CreatedAt = now
	credential.UpdatedAt = now

	stored := cloneWebAuthnCredential(credential)
	s.webauthnCreds[userID] = append(s.webauthnCreds[userID], stored)
	s.webauthnCredsByID[string(credential.ID)] = stored

	return nil
}

// GetWebAuthnCredentials retrieves every credential for a user, or an empty
// slice when the user has none.
func (s *InMemoryCredentialStore) GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds := s.webauthnCreds[userID]
	out := make([]*WebAuthnCredential, 0, len(creds))
	for _, cred := range creds {
		out = append(out, cloneWebAuthnCredential(cred))
	}

	return out, nil
}

// UpdateWebAuthnCredential updates a stored credential, typically to advance the
// signature counter.
//
// A credential naming a different owner than the one on record is reported as
// ErrNotFound: a credential lookup is scoped to its owner, so an update for the
// wrong user finds nothing to update, and re-owning a credential is not an edit.
func (s *InMemoryCredentialStore) UpdateWebAuthnCredential(ctx context.Context, credential *WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.webauthnCredsByID[string(credential.ID)]
	if !exists {
		return ErrNotFound
	}

	if credential.UserID != "" && credential.UserID != existing.UserID {
		return ErrNotFound
	}

	credential.UpdatedAt = time.Now()

	updated := cloneWebAuthnCredential(credential)
	updated.UserID = existing.UserID
	updated.CreatedAt = existing.CreatedAt

	// The per-user slice and the by-ID index hold the same pointer, so writing
	// through it keeps the two views from drifting apart.
	*existing = *updated

	return nil
}

// DeleteWebAuthnCredential removes a credential by ID, or returns ErrNotFound.
func (s *InMemoryCredentialStore) DeleteWebAuthnCredential(ctx context.Context, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.webauthnCredsByID[string(credentialID)]
	if !exists {
		return ErrNotFound
	}

	// Remove from user's credential list
	userCreds := s.webauthnCreds[cred.UserID]
	for i, c := range userCreds {
		if bytes.Equal(c.ID, credentialID) {
			s.webauthnCreds[cred.UserID] = append(userCreds[:i], userCreds[i+1:]...)
			break
		}
	}

	delete(s.webauthnCredsByID, string(credentialID))

	return nil
}

// StorePasswordResetToken stores the HASH of a password reset token (F-05).
func (s *InMemoryCredentialStore) StorePasswordResetToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset tokens are minted by an unauthenticated endpoint, so without a sweep
	// the map is an allocation an attacker controls the size of.
	sweepExpiredTokens(s.passwordResetTokens)

	s.passwordResetTokens[token] = &tokenData{
		userID:    userID,
		expiresAt: expiresAt,
	}

	return nil
}

// ValidatePasswordResetToken resolves a token hash to a user ID, returning
// ErrNotFound for an unknown hash and ErrExpired for a lapsed one.
func (s *InMemoryCredentialStore) ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return lookupToken(s.passwordResetTokens, token)
}

// DeletePasswordResetToken deletes a token by its hash. Deleting an absent token
// is not an error, so a caller that has already consumed it is not punished.
func (s *InMemoryCredentialStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.passwordResetTokens, token)
	return nil
}

// StoreEmailVerificationToken stores the HASH of a verification token (F-05).
func (s *InMemoryCredentialStore) StoreEmailVerificationToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sweepExpiredTokens(s.emailVerifyTokens)

	s.emailVerifyTokens[token] = &tokenData{
		userID:    userID,
		expiresAt: expiresAt,
	}

	return nil
}

// ValidateEmailVerificationToken resolves a token hash to a user ID, returning
// ErrNotFound for an unknown hash and ErrExpired for a lapsed one.
func (s *InMemoryCredentialStore) ValidateEmailVerificationToken(ctx context.Context, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return lookupToken(s.emailVerifyTokens, token)
}

// DeleteEmailVerificationToken deletes a token by its hash.
func (s *InMemoryCredentialStore) DeleteEmailVerificationToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.emailVerifyTokens, token)
	return nil
}

// StoreTOTPSecret stores a TOTP secret (possibly ciphertext) and the hashed
// backup codes for a user, replacing any previous enrolment.
func (s *InMemoryCredentialStore) StoreTOTPSecret(ctx context.Context, userID, secret string, backupCodes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	codes := make([]backupCode, 0, len(backupCodes))
	for _, code := range backupCodes {
		codes = append(codes, backupCode{value: code})
	}

	s.totpSecrets[userID] = &totpData{
		secret:      secret,
		backupCodes: codes,
	}

	return nil
}

// GetTOTPSecret returns the stored secret and the backup codes not yet
// consumed, exactly as they were stored, or ErrNotFound.
func (s *InMemoryCredentialStore) GetTOTPSecret(ctx context.Context, userID string) (string, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.totpSecrets[userID]
	if !exists {
		return "", nil, ErrNotFound
	}

	unusedCodes := make([]string, 0, len(data.backupCodes))
	for _, code := range data.backupCodes {
		if !code.used {
			unusedCodes = append(unusedCodes, code.value)
		}
	}

	return data.secret, unusedCodes, nil
}

// DeleteTOTPSecret removes a user's enrolment.
func (s *InMemoryCredentialStore) DeleteTOTPSecret(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.totpSecrets, userID)
	return nil
}

// UseBackupCode consumes a backup code.
//
// Check and consume happen under one exclusive lock, so two callers racing with
// the same code cannot both win: single use is a property of the store, not of
// the caller's sequencing.
//
// The scan is constant-time and does not stop at the first match. A comparison
// that returns early distinguishes "no such code" from "that code was already
// used" by how long it took, which tells an attacker which of the codes they
// hold were ever issued (CWE-208).
func (s *InMemoryCredentialStore) UseBackupCode(ctx context.Context, userID, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, exists := s.totpSecrets[userID]
	if !exists {
		return ErrNotFound
	}

	matched := -1
	for i := range data.backupCodes {
		if subtle.ConstantTimeCompare([]byte(data.backupCodes[i].value), []byte(code)) == 1 {
			matched = i
		}
	}

	if matched < 0 {
		return ErrInvalidBackupCode
	}

	if data.backupCodes[matched].used {
		return ErrBackupCodeUsed
	}

	data.backupCodes[matched].used = true

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

// CreateSession stores a new session under sessionID.
//
// An ID already in use is rejected with ErrAlreadyExists rather than replaced.
// Session IDs carry 256 bits of entropy, so a collision is not chance: it is a
// defect, or an ID that did not come from session.Manager, which is the shape of
// a session fixation attempt (F-14, CWE-384). It is also what makes
// session.Manager.Rotate safe -- a rotation can never land on top of a live
// session.
func (s *InMemorySessionStore) CreateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, exists := s.sessions[sessionID]; exists && time.Now().Before(existing.expiresAt) {
		return ErrAlreadyExists
	}

	now := time.Now()
	data.CreatedAt = now
	data.ExpiresAt = now.Add(ttl)

	s.sessions[sessionID] = &sessionEntry{
		data:      cloneSessionData(data),
		expiresAt: data.ExpiresAt,
	}

	return nil
}

// GetSession returns a copy of the session data, ErrNotFound for an unknown ID,
// or ErrExpired for a lapsed one, which it also evicts.
func (s *InMemorySessionStore) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		delete(s.sessions, sessionID)
		return nil, ErrExpired
	}

	// A copy, not the entry: a caller holding the stored pointer races every
	// RefreshSession that writes through it, and can edit a live session without
	// ever calling UpdateSession.
	return cloneSessionData(entry.data), nil
}

// UpdateSession replaces a live session's data and resets its TTL.
func (s *InMemorySessionStore) UpdateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		return ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		delete(s.sessions, sessionID)
		return ErrExpired
	}

	expiresAt := time.Now().Add(ttl)
	data.ExpiresAt = expiresAt

	stored := cloneSessionData(data)
	// The session was created once; an update is not a new session, and losing
	// the original creation time loses the only evidence of its age.
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = entry.data.CreatedAt
	}

	s.sessions[sessionID] = &sessionEntry{
		data:      stored,
		expiresAt: expiresAt,
	}

	return nil
}

// DeleteSession removes a session. Deleting an absent session is not an error.
func (s *InMemorySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

// RefreshSession extends a live session's TTL, or returns ErrExpired for a
// lapsed one, which it also evicts.
func (s *InMemorySessionStore) RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		return ErrNotFound
	}

	if time.Now().After(entry.expiresAt) {
		delete(s.sessions, sessionID)
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

// StoreRefreshToken records a refresh token ID for a user.
func (s *InMemoryTokenStore) StoreRefreshToken(ctx context.Context, userID, tokenID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Expired entries are swept here rather than on read: a revocation must stay
	// visible for as long as the token could still be presented, so eviction is
	// tied to expiry and nothing else.
	now := time.Now()
	for id, entry := range s.tokens {
		if now.After(entry.expiresAt) {
			delete(s.tokens, id)
		}
	}

	s.tokens[tokenID] = &tokenEntry{
		userID:    userID,
		expiresAt: expiresAt,
		revoked:   false,
	}

	return nil
}

// ValidateRefreshToken resolves a token ID to its user, or returns ErrNotFound,
// ErrTokenRevoked or ErrExpired.
func (s *InMemoryTokenStore) ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.tokens[tokenID]
	if !exists {
		return "", ErrNotFound
	}

	if entry.revoked {
		return "", ErrTokenRevoked
	}

	if time.Now().After(entry.expiresAt) {
		return "", ErrExpired
	}

	return entry.userID, nil
}

// RevokeRefreshToken revokes a single refresh token, or returns ErrNotFound.
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

// RevokeAllUserTokens revokes every refresh token held for a user. Revoking
// nothing is not an error: the postcondition -- the user holds no live refresh
// token -- is satisfied either way.
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

// StoreState records the state of an in-flight OIDC authorization request.
func (s *InMemoryOIDCStateStore) StoreState(ctx context.Context, state string, data *OIDCState, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// An abandoned flow leaves a state nothing ever reads, and starting a flow
	// needs no authentication. Without this sweep the map grows for as long as an
	// attacker keeps hitting the authorization endpoint.
	now := time.Now()
	for key, entry := range s.states {
		if now.After(entry.expiresAt) {
			delete(s.states, key)
		}
	}

	data.CreatedAt = now

	s.states[state] = &stateEntry{
		data:      cloneOIDCState(data),
		expiresAt: now.Add(ttl),
	}

	return nil
}

// GetState retrieves a state and consumes it.
//
// Read and delete happen under one exclusive lock. Two callbacks racing with the
// same state must not both receive it, or the state parameter stops being
// single-use and stops being an anti-replay control.
func (s *InMemoryOIDCStateStore) GetState(ctx context.Context, state string) (*OIDCState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.states[state]
	if !exists {
		return nil, ErrNotFound
	}

	delete(s.states, state) // One-time use, whether or not it was still valid.

	if time.Now().After(entry.expiresAt) {
		return nil, ErrExpired
	}

	return cloneOIDCState(entry.data), nil
}

// DeleteState removes a state. Deleting an absent state is not an error.
func (s *InMemoryOIDCStateStore) DeleteState(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.states, state)
	return nil
}

// lookupToken resolves a token hash against a token map, evicting an expired
// entry as it goes. The caller must hold the write lock.
func lookupToken(tokens map[string]*tokenData, token string) (string, error) {
	data, exists := tokens[token]
	if !exists {
		return "", ErrNotFound
	}

	if time.Now().After(data.expiresAt) {
		delete(tokens, token)
		return "", ErrExpired
	}

	return data.userID, nil
}

// sweepExpiredTokens drops every lapsed entry. The caller must hold the write
// lock.
func sweepExpiredTokens(tokens map[string]*tokenData) {
	now := time.Now()
	for token, data := range tokens {
		if now.After(data.expiresAt) {
			delete(tokens, token)
		}
	}
}

func cloneMetadata(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}

	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}

	return out
}

func cloneUser(user *User) *User {
	if user == nil {
		return nil
	}

	clone := *user
	clone.Metadata = cloneMetadata(user.Metadata)

	return &clone
}

func cloneWebAuthnCredential(cred *WebAuthnCredential) *WebAuthnCredential {
	if cred == nil {
		return nil
	}

	clone := *cred
	clone.ID = append([]byte(nil), cred.ID...)
	clone.PublicKey = append([]byte(nil), cred.PublicKey...)
	clone.AAGUID = append([]byte(nil), cred.AAGUID...)
	if cred.Transports != nil {
		clone.Transports = append([]string(nil), cred.Transports...)
	}
	clone.Metadata = cloneMetadata(cred.Metadata)

	return &clone
}

func cloneSessionData(data *SessionData) *SessionData {
	if data == nil {
		return nil
	}

	clone := *data
	clone.Metadata = cloneMetadata(data.Metadata)

	return &clone
}

func cloneOIDCState(state *OIDCState) *OIDCState {
	if state == nil {
		return nil
	}

	clone := *state
	clone.Metadata = cloneMetadata(state.Metadata)

	return &clone
}
