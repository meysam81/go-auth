// Package webauthn provides WebAuthn/Passkey authentication support.
package webauthn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/meysam81/go-auth/storage"
)

var (
	// ErrUserNotFound is returned when a user doesn't exist.
	ErrUserNotFound = errors.New("user not found")

	// ErrCredentialNotFound is returned when a credential doesn't exist.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrRegistrationFailed is returned when registration fails.
	ErrRegistrationFailed = errors.New("registration failed")

	// ErrAuthenticationFailed is returned when authentication fails.
	ErrAuthenticationFailed = errors.New("authentication failed")
)

// Authenticator handles WebAuthn/Passkey authentication.
type Authenticator struct {
	webAuthn        *webauthn.WebAuthn
	userStore       storage.UserStore
	credentialStore storage.CredentialStore
	sessionStore    storage.OIDCStateStore // Reused for storing challenge data
}

// Config configures the WebAuthn authenticator.
type Config struct {
	// RelyingParty configuration
	RPDisplayName string // e.g., "My App"
	RPID          string // e.g., "example.com"
	RPOrigins     []string // e.g., ["https://example.com"]

	// Storage
	UserStore       storage.UserStore
	CredentialStore storage.CredentialStore
	SessionStore    storage.OIDCStateStore // For storing challenges

	// Optional WebAuthn configuration
	Timeout                  int    // Optional: timeout in milliseconds (default 60000)
	AuthenticatorAttachment  string // Optional: "platform", "cross-platform", or "" for both
	UserVerification         string // Optional: "required", "preferred", "discouraged"
	ResidentKey              string // Optional: "required", "preferred", "discouraged"
}

// NewAuthenticator creates a new WebAuthn authenticator.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if cfg.UserStore == nil {
		return nil, errors.New("user store is required")
	}
	if cfg.CredentialStore == nil {
		return nil, errors.New("credential store is required")
	}
	if cfg.SessionStore == nil {
		return nil, errors.New("session store is required for challenge storage")
	}
	if cfg.RPID == "" {
		return nil, errors.New("relying party ID is required")
	}
	if cfg.RPDisplayName == "" {
		return nil, errors.New("relying party display name is required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, errors.New("at least one relying party origin is required")
	}

	wconfig := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	}

	// Set authenticator selection criteria
	if cfg.AuthenticatorAttachment != "" || cfg.UserVerification != "" || cfg.ResidentKey != "" {
		wconfig.AuthenticatorSelection = protocol.AuthenticatorSelection{}

		if cfg.AuthenticatorAttachment != "" {
			attachment := protocol.AuthenticatorAttachment(cfg.AuthenticatorAttachment)
			wconfig.AuthenticatorSelection.AuthenticatorAttachment = attachment
		}

		if cfg.UserVerification != "" {
			wconfig.AuthenticatorSelection.UserVerification = protocol.UserVerificationRequirement(cfg.UserVerification)
		}

		if cfg.ResidentKey != "" {
			requirement := protocol.ResidentKeyRequirement(cfg.ResidentKey)
			wconfig.AuthenticatorSelection.ResidentKey = requirement
		}
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &Authenticator{
		webAuthn:        wa,
		userStore:       cfg.UserStore,
		credentialStore: cfg.CredentialStore,
		sessionStore:    cfg.SessionStore,
	}, nil
}

// webAuthnUser wraps a storage.User to implement webauthn.User interface.
type webAuthnUser struct {
	user        *storage.User
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *webAuthnUser) WebAuthnName() string {
	if u.user.Username != "" {
		return u.user.Username
	}
	return u.user.Email
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.user.Name != "" {
		return u.user.Name
	}
	return u.WebAuthnName()
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *webAuthnUser) WebAuthnIcon() string {
	return ""
}

// BeginRegistration starts the WebAuthn registration ceremony.
// Returns the credential creation options to send to the client.
func (a *Authenticator) BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", ErrUserNotFound
		}
		return nil, "", fmt.Errorf("failed to get user: %w", err)
	}

	// Get existing credentials
	existingCreds, err := a.credentialStore.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get existing credentials: %w", err)
	}

	// Convert to webauthn credentials
	credentials := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credentials = append(credentials, a.storageCredToWebAuthn(cred))
	}

	webUser := &webAuthnUser{
		user:        user,
		credentials: credentials,
	}

	options, session, err := a.webAuthn.BeginRegistration(webUser)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store session data
	sessionID := string(session.Challenge)
	sessionData, err := encodeSessionData(session)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode session data: %w", err)
	}

	stateData := &storage.OIDCState{
		Provider: "webauthn",
		Metadata: map[string]interface{}{
			"user_id": userID,
			"session": sessionData,
		},
	}

	if err := a.sessionStore.StoreState(ctx, sessionID, stateData, 300); err != nil { // 5 min timeout
		return nil, "", fmt.Errorf("failed to store challenge: %w", err)
	}

	return options, sessionID, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// Stores the new credential and returns it.
func (a *Authenticator) FinishRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (*storage.WebAuthnCredential, error) {
	// Retrieve session data
	stateData, err := a.sessionStore.GetState(ctx, sessionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return nil, ErrRegistrationFailed
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	userID, ok := stateData.Metadata["user_id"].(string)
	if !ok {
		return nil, ErrRegistrationFailed
	}

	sessionDataStr, ok := stateData.Metadata["session"].(string)
	if !ok {
		return nil, ErrRegistrationFailed
	}

	session, err := decodeSessionData(sessionDataStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session data: %w", err)
	}

	// Get user
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get existing credentials
	existingCreds, err := a.credentialStore.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing credentials: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credentials = append(credentials, a.storageCredToWebAuthn(cred))
	}

	webUser := &webAuthnUser{
		user:        user,
		credentials: credentials,
	}

	credential, err := a.webAuthn.CreateCredential(webUser, *session, response)
	if err != nil {
		return nil, ErrRegistrationFailed
	}

	// Store credential
	storageCred := &storage.WebAuthnCredential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		UserID:          userID,
		Transports:      protocolTransportsToStrings(credential.Transport),
		Metadata:        make(map[string]interface{}),
	}

	if err := a.credentialStore.StoreWebAuthnCredential(ctx, userID, storageCred); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	return storageCred, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
func (a *Authenticator) BeginLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, string, error) {
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", ErrUserNotFound
		}
		return nil, "", fmt.Errorf("failed to get user: %w", err)
	}

	// Get credentials
	existingCreds, err := a.credentialStore.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get credentials: %w", err)
	}

	if len(existingCreds) == 0 {
		return nil, "", ErrCredentialNotFound
	}

	credentials := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credentials = append(credentials, a.storageCredToWebAuthn(cred))
	}

	webUser := &webAuthnUser{
		user:        user,
		credentials: credentials,
	}

	options, session, err := a.webAuthn.BeginLogin(webUser)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin login: %w", err)
	}

	// Store session data
	sessionID := string(session.Challenge)
	sessionData, err := encodeSessionData(session)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode session data: %w", err)
	}

	stateData := &storage.OIDCState{
		Provider: "webauthn",
		Metadata: map[string]interface{}{
			"user_id": userID,
			"session": sessionData,
		},
	}

	if err := a.sessionStore.StoreState(ctx, sessionID, stateData, 300); err != nil { // 5 min timeout
		return nil, "", fmt.Errorf("failed to store challenge: %w", err)
	}

	return options, sessionID, nil
}

// FinishLogin completes the WebAuthn authentication ceremony.
func (a *Authenticator) FinishLogin(ctx context.Context, sessionID string, response *protocol.ParsedCredentialAssertionData) (*storage.User, error) {
	// Retrieve session data
	stateData, err := a.sessionStore.GetState(ctx, sessionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return nil, ErrAuthenticationFailed
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	userID, ok := stateData.Metadata["user_id"].(string)
	if !ok {
		return nil, ErrAuthenticationFailed
	}

	sessionDataStr, ok := stateData.Metadata["session"].(string)
	if !ok {
		return nil, ErrAuthenticationFailed
	}

	session, err := decodeSessionData(sessionDataStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session data: %w", err)
	}

	// Get user
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get credentials
	existingCreds, err := a.credentialStore.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credentials = append(credentials, a.storageCredToWebAuthn(cred))
	}

	webUser := &webAuthnUser{
		user:        user,
		credentials: credentials,
	}

	credential, err := a.webAuthn.ValidateLogin(webUser, *session, response)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	// Update credential sign count
	for _, cred := range existingCreds {
		if string(cred.ID) == string(credential.ID) {
			cred.SignCount = credential.Authenticator.SignCount
			if err := a.credentialStore.UpdateWebAuthnCredential(ctx, cred); err != nil {
				// Log but don't fail authentication
				fmt.Printf("Warning: failed to update credential sign count: %v\n", err)
			}
			break
		}
	}

	return user, nil
}

// DeleteCredential removes a WebAuthn credential.
func (a *Authenticator) DeleteCredential(ctx context.Context, credentialID []byte) error {
	return a.credentialStore.DeleteWebAuthnCredential(ctx, credentialID)
}

// GetUserCredentials returns all WebAuthn credentials for a user.
func (a *Authenticator) GetUserCredentials(ctx context.Context, userID string) ([]*storage.WebAuthnCredential, error) {
	return a.credentialStore.GetWebAuthnCredentials(ctx, userID)
}

// storageCredToWebAuthn converts a storage credential to webauthn format.
func (a *Authenticator) storageCredToWebAuthn(cred *storage.WebAuthnCredential) webauthn.Credential {
	return webauthn.Credential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       stringsToProtocolTransports(cred.Transports),
		Authenticator: webauthn.Authenticator{
			AAGUID:    cred.AAGUID,
			SignCount: cred.SignCount,
		},
	}
}

// Helper functions for protocol transport conversion
func protocolTransportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	result := make([]string, len(transports))
	for i, t := range transports {
		result[i] = string(t)
	}
	return result
}

func stringsToProtocolTransports(transports []string) []protocol.AuthenticatorTransport {
	result := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		result[i] = protocol.AuthenticatorTransport(t)
	}
	return result
}

// Session data encoding helpers
func encodeSessionData(session *webauthn.SessionData) (string, error) {
	// In production, use proper encoding (JSON, protobuf, etc.)
	// For simplicity, we'll use base64 encoding of a JSON representation
	data := fmt.Sprintf("%s:%s",
		string(session.Challenge),
		string(session.UserID),
	)
	return base64.RawURLEncoding.EncodeToString([]byte(data)), nil
}

func decodeSessionData(encoded string) (*webauthn.SessionData, error) {
	// This is a simplified implementation
	// In production, use proper decoding matching your encoding strategy
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	// Parse the encoded data
	// This is a placeholder - you'd need proper serialization
	session := &webauthn.SessionData{}

	// For now, we'll extract challenge from the encoded string
	// In production, use proper JSON/protobuf serialization
	// Simple parsing - in production use proper serialization
	session.Challenge = string(decoded)

	return session, nil
}
