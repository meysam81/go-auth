// Package webauthn provides WebAuthn/Passkey authentication support.
package webauthn

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/meysam81/go-auth/storage"
)

// Ceremony parameters that are not a caller's to get wrong.
const (
	// defaultCeremonyTimeout bounds one ceremony when Config.Timeout is unset.
	//
	// Five minutes is what go-webauthn advertises to the browser by default, and
	// the two windows must agree: the deadline the client is told about and the
	// deadline the relying party will honor are the same deadline.
	//
	// The type matters as much as the number. Both Begin calls used to hand the
	// untyped constant 300 to a time.Duration parameter under a "5 min timeout"
	// comment, which is 300 NANOSECONDS -- the challenge lapsed before the
	// options finished being serialized, so no ceremony this package started
	// could ever be completed against a store that honors the TTL it is given.
	defaultCeremonyTimeout = 5 * time.Minute

	// maxCeremonyTimeout is the longest window Config.Timeout may ask for.
	//
	// Past this a ceremony is no longer a ceremony: the browser prompt is long
	// gone and the stored challenge has become a long-lived bearer value waiting
	// for whoever reaches the challenge store first. Construction is the cheap
	// place to say so, since the alternative is discovering it in an incident.
	maxCeremonyTimeout = 15 * time.Minute

	// stateProvider tags every challenge record this package writes.
	//
	// Challenges are kept in a storage.OIDCStateStore, which the OIDC flow also
	// uses, and both flows hand their key to the browser -- the OIDC state in the
	// authorization URL, the WebAuthn challenge in the credential options. With
	// no type tag either flow can consume the other's single-use record, which is
	// CWE-843 spread across two protocols. The tag is written on the way in and
	// required on the way out.
	stateProvider = "webauthn"
)

// Keys inside a challenge record's metadata.
//
// They are part of a persisted format: a ceremony started by one build is
// finished by whatever build is running when the browser answers, so the two
// spellings must not drift.
const (
	stateKeyUserID  = "user_id"
	stateKeySession = "session"
)

// Keys inside a stored credential's metadata, carrying the WebAuthn Level 3
// backup flags.
//
// storage.WebAuthnCredential has no field for them and the v1 API is frozen, so
// they ride in the credential's own extensible metadata map. They are not
// decoration: §7.2 requires an assertion whose backup-eligibility disagrees with
// the value recorded at registration to be refused, and a relying party that
// cannot remember the registered value compares every assertion against a
// constant false -- which refuses every synced passkey, because those report
// BE=1.
const (
	metaKeyBackupEligible = "webauthn_backup_eligible"
	metaKeyBackupState    = "webauthn_backup_state"
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

	// ErrCredentialCloned is returned when an assertion's signature counter did
	// not advance past the value stored for that credential.
	//
	// WebAuthn Level 3 §6.1.1 names this the signal that at least two copies of a
	// credential's private key exist and are being used in parallel. It is the
	// only cloned-authenticator signal the protocol produces, because origin, RP
	// ID hash, challenge and signature all verify perfectly for a clone.
	//
	// It wraps ErrAuthenticationFailed so a caller that already treats that
	// sentinel as "refuse the sign-in" keeps doing so unchanged, while a caller
	// that wants to raise the security event a suspected clone deserves can match
	// this one specifically.
	ErrCredentialCloned = fmt.Errorf("%w: signature counter did not advance", ErrAuthenticationFailed)

	// ErrSignCountNotPersisted is returned when the credential store refused the
	// signature-counter write that an accepted assertion produced.
	//
	// The counter detects a clone only while it is durable: a dropped write
	// leaves the next assertion measured against a stale value, and the detector
	// is then blind for that credential permanently. Reporting that as success
	// hides the loss of the control, so the ceremony fails instead.
	//
	// It deliberately does NOT wrap ErrAuthenticationFailed. The credential
	// proved itself; the relying party's own storage is what failed, so this is a
	// server-side fault to alert on rather than a rejected user. Either way no
	// session is issued.
	ErrSignCountNotPersisted = errors.New("signature counter could not be persisted")
)

// errCeremonyState marks a challenge record that cannot be used: absent, lapsed,
// written by another flow, or structurally wrong.
//
// It stays inside the package. Each ceremony maps it onto its own sentinel so
// the caller cannot tell a lapsed challenge from one that never existed, which
// would otherwise answer "did this ceremony ever start?" for anyone who asks
// (CWE-204).
var errCeremonyState = errors.New("ceremony state unusable")

// Authenticator handles WebAuthn/Passkey authentication.
type Authenticator struct {
	webAuthn        *webauthn.WebAuthn
	userStore       storage.UserStore
	credentialStore storage.CredentialStore
	sessionStore    storage.OIDCStateStore // Reused for storing challenge data

	// ceremonyTimeout is the resolved Config.Timeout: the TTL of the stored
	// challenge, the expiry stamped into the ceremony's own session record, and
	// the hint sent to the browser, all the same value.
	ceremonyTimeout time.Duration
}

// Config configures the WebAuthn authenticator.
type Config struct {
	// RelyingParty configuration
	RPDisplayName string   // e.g., "My App"
	RPID          string   // e.g., "example.com"
	RPOrigins     []string // e.g., ["https://example.com"]

	// Storage
	UserStore       storage.UserStore
	CredentialStore storage.CredentialStore
	SessionStore    storage.OIDCStateStore // For storing challenges

	// Timeout bounds one ceremony, in milliseconds, and defaults to 300000 (five
	// minutes) -- the window go-webauthn advertises to the browser by default.
	//
	// It bounds three things at once so they cannot disagree: the timeout hint
	// sent to the client, the relying-party-side expiry stamped into the stored
	// session record, and the TTL of the stored challenge. A value above 15
	// minutes is refused at construction (see maxCeremonyTimeout).
	Timeout int

	// Optional WebAuthn configuration
	AuthenticatorAttachment string // Optional: "platform", "cross-platform", or "" for both
	UserVerification        string // Optional: "required", "preferred", "discouraged"
	ResidentKey             string // Optional: "required", "preferred", "discouraged"
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

	timeout, err := resolveCeremonyTimeout(cfg.Timeout)
	if err != nil {
		return nil, err
	}

	wconfig := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,

		// Enforce puts the deadline inside the ceremony's own session record, so
		// the window survives a challenge store that quietly ignores the TTL it
		// is handed. Two independent expiries, one number.
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    timeout,
				TimeoutUVD: timeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    timeout,
				TimeoutUVD: timeout,
			},
		},
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
		ceremonyTimeout: timeout,
	}, nil
}

// resolveCeremonyTimeout turns the configured millisecond count into the one
// duration every leg of a ceremony is measured against.
//
// A negative value is a mistake with a security consequence -- it would store
// the challenge with an already-lapsed TTL, or worse, be read as "no expiry" by
// a store that treats non-positive TTLs as unlimited -- so it is refused rather
// than interpreted.
func resolveCeremonyTimeout(milliseconds int) (time.Duration, error) {
	switch {
	case milliseconds < 0:
		return 0, errors.New("timeout must not be negative")
	case milliseconds == 0:
		return defaultCeremonyTimeout, nil
	}

	timeout := time.Duration(milliseconds) * time.Millisecond
	if timeout > maxCeremonyTimeout || timeout < time.Duration(milliseconds) {
		return 0, fmt.Errorf("timeout must not exceed %v", maxCeremonyTimeout)
	}

	return timeout, nil
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
	webUser, _, err := a.credentialSet(ctx, userID)
	if err != nil {
		return nil, "", err
	}

	options, session, err := a.webAuthn.BeginRegistration(webUser)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}

	sessionID := session.Challenge

	if err := a.storeCeremony(ctx, sessionID, userID, session); err != nil {
		return nil, "", err
	}

	return options, sessionID, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// Stores the new credential and returns it.
func (a *Authenticator) FinishRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (*storage.WebAuthnCredential, error) {
	if response == nil {
		// A caller that mishandled the parse error hands us nil, and
		// CreateCredential dereferences it. A library must not turn one handler's
		// slip into a panic that takes every other request in flight with it
		// (CWE-476).
		return nil, ErrRegistrationFailed
	}

	userID, session, err := a.loadCeremony(ctx, sessionID)
	if err != nil {
		return nil, ceremonyError(err, ErrRegistrationFailed)
	}

	webUser, _, err := a.credentialSet(ctx, userID)
	if err != nil {
		return nil, ceremonyError(err, ErrRegistrationFailed)
	}

	credential, err := a.webAuthn.CreateCredential(webUser, *session, response)
	if err != nil {
		return nil, ErrRegistrationFailed
	}

	storageCred := &storage.WebAuthnCredential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		UserID:          userID,
		Transports:      protocolTransportsToStrings(credential.Transport),
		Metadata:        make(map[string]any),
	}
	setCredentialFlags(storageCred, credential.Flags)

	if err := a.credentialStore.StoreWebAuthnCredential(ctx, userID, storageCred); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	return storageCred, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
func (a *Authenticator) BeginLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, string, error) {
	webUser, stored, err := a.credentialSet(ctx, userID)
	if err != nil {
		return nil, "", err
	}

	if len(stored) == 0 {
		return nil, "", ErrCredentialNotFound
	}

	options, session, err := a.webAuthn.BeginLogin(webUser)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin login: %w", err)
	}

	sessionID := session.Challenge

	if err := a.storeCeremony(ctx, sessionID, userID, session); err != nil {
		return nil, "", err
	}

	return options, sessionID, nil
}

// FinishLogin completes the WebAuthn authentication ceremony.
//
// A successful return means more than "the signature verified": the credential
// was resolved inside this user's own credential set, its signature counter
// advanced, and that advance reached the credential store.
func (a *Authenticator) FinishLogin(ctx context.Context, sessionID string, response *protocol.ParsedCredentialAssertionData) (*storage.User, error) {
	if response == nil {
		// See FinishRegistration: nil is a caller mistake, not a panic.
		return nil, ErrAuthenticationFailed
	}

	userID, session, err := a.loadCeremony(ctx, sessionID)
	if err != nil {
		return nil, ceremonyError(err, ErrAuthenticationFailed)
	}

	webUser, stored, err := a.credentialSet(ctx, userID)
	if err != nil {
		return nil, ceremonyError(err, ErrAuthenticationFailed)
	}

	credential, err := a.webAuthn.ValidateLogin(webUser, *session, response)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	if err := a.recordAssertion(ctx, stored, credential, response); err != nil {
		return nil, err
	}

	return webUser.user, nil
}

// recordAssertion applies the checks WebAuthn hands to the relying party once
// the signature itself verifies, then persists what the assertion advanced.
//
// Order is deliberate: nothing is written until every refusal has had its say,
// so a refused assertion cannot move the counter it is being measured against.
func (a *Authenticator) recordAssertion(
	ctx context.Context,
	stored []*storage.WebAuthnCredential,
	credential *webauthn.Credential,
	response *protocol.ParsedCredentialAssertionData,
) error {
	cred := findStoredCredential(stored, credential.ID)
	if cred == nil {
		// go-webauthn resolved this credential out of the very set we handed it,
		// so a miss here means the store answered two questions two different
		// ways. Refuse rather than guess which answer is current.
		return ErrAuthenticationFailed
	}

	if !hasCanonicalSignature(cred.PublicKey, response.Response.Signature) {
		return ErrAuthenticationFailed
	}

	presented := response.Response.AuthenticatorData.Counter

	// CloneWarning is go-webauthn's verdict and isSignCountRollback is ours. They
	// agree today; both are consulted so that a change to either one can only
	// ever refuse more, never less.
	if credential.Authenticator.CloneWarning || isSignCountRollback(cred.SignCount, presented) {
		return ErrCredentialCloned
	}

	if presented == cred.SignCount {
		// Nothing advanced, so there is nothing to persist. This is the
		// counter-less authenticator described on isSignCountRollback: both values
		// are zero and always will be. Writing here would make every one of its
		// sign-ins depend on a store round trip that cannot change a byte.
		return nil
	}

	cred.SignCount = presented
	// The backup state of a passkey changes over its life (it becomes backed up),
	// so the record is refreshed while it is already being written. Backup
	// eligibility cannot change -- an assertion that disagreed with the stored
	// value was refused by ValidateLogin above.
	setCredentialFlags(cred, credential.Flags)

	if err := a.credentialStore.UpdateWebAuthnCredential(ctx, cred); err != nil {
		return fmt.Errorf("%w: %w", ErrSignCountNotPersisted, err)
	}

	return nil
}

// DeleteCredential removes a WebAuthn credential.
func (a *Authenticator) DeleteCredential(ctx context.Context, credentialID []byte) error {
	return a.credentialStore.DeleteWebAuthnCredential(ctx, credentialID)
}

// GetUserCredentials returns all WebAuthn credentials for a user.
func (a *Authenticator) GetUserCredentials(ctx context.Context, userID string) ([]*storage.WebAuthnCredential, error) {
	return a.credentialStore.GetWebAuthnCredentials(ctx, userID)
}

// credentialSet loads a user and their credentials in the shape the go-webauthn
// ceremony functions expect, alongside the stored records the ceremony's own
// bookkeeping needs.
func (a *Authenticator) credentialSet(ctx context.Context, userID string) (*webAuthnUser, []*storage.WebAuthnCredential, error) {
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, ErrUserNotFound
		}

		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}

	stored, err := a.credentialStore.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(stored))
	for _, cred := range stored {
		credentials = append(credentials, a.storageCredToWebAuthn(cred))
	}

	return &webAuthnUser{user: user, credentials: credentials}, stored, nil
}

// storeCeremony persists the challenge half of a ceremony that has just started.
func (a *Authenticator) storeCeremony(ctx context.Context, sessionID, userID string, session *webauthn.SessionData) error {
	sessionData, err := encodeSessionData(session)
	if err != nil {
		return fmt.Errorf("failed to encode session data: %w", err)
	}

	stateData := &storage.OIDCState{
		Provider: stateProvider,
		Metadata: map[string]any{
			stateKeyUserID:  userID,
			stateKeySession: sessionData,
		},
	}

	if err := a.sessionStore.StoreState(ctx, sessionID, stateData, a.ceremonyTimeout); err != nil {
		return fmt.Errorf("failed to store challenge: %w", err)
	}

	return nil
}

// loadCeremony reads back the record a Begin call wrote and returns its two
// halves: whose ceremony this is, and the session the verifier needs.
//
// Every unusable record comes back wrapped in errCeremonyState, which the
// callers turn into their own sentinel. Note what is NOT checked here: the user
// handle in the metadata is not compared against the one in the session blob,
// because go-webauthn already compares the session's UserID against the loaded
// user's WebAuthnID -- and that comparison is the robust one, since both sides
// come from the user record rather than from the lookup key a caller happened to
// use.
func (a *Authenticator) loadCeremony(ctx context.Context, sessionID string) (string, *webauthn.SessionData, error) {
	stateData, err := a.sessionStore.GetState(ctx, sessionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return "", nil, fmt.Errorf("%w: challenge is not live", errCeremonyState)
		}

		return "", nil, fmt.Errorf("failed to get session: %w", err)
	}

	// A store that reports neither data nor error is broken, not permissive.
	if stateData == nil {
		return "", nil, fmt.Errorf("%w: store returned no record", errCeremonyState)
	}

	// The provider tag is what keeps this flow from consuming, or being satisfied
	// by, an OIDC authorization state sharing the same keyspace. Neither value is
	// a secret, so a plain comparison is the honest one; a constant-time compare
	// here would only imply a confidentiality property that does not exist.
	if stateData.Provider != stateProvider {
		return "", nil, fmt.Errorf("%w: record belongs to another flow", errCeremonyState)
	}

	userID, ok := stateData.Metadata[stateKeyUserID].(string)
	if !ok || userID == "" {
		return "", nil, fmt.Errorf("%w: record names no user", errCeremonyState)
	}

	encoded, ok := stateData.Metadata[stateKeySession].(string)
	if !ok {
		return "", nil, fmt.Errorf("%w: record carries no session", errCeremonyState)
	}

	session, err := decodeSessionData(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", errCeremonyState, err)
	}

	// A zero-value SessionData has an empty challenge and an empty user handle,
	// which is exactly the shape that would let anybody through if the verifier
	// ever stopped comparing them. Refuse it here too.
	if session.Challenge == "" || len(session.UserID) == 0 {
		return "", nil, fmt.Errorf("%w: session carries no ceremony", errCeremonyState)
	}

	return userID, session, nil
}

// ceremonyError maps an internal failure onto the sentinel the ceremony
// documents, leaving genuine infrastructure failures wrapped and distinguishable.
//
// A missing user is deliberately answered with the ceremony's own sentinel: it
// is a definite negative, and reporting it as ErrUserNotFound from a callback
// would tell an unauthenticated caller which identifiers exist.
func ceremonyError(err, sentinel error) error {
	if errors.Is(err, errCeremonyState) || errors.Is(err, ErrUserNotFound) {
		return sentinel
	}

	return err
}

// findStoredCredential returns the stored record for a credential ID, or nil.
//
// A credential ID is a public identifier that the browser just sent in the
// clear, so a plain byte comparison is correct here; constant time is for
// secrets, and using it on a lookup key only muddies which values are which.
func findStoredCredential(creds []*storage.WebAuthnCredential, id []byte) *storage.WebAuthnCredential {
	for _, cred := range creds {
		if bytes.Equal(cred.ID, id) {
			return cred
		}
	}

	return nil
}

// isSignCountRollback reports whether a presented signature counter is the clone
// signal of WebAuthn Level 3 §6.1.1.
//
// The rule is "not greater than the stored value", with one exception that is
// not optional. An authenticator is permitted to implement no signature counter
// at all, and one that does not reports 0 on every assertion -- so 0 presented
// against a stored 0 is that authenticator working correctly, not a rollback.
// Zero presented against a stored non-zero is a counter that went backwards,
// which is precisely what a freshly made clone produces.
//
// Getting the exception wrong is not a subtle failure: treating 0-against-0 as a
// rollback locks out every counter-less authenticator forever, and synced
// passkeys are counter-less by construction because a counter cannot be kept
// consistent across the devices they sync to.
func isSignCountRollback(stored, presented uint32) bool {
	if stored == 0 && presented == 0 {
		return false
	}

	return presented <= stored
}

// hasCanonicalSignature reports whether a signature is the single encoding of
// itself that its algorithm allows.
//
// An ES256 signature is a DER SEQUENCE of two INTEGERs, and DER is by definition
// a distinguished encoding: exactly one byte string means a given (r, s). The
// verifier this package sits on decodes it with asn1.Unmarshal and discards the
// unconsumed remainder, so every signature has an unbounded family of accepted
// spellings. That is not a forgery -- an attacker still cannot produce a valid
// (r, s) without the key -- but it destroys the assumption that an assertion has
// a canonical form, which is what a replay cache, an audit record or an
// idempotency key computed over the assertion bytes relies on.
//
// Only elliptic-curve signatures are ASN.1. RSA and Ed25519 signatures are
// fixed-width byte strings whose length the verifier already pins, so there is
// nothing to canonicalize and they are reported as canonical. A public key that
// cannot be parsed is reported as non-canonical: the verifier that just accepted
// this assertion parsed the same key, so failure here means the record moved
// underneath us and the safe answer is to refuse.
//
// The test is re-encoding rather than "did anything remain unparsed", because
// asn1.Unmarshal leaves TWO kinds of remainder and reports only one of them. It
// returns the bytes after the outer SEQUENCE, which the caller can check -- and
// it silently ignores any bytes left over INSIDE the SEQUENCE once it has filled
// the struct's fields, which the caller cannot see at all. Padding a signature
// from within therefore survives a remainder check. Marshaling the parsed value
// back and requiring the original bytes catches both, because DER means exactly
// one encoding per value.
func hasCanonicalSignature(publicKey, signature []byte) bool {
	key, err := webauthncose.ParsePublicKey(publicKey)
	if err != nil {
		return false
	}

	switch key.(type) {
	case webauthncose.EC2PublicKeyData, *webauthncose.EC2PublicKeyData:
	default:
		return true
	}

	var parsed ecdsaSignature

	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 {
		return false
	}

	canonical, err := asn1.Marshal(parsed)
	if err != nil {
		return false
	}

	return bytes.Equal(canonical, signature)
}

// ecdsaSignature is the ASN.1 shape of an ES256/ES384/ES512 signature, the
// ECDSA-Sig-Value of RFC 3279 section 2.2.3.
type ecdsaSignature struct {
	R, S *big.Int
}

// setCredentialFlags records the authenticator flags that must survive to the
// next assertion, without disturbing whatever else the caller keeps in the
// credential's metadata.
func setCredentialFlags(cred *storage.WebAuthnCredential, flags webauthn.CredentialFlags) {
	if cred.Metadata == nil {
		cred.Metadata = make(map[string]any, 2)
	}

	cred.Metadata[metaKeyBackupEligible] = flags.BackupEligible
	cred.Metadata[metaKeyBackupState] = flags.BackupState
}

// credentialFlags reconstructs the flags recorded at registration.
//
// The metadata map comes back from a store the library does not control and may
// have been round-tripped through JSON, so each value is taken only when it
// really is the boolean it claims to be. Anything else -- absent, the wrong
// type, a credential registered before this package recorded flags at all --
// reads as false, which is the conservative direction: a false stored
// backup-eligibility refuses an assertion that claims BE=1, it never admits one.
func credentialFlags(meta map[string]any) webauthn.CredentialFlags {
	return webauthn.CredentialFlags{
		BackupEligible: metadataFlag(meta, metaKeyBackupEligible),
		BackupState:    metadataFlag(meta, metaKeyBackupState),
	}
}

func metadataFlag(meta map[string]any, key string) bool {
	value, ok := meta[key].(bool)

	return ok && value
}

// storageCredToWebAuthn converts a storage credential to webauthn format.
func (a *Authenticator) storageCredToWebAuthn(cred *storage.WebAuthnCredential) webauthn.Credential {
	return webauthn.Credential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       stringsToProtocolTransports(cred.Transports),
		Flags:           credentialFlags(cred.Metadata),
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
	// Use JSON encoding for proper serialization
	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeSessionData(encoded string) (*webauthn.SessionData, error) {
	// Decode base64
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Unmarshal JSON
	session := &webauthn.SessionData{}
	if err := json.Unmarshal(decoded, session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return session, nil
}
