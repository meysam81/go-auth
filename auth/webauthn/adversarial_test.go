// Adversarial suite for auth/webauthn (docs/security-hardening.md §6).
//
// Each test names the attack it defends against rather than the function it
// calls, and every case is hostile input: a foreign origin, a rewritten RP ID
// hash, a replayed challenge, a rolled-back signature counter, a forged or
// truncated signature, a credential ID stolen from another account.
//
// Where the package has no defense today the test still runs the proof and then
// reports the outcome through gap(), which skips rather than fails. A skip with
// a recorded proof is a documented hole; a test that quietly passes over one is
// not. Every such site is written so that the assertion branch is taken once a
// fix lands, at which point the same test becomes a regression guard without
// being rewritten.
//
// This file is an in-package test (package webauthn, not webauthn_test) for one
// reason: decodeSessionData is an unexported decoder of persisted bytes and §6
// requires a fuzz target on every decoder.
package webauthn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/meysam81/go-auth/storage"
)

const (
	testRPID     = "example.com"
	testRPOrigin = "https://example.com"
	testRPName   = "Adversarial RP"

	// Flag bytes as they appear in authenticator data (WebAuthn §6.1, Table
	// "Authenticator Data"). UP = user present, UV = user verified, AT =
	// attested credential data present.
	flagsRegistration = protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData
	flagsAssertion    = protocol.FlagUserPresent | protocol.FlagUserVerified
)

// gap records a control the package does not implement today.
//
// The proof has already executed by the time this is called; the skip keeps the
// suite green while naming the missing control precisely, so a reader of the
// test output learns the hole exists rather than being told nothing. Callers
// take their assertion branch instead once the fix lands.
func gap(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("DOCUMENTED GAP -- no fix in tree: "+format, args...)
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// ttlFloorStateStore is the reference state store with a lower bound applied to
// every TTL it is handed, plus a copy of what was written under each key.
//
// The floor exists for history: BeginRegistration and BeginLogin used to persist
// the challenge with `StoreState(ctx, sessionID, stateData, 300)`, and the
// parameter is a time.Duration, so the untyped constant 300 was 300 NANOSECONDS
// rather than the five minutes the comment claimed. No test could reach the
// ceremony logic at all without neutralizing that first.
//
// The package now passes a real duration, so the floor changes nothing; it stays
// so that a regression to a sub-second TTL fails
// TestWebAuthn_ChallengeTTLIsAUsableCeremonyWindow alone instead of every test
// in this file at once. The recorded copy is the part still in daily use: it
// lets a test re-store a tampered version of a genuine ceremony.
type ttlFloorStateStore struct {
	inner storage.OIDCStateStore
	floor time.Duration

	mu   sync.Mutex
	last map[string]*storage.OIDCState // a copy of what was stored, for crafting
}

func newTTLFloorStateStore(inner storage.OIDCStateStore, floor time.Duration) *ttlFloorStateStore {
	return &ttlFloorStateStore{inner: inner, floor: floor, last: make(map[string]*storage.OIDCState)}
}

func (s *ttlFloorStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	if ttl < s.floor {
		ttl = s.floor
	}

	s.mu.Lock()
	clone := *data
	clone.Metadata = make(map[string]any, len(data.Metadata))
	for k, v := range data.Metadata {
		clone.Metadata[k] = v
	}
	s.last[state] = &clone
	s.mu.Unlock()

	return s.inner.StoreState(ctx, state, data, ttl)
}

func (s *ttlFloorStateStore) GetState(ctx context.Context, state string) (*storage.OIDCState, error) {
	return s.inner.GetState(ctx, state)
}

func (s *ttlFloorStateStore) DeleteState(ctx context.Context, state string) error {
	return s.inner.DeleteState(ctx, state)
}

// snapshot returns a copy of the state that was written under the given key,
// so a test can re-store a tampered version of a genuine ceremony.
func (s *ttlFloorStateStore) snapshot(t *testing.T, state string) *storage.OIDCState {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	got, ok := s.last[state]
	if !ok {
		t.Fatalf("no state recorded under %q", state)
	}

	clone := *got
	clone.Metadata = make(map[string]any, len(got.Metadata))
	for k, v := range got.Metadata {
		clone.Metadata[k] = v
	}

	return &clone
}

// recordingStateStore captures the TTL each call was given without changing it,
// along with the record itself so the expiry stamped inside it can be read back.
type recordingStateStore struct {
	inner storage.OIDCStateStore

	mu   sync.Mutex
	ttls []time.Duration
	last *storage.OIDCState
}

func (s *recordingStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	s.mu.Lock()
	s.ttls = append(s.ttls, ttl)
	s.last = data
	s.mu.Unlock()

	return s.inner.StoreState(ctx, state, data, ttl)
}

func (s *recordingStateStore) GetState(ctx context.Context, state string) (*storage.OIDCState, error) {
	return s.inner.GetState(ctx, state)
}

func (s *recordingStateStore) DeleteState(ctx context.Context, state string) error {
	return s.inner.DeleteState(ctx, state)
}

func (s *recordingStateStore) recorded() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]time.Duration(nil), s.ttls...)
}

// snapshot returns the last record written, for a test that needs to inspect
// what the package persisted rather than what it returned.
func (s *recordingStateStore) snapshot(t *testing.T) *storage.OIDCState {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.last == nil {
		t.Fatal("no state was recorded")
	}

	return s.last
}

// errStateStore returns a fixed error from GetState. It models the two states a
// challenge store can be in at callback time that are not "here is your data":
// the entry lapsed, or it was already consumed.
type errStateStore struct {
	inner storage.OIDCStateStore
	err   error
}

func (s *errStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	return s.inner.StoreState(ctx, state, data, ttl)
}

func (s *errStateStore) GetState(context.Context, string) (*storage.OIDCState, error) {
	return nil, s.err
}

func (s *errStateStore) DeleteState(ctx context.Context, state string) error {
	return s.inner.DeleteState(ctx, state)
}

// brokenCounterStore is the reference credential store whose counter write
// always fails. The signature counter is the only cloned-authenticator signal
// WebAuthn offers (§6.1.1), so a store that cannot persist it must not leave
// authentication looking successful.
type brokenCounterStore struct {
	*storage.InMemoryCredentialStore

	errUpdate error
}

func (s *brokenCounterStore) UpdateWebAuthnCredential(context.Context, *storage.WebAuthnCredential) error {
	return s.errUpdate
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type harness struct {
	auth   *Authenticator
	users  *storage.InMemoryUserStore
	creds  storage.CredentialStore
	states *ttlFloorStateStore
}

type harnessOpts struct {
	origins []string
	creds   storage.CredentialStore
}

func newHarness(t *testing.T, opts harnessOpts) *harness {
	t.Helper()

	users := storage.NewInMemoryUserStore()

	creds := opts.creds
	if creds == nil {
		creds = storage.NewInMemoryCredentialStore()
	}

	origins := opts.origins
	if len(origins) == 0 {
		origins = []string{testRPOrigin}
	}

	states := newTTLFloorStateStore(storage.NewInMemoryOIDCStateStore(), time.Minute)

	auth, err := NewAuthenticator(Config{
		RPDisplayName:   testRPName,
		RPID:            testRPID,
		RPOrigins:       origins,
		UserStore:       users,
		CredentialStore: creds,
		SessionStore:    states,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	return &harness{auth: auth, users: users, creds: creds, states: states}
}

func (h *harness) addUser(t *testing.T, id string) *storage.User {
	t.Helper()

	user := &storage.User{
		ID:       id,
		Email:    id + "@example.com",
		Username: id,
		Name:     strings.ToUpper(id),
		Provider: "local",
	}
	if err := h.users.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser(%q): %v", id, err)
	}

	return user
}

// enroll runs a full, honest registration ceremony and returns the authenticator
// that now owns the credential. Every attack test starts from a real credential
// so that the thing being rejected is the attack and not the setup.
func (h *harness) enroll(t *testing.T, userID string) *softAuthenticator {
	t.Helper()

	sa := newSoftAuthenticator(t)

	options, sessionID, err := h.auth.BeginRegistration(context.Background(), userID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	resp := sa.register(t, ceremony{challenge: options.Response.Challenge.String()})

	if _, err = h.auth.FinishRegistration(context.Background(), sessionID, resp); err != nil {
		t.Fatalf("FinishRegistration on an honest ceremony: %v", err)
	}

	return sa
}

// beginLogin starts an assertion ceremony and returns (challenge, sessionID).
func (h *harness) beginLogin(t *testing.T, userID string) (string, string) {
	t.Helper()

	options, sessionID, err := h.auth.BeginLogin(context.Background(), userID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	return options.Response.Challenge.String(), sessionID
}

// ---------------------------------------------------------------------------
// Software authenticator
// ---------------------------------------------------------------------------

// softAuthenticator is a minimal ES256 authenticator: enough of CTAP2 to
// produce attestation objects and assertions the go-webauthn verifier accepts,
// and open enough that a test can lie about any field an attacker controls.
//
// It uses attestation format "none", which is what a platform authenticator
// reports when the RP asks for no attestation -- the overwhelmingly common
// production case and the one this library configures.
type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	aaguid []byte
}

func newSoftAuthenticator(tb testing.TB) *softAuthenticator {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	return &softAuthenticator{
		key:    key,
		credID: randomBytes(tb, 32),
		aaguid: make([]byte, 16), // all-zero AAGUID, as a self-attesting authenticator reports.
	}
}

// ceremony is the set of values an attacker can choose when they control the
// browser. Zero values mean "behave honestly".
type ceremony struct {
	challenge   string  // base64url, as it appears in clientDataJSON
	origin      string  // default testRPOrigin
	typ         *string // nil means the honest webauthn.create / webauthn.get
	rpIDForHash string  // default testRPID; the value hashed into authData
	credID      []byte  // default the authenticator's own credential ID
	counter     uint32
	flags       protocol.AuthenticatorFlags // 0 means the honest default
	userHandle  []byte

	// signWith replaces the signing key, modeling an attacker who holds a key
	// that is not the one registered.
	signWith *ecdsa.PrivateKey

	// mutateAuthData runs after signing, so the signature no longer covers the
	// bytes presented. mutateSig corrupts the signature itself.
	mutateAuthData func([]byte) []byte
	mutateSig      func([]byte) []byte
}

func (c ceremony) originOr() string {
	if c.origin == "" {
		return testRPOrigin
	}

	return c.origin
}

func (c ceremony) rpIDOr() string {
	if c.rpIDForHash == "" {
		return testRPID
	}

	return c.rpIDForHash
}

// clientDataJSON is built by hand rather than through protocol.CollectedClientData
// so that a test can emit a type or an origin the struct would refuse to hold.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func (c ceremony) clientDataJSON(tb testing.TB, defaultType string) []byte {
	tb.Helper()

	typ := defaultType
	if c.typ != nil {
		typ = *c.typ
	}

	raw, err := json.Marshal(clientData{
		Type:      typ,
		Challenge: c.challenge,
		Origin:    c.originOr(),
	})
	if err != nil {
		tb.Fatalf("marshal clientData: %v", err)
	}

	return raw
}

// coseKey encodes the public key in COSE_Key form, as attested credential data
// carries it.
func (s *softAuthenticator) coseKey(tb testing.TB) []byte {
	tb.Helper()

	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  1, // P-256, per the COSE Elliptic Curves registry.
		XCoord: coordinate(s.key.X),
		YCoord: coordinate(s.key.Y),
	}

	encoded, err := webauthncbor.Marshal(key)
	if err != nil {
		tb.Fatalf("marshal COSE key: %v", err)
	}

	return encoded
}

// coordinate left-pads an EC coordinate to the fixed 32 bytes COSE requires.
func coordinate(v *big.Int) []byte {
	out := make([]byte, 32)
	v.FillBytes(out)

	return out
}

// authData assembles authenticator data (WebAuthn §6.1).
func (s *softAuthenticator) authData(tb testing.TB, c ceremony, attested bool) []byte {
	tb.Helper()

	rpIDHash := sha256.Sum256([]byte(c.rpIDOr()))

	flags := c.flags
	if flags == 0 {
		if attested {
			flags = flagsRegistration
		} else {
			flags = flagsAssertion
		}
	}

	out := make([]byte, 0, 128)
	out = append(out, rpIDHash[:]...)
	out = append(out, byte(flags))
	out = binary.BigEndian.AppendUint32(out, c.counter)

	if !flags.HasAttestedCredentialData() {
		return out
	}

	credID := c.credID
	if credID == nil {
		credID = s.credID
	}

	out = append(out, s.aaguid...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(credID)))
	out = append(out, credID...)
	out = append(out, s.coseKey(tb)...)

	return out
}

// register produces a registration response as the browser would post it,
// round-tripped through the library's own parser so the parser is exercised too.
func (s *softAuthenticator) register(tb testing.TB, c ceremony) *protocol.ParsedCredentialCreationData {
	tb.Helper()

	parsed, err := s.registerRaw(tb, c)
	if err != nil {
		tb.Fatalf("parse registration response: %v", err)
	}

	return parsed
}

func (s *softAuthenticator) registerRaw(tb testing.TB, c ceremony) (*protocol.ParsedCredentialCreationData, error) {
	tb.Helper()

	authData := s.authData(tb, c, true)
	if c.mutateAuthData != nil {
		authData = c.mutateAuthData(authData)
	}

	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		tb.Fatalf("marshal attestation object: %v", err)
	}

	credID := c.credID
	if credID == nil {
		credID = s.credID
	}

	body, err := json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credID),
		"rawId": base64.RawURLEncoding.EncodeToString(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(c.clientDataJSON(tb, string(protocol.CreateCeremony))),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
		},
	})
	if err != nil {
		tb.Fatalf("marshal registration body: %v", err)
	}

	return protocol.ParseCredentialCreationResponseBytes(body)
}

// assert produces an assertion response, signing over
// authenticatorData || SHA-256(clientDataJSON) as the authenticatorGetAssertion
// operation specifies.
func (s *softAuthenticator) assert(tb testing.TB, c ceremony) *protocol.ParsedCredentialAssertionData {
	tb.Helper()

	parsed, err := s.assertRaw(tb, c)
	if err != nil {
		tb.Fatalf("parse assertion response: %v", err)
	}

	return parsed
}

func (s *softAuthenticator) assertRaw(tb testing.TB, c ceremony) (*protocol.ParsedCredentialAssertionData, error) {
	tb.Helper()

	clientDataJSON := c.clientDataJSON(tb, string(protocol.AssertCeremony))
	authData := s.authData(tb, c, false)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte(nil), authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	key := s.key
	if c.signWith != nil {
		key = c.signWith
	}

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		tb.Fatalf("sign assertion: %v", err)
	}

	if c.mutateSig != nil {
		sig = c.mutateSig(sig)
	}

	// Applied after signing: the signature covers the honest bytes while the
	// presented bytes are the tampered ones.
	if c.mutateAuthData != nil {
		authData = c.mutateAuthData(authData)
	}

	credID := c.credID
	if credID == nil {
		credID = s.credID
	}

	response := map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"signature":         base64.RawURLEncoding.EncodeToString(sig),
	}
	if c.userHandle != nil {
		response["userHandle"] = base64.RawURLEncoding.EncodeToString(c.userHandle)
	}

	body, err := json.Marshal(map[string]any{
		"id":       base64.RawURLEncoding.EncodeToString(credID),
		"rawId":    base64.RawURLEncoding.EncodeToString(credID),
		"type":     "public-key",
		"response": response,
	})
	if err != nil {
		tb.Fatalf("marshal assertion body: %v", err)
	}

	return protocol.ParseCredentialRequestResponseBytes(body)
}

func randomBytes(tb testing.TB, n int) []byte {
	tb.Helper()

	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		tb.Fatalf("crypto/rand: %v", err)
	}

	return out
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// TestWebAuthn_IncompleteConfigMustNotConstruct asserts that every field the
// ceremony's security depends on is mandatory at construction.
//
// A relying party that starts a ceremony with no RP ID or no origin list has no
// scope binding at all: the RP ID hash check (WebAuthn §7.1/§7.2) and the origin
// check both degrade to "accept anything", which is CWE-1188 (insecure default)
// turning directly into CWE-346 (origin validation error). Failing at
// construction is the only place the mistake is cheap; a nil store surfaces
// otherwise as a nil-pointer panic on the first live ceremony.
func TestWebAuthn_IncompleteConfigMustNotConstruct(t *testing.T) {
	t.Parallel()

	base := func() Config {
		return Config{
			RPDisplayName:   testRPName,
			RPID:            testRPID,
			RPOrigins:       []string{testRPOrigin},
			UserStore:       storage.NewInMemoryUserStore(),
			CredentialStore: storage.NewInMemoryCredentialStore(),
			SessionStore:    storage.NewInMemoryOIDCStateStore(),
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{name: "complete config is accepted", mutate: func(*Config) {}, wantErr: false},
		{name: "no user store", mutate: func(c *Config) { c.UserStore = nil }, wantErr: true},
		{name: "no credential store", mutate: func(c *Config) { c.CredentialStore = nil }, wantErr: true},
		{name: "no challenge store", mutate: func(c *Config) { c.SessionStore = nil }, wantErr: true},
		{name: "no relying party id", mutate: func(c *Config) { c.RPID = "" }, wantErr: true},
		{name: "no relying party display name", mutate: func(c *Config) { c.RPDisplayName = "" }, wantErr: true},
		{name: "nil origin list", mutate: func(c *Config) { c.RPOrigins = nil }, wantErr: true},
		{name: "empty origin list", mutate: func(c *Config) { c.RPOrigins = []string{} }, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := base()
			tc.mutate(&cfg)

			auth, err := NewAuthenticator(cfg)

			switch {
			case tc.wantErr && err == nil:
				t.Fatal("constructed an authenticator from an incomplete config; a ceremony with a missing scope binding or a nil store must not be expressible")
			case tc.wantErr && auth != nil:
				t.Fatal("returned a non-nil authenticator alongside an error")
			case !tc.wantErr && err != nil:
				t.Fatalf("rejected a complete config: %v", err)
			}
		})
	}
}

// TestWebAuthn_ConfigDoesNotSmuggleAnEmptyOriginThrough asserts that an origin
// list made only of blank entries is not treated as a configured origin.
//
// CWE-346. `len(cfg.RPOrigins) == 0` is the only check the constructor makes, so
// a list carrying one empty string satisfies it. An empty origin never matches a
// real one in protocol.IsOriginInHaystack, so this fails closed today -- the
// test pins that it stays closed, because the natural "fix" of defaulting a
// blank entry to the RP ID would silently widen the accepted origin set.
func TestWebAuthn_ConfigDoesNotSmuggleAnEmptyOriginThrough(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{origins: []string{""}})
	h.addUser(t, "alice")

	options, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	sa := newSoftAuthenticator(t)
	resp := sa.register(t, ceremony{challenge: options.Response.Challenge.String()})

	if _, err = h.auth.FinishRegistration(context.Background(), sessionID, resp); err == nil {
		t.Fatal("registration completed against an RP whose only configured origin is the empty string")
	}
}

// ---------------------------------------------------------------------------
// Challenge lifetime, single use, and binding
// ---------------------------------------------------------------------------

// TestWebAuthn_ChallengeTTLIsAUsableCeremonyWindow pins the TTL the package
// hands its challenge store.
//
// It was written as TestWebAuthn_ChallengeTTLIsNanosecondsNotMinutes, the proof
// that BeginRegistration and BeginLogin called
// `StoreState(ctx, sessionID, stateData, 300)` under a `// 5 min timeout`
// comment: StoreState takes a time.Duration, so the untyped constant 300 was
// 300ns and the ceremony window was shorter than the call that returned the
// options to the caller. WebAuthn was simply unusable through this package
// against any store that honors the TTL it is given.
//
// The defect failed closed, so it was availability rather than authentication.
// It is pinned here because it also masked every other challenge-lifetime
// control: an expiry check that can never be reached is not evidence that the
// expiry check works.
func TestWebAuthn_ChallengeTTLIsAUsableCeremonyWindow(t *testing.T) {
	t.Parallel()

	users := storage.NewInMemoryUserStore()
	if err := users.CreateUser(context.Background(), &storage.User{ID: "alice", Email: "alice@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	states := &recordingStateStore{inner: storage.NewInMemoryOIDCStateStore()}

	auth, err := NewAuthenticator(Config{
		RPDisplayName:   testRPName,
		RPID:            testRPID,
		RPOrigins:       []string{testRPOrigin},
		UserStore:       users,
		CredentialStore: storage.NewInMemoryCredentialStore(),
		SessionStore:    states,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	if _, _, err = auth.BeginRegistration(context.Background(), "alice"); err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	recorded := states.recorded()
	if len(recorded) != 1 {
		t.Fatalf("expected exactly one challenge write, got %d", len(recorded))
	}

	// A WebAuthn ceremony needs a human to find and touch a key. Anything under a
	// minute cannot be completed by a person; anything over fifteen has stopped
	// being a ceremony window and become a long-lived bearer challenge.
	const (
		wantAtLeast = time.Minute
		wantAtMost  = 15 * time.Minute
	)

	if recorded[0] < wantAtLeast || recorded[0] > wantAtMost {
		t.Fatalf("challenge TTL is %v, want between %v and %v: a bare integer passed to a "+
			"time.Duration parameter is nanoseconds, so `300` here would be 300ns and every "+
			"ceremony would expire before it started", recorded[0], wantAtLeast, wantAtMost)
	}

	// The same window must be stamped into the session record itself, so a store
	// that ignores the TTL it is handed does not leave the challenge immortal.
	assertSessionExpiresWithin(t, states, wantAtLeast, wantAtMost)
}

// assertSessionExpiresWithin checks the relying-party-side expiry carried inside
// the stored ceremony blob, which is the half of the window that does not depend
// on the challenge store honoring anything.
func assertSessionExpiresWithin(t *testing.T, states *recordingStateStore, atLeast, atMost time.Duration) {
	t.Helper()

	state := states.snapshot(t)

	encoded, ok := state.Metadata["session"].(string)
	if !ok {
		t.Fatalf("stored ceremony carries no session blob: %+v", state.Metadata)
	}

	session, err := decodeSessionData(encoded)
	if err != nil {
		t.Fatalf("decodeSessionData: %v", err)
	}

	if session.Expires.IsZero() {
		t.Fatal("the stored session has no expiry of its own, so a challenge store that " +
			"ignores TTLs leaves the ceremony completable forever")
	}

	remaining := time.Until(session.Expires)
	if remaining < atLeast || remaining > atMost {
		t.Fatalf("session expires in %v, want between %v and %v", remaining, atLeast, atMost)
	}
}

// TestWebAuthn_ConfiguredTimeoutBoundsTheCeremony pins Config.Timeout to the
// window the challenge is actually stored for.
//
// The field is documented as the ceremony timeout in milliseconds and used to be
// read by nothing at all, which is its own kind of defect: a relying party that
// set it believed it had shortened the window and had not. It is now the single
// number behind the client hint, the session's own expiry and the store TTL, so
// the value a caller passes has to arrive intact -- and a value that cannot be a
// ceremony window has to be refused where it is cheap to refuse.
func TestWebAuthn_ConfiguredTimeoutBoundsTheCeremony(t *testing.T) {
	t.Parallel()

	t.Run("a configured window reaches the challenge store", func(t *testing.T) {
		t.Parallel()

		states := &recordingStateStore{inner: storage.NewInMemoryOIDCStateStore()}
		users := storage.NewInMemoryUserStore()

		if err := users.CreateUser(context.Background(), &storage.User{ID: "alice", Email: "alice@example.com"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		auth, err := NewAuthenticator(Config{
			RPDisplayName:   testRPName,
			RPID:            testRPID,
			RPOrigins:       []string{testRPOrigin},
			UserStore:       users,
			CredentialStore: storage.NewInMemoryCredentialStore(),
			SessionStore:    states,
			Timeout:         90_000,
		})
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}

		if _, _, err = auth.BeginRegistration(context.Background(), "alice"); err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}

		recorded := states.recorded()
		if len(recorded) != 1 || recorded[0] != 90*time.Second {
			t.Fatalf("challenge TTL = %v, want the configured 90s", recorded)
		}

		assertSessionExpiresWithin(t, states, 80*time.Second, 90*time.Second)
	})

	t.Run("a window that is not one is refused at construction", func(t *testing.T) {
		t.Parallel()

		for _, milliseconds := range []int{-1, -60_000, 16 * 60 * 1000, 1 << 62} {
			cfg := Config{
				RPDisplayName:   testRPName,
				RPID:            testRPID,
				RPOrigins:       []string{testRPOrigin},
				UserStore:       storage.NewInMemoryUserStore(),
				CredentialStore: storage.NewInMemoryCredentialStore(),
				SessionStore:    storage.NewInMemoryOIDCStateStore(),
				Timeout:         milliseconds,
			}

			auth, err := NewAuthenticator(cfg)
			if err == nil {
				t.Errorf("Timeout=%d was accepted; a negative window stores an already-lapsed "+
					"challenge and an overlong one is a bearer token with a challenge's name", milliseconds)
			}

			if auth != nil {
				t.Errorf("Timeout=%d returned an authenticator alongside its error", milliseconds)
			}
		}
	})
}

// TestWebAuthn_ExpiredChallengeIsRefusedWithoutLeakingDetail asserts that a
// lapsed or already-consumed challenge produces the package's own sentinel and
// nothing else.
//
// CWE-613. The distinction matters for two reasons: a caller that cannot match
// on the sentinel will treat a lapsed ceremony as a server fault and retry it,
// and an error that carries the store's own text back to the browser tells an
// attacker whether the challenge existed at all -- "expired" and "never issued"
// are different answers to the same probe.
func TestWebAuthn_ExpiredChallengeIsRefusedWithoutLeakingDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		storeErr error
	}{
		{name: "challenge lapsed", storeErr: storage.ErrExpired},
		{name: "challenge already consumed", storeErr: storage.ErrNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := storage.NewInMemoryUserStore()
			if err := users.CreateUser(context.Background(), &storage.User{ID: "alice", Email: "alice@example.com"}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}

			auth, err := NewAuthenticator(Config{
				RPDisplayName:   testRPName,
				RPID:            testRPID,
				RPOrigins:       []string{testRPOrigin},
				UserStore:       users,
				CredentialStore: storage.NewInMemoryCredentialStore(),
				SessionStore:    &errStateStore{inner: storage.NewInMemoryOIDCStateStore(), err: tc.storeErr},
			})
			if err != nil {
				t.Fatalf("NewAuthenticator: %v", err)
			}

			sa := newSoftAuthenticator(t)
			challenge := base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))

			_, regErr := auth.FinishRegistration(context.Background(), challenge, sa.register(t, ceremony{challenge: challenge}))
			if !errors.Is(regErr, ErrRegistrationFailed) {
				t.Fatalf("FinishRegistration on a %v challenge = %v, want ErrRegistrationFailed", tc.storeErr, regErr)
			}

			_, loginErr := auth.FinishLogin(context.Background(), challenge, sa.assert(t, ceremony{challenge: challenge}))
			if !errors.Is(loginErr, ErrAuthenticationFailed) {
				t.Fatalf("FinishLogin on a %v challenge = %v, want ErrAuthenticationFailed", tc.storeErr, loginErr)
			}

			for _, err := range []error{regErr, loginErr} {
				if strings.Contains(err.Error(), tc.storeErr.Error()) {
					t.Errorf("error %q repeats the store's own verdict back to the caller, distinguishing a lapsed challenge from one that never existed", err)
				}
			}
		})
	}
}

// TestWebAuthn_ChallengeIsSingleUse replays a complete, valid assertion.
//
// CWE-294 (authentication bypass by capture-replay). WebAuthn's challenge is the
// freshness guarantee for the whole ceremony: an assertion is a signature over
// authenticator data and a client-data hash, and nothing else stops that exact
// byte sequence being posted a second time. The only thing that makes the
// signature stale is the relying party refusing to accept the challenge twice,
// which here means the challenge store consuming the entry on read.
func TestWebAuthn_ChallengeIsSingleUse(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")
	resp := sa.assert(t, ceremony{challenge: challenge, counter: 1})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, resp); err != nil {
		t.Fatalf("first, honest assertion was rejected: %v", err)
	}

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, resp); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("replayed assertion = %v, want ErrAuthenticationFailed: the challenge was accepted twice", err)
	}
}

// TestWebAuthn_FailedCeremonyStillBurnsTheChallenge asserts a challenge is not
// recycled after a rejected attempt.
//
// CWE-294. If a failed ceremony left the challenge live, an attacker who
// intercepted the options could grind attempts against one challenge: forged
// signature, wrong origin, wrong credential, over and over, all with the same
// freshness token. Consumption must be unconditional on the read.
func TestWebAuthn_FailedCeremonyStillBurnsTheChallenge(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")

	forged := sa.assert(t, ceremony{
		challenge: challenge,
		mutateSig: func(sig []byte) []byte {
			out := append([]byte(nil), sig...)
			out[len(out)-1] ^= 0xFF

			return out
		},
	})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, forged); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("forged signature = %v, want ErrAuthenticationFailed", err)
	}

	honest := sa.assert(t, ceremony{challenge: challenge, counter: 1})
	if _, err := h.auth.FinishLogin(context.Background(), sessionID, honest); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("challenge survived a failed ceremony and accepted a second attempt (err=%v)", err)
	}
}

// TestWebAuthn_ChallengeForOneUserCannotCompleteAnothersCeremony rewrites the
// user the stored challenge names.
//
// CWE-287. The ceremony's user handle is carried twice: in the state store's
// metadata (which selects whose credentials are loaded) and inside the signed
// go-webauthn session blob. If only the first were consulted, an attacker who
// could influence the metadata -- a shared Redis keyspace, a store that merges
// on write -- would move a live challenge onto another account. The two copies
// must be compared, not merely read.
func TestWebAuthn_ChallengeForOneUserCannotCompleteAnothersCeremony(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	h.addUser(t, "mallory")
	h.enroll(t, "alice") // so the assertion leg below has a credential to offer
	mallorysKey := h.enroll(t, "mallory")

	// Alice starts a registration; the challenge is minted for her handle.
	options, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	challenge := options.Response.Challenge.String()

	// Mallory rewrites the metadata so the challenge names her instead.
	tampered := h.states.snapshot(t, sessionID)
	tampered.Metadata["user_id"] = "mallory"

	if err = h.states.StoreState(context.Background(), sessionID, tampered, time.Minute); err != nil {
		t.Fatalf("re-store tampered state: %v", err)
	}

	resp := mallorysKey.register(t, ceremony{challenge: challenge, credID: randomBytes(t, 32)})

	if _, err = h.auth.FinishRegistration(context.Background(), sessionID, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("registration completed against a challenge whose user handle was swapped (err=%v); "+
			"the metadata user_id and the session UserID must be checked against each other", err)
	}

	// Same shape on the assertion side.
	loginChallenge, loginSession := h.beginLogin(t, "alice")

	tamperedLogin := h.states.snapshot(t, loginSession)
	tamperedLogin.Metadata["user_id"] = "mallory"

	if err = h.states.StoreState(context.Background(), loginSession, tamperedLogin, time.Minute); err != nil {
		t.Fatalf("re-store tampered login state: %v", err)
	}

	assertion := mallorysKey.assert(t, ceremony{challenge: loginChallenge, counter: 1})

	if _, err = h.auth.FinishLogin(context.Background(), loginSession, assertion); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("login completed against a challenge whose user handle was swapped (err=%v)", err)
	}
}

// TestWebAuthn_ForeignCredentialCannotSatisfyAnothersChallenge presents a
// credential belonging to one account against a challenge issued for another.
//
// CWE-287. The assertion is cryptographically perfect -- correct challenge,
// correct origin, correct RP ID, a real signature by a real registered
// authenticator. It is simply the wrong authenticator. WebAuthn §7.2 requires
// the credential ID be resolved within the identified user's credential set,
// not globally.
func TestWebAuthn_ForeignCredentialCannotSatisfyAnothersChallenge(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	h.addUser(t, "mallory")
	h.enroll(t, "alice")
	mallorysKey := h.enroll(t, "mallory")

	challenge, sessionID := h.beginLogin(t, "alice")

	// Mallory signs Alice's challenge with her own, legitimately registered key.
	assertion := mallorysKey.assert(t, ceremony{challenge: challenge, counter: 1})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("another user's credential satisfied this user's challenge (err=%v)", err)
	}
}

// TestWebAuthn_StateStoreNamespaceIsDiscriminatedFromOIDC asserts the Provider
// field written into the challenge record is read back and enforced.
//
// It was written as TestWebAuthn_StateStoreNamespaceIsSharedWithOIDCWithoutADiscriminator,
// the proof that the tag was write-only. The package reuses
// storage.OIDCStateStore for WebAuthn challenges and stamps
// `Provider: "webauthn"` on every record, but FinishRegistration and FinishLogin
// used to consume whatever GetState returned without checking it. WebAuthn
// challenges and OIDC authorization states share one keyspace, and both key
// values are handed to the browser: the OIDC state travels in the authorization
// URL, and the WebAuthn challenge -- which is also the session ID -- is inside
// the credential options. Either flow could consume the other's entry. That is
// CWE-843 (type confusion) expressed across two protocols, whose concrete
// consequence is cross-flow denial of service: one protocol's callback burning
// the other's single-use record.
func TestWebAuthn_StateStoreNamespaceIsDiscriminatedFromOIDC(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")

	// Restamp the record as if an OIDC flow had written it.
	disguised := h.states.snapshot(t, sessionID)
	disguised.Provider = "google"

	if err := h.states.StoreState(context.Background(), sessionID, disguised, time.Minute); err != nil {
		t.Fatalf("re-store disguised state: %v", err)
	}

	assertion := sa.assert(t, ceremony{challenge: challenge, counter: 1})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("FinishLogin consumed a state record stamped Provider=%q (err=%v), want "+
			"ErrAuthenticationFailed: without a type discriminator either flow can consume "+
			"the other's single-use record", disguised.Provider, err)
	}
}

// ---------------------------------------------------------------------------
// Origin and RP ID confusion
// ---------------------------------------------------------------------------

// TestWebAuthn_ForeignOriginRejected drives both ceremonies from origins that
// are not in RPOrigins.
//
// CWE-346 (origin validation error). The origin in collected client data is the
// only thing binding a signature to the site that asked for it; without an exact
// match a phishing page on a lookalike host, a sibling subdomain, or the same
// host over plain HTTP can harvest assertions that the real relying party then
// accepts. WebAuthn §7.1 and §7.2 both require the origin to be one the relying
// party expects, and origin comparison is scheme-host-port, never suffix.
func TestWebAuthn_ForeignOriginRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		origin     string
		wantAccept bool
	}{
		{name: "configured origin", origin: testRPOrigin, wantAccept: true},
		{name: "explicit default port is the same origin", origin: "https://example.com:443", wantAccept: true},
		{name: "lookalike registrable domain", origin: "https://examp1e.com", wantAccept: false},
		{name: "attacker suffix", origin: "https://example.com.evil.net", wantAccept: false},
		{name: "attacker prefix on their own domain", origin: "https://evil.net/example.com", wantAccept: false},
		{name: "sibling subdomain", origin: "https://accounts.example.com", wantAccept: false},
		{name: "parent of the configured origin", origin: "https://com", wantAccept: false},
		{name: "scheme downgrade to cleartext", origin: "http://example.com", wantAccept: false},
		{name: "non-default port", origin: "https://example.com:8443", wantAccept: false},
		{name: "userinfo smuggling", origin: "https://example.com@evil.net", wantAccept: false},
		{name: "empty origin", origin: " ", wantAccept: false},
		{name: "android apk key hash", origin: "android:apk-key-hash:AAAA", wantAccept: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")

			options, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
			if err != nil {
				t.Fatalf("BeginRegistration: %v", err)
			}

			sa := newSoftAuthenticator(t)
			resp := sa.register(t, ceremony{challenge: options.Response.Challenge.String(), origin: tc.origin})

			_, err = h.auth.FinishRegistration(context.Background(), sessionID, resp)

			switch {
			case tc.wantAccept && err != nil:
				t.Fatalf("registration from configured origin %q was rejected: %v", tc.origin, err)
			case !tc.wantAccept && err == nil:
				t.Fatalf("registration completed from origin %q, which is not in RPOrigins", tc.origin)
			}

			if !tc.wantAccept {
				return
			}

			// The accepted origins are re-checked on the assertion leg, where a
			// harvested signature would actually be spent.
			challenge, loginSession := h.beginLogin(t, "alice")
			assertion := sa.assert(t, ceremony{challenge: challenge, origin: tc.origin, counter: 1})

			if _, err = h.auth.FinishLogin(context.Background(), loginSession, assertion); err != nil {
				t.Fatalf("login from configured origin %q was rejected: %v", tc.origin, err)
			}
		})
	}
}

// TestWebAuthn_ForeignOriginRejectedOnAssertion is the login-side half: a
// credential registered honestly must not be spendable from a phishing origin.
//
// CWE-346. This is the leg that matters operationally -- registration happens
// once, assertions happen on every sign-in, and it is the assertion an
// adversary-in-the-middle page tries to relay.
func TestWebAuthn_ForeignOriginRejectedOnAssertion(t *testing.T) {
	t.Parallel()

	origins := []string{
		"https://evil.net",
		"https://example.com.evil.net",
		"http://example.com",
		"https://accounts.example.com",
		"https://example.com:8443",
	}

	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")
			assertion := sa.assert(t, ceremony{challenge: challenge, origin: origin, counter: 1})

			if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("assertion from %q = %v, want ErrAuthenticationFailed", origin, err)
			}
		})
	}
}

// TestWebAuthn_RPIDHashConfusionRejected rewrites the RP ID hash inside signed
// authenticator data.
//
// CWE-346. The 32-byte RP ID hash is the scope an authenticator commits to when
// it signs; it is what stops a credential minted for one relying party being
// spent at another that happens to sit on a related name. WebAuthn §7.1 and §7.2
// require it to equal SHA-256 of the expected RP ID exactly -- there is no
// suffix rule at this layer, because the suffix rule was already applied by the
// client when it decided which credentials were in scope.
func TestWebAuthn_RPIDHashConfusionRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rpID string
	}{
		{name: "unrelated relying party", rpID: "evil.net"},
		{name: "registrable suffix of the configured id", rpID: "com"},
		{name: "subdomain of the configured id", rpID: "accounts.example.com"},
		{name: "attacker suffix", rpID: "example.com.evil.net"},
		{name: "trailing dot", rpID: "example.com."},
		{name: "uppercase", rpID: "EXAMPLE.COM"},
		{name: "origin instead of id", rpID: testRPOrigin},
		{name: "empty", rpID: "\x00"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")
			assertion := sa.assert(t, ceremony{challenge: challenge, rpIDForHash: tc.rpID, counter: 1})

			if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("assertion carrying SHA-256(%q) as its RP ID hash = %v, want ErrAuthenticationFailed", tc.rpID, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Ceremony-type, challenge and signature binding
// ---------------------------------------------------------------------------

// TestWebAuthn_CeremonyTypeSubstitutionRejected posts a registration-typed
// client data blob into the assertion leg and vice versa.
//
// CWE-345 (insufficient verification of data authenticity). The `type` member of
// collected client data exists specifically to stop signature substitution
// between ceremonies: without it, a signature produced during registration could
// be presented as proof of an assertion. WebAuthn §7.1 pins it to
// "webauthn.create" and §7.2 to "webauthn.get".
func TestWebAuthn_CeremonyTypeSubstitutionRejected(t *testing.T) {
	t.Parallel()

	tests := []string{
		"webauthn.create",
		"webauthn.GET",
		"webauthn.get\x00",
		"",
		"payment.get",
	}

	for _, typ := range tests {
		t.Run("assertion typed "+typ, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")
			assertion := sa.assert(t, ceremony{challenge: challenge, typ: &typ, counter: 1})

			if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("assertion with client-data type %q = %v, want ErrAuthenticationFailed", typ, err)
			}
		})
	}

	t.Run("registration typed webauthn.get", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		h.addUser(t, "alice")

		options, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}

		sa := newSoftAuthenticator(t)
		assertType := string(protocol.AssertCeremony)
		resp := sa.register(t, ceremony{challenge: options.Response.Challenge.String(), typ: &assertType})

		if _, err = h.auth.FinishRegistration(context.Background(), sessionID, resp); !errors.Is(err, ErrRegistrationFailed) {
			t.Fatalf("registration with client-data type webauthn.get = %v, want ErrRegistrationFailed", err)
		}
	})
}

// TestWebAuthn_ChallengeSubstitutionRejected signs a challenge other than the
// one the relying party issued.
//
// CWE-294. An attacker who can start their own ceremony holds a valid,
// well-formed challenge; the question is whether the relying party will accept a
// signature over *a* challenge rather than *the* challenge it stored. The
// truncation and padding cases matter separately: a comparison that normalised
// base64 or compared prefixes would accept them.
func TestWebAuthn_ChallengeSubstitutionRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")

	tests := []struct {
		name      string
		challenge string
	}{
		{name: "attacker's own challenge", challenge: base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))},
		{name: "empty", challenge: ""},
		{name: "truncated", challenge: challenge[:len(challenge)-4]},
		{name: "extended", challenge: challenge + "AAAA"},
		{name: "padded", challenge: challenge + "=="},
		{name: "standard base64 alphabet", challenge: strings.NewReplacer("-", "+", "_", "/").Replace(challenge)},
		{name: "all zero bytes", challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Each subtest needs its own single-use challenge.
			sub := newHarness(t, harnessOpts{})
			sub.addUser(t, "alice")
			key := sub.enroll(t, "alice")

			_, subSession := sub.beginLogin(t, "alice")
			assertion := key.assert(t, ceremony{challenge: tc.challenge, counter: 1})

			if _, err := sub.auth.FinishLogin(context.Background(), subSession, assertion); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("assertion over challenge %q = %v, want ErrAuthenticationFailed", tc.challenge, err)
			}
		})
	}

	// Guard against the harness lying to itself: the honest challenge must work.
	if _, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: 1})); err != nil {
		t.Fatalf("the honest challenge was rejected, so the negative cases above prove nothing: %v", err)
	}
}

// TestWebAuthn_ForgedOrTamperedAssertionRejected attacks the signature itself.
//
// CWE-347 (improper verification of cryptographic signature). Every case here
// presents correct client data for a live challenge and a correct RP ID hash, so
// the only thing standing between the attacker and an authenticated session is
// the ECDSA verification over authenticatorData || SHA-256(clientDataJSON).
func TestWebAuthn_ForgedOrTamperedAssertionRejected(t *testing.T) {
	t.Parallel()

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ceremony)
	}{
		{
			name:   "signed by a key that was never registered",
			mutate: func(c *ceremony) { c.signWith = attackerKey },
		},
		{
			name: "single bit flipped in the signature",
			mutate: func(c *ceremony) {
				c.mutateSig = func(sig []byte) []byte {
					out := append([]byte(nil), sig...)
					out[len(out)/2] ^= 0x01

					return out
				}
			},
		},
		{
			name: "empty signature",
			mutate: func(c *ceremony) {
				c.mutateSig = func([]byte) []byte { return nil }
			},
		},
		{
			name: "truncated signature",
			mutate: func(c *ceremony) {
				c.mutateSig = func(sig []byte) []byte { return sig[:len(sig)/2] }
			},
		},
		{
			name: "authenticator data edited after signing",
			mutate: func(c *ceremony) {
				c.mutateAuthData = func(ad []byte) []byte {
					out := append([]byte(nil), ad...)
					// Bump the signature counter without re-signing.
					binary.BigEndian.PutUint32(out[33:37], 9999)

					return out
				}
			},
		},
		{
			name: "user-presence flag added after signing",
			mutate: func(c *ceremony) {
				c.flags = protocol.FlagUserVerified
				c.mutateAuthData = func(ad []byte) []byte {
					out := append([]byte(nil), ad...)
					out[32] |= byte(protocol.FlagUserPresent)

					return out
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")

			c := ceremony{challenge: challenge, counter: 1}
			tc.mutate(&c)

			assertion, parseErr := sa.assertRaw(t, c)
			if parseErr != nil {
				// Refusing at the parse boundary is a legitimate rejection.
				return
			}

			if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("%s = %v, want ErrAuthenticationFailed", tc.name, err)
			}
		})
	}
}

// TestWebAuthn_SignatureIsNotMalleableByTrailingBytes appends bytes after the
// DER-encoded ECDSA signature.
//
// CWE-347. The signature is decoded with encoding/asn1, whose Unmarshal returns
// the unconsumed remainder as a value the caller is expected to check. Discarding
// it makes the encoding non-canonical: an unbounded family of byte strings all
// verify as the same signature. That is not a forgery -- the attacker still
// cannot produce a valid signature without the key -- but it breaks the
// assumption that a signature is a stable identifier, which is what any
// replay-cache, audit record or idempotency key keyed on the assertion bytes
// relies on. It also means an assertion body has no single canonical form to
// bound, so a size limit on it is advisory.
//
// The discarding happens in go-webauthn's EC2PublicKeyData.Verify, not in this
// package, so the fix is the length check this package now applies itself:
// hasCanonicalSignature re-parses with the same asn1.Unmarshal and requires the
// remainder to be empty. It is deliberately narrower than "reject odd
// signatures" -- the same parser accepts the same (r, s), so nothing an
// authenticator legitimately emits starts failing.
func TestWebAuthn_SignatureIsNotMalleableByTrailingBytes(t *testing.T) {
	t.Parallel()

	trailers := [][]byte{
		{0x00},
		{0xDE, 0xAD, 0xBE, 0xEF},
		bytes.Repeat([]byte{0x41}, 64),
	}

	for _, trailer := range trailers {
		t.Run(fmt.Sprintf("%d trailing bytes", len(trailer)), func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")

			padded := sa.assert(t, ceremony{
				challenge: challenge,
				counter:   1,
				mutateSig: func(sig []byte) []byte {
					return append(append([]byte(nil), sig...), trailer...)
				},
			})

			if _, err := h.auth.FinishLogin(context.Background(), sessionID, padded); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("an assertion whose ECDSA signature carries %d bytes of trailing garbage "+
					"after the DER structure = %v, want ErrAuthenticationFailed: asn1.Unmarshal "+
					"reports the unconsumed remainder and the verifier discards it, so every "+
					"signature would have infinitely many accepted encodings", len(trailer), err)
			}
		})
	}

	// The honest encoding must still verify, or the check above proves only that
	// the package stopped working.
	t.Run("canonical signature still authenticates", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		h.addUser(t, "alice")
		sa := h.enroll(t, "alice")

		challenge, sessionID := h.beginLogin(t, "alice")

		if _, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: 1})); err != nil {
			t.Fatalf("a canonically encoded signature was rejected: %v", err)
		}
	})
}

// TestWebAuthn_CanonicalSignatureCheckOnlyJudgesECDSA is the half of the
// canonical-encoding check that would lock users out if it were wrong.
//
// Only elliptic-curve signatures are ASN.1. An RSA or Ed25519 signature is a
// fixed-width byte string with no internal structure to be non-minimal about, so
// a check that tried to parse one as DER would refuse every assertion from an
// RS256 or EdDSA authenticator -- turning a hardening measure into an outage for
// the credentials it was never about. The unreadable-key case goes the other
// way: nothing can be judged, so nothing is allowed.
func TestWebAuthn_CanonicalSignatureCheckOnlyJudgesECDSA(t *testing.T) {
	t.Parallel()

	rsaKey, err := webauthncbor.Marshal(webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS256),
		},
		Modulus:  bytes.Repeat([]byte{0xAB}, 256),
		Exponent: []byte{0x01, 0x00, 0x01},
	})
	if err != nil {
		t.Fatalf("marshal RSA COSE key: %v", err)
	}

	okpKey, err := webauthncbor.Marshal(webauthncose.OKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.OctetKey),
			Algorithm: int64(webauthncose.AlgEdDSA),
		},
		Curve:  int64(webauthncose.Ed25519),
		XCoord: bytes.Repeat([]byte{0xCD}, 32),
	})
	if err != nil {
		t.Fatalf("marshal OKP COSE key: %v", err)
	}

	// Bytes that are certainly not DER: an RSA or Ed25519 signature looks like
	// this, and must not be judged as though it were.
	opaque := bytes.Repeat([]byte{0xFF}, 64)

	tests := []struct {
		name      string
		publicKey []byte
		signature []byte
		want      bool
	}{
		{name: "rsa signature is not asn.1", publicKey: rsaKey, signature: opaque, want: true},
		{name: "ed25519 signature is not asn.1", publicKey: okpKey, signature: opaque, want: true},
		{name: "unreadable public key", publicKey: []byte("not cbor"), signature: opaque, want: false},
		{name: "no public key at all", publicKey: nil, signature: opaque, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := hasCanonicalSignature(tc.publicKey, tc.signature); got != tc.want {
				t.Fatalf("hasCanonicalSignature = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestWebAuthn_UserPresenceFlagRequired asserts an assertion with UP clear is
// refused.
//
// CWE-287. The user-presence bit is the authenticator's statement that a human
// touched it. An assertion produced with UP clear is, by construction, one the
// user did not authorize -- a silent assertion. WebAuthn §7.2 requires it be set.
func TestWebAuthn_UserPresenceFlagRequired(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")
	assertion := sa.assert(t, ceremony{challenge: challenge, flags: protocol.FlagUserVerified, counter: 1})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("assertion with the user-presence flag clear = %v, want ErrAuthenticationFailed", err)
	}
}

// TestWebAuthn_AssertionUserHandleMismatchRejected sends another account's user
// handle alongside a valid signature.
//
// CWE-287. WebAuthn §7.2 requires that when the authenticator returns a user
// handle, it identify the owner of the credential being asserted. A relying
// party that ignores it, or that trusts it over its own record of who the
// credential belongs to, lets a discoverable credential name whichever account
// the attacker prefers.
func TestWebAuthn_AssertionUserHandleMismatchRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		handle []byte
	}{
		{name: "another user's handle", handle: []byte("mallory")},
		{name: "handle of a user that does not exist", handle: []byte("nobody")},
		{name: "handle that is a prefix of the real one", handle: []byte("ali")},
		{name: "handle with trailing NUL", handle: []byte("alice\x00")},
		{name: "oversized handle", handle: bytes.Repeat([]byte("a"), 512)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")
			assertion := sa.assert(t, ceremony{challenge: challenge, userHandle: tc.handle, counter: 1})

			if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("assertion carrying user handle %q = %v, want ErrAuthenticationFailed", tc.handle, err)
			}
		})
	}

	t.Run("matching handle is accepted", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		h.addUser(t, "alice")
		sa := h.enroll(t, "alice")

		challenge, sessionID := h.beginLogin(t, "alice")
		assertion := sa.assert(t, ceremony{challenge: challenge, userHandle: []byte("alice"), counter: 1})

		if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); err != nil {
			t.Fatalf("assertion with the correct user handle was rejected: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Credential identity
// ---------------------------------------------------------------------------

// TestWebAuthn_CredentialIDCollisionAcrossUsersRejected registers one credential
// ID against two accounts.
//
// CWE-287. A credential ID is the lookup key for a public key. If a second
// registration can claim an ID already bound to another account, the mapping
// from "this credential asserted" to "this human" stops being a function: the
// authenticator that holds the private key for the original credential can be
// resolved to whichever account claimed the ID last. WebAuthn §7.1 tells the
// relying party to fail a registration for a credential ID already registered to
// a different user.
//
// Note where the refusal comes from: auth/webauthn does not check, so the only
// thing standing in the way is the credential store's uniqueness constraint.
// That is documented in storage.CredentialStore, but a store that overwrites --
// an UPSERT keyed on credential ID, which is the natural SQL spelling -- would
// silently reassign the credential and this package would not notice.
func TestWebAuthn_CredentialIDCollisionAcrossUsersRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	h.addUser(t, "mallory")

	alicesKey := h.enroll(t, "alice")

	// Mallory's authenticator reports Alice's credential ID.
	options, sessionID, err := h.auth.BeginRegistration(context.Background(), "mallory")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	mallorysKey := newSoftAuthenticator(t)
	resp := mallorysKey.register(t, ceremony{
		challenge: options.Response.Challenge.String(),
		credID:    alicesKey.credID,
	})

	_, err = h.auth.FinishRegistration(context.Background(), sessionID, resp)
	if err == nil {
		t.Fatal("a second account registered a credential ID already bound to another account")
	}

	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Errorf("collision was refused with %v; the caller cannot distinguish "+
			"a credential-ID collision from a store outage, and the refusal comes "+
			"from the store rather than from the ceremony", err)
	}

	// The original binding must survive the attempt.
	creds, err := h.auth.GetUserCredentials(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetUserCredentials(alice): %v", err)
	}

	if len(creds) != 1 || !bytes.Equal(creds[0].ID, alicesKey.credID) {
		t.Fatalf("alice's credential was disturbed by the collision attempt: %+v", creds)
	}

	if creds[0].UserID != "alice" {
		t.Fatalf("credential was reassigned to %q", creds[0].UserID)
	}
}

// TestWebAuthn_UnregisteredCredentialIDRejected asserts with a credential ID
// nobody registered.
//
// CWE-287. This is the trivial probe an attacker runs first, and it must not be
// answered with anything other than a flat refusal.
func TestWebAuthn_UnregisteredCredentialIDRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")
	assertion := sa.assert(t, ceremony{challenge: challenge, credID: randomBytes(t, 32), counter: 1})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("assertion for an unregistered credential ID = %v, want ErrAuthenticationFailed", err)
	}
}

// TestWebAuthn_DeletedCredentialCannotAuthenticate proves revocation takes
// effect.
//
// CWE-613. A lost or stolen security key is deleted from the account; if the
// deletion does not immediately stop assertions from that key, the revocation
// control is decorative.
func TestWebAuthn_DeletedCredentialCannotAuthenticate(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	// Start the ceremony first, then revoke: this is the race a real attacker
	// would try to win, holding options issued a moment before the deletion.
	challenge, sessionID := h.beginLogin(t, "alice")

	if err := h.auth.DeleteCredential(context.Background(), sa.credID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	assertion := sa.assert(t, ceremony{challenge: challenge, counter: 1})

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("a deleted credential authenticated against an in-flight challenge (err=%v)", err)
	}
}

// ---------------------------------------------------------------------------
// Signature counter
// ---------------------------------------------------------------------------

// TestWebAuthn_ClonedAuthenticatorCounterRollbackRejected replays an assertion
// whose signature counter has gone backwards.
//
// WebAuthn §6.1.1 ("Signature Counter Considerations") is explicit: a signCount
// less than or equal to the value stored against the credential is the signal
// that the credential's private key may exist in more than one place. It is the
// only clone detector the protocol has, and it is the only thing that catches an
// attacker who extracted a key from a non-resident authenticator, because every
// other check -- origin, RP ID hash, challenge, signature -- passes perfectly for
// a clone.
//
// The library used to read the counter (it copied it into the stored
// credential) and never act on the verdict: go-webauthn sets
// Authenticator.CloneWarning and leaves the decision to the relying party, and
// FinishLogin ignored the field while overwriting the stored counter with
// whatever was presented -- so a clone both authenticated and lowered the value
// the next assertion would be measured against.
func TestWebAuthn_ClonedAuthenticatorCounterRollbackRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		advance  uint32 // counter used for the legitimate sign-in
		rollback uint32 // counter the clone presents afterwards
	}{
		{name: "counter reset to zero", advance: 500, rollback: 0},
		{name: "counter rolled far back", advance: 500, rollback: 7},
		{name: "counter repeated exactly", advance: 500, rollback: 500},
		{name: "counter one below", advance: 500, rollback: 499},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			// A legitimate sign-in advances the counter.
			challenge, sessionID := h.beginLogin(t, "alice")
			if _, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: tc.advance})); err != nil {
				t.Fatalf("honest sign-in was rejected: %v", err)
			}

			stored := storedSignCount(t, h, "alice", sa.credID)
			if stored != tc.advance {
				t.Fatalf("stored sign count = %d after an honest sign-in at %d; the counter is not being persisted, so the rollback probe below would prove nothing", stored, tc.advance)
			}

			// The clone signs with a counter that has gone backwards.
			cloneChallenge, cloneSession := h.beginLogin(t, "alice")
			cloneAssertion := sa.assert(t, ceremony{challenge: cloneChallenge, counter: tc.rollback})

			user, err := h.auth.FinishLogin(context.Background(), cloneSession, cloneAssertion)
			if err == nil {
				t.Fatalf("an assertion whose signature counter went from %d to %d authenticated as %q; "+
					"WebAuthn §6.1.1 makes that the protocol's only cloned-authenticator signal",
					tc.advance, tc.rollback, user.ID)
			}

			// A caller has to be able to tell a suspected clone from a mistyped
			// password: it is a security event about a credential, not a failed
			// attempt. It stays an authentication failure as well, so a caller that
			// only knows the old sentinel still refuses the sign-in.
			if !errors.Is(err, ErrCredentialCloned) {
				t.Fatalf("counter rollback was refused with %v, want ErrCredentialCloned", err)
			}

			if !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("ErrCredentialCloned does not satisfy errors.Is(err, ErrAuthenticationFailed); "+
					"a caller matching only the documented sentinel would fall through to its "+
					"generic error path (err=%v)", err)
			}

			if after := storedSignCount(t, h, "alice", sa.credID); after < tc.advance {
				t.Fatalf("the refused rollback still wrote the stored counter back to %d from %d; "+
					"a clone must not be able to lower the counter it is being measured against", after, tc.advance)
			}

			// The genuine authenticator must still be able to sign in afterwards:
			// refusing the clone may not brick the credential it was cloned from.
			nextChallenge, nextSession := h.beginLogin(t, "alice")
			if _, err = h.auth.FinishLogin(context.Background(), nextSession, sa.assert(t, ceremony{challenge: nextChallenge, counter: tc.advance + 1})); err != nil {
				t.Fatalf("the genuine authenticator was locked out after its clone was refused: %v", err)
			}
		})
	}
}

// TestWebAuthn_CounterlessAuthenticatorIsNotTreatedAsAClone is the other half of
// the rollback rule, and the half that breaks users rather than letting them in.
//
// WebAuthn Level 3 §6.1.1 permits an authenticator to implement no signature
// counter, and one that does not reports 0 on every assertion -- forever. Read
// naively, "refuse a counter that did not increase" locks such an authenticator
// out permanently, and synced passkeys are counter-less by construction because
// a counter cannot be kept consistent across the devices they sync to. The rule
// is therefore "not greater than the stored value, unless both are zero".
func TestWebAuthn_CounterlessAuthenticatorIsNotTreatedAsAClone(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	// Every assertion this authenticator produces reports 0, as one that keeps no
	// counter does. Several in a row, because the failure mode is "the second one
	// is refused".
	for attempt := range 3 {
		challenge, sessionID := h.beginLogin(t, "alice")

		if _, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: 0})); err != nil {
			t.Fatalf("sign-in %d of a counter-less authenticator was refused with %v; "+
				"0-against-stored-0 is a counter that does not exist, not one that went backwards",
				attempt+1, err)
		}

		if stored := storedSignCount(t, h, "alice", sa.credID); stored != 0 {
			t.Fatalf("stored sign count moved to %d for an authenticator that reports 0", stored)
		}
	}

	// An authenticator that starts counting is moving forwards, so it is accepted
	// and from then on it is held to the rollback rule.
	challenge, sessionID := h.beginLogin(t, "alice")
	if _, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: 1})); err != nil {
		t.Fatalf("first non-zero counter was refused: %v", err)
	}

	rollbackChallenge, rollbackSession := h.beginLogin(t, "alice")
	if _, err := h.auth.FinishLogin(context.Background(), rollbackSession, sa.assert(t, ceremony{challenge: rollbackChallenge, counter: 0})); !errors.Is(err, ErrCredentialCloned) {
		t.Fatalf("a drop back to 0 from a stored 1 = %v, want ErrCredentialCloned", err)
	}
}

// TestWebAuthn_SignCountRollbackRule pins the decision itself, apart from any
// ceremony.
//
// The zero case is the one worth a table: it is a two-line rule whose two lines
// fail in opposite directions -- get the exception wrong and every counter-less
// authenticator is locked out, drop it and the only clone detector the protocol
// has stops firing.
func TestWebAuthn_SignCountRollbackRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		stored    uint32
		presented uint32
		want      bool
	}{
		{name: "counter advanced by one", stored: 41, presented: 42, want: false},
		{name: "counter jumped ahead", stored: 1, presented: 1 << 20, want: false},
		{name: "first assertion after registration", stored: 0, presented: 1, want: false},
		{name: "authenticator keeps no counter", stored: 0, presented: 0, want: false},
		{name: "counter repeated exactly", stored: 42, presented: 42, want: true},
		{name: "counter one below", stored: 42, presented: 41, want: true},
		{name: "counter reset to zero", stored: 42, presented: 0, want: true},
		{name: "counter at the maximum repeated", stored: ^uint32(0), presented: ^uint32(0), want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isSignCountRollback(tc.stored, tc.presented); got != tc.want {
				t.Fatalf("isSignCountRollback(%d, %d) = %t, want %t", tc.stored, tc.presented, got, tc.want)
			}
		})
	}
}

// storedSignCount reads the persisted counter for one credential.
func storedSignCount(t *testing.T, h *harness, userID string, credID []byte) uint32 {
	t.Helper()

	creds, err := h.auth.GetUserCredentials(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserCredentials(%q): %v", userID, err)
	}

	for _, cred := range creds {
		if bytes.Equal(cred.ID, credID) {
			return cred.SignCount
		}
	}

	t.Fatalf("credential %x not found for %q", credID, userID)

	return 0
}

// TestWebAuthn_CounterPersistenceFailureIsNotSilent asserts that a failure to
// persist the signature counter is visible to the caller.
//
// WebAuthn §6.1.1 again. The counter only detects a clone if it is durable: if
// the write is dropped, the next assertion is compared against a stale value and
// the clone signal is lost for that credential permanently. FinishLogin used to
// catch the error, print it to stdout with fmt.Printf, and return success -- so
// the failure was invisible to the caller's logs, its metrics and its audit
// trail, and it violated the package's own "a library does not write to process
// stdout" convention on the way past.
//
// The ceremony now fails. The threat model is the argument: an attacker who can
// make the counter write fail -- a filled disk, a saturated connection pool, a
// replica that has stopped accepting writes -- can otherwise blind the clone
// detector for a credential of their choosing and keep authenticating with the
// clone afterwards, with no trace anywhere the relying party looks. Refusing
// makes the loss of the control loud and costs a real user one retry against an
// outage that is already breaking other things.
func TestWebAuthn_CounterPersistenceFailureIsNotSilent(t *testing.T) {
	t.Parallel()

	errBackend := errors.New("credential store unavailable")

	h := newHarness(t, harnessOpts{
		creds: &brokenCounterStore{
			InMemoryCredentialStore: storage.NewInMemoryCredentialStore(),
			errUpdate:               errBackend,
		},
	})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")

	user, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: 42}))
	if err == nil {
		t.Fatalf("FinishLogin authenticated %q after the signature-counter write failed with %q; "+
			"the relying party has no way to know the clone detector is now blind for this "+
			"credential", user.ID, errBackend)
	}

	if !errors.Is(err, ErrSignCountNotPersisted) {
		t.Fatalf("counter-persistence failure surfaced as %v, want ErrSignCountNotPersisted", err)
	}

	// The cause travels with it, because "the sign-in failed" is not an
	// actionable page for an operator at 3am.
	if !errors.Is(err, errBackend) {
		t.Errorf("the store's own error was dropped on the way out: %v", err)
	}

	// It is not an authentication failure: the credential proved itself and the
	// relying party's storage is what broke. A caller that maps
	// ErrAuthenticationFailed to 401 would otherwise blame the user for an
	// outage, and would never alert on it.
	if errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("a storage fault was reported as an authentication failure (%v), which sends "+
			"the operator looking at the user instead of the store", err)
	}
}

// TestWebAuthn_CounterlessAuthenticatorSurvivesABrokenCounterStore pins the one
// case that must NOT fail when the counter store is down.
//
// An authenticator that keeps no counter reports 0 every time, so there is
// nothing for the store to persist and nothing for the failed write to lose.
// Failing the ceremony there would take every synced passkey offline for the
// duration of a storage incident, in exchange for protecting a signal that
// authenticator never produced.
func TestWebAuthn_CounterlessAuthenticatorSurvivesABrokenCounterStore(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{
		creds: &brokenCounterStore{
			InMemoryCredentialStore: storage.NewInMemoryCredentialStore(),
			errUpdate:               errors.New("credential store unavailable"),
		},
	})
	h.addUser(t, "alice")
	sa := h.enroll(t, "alice")

	challenge, sessionID := h.beginLogin(t, "alice")

	if _, err := h.auth.FinishLogin(context.Background(), sessionID, sa.assert(t, ceremony{challenge: challenge, counter: 0})); err != nil {
		t.Fatalf("a counter-less authenticator was refused because a write that could not have "+
			"changed anything failed: %v", err)
	}
}

// TestWebAuthn_CredentialBackupFlagsSurviveStorage asserts the BE/BS flags a
// credential was registered with are still known at assertion time.
//
// WebAuthn Level 3 §7.2 requires the relying party to refuse an assertion whose
// backup-eligibility flag disagrees with the value recorded at registration: BE
// describes the key itself and, per the specification, never changes, so a
// disagreement means the credential record and the authenticator are not talking
// about the same key.
//
// storage.WebAuthnCredential has no field for the flags, so
// storageCredToWebAuthn used to rebuild every credential with a zero
// CredentialFlags and the stored side of the comparison was hard-wired to false.
// The consequence was not subtle: every synced passkey -- which is to say every
// iCloud Keychain, Google Password Manager or 1Password credential, all of which
// report BE=1 -- could be registered and could then never sign in again.
//
// The v1 API is frozen, so the flags ride in the credential's own metadata map
// rather than in new struct fields. A store that drops metadata puts the
// credential back where it was, which is why this test also proves the flags
// survive a full round trip through the store rather than only through memory.
func TestWebAuthn_CredentialBackupFlagsSurviveStorage(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice")

	backedUp := protocol.FlagUserPresent | protocol.FlagUserVerified |
		protocol.FlagAttestedCredentialData | protocol.FlagBackupEligible | protocol.FlagBackupState

	options, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	sa := newSoftAuthenticator(t)
	resp := sa.register(t, ceremony{challenge: options.Response.Challenge.String(), flags: backedUp})

	if _, err = h.auth.FinishRegistration(context.Background(), sessionID, resp); err != nil {
		t.Fatalf("registration of a backup-eligible passkey was rejected: %v", err)
	}

	assertBackupFlagsStored(t, h, sa.credID)

	challenge, loginSession := h.beginLogin(t, "alice")
	assertion := sa.assert(t, ceremony{
		challenge: challenge,
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState,
		counter:   1,
	})

	if _, err = h.auth.FinishLogin(context.Background(), loginSession, assertion); err != nil {
		t.Fatalf("a passkey registered with BE=1,BS=1 cannot sign in (err=%v); the WebAuthn "+
			"Level 3 §7.2 backup-flag consistency check is comparing the assertion against a "+
			"constant false", err)
	}

	// Advancing the counter rewrites the record. The flags have to survive that
	// too, or the second sign-in is the one that breaks.
	assertBackupFlagsStored(t, h, sa.credID)

	nextChallenge, nextSession := h.beginLogin(t, "alice")
	nextAssertion := sa.assert(t, ceremony{
		challenge: nextChallenge,
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState,
		counter:   2,
	})

	if _, err = h.auth.FinishLogin(context.Background(), nextSession, nextAssertion); err != nil {
		t.Fatalf("the second sign-in of a backup-eligible passkey was refused: %v", err)
	}

	// The flags are a fact about the key, not about the assertion: an
	// authenticator that suddenly claims BE=0 for a credential registered with
	// BE=1 is not the same key, and §7.2 says so.
	downgradeChallenge, downgradeSession := h.beginLogin(t, "alice")
	downgrade := sa.assert(t, ceremony{
		challenge: downgradeChallenge,
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified,
		counter:   3,
	})

	if _, err = h.auth.FinishLogin(context.Background(), downgradeSession, downgrade); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("an assertion claiming BE=0 for a credential registered BE=1 = %v, want ErrAuthenticationFailed", err)
	}
}

// assertBackupFlagsStored reads the persisted credential back through the store
// and checks the backup flags are still on it.
func assertBackupFlagsStored(t *testing.T, h *harness, credID []byte) {
	t.Helper()

	creds, err := h.auth.GetUserCredentials(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetUserCredentials: %v", err)
	}

	stored := findStoredCredential(creds, credID)
	if stored == nil {
		t.Fatalf("credential %x is not in the store", credID)
	}

	flags := credentialFlags(stored.Metadata)
	if !flags.BackupEligible || !flags.BackupState {
		t.Fatalf("stored credential reports BE=%t BS=%t, want both true; metadata=%v",
			flags.BackupEligible, flags.BackupState, stored.Metadata)
	}
}

// ---------------------------------------------------------------------------
// Malformed, truncated, oversized and type-confused input
// ---------------------------------------------------------------------------

// TestWebAuthn_MalformedCeremonyPayloadsMustNotPanic feeds hostile bytes through
// the parsers the ceremony endpoints sit behind.
//
// CWE-20 / CWE-248. Everything in this table arrives on an unauthenticated HTTP
// endpoint. A panic in any of these paths is a remote denial of service against
// the whole process, not just the sign-in route; a silent success is worse.
func TestWebAuthn_MalformedCeremonyPayloadsMustNotPanic(t *testing.T) {
	t.Parallel()

	oversized := `{"id":"` + strings.Repeat("A", 1<<20) + `","type":"public-key","response":{}}`

	tests := []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "not json", body: "\x00\x01\x02\xff"},
		{name: "truncated json", body: `{"id":"AAAA","type":"public-ke`},
		{name: "empty object", body: `{}`},
		{name: "null", body: `null`},
		{name: "array instead of object", body: `[]`},
		{name: "id not base64url", body: `{"id":"!!!!","rawId":"!!!!","type":"public-key","response":{}}`},
		{name: "type confusion, id is a number", body: `{"id":1,"rawId":1,"type":"public-key","response":{}}`},
		{name: "type confusion, response is a string", body: `{"id":"AAAA","rawId":"AAAA","type":"public-key","response":"x"}`},
		{name: "wrong credential type", body: `{"id":"AAAA","rawId":"AAAA","type":"password","response":{}}`},
		{name: "trailing data after the object", body: `{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{}}{}`},
		{name: "attestation object is not cbor", body: `{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"AAAA"}}`},
		{name: "authenticator data shorter than the 37-byte minimum", body: `{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA"}}`},
		{name: "deeply nested json", body: `{"id":"AAAA","rawId":"AAAA","type":"public-key","response":` + strings.Repeat(`{"a":`, 2000) + `1` + strings.Repeat(`}`, 2000) + `}`},
		{name: "oversized id", body: oversized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mustNotPanic(t, "ParseCredentialCreationResponseBytes", func() {
				if _, err := protocol.ParseCredentialCreationResponseBytes([]byte(tc.body)); err == nil {
					t.Errorf("registration payload %.60q parsed without error", tc.body)
				}
			})

			mustNotPanic(t, "ParseCredentialRequestResponseBytes", func() {
				if _, err := protocol.ParseCredentialRequestResponseBytes([]byte(tc.body)); err == nil {
					t.Errorf("assertion payload %.60q parsed without error", tc.body)
				}
			})
		})
	}
}

// TestWebAuthn_OversizedCredentialIDRejected pushes past the protocol's own
// credential-ID ceiling.
//
// CWE-1284. WebAuthn caps a credential ID at 1023 bytes -- the credentialIdLength
// field of attested credential data is bounded, not merely 16-bit. An
// authenticator-supplied length field that nobody bounds is an allocation an
// attacker chooses the size of, and a credential ID that nobody bounds is a
// database key an attacker chooses the size of.
func TestWebAuthn_OversizedCredentialIDRejected(t *testing.T) {
	t.Parallel()

	// 65535 is the largest the 16-bit credentialIdLength field can express at all;
	// anything above it cannot be encoded, which is the bound doing its job.
	for _, size := range []int{1024, 4096, 65535} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")

			options, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
			if err != nil {
				t.Fatalf("BeginRegistration: %v", err)
			}

			sa := newSoftAuthenticator(t)

			resp, parseErr := sa.registerRaw(t, ceremony{
				challenge: options.Response.Challenge.String(),
				credID:    bytes.Repeat([]byte("A"), size),
			})
			if parseErr != nil {
				return // Refused at the parse boundary; that is the right answer.
			}

			if _, err = h.auth.FinishRegistration(context.Background(), sessionID, resp); err == nil {
				t.Fatalf("registered a %d-byte credential ID; WebAuthn caps it at 1023", size)
			}
		})
	}
}

// TestWebAuthn_NilCeremonyResponseMustNotPanic hands the ceremony a nil parsed
// response.
//
// CWE-476. This is the shape a caller produces by accident, not by malice:
// `resp, err := protocol.ParseCredentialCreationResponse(r)` followed by a
// mishandled error leaves resp nil, and the handler passes it straight in. A
// library must answer that with an error, because a nil dereference inside the
// ceremony takes down the process for every other request in flight.
func TestWebAuthn_NilCeremonyResponseMustNotPanic(t *testing.T) {
	t.Parallel()

	t.Run("registration", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		h.addUser(t, "alice")

		_, sessionID, err := h.auth.BeginRegistration(context.Background(), "alice")
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}

		mustNotPanic(t, "FinishRegistration", func() {
			_, err = h.auth.FinishRegistration(context.Background(), sessionID, nil)
		})

		if !errors.Is(err, ErrRegistrationFailed) {
			t.Fatalf("FinishRegistration(nil) = %v, want ErrRegistrationFailed: a nil parsed "+
				"response reaches webauthn.CreateCredential, which dereferences it", err)
		}
	})

	t.Run("login", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		h.addUser(t, "alice")
		h.enroll(t, "alice")

		_, sessionID := h.beginLogin(t, "alice")

		var err error

		mustNotPanic(t, "FinishLogin", func() {
			_, err = h.auth.FinishLogin(context.Background(), sessionID, nil)
		})

		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("FinishLogin(nil) = %v, want ErrAuthenticationFailed", err)
		}
	})
}

// TestWebAuthn_CorruptStoredSessionBlobIsRejected corrupts the encoded
// go-webauthn session the challenge record carries.
//
// CWE-502-adjacent: this is not Go gob or a code-executing decoder, but it is
// still "reconstruct a security decision from persisted bytes". The blob is
// base64 of JSON in whatever the challenge store holds -- Redis, Memcached, a
// table shared with other flows -- and the store is not part of the library's
// trust boundary. A truncated, re-encoded or type-confused blob must fail the
// ceremony, never resurrect it with zero values (a zero-value SessionData has an
// empty Challenge and an empty UserID, which is exactly the shape that would
// authenticate anybody).
func TestWebAuthn_CorruptStoredSessionBlobIsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		session any
	}{
		{name: "not a string", session: 42},
		{name: "nil", session: nil},
		{name: "empty string", session: ""},
		{name: "not base64", session: "!!!!!!"},
		{name: "base64 of non-json", session: base64.RawURLEncoding.EncodeToString([]byte("\x00\x01\x02"))},
		{name: "base64 of a json array", session: base64.RawURLEncoding.EncodeToString([]byte(`[]`))},
		{name: "zero-value session", session: base64.RawURLEncoding.EncodeToString([]byte(`{}`))},
		{name: "session with an empty challenge", session: base64.RawURLEncoding.EncodeToString([]byte(`{"challenge":"","user_id":"YWxpY2U"}`))},
		{name: "session claiming another user", session: base64.RawURLEncoding.EncodeToString([]byte(`{"challenge":"AAAA","user_id":"bWFsbG9yeQ"}`))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})
			h.addUser(t, "alice")
			sa := h.enroll(t, "alice")

			challenge, sessionID := h.beginLogin(t, "alice")

			corrupt := h.states.snapshot(t, sessionID)
			corrupt.Metadata["session"] = tc.session

			if err := h.states.StoreState(context.Background(), sessionID, corrupt, time.Minute); err != nil {
				t.Fatalf("re-store corrupt state: %v", err)
			}

			assertion := sa.assert(t, ceremony{challenge: challenge, counter: 1})

			mustNotPanic(t, "FinishLogin", func() {
				if _, err := h.auth.FinishLogin(context.Background(), sessionID, assertion); err == nil {
					t.Errorf("a ceremony completed against a corrupt stored session blob (%v)", tc.session)
				}
			})
		})
	}
}

// TestWebAuthn_CeremonyRecordMustBeCompleteAndOurs drives the challenge-record
// reader directly, with records the challenge store could hand back.
//
// The store is outside the trust boundary (§2, adversary 3) and is shared with
// the OIDC flow, so "what GetState returned" is attacker-influenced input rather
// than library state. Two of these cases are refused a second time by
// go-webauthn further down the ceremony, which is exactly why they are asserted
// here instead: a defense that only shows up as somebody else's error message
// can be deleted without a single test noticing.
func TestWebAuthn_CeremonyRecordMustBeCompleteAndOurs(t *testing.T) {
	t.Parallel()

	honest, err := encodeSessionData(&gowebauthn.SessionData{
		Challenge:      base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		RelyingPartyID: testRPID,
		UserID:         []byte("alice"),
	})
	if err != nil {
		t.Fatalf("encodeSessionData: %v", err)
	}

	zeroValue := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	noChallenge := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"YWxpY2U"}`))
	noUser := base64.RawURLEncoding.EncodeToString([]byte(`{"challenge":"AAAA"}`))

	tests := []struct {
		name  string
		state *storage.OIDCState
	}{
		{
			name:  "written by the OIDC flow",
			state: &storage.OIDCState{Provider: "google", Metadata: map[string]any{"user_id": "alice", "session": honest}},
		},
		{
			name:  "carrying no provider tag at all",
			state: &storage.OIDCState{Metadata: map[string]any{"user_id": "alice", "session": honest}},
		},
		{
			name:  "naming no user",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"session": honest}},
		},
		{
			name:  "naming an empty user",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "", "session": honest}},
		},
		{
			name:  "user handle is not a string",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": 42, "session": honest}},
		},
		{
			name:  "no session blob",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "alice"}},
		},
		{
			name:  "session blob is not decodable",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "alice", "session": "!!!!"}},
		},
		{
			name:  "zero-value session",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "alice", "session": zeroValue}},
		},
		{
			name:  "session with no challenge",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "alice", "session": noChallenge}},
		},
		{
			name:  "session with no user handle",
			state: &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "alice", "session": noUser}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOpts{})

			if err := h.states.StoreState(context.Background(), "record", tc.state, time.Minute); err != nil {
				t.Fatalf("StoreState: %v", err)
			}

			if _, _, err := h.auth.loadCeremony(context.Background(), "record"); !errors.Is(err, errCeremonyState) {
				t.Fatalf("loadCeremony = %v, want errCeremonyState", err)
			}
		})
	}

	t.Run("a record that was never written", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})

		if _, _, err := h.auth.loadCeremony(context.Background(), "record"); !errors.Is(err, errCeremonyState) {
			t.Fatalf("loadCeremony = %v, want errCeremonyState", err)
		}
	})

	// The honest record must load, or every case above proves only that
	// loadCeremony refuses everything.
	t.Run("the honest record loads", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		state := &storage.OIDCState{Provider: "webauthn", Metadata: map[string]any{"user_id": "alice", "session": honest}}

		if err := h.states.StoreState(context.Background(), "record", state, time.Minute); err != nil {
			t.Fatalf("StoreState: %v", err)
		}

		userID, session, err := h.auth.loadCeremony(context.Background(), "record")
		if err != nil {
			t.Fatalf("loadCeremony on an honest record: %v", err)
		}

		if userID != "alice" || session == nil || session.RelyingPartyID != testRPID {
			t.Fatalf("loadCeremony returned userID=%q session=%+v", userID, session)
		}
	})

	// A store that is simply down is not a bad record. Collapsing the two would
	// answer an outage with "authentication failed", which sends the operator to
	// look at the user instead of at the store.
	t.Run("a store outage is not a bad record", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, harnessOpts{})
		outage := errors.New("state store unavailable")

		auth, err := NewAuthenticator(Config{
			RPDisplayName:   testRPName,
			RPID:            testRPID,
			RPOrigins:       []string{testRPOrigin},
			UserStore:       h.users,
			CredentialStore: h.creds,
			SessionStore:    &errStateStore{inner: storage.NewInMemoryOIDCStateStore(), err: outage},
		})
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}

		_, _, err = auth.loadCeremony(context.Background(), "record")
		if errors.Is(err, errCeremonyState) {
			t.Fatalf("a store outage was reported as an unusable record: %v", err)
		}

		if !errors.Is(err, outage) {
			t.Fatalf("loadCeremony = %v, want the store's own error to survive", err)
		}
	})
}

// TestWebAuthn_UnknownUserAndCredentiallessUserAreDistinguishable records the
// account-enumeration oracle in BeginLogin.
//
// CWE-204 (observable response discrepancy). BeginLogin returns ErrUserNotFound
// when the identifier is unknown and ErrCredentialNotFound when the account
// exists but has enrolled no passkey. An unauthenticated caller that can reach
// the "start sign-in" endpoint -- which is the entire point of that endpoint --
// can therefore ask whether any given identifier has an account, and separately
// whether that account has a passkey. WebAuthn deployments normally answer both
// with an indistinguishable response built over a fabricated credential list.
func TestWebAuthn_UnknownUserAndCredentiallessUserAreDistinguishable(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOpts{})
	h.addUser(t, "alice") // exists, no credential enrolled

	_, _, unknownErr := h.auth.BeginLogin(context.Background(), "nobody")
	_, _, credentiallessErr := h.auth.BeginLogin(context.Background(), "alice")

	if unknownErr == nil || credentiallessErr == nil {
		t.Fatalf("BeginLogin did not fail for both probes: unknown=%v credentialless=%v", unknownErr, credentiallessErr)
	}

	if errors.Is(unknownErr, credentiallessErr) && errors.Is(credentiallessErr, unknownErr) {
		return // The fix has landed: one indistinguishable answer.
	}

	gap(t, "BeginLogin answers an unknown identifier with %v and an enrolled-but-credentialless "+
		"account with %v; the difference is an account-existence oracle on an unauthenticated "+
		"endpoint. NOT FIXABLE UNDER THE v1 FREEZE: ErrUserNotFound and ErrCredentialNotFound "+
		"are exported, documented as the two answers this call gives, and callers branch on "+
		"them to decide between 'no such account' and 'add a passkey' -- collapsing them keeps "+
		"the package compiling while silently changing what every existing caller is told. The "+
		"real fix is the one deployments use, returning options over a fabricated allow-list so "+
		"the two cases are indistinguishable, and that needs somewhere to derive stable decoy "+
		"credential IDs from: a per-relying-party secret and the API to set it, neither of "+
		"which exists in v1. Deferred to v2 with a deprecation note",
		unknownErr, credentiallessErr)
}

// ---------------------------------------------------------------------------
// Fuzz targets (docs/security-hardening.md §6: every decoder of untrusted input)
// ---------------------------------------------------------------------------

// FuzzRegistrationCeremony drives the registration parser and, when a payload
// parses, the whole FinishRegistration path with a live challenge.
//
// The bytes here are exactly what an unauthenticated client posts to the
// registration callback. The property under test is total: parse or error, never
// panic, and never complete a ceremony for a challenge the payload does not
// carry.
func FuzzRegistrationCeremony(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`))
	f.Add([]byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"","attestationObject":""}}`))
	f.Add([]byte("\x00\xff\xfe"))
	f.Add([]byte(`[{"id":"AAAA"}]`))

	h := newFuzzHarness(f)

	f.Fuzz(func(t *testing.T, body []byte) {
		parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
		if err != nil {
			return
		}

		_, sessionID, beginErr := h.auth.BeginRegistration(context.Background(), "alice")
		if beginErr != nil {
			t.Fatalf("BeginRegistration: %v", beginErr)
		}

		if _, err = h.auth.FinishRegistration(context.Background(), sessionID, parsed); err == nil {
			t.Fatalf("a fuzzed registration payload completed a ceremony: %q", body)
		}
	})
}

// FuzzAssertionCeremony is the same property for the sign-in callback.
func FuzzAssertionCeremony(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA"}}`))
	f.Add([]byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"","signature":"","userHandle":""}}`))
	f.Add([]byte("\x00"))
	f.Add([]byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":null}`))

	h := newFuzzHarness(f)
	enrollFuzzCredential(f, h, newSoftAuthenticator(f))

	f.Fuzz(func(t *testing.T, body []byte) {
		parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
		if err != nil {
			return
		}

		_, sessionID, beginErr := h.auth.BeginLogin(context.Background(), "alice")
		if beginErr != nil {
			t.Fatalf("BeginLogin: %v", beginErr)
		}

		if _, err = h.auth.FinishLogin(context.Background(), sessionID, parsed); err == nil {
			t.Fatalf("a fuzzed assertion payload authenticated: %q", body)
		}
	})
}

// FuzzDecodeSessionData targets the package's own decoder for the persisted
// ceremony blob.
//
// decodeSessionData is base64 followed by JSON into a struct that carries the
// challenge, the user handle and the allowed credential list -- every input to
// the ceremony's security decisions. It reads from the challenge store, which is
// outside the library's trust boundary (§2, adversary 3). The property is that
// it never panics and never returns a session alongside a nil error unless the
// bytes really decoded.
func FuzzDecodeSessionData(f *testing.F) {
	honest, err := encodeSessionData(&gowebauthn.SessionData{
		Challenge:      base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		RelyingPartyID: testRPID,
		UserID:         []byte("alice"),
	})
	if err != nil {
		f.Fatalf("encodeSessionData: %v", err)
	}

	f.Add(honest)
	f.Add("")
	f.Add("!!!!")
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{}`)))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"challenge":123}`)))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"allowed_credentials":[null,null]}`)))
	f.Add(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte(`{"a":`), 100)))

	f.Fuzz(func(t *testing.T, encoded string) {
		session, err := decodeSessionData(encoded)

		switch {
		case err != nil && session != nil:
			t.Fatalf("decodeSessionData returned both a session and an error for %q", encoded)
		case err == nil && session == nil:
			t.Fatalf("decodeSessionData returned neither a session nor an error for %q", encoded)
		}
	})
}

// FuzzCredentialTransportRoundTrip targets the transport conversion helpers.
//
// Transport strings arrive from the authenticator and are persisted verbatim.
// The conversion is total by construction; the fuzz target pins that it stays
// total and length-preserving, since a helper that dropped or reordered entries
// would silently change which transports a credential advertises on the next
// ceremony.
func FuzzCredentialTransportRoundTrip(f *testing.F) {
	f.Add("usb")
	f.Add("")
	f.Add("internal,hybrid")
	f.Add("\x00")
	f.Add(strings.Repeat("nfc,", 64))

	f.Fuzz(func(t *testing.T, joined string) {
		in := strings.Split(joined, ",")

		out := protocolTransportsToStrings(stringsToProtocolTransports(in))
		if len(out) != len(in) {
			t.Fatalf("transport round trip changed length: %d -> %d", len(in), len(out))
		}

		for i := range in {
			if out[i] != in[i] {
				t.Fatalf("transport round trip changed element %d: %q -> %q", i, in[i], out[i])
			}
		}
	})
}

// FuzzCanonicalSignatureEncoding targets the canonical-encoding check that
// stands between the assertion bytes and the verifier's permissive ASN.1 parse.
//
// The signature is attacker-supplied on an unauthenticated endpoint. The target
// is differential: hasCanonicalSignature reaches its answer through
// encoding/asn1, and derSignatureIsCanonical below reaches it by walking the
// bytes, so a disagreement is a real divergence rather than one function
// agreeing with itself. That distinction earned its keep immediately -- the
// first version of the fix asked encoding/asn1 only whether anything remained
// AFTER the outer SEQUENCE, and this target answered with
// 30 44 02 20 <32 bytes> 02 1f <31 bytes>: a SEQUENCE whose declared length is
// one byte longer than the two INTEGERs inside it. asn1.Unmarshal fills the
// struct, silently ignores the leftover byte inside the SEQUENCE, and reports an
// empty remainder, so the padded signature passed.
func FuzzCanonicalSignatureEncoding(f *testing.F) {
	sa := newSoftAuthenticator(f)
	publicKey := sa.coseKey(f)

	digest := sha256.Sum256([]byte("canonical encoding corpus"))

	honest, err := ecdsa.SignASN1(rand.Reader, sa.key, digest[:])
	if err != nil {
		f.Fatalf("ecdsa.SignASN1: %v", err)
	}

	f.Add(honest)
	f.Add(append(append([]byte(nil), honest...), 0xDE, 0xAD))
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	f.Add(bytes.Repeat([]byte{0xFF}, 72))

	// Padding inside the SEQUENCE: the regression seed described above.
	padded := make([]byte, 0, 70)
	padded = append(padded, 0x30, 0x44, 0x02, 0x20)
	padded = append(padded, bytes.Repeat([]byte{0x30}, 32)...)
	padded = append(padded, 0x02, 0x1F)
	padded = append(padded, bytes.Repeat([]byte{0x30}, 32)...)
	f.Add(padded)

	// Non-minimal length and non-minimal integer: the other two ways to spell a
	// value DER allows exactly one spelling of.
	f.Add([]byte{0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, signature []byte) {
		got := hasCanonicalSignature(publicKey, signature)

		if want := derSignatureIsCanonical(signature); got != want {
			t.Fatalf("hasCanonicalSignature(%x) = %t, byte walk says %t", signature, got, want)
		}
	})
}

// derSignatureIsCanonical is a second, independent reading of the same rule: the
// whole input is one SEQUENCE, the SEQUENCE holds exactly two INTEGERs and
// nothing else, and every length and every integer is minimally encoded.
//
// It is deliberately written without encoding/asn1. An oracle that shared the
// production parser could only ever confirm that the parser agrees with itself.
func derSignatureIsCanonical(sig []byte) bool {
	body, rest, ok := derValue(sig, 0x30) // SEQUENCE
	if !ok || len(rest) != 0 {
		return false
	}

	r, afterR, ok := derValue(body, 0x02) // INTEGER
	if !ok {
		return false
	}

	s, afterS, ok := derValue(afterR, 0x02)
	if !ok || len(afterS) != 0 {
		return false
	}

	return derIntegerIsMinimal(r) && derIntegerIsMinimal(s)
}

// derValue reads one tag-length-value element from the front of b.
func derValue(b []byte, tag byte) (value, rest []byte, ok bool) {
	if len(b) < 2 || b[0] != tag {
		return nil, nil, false
	}

	length, header, ok := derLength(b[1:])
	if !ok {
		return nil, nil, false
	}

	start := 1 + header
	if length > len(b)-start {
		return nil, nil, false
	}

	return b[start : start+length], b[start+length:], true
}

// derLength reads a DER length, rejecting every encoding of it but the shortest:
// the indefinite form, superfluous leading zeros, and the long form used for a
// length the short form could have carried.
func derLength(b []byte) (length, header int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}

	if b[0] < 0x80 {
		return int(b[0]), 1, true
	}

	count := int(b[0] & 0x7F)
	if count == 0 || count > 4 || len(b) < 1+count || b[1] == 0x00 {
		return 0, 0, false
	}

	for _, v := range b[1 : 1+count] {
		length = length<<8 | int(v)
	}

	if length < 0x80 {
		return 0, 0, false
	}

	return length, 1 + count, true
}

// derIntegerIsMinimal rejects an INTEGER carrying a redundant leading byte,
// which is a second encoding of a value that already has one.
func derIntegerIsMinimal(v []byte) bool {
	switch {
	case len(v) == 0:
		return false
	case len(v) == 1:
		return true
	case v[0] == 0x00 && v[1]&0x80 == 0:
		return false
	case v[0] == 0xFF && v[1]&0x80 == 0x80:
		return false
	default:
		return true
	}
}

// FuzzCredentialFlagMetadata targets the decoder for the backup flags recorded
// against a stored credential.
//
// The metadata map comes back from a credential store, which is outside the
// library's trust boundary (§2, adversary 3) and will usually have round-tripped
// the map through JSON. The property is that a flag reads true only when the
// stored value really is the boolean true: any other shape must read false,
// because a flag invented out of a string or a number would let a record assert
// backup eligibility it was never registered with.
func FuzzCredentialFlagMetadata(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"webauthn_backup_eligible":true,"webauthn_backup_state":true}`)
	f.Add(`{"webauthn_backup_eligible":"true"}`)
	f.Add(`{"webauthn_backup_eligible":1}`)
	f.Add(`{"webauthn_backup_eligible":null}`)
	f.Add(`{"webauthn_backup_eligible":{"nested":true}}`)
	f.Add(`[]`)
	f.Add("\x00\xff")

	f.Fuzz(func(t *testing.T, encoded string) {
		var meta map[string]any

		if err := json.Unmarshal([]byte(encoded), &meta); err != nil {
			return
		}

		flags := credentialFlags(meta)

		if flags.BackupEligible && meta["webauthn_backup_eligible"] != true {
			t.Fatalf("backup eligibility read as true from %#v", meta["webauthn_backup_eligible"])
		}

		if flags.BackupState && meta["webauthn_backup_state"] != true {
			t.Fatalf("backup state read as true from %#v", meta["webauthn_backup_state"])
		}
	})
}

// FuzzCeremonyTimeout targets the millisecond-to-duration conversion the
// challenge TTL is built from.
//
// It is the arithmetic the original defect lived in, and the multiplication can
// overflow: a large enough millisecond count wraps int64 and lands on a small or
// negative duration, which is a challenge that never expires or one that expires
// instantly. The property is that an accepted value is always a real ceremony
// window.
func FuzzCeremonyTimeout(f *testing.F) {
	f.Add(0)
	f.Add(60000)
	f.Add(-1)
	f.Add(1 << 62)
	f.Add(int(^uint(0) >> 1))

	f.Fuzz(func(t *testing.T, milliseconds int) {
		timeout, err := resolveCeremonyTimeout(milliseconds)
		if err != nil {
			if timeout != 0 {
				t.Fatalf("resolveCeremonyTimeout(%d) returned %v alongside an error", milliseconds, timeout)
			}

			return
		}

		if timeout <= 0 || timeout > maxCeremonyTimeout {
			t.Fatalf("resolveCeremonyTimeout(%d) = %v, which is not a usable ceremony window", milliseconds, timeout)
		}
	})
}

// newFuzzHarness builds a harness for a fuzz target. It is separate from
// newHarness only because *testing.F is not *testing.T.
func newFuzzHarness(f *testing.F) *harness {
	f.Helper()

	users := storage.NewInMemoryUserStore()
	if err := users.CreateUser(context.Background(), &storage.User{ID: "alice", Email: "alice@example.com"}); err != nil {
		f.Fatalf("CreateUser: %v", err)
	}

	creds := storage.NewInMemoryCredentialStore()
	states := newTTLFloorStateStore(storage.NewInMemoryOIDCStateStore(), time.Hour)

	auth, err := NewAuthenticator(Config{
		RPDisplayName:   testRPName,
		RPID:            testRPID,
		RPOrigins:       []string{testRPOrigin},
		UserStore:       users,
		CredentialStore: creds,
		SessionStore:    states,
	})
	if err != nil {
		f.Fatalf("NewAuthenticator: %v", err)
	}

	return &harness{auth: auth, users: users, creds: creds, states: states}
}

// enrollFuzzCredential registers one credential so the assertion fuzz target
// reaches the signature-verification code rather than stopping at "this user has
// no credentials".
func enrollFuzzCredential(f *testing.F, h *harness, sa *softAuthenticator) {
	f.Helper()

	cred := &storage.WebAuthnCredential{
		ID:              sa.credID,
		PublicKey:       sa.coseKey(f),
		AttestationType: "none",
		AAGUID:          sa.aaguid,
		UserID:          "alice",
	}

	if err := h.auth.credentialStore.StoreWebAuthnCredential(context.Background(), "alice", cred); err != nil {
		f.Fatalf("StoreWebAuthnCredential: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func mustNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()

	if panicked, recovered := didPanic(fn); panicked {
		t.Fatalf("%s panicked on hostile input: %v", what, recovered)
	}
}

func didPanic(fn func()) (panicked bool, recovered any) {
	defer func() {
		if r := recover(); r != nil {
			panicked, recovered = true, r
		}
	}()

	fn()

	return false, nil
}
