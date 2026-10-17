package webauthn_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

const (
	rpID    = "example.test"
	origin  = "https://app.example.test"
	purpose = "enroll"
)

var (
	alice = webauthn.Subject{ID: "subject-alice", Name: "alice@example.test", DisplayName: "Alice"}
	bob   = webauthn.Subject{ID: "subject-bob", Name: "bob@example.test", DisplayName: "Bob"}

	passkey     = webauthn.RegistrationOptions{Kind: webauthn.Passkey, Purpose: purpose}
	securityKey = webauthn.RegistrationOptions{Kind: webauthn.SecurityKey, Purpose: purpose}
)

// clock is a settable time source the relying party and the flow store share.
// It starts at the wall clock because go-webauthn checks a session's expiry
// against time.Now.
type clock struct {
	t  time.Time
	mu sync.Mutex
}

func newClock() *clock { return &clock{t: time.Now().Truncate(time.Second)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// flowRecorder is a store.FlowStore that records every Put and counts Takes.
type flowRecorder struct {
	store.FlowStore
	puts  []putCall
	takes int
	mu    sync.Mutex
}

type putCall struct {
	id   string
	flow store.Flow
}

func (r *flowRecorder) Put(ctx context.Context, id string, f store.Flow) error {
	r.mu.Lock()
	r.puts = append(r.puts, putCall{id: id, flow: f})
	r.mu.Unlock()
	return r.FlowStore.Put(ctx, id, f)
}

func (r *flowRecorder) Take(ctx context.Context, id string) (store.Flow, error) {
	r.mu.Lock()
	r.takes++
	r.mu.Unlock()
	return r.FlowStore.Take(ctx, id)
}

func (r *flowRecorder) recorded() ([]putCall, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.puts), r.takes
}

// listOverride is a CredentialStore whose List answers from a function.
type listOverride struct {
	webauthn.CredentialStore
	list func(subject, rpID string) ([]webauthn.Credential, error)
}

func (s listOverride) List(_ context.Context, subject, rpID string) ([]webauthn.Credential, error) {
	return s.list(subject, rpID)
}

type harness struct {
	rp    *webauthn.RP
	clock *clock
	flows *flowRecorder
	creds *authtest.MemoryWebAuthnStore
}

// newHarness returns a relying party for example.test with memory stores;
// edit, when non-nil, changes the configuration first.
func newHarness(t *testing.T, edit func(*webauthn.Config)) *harness {
	t.Helper()
	clk := newClock()
	cfg := webauthn.Config{RPID: rpID, RPName: "Example", Origins: []string{origin}, Now: clk.Now}
	if edit != nil {
		edit(&cfg)
	}
	rp, err := webauthn.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{
		rp:    rp,
		clock: clk,
		flows: &flowRecorder{FlowStore: authtest.NewMemoryFlowStore(clk.Now)},
		creds: authtest.NewMemoryWebAuthnStore(),
	}
}

func (h *harness) begin(t *testing.T, sub webauthn.Subject, opts webauthn.RegistrationOptions) webauthn.Begun {
	t.Helper()
	b, err := h.rp.BeginRegistration(t.Context(), h.flows, h.creds, h.creds, sub, opts)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	return b
}

func expectFor(sub webauthn.Subject, b webauthn.Begun) webauthn.Expect {
	return webauthn.Expect{FlowID: b.FlowID, Purpose: purpose, Subject: sub.ID}
}

func (h *harness) finish(t *testing.T, e webauthn.Expect, response []byte) (webauthn.Credential, error) {
	t.Helper()
	return h.rp.FinishRegistration(t.Context(), h.flows, h.creds, e, response)
}

// attempt runs one registration: Begin, a answers the options with tampers,
// edit (when non-nil) changes the Expect, and Finish.
func (h *harness) attempt(t *testing.T, a *authtest.Authenticator, sub webauthn.Subject, opts webauthn.RegistrationOptions, edit func(*webauthn.Expect), tampers ...authtest.Tamper) (webauthn.Credential, error) {
	t.Helper()
	b := h.begin(t, sub, opts)
	e := expectFor(sub, b)
	if edit != nil {
		edit(&e)
	}
	return h.finish(t, e, respond(t, a, b, tampers...))
}

func (h *harness) list(t *testing.T, sub webauthn.Subject) []webauthn.Credential {
	t.Helper()
	got, err := h.creds.List(t.Context(), sub.ID, rpID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return got
}

// requireRefused fails unless err is ErrInvalidCredentials and sub holds no
// credential.
func (h *harness) requireRefused(t *testing.T, err error, sub webauthn.Subject) {
	t.Helper()
	if !errors.Is(err, webauthn.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if got := h.list(t, sub); len(got) != 0 {
		t.Fatalf("a refused registration stored %d credential(s)", len(got))
	}
}

func respond(t *testing.T, a *authtest.Authenticator, b webauthn.Begun, tampers ...authtest.Tamper) []byte {
	t.Helper()
	resp, err := a.Register(b.Options, origin, tampers...)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return resp
}

func newAuthenticator(t *testing.T, cfg authtest.AuthenticatorConfig) *authtest.Authenticator {
	t.Helper()
	a, err := authtest.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// passkeyAuthenticator verifies the user and keeps a discoverable credential.
func passkeyAuthenticator(t *testing.T) *authtest.Authenticator {
	t.Helper()
	return newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true})
}

func isSentinel(err error) bool {
	return errors.Is(err, webauthn.ErrInvalidCredentials) || errors.Is(err, webauthn.ErrUnknownCredential) ||
		errors.Is(err, webauthn.ErrCloneSuspected)
}

// creationOptions is the part of the creation options JSON the tests read.
type creationOptions struct {
	User                   userEntity             `json:"user"`
	PubKeyCredParams       []credentialParameter  `json:"pubKeyCredParams"`
	ExcludeCredentials     []credentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection authenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
	Hints                  []string               `json:"hints"`
	Extensions             creationExtensions     `json:"extensions"`
}

type userEntity struct {
	ID protocol.URLEncodedBase64 `json:"id"`
}

type credentialParameter struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type credentialDescriptor struct {
	Type string                    `json:"type"`
	ID   protocol.URLEncodedBase64 `json:"id"`
}

type authenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

type creationExtensions struct {
	CredProps bool `json:"credProps"`
}

func decodeOptions(t *testing.T, b webauthn.Begun) creationOptions {
	t.Helper()
	var o creationOptions
	if err := json.Unmarshal(b.Options, &o); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	return o
}

func clearUserPresence(c *authtest.Ceremony) { c.Flags &^= byte(protocol.FlagUserPresent) }

func TestRegister_Passkey_StoresCredential(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	aaguid := [16]byte{0xa1, 0xb2, 0xc3, 0xd4, 15: 0x01}
	a := newAuthenticator(t, authtest.AuthenticatorConfig{
		UserVerified: true, Discoverable: true, BackupEligible: true, BackupState: true, AAGUID: aaguid,
	})

	got, err := h.attempt(t, a, alice, passkey, nil)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	stored := h.list(t, alice)
	if len(stored) != 1 {
		t.Fatalf("List returned %d credentials, want 1", len(stored))
	}
	c := stored[0]
	switch {
	case c.Version != webauthn.CurrentVersion:
		t.Errorf("Version = %d, want %d", c.Version, webauthn.CurrentVersion)
	case c.RPID != rpID:
		t.Errorf("RPID = %q, want %q", c.RPID, rpID)
	case c.Subject != alice.ID:
		t.Errorf("Subject = %q, want %q", c.Subject, alice.ID)
	case !bytes.Equal(c.ID, a.CredentialID()):
		t.Errorf("ID = %x, want the authenticator's %x", c.ID, a.CredentialID())
	case len(c.PublicKey) == 0:
		t.Error("PublicKey is empty")
	case c.Algorithm != -7:
		t.Errorf("Algorithm = %d, want -7", c.Algorithm)
	case c.Discoverable == nil || !*c.Discoverable:
		t.Errorf("Discoverable = %v, want true", c.Discoverable)
	case !c.UVInitialized:
		t.Error("UVInitialized = false, want true")
	case !c.BackupEligible || !c.BackupState:
		t.Errorf("BackupEligible, BackupState = %v, %v, want true, true", c.BackupEligible, c.BackupState)
	case c.AAGUID != aaguid:
		t.Errorf("AAGUID = %x, want %x", c.AAGUID, aaguid)
	case !slices.Equal(c.Transports, []string{"internal"}):
		t.Errorf("Transports = %q, want [internal]", c.Transports)
	case c.SignCount != 0:
		t.Errorf("SignCount = %d, want 0", c.SignCount)
	case !c.CreatedAt.Equal(h.clock.Now()):
		t.Errorf("CreatedAt = %v, want %v", c.CreatedAt, h.clock.Now())
	case !c.LastUsedAt.IsZero() || !c.CloneSuspectedAt.IsZero():
		t.Errorf("LastUsedAt, CloneSuspectedAt = %v, %v, want zero", c.LastUsedAt, c.CloneSuspectedAt)
	}
	if !reflect.DeepEqual(got, c) {
		t.Errorf("FinishRegistration returned %+v, the store holds %+v", got, c)
	}
}

// The stored algorithm is the attested COSE key's, never the client-reported
// publicKeyAlgorithm, which no signature covers.
func TestRegister_AlgorithmFromAttestedKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		key     int // the authenticator's real key
		claimed int // the forged publicKeyAlgorithm
	}{
		{"ES256 key claimed as RS256", -7, -257},
		{"Ed25519 key claimed as ES256", -8, -7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := newAuthenticator(t, authtest.AuthenticatorConfig{Algorithm: tc.key, UserVerified: true, Discoverable: true})
			c, err := h.attempt(t, a, alice, passkey, nil, func(c *authtest.Ceremony) { c.ReportedAlgorithm = tc.claimed })
			if err != nil {
				t.Fatalf("FinishRegistration: %v", err)
			}
			if c.Algorithm != tc.key {
				t.Fatalf("Algorithm = %d, want the key's %d", c.Algorithm, tc.key)
			}
		})
	}
}

func TestRegister_Passkey_Options(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b := h.begin(t, alice, passkey)
	o := decodeOptions(t, b)

	algs := make([]int, len(o.PubKeyCredParams))
	for i, p := range o.PubKeyCredParams {
		algs[i] = p.Alg
	}
	switch {
	case o.AuthenticatorSelection.ResidentKey != "required":
		t.Errorf("residentKey = %q, want required", o.AuthenticatorSelection.ResidentKey)
	case o.AuthenticatorSelection.UserVerification != "required":
		t.Errorf("userVerification = %q, want required", o.AuthenticatorSelection.UserVerification)
	case o.Attestation != "none":
		t.Errorf("attestation = %q, want none", o.Attestation)
	case !slices.Equal(algs, []int{-8, -7, -257}):
		t.Errorf("pubKeyCredParams algs = %v, want [-8 -7 -257]", algs)
	case !o.Extensions.CredProps:
		t.Error("extensions.credProps is not requested")
	case len(o.User.ID) != 64:
		t.Errorf("user.id is %d bytes, want 64", len(o.User.ID))
	case len(o.ExcludeCredentials) != 0:
		t.Errorf("excludeCredentials = %v, want none", o.ExcludeCredentials)
	case len(o.Hints) != 0:
		t.Errorf("hints = %q, want none", o.Hints)
	case b.Mediation != "":
		t.Errorf("Mediation = %q, want empty", b.Mediation)
	}
}

func TestRegister_SecurityKey_Options(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b := h.begin(t, alice, securityKey)
	o := decodeOptions(t, b)
	switch {
	case o.AuthenticatorSelection.ResidentKey != "discouraged":
		t.Errorf("residentKey = %q, want discouraged", o.AuthenticatorSelection.ResidentKey)
	case o.AuthenticatorSelection.UserVerification != "preferred":
		t.Errorf("userVerification = %q, want preferred", o.AuthenticatorSelection.UserVerification)
	case !slices.Equal(o.Hints, []string{"security-key"}):
		t.Errorf("hints = %q, want [security-key]", o.Hints)
	case b.Mediation != "":
		t.Errorf("Mediation = %q, want empty", b.Mediation)
	}
}

func TestRegister_SecurityKey_WithoutUserVerification(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{})
	c, err := h.attempt(t, a, alice, securityKey, nil)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if c.UVInitialized || c.BackupEligible || c.Discoverable == nil || *c.Discoverable {
		t.Fatalf("UVInitialized, BackupEligible, Discoverable = %v, %v, %v, want false, false, false",
			c.UVInitialized, c.BackupEligible, c.Discoverable)
	}
}

func TestRegister_ExcludesExistingCredentials(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	first := passkeyAuthenticator(t)
	if _, err := h.attempt(t, first, alice, passkey, nil); err != nil {
		t.Fatalf("first registration: %v", err)
	}

	o := decodeOptions(t, h.begin(t, alice, securityKey))
	if len(o.ExcludeCredentials) != 1 || !bytes.Equal(o.ExcludeCredentials[0].ID, first.CredentialID()) ||
		o.ExcludeCredentials[0].Type != "public-key" {
		t.Fatalf("excludeCredentials = %+v, want exactly the first credential %x", o.ExcludeCredentials, first.CredentialID())
	}
}

func TestRegister_UserHandleStableAcrossRegistrations(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b1 := h.begin(t, alice, passkey)
	if _, err := h.finish(t, expectFor(alice, b1), respond(t, passkeyAuthenticator(t), b1)); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	b2 := h.begin(t, alice, securityKey)

	first, second := decodeOptions(t, b1).User.ID, decodeOptions(t, b2).User.ID
	if !bytes.Equal(first, second) {
		t.Fatalf("user.id changed between registrations: %x then %x", first, second)
	}
	if bytes.Equal(first, []byte(alice.ID)) {
		t.Fatal("user.id is the subject ID")
	}
	if sub, err := h.creds.Subject(t.Context(), first); err != nil || sub != alice.ID {
		t.Fatalf("Subject(user.id) = %q, %v, want %q", sub, err, alice.ID)
	}
	if other := decodeOptions(t, h.begin(t, bob, passkey)).User.ID; bytes.Equal(other, first) {
		t.Fatal("two subjects share a user handle")
	}
}

func TestRegister_Conditional(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	opts := passkey
	opts.Conditional = true
	b := h.begin(t, alice, opts)
	if b.Mediation != "conditional" {
		t.Errorf("Mediation = %q, want conditional", b.Mediation)
	}
	if uv := decodeOptions(t, b).AuthenticatorSelection.UserVerification; uv != "preferred" {
		t.Errorf("userVerification = %q, want preferred", uv)
	}

	a := newAuthenticator(t, authtest.AuthenticatorConfig{Discoverable: true}) // UV=0
	c, err := h.finish(t, expectFor(alice, b), respond(t, a, b, clearUserPresence))
	if err != nil {
		t.Fatalf("FinishRegistration (UP=0, UV=0, conditional): %v", err)
	}
	if c.UVInitialized {
		t.Fatal("UVInitialized = true for a response without UV")
	}
}

func TestRegister_WrongOrigin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, nil,
		func(c *authtest.Ceremony) { c.Origin = "https://evil.example.test" })
	h.requireRefused(t, err, alice)
}

// A cross-origin iframe on another site: crossOrigin true with its topOrigin.
func TestRegister_TopOrigin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, nil, func(c *authtest.Ceremony) {
		c.CrossOrigin = true
		c.TopOrigin = "https://evil.example"
	})
	h.requireRefused(t, err, alice)
}

func TestRegister_TopOriginOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, nil,
		func(c *authtest.Ceremony) { c.TopOrigin = "https://evil.example" })
	h.requireRefused(t, err, alice)
}

func TestRegister_ReplayedFlow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b := h.begin(t, alice, passkey)
	if _, err := h.finish(t, expectFor(alice, b), respond(t, passkeyAuthenticator(t), b)); err != nil {
		t.Fatalf("first Finish: %v", err)
	}

	_, err := h.finish(t, expectFor(alice, b), respond(t, passkeyAuthenticator(t), b))
	if !errors.Is(err, webauthn.ErrInvalidCredentials) {
		t.Fatalf("second Finish on the same flow: err = %v, want ErrInvalidCredentials", err)
	}
	if got := h.list(t, alice); len(got) != 1 {
		t.Fatalf("the replayed flow left %d credentials, want 1", len(got))
	}
}

func TestRegister_ExpiredFlow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b := h.begin(t, alice, passkey)
	h.clock.Advance(6 * time.Minute)
	_, err := h.finish(t, expectFor(alice, b), respond(t, passkeyAuthenticator(t), b))
	h.requireRefused(t, err, alice)
}

func TestRegister_WrongPurpose(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, func(e *webauthn.Expect) { e.Purpose = "stepup" })
	h.requireRefused(t, err, alice)
}

func TestRegister_WrongSubject(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, subject string }{
		{"another subject", bob.ID},
		{"no subject", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, func(e *webauthn.Expect) { e.Subject = tc.subject })
			h.requireRefused(t, err, alice)
			if got, listErr := h.creds.List(t.Context(), bob.ID, rpID); listErr != nil || len(got) != 0 {
				t.Fatalf("List(bob) = %d credentials, %v, want none", len(got), listErr)
			}
		})
	}
}

// A flow of another ceremony is refused even when its payload, purpose and
// subject would all pass: the copy differs from a genuine registration flow
// in its kind only.
func TestRegister_FlowOfAnotherKind(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b := h.begin(t, alice, passkey)
	puts, _ := h.flows.recorded()
	foreign := puts[0].flow
	foreign.Kind = "webauthn.passkey"
	const foreignID = "foreign-flow-id"
	if err := h.flows.Put(t.Context(), foreignID, foreign); err != nil {
		t.Fatalf("Put: %v", err)
	}

	e := expectFor(alice, b)
	e.FlowID = foreignID
	_, err := h.finish(t, e, respond(t, passkeyAuthenticator(t), b))
	h.requireRefused(t, err, alice)
}

// Two relying parties share one flow store and accept the same origin: a
// flow begun for one must not finish on the other.
func TestRegister_FlowOfAnotherRP(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	other, err := webauthn.New(webauthn.Config{
		RPID: "app.example.test", RPName: "Other", Origins: []string{origin}, Now: h.clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b := h.begin(t, alice, passkey)
	_, err = other.FinishRegistration(t.Context(), h.flows, h.creds, expectFor(alice, b), respond(t, passkeyAuthenticator(t), b))
	h.requireRefused(t, err, alice)
	if got, listErr := h.creds.List(t.Context(), alice.ID, "app.example.test"); listErr != nil || len(got) != 0 {
		t.Fatalf("List(app.example.test) = %d credentials, %v, want none", len(got), listErr)
	}
}

func TestRegister_EmptyFlowID(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, func(e *webauthn.Expect) { e.FlowID = "" })
	h.requireRefused(t, err, alice)
	if _, takes := h.flows.recorded(); takes != 0 {
		t.Fatalf("an empty flow ID reached the store (%d Take calls)", takes)
	}
}

func TestRegister_DisallowedAlgorithm(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(c *webauthn.Config) { c.Algorithms = []int{-7} })
	a := newAuthenticator(t, authtest.AuthenticatorConfig{Algorithm: -8, UserVerified: true, Discoverable: true})
	_, err := h.attempt(t, a, alice, passkey, nil)
	h.requireRefused(t, err, alice)
}

// The client claims an allowed algorithm for a key of a refused one.
func TestRegister_DisallowedAlgorithm_ForgedClaim(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(c *webauthn.Config) { c.Algorithms = []int{-7} })
	a := newAuthenticator(t, authtest.AuthenticatorConfig{Algorithm: -8, UserVerified: true, Discoverable: true})
	_, err := h.attempt(t, a, alice, passkey, nil, func(c *authtest.Ceremony) { c.ReportedAlgorithm = -7 })
	h.requireRefused(t, err, alice)
}

func TestRegister_BackupStateWithoutEligibility(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true, BackupState: true})
	_, err := h.attempt(t, a, alice, passkey, nil)
	h.requireRefused(t, err, alice)
}

func TestRegister_WithoutUserPresence(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.attempt(t, passkeyAuthenticator(t), alice, passkey, nil, clearUserPresence)
	h.requireRefused(t, err, alice)
}

func TestRegister_Passkey_WithoutUserVerification(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{Discoverable: true}) // UV=0
	_, err := h.attempt(t, a, alice, passkey, nil)
	h.requireRefused(t, err, alice)
}

// A body that is not JSON still consumes the flow: flows are single-use.
func TestRegister_NotJSON(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	b := h.begin(t, alice, passkey)
	_, err := h.finish(t, expectFor(alice, b), []byte("not json"))
	h.requireRefused(t, err, alice)

	_, err = h.finish(t, expectFor(alice, b), respond(t, passkeyAuthenticator(t), b))
	h.requireRefused(t, err, alice)
}

// A valid response padded with JSON whitespace: the size alone decides.
func TestRegister_OversizedResponse(t *testing.T) {
	t.Parallel()
	const limit = 64 << 10
	tests := []struct {
		name   string
		size   int
		refuse bool
	}{
		{"at the limit", limit, false},
		{"one byte over", limit + 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			b := h.begin(t, alice, passkey)
			resp := respond(t, passkeyAuthenticator(t), b)
			resp = append(resp, bytes.Repeat([]byte(" "), tc.size-len(resp))...)

			_, err := h.finish(t, expectFor(alice, b), resp)
			if tc.refuse {
				h.requireRefused(t, err, alice)
				return
			}
			if err != nil {
				t.Fatalf("FinishRegistration with a %d-byte response: %v", tc.size, err)
			}
		})
	}
}

func TestRegister_SameAuthenticatorOtherSubject_ErrDuplicate(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	if _, err := h.attempt(t, a, alice, passkey, nil); err != nil {
		t.Fatalf("alice's registration: %v", err)
	}

	_, err := h.attempt(t, a, bob, passkey, nil)
	if !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("err = %v, want store.ErrDuplicate", err)
	}
	if isSentinel(err) {
		t.Fatalf("err = %v also matches a webauthn sentinel", err)
	}
	if got := h.list(t, bob); len(got) != 0 {
		t.Fatalf("bob holds %d credential(s), want none", len(got))
	}
}

func TestBeginRegistration_FlowRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	start := time.Now()
	b := h.begin(t, alice, passkey)
	end := time.Now()

	puts, _ := h.flows.recorded()
	if len(puts) != 1 {
		t.Fatalf("Begin wrote %d flows, want 1", len(puts))
	}
	p := puts[0]
	if p.id != b.FlowID || p.flow.Kind != "webauthn.register" {
		t.Errorf("flow %q of kind %q, want %q of kind webauthn.register", p.id, p.flow.Kind, b.FlowID)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(b.FlowID); err != nil || len(raw) != 32 {
		t.Errorf("FlowID %q is not 32 bytes of base64url (%d bytes, %v)", b.FlowID, len(raw), err)
	}
	// go-webauthn sets the session's expiry from the wall clock; the flow
	// expires with it.
	if p.flow.ExpiresAt.Before(start.Add(5*time.Minute)) || p.flow.ExpiresAt.After(end.Add(5*time.Minute)) {
		t.Errorf("ExpiresAt = %v, want Begin's wall clock plus 5m (%v to %v)", p.flow.ExpiresAt, start, end)
	}
}

// Programming errors are refused before any state is written, with an error
// that is not a verification failure.
func TestBeginRegistration_RefusesBadInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sub  webauthn.Subject
		opts webauthn.RegistrationOptions
	}{
		{"zero kind", alice, webauthn.RegistrationOptions{Purpose: purpose}},
		{"unknown kind", alice, webauthn.RegistrationOptions{Kind: 3, Purpose: purpose}},
		{"empty purpose", alice, webauthn.RegistrationOptions{Kind: webauthn.Passkey}},
		{"empty subject ID", webauthn.Subject{Name: "alice@example.test"}, passkey},
		{"empty subject name", webauthn.Subject{ID: alice.ID}, passkey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			_, err := h.rp.BeginRegistration(t.Context(), h.flows, h.creds, h.creds, tc.sub, tc.opts)
			if err == nil || isSentinel(err) {
				t.Fatalf("err = %v, want a plain error", err)
			}
			if puts, _ := h.flows.recorded(); len(puts) != 0 {
				t.Fatalf("a refused Begin wrote %d flow(s)", len(puts))
			}
		})
	}
}

// Design §4.2 rule 3: a credential the store answers with a zero value where
// the library needs one, or of another subject or RP ID, is a store fault.
func TestBeginRegistration_StoreFault(t *testing.T) {
	t.Parallel()
	valid := webauthn.Credential{
		Version: webauthn.CurrentVersion, ID: []byte{1, 2, 3}, Subject: alice.ID, RPID: rpID,
		PublicKey: []byte{4, 5, 6}, Algorithm: -7, CreatedAt: time.Unix(1_700_000_000, 0),
	}
	tests := []struct {
		name  string
		edit  func(*webauthn.Credential)
		fault bool
	}{
		{"valid", func(*webauthn.Credential) {}, false},
		{"zero version", func(c *webauthn.Credential) { c.Version = 0 }, true},
		{"empty ID", func(c *webauthn.Credential) { c.ID = nil }, true},
		{"empty public key", func(c *webauthn.Credential) { c.PublicKey = nil }, true},
		{"empty RP ID", func(c *webauthn.Credential) { c.RPID = "" }, true},
		{"zero CreatedAt", func(c *webauthn.Credential) { c.CreatedAt = time.Time{} }, true},
		{"another subject", func(c *webauthn.Credential) { c.Subject = bob.ID }, true},
		{"another RP ID", func(c *webauthn.Credential) { c.RPID = "other.test" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			c := valid
			tc.edit(&c)
			creds := listOverride{CredentialStore: h.creds, list: func(string, string) ([]webauthn.Credential, error) {
				return []webauthn.Credential{c}, nil
			}}
			_, err := h.rp.BeginRegistration(t.Context(), h.flows, creds, h.creds, alice, passkey)
			puts, _ := h.flows.recorded()
			if !tc.fault {
				if err != nil || len(puts) != 1 {
					t.Fatalf("valid credential: err = %v, %d flow(s) written", err, len(puts))
				}
				return
			}
			if !errors.Is(err, webauthn.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			if len(puts) != 0 {
				t.Fatalf("a store fault wrote %d flow(s)", len(puts))
			}
		})
	}
}

// A failing store is an infrastructure error, never a verification result.
func TestBeginRegistration_StoreError(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	down := errors.New("database is down")
	creds := listOverride{CredentialStore: h.creds, list: func(string, string) ([]webauthn.Credential, error) {
		return nil, down
	}}
	_, err := h.rp.BeginRegistration(t.Context(), h.flows, creds, h.creds, alice, passkey)
	if !errors.Is(err, down) || isSentinel(err) {
		t.Fatalf("err = %v, want the store's error and no sentinel", err)
	}
	if puts, _ := h.flows.recorded(); len(puts) != 0 {
		t.Fatalf("a failed Begin wrote %d flow(s)", len(puts))
	}
}
