package webauthn_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/meysam81/go-auth/v2/amr"
	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

const signInPurpose = "login"

var signIn = webauthn.PasskeyOptions{Purpose: signInPurpose}

// recordOverride is a CredentialStore whose RecordAssertion answers from a
// function after recording the update.
type recordOverride struct {
	webauthn.CredentialStore
	record  func(webauthn.AssertionUpdate) (bool, error)
	updates []webauthn.AssertionUpdate
	mu      sync.Mutex
}

func (s *recordOverride) RecordAssertion(ctx context.Context, u webauthn.AssertionUpdate) (bool, error) {
	s.mu.Lock()
	s.updates = append(s.updates, u)
	s.mu.Unlock()
	if s.record == nil {
		return s.CredentialStore.RecordAssertion(ctx, u)
	}
	return s.record(u)
}

func (s *recordOverride) recorded() []webauthn.AssertionUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.updates)
}

// markOverride is a CredentialStore whose MarkCloneSuspected fails with err.
type markOverride struct {
	webauthn.CredentialStore
	err error
}

func (s markOverride) MarkCloneSuspected(context.Context, string, []byte, time.Time) error {
	return s.err
}

// subjectOverride is a HandleStore whose Subject answers from a function.
type subjectOverride struct {
	webauthn.HandleStore
	subject func([]byte) (string, error)
}

func (s subjectOverride) Subject(_ context.Context, handle []byte) (string, error) {
	return s.subject(handle)
}

func (h *harness) beginPasskey(t *testing.T, opts webauthn.PasskeyOptions) webauthn.Begun {
	t.Helper()
	b, err := h.rp.BeginPasskey(t.Context(), h.flows, opts)
	if err != nil {
		t.Fatalf("BeginPasskey: %v", err)
	}
	return b
}

func signInExpect(b webauthn.Begun) webauthn.Expect {
	return webauthn.Expect{FlowID: b.FlowID, Purpose: signInPurpose}
}

func (h *harness) finishPasskey(t *testing.T, e webauthn.Expect, response []byte) (webauthn.Verified, error) {
	t.Helper()
	return h.rp.FinishPasskey(t.Context(), h.flows, h.creds, h.creds, e, response)
}

// signIn runs one passkey sign-in: Begin, a answers the options with tampers,
// and Finish.
func (h *harness) signIn(t *testing.T, a *authtest.Authenticator, tampers ...authtest.Tamper) (webauthn.Verified, error) {
	t.Helper()
	b := h.beginPasskey(t, signIn)
	return h.finishPasskey(t, signInExpect(b), assertion(t, a, b, tampers...))
}

func assertion(t *testing.T, a *authtest.Authenticator, b webauthn.Begun, tampers ...authtest.Tamper) []byte {
	t.Helper()
	resp, err := a.Assert(b.Options, origin, tampers...)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	return resp
}

// enroll registers a's passkey for sub and returns the stored credential.
func (h *harness) enroll(t *testing.T, a *authtest.Authenticator, sub webauthn.Subject) webauthn.Credential {
	t.Helper()
	c, err := h.attempt(t, a, sub, passkey, nil)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return c
}

// rewrite replaces sub's only credential with edit applied, standing in for
// a credential imported or changed outside the library.
func (h *harness) rewrite(t *testing.T, sub webauthn.Subject, edit func(*webauthn.Credential)) {
	t.Helper()
	list := h.list(t, sub)
	if len(list) != 1 {
		t.Fatalf("%s holds %d credentials, want 1", sub.ID, len(list))
	}
	c := list[0]
	h.creds.Delete(sub.ID, c.ID)
	edit(&c)
	if err := h.creds.Insert(t.Context(), c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

// only returns sub's only credential.
func (h *harness) only(t *testing.T, sub webauthn.Subject) webauthn.Credential {
	t.Helper()
	list := h.list(t, sub)
	if len(list) != 1 {
		t.Fatalf("%s holds %d credentials, want 1", sub.ID, len(list))
	}
	return list[0]
}

// requireOnly fails unless err matches sentinel and no other webauthn
// sentinel.
func requireOnly(t *testing.T, err, sentinel error) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	n := 0
	for _, s := range []error{webauthn.ErrInvalidCredentials, webauthn.ErrUnknownCredential, webauthn.ErrCloneSuspected} {
		if errors.Is(err, s) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("err = %v matches %d sentinels, want exactly one", err, n)
	}
}

// requireSignInRefused fails unless err matches only sentinel and no
// credential of sub recorded a use or a clone suspicion.
func (h *harness) requireSignInRefused(t *testing.T, err, sentinel error, sub webauthn.Subject) {
	t.Helper()
	requireOnly(t, err, sentinel)
	list := h.list(t, sub)
	for i := range list {
		if c := &list[i]; !c.LastUsedAt.IsZero() || !c.CloneSuspectedAt.IsZero() {
			t.Fatalf("a refused sign-in changed credential %x: LastUsedAt %v, CloneSuspectedAt %v",
				c.ID, c.LastUsedAt, c.CloneSuspectedAt)
		}
	}
}

func setFlag(f protocol.AuthenticatorFlags) authtest.Tamper {
	return func(c *authtest.Ceremony) { c.Flags |= byte(f) }
}

func clearFlag(f protocol.AuthenticatorFlags) authtest.Tamper {
	return func(c *authtest.Ceremony) { c.Flags &^= byte(f) }
}

// editJSON decodes resp's top-level members, lets edit change them, and
// encodes the result.
func editJSON(t *testing.T, resp []byte, edit func(map[string]json.RawMessage)) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(resp, &top); err != nil {
		t.Fatalf("decode: %v", err)
	}
	edit(top)
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out
}

// berSignature re-encodes the assertion's DER ECDSA signature with r padded
// by one leading zero byte: the same integers in valid BER that DER forbids.
func berSignature(t *testing.T, resp []byte) []byte {
	t.Helper()
	return editJSON(t, resp, func(top map[string]json.RawMessage) {
		var r map[string]string
		if err := json.Unmarshal(top["response"], &r); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		der, err := base64.RawURLEncoding.DecodeString(r["signature"])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		// SEQUENCE { INTEGER r, INTEGER s }; every length of a P-256
		// signature fits the short form.
		if len(der) < 8 || der[0] != 0x30 || int(der[1]) != len(der)-2 || der[2] != 0x02 {
			t.Fatalf("signature %x is not a short-form DER ECDSA signature", der)
		}
		rLen := int(der[3])
		inner := append([]byte{0x02, byte(rLen + 1), 0x00}, der[4:4+rLen]...)
		inner = append(inner, der[4+rLen:]...)
		r["signature"] = base64.RawURLEncoding.EncodeToString(append([]byte{0x30, byte(len(inner))}, inner...))
		if top["response"], err = json.Marshal(r); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	})
}

// handleOf returns sub's user handle.
func (h *harness) handleOf(t *testing.T, sub webauthn.Subject) []byte {
	t.Helper()
	handle, err := h.creds.Ensure(t.Context(), sub.ID, bytes.Repeat([]byte{0xee}, 64))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return handle
}

func TestPasskey_SyncedPasskey(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	aaguid := [16]byte{0xa1, 15: 0x07}
	a := newAuthenticator(t, authtest.AuthenticatorConfig{
		UserVerified: true, Discoverable: true, BackupEligible: true, BackupState: true, AAGUID: aaguid,
	})
	h.enroll(t, a, alice)
	h.clock.Advance(time.Minute)
	creds := &recordOverride{CredentialStore: h.creds}

	b := h.beginPasskey(t, signIn)
	v, err := h.rp.FinishPasskey(t.Context(), h.flows, creds, h.creds, signInExpect(b), assertion(t, a, b))
	if err != nil {
		t.Fatalf("FinishPasskey: %v", err)
	}

	now := h.clock.Now()
	want := webauthn.Verified{
		Subject: alice.ID, CredentialID: a.CredentialID(), UserVerified: true,
		BackupEligible: true, BackupState: true, AAGUID: aaguid,
		Methods: []amr.Method{amr.SWK, amr.MFA}, At: now,
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("Verified = %+v, want %+v", v, want)
	}
	wantUpdate := webauthn.AssertionUpdate{
		Subject: alice.ID, CredentialID: a.CredentialID(), PrevSignCount: 0, SignCount: 0,
		BackupEligible: true, BackupState: true, Version: webauthn.CurrentVersion, At: now,
	}
	if got := creds.recorded(); len(got) != 1 || !reflect.DeepEqual(got[0], wantUpdate) {
		t.Errorf("RecordAssertion calls = %+v, want one %+v", got, wantUpdate)
	}
}

func TestPasskey_DeviceBound(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true, CounterStep: 1})
	h.enroll(t, a, alice)

	for want := uint32(1); want <= 2; want++ {
		h.clock.Advance(time.Minute)
		v, err := h.signIn(t, a)
		if err != nil {
			t.Fatalf("sign-in %d: %v", want, err)
		}
		if !slices.Equal(v.Methods, []amr.Method{amr.HWK, amr.MFA}) || v.BackupEligible || v.BackupState {
			t.Errorf("sign-in %d: Methods %v, BE %v, BS %v, want [hwk mfa], false, false", want, v.Methods, v.BackupEligible, v.BackupState)
		}
		c := h.only(t, alice)
		if c.SignCount != want || !c.LastUsedAt.Equal(h.clock.Now()) || !v.At.Equal(h.clock.Now()) {
			t.Errorf("sign-in %d: stored SignCount %d, LastUsedAt %v, Verified.At %v, want %d, %v, %v",
				want, c.SignCount, c.LastUsedAt, v.At, want, h.clock.Now(), h.clock.Now())
		}
	}
}

// assertionOptions is the part of the request options JSON the tests read.
type assertionOptions struct {
	RPID             string `json:"rpId"`
	UserVerification string `json:"userVerification"`
	Timeout          int    `json:"timeout"`
}

func TestPasskey_Options(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		opts      webauthn.PasskeyOptions
		mediation string
	}{
		{"modal", signIn, ""},
		{"conditional", webauthn.PasskeyOptions{Purpose: signInPurpose, Conditional: true}, "conditional"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			b := h.beginPasskey(t, tc.opts)

			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b.Options, &raw); err != nil {
				t.Fatalf("decode options: %v", err)
			}
			var o assertionOptions
			if err := json.Unmarshal(b.Options, &o); err != nil {
				t.Fatalf("decode options: %v", err)
			}
			if _, ok := raw["allowCredentials"]; ok {
				t.Errorf("allowCredentials = %s, want absent", raw["allowCredentials"])
			}
			switch {
			case o.UserVerification != "required":
				t.Errorf("userVerification = %q, want required", o.UserVerification)
			case o.RPID != rpID:
				t.Errorf("rpId = %q, want %q", o.RPID, rpID)
			case o.Timeout != int((5 * time.Minute).Milliseconds()):
				t.Errorf("timeout = %d, want 300000", o.Timeout)
			case b.Mediation != tc.mediation:
				t.Errorf("Mediation = %q, want %q", b.Mediation, tc.mediation)
			}
			if puts, _ := h.flows.recorded(); len(puts) != 1 || puts[0].id != b.FlowID || puts[0].flow.Kind != "webauthn.passkey" {
				t.Errorf("flows written = %+v, want one webauthn.passkey flow %q", puts, b.FlowID)
			}
		})
	}
}

func TestBeginPasskey_RefusesEmptyPurpose(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	_, err := h.rp.BeginPasskey(t.Context(), h.flows, webauthn.PasskeyOptions{})
	if err == nil || isSentinel(err) {
		t.Fatalf("err = %v, want a plain error", err)
	}
	if puts, _ := h.flows.recorded(); len(puts) != 0 {
		t.Fatalf("a refused Begin wrote %d flow(s)", len(puts))
	}
}

// Check 3: a passkey sign-in without user verification is refused, never
// downgraded to a single factor.
func TestPasskey_WithoutUserVerification(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, clearFlag(protocol.FlagUserVerified))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

func TestPasskey_WithoutUserPresence(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, clearUserPresence)
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// A discoverable assertion without a user handle names no subject to look
// up, and one longer than WebAuthn's 64 bytes is no handle any subject holds:
// both are malformed, refused before the handle store is asked.
func TestPasskey_MalformedUserHandle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		handle []byte
	}{
		{"missing", nil},
		{"65 bytes", bytes.Repeat([]byte{0x5a}, 65)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := passkeyAuthenticator(t)
			h.enroll(t, a, alice)
			lookups := 0
			handles := subjectOverride{HandleStore: h.creds, subject: func(handle []byte) (string, error) {
				lookups++
				return h.creds.Subject(t.Context(), handle)
			}}
			b := h.beginPasskey(t, signIn)
			resp := assertion(t, a, b, func(c *authtest.Ceremony) { c.UserHandle = tc.handle })
			_, err := h.rp.FinishPasskey(t.Context(), h.flows, h.creds, handles, signInExpect(b), resp)
			h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
			if lookups != 0 {
				t.Fatalf("a malformed user handle reached the handle store (%d Subject calls)", lookups)
			}
		})
	}
}

// A passkey sign-in has no subject until the assertion names one; an Expect
// that names a subject is refused.
func TestPasskey_ExpectNamesSubject(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	e := signInExpect(b)
	e.Subject = alice.ID
	_, err := h.finishPasskey(t, e, assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// A cross-origin iframe on another site: crossOrigin true with its topOrigin.
func TestPasskey_TopOrigin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, func(c *authtest.Ceremony) {
		c.CrossOrigin = true
		c.TopOrigin = "https://evil.example"
	})
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// Check 2: topOrigin present without crossOrigin.
func TestPasskey_TopOriginOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, func(c *authtest.Ceremony) { c.TopOrigin = "https://evil.example" })
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

func TestPasskey_WrongOrigin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, func(c *authtest.Ceremony) { c.Origin = "https://evil.example.test" })
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

func TestPasskey_CorruptSignature(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, func(c *authtest.Ceremony) { c.CorruptSignature = true })
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// Check 8: only canonical DER is an ES256 signature. Both encodings below
// carry a signature that verifies; only the encoding is wrong.
func TestPasskey_NonDERSignature(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tampers []authtest.Tamper
		edit    func(*testing.T, []byte) []byte
	}{
		{"raw r||s", []authtest.Tamper{func(c *authtest.Ceremony) { c.RawECDSA = true }}, nil},
		{"BER integer", nil, berSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := passkeyAuthenticator(t)
			h.enroll(t, a, alice)
			b := h.beginPasskey(t, signIn)
			resp := assertion(t, a, b, tc.tampers...)
			if tc.edit != nil {
				resp = tc.edit(t, resp)
			}
			_, err := h.finishPasskey(t, signInExpect(b), resp)
			h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
		})
	}
}

// Check 7: BE is fixed when the credential is created. A credential stored
// as device-bound that asserts backup eligibility is refused, and the stored
// value is not rewritten.
func TestPasskey_BackupEligibilityChanged(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t) // BE=0
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, setFlag(protocol.FlagBackupEligible))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
	if c := h.only(t, alice); c.BackupEligible || c.Version != webauthn.CurrentVersion {
		t.Fatalf("BackupEligible, Version = %v, %d, want false, %d", c.BackupEligible, c.Version, webauthn.CurrentVersion)
	}
}

// Check 7: BE=0 with BS=1 is refused for every credential version, a
// Version 1 credential adopting its flags included.
func TestPasskey_BackupStateWithoutEligibility(t *testing.T) {
	t.Parallel()
	for _, version := range []uint16{webauthn.CurrentVersion, 1} {
		t.Run(fmt.Sprintf("version %d", version), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := passkeyAuthenticator(t) // BE=0
			h.enroll(t, a, alice)
			h.rewrite(t, alice, func(c *webauthn.Credential) { c.Version = version })
			_, err := h.signIn(t, a, setFlag(protocol.FlagBackupState))
			h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
			if c := h.only(t, alice); c.Version != version || c.BackupState {
				t.Fatalf("Version, BackupState = %d, %v, want %d, false", c.Version, c.BackupState, version)
			}
		})
	}
}

// Design §8: a credential imported from v1 never recorded its backup flags.
// Its first assertion records them and moves it to the current version; a
// current-version credential asserting the same flags is refused.
func TestPasskey_Version1Credential_AdoptsFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version uint16
		adopt   bool
	}{
		{"version 1 adopts", 1, true},
		{"version 2 refuses", webauthn.CurrentVersion, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := newAuthenticator(t, authtest.AuthenticatorConfig{
				UserVerified: true, Discoverable: true, BackupEligible: true, BackupState: true,
			})
			h.enroll(t, a, alice)
			h.rewrite(t, alice, func(c *webauthn.Credential) {
				c.Version, c.BackupEligible, c.BackupState = tc.version, false, false
			})

			v, err := h.signIn(t, a)
			c := h.only(t, alice)
			if !tc.adopt {
				h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
				if c.Version != tc.version || c.BackupEligible || c.BackupState {
					t.Fatalf("Version, BE, BS = %d, %v, %v, want %d, false, false", c.Version, c.BackupEligible, c.BackupState, tc.version)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishPasskey: %v", err)
			}
			if c.Version != webauthn.CurrentVersion || !c.BackupEligible || !c.BackupState {
				t.Fatalf("Version, BE, BS = %d, %v, %v, want %d, true, true", c.Version, c.BackupEligible, c.BackupState, webauthn.CurrentVersion)
			}
			if !v.BackupEligible || !slices.Equal(v.Methods, []amr.Method{amr.SWK, amr.MFA}) {
				t.Fatalf("Verified BE %v, Methods %v, want true, [swk mfa]", v.BackupEligible, v.Methods)
			}
		})
	}
}

// Check 9: a write the store did not apply is never a pass, and a credential
// gone from the store never surfaces store.ErrNotFound.
func TestPasskey_RecordAssertionNotApplied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{"not applied", nil},
		{"credential gone", store.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := passkeyAuthenticator(t)
			h.enroll(t, a, alice)
			creds := &recordOverride{CredentialStore: h.creds, record: func(webauthn.AssertionUpdate) (bool, error) { return false, tc.err }}
			b := h.beginPasskey(t, signIn)
			v, err := h.rp.FinishPasskey(t.Context(), h.flows, creds, h.creds, signInExpect(b), assertion(t, a, b))
			h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
			if errors.Is(err, store.ErrNotFound) {
				t.Fatalf("err = %v surfaces store.ErrNotFound", err)
			}
			if !reflect.DeepEqual(v, webauthn.Verified{}) {
				t.Fatalf("a refused sign-in returned %+v, want the zero Verified", v)
			}
			if got := creds.recorded(); len(got) != 1 {
				t.Fatalf("RecordAssertion called %d times, want 1", len(got))
			}
		})
	}
}

// Design §4.2 rule 3 on the sign-in path: a listed credential the store
// answers with a zero value the library needs fails closed.
func TestPasskey_StoreFault_EmptyPublicKey(t *testing.T) {
	t.Parallel()
	requirePasskeyStoreFault(t, func(c *webauthn.Credential) { c.PublicKey = nil })
}

func TestPasskey_StoreFault_ZeroVersion(t *testing.T) {
	t.Parallel()
	requirePasskeyStoreFault(t, func(c *webauthn.Credential) { c.Version = 0 })
}

func requirePasskeyStoreFault(t *testing.T, edit func(*webauthn.Credential)) {
	t.Helper()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	creds := listOverride{CredentialStore: h.creds, list: func(subject, rpID string) ([]webauthn.Credential, error) {
		list, err := h.creds.List(t.Context(), subject, rpID)
		for i := range list {
			edit(&list[i])
		}
		return list, err
	}}
	b := h.beginPasskey(t, signIn)
	_, err := h.rp.FinishPasskey(t.Context(), h.flows, creds, h.creds, signInExpect(b), assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
	if !strings.Contains(err.Error(), "store fault") {
		t.Fatalf("err = %v, want a store fault", err)
	}
}

// A user handle the store resolves to an empty subject is a store fault, not
// a subject.
func TestPasskey_StoreFault_EmptySubject(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	handles := subjectOverride{HandleStore: h.creds, subject: func([]byte) (string, error) { return "", nil }}
	b := h.beginPasskey(t, signIn)
	_, err := h.rp.FinishPasskey(t.Context(), h.flows, h.creds, handles, signInExpect(b), assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
	if !strings.Contains(err.Error(), "store fault") {
		t.Fatalf("err = %v, want a store fault", err)
	}
}

// A body that is not JSON still consumes the flow: flows are single-use.
func TestPasskey_NotJSON(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	_, err := h.finishPasskey(t, signInExpect(b), []byte("not json"))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)

	_, err = h.finishPasskey(t, signInExpect(b), assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// A valid response padded with JSON whitespace: the size alone decides.
func TestPasskey_OversizedResponse(t *testing.T) {
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
			a := passkeyAuthenticator(t)
			h.enroll(t, a, alice)
			_, takesBefore := h.flows.recorded()
			b := h.beginPasskey(t, signIn)
			resp := assertion(t, a, b)
			resp = append(resp, bytes.Repeat([]byte(" "), tc.size-len(resp))...)

			_, err := h.finishPasskey(t, signInExpect(b), resp)
			if !tc.refuse {
				if err != nil {
					t.Fatalf("FinishPasskey with a %d-byte response: %v", tc.size, err)
				}
				return
			}
			h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
			if _, takes := h.flows.recorded(); takes != takesBefore {
				t.Fatalf("an oversized response reached the flow store (%d Take calls)", takes-takesBefore)
			}
		})
	}
}

// Check 5: a user handle no subject holds.
func TestPasskey_UnknownHandle(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	_, err := h.signIn(t, a, func(c *authtest.Ceremony) { c.UserHandle = bytes.Repeat([]byte{0x5a}, 64) })
	h.requireSignInRefused(t, err, webauthn.ErrUnknownCredential, alice)
}

// Check 5: the application deleted the credential; its holder still offers
// it, and learns only that this relying party forgot it.
func TestPasskey_DeletedCredential(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	h.creds.Delete(alice.ID, a.CredentialID())
	_, err := h.signIn(t, a)
	requireOnly(t, err, webauthn.ErrUnknownCredential)
}

// Check 5 is the only binding between a user handle and a credential: the
// handle resolves to one subject and the credential belongs to another.
func TestPasskey_CredentialNotHeldByHandleOwner(t *testing.T) {
	t.Parallel()
	t.Run("handle swapped at assertion", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		h.enroll(t, passkeyAuthenticator(t), alice)
		mallory := passkeyAuthenticator(t)
		h.enroll(t, mallory, bob)
		aliceHandle := h.handleOf(t, alice)

		_, err := h.signIn(t, mallory, func(c *authtest.Ceremony) { c.UserHandle = aliceHandle })
		h.requireSignInRefused(t, err, webauthn.ErrUnknownCredential, alice)
		h.requireSignInRefused(t, err, webauthn.ErrUnknownCredential, bob)
	})
	// The authenticator was registered for bob but given alice's user.id, so
	// it asserts alice's handle with a credential only bob holds.
	t.Run("registered under a foreign user.id", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		h.enroll(t, passkeyAuthenticator(t), alice)
		aliceHandle := h.handleOf(t, alice)
		mallory := passkeyAuthenticator(t)
		b := h.begin(t, bob, passkey)
		forged := editJSON(t, b.Options, func(top map[string]json.RawMessage) {
			var u map[string]json.RawMessage
			if err := json.Unmarshal(top["user"], &u); err != nil {
				t.Fatalf("decode user: %v", err)
			}
			id, err := json.Marshal(base64.RawURLEncoding.EncodeToString(aliceHandle))
			if err != nil {
				t.Fatalf("encode user.id: %v", err)
			}
			u["id"] = id
			if top["user"], err = json.Marshal(u); err != nil {
				t.Fatalf("encode user: %v", err)
			}
		})
		resp, err := mallory.Register(forged, origin)
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if _, err = h.finish(t, expectFor(bob, b), resp); err != nil {
			t.Fatalf("bob's registration: %v", err)
		}

		_, err = h.signIn(t, mallory)
		h.requireSignInRefused(t, err, webauthn.ErrUnknownCredential, alice)
		h.requireSignInRefused(t, err, webauthn.ErrUnknownCredential, bob)
	})
}

// Check 5: the credential is the handle owner's, but registered under
// another RP ID that shares the stores and the origin.
func TestPasskey_CredentialOfOtherRPID(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	other, err := webauthn.New(webauthn.Config{
		RPID: "app.example.test", RPName: "Other", Origins: []string{origin}, Now: h.clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := passkeyAuthenticator(t)
	b, err := other.BeginRegistration(t.Context(), h.flows, h.creds, h.creds, alice, passkey)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err = other.FinishRegistration(t.Context(), h.flows, h.creds, expectFor(alice, b), respond(t, a, b)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	_, err = h.signIn(t, a)
	requireOnly(t, err, webauthn.ErrUnknownCredential)
	held, err := h.creds.List(t.Context(), alice.ID, "app.example.test")
	if err != nil || len(held) != 1 || !held[0].LastUsedAt.IsZero() {
		t.Fatalf("List(app.example.test) = %+v, %v, want one unused credential", held, err)
	}
}

// Check 8 on a device-bound credential whose counter went backwards.
func TestPasskey_CounterRegression_DeviceBound(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true, SignCount: 10, CounterStep: 1})
	h.enroll(t, a, alice)
	a.SetSignCount(4) // the next assertion signs 5
	h.clock.Advance(time.Minute)

	_, err := h.signIn(t, a)
	requireOnly(t, err, webauthn.ErrCloneSuspected)
	c := h.only(t, alice)
	if !c.CloneSuspectedAt.Equal(h.clock.Now()) || c.SignCount != 10 || !c.LastUsedAt.IsZero() {
		t.Fatalf("CloneSuspectedAt %v, SignCount %d, LastUsedAt %v, want %v, 10, zero",
			c.CloneSuspectedAt, c.SignCount, c.LastUsedAt, h.clock.Now())
	}
}

// Check 8 runs only after a verified signature: a forged assertion carrying a
// lower counter must not mark the credential, or anyone could lock out its
// holder.
func TestPasskey_ForgedCounterRegression_DoesNotMark(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true, SignCount: 10})
	h.enroll(t, a, alice)
	a.SetSignCount(5)
	_, err := h.signIn(t, a, func(c *authtest.Ceremony) { c.CorruptSignature = true })
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
	if c := h.only(t, alice); c.SignCount != 10 {
		t.Fatalf("SignCount = %d after a forged assertion, want 10", c.SignCount)
	}
}

// Check 8 at its boundaries: both zero is a synced passkey; otherwise the
// counter must advance past a non-zero stored one.
func TestPasskey_CounterBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stored, received uint32
		clone            bool
	}{
		{0, 0, false},
		{0, 5, false},
		{10, 11, false},
		{10, 10, true},
		{10, 5, true},
		{10, 0, true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("stored %d received %d", tc.stored, tc.received), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true, SignCount: tc.stored})
			h.enroll(t, a, alice)
			a.SetSignCount(tc.received) // CounterStep 0: the assertion signs received
			h.clock.Advance(time.Minute)

			_, err := h.signIn(t, a)
			c := h.only(t, alice)
			now := h.clock.Now()
			if tc.clone {
				requireOnly(t, err, webauthn.ErrCloneSuspected)
				if !c.CloneSuspectedAt.Equal(now) || c.SignCount != tc.stored || !c.LastUsedAt.IsZero() {
					t.Fatalf("CloneSuspectedAt %v, SignCount %d, LastUsedAt %v, want %v, %d, zero",
						c.CloneSuspectedAt, c.SignCount, c.LastUsedAt, now, tc.stored)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishPasskey: %v", err)
			}
			if !c.CloneSuspectedAt.IsZero() || c.SignCount != tc.received || !c.LastUsedAt.Equal(now) {
				t.Fatalf("CloneSuspectedAt %v, SignCount %d, LastUsedAt %v, want zero, %d, %v",
					c.CloneSuspectedAt, c.SignCount, c.LastUsedAt, tc.received, now)
			}
		})
	}
}

// The flow Take is the single-use gate: one response submitted eight times
// at once signs in once.
func TestPasskey_ConcurrentReplay_OneWinner(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	resp := assertion(t, a, b)

	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, errs[i] = h.rp.FinishPasskey(t.Context(), h.flows, h.creds, h.creds, signInExpect(b), resp)
		})
	}
	wg.Wait()

	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
			continue
		}
		requireOnly(t, err, webauthn.ErrInvalidCredentials)
	}
	if wins != 1 {
		t.Fatalf("%d of %d concurrent submissions signed in, want exactly 1", wins, n)
	}
}

func TestPasskey_ReplayedFlow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	if _, err := h.finishPasskey(t, signInExpect(b), assertion(t, a, b)); err != nil {
		t.Fatalf("first Finish: %v", err)
	}
	_, err := h.finishPasskey(t, signInExpect(b), assertion(t, a, b))
	requireOnly(t, err, webauthn.ErrInvalidCredentials)
}

func TestPasskey_ExpiredFlow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	h.clock.Advance(6 * time.Minute)
	_, err := h.finishPasskey(t, signInExpect(b), assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

func TestPasskey_WrongPurpose(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	e := signInExpect(b)
	e.Purpose = "stepup"
	_, err := h.finishPasskey(t, e, assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// A copy of a genuine passkey flow under another ceremony's kind is refused.
func TestPasskey_FlowOfAnotherKind(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := passkeyAuthenticator(t)
	h.enroll(t, a, alice)
	b := h.beginPasskey(t, signIn)
	puts, _ := h.flows.recorded()
	foreign := puts[len(puts)-1].flow
	foreign.Kind = "webauthn.second_factor"
	const foreignID = "foreign-flow-id"
	if err := h.flows.Put(t.Context(), foreignID, foreign); err != nil {
		t.Fatalf("Put: %v", err)
	}

	e := signInExpect(b)
	e.FlowID = foreignID
	_, err := h.finishPasskey(t, e, assertion(t, a, b))
	h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, alice)
}

// A failing store is an infrastructure error, never a verification result
// and never a recorded sign-in.
func TestFinishPasskey_StoreError(t *testing.T) {
	t.Parallel()
	down := errors.New("database is down")
	tests := []struct {
		name    string
		flows   func(store.FlowStore) store.FlowStore
		creds   func(webauthn.CredentialStore) webauthn.CredentialStore
		handles func(webauthn.HandleStore) webauthn.HandleStore
	}{
		{
			name:  "Take",
			flows: func(f store.FlowStore) store.FlowStore { return takeOutage{FlowStore: f, err: down} },
		},
		{
			name: "Subject",
			handles: func(hs webauthn.HandleStore) webauthn.HandleStore {
				return subjectOverride{HandleStore: hs, subject: func([]byte) (string, error) { return "", down }}
			},
		},
		{
			name: "List",
			creds: func(c webauthn.CredentialStore) webauthn.CredentialStore {
				return listOverride{CredentialStore: c, list: func(string, string) ([]webauthn.Credential, error) { return nil, down }}
			},
		},
		{
			name: "RecordAssertion",
			creds: func(c webauthn.CredentialStore) webauthn.CredentialStore {
				return &recordOverride{CredentialStore: c, record: func(webauthn.AssertionUpdate) (bool, error) { return false, down }}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := passkeyAuthenticator(t)
			h.enroll(t, a, alice)
			var (
				flows   store.FlowStore          = h.flows
				creds   webauthn.CredentialStore = h.creds
				handles webauthn.HandleStore     = h.creds
			)
			if tc.flows != nil {
				flows = tc.flows(flows)
			}
			if tc.creds != nil {
				creds = tc.creds(creds)
			}
			if tc.handles != nil {
				handles = tc.handles(handles)
			}
			b := h.beginPasskey(t, signIn)
			v, err := h.rp.FinishPasskey(t.Context(), flows, creds, handles, signInExpect(b), assertion(t, a, b))
			if !errors.Is(err, down) || isSentinel(err) {
				t.Fatalf("err = %v, want the store's error and no sentinel", err)
			}
			if !reflect.DeepEqual(v, webauthn.Verified{}) {
				t.Fatalf("a failed Finish returned %+v, want the zero Verified", v)
			}
			if c := h.only(t, alice); !c.LastUsedAt.IsZero() {
				t.Fatalf("a failed Finish recorded a use at %v", c.LastUsedAt)
			}
		})
	}
}

// Marking a clone that the store cannot record is never a pass, and a
// credential gone from the store never surfaces store.ErrNotFound.
func TestPasskey_MarkCloneSuspectedFails(t *testing.T) {
	t.Parallel()
	down := errors.New("database is down")
	tests := []struct {
		name  string
		err   error
		check func(*testing.T, error)
	}{
		{"outage", down, func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, down) || isSentinel(err) {
				t.Fatalf("err = %v, want the store's error and no sentinel", err)
			}
		}},
		{"credential gone", store.ErrNotFound, func(t *testing.T, err error) {
			t.Helper()
			requireOnly(t, err, webauthn.ErrInvalidCredentials)
			if errors.Is(err, store.ErrNotFound) {
				t.Fatalf("err = %v surfaces store.ErrNotFound", err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true, SignCount: 10})
			h.enroll(t, a, alice)
			a.SetSignCount(5)
			creds := &recordOverride{CredentialStore: markOverride{CredentialStore: h.creds, err: tc.err}}
			b := h.beginPasskey(t, signIn)
			_, err := h.rp.FinishPasskey(t.Context(), h.flows, creds, h.creds, signInExpect(b), assertion(t, a, b))
			tc.check(t, err)
			if got := creds.recorded(); len(got) != 0 {
				t.Fatalf("a clone-suspected assertion called RecordAssertion %d times", len(got))
			}
		})
	}
}
