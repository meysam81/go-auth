package webauthn_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/meysam81/go-auth/v2/amr"
	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

const stepUpPurpose = "stepup"

var (
	stepUp    = webauthn.SecondFactorOptions{Purpose: stepUpPurpose}
	requireUV = webauthn.SecondFactorOptions{Purpose: stepUpPurpose, RequireUV: true}
)

// ensureCounter is a HandleStore that counts Ensure calls.
type ensureCounter struct {
	webauthn.HandleStore
	calls int
}

func (s *ensureCounter) Ensure(ctx context.Context, subject string, h []byte) ([]byte, error) {
	s.calls++
	return s.HandleStore.Ensure(ctx, subject, h)
}

// securityKeyAuthenticator returns an authenticator that keeps a non-discoverable
// credential and verifies the user only when uv is set.
func securityKeyAuthenticator(t *testing.T, uv bool) *authtest.Authenticator {
	t.Helper()
	return newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: uv})
}

// enrollKey registers a's credential for sub as a security key and returns
// the stored credential.
func (h *harness) enrollKey(t *testing.T, a *authtest.Authenticator, sub webauthn.Subject) webauthn.Credential {
	t.Helper()
	c, err := h.attempt(t, a, sub, securityKey, nil)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return c
}

// enrollOtherRP registers a's credential for sub under app.example.test, a
// relying party that shares h's stores and origin.
func (h *harness) enrollOtherRP(t *testing.T, a *authtest.Authenticator, sub webauthn.Subject) {
	t.Helper()
	other, err := webauthn.New(webauthn.Config{
		RPID: "app.example.test", RPName: "Other", Origins: []string{origin}, Now: h.clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b, err := other.BeginRegistration(t.Context(), h.flows, h.creds, h.creds, sub, securityKey)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err = other.FinishRegistration(t.Context(), h.flows, h.creds, expectFor(sub, b), respond(t, a, b)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
}

func (h *harness) beginSecondFactor(t *testing.T, sub webauthn.Subject, opts webauthn.SecondFactorOptions) webauthn.Begun {
	t.Helper()
	b, err := h.rp.BeginSecondFactor(t.Context(), h.flows, h.creds, h.creds, sub.ID, opts)
	if err != nil {
		t.Fatalf("BeginSecondFactor: %v", err)
	}
	return b
}

func stepUpExpect(sub webauthn.Subject, b webauthn.Begun) webauthn.Expect {
	return webauthn.Expect{FlowID: b.FlowID, Purpose: stepUpPurpose, Subject: sub.ID}
}

func (h *harness) finishSecondFactor(t *testing.T, e webauthn.Expect, response []byte) (webauthn.Verified, error) {
	t.Helper()
	return h.rp.FinishSecondFactor(t.Context(), h.flows, h.creds, e, response)
}

// secondFactor runs one second-factor ceremony for alice: Begin with opts, a
// answers the options with tampers, and Finish.
func (h *harness) secondFactor(t *testing.T, a *authtest.Authenticator, opts webauthn.SecondFactorOptions, tampers ...authtest.Tamper) (webauthn.Verified, error) {
	t.Helper()
	b := h.beginSecondFactor(t, alice, opts)
	return h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b, tampers...))
}

// requireStepUpRefused fails unless err is ErrInvalidCredentials and no other
// sentinel, and no credential of subs recorded a use or a clone suspicion. A
// second-factor failure is never ErrUnknownCredential: the caller already
// identified the subject.
func (h *harness) requireStepUpRefused(t *testing.T, err error, subs ...webauthn.Subject) {
	t.Helper()
	if errors.Is(err, webauthn.ErrUnknownCredential) {
		t.Fatalf("err = %v is ErrUnknownCredential; a second factor never distinguishes an unknown credential", err)
	}
	for _, sub := range subs {
		h.requireSignInRefused(t, err, webauthn.ErrInvalidCredentials, sub)
	}
}

// stepUpRequest is the part of the request options JSON the tests read.
type stepUpRequest struct {
	assertionOptions
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
}

func TestSecondFactor_WithoutUV(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	aaguid := [16]byte{0x5e, 15: 0xc0}
	a := newAuthenticator(t, authtest.AuthenticatorConfig{AAGUID: aaguid, CounterStep: 1})
	h.enrollKey(t, a, alice)
	h.clock.Advance(time.Minute)

	v, err := h.secondFactor(t, a, stepUp)
	if err != nil {
		t.Fatalf("FinishSecondFactor: %v", err)
	}
	now := h.clock.Now()
	want := webauthn.Verified{
		Subject: alice.ID, CredentialID: a.CredentialID(), AAGUID: aaguid,
		Methods: []amr.Method{amr.HWK}, At: now,
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("Verified = %+v, want %+v", v, want)
	}
	if c := h.only(t, alice); c.SignCount != 1 || !c.LastUsedAt.Equal(now) || !c.CloneSuspectedAt.IsZero() {
		t.Errorf("stored SignCount %d, LastUsedAt %v, CloneSuspectedAt %v, want 1, %v, zero",
			c.SignCount, c.LastUsedAt, c.CloneSuspectedAt, now)
	}
}

// User verification adds mfa whether the caller required it or not.
func TestSecondFactor_WithUV(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts webauthn.SecondFactorOptions
	}{
		{"user verification preferred", stepUp},
		{"user verification required", requireUV},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := securityKeyAuthenticator(t, true)
			h.enrollKey(t, a, alice)

			v, err := h.secondFactor(t, a, tc.opts)
			if err != nil {
				t.Fatalf("FinishSecondFactor: %v", err)
			}
			if !v.UserVerified || !slices.Equal(v.Methods, []amr.Method{amr.HWK, amr.MFA}) {
				t.Fatalf("UserVerified %v, Methods %v, want true, [hwk mfa]", v.UserVerified, v.Methods)
			}
		})
	}
}

// Any credential the options listed answers, and only that one records the
// use.
func TestSecondFactor_AnyListedCredential(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	first, second := securityKeyAuthenticator(t, false), securityKeyAuthenticator(t, false)
	h.enrollKey(t, first, alice)
	h.enrollKey(t, second, alice)
	h.clock.Advance(time.Minute)

	v, err := h.secondFactor(t, second, stepUp)
	if err != nil {
		t.Fatalf("FinishSecondFactor: %v", err)
	}
	if !bytes.Equal(v.CredentialID, second.CredentialID()) {
		t.Fatalf("CredentialID = %x, want the second credential %x", v.CredentialID, second.CredentialID())
	}
	for _, c := range h.list(t, alice) {
		if used := !c.LastUsedAt.IsZero(); used != bytes.Equal(c.ID, second.CredentialID()) {
			t.Fatalf("credential %x LastUsedAt %v; only the asserted credential records a use", c.ID, c.LastUsedAt)
		}
	}
}

// A passkey serves as a second factor too. Its assertion carries a user
// handle, which must be the flow subject's.
func TestSecondFactor_UserHandle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		handle func(*testing.T, *harness) []byte
		refuse bool
	}{
		{"the subject's own", func(*testing.T, *harness) []byte { return nil }, false},
		{"another subject's", func(t *testing.T, h *harness) []byte {
			t.Helper()
			h.enroll(t, passkeyAuthenticator(t), bob)
			return h.handleOf(t, bob)
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := passkeyAuthenticator(t)
			h.enroll(t, a, alice)
			var tamper authtest.Tamper
			if handle := tc.handle(t, h); handle != nil {
				tamper = func(c *authtest.Ceremony) { c.UserHandle = handle }
			}
			v, err := h.secondFactor(t, a, stepUp, tamper)
			if tc.refuse {
				h.requireStepUpRefused(t, err, alice, bob)
				return
			}
			if err != nil {
				t.Fatalf("FinishSecondFactor: %v", err)
			}
			if v.Subject != alice.ID || !slices.Equal(v.Methods, []amr.Method{amr.HWK, amr.MFA}) {
				t.Fatalf("Subject %q, Methods %v, want %q, [hwk mfa]", v.Subject, v.Methods, alice.ID)
			}
		})
	}
}

func TestSecondFactor_Options(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts webauthn.SecondFactorOptions
		uv   string
	}{
		{"user verification preferred", stepUp, "preferred"},
		{"user verification required", requireUV, "required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			key, pk := securityKeyAuthenticator(t, false), passkeyAuthenticator(t)
			h.enrollKey(t, key, alice)
			h.enroll(t, pk, alice)
			h.enrollKey(t, securityKeyAuthenticator(t, false), bob)
			h.enrollOtherRP(t, securityKeyAuthenticator(t, false), alice)
			putsBefore, _ := h.flows.recorded()

			b := h.beginSecondFactor(t, alice, tc.opts)

			var o stepUpRequest
			if err := json.Unmarshal(b.Options, &o); err != nil {
				t.Fatalf("decode options: %v", err)
			}
			got := make([][]byte, len(o.AllowCredentials))
			for i, d := range o.AllowCredentials {
				if d.Type != "public-key" {
					t.Errorf("allowCredentials[%d].type = %q, want public-key", i, d.Type)
				}
				got[i] = d.ID
			}
			want := [][]byte{key.CredentialID(), pk.CredentialID()}
			slices.SortFunc(got, bytes.Compare)
			slices.SortFunc(want, bytes.Compare)
			if !slices.EqualFunc(got, want, bytes.Equal) {
				t.Errorf("allowCredentials IDs = %x, want exactly alice's credentials for %s %x", got, rpID, want)
			}
			if o.UserVerification != tc.uv {
				t.Errorf("userVerification = %q, want %q", o.UserVerification, tc.uv)
			}
			if o.RPID != rpID {
				t.Errorf("rpId = %q, want %q", o.RPID, rpID)
			}
			if o.Timeout != int((5 * time.Minute).Milliseconds()) {
				t.Errorf("timeout = %d, want 300000", o.Timeout)
			}
			if b.Mediation != "" {
				t.Errorf("Mediation = %q, want empty", b.Mediation)
			}

			puts, _ := h.flows.recorded()
			if len(puts) != len(putsBefore)+1 {
				t.Fatalf("Begin wrote %d flows, want 1", len(puts)-len(putsBefore))
			}
			p := puts[len(puts)-1]
			var payload struct {
				Purpose   string `json:"purpose"`
				Subject   string `json:"subject"`
				RequireUV bool   `json:"require_uv"`
			}
			if err := json.Unmarshal(p.flow.Payload, &payload); err != nil {
				t.Fatalf("decode flow payload: %v", err)
			}
			if p.id != b.FlowID || p.flow.Kind != "webauthn.second_factor" || payload.Purpose != stepUpPurpose ||
				payload.Subject != alice.ID || payload.RequireUV != tc.opts.RequireUV {
				t.Errorf("flow %q of kind %q with %+v, want %q of kind webauthn.second_factor for %s, %s, require_uv %v",
					p.id, p.flow.Kind, payload, b.FlowID, stepUpPurpose, alice.ID, tc.opts.RequireUV)
			}
		})
	}
}

// Check 3: a caller that requires user verification never gets a pass
// without it.
func TestSecondFactor_RequireUV_RefusesWithoutUV(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, false)
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, requireUV)
	h.requireStepUpRefused(t, err, alice)
}

func TestSecondFactor_WithoutUserPresence(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, stepUp, clearUserPresence)
	h.requireStepUpRefused(t, err, alice)
}

// A subject with no credential for this RP ID has nothing to assert: Begin
// fails before it writes a flow or creates a user handle.
func TestSecondFactor_NoCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(*testing.T, *harness)
	}{
		{"none at all", func(*testing.T, *harness) {}},
		{"only under another RP ID", func(t *testing.T, h *harness) {
			t.Helper()
			h.enrollOtherRP(t, securityKeyAuthenticator(t, false), alice)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			tc.setup(t, h)
			putsBefore, _ := h.flows.recorded()
			handles := &ensureCounter{HandleStore: h.creds}

			b, err := h.rp.BeginSecondFactor(t.Context(), h.flows, h.creds, handles, alice.ID, stepUp)
			requireOnly(t, err, webauthn.ErrInvalidCredentials)
			if !reflect.DeepEqual(b, webauthn.Begun{}) {
				t.Errorf("a refused Begin returned %+v, want the zero Begun", b)
			}
			if puts, _ := h.flows.recorded(); len(puts) != len(putsBefore) {
				t.Errorf("a refused Begin wrote %d flow(s)", len(puts)-len(putsBefore))
			}
			if handles.calls != 0 {
				t.Errorf("a refused Begin called Ensure %d times", handles.calls)
			}
		})
	}
}

// Check 6: bob's authenticator answers alice's ceremony. The virtual
// authenticator ignores allowCredentials, as an attacker's client would.
func TestSecondFactor_OtherSubjectsAuthenticator(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.enrollKey(t, securityKeyAuthenticator(t, true), alice)
	mallory := securityKeyAuthenticator(t, true)
	h.enrollKey(t, mallory, bob)

	_, err := h.secondFactor(t, mallory, stepUp)
	h.requireStepUpRefused(t, err, alice, bob)
}

// Check 6: a credential alice holds under another RP ID that shares the
// stores and the origin is not one of her credentials here.
func TestSecondFactor_CredentialOfOtherRPID(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.enrollKey(t, securityKeyAuthenticator(t, true), alice)
	elsewhere := securityKeyAuthenticator(t, true)
	h.enrollOtherRP(t, elsewhere, alice)

	_, err := h.secondFactor(t, elsewhere, stepUp)
	h.requireStepUpRefused(t, err, alice)
	held, err := h.creds.List(t.Context(), alice.ID, "app.example.test")
	if err != nil || len(held) != 1 || !held[0].LastUsedAt.IsZero() {
		t.Fatalf("List(app.example.test) = %+v, %v, want one unused credential", held, err)
	}
}

// Check 1: the flow was begun for alice; an Expect for anyone else, or for
// no one, is refused.
func TestSecondFactor_ExpectWrongSubject(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, subject string }{
		{"another subject", bob.ID},
		{"no subject", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := securityKeyAuthenticator(t, true)
			h.enrollKey(t, a, alice)
			h.enrollKey(t, securityKeyAuthenticator(t, true), bob)
			b := h.beginSecondFactor(t, alice, stepUp)
			e := stepUpExpect(alice, b)
			e.Subject = tc.subject
			_, err := h.finishSecondFactor(t, e, assertion(t, a, b))
			h.requireStepUpRefused(t, err, alice, bob)
		})
	}
}

// Check 6 runs against the credentials the subject holds when Finish runs.
// go-webauthn also requires the subject to still hold every credential the
// options listed, so removing any of them fails the ceremony in flight.
func TestSecondFactor_CredentialRemovedMidCeremony(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		removed func(asserted, other []byte) []byte
	}{
		{"the asserted credential", func(asserted, _ []byte) []byte { return asserted }},
		{"another listed credential", func(_, other []byte) []byte { return other }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a, other := securityKeyAuthenticator(t, true), securityKeyAuthenticator(t, true)
			h.enrollKey(t, a, alice)
			h.enrollKey(t, other, alice)
			b := h.beginSecondFactor(t, alice, stepUp)
			h.creds.Delete(alice.ID, tc.removed(a.CredentialID(), other.CredentialID()))

			_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b))
			h.requireStepUpRefused(t, err, alice)
		})
	}
}

// Check 6: a credential registered after Begin was not offered, so it cannot
// answer.
func TestSecondFactor_CredentialAddedMidCeremony(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.enrollKey(t, securityKeyAuthenticator(t, true), alice)
	b := h.beginSecondFactor(t, alice, stepUp)
	late := securityKeyAuthenticator(t, true)
	h.enrollKey(t, late, alice)

	_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, late, b))
	h.requireStepUpRefused(t, err, alice)
}

// Check 8 on the second-factor path.
func TestSecondFactor_CounterRegression(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{SignCount: 10, CounterStep: 1})
	cred := h.enrollKey(t, a, alice)
	a.SetSignCount(4) // the next assertion signs 5
	h.clock.Advance(time.Minute)

	_, err := h.secondFactor(t, a, stepUp)
	requireCloneSuspected(t, err, alice, cred.ID, true)
	c := h.only(t, alice)
	if !c.CloneSuspectedAt.Equal(h.clock.Now()) || c.SignCount != 10 || !c.LastUsedAt.IsZero() {
		t.Fatalf("CloneSuspectedAt %v, SignCount %d, LastUsedAt %v, want %v, 10, zero",
			c.CloneSuspectedAt, c.SignCount, c.LastUsedAt, h.clock.Now())
	}
}

// Check 8 after the mark, on the second-factor path: a clone-suspected
// credential stays refused even with a counter that advances, records no use
// and is not marked again.
func TestSecondFactor_CloneSuspectedCredential_Refused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{SignCount: 10, CounterStep: 1})
	cred := h.enrollKey(t, a, alice)
	a.SetSignCount(4) // the next assertion signs 5: a regression
	h.clock.Advance(time.Minute)
	_, err := h.secondFactor(t, a, stepUp)
	requireCloneSuspected(t, err, alice, cred.ID, true)
	marked := h.clock.Now()

	a.SetSignCount(49) // the next assertion signs 50, past the stored 10
	h.clock.Advance(time.Minute)
	creds := &recordOverride{CredentialStore: h.creds}
	b := h.beginSecondFactor(t, alice, stepUp)
	v, err := h.rp.FinishSecondFactor(t.Context(), h.flows, creds, stepUpExpect(alice, b), assertion(t, a, b))
	requireCloneSuspected(t, err, alice, cred.ID, false)
	if !reflect.DeepEqual(v, webauthn.Verified{}) {
		t.Fatalf("a refused second factor returned %+v, want the zero Verified", v)
	}
	if got := creds.recorded(); len(got) != 0 {
		t.Fatalf("a clone-suspected credential called RecordAssertion %d times", len(got))
	}
	if c := h.only(t, alice); !c.CloneSuspectedAt.Equal(marked) || c.SignCount != 10 || !c.LastUsedAt.IsZero() {
		t.Fatalf("CloneSuspectedAt %v, SignCount %d, LastUsedAt %v, want %v (the first mark), 10, zero",
			c.CloneSuspectedAt, c.SignCount, c.LastUsedAt, marked)
	}
}

// The clone refusal comes only after a verified signature, on the
// second-factor path too: a forged assertion for a marked credential is an
// ordinary ErrInvalidCredentials and writes nothing.
func TestSecondFactor_CloneSuspectedCredential_ForgedSignature(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{SignCount: 10, CounterStep: 1})
	cred := h.enrollKey(t, a, alice)
	marked := h.clock.Now()
	if err := h.creds.MarkCloneSuspected(t.Context(), alice.ID, cred.ID, marked); err != nil {
		t.Fatalf("MarkCloneSuspected: %v", err)
	}
	h.clock.Advance(time.Minute)

	creds := &recordOverride{CredentialStore: h.creds}
	b := h.beginSecondFactor(t, alice, stepUp)
	_, err := h.rp.FinishSecondFactor(t.Context(), h.flows, creds, stepUpExpect(alice, b),
		assertion(t, a, b, func(c *authtest.Ceremony) { c.CorruptSignature = true }))
	requireNotCloneError(t, err)
	if got := creds.recorded(); len(got) != 0 {
		t.Fatalf("a forged assertion called RecordAssertion %d times", len(got))
	}
	if c := h.only(t, alice); !c.CloneSuspectedAt.Equal(marked) || c.SignCount != 10 || !c.LastUsedAt.IsZero() {
		t.Fatalf("CloneSuspectedAt %v, SignCount %d, LastUsedAt %v, want %v, 10, zero",
			c.CloneSuspectedAt, c.SignCount, c.LastUsedAt, marked)
	}
}

// Check 8 runs only after a verified signature: a forged assertion carrying a
// lower counter must not mark the credential, or anyone could lock out its
// holder.
func TestSecondFactor_ForgedCounterRegression_DoesNotMark(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{SignCount: 10})
	h.enrollKey(t, a, alice)
	a.SetSignCount(5)
	_, err := h.secondFactor(t, a, stepUp, func(c *authtest.Ceremony) { c.CorruptSignature = true })
	h.requireStepUpRefused(t, err, alice)
}

// Check 7 on the second-factor path: BE is fixed when the credential is
// created.
func TestSecondFactor_BackupEligibilityChanged(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true) // BE=0
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, stepUp, setFlag(protocol.FlagBackupEligible))
	h.requireStepUpRefused(t, err, alice)
	if c := h.only(t, alice); c.BackupEligible {
		t.Fatal("a refused assertion rewrote the stored BackupEligible")
	}
}

func TestSecondFactor_BackupStateWithoutEligibility(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true) // BE=0
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, stepUp, setFlag(protocol.FlagBackupState))
	h.requireStepUpRefused(t, err, alice)
}

// A credential imported from v1 carries over as a second factor.
// Its first assertion records its backup flags and moves it to the current
// version; a current-version credential asserting the same flags is refused.
func TestSecondFactor_Version1Credential_AdoptsFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version uint16
		adopt   bool
	}{
		{"version 1 adopts", webauthn.ImportedVersion, true},
		{"version 2 refuses", webauthn.CurrentVersion, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, BackupEligible: true, BackupState: true})
			h.enrollKey(t, a, alice)
			h.rewrite(t, alice, func(c *webauthn.Credential) {
				c.Version, c.BackupEligible, c.BackupState = tc.version, false, false
			})

			v, err := h.secondFactor(t, a, stepUp)
			c := h.only(t, alice)
			if !tc.adopt {
				h.requireStepUpRefused(t, err, alice)
				if c.Version != tc.version || c.BackupEligible || c.BackupState {
					t.Fatalf("Version, BE, BS = %d, %v, %v, want %d, false, false", c.Version, c.BackupEligible, c.BackupState, tc.version)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishSecondFactor: %v", err)
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

// Check 9 on the second-factor path: a write the store did not apply is
// never a pass.
func TestSecondFactor_RecordAssertionNotApplied(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	creds := &recordOverride{CredentialStore: h.creds, record: func(webauthn.AssertionUpdate) (bool, error) { return false, nil }}
	b := h.beginSecondFactor(t, alice, stepUp)
	v, err := h.rp.FinishSecondFactor(t.Context(), h.flows, creds, stepUpExpect(alice, b), assertion(t, a, b))
	h.requireStepUpRefused(t, err, alice)
	if !reflect.DeepEqual(v, webauthn.Verified{}) {
		t.Fatalf("a refused assertion returned %+v, want the zero Verified", v)
	}
	if got := creds.recorded(); len(got) != 1 {
		t.Fatalf("RecordAssertion called %d times, want 1", len(got))
	}
}

func TestSecondFactor_ReplayedFlow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{UserVerified: true, CounterStep: 1})
	h.enrollKey(t, a, alice)
	b := h.beginSecondFactor(t, alice, stepUp)
	if _, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b)); err != nil {
		t.Fatalf("first Finish: %v", err)
	}
	_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b))
	requireOnly(t, err, webauthn.ErrInvalidCredentials)
	if c := h.only(t, alice); c.SignCount != 1 {
		t.Fatalf("SignCount = %d after a replayed flow, want 1", c.SignCount)
	}
}

func TestSecondFactor_ExpiredFlow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	b := h.beginSecondFactor(t, alice, stepUp)
	h.clock.Advance(6 * time.Minute)
	_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b))
	h.requireStepUpRefused(t, err, alice)
}

// A flow begun for a sign-in second factor does not complete a step-up.
func TestSecondFactor_WrongPurpose(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	b := h.beginSecondFactor(t, alice, webauthn.SecondFactorOptions{Purpose: "login"})
	_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b))
	h.requireStepUpRefused(t, err, alice)
}

// A passkey flow's ID is refused, and so is a copy of a genuine second-factor
// flow that differs from it in its kind only.
func TestSecondFactor_FlowOfAnotherKind(t *testing.T) {
	t.Parallel()
	t.Run("a passkey flow", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		a := securityKeyAuthenticator(t, true)
		h.enrollKey(t, a, alice)
		b := h.beginPasskey(t, webauthn.PasskeyOptions{Purpose: stepUpPurpose})
		_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b))
		h.requireStepUpRefused(t, err, alice)
	})
	t.Run("a second-factor payload under the passkey kind", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		a := securityKeyAuthenticator(t, true)
		h.enrollKey(t, a, alice)
		b := h.beginSecondFactor(t, alice, stepUp)
		puts, _ := h.flows.recorded()
		foreign := puts[len(puts)-1].flow
		foreign.Kind = "webauthn.passkey"
		const foreignID = "foreign-flow-id"
		if err := h.flows.Put(t.Context(), foreignID, foreign); err != nil {
			t.Fatalf("Put: %v", err)
		}
		e := stepUpExpect(alice, b)
		e.FlowID = foreignID
		_, err := h.finishSecondFactor(t, e, assertion(t, a, b))
		h.requireStepUpRefused(t, err, alice)
	})
}

// Check 2: a cross-origin iframe on another site.
func TestSecondFactor_TopOrigin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, stepUp, func(c *authtest.Ceremony) {
		c.CrossOrigin = true
		c.TopOrigin = "https://evil.example"
	})
	h.requireStepUpRefused(t, err, alice)
}

// Check 2: topOrigin present without crossOrigin.
func TestSecondFactor_TopOriginOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, stepUp, func(c *authtest.Ceremony) { c.TopOrigin = "https://evil.example" })
	h.requireStepUpRefused(t, err, alice)
}

func TestSecondFactor_WrongOrigin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	_, err := h.secondFactor(t, a, stepUp, func(c *authtest.Ceremony) { c.Origin = "https://evil.example.test" })
	h.requireStepUpRefused(t, err, alice)
}

// A body that is not JSON still consumes the flow: flows are single-use.
func TestSecondFactor_NotJSON(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := securityKeyAuthenticator(t, true)
	h.enrollKey(t, a, alice)
	b := h.beginSecondFactor(t, alice, stepUp)
	_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), []byte("not json"))
	h.requireStepUpRefused(t, err, alice)

	_, err = h.finishSecondFactor(t, stepUpExpect(alice, b), assertion(t, a, b))
	h.requireStepUpRefused(t, err, alice)
}

// A valid response padded with JSON whitespace: the size alone decides.
func TestSecondFactor_OversizedResponse(t *testing.T) {
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
			a := securityKeyAuthenticator(t, true)
			h.enrollKey(t, a, alice)
			b := h.beginSecondFactor(t, alice, stepUp)
			_, takesBefore := h.flows.recorded()
			resp := assertion(t, a, b)
			resp = append(resp, bytes.Repeat([]byte(" "), tc.size-len(resp))...)

			_, err := h.finishSecondFactor(t, stepUpExpect(alice, b), resp)
			if !tc.refuse {
				if err != nil {
					t.Fatalf("FinishSecondFactor with a %d-byte response: %v", tc.size, err)
				}
				return
			}
			h.requireStepUpRefused(t, err, alice)
			if _, takes := h.flows.recorded(); takes != takesBefore {
				t.Fatalf("an oversized response reached the flow store (%d Take calls)", takes-takesBefore)
			}
		})
	}
}

// At Finish, a listed credential the store answers with a
// zero value the library needs, or with a version it never writes, fails
// closed.
func TestSecondFactor_StoreFault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*webauthn.Credential)
	}{
		{"empty public key", func(c *webauthn.Credential) { c.PublicKey = nil }},
		{"zero version", func(c *webauthn.Credential) { c.Version = 0 }},
		{"version from the future", func(c *webauthn.Credential) { c.Version = webauthn.CurrentVersion + 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			a := securityKeyAuthenticator(t, true)
			h.enrollKey(t, a, alice)
			creds := listOverride{CredentialStore: h.creds, list: func(subject, rpID string) ([]webauthn.Credential, error) {
				list, err := h.creds.List(t.Context(), subject, rpID)
				for i := range list {
					tc.edit(&list[i])
				}
				return list, err
			}}
			b := h.beginSecondFactor(t, alice, stepUp)
			_, err := h.rp.FinishSecondFactor(t.Context(), h.flows, creds, stepUpExpect(alice, b), assertion(t, a, b))
			h.requireStepUpRefused(t, err, alice)
			if !strings.Contains(err.Error(), "store fault") {
				t.Fatalf("err = %v, want a store fault", err)
			}
		})
	}
}

// Programming errors are refused before any state is written, with an error
// that is not a verification failure.
func TestBeginSecondFactor_RefusesBadInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		subject string
		opts    webauthn.SecondFactorOptions
	}{
		{"empty subject", "", stepUp},
		{"empty purpose", alice.ID, webauthn.SecondFactorOptions{RequireUV: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			h.enrollKey(t, securityKeyAuthenticator(t, true), alice)
			putsBefore, _ := h.flows.recorded()
			_, err := h.rp.BeginSecondFactor(t.Context(), h.flows, h.creds, h.creds, tc.subject, tc.opts)
			if err == nil || isSentinel(err) {
				t.Fatalf("err = %v, want a plain error", err)
			}
			if puts, _ := h.flows.recorded(); len(puts) != len(putsBefore) {
				t.Fatalf("a refused Begin wrote %d flow(s)", len(puts)-len(putsBefore))
			}
		})
	}
}

// A user handle the store answers outside 1 to 64 bytes is a store fault,
// refused before any flow is written, as an infrastructure failure.
func TestBeginSecondFactor_UserHandleFault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		size  int
		fault bool
	}{
		{"empty", 0, true},
		{"one byte", 1, false},
		{"65 bytes", 65, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			h.enrollKey(t, securityKeyAuthenticator(t, true), alice)
			putsBefore, _ := h.flows.recorded()
			handles := ensureOverride{HandleStore: h.creds, handle: bytes.Repeat([]byte{7}, tc.size)}
			_, err := h.rp.BeginSecondFactor(t.Context(), h.flows, h.creds, handles, alice.ID, stepUp)
			puts, _ := h.flows.recorded()
			if !tc.fault {
				if err != nil || len(puts) != len(putsBefore)+1 {
					t.Fatalf("%d-byte handle: err = %v, %d flow(s) written", tc.size, err, len(puts)-len(putsBefore))
				}
				return
			}
			requireBeginStoreFault(t, err)
			if len(puts) != len(putsBefore) {
				t.Fatalf("a store fault wrote %d flow(s)", len(puts)-len(putsBefore))
			}
		})
	}
}

// At Begin, a store fault is an infrastructure failure,
// never ErrInvalidCredentials, which here also means "no credential": a
// caller that reads that as "not enrolled" and skips the factor must not be
// handed a broken store's answer.
func TestBeginSecondFactor_StoreFault(t *testing.T) {
	t.Parallel()
	for _, version := range []uint16{0, webauthn.CurrentVersion + 1} {
		t.Run(fmt.Sprintf("version %d", version), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			creds := listOverride{CredentialStore: h.creds, list: func(string, string) ([]webauthn.Credential, error) {
				return []webauthn.Credential{{
					Version: version, ID: []byte{1, 2, 3}, Subject: alice.ID, RPID: rpID, PublicKey: []byte{4, 5, 6},
					Algorithm: -7, CreatedAt: time.Unix(1_700_000_000, 0),
				}}, nil
			}}
			_, err := h.rp.BeginSecondFactor(t.Context(), h.flows, creds, h.creds, alice.ID, stepUp)
			requireBeginStoreFault(t, err)
			if puts, _ := h.flows.recorded(); len(puts) != 0 {
				t.Fatalf("a store fault wrote %d flow(s)", len(puts))
			}
		})
	}
}

// A failing store is an infrastructure error, never a verification result.
func TestBeginSecondFactor_StoreError(t *testing.T) {
	t.Parallel()
	down := errors.New("database is down")
	tests := []struct {
		name    string
		creds   func(webauthn.CredentialStore) webauthn.CredentialStore
		handles func(webauthn.HandleStore) webauthn.HandleStore
	}{
		{
			name: "List",
			creds: func(c webauthn.CredentialStore) webauthn.CredentialStore {
				return listOverride{CredentialStore: c, list: func(string, string) ([]webauthn.Credential, error) { return nil, down }}
			},
		},
		{
			name:    "Ensure",
			handles: func(hs webauthn.HandleStore) webauthn.HandleStore { return ensureOverride{HandleStore: hs, err: down} },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			h.enrollKey(t, securityKeyAuthenticator(t, true), alice)
			putsBefore, _ := h.flows.recorded()
			var (
				creds   webauthn.CredentialStore = h.creds
				handles webauthn.HandleStore     = h.creds
			)
			if tc.creds != nil {
				creds = tc.creds(creds)
			}
			if tc.handles != nil {
				handles = tc.handles(handles)
			}
			_, err := h.rp.BeginSecondFactor(t.Context(), h.flows, creds, handles, alice.ID, stepUp)
			if !errors.Is(err, down) || isSentinel(err) {
				t.Fatalf("err = %v, want the store's error and no sentinel", err)
			}
			if puts, _ := h.flows.recorded(); len(puts) != len(putsBefore) {
				t.Fatalf("a failed Begin wrote %d flow(s)", len(puts)-len(putsBefore))
			}
		})
	}
}

// A failing store at Finish is an infrastructure error, never a verification
// result and never a recorded use.
func TestFinishSecondFactor_StoreError(t *testing.T) {
	t.Parallel()
	down := errors.New("database is down")
	tests := []struct {
		name  string
		flows func(store.FlowStore) store.FlowStore
		creds func(webauthn.CredentialStore) webauthn.CredentialStore
	}{
		{
			name:  "Take",
			flows: func(f store.FlowStore) store.FlowStore { return takeOutage{FlowStore: f, err: down} },
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
			a := securityKeyAuthenticator(t, true)
			h.enrollKey(t, a, alice)
			var (
				flows store.FlowStore          = h.flows
				creds webauthn.CredentialStore = h.creds
			)
			if tc.flows != nil {
				flows = tc.flows(flows)
			}
			if tc.creds != nil {
				creds = tc.creds(creds)
			}
			b := h.beginSecondFactor(t, alice, stepUp)
			v, err := h.rp.FinishSecondFactor(t.Context(), flows, creds, stepUpExpect(alice, b), assertion(t, a, b))
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
