package webauthn_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

// fuzzRig is one relying party with fresh memory stores and one authenticator.
// Every fuzz iteration builds its own rig and begins its own flow, so a
// response the fuzzer finds is answering a challenge it never saw.
type fuzzRig struct {
	rp    *webauthn.RP
	flows store.FlowStore
	store *authtest.MemoryWebAuthnStore
	auth  *authtest.Authenticator
}

func newFuzzRig(tb testing.TB, a *authtest.Authenticator) *fuzzRig {
	tb.Helper()
	rp, err := webauthn.New(webauthn.Config{RPID: rpID, RPName: "Example", Origins: []string{origin}})
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return &fuzzRig{rp: rp, flows: authtest.NewMemoryFlowStore(nil), store: authtest.NewMemoryWebAuthnStore(), auth: a}
}

func fuzzAuthenticator(tb testing.TB) *authtest.Authenticator {
	tb.Helper()
	a, err := authtest.NewAuthenticator(authtest.AuthenticatorConfig{UserVerified: true, Discoverable: true})
	if err != nil {
		tb.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// beginRegistration begins a passkey registration for alice and returns the
// flow with the authenticator's response to it.
func (r *fuzzRig) beginRegistration(tb testing.TB) (webauthn.Begun, []byte) {
	tb.Helper()
	b, err := r.rp.BeginRegistration(tb.Context(), r.flows, r.store, r.store, alice, passkey)
	if err != nil {
		tb.Fatalf("BeginRegistration: %v", err)
	}
	resp, err := r.auth.Register(b.Options, origin)
	if err != nil {
		tb.Fatalf("Register: %v", err)
	}
	return b, resp
}

// enroll registers the authenticator's passkey for alice.
func (r *fuzzRig) enroll(tb testing.TB) {
	tb.Helper()
	b, resp := r.beginRegistration(tb)
	if _, err := r.rp.FinishRegistration(tb.Context(), r.flows, r.store, expectFor(alice, b), resp); err != nil {
		tb.Fatalf("FinishRegistration: %v", err)
	}
}

// validAssertion enrolls, begins a sign-in and returns the authenticator's
// response to it.
func (r *fuzzRig) validAssertion(tb testing.TB) []byte {
	tb.Helper()
	r.enroll(tb)
	b, err := r.rp.BeginPasskey(tb.Context(), r.flows, signIn)
	if err != nil {
		tb.Fatalf("BeginPasskey: %v", err)
	}
	resp, err := r.auth.Assert(b.Options, origin)
	if err != nil {
		tb.Fatalf("Assert: %v", err)
	}
	return resp
}

// addSeeds adds the corpus every target starts from: a valid response to
// another flow, empty and null JSON, a truncated response and a response one
// byte over the size limit.
func addSeeds(f *testing.F, valid []byte) {
	f.Helper()
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add(valid[:len(valid)/2])
	f.Add(bytes.Repeat([]byte(" "), 64<<10+1))
}

// requireRefusal fails unless err is a refusal the contract allows: exactly one
// of the three sentinels, or store.ErrDuplicate alone. A nil error would mean
// the input answered a challenge it never saw.
func requireRefusal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a response to a flow it never saw was accepted")
	}
	n := 0
	for _, s := range []error{webauthn.ErrInvalidCredentials, webauthn.ErrUnknownCredential,
		webauthn.ErrCloneSuspected, store.ErrDuplicate} {
		if errors.Is(err, s) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("err = %v matches %d sentinels, want exactly 1", err, n)
	}
}

func FuzzFinishRegistration(f *testing.F) {
	a := fuzzAuthenticator(f)
	_, valid := newFuzzRig(f, a).beginRegistration(f)
	addSeeds(f, valid)
	f.Fuzz(func(t *testing.T, response []byte) {
		r := newFuzzRig(t, a)
		b, _ := r.beginRegistration(t)
		_, err := r.rp.FinishRegistration(t.Context(), r.flows, r.store, expectFor(alice, b), response)
		requireRefusal(t, err)
	})
}

func FuzzFinishPasskey(f *testing.F) {
	a := fuzzAuthenticator(f)
	addSeeds(f, newFuzzRig(f, a).validAssertion(f))
	f.Fuzz(func(t *testing.T, response []byte) {
		r := newFuzzRig(t, a)
		r.enroll(t)
		b, err := r.rp.BeginPasskey(t.Context(), r.flows, signIn)
		if err != nil {
			t.Fatalf("BeginPasskey: %v", err)
		}
		_, err = r.rp.FinishPasskey(t.Context(), r.flows, r.store, r.store, signInExpect(b), response)
		requireRefusal(t, err)
	})
}

func FuzzFinishSecondFactor(f *testing.F) {
	a := fuzzAuthenticator(f)
	addSeeds(f, newFuzzRig(f, a).validAssertion(f))
	f.Fuzz(func(t *testing.T, response []byte) {
		r := newFuzzRig(t, a)
		r.enroll(t)
		b, err := r.rp.BeginSecondFactor(t.Context(), r.flows, r.store, r.store, alice.ID, stepUp)
		if err != nil {
			t.Fatalf("BeginSecondFactor: %v", err)
		}
		_, err = r.rp.FinishSecondFactor(t.Context(), r.flows, r.store, stepUpExpect(alice, b), response)
		requireRefusal(t, err)
	})
}
