package webauthn

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/meysam81/go-auth/v2/store"
)

// mapFlows is a minimal store.FlowStore; this package's own tests cannot
// import authtest, which imports this package.
type mapFlows struct {
	flows map[string]store.Flow
	mu    sync.Mutex
}

func (m *mapFlows) Put(_ context.Context, id string, f store.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.flows[id]; ok {
		return store.ErrDuplicate
	}
	m.flows[id] = f
	return nil
}

func (m *mapFlows) Take(_ context.Context, id string) (store.Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flows[id]
	if !ok {
		return store.Flow{}, store.ErrNotFound
	}
	delete(m.flows, id)
	return f, nil
}

// validPayload returns a register payload every check of rp.takeFlow accepts,
// with every SessionData field go-webauthn reads at Finish set. Origin stays
// empty: the package never binds a ceremony to one origin.
func validPayload(rp *RP) flowPayload {
	return flowPayload{
		Purpose:   "enroll",
		Subject:   "subject-alice",
		Handle:    []byte{1, 2, 3},
		RPID:      rp.ID(),
		RequireUV: true,
		Session: gowebauthn.SessionData{
			Challenge:            "Y2hhbGxlbmdlLWNoYWxsZW5nZQ",
			RelyingPartyID:       rp.ID(),
			UserID:               []byte{1, 2, 3},
			AllowedCredentialIDs: [][]byte{{4, 5}, {6}},
			Expires:              time.Unix(1_700_000_000, 123_456_789).UTC(),
			UserVerification:     protocol.VerificationRequired,
			Extensions:           protocol.SessionExtensions{Requested: []string{"credProps"}},
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			},
			Mediation:                 protocol.MediationConditional,
			AuthorizeUVInitialization: true,
		},
	}
}

func newTestRP(t *testing.T) *RP {
	t.Helper()
	rp, err := New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rp
}

// Every SessionData field go-webauthn reads at Finish survives the flow
// payload, Expires included: go-webauthn enforces the timeout from it.
func TestFlow_RoundTripsSessionData(t *testing.T) {
	t.Parallel()
	rp := newTestRP(t)
	in := validPayload(rp)
	flows := &mapFlows{flows: make(map[string]store.Flow)}
	id, err := putFlow(t.Context(), flows, flowRegister, &in, in.Session.Expires)
	if err != nil {
		t.Fatalf("putFlow: %v", err)
	}
	if f := flows.flows[id]; f.Kind != flowRegister || !f.ExpiresAt.Equal(in.Session.Expires) {
		t.Fatalf("stored flow kind %q expiring %v, want %q expiring %v", f.Kind, f.ExpiresAt, flowRegister, in.Session.Expires)
	}

	out, err := rp.takeFlow(t.Context(), flows, Expect{FlowID: id, Purpose: in.Purpose, Subject: in.Subject}, flowRegister)
	if err != nil {
		t.Fatalf("takeFlow: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("payload changed in the round trip:\n got %+v\nwant %+v", out, in)
	}
}

// The flow store is the application's: what the package can derive from its
// own configuration, it cross-checks on every take, and a payload that
// disagrees is a store fault.
func TestTakeFlow_StoreFaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*flowPayload)
	}{
		{"session for another RP ID", func(p *flowPayload) { p.Session.RelyingPartyID = "other.test" }},
		{"session bound to an origin", func(p *flowPayload) { p.Session.Origin = "https://app.example.test" }},
		{"session algorithm outside the configuration", func(p *flowPayload) {
			p.Session.CredParams = append(p.Session.CredParams,
				protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES384})
		}},
		{"UV required by the package, not the session", func(p *flowPayload) { p.Session.UserVerification = protocol.VerificationPreferred }},
		{"UV required by the session, not the package", func(p *flowPayload) { p.RequireUV = false }},
		{"register flow names no subject", func(p *flowPayload) { p.Subject = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rp := newTestRP(t)
			p := validPayload(rp)
			tc.edit(&p)
			flows := &mapFlows{flows: make(map[string]store.Flow)}
			id, err := putFlow(t.Context(), flows, flowRegister, &p, p.Session.Expires)
			if err != nil {
				t.Fatalf("putFlow: %v", err)
			}
			_, err = rp.takeFlow(t.Context(), flows, Expect{FlowID: id, Purpose: p.Purpose, Subject: p.Subject}, flowRegister)
			if !errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "store fault") {
				t.Fatalf("err = %v, want a store-fault ErrInvalidCredentials", err)
			}
		})
	}
}

// A passkey flow names no subject and always requires user verification: the
// package writes no other kind, so a payload that does is a store fault, even
// when the Expect agrees with it.
func TestTakeFlow_PasskeyStoreFaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(*flowPayload)
		fault bool
	}{
		{"valid", func(*flowPayload) {}, false},
		{"passkey flow names a subject", func(p *flowPayload) { p.Subject = "subject-alice" }, true},
		{"passkey flow without user verification", func(p *flowPayload) {
			p.RequireUV = false
			p.Session.UserVerification = protocol.VerificationPreferred
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rp := newTestRP(t)
			p := validPayload(rp)
			p.Subject, p.Handle, p.Session.UserID = "", nil, nil
			tc.edit(&p)
			flows := &mapFlows{flows: make(map[string]store.Flow)}
			id, err := putFlow(t.Context(), flows, flowPasskey, &p, p.Session.Expires)
			if err != nil {
				t.Fatalf("putFlow: %v", err)
			}
			_, err = rp.takeFlow(t.Context(), flows, Expect{FlowID: id, Purpose: p.Purpose, Subject: p.Subject}, flowPasskey)
			if !tc.fault {
				if err != nil {
					t.Fatalf("takeFlow: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "store fault") {
				t.Fatalf("err = %v, want a store-fault ErrInvalidCredentials", err)
			}
		})
	}
}
