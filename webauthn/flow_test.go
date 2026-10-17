package webauthn

import (
	"context"
	"reflect"
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

// Every SessionData field go-webauthn reads at Finish survives the flow
// payload, Expires included: go-webauthn enforces the timeout from it.
func TestFlow_RoundTripsSessionData(t *testing.T) {
	t.Parallel()
	rp, err := New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	in := flowPayload{
		Purpose:   "enroll",
		Subject:   "subject-alice",
		Handle:    []byte{1, 2, 3},
		RPID:      rp.ID(),
		RequireUV: true,
		Session: gowebauthn.SessionData{
			Challenge:            "Y2hhbGxlbmdlLWNoYWxsZW5nZQ",
			RelyingPartyID:       rp.ID(),
			Origin:               "https://app.example.test",
			UserID:               []byte{1, 2, 3},
			AllowedCredentialIDs: [][]byte{{4, 5}, {6}},
			Expires:              time.Unix(1_700_000_000, 123_456_789).UTC(),
			UserVerification:     protocol.VerificationRequired,
			Extensions:           protocol.SessionExtensions{Requested: []string{"credProps"}},
			CredParams: []protocol.CredentialParameter{
				{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
			},
			Mediation:                 protocol.MediationConditional,
			AuthorizeUVInitialization: true,
		},
	}
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
