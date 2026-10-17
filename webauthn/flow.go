package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/meysam81/go-auth/v2/store"
)

// Flow kinds: the ceremony that wrote a flow. A Finish takes only its own kind.
const (
	flowRegister     = "webauthn.register"
	flowPasskey      = "webauthn.passkey" //nolint:gosec // G101: a flow kind, not a credential
	flowSecondFactor = "webauthn.second_factor"
)

const (
	flowIDSize = 32 // bytes from crypto/rand, sent base64url

	// maxResponseSize bounds the response a Finish reads. A browser's toJSON()
	// output is a few KiB; anything past 64 KiB is refused unparsed.
	maxResponseSize = 64 << 10
)

// flowPayload is the state a Begin writes and its Finish reads. The
// application stores it without interpreting it.
type flowPayload struct {
	Purpose string `json:"purpose"`
	Subject string `json:"subject,omitempty"` // empty for a passkey sign-in
	Handle  []byte `json:"handle,omitempty"`
	RPID    string `json:"rp_id"`

	// RequireUV is the package's own record that the ceremony requires user
	// verification, kept apart from the session go-webauthn enforces it from.
	// takeFlow refuses a payload where the two disagree.
	RequireUV bool `json:"require_uv"`

	Session gowebauthn.SessionData `json:"session"` // go-webauthn's documented JSON form
}

// newFlowID returns a fresh flow ID: 32 bytes from crypto/rand, base64url.
func newFlowID() (string, error) {
	b := make([]byte, flowIDSize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("webauthn: flow ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// putFlow stores p as a flow of kind under a fresh ID, expiring at expires,
// and returns the ID.
func putFlow(ctx context.Context, flows store.FlowStore, kind string, p *flowPayload, expires time.Time) (string, error) {
	id, err := newFlowID()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("webauthn: encode flow: %w", err)
	}
	if err = flows.Put(ctx, id, store.Flow{Kind: kind, Payload: payload, ExpiresAt: expires}); err != nil {
		return "", fmt.Errorf("webauthn: store flow: %w", err)
	}
	return id, nil
}

// takeFlow consumes the flow e names and returns its payload, decoded into a
// fresh value. The flow must be of kind, written by this relying party, for
// e.Purpose and for e.Subject, and agree with what the package itself writes
// (payloadFault). Every refusal is ErrInvalidCredentials; a store error other
// than store.ErrNotFound is returned wrapped, as the infrastructure failure it
// is.
func (rp *RP) takeFlow(ctx context.Context, flows store.FlowStore, e Expect, kind string) (flowPayload, error) {
	if e.FlowID == "" {
		return flowPayload{}, fail(ErrInvalidCredentials, "no flow ID", nil)
	}
	f, err := flows.Take(ctx, e.FlowID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return flowPayload{}, fail(ErrInvalidCredentials, "flow missing, expired or already used", nil)
	case err != nil:
		return flowPayload{}, fmt.Errorf("webauthn: take flow: %w", err)
	case f.Kind != kind:
		return flowPayload{}, fail(ErrInvalidCredentials, "flow of another ceremony", nil)
	}

	var p flowPayload
	if err = json.Unmarshal(f.Payload, &p); err != nil {
		return flowPayload{}, fail(ErrInvalidCredentials, "store fault: unreadable flow payload", err)
	}
	switch {
	case p.RPID != rp.id:
		return flowPayload{}, fail(ErrInvalidCredentials, "flow of another relying party", nil)
	case p.Purpose != e.Purpose:
		return flowPayload{}, fail(ErrInvalidCredentials, "flow for another purpose", nil)
	case p.Subject != e.Subject:
		return flowPayload{}, fail(ErrInvalidCredentials, "flow for another subject", nil)
	}
	if reason := rp.payloadFault(&p, kind); reason != "" {
		return flowPayload{}, fail(ErrInvalidCredentials, "store fault: "+reason, nil)
	}
	return p, nil
}

// payloadFault names what in a flow of kind disagrees with what the package
// writes, or returns "". The flow store is the application's, so every value
// the package can derive from its own configuration is checked again: register
// and second-factor flows name a subject, the session is for this RP ID and
// bound to no single origin, its algorithms are configured ones, and the two
// user-verification records agree.
func (rp *RP) payloadFault(p *flowPayload, kind string) string {
	s := &p.Session
	switch {
	case (kind == flowRegister || kind == flowSecondFactor) && p.Subject == "":
		return "flow names no subject"
	case s.RelyingPartyID != rp.id:
		return "session for another RP ID"
	case s.Origin != "":
		return "session bound to an origin"
	case p.RequireUV != (s.UserVerification == protocol.VerificationRequired):
		return "user verification records disagree"
	}
	for _, cp := range s.CredParams {
		if !slices.Contains(rp.algorithms, int(cp.Algorithm)) {
			return fmt.Sprintf("session algorithm %d is not configured", cp.Algorithm)
		}
	}
	return ""
}
