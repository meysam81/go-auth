package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	Purpose   string                 `json:"purpose"`
	Subject   string                 `json:"subject,omitempty"` // empty for a passkey sign-in
	Handle    []byte                 `json:"handle,omitempty"`
	RPID      string                 `json:"rp_id"`
	RequireUV bool                   `json:"require_uv"`
	Session   gowebauthn.SessionData `json:"session"` // go-webauthn's documented JSON form
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
// e.Purpose and for e.Subject; register and second-factor flows always name a
// subject, a passkey flow never does. Every refusal is ErrInvalidCredentials;
// a store error other than store.ErrNotFound is returned wrapped, as the
// infrastructure failure it is.
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
	case (kind == flowRegister || kind == flowSecondFactor) && p.Subject == "":
		return flowPayload{}, fail(ErrInvalidCredentials, "store fault: flow names no subject", nil)
	}
	return p, nil
}
