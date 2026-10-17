package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/meysam81/go-auth/v2/store"
)

// PasskeyOptions selects how a passkey sign-in is offered.
type PasskeyOptions struct {
	Purpose     string // bound into the flow; FinishPasskey's Expect must name it
	Conditional bool   // mediation "conditional" (autofill)
}

// BeginPasskey starts a sign-in with no identifier. The options list no
// credentials and require user verification, so every caller gets the same
// answer whether or not any account exists. It writes one flow that
// FinishPasskey consumes.
//
// An empty opts.Purpose is a programming error: Begin returns a plain error
// and writes nothing. A store error is returned wrapped.
func (rp *RP) BeginPasskey(ctx context.Context, flows store.FlowStore, opts PasskeyOptions) (Begun, error) {
	if opts.Purpose == "" {
		return Begun{}, errors.New("webauthn: purpose is required")
	}
	mediation := protocol.MediationDefault
	if opts.Conditional {
		mediation = protocol.MediationConditional
	}
	request, session, err := rp.wa.BeginDiscoverableMediatedLogin(mediation,
		gowebauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Begun{}, fmt.Errorf("webauthn: begin passkey sign-in: %w", err)
	}
	options, err := json.Marshal(request.Response)
	if err != nil {
		return Begun{}, fmt.Errorf("webauthn: encode request options: %w", err)
	}
	id, err := putFlow(ctx, flows, flowPasskey, &flowPayload{
		Purpose:   opts.Purpose,
		RPID:      rp.id,
		RequireUV: session.UserVerification == protocol.VerificationRequired,
		Session:   *session,
	}, session.Expires)
	if err != nil {
		return Begun{}, err
	}
	return Begun{FlowID: id, Options: options, Mediation: string(request.Mediation)}, nil
}

// FinishPasskey verifies response, the browser's PublicKeyCredential.toJSON()
// of a discoverable assertion, against the flow e names. The subject comes
// from the assertion's user handle, so e.Subject must be empty.
//
// A user handle no subject holds, or a credential ID that subject does not
// hold for this RP ID, is ErrUnknownCredential: the credential's holder may
// tell its authenticator the credential is gone. A valid signature whose
// counter did not advance past a non-zero stored counter marks the credential
// clone-suspected and is ErrCloneSuspected; a valid signature of a credential
// already marked is ErrCloneSuspected too, with no new mark and no recorded
// use. Either is a *CloneSuspectedError, which names the subject. Every other
// verification failure is ErrInvalidCredentials: a response larger than 64
// KiB, one without user verification or without a user handle or with one
// longer than 64 bytes, and an assertion the store did not record included. A
// store error is returned wrapped. The flow is consumed by every attempt that
// reaches it, a response that fails to parse included. That Take and the mark
// must persist when Finish fails: pass a FlowStore outside any transaction
// you roll back on failure, and commit MarkCloneSuspected (or give it a store
// of its own) before rolling back. Error text is for logs, never for a client.
func (rp *RP) FinishPasskey(ctx context.Context, flows store.FlowStore, creds CredentialStore, handles HandleStore, e Expect, response []byte) (Verified, error) {
	if len(response) > maxResponseSize {
		return Verified{}, fail(ErrInvalidCredentials, "response larger than 64 KiB", nil)
	}
	p, err := rp.takeFlow(ctx, flows, e, flowPasskey)
	if err != nil {
		return Verified{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Verified{}, fail(ErrInvalidCredentials, "unreadable assertion response", err)
	}
	switch n := len(parsed.Response.UserHandle); {
	case n == 0:
		return Verified{}, fail(ErrInvalidCredentials, "discoverable assertion without a user handle", nil)
	case n > userHandleSize:
		return Verified{}, fail(ErrInvalidCredentials, fmt.Sprintf("user handle of %d bytes, longer than 64", n), nil)
	}

	// go-webauthn calls the handler before verifying the assertion and wraps
	// its error in its own; the handler's outcome is carried out unchanged in
	// lookupErr instead, so an unknown credential, a store fault and a store
	// outage each keep their own classification.
	var (
		stored    Credential
		lookupErr error
	)
	handler := func(rawID, handle []byte) (gowebauthn.User, error) {
		if stored, lookupErr = rp.discover(ctx, creds, handles, rawID, handle); lookupErr != nil {
			return nil, lookupErr
		}
		lc := assertionCredential(&stored, parsed.Response.AuthenticatorData.Flags)
		return &user{handle: handle, creds: []gowebauthn.Credential{lc}}, nil
	}
	// go-webauthn checks the challenge, type, origin, crossOrigin and
	// topOrigin, the RP ID hash, UP, UV (the session requires it), the
	// signature (canonical DER for ECDSA), that the user handle is the
	// handler's user's, BE against the credential's and BE=0 with BS=1.
	_, _, err = rp.wa.ValidatePasskeyLogin(handler, p.Session, parsed)
	switch {
	case lookupErr != nil:
		return Verified{}, lookupErr
	case err != nil:
		return Verified{}, fail(ErrInvalidCredentials, "assertion refused", err)
	}
	return rp.settle(ctx, creds, stored, &parsed.Response.AuthenticatorData, rp.now())
}

// discover resolves a discoverable assertion to the stored credential (check
// 5): the user handle must resolve to a subject, and the credential ID must
// be among that subject's credentials for this RP ID. Either miss is
// ErrUnknownCredential. A store error is returned wrapped; an empty subject or
// a listed credential that fails rule 3 is a store fault, refused as
// ErrInvalidCredentials.
func (rp *RP) discover(ctx context.Context, creds CredentialStore, handles HandleStore, rawID, handle []byte) (Credential, error) {
	subject, err := handles.Subject(ctx, handle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Credential{}, fail(ErrUnknownCredential, "user handle held by no subject", nil)
	case err != nil:
		return Credential{}, fmt.Errorf("webauthn: resolve user handle: %w", err)
	case subject == "":
		return Credential{}, fail(ErrInvalidCredentials, "store fault: user handle resolves to an empty subject", nil)
	}
	list, err := rp.credentials(ctx, creds, subject)
	if err != nil {
		return Credential{}, refuseStoreFault(err)
	}
	if i := indexOf(list, rawID); i >= 0 {
		return list[i], nil
	}
	return Credential{}, fail(ErrUnknownCredential, "credential not held by the user handle's subject for this RP ID", nil)
}
