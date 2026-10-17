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

// SecondFactorOptions selects how a second-factor or step-up assertion is
// requested.
type SecondFactorOptions struct {
	Purpose   string // e.g. "login", "stepup"; bound into the flow, FinishSecondFactor's Expect must name it
	RequireUV bool   // user verification "required" instead of "preferred"
}

// BeginSecondFactor starts an assertion for subject, whom the caller has
// already authenticated: a second factor after a password sign-in, or a
// step-up within a session. The options list exactly the subject's
// credentials for this RP ID in allowCredentials and set user verification to
// "preferred", or "required" when opts.RequireUV is set. It writes one flow
// that FinishSecondFactor consumes.
//
// A subject with no credential for this RP ID is ErrInvalidCredentials; no
// flow is written and no user handle created. An empty subject or
// opts.Purpose is a programming error: Begin returns a plain error and writes
// nothing. A store error is returned wrapped; a user handle or stored
// credential that fails the store contract is ErrInvalidCredentials. Error
// text is for logs, never for a client.
func (rp *RP) BeginSecondFactor(ctx context.Context, flows store.FlowStore, creds CredentialStore, handles HandleStore, subject string, opts SecondFactorOptions) (Begun, error) {
	switch {
	case subject == "":
		return Begun{}, errors.New("webauthn: subject is required")
	case opts.Purpose == "":
		return Begun{}, errors.New("webauthn: purpose is required")
	}
	list, err := rp.credentials(ctx, creds, subject)
	if err != nil {
		return Begun{}, err
	}
	if len(list) == 0 {
		return Begun{}, fail(ErrInvalidCredentials, "subject holds no credential for this RP ID", nil)
	}
	handle, err := ensureHandle(ctx, handles, subject)
	if err != nil {
		return Begun{}, err
	}

	uv := protocol.VerificationPreferred
	if opts.RequireUV {
		uv = protocol.VerificationRequired
	}
	// BeginLogin lists the adapter's credentials in allowCredentials and
	// records them, with the user handle, in the session.
	request, session, err := rp.wa.BeginLogin(newUser(handle, "", "", list), gowebauthn.WithUserVerification(uv))
	if err != nil {
		return Begun{}, fmt.Errorf("webauthn: begin second factor: %w", err)
	}
	options, err := json.Marshal(request.Response)
	if err != nil {
		return Begun{}, fmt.Errorf("webauthn: encode request options: %w", err)
	}
	id, err := putFlow(ctx, flows, flowSecondFactor, &flowPayload{
		Purpose:   opts.Purpose,
		Subject:   subject,
		Handle:    handle,
		RPID:      rp.id,
		RequireUV: session.UserVerification == protocol.VerificationRequired,
		Session:   *session,
	}, session.Expires)
	if err != nil {
		return Begun{}, err
	}
	return Begun{FlowID: id, Options: options, Mediation: string(request.Mediation)}, nil
}

// FinishSecondFactor verifies response, the browser's
// PublicKeyCredential.toJSON() of an assertion, against the flow e names.
// e.Subject must name the subject BeginSecondFactor was called for.
//
// The credential must be one the options listed and one the subject still
// holds for this RP ID. A credential of another subject or RP ID, or one
// registered or removed since Begin, is ErrInvalidCredentials, never
// ErrUnknownCredential: the caller already knows the subject. go-webauthn also
// requires the subject to still hold every credential the options listed, so
// removing any of them fails a ceremony in flight; a fresh Begin lists what
// remains.
//
// Finish enforces what Begin recorded in the flow: user verification is
// required only when Begin's opts.RequireUV was set, and Expect carries no UV
// requirement of its own. Give a UV-required ceremony its own purpose, or
// check that Verified.Methods holds mfa, which it does only when this
// assertion verified the user.
//
// A valid signature whose counter did not advance past a non-zero stored
// counter marks the credential clone-suspected and is ErrCloneSuspected. Every
// other verification failure is ErrInvalidCredentials: a response larger than
// 64 KiB and an assertion the store did not record included. A store error is
// returned wrapped. The flow is consumed by every attempt that reaches it, a
// response that fails to parse included. Error text is for logs, never for a
// client.
func (rp *RP) FinishSecondFactor(ctx context.Context, flows store.FlowStore, creds CredentialStore, e Expect, response []byte) (Verified, error) {
	if len(response) > maxResponseSize {
		return Verified{}, fail(ErrInvalidCredentials, "response larger than 64 KiB", nil)
	}
	p, err := rp.takeFlow(ctx, flows, e, flowSecondFactor)
	if err != nil {
		return Verified{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Verified{}, fail(ErrInvalidCredentials, "unreadable assertion response", err)
	}

	// Check 6, against the credentials the subject holds now: one removed
	// since Begin is simply absent.
	list, err := rp.credentials(ctx, creds, p.Subject)
	if err != nil {
		return Verified{}, err
	}
	i := indexOf(list, parsed.RawID)
	if i < 0 {
		return Verified{}, fail(ErrInvalidCredentials, "credential not among the subject's credentials for this RP ID", nil)
	}
	u := newUser(p.Handle, "", "", list)
	u.creds[i] = assertionCredential(&list[i], parsed.Response.AuthenticatorData.Flags)

	// go-webauthn checks that the subject holds every credential the session
	// listed and that this one was listed, the user handle when the response
	// carries one, the challenge, type, origin, crossOrigin and topOrigin, the
	// RP ID hash, UP, UV when the session requires it, the signature
	// (canonical DER for ECDSA), BE against the credential's and BE=0 with
	// BS=1. Its *protocol.ErrorUnknownCredential, like every refusal here, is
	// ErrInvalidCredentials.
	if _, err = rp.wa.ValidateLogin(u, p.Session, parsed); err != nil {
		return Verified{}, fail(ErrInvalidCredentials, "assertion refused", err)
	}
	return rp.settle(ctx, creds, list[i], &parsed.Response.AuthenticatorData, rp.now())
}
