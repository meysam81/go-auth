package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/meysam81/go-auth/v2/store"
)

// RegistrationOptions selects what a registration creates.
type RegistrationOptions struct {
	Kind        CredentialKind
	Purpose     string // bound into the flow; FinishRegistration's Expect must name it
	Conditional bool   // mediation "conditional" (an upgrade after a password sign-in); Passkey only
}

// BeginRegistration starts adding a credential for sub, a subject the caller
// has already authenticated. It creates the subject's user handle on first
// use, lists the subject's credentials in excludeCredentials, and writes one
// flow that FinishRegistration consumes.
//
// An empty sub.ID, sub.Name or opts.Purpose, a Kind other than Passkey or
// SecurityKey, or a conditional SecurityKey, is a programming error: Begin
// returns a plain error and writes nothing. A store error is returned
// wrapped; a user handle or stored credential that fails the store contract
// is ErrInvalidCredentials.
func (rp *RP) BeginRegistration(ctx context.Context, flows store.FlowStore, creds CredentialStore, handles HandleStore, sub Subject, opts RegistrationOptions) (Begun, error) {
	if err := validateRegistration(sub, opts); err != nil {
		return Begun{}, err
	}
	handle, err := ensureHandle(ctx, handles, sub.ID)
	if err != nil {
		return Begun{}, err
	}
	existing, err := rp.credentials(ctx, creds, sub.ID)
	if err != nil {
		return Begun{}, err
	}

	u := newUser(handle, sub.Name, sub.DisplayName, existing)
	mediation := protocol.MediationDefault
	if opts.Conditional {
		mediation = protocol.MediationConditional
	}
	creation, session, err := rp.wa.BeginMediatedRegistration(u, mediation, rp.registrationOptions(u, opts)...)
	if err != nil {
		return Begun{}, fmt.Errorf("webauthn: begin registration: %w", err)
	}
	options, err := json.Marshal(creation.Response)
	if err != nil {
		return Begun{}, fmt.Errorf("webauthn: encode creation options: %w", err)
	}
	id, err := putFlow(ctx, flows, flowRegister, &flowPayload{
		Purpose:   opts.Purpose,
		Subject:   sub.ID,
		Handle:    handle,
		RPID:      rp.id,
		RequireUV: session.UserVerification == protocol.VerificationRequired,
		Session:   *session,
	}, session.Expires)
	if err != nil {
		return Begun{}, err
	}
	return Begun{FlowID: id, Options: options, Mediation: string(creation.Mediation)}, nil
}

func validateRegistration(sub Subject, opts RegistrationOptions) error {
	switch {
	case sub.ID == "":
		return errors.New("webauthn: subject ID is required")
	case sub.Name == "":
		return errors.New("webauthn: subject name is required")
	case opts.Purpose == "":
		return errors.New("webauthn: purpose is required")
	case opts.Kind != Passkey && opts.Kind != SecurityKey:
		return fmt.Errorf("webauthn: unknown credential kind %d", opts.Kind)
	case opts.Conditional && opts.Kind != Passkey:
		// Conditional create is a password manager upgrading a password
		// sign-in to a passkey, and it skips user presence.
		return errors.New("webauthn: only a passkey registration can be conditional")
	}
	return nil
}

// registrationOptions returns the creation options for opts: the configured
// algorithms only, credProps, no attestation, the subject's credentials
// excluded. A passkey requires a resident key and user verification (preferred
// for a conditional create); a security key discourages a resident key,
// prefers user verification and carries the security-key hint.
func (rp *RP) registrationOptions(u *user, opts RegistrationOptions) []gowebauthn.RegistrationOption {
	params := make([]protocol.CredentialParameter, len(rp.algorithms))
	for i, alg := range rp.algorithms {
		params[i] = protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.COSEAlgorithmIdentifier(alg),
		}
	}
	common := []gowebauthn.RegistrationOption{
		gowebauthn.WithExclusions(u.descriptors()),
		gowebauthn.WithCredentialParameters(params),
		gowebauthn.WithExtensions(gowebauthn.WithExtensionCredProps()),
		gowebauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	}

	if opts.Kind == Passkey {
		uv := protocol.VerificationRequired
		if opts.Conditional {
			uv = protocol.VerificationPreferred
		}
		return append(common,
			gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: uv}),
			gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	}
	return append(common,
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationPreferred}),
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged),
		gowebauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintSecurityKey}))
}

// FinishRegistration verifies response, the browser's
// PublicKeyCredential.toJSON() of the new credential, against the flow e
// names, and stores the credential.
//
// Every verification failure is ErrInvalidCredentials, a response larger than
// 64 KiB included. A credential ID any subject already holds is returned so
// that errors.Is(err, store.ErrDuplicate) holds; the application must not
// resolve it by re-binding the credential. Any other store error is returned
// wrapped. The flow is consumed by every attempt that reaches it, a response
// that fails to parse included.
func (rp *RP) FinishRegistration(ctx context.Context, flows store.FlowStore, creds CredentialStore, e Expect, response []byte) (Credential, error) {
	if len(response) > maxResponseSize {
		return Credential{}, fail(ErrInvalidCredentials, "response larger than 64 KiB", nil)
	}
	p, err := rp.takeFlow(ctx, flows, e, flowRegister)
	if err != nil {
		return Credential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Credential{}, fail(ErrInvalidCredentials, "unreadable registration response", err)
	}
	// go-webauthn checks the challenge, type, origin, crossOrigin and
	// topOrigin, the RP ID hash, UP (unless conditional), UV when the session
	// requires it, the key's algorithm against the session's credParams, and
	// BE=0 with BS=1.
	got, err := rp.wa.CreateCredential(newUser(p.Handle, "", "", nil), p.Session, parsed)
	if err != nil {
		return Credential{}, fail(ErrInvalidCredentials, "registration response refused", err)
	}
	alg, err := keyAlgorithm(got.PublicKey)
	if err != nil {
		return Credential{}, fail(ErrInvalidCredentials, "unreadable credential public key", err)
	}

	c := Credential{
		Version:        CurrentVersion,
		ID:             got.ID,
		Subject:        p.Subject,
		RPID:           rp.id,
		PublicKey:      got.PublicKey,
		Algorithm:      alg,
		SignCount:      got.Authenticator.SignCount,
		BackupEligible: got.Flags.BackupEligible,
		BackupState:    got.Flags.BackupState,
		UVInitialized:  got.Flags.UserVerified,
		Discoverable:   got.Extensions.RK,
		CreatedAt:      rp.now(),
	}
	copy(c.AAGUID[:], got.Authenticator.AAGUID)
	for _, t := range got.Transport {
		c.Transports = append(c.Transports, string(t))
	}

	if err = creds.Insert(ctx, c); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			// The store's words stay in the text; only store.ErrDuplicate is
			// wrapped, so no sentinel in the store's chain reaches the result.
			return Credential{}, fmt.Errorf("webauthn: credential ID already registered: %w (store: %s)", store.ErrDuplicate, err.Error())
		}
		return Credential{}, fmt.Errorf("webauthn: insert credential: %w", err)
	}
	return c, nil
}

// keyAlgorithm returns the COSE algorithm of an attested credential public
// key. The client-reported publicKeyAlgorithm is never read: no signature
// covers it.
func keyAlgorithm(coseKey []byte) (int, error) {
	var pk webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(coseKey, &pk); err != nil {
		return 0, err
	}
	return int(pk.Algorithm), nil
}
