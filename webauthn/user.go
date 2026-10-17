package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

const userHandleSize = 64 // bytes from crypto/rand, created once per subject; also WebAuthn's maximum

// user adapts a subject and its stored credentials to go-webauthn's User.
type user struct {
	handle      []byte
	name        string
	displayName string
	creds       []gowebauthn.Credential
}

// newUser returns the adapter for the subject holding handle and creds.
func newUser(handle []byte, name, displayName string, creds []Credential) *user {
	u := &user{handle: handle, name: name, displayName: displayName, creds: make([]gowebauthn.Credential, len(creds))}
	for i := range creds {
		u.creds[i] = libraryCredential(&creds[i])
	}
	return u
}

func (u *user) WebAuthnID() []byte                           { return u.handle }
func (u *user) WebAuthnName() string                         { return u.name }
func (u *user) WebAuthnDisplayName() string                  { return u.displayName }
func (u *user) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

// descriptors returns the subject's credentials as excludeCredentials or
// allowCredentials entries.
func (u *user) descriptors() []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, len(u.creds))
	for i := range u.creds {
		out[i] = u.creds[i].Descriptor()
	}
	return out
}

// libraryCredential converts a stored credential to go-webauthn's form. The
// flags are rebuilt with NewCredentialFlags from the stored booleans, so the
// raw flags byte go-webauthn keeps agrees with them.
func libraryCredential(c *Credential) gowebauthn.Credential {
	var flags protocol.AuthenticatorFlags
	if c.UVInitialized {
		flags |= protocol.FlagUserVerified
	}
	if c.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	if c.BackupState {
		flags |= protocol.FlagBackupState
	}
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return gowebauthn.Credential{
		ID:            c.ID,
		PublicKey:     c.PublicKey,
		Transport:     transports,
		Flags:         gowebauthn.NewCredentialFlags(flags),
		Authenticator: gowebauthn.Authenticator{AAGUID: c.AAGUID[:], SignCount: c.SignCount},
	}
}

// storeFaultError is a record the store answered against its contract
// (design §4.2 rule 3). A Begin returns it as is: an infrastructure failure
// matching no sentinel, so a caller that branches on ErrInvalidCredentials
// never reads a broken store as "no credential". A Finish refuses the
// ceremony with it as ErrInvalidCredentials (refuseStoreFault).
type storeFaultError struct{ reason string }

func (e *storeFaultError) Error() string { return "webauthn: store fault: " + e.reason }

// refuseStoreFault returns err as ErrInvalidCredentials when it is a store
// fault, and unchanged otherwise.
func refuseStoreFault(err error) error {
	if fault, ok := errors.AsType[*storeFaultError](err); ok {
		return fail(ErrInvalidCredentials, "store fault: "+fault.reason, nil)
	}
	return err
}

// credentials loads the subject's credentials for this relying party. Design
// §4.2 rule 3: a credential the store answers with a zero value the library
// needs, a version the library never writes, or that belongs to another
// subject or RP ID, is a *storeFaultError. A store error is returned wrapped.
// Neither is a sentinel.
func (rp *RP) credentials(ctx context.Context, creds CredentialStore, subject string) ([]Credential, error) {
	list, err := creds.List(ctx, subject, rp.id)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	for i := range list {
		if reason := storeFault(&list[i], subject, rp.id); reason != "" {
			return nil, &storeFaultError{reason}
		}
	}
	return list, nil
}

// indexOf returns the index of the credential id in list, or -1.
func indexOf(list []Credential, id []byte) int {
	for i := range list {
		if bytes.Equal(list[i].ID, id) {
			return i
		}
	}
	return -1
}

// storeFault names what makes a loaded credential unusable, or returns "".
func storeFault(c *Credential, subject, rpID string) string {
	switch {
	case c.Version == 0:
		return "credential with a zero version"
	case c.Version > CurrentVersion:
		return fmt.Sprintf("credential version %d, newer than %d", c.Version, CurrentVersion)
	case len(c.ID) == 0:
		return "credential with an empty ID"
	case len(c.PublicKey) == 0:
		return "credential with an empty public key"
	case c.CreatedAt.IsZero():
		return "credential with a zero creation time"
	case c.Subject != subject:
		return "credential of another subject"
	case c.RPID != rpID: // an empty RP ID included
		return "credential of another RP ID"
	}
	return ""
}

// ensureHandle returns the subject's user handle, storing a fresh random one
// first when the subject has none. Only a Begin calls it. A handle the store
// answers outside 1 to 64 bytes is a *storeFaultError; a store error is
// returned wrapped.
func ensureHandle(ctx context.Context, handles HandleStore, subject string) ([]byte, error) {
	fresh := make([]byte, userHandleSize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("webauthn: user handle: %w", err)
	}
	handle, err := handles.Ensure(ctx, subject, fresh)
	if err != nil {
		return nil, fmt.Errorf("webauthn: ensure user handle: %w", err)
	}
	if len(handle) == 0 || len(handle) > userHandleSize {
		return nil, &storeFaultError{fmt.Sprintf("user handle of %d bytes", len(handle))}
	}
	return handle, nil
}
