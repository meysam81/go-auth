package webauthn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/meysam81/go-auth/v2/amr"
	"github.com/meysam81/go-auth/v2/store"
)

// importedVersion is the credential version of a credential imported from v1,
// whose backup flags were never recorded (design §8).
const importedVersion uint16 = 1

// assertionCredential returns stored in go-webauthn's form for verifying an
// assertion whose authenticator data carries flags. go-webauthn refuses an
// assertion whose BE differs from the credential's (check 7), so a credential
// keeps its stored BE, which is fixed at creation. An imported Version 1
// credential has no recorded BE: it takes BE and BS from this assertion, and
// settle records them. BE=0 with BS=1 is refused by go-webauthn either way.
func assertionCredential(stored *Credential, flags protocol.AuthenticatorFlags) gowebauthn.Credential {
	c := *stored
	if c.Version == importedVersion {
		c.BackupEligible, c.BackupState = flags.HasBackupEligible(), flags.HasBackupState()
	}
	return libraryCredential(&c)
}

// settle completes an assertion go-webauthn has verified against
// assertionCredential(&stored, asserted.Flags): it applies the counter rule
// (check 8), records the assertion (check 9) and returns the verified facts.
//
// asserted is the assertion's own authenticator data. The credential
// go-webauthn returns is not read: its UV flag is the stored uvInitialized
// latch, not this assertion's, and after a regression its counter is the
// stored one.
func (rp *RP) settle(ctx context.Context, creds CredentialStore, stored Credential, asserted *protocol.AuthenticatorData, now time.Time) (Verified, error) {
	received := asserted.Counter
	// Both zero is a synced passkey, which never counts; a counter above the
	// stored one advances. Anything else, with a non-zero stored counter, is
	// a counter that went backwards or stood still: a cloned authenticator.
	if stored.SignCount != 0 && received <= stored.SignCount {
		switch err := creds.MarkCloneSuspected(ctx, stored.Subject, stored.ID, now); {
		case errors.Is(err, store.ErrNotFound):
			return Verified{}, fail(ErrInvalidCredentials, "credential removed during the ceremony", nil)
		case err != nil:
			return Verified{}, fmt.Errorf("webauthn: mark clone suspected: %w", err)
		}
		return Verified{}, fail(ErrCloneSuspected,
			fmt.Sprintf("signature counter %d did not advance past the stored %d", received, stored.SignCount), nil)
	}

	flags := asserted.Flags
	be, bs := flags.HasBackupEligible(), flags.HasBackupState()
	applied, err := creds.RecordAssertion(ctx, AssertionUpdate{
		Subject:        stored.Subject,
		CredentialID:   stored.ID,
		PrevSignCount:  stored.SignCount,
		SignCount:      received,
		BackupEligible: be, // the stored BE, or the adopted one of a Version 1 credential
		BackupState:    bs,
		Version:        CurrentVersion,
		At:             now,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Verified{}, fail(ErrInvalidCredentials, "credential removed during the ceremony", nil)
	case err != nil:
		return Verified{}, fmt.Errorf("webauthn: record assertion: %w", err)
	case !applied:
		return Verified{}, fail(ErrInvalidCredentials, "assertion not recorded: the stored counter changed concurrently", nil)
	}

	methods := []amr.Method{amr.HWK}
	if be {
		methods[0] = amr.SWK
	}
	if flags.HasUserVerified() {
		methods = append(methods, amr.MFA)
	}
	return Verified{
		Subject:        stored.Subject,
		CredentialID:   stored.ID,
		UserVerified:   flags.HasUserVerified(),
		BackupEligible: be,
		BackupState:    bs,
		AAGUID:         stored.AAGUID,
		Methods:        methods,
		At:             now,
	}, nil
}
