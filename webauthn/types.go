package webauthn

import (
	"context"
	"encoding/json"
	"time"

	"github.com/meysam81/go-auth/v2/amr"
)

// Subject is who a ceremony is for.
type Subject struct {
	ID          string // the application's key; opaque to the library
	Name        string // shown by credential managers, e.g. an email address
	DisplayName string
}

// CredentialKind is the kind of credential a registration creates.
type CredentialKind uint8

const (
	// Passkey is a discoverable credential with user verification required.
	Passkey CredentialKind = 1
	// SecurityKey is a roaming credential with user verification preferred.
	SecurityKey CredentialKind = 2
)

// CurrentVersion is the credential schema version the library writes. Version 1
// is reserved for credentials imported from v1, whose backup flags were never
// recorded.
const CurrentVersion uint16 = 2

// Credential is one stored WebAuthn credential.
type Credential struct {
	Version          uint16 // set by the library; zero on load is a store fault
	ID               []byte
	Subject          string
	RPID             string
	PublicKey        []byte // COSE_Key
	Algorithm        int
	AAGUID           [16]byte // kept for naming even when unattested
	Transports       []string // self-reported; a hint, never evidence
	SignCount        uint32
	BackupEligible   bool // fixed at creation
	BackupState      bool
	UVInitialized    bool
	Discoverable     *bool // credProps rk; nil when the client did not report it
	CreatedAt        time.Time
	LastUsedAt       time.Time
	CloneSuspectedAt time.Time
}

// AssertionUpdate is what one verified assertion changes.
type AssertionUpdate struct {
	Subject        string
	CredentialID   []byte
	PrevSignCount  uint32 // the counter the library read; the update applies only while it still holds
	SignCount      uint32
	BackupEligible bool // equals the stored value except when adopting a Version 1 credential
	BackupState    bool
	Version        uint16 // CurrentVersion after any assertion
	At             time.Time
}

// CredentialStore holds WebAuthn credentials. Rename, delete and listing for a
// settings page are the application's own queries; the library calls only these.
type CredentialStore interface {
	// Insert stores a new credential. It returns store.ErrDuplicate when ANY
	// subject already holds this credential ID (a unique index on the ID, not
	// on (subject, ID)).
	Insert(ctx context.Context, c Credential) error

	// List returns the subject's credentials for this RP ID.
	List(ctx context.Context, subject, rpID string) ([]Credential, error)

	// RecordAssertion applies one verified assertion only while the stored
	// counter still equals u.PrevSignCount. applied=false means a concurrent
	// assertion won; the caller fails.
	RecordAssertion(ctx context.Context, u AssertionUpdate) (applied bool, err error)

	// MarkCloneSuspected records a counter regression on the credential.
	MarkCloneSuspected(ctx context.Context, subject string, id []byte, at time.Time) error
}

// HandleStore maps subjects to their WebAuthn user handle.
type HandleStore interface {
	// Ensure returns the subject's handle, storing h first when it has none
	// (create-if-absent; two concurrent callers get the same handle back).
	Ensure(ctx context.Context, subject string, h []byte) ([]byte, error)

	// Subject resolves a handle from a discoverable assertion. It returns
	// store.ErrNotFound when no subject holds it.
	Subject(ctx context.Context, handle []byte) (string, error)
}

// Begun is what a Begin function returns to the caller.
type Begun struct {
	FlowID    string
	Options   json.RawMessage // the publicKey object for parse*OptionsFromJSON
	Mediation string          // "" or "conditional"
}

// Expect is what a Finish function checks the flow against.
type Expect struct{ FlowID, Purpose, Subject string }

// Verified is the set of facts a verified assertion establishes.
type Verified struct {
	Subject        string
	CredentialID   []byte
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
	AAGUID         [16]byte
	Methods        []amr.Method // hwk or swk, plus mfa when UserVerified
	At             time.Time
}
