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
	// SecurityKey is requested with the security-key hint and user
	// verification preferred.
	SecurityKey CredentialKind = 2
)

// Credential schema versions. A loaded credential with a version outside 1 to
// CurrentVersion is a store fault.
const (
	// ImportedVersion marks a credential imported from v1, whose backup flags
	// were never recorded: its first assertion records them and moves it to
	// CurrentVersion (design §8).
	ImportedVersion uint16 = 1
	// CurrentVersion is the credential schema version the library writes.
	CurrentVersion uint16 = 2
)

// Credential is one stored WebAuthn credential.
type Credential struct {
	Version          uint16 // set by the library; 0 or above CurrentVersion on load is a store fault
	ID               []byte
	Subject          string
	RPID             string
	PublicKey        []byte // COSE_Key
	Algorithm        int
	AAGUID           [16]byte // kept for naming even when unattested
	Transports       []string // self-reported; a hint, never evidence. nil and empty alike mean none reported
	SignCount        uint32
	BackupEligible   bool // fixed at creation; set once by the first assertion of an ImportedVersion credential
	BackupState      bool
	UVInitialized    bool
	Discoverable     *bool // credProps rk; nil when the client did not report it
	CreatedAt        time.Time
	LastUsedAt       time.Time
	CloneSuspectedAt time.Time // non-zero: refused until the application clears it
}

// AssertionUpdate is what one verified assertion changes.
type AssertionUpdate struct {
	Subject        string
	CredentialID   []byte
	PrevSignCount  uint32 // the counter the library read; the update applies only while it still holds
	SignCount      uint32
	BackupEligible bool // equals the stored value except when adopting an ImportedVersion credential
	BackupState    bool
	Version        uint16    // CurrentVersion after any assertion
	At             time.Time // becomes the credential's last_used_at
}

// CredentialStore holds WebAuthn credentials. Rename, delete and listing for a
// settings page are the application's own queries; the library calls only these.
// Times are kept to the microsecond, as package [store] says.
type CredentialStore interface {
	// Insert stores a new credential. It returns store.ErrDuplicate when ANY
	// subject already holds this credential ID (a unique index on the ID, not
	// on (subject, ID)), and for no other refusal: a CHECK, a NOT NULL or
	// another unique index of the application's is some other error.
	Insert(ctx context.Context, c Credential) error

	// List returns the subject's credentials for this RP ID.
	List(ctx context.Context, subject, rpID string) ([]Credential, error)

	// RecordAssertion applies one verified assertion only while the stored
	// counter still equals u.PrevSignCount, as one conditional update:
	//
	//	UPDATE ... SET sign_count = ?, backup_eligible = ?, backup_state = ?,
	//	  version = ?, last_used_at = ?
	//	WHERE subject = ? AND credential_id = ? AND sign_count = ?
	//
	// applied=false means no row matched (a concurrent assertion won); the
	// caller fails. A matched row is applied=true even when no value changes
	// (a counter that stays 0, a last-used time equal to the stored one): count
	// matched rows, not changed ones.
	RecordAssertion(ctx context.Context, u AssertionUpdate) (applied bool, err error)

	// MarkCloneSuspected records a counter regression on the credential by
	// setting its CloneSuspectedAt to at. The library refuses the credential
	// from then on; clearing the mark is the application's own query. It
	// returns store.ErrNotFound when no credential matches, and nil for a
	// matched one even when it already holds at: count matched rows, not
	// changed ones.
	MarkCloneSuspected(ctx context.Context, subject string, id []byte, at time.Time) error
}

// HandleStore maps subjects to their WebAuthn user handle.
type HandleStore interface {
	// Ensure returns the subject's handle, storing h first when it has none
	// (create-if-absent; two concurrent callers get the same handle back).
	// When the subject has none and another subject holds h, it returns an
	// error and stores nothing: a handle resolves to one subject, and is
	// never moved.
	Ensure(ctx context.Context, subject string, h []byte) ([]byte, error)

	// Subject resolves a handle from a discoverable assertion, comparing bytes
	// exactly. It returns store.ErrNotFound when no subject holds it.
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
