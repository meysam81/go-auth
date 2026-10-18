package webauthn

import "errors"

var (
	// ErrInvalidCredentials is returned for every verification failure except
	// the two documented exceptions, ErrUnknownCredential and
	// ErrCloneSuspected: an unknown subject, a subject without the credential,
	// and a wrong proof alike. A failure matches exactly one of the three.
	ErrInvalidCredentials = errors.New("webauthn: invalid credentials")

	// ErrUnknownCredential is returned by a discoverable sign-in when the
	// presented credential or user handle maps to no subject. A failure
	// matches exactly one sentinel. The error's text says which of the two
	// missed; it is for logs only, never for a client.
	ErrUnknownCredential = errors.New("webauthn: unknown credential")

	// ErrCloneSuspected is returned when a valid signature carried a counter
	// that did not advance past a non-zero stored counter (equal or lower),
	// and for every later valid signature of a credential so marked. The error
	// is a *CloneSuspectedError. A failure matches exactly one sentinel.
	ErrCloneSuspected = errors.New("webauthn: clone suspected")
)

// CloneSuspectedError is every ErrCloneSuspected failure: errors.Is matches
// ErrCloneSuspected and no other sentinel, and errors.As retrieves it.
//
// When New is true, this ceremony set the mark: tell the credential's owner,
// Subject. Two concurrent regressing ceremonies can both report New, so
// deduplicate the notices by CredentialID. Subject and CredentialID stay on
// the server: the refused client gets the same answer as any failed sign-in.
// A marked credential is refused, whatever its counter, until the
// application, after the owner confirms, clears its CloneSuspectedAt in its
// own store, or deletes it; the store interfaces have no method for either.
type CloneSuspectedError struct {
	Subject      string
	CredentialID []byte
	New          bool // this ceremony set the mark

	reason string
}

// Error returns the failure with its reason, for logs only.
func (e *CloneSuspectedError) Error() string {
	if e.reason == "" {
		return ErrCloneSuspected.Error()
	}
	return ErrCloneSuspected.Error() + ": " + e.reason
}

// Is reports whether target is ErrCloneSuspected.
func (e *CloneSuspectedError) Is(target error) bool { return target == ErrCloneSuspected }

// failure is a ceremony failure: it matches exactly one sentinel, carries a
// reason for logs and wraps the underlying cause, never shown to a client.
type failure struct {
	sentinel error
	reason   string
	cause    error
}

// fail builds a failure that satisfies errors.Is for sentinel and for no other
// sentinel. It panics unless sentinel is ErrInvalidCredentials or
// ErrUnknownCredential: an ErrCloneSuspected failure is a
// *CloneSuspectedError. A cause whose chain carries a sentinel is flattened to
// its text so the result stays exclusive; any other cause stays reachable
// through errors.As.
func fail(sentinel error, reason string, cause error) error {
	if sentinel != ErrInvalidCredentials && sentinel != ErrUnknownCredential { //nolint:errorlint // identity of the sentinels
		panic("webauthn: fail called with an error other than ErrInvalidCredentials or ErrUnknownCredential")
	}
	if cause != nil && (errors.Is(cause, ErrInvalidCredentials) ||
		errors.Is(cause, ErrUnknownCredential) || errors.Is(cause, ErrCloneSuspected)) {
		cause = errors.New(cause.Error())
	}
	return &failure{sentinel: sentinel, reason: reason, cause: cause}
}

func (f *failure) Error() string {
	if f.cause == nil {
		return "webauthn: " + f.reason
	}
	return "webauthn: " + f.reason + ": " + f.cause.Error()
}

// Is reports whether target is the failure's sentinel.
func (f *failure) Is(target error) bool { return target == f.sentinel }

// Unwrap returns the cause so errors.As still reaches the underlying error.
func (f *failure) Unwrap() error { return f.cause }
