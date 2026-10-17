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
	// matches exactly one sentinel.
	ErrUnknownCredential = errors.New("webauthn: unknown credential")

	// ErrCloneSuspected is returned when a valid signature carried a counter
	// that did not advance past a non-zero stored counter (equal or lower). A
	// failure matches exactly one sentinel.
	ErrCloneSuspected = errors.New("webauthn: clone suspected")
)

// failure is a ceremony failure: it matches exactly one sentinel, carries a
// reason for logs and wraps the underlying cause, never shown to a client.
type failure struct {
	sentinel error
	reason   string
	cause    error
}

// fail builds a failure that satisfies errors.Is for sentinel and for no other
// sentinel. It panics when sentinel is not one of the three exported ones. A
// cause whose chain carries a sentinel is flattened to its text so the result
// stays exclusive; any other cause stays reachable through errors.As.
func fail(sentinel error, reason string, cause error) error {
	if !isSentinel(sentinel) {
		panic("webauthn: fail called with a non-sentinel error")
	}
	if cause != nil && (errors.Is(cause, ErrInvalidCredentials) ||
		errors.Is(cause, ErrUnknownCredential) || errors.Is(cause, ErrCloneSuspected)) {
		cause = errors.New(cause.Error())
	}
	return &failure{sentinel: sentinel, reason: reason, cause: cause}
}

func isSentinel(err error) bool {
	return err == ErrInvalidCredentials || err == ErrUnknownCredential || err == ErrCloneSuspected //nolint:errorlint // identity of the sentinels
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
