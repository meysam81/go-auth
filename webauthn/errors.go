package webauthn

import "errors"

var (
	// ErrInvalidCredentials is returned for every verification failure: an
	// unknown subject, a subject without the credential, and a wrong proof alike.
	ErrInvalidCredentials = errors.New("webauthn: invalid credentials")

	// ErrUnknownCredential is returned by a discoverable sign-in when the
	// presented credential or user handle maps to no subject.
	ErrUnknownCredential = errors.New("webauthn: unknown credential")

	// ErrCloneSuspected is returned when a valid signature carried a signature
	// counter that went backwards.
	ErrCloneSuspected = errors.New("webauthn: clone suspected")
)

// failure is a ceremony failure: it matches one sentinel, carries a reason for
// logs and wraps the underlying cause, never shown to a client.
type failure struct {
	sentinel error
	reason   string
	cause    error
}

// fail builds a failure that satisfies errors.Is(err, sentinel).
func fail(sentinel error, reason string, cause error) error {
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
