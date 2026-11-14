package oauthrs

import "errors"

// ErrInvalidToken is every extraction and verification failure: no bearer
// token, a malformed or repeated Authorization header, a token in the URI
// query, and a token that is not an active access token from the issuer.
var ErrInvalidToken = errors.New("oauthrs: invalid token")

// failure matches ErrInvalidToken and carries a reason for logs only.
type failure struct{ reason string }

func fail(reason string) error { return &failure{reason: reason} }

func (f *failure) Error() string { return ErrInvalidToken.Error() + ": " + f.reason }

// Is reports whether target is ErrInvalidToken.
func (f *failure) Is(target error) bool { return target == ErrInvalidToken }
