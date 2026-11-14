// Package oauthrs is the protected-resource side of OAuth 2.0: it reads a
// bearer token from a request (RFC 6750), verifies it at an introspection
// endpoint (RFC 7662), publishes the resource's metadata document (RFC 9728)
// and writes the challenge a refused request carries.
//
// The package never sees a user record. A verified [Token] is a fact about a
// token; the application decides what its subject, client and extension
// claims mean.
//
// Verification asks for an access token. An answer that is not active, whose
// token_use is not "access_token" (a refresh token is active too), whose
// issuer differs, or that lacks a subject, a client or a future expiry is
// refused. RFC 7662 does not define token_use (Ory Hydra returns it), so an
// endpoint that omits it is refused rather than trusted.
//
// Every extraction and verification failure matches [ErrInvalidToken] and
// nothing else: a missing or malformed header and a bad token are answered
// alike. An error that matches nothing is an infrastructure failure (the
// endpoint was unreachable or slow, answered a status other than 200, or sent
// a body over the cap): answer it as a server error, never as a refused
// token. An error's text is for logs only and never carries the token.
//
// Requests go through the *http.Client the application supplies, which must
// carry a Timeout; the package never follows a redirect.
package oauthrs
