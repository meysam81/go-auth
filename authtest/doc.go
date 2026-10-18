// Package authtest is test support for go-auth and for the applications built
// on it. It is a normal importable package, not a _test.go file, so an
// application's own tests can use it.
//
// [Authenticator] is a software WebAuthn authenticator: ES256 or Ed25519 keys,
// attestation "none", flags and a signature counter set by configuration, and
// [Tamper] hooks that edit what it is about to sign. It produces the responses
// a browser's PublicKeyCredential.toJSON() would, so a relying party is tested
// end to end against real signatures, and every security check can be shown
// to refuse a forged origin, challenge, ceremony type, RP ID hash, flag or
// counter rather than a mock that pretends to.
//
// The authenticator models a client an attacker may control: it signs
// whatever its configuration and Tampers say, never what the relying party
// asked for. Never use it outside tests.
package authtest
