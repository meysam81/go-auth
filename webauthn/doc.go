// Package webauthn is a thin, opinionated layer over go-webauthn: it decides
// what is allowed, binds every ceremony to its purpose, and owns the checks
// go-webauthn leaves to its caller.
//
// The package never sees a user record. A subject is an opaque string the
// application chooses, and credentials and user handles live in the stores the
// application supplies.
package webauthn
