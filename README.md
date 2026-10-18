# go-auth

[![CI](https://img.shields.io/github/actions/workflow/status/meysam81/go-auth/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&style=flat-square)](https://github.com/meysam81/go-auth/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/meysam81/go-auth?style=flat-square)](LICENSE)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white&style=flat-square)](https://www.conventionalcommits.org)

Authentication primitives for Go. Each package verifies one kind of credential
and returns a verified fact; your application owns users, sessions and every
identity decision.

## v2 alpha

The `v2` branch carries the v2 module, in alpha. `main` keeps v1
(`github.com/meysam81/go-auth`) until `v2.0.0`, when `v2` merges into it. The v2
import path is:

```go
import "github.com/meysam81/go-auth/v2/store"
```

Expect breaking changes between alpha releases until `v2.0.0`.

### What the first phase (G1) contains

- `webauthn`: registration, passkey sign-in and second-factor ceremonies over
  [go-webauthn](https://github.com/go-webauthn/webauthn), with the checks the
  design lists in §5.4.
- `amr`: authentication methods (RFC 8176), factor classes and policy.
- `store`: the single-use `FlowStore` for short-lived ceremony state, and the
  shared `ErrNotFound` / `ErrDuplicate` sentinels.
- `authtest`: conformance suites for your stores, in-memory stores and a
  virtual authenticator for your own tests.

`examples/passkeys` is a runnable demonstration. It is not production code.

More packages land phase by phase; this list names only what the repository
contains today. The full design, including the planned package layout, is in
[`docs/v2-design.md`](docs/v2-design.md).

### Quickstart: WebAuthn

Configure the relying party once. The RP ID is fixed for the life of every
credential.

```go
rp, err := webauthn.New(webauthn.Config{
	RPID:    "example.com",
	RPName:  "Example",
	Origins: []string{"https://app.example.com"},
})
```

You supply three stores, passed on every call and never held: a
`store.FlowStore` (single-use ceremony state), a `webauthn.CredentialStore` and
a `webauthn.HandleStore`. Each `Begin` returns `Begun`: send `Options` to the
browser (`PublicKeyCredential.parse*OptionsFromJSON`), pass `Mediation` to the
`navigator.credentials` call when it is set (`"conditional"`), and keep
`FlowID` beside the session. Each `Finish` takes the browser's `toJSON()`
output and an `Expect` naming the flow, the purpose and, where the ceremony has
one, the subject.

```go
// Add a credential for a subject you have already authenticated.
sub := webauthn.Subject{ID: userID, Name: "alice@example.com", DisplayName: "Alice"}
begun, err := rp.BeginRegistration(ctx, flows, creds, handles, sub,
	webauthn.RegistrationOptions{Kind: webauthn.Passkey, Purpose: "enroll"})
// ... browser round trip ...
cred, err := rp.FinishRegistration(ctx, flows, creds,
	webauthn.Expect{FlowID: begun.FlowID, Purpose: "enroll", Subject: userID}, body)

// Sign in with no identifier. The result is a verified fact: you decide
// what it means for your user.
begun, err = rp.BeginPasskey(ctx, flows, webauthn.PasskeyOptions{Purpose: "login"})
verified, err := rp.FinishPasskey(ctx, flows, creds, handles,
	webauthn.Expect{FlowID: begun.FlowID, Purpose: "login"}, body)

// A second factor, or a step-up, for a subject you have already identified.
begun, err = rp.BeginSecondFactor(ctx, flows, creds, handles, userID,
	webauthn.SecondFactorOptions{Purpose: "stepup", RequireUV: true})
verified, err = rp.FinishSecondFactor(ctx, flows, creds,
	webauthn.Expect{FlowID: begun.FlowID, Purpose: "stepup", Subject: userID}, body)
```

Every verification failure matches exactly one of `webauthn.ErrInvalidCredentials`,
`webauthn.ErrUnknownCredential` and `webauthn.ErrCloneSuspected` (a duplicate
credential ID on registration is `store.ErrDuplicate`). Branch with
`errors.Is`. An error that matches none of them is an infrastructure failure,
such as a store outage or a store answering against its contract: answer it as
a server error (500), never as a failed sign-in. An error's text is for logs
only: never send it to a client.

`ErrCloneSuspected` is a `*webauthn.CloneSuspectedError` (`errors.As`). When
its `New` is true, that ceremony marked the credential: tell its `Subject`
that the key may have been cloned. Two concurrent ceremonies can both report
`New`, so deduplicate the notices by `CredentialID`. `Subject` and
`CredentialID` stay on the server: answer the refused client exactly as any
failed sign-in. A marked credential is refused until you clear its
`CloneSuspectedAt` in your store after the owner confirms, or delete it.

Decide whether a subject needs a second factor from your own records, never
from `BeginSecondFactor`'s error: its `ErrInvalidCredentials` means the
subject holds no credential to assert, and a subject your records hold as
enrolled whose `Begin` fails, for any reason, is refused, not let through.

If you import subjects from v1, seed their user handles through your
`HandleStore` before the first `BeginRegistration` or `BeginSecondFactor`:
both call `Ensure`, which creates a handle for a subject that has none.
`BeginPasskey` takes no `HandleStore`.

#### Implement the stores, then prove them

Map `CredentialStore` and `HandleStore` onto your own tables, and `FlowStore`
onto a table or cache with an atomic take. Pass stores bound to your request's
transaction, so a new credential and your own writes commit together, with two
writes that must persist even when a `Finish` fails: the flow `Take` (pass a
`FlowStore` outside any transaction you roll back on failure) and
`MarkCloneSuspected` (commit it, or give it a store of its own, before rolling
back).

The library never deletes a flow: `Take` only refuses consumed and expired
ones, so purge them on a schedule. `BeginPasskey` is unauthenticated and
writes a flow per call: rate-limit it.

Then run the conformance suites in your tests; they exercise the contract a
database can get wrong, such as a single-use `Take` under concurrency and a
conditional `RecordAssertion`.

```go
func TestStores(t *testing.T) {
	t.Run("FlowStore", authtest.FlowStoreSuite(func(t *testing.T) store.FlowStore {
		return newFlowStore(t)
	}))
	t.Run("WebAuthnStore", authtest.WebAuthnStoreSuite(authtest.WebAuthnHarness{
		NewStores: func(t *testing.T) (webauthn.CredentialStore, webauthn.HandleStore) {
			s := newCredentialStore(t)
			return s, s
		},
		NewSubject: func(t *testing.T) string { return uuid.NewString() },
	}))
}
```

`authtest.NewMemoryFlowStore` and `authtest.NewMemoryWebAuthnStore` are
in-memory implementations for tests, and `authtest.NewAuthenticator` signs real
registrations and assertions so your handlers are tested end to end.

## v1

v1 lives on the `v1` branch. Its import path is unchanged:

```go
import "github.com/meysam81/go-auth"
```

v1 receives security fixes as described in [`SECURITY.md`](SECURITY.md).

## Contributing

Commits follow [Conventional Commits](https://www.conventionalcommits.org).
Run `golangci-lint run` and `go test -race ./...` before opening a pull request.

## License

See [`LICENSE`](LICENSE).
