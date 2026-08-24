# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | yes       |
| < 1.0   | no        |

## Reporting a vulnerability

Report privately through GitHub's
[security advisory form](https://github.com/meysam81/go-auth/security/advisories/new).
Please do not open a public issue for a security defect.

Include what you have: the affected package and version, a description of the
impact, and — if you have one — a minimal reproducer. A failing Go test is the
most useful thing you can send.

Expect an initial response within seven days. Confirmed issues are fixed on a
branch, released, and then disclosed in an advisory crediting the reporter
unless anonymity is requested.

## Scope

In scope: everything under `auth/`, `session/`, `middleware/`, `storage/`,
`provider/`, and `audit/`.

Out of scope: the contents of `examples/`, which exist to illustrate wiring and
are not intended for production use; and defects that require a compromised Go
toolchain or physical access to the running process.

## Design boundaries a consumer must respect

go-auth verifies credentials and emits verified facts. It does not own identity.
Several security properties are therefore the consuming application's
responsibility, and the library cannot enforce them on your behalf:

- **Storage confidentiality.** The library hashes what should be hashed before
  handing it to your store, but the store itself — and its backups — are yours
  to protect.
- **Store fidelity.** A store must round-trip a whole record, not the fields it
  recognises. `OIDCState.CodeVerifier`, `OIDCState.BindingHash`,
  `OIDCState.Nonce`, `User.ProviderSubject` and the `Metadata` maps each carry a
  control the library later refuses to proceed without. Dropping one is refused
  (`ErrStateControlMissing`), not silently tolerated.
- **Transport.** Use HTTPS. Set `Secure` and `HttpOnly` on session cookies, or
  build the writer with `middleware.NewSecureCookieWriter`, which sets both and
  validates the rest. The zero-value `CookieWriter` is not secure.
- **Outbound HTTP policy.** When an identity provider's issuer URL is supplied
  by an operator rather than fixed at build time, supply an `HTTPClient` whose
  transport refuses to dial private address ranges. The library bounds the
  timeout and the response size but will not ship its own dialer policy; see
  `docs/security-hardening.md` §F-20.
- **Identity decisions.** Whether an assertion refers to an existing user, which
  tenant they belong to, and whether they may be provisioned on first sight are
  application decisions. The library gives you verified claims and declines to
  guess: `oidc.Config.CreatePolicy` and `oidc.Config.LinkPolicy` are where you
  answer, and a nil policy refuses.

## Controls you have to opt into

These are off unless you turn them on. A deployment that upgrades without
touching its configuration does not get them:

- **OIDC login-CSRF binding (F-16).** Only
  `Client.GetAuthorizationURLWithBinding` + `Client.HandleCallbackWithBinding`
  bind a flow to the browser that started it. The older
  `GetAuthorizationURL`/`HandleCallback` pair is deprecated and still exposed.
- **TOTP secret encryption (F-06).** `totp.Config.Cipher` encrypts the shared
  secret at rest. Backup codes are hashed either way.
- **JWT issuer and audience checks (F-03).** Enforced only when
  `jwt.Config.Issuer` / `.Audience` are set.
- **Microsoft multi-tenant issuer check (F-30).** `provider.NewMicrosoftProvider`
  targets the `common` endpoint, which has no fixed issuer, so it verifies
  signature and audience but not `iss`. Check the `tid` claim yourself, or use
  `NewOIDCProvider` with a tenant-specific issuer URL.

## Known issues, already reported

Please do not spend a report on these — they are recorded, with the reasoning,
in [`docs/security-hardening.md`](docs/security-hardening.md):

- **F-29** — `webauthn.Authenticator.BeginLogin` answers an unknown identifier
  and a credential-less account with different errors, which is an
  account-existence oracle on an unauthenticated endpoint. It cannot be closed
  inside v1 without silently changing what existing callers are told; the v2 fix
  is designed and the test is written.
- **F-15** — `middleware.BasicAuthMiddleware` runs one bcrypt evaluation per
  request and cannot carry a second factor. Deprecated, removed in v2, and
  documented as unsafe to mount on any route an untrusted client can reach.
- **F-30** — the Microsoft constructor's issuer check, above.

A hardening audit of this library, every finding it produced — including the
defects two independent adversarial reviews found in the fixes themselves — and
the plan closing them is tracked in
[`docs/security-hardening.md`](docs/security-hardening.md). Upgrading within
v1.x preserves compilation but changes several run-time behaviours on purpose;
§7 of that document is the checklist.
