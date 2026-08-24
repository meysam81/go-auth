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
- **Transport.** Use HTTPS. Set `Secure` and `HttpOnly` on session cookies.
- **Outbound HTTP policy.** When an identity provider's issuer URL is supplied
  by an operator rather than fixed at build time, supply an `HTTPClient` whose
  transport refuses to dial private address ranges. The library will not ship
  its own dialer policy; see `docs/security-hardening.md` §F-20.
- **Identity decisions.** Whether an assertion refers to an existing user, which
  tenant they belong to, and whether they may be provisioned on first sight are
  application decisions. The library gives you verified claims and declines to
  guess.

A hardening audit of this library, its findings, and the plan closing them is
tracked in [`docs/security-hardening.md`](docs/security-hardening.md).
