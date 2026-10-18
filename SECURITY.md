# Security Policy

## Supported versions

| Version        | Supported                                                  |
| -------------- | ---------------------------------------------------------- |
| 2.0.0-alpha.\* | best effort                                                |
| 1.x            | security fixes for twelve months from the `v2.0.0` release |
| < 1.0          | no                                                         |

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

In scope: every package in this repository.

Out of scope: defects that require a compromised Go toolchain or physical access
to the running process.

## Design boundaries a consumer must respect

go-auth verifies credentials and emits verified facts. It does not own identity.
Several security properties are therefore the consuming application's
responsibility, and the library cannot enforce them on your behalf:

- **Storage confidentiality.** The store behind the library, and its backups,
  are yours to protect.
- **Transport.** Use HTTPS, and set `Secure` and `HttpOnly` on any cookie that
  carries a credential.
- **Identity decisions.** Whether an assertion refers to an existing user, which
  tenant they belong to, and whether they may be provisioned on first sight are
  application decisions.

Security notes for v1 are on `main` until `v2.0.0`, then on the `v1` branch.
