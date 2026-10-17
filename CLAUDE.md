# CLAUDE.md

This file provides guidance for AI assistants working on the go-auth project.

## Project Overview

go-auth v2 is a set of authentication primitives for Go: each package verifies
one kind of credential and returns a verified fact. There is no user store and
no identity decision in the library. The design is `docs/v2-design.md`; v1
lives on the `v1` branch.

## Build & Test Commands

```bash
go build ./... && go vet ./...
go test -race ./...
golangci-lint run
```

## Project Structure

One module, `github.com/meysam81/go-auth/v2`, at the repository root. The phase
column is the delivery order; only G1 packages exist before their phase ships.

```
(repository root)
  amr/          authentication methods (RFC 8176), factor classes, policy        G1
  webauthn/     registration, second-factor and passkey ceremonies              G1
  store/        the single-use FlowStore and the shared error sentinels         G1
  authtest/     conformance suites and a virtual authenticator                  G1
  challenge/    typed hand-off token, durable challenge state, step-up          G2
  attempt/      failed-attempt budgets                                          G2
  totp/         RFC 6238 enrolment and validation, durable replay guard         G2
  recovery/     recovery codes: generation, keyed digests, legacy verifiers     G2
  token/        opaque secret mint / digest / verify (reset, verification)      G3
  session/      session identifiers, rotation, refresh families                 G3
  oidcrp/       OIDC relying party: handshake in, verified claims out           G3
  httpx/        outbound transport that refuses non-public addresses            G3
  jwtx/         JWT mint and verify                                             G3
  hash/         password hashing: pluggable, PHC-encoded, parameter-bounded     later
  normalize/    PRECIS identifier normalisation                                 later
  audit/        event vocabulary and a Logger interface. Nothing else.          later
  httpmw/       credential extraction middleware                                later
  batteries/    optional wired-up flows; deferred                               -
```

## Code Style Guidelines

### General

- Follow the Google Go Style Guide
- Minimal dependencies - prefer stdlib where possible
- Interface-based design for testability
- All public APIs must be documented

### Error Handling

- Define package-level sentinel errors (e.g., `ErrInvalidCode`, `ErrNotEnabled`)
- Wrap errors with context using `fmt.Errorf("context: %w", err)`
- Check for `store.ErrNotFound` for missing resources

### Naming Conventions

- Packages: lowercase, single-word (e.g., `audit`, `totp`)
- Interfaces: descriptive names ending in `-er` where appropriate (e.g., `UserStore`, `AuditLogger`)
- Constructors: `NewXxx(config Config) (*Xxx, error)`
- Config structs: named `Config` within each package

### Configuration Pattern

```go
type Config struct {
    RequiredField SomeType
    OptionalField int // defaults in constructor
}

func NewManager(cfg Config) (*Manager, error) {
    if cfg.RequiredField == nil {
        return nil, errors.New("required field is required")
    }
    if cfg.OptionalField == 0 {
        cfg.OptionalField = DefaultValue
    }
    // ...
}
```

## Storage

Durable credentials are typed: each package declares the narrow store interface
it calls. Short-lived ceremony state is opaque and lives in `store.FlowStore`.
Check for `store.ErrNotFound` and `store.ErrDuplicate`.

## Dependencies

The direct-dependency allow-list is enforced by `depguard` in `.golangci.yml`.
`github.com/go-webauthn/webauthn` is pinned exactly at `v0.18.2`.
