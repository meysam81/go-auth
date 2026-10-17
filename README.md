# go-auth

[![CI](https://img.shields.io/github/actions/workflow/status/meysam81/go-auth/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&style=flat-square)](https://github.com/meysam81/go-auth/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/meysam81/go-auth?style=flat-square)](LICENSE)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white&style=flat-square)](https://www.conventionalcommits.org)

Authentication primitives for Go. Each package verifies one kind of credential
and returns a verified fact; your application owns users, sessions and every
identity decision.

## v2 alpha

`main` is the v2 module, in alpha. Its import path is:

```go
import "github.com/meysam81/go-auth/v2/store"
```

Expect breaking changes between alpha releases until `v2.0.0`.

### What the first phase (G1) contains

- `store`: the single-use `FlowStore` for short-lived ceremony state, and the
  shared `ErrNotFound` / `ErrDuplicate` sentinels.

More packages land phase by phase; this list names only what the repository
contains today. The full design, including the planned package layout, is in
[`docs/v2-design.md`](docs/v2-design.md).

## v1

v1 lives on the `v1` branch. Its import path is unchanged:

```go
import "github.com/meysam81/go-auth"
```

v1 receives security fixes as described in [`SECURITY.md`](SECURITY.md).

## Contributing

Commits follow [Conventional Commits](https://www.conventionalcommits.org).
Run `golangci-lint run` and `go test ./...` before opening a pull request.

## License

See [`LICENSE`](LICENSE).
