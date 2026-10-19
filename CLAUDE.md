# go-auth

Public, open-source authentication primitives for Go: each package verifies one
kind of credential and returns a verified fact. Design and decisions:
`docs/design.md`; CI, branches and releases: `docs/ci.md`; each package's doc
comment is its contract.

## Hard rules

- The library never creates, mutates or owns identity: no user store, lookup,
  provisioning, account linking or ceremony HTTP handler. It returns facts; the
  application decides.
- Never name a consuming product, or a `goauth-` bead ID, in code, docs, commits
  or pull requests.
- Fail closed. A security question whose wrong answer is a bypass is never
  answered from optional wiring, a zero value or a missing field; unknown is
  never a pass. A missing dependency is a constructor error, never a
  nil-tolerant field.
- A verification failure matches exactly one sentinel, built with the package's
  `fail()`, never by wrapping a sentinel with `%w`; an infrastructure failure
  matches none. No path that takes an identifier exports a distinguishable
  not-found. Error text is for logs, never for a client.
- Stores: each package declares the narrow typed interface it calls, beside the
  caller; stores are passed per call, never held. Every invariant that needs
  atomicity is one named store method whose doc states its SQL shape, and an
  `authtest` suite races it. Ceremony state lives only in `store.FlowStore`.
- A published interface never gains a method (a new capability is a new
  interface found by type assertion); a struct may gain fields. An incompatible
  change carries `!` in the pull request title: the squash commit is the title
  and release-please reads nothing else.
- Keep every check in this module even where go-webauthn also performs it.

## Tests

- Every fix ships a test that fails when the fix is reverted, named for the
  attack and citing its RFC or CVE class; a vulnerability reproduction is such a
  test, never a standalone program.
- Every parser reachable with attacker-controlled bytes has a fuzz target.
- `.coverage-floor` only rises; lowering a floor is its own reviewed change.
- The root `go test -race ./...` skips two modules: `examples/sqlitestore`
  (store changes) and `examples/passkeys/e2e` (Chrome, `CHROME_PATH`).
- Mutation shows a fix is load-bearing, not correct: a security change also gets
  an adversarial review that attacks the fix itself.

## Process

- Until `v2.0.0`, branch from `v2` and open pull requests against it; `main` is
  v1, security fixes only.
- One canonical doc per topic: extend `docs/design.md`, `docs/ci.md` or a
  package doc comment, never a sibling file. Specs and plans stay in untracked
  `.claude/plans/`; fold their decisions into the design before the pull request
  opens. Comments state the rule, never a doc section number.
- Tracker: beads (`bd`, prefix `goauth-`), local only, never pushed. A bead
  links its pull request with `--external-ref gh-<n>`.
