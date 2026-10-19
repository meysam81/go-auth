# CI and branch protection

`.github/workflows/ci.yml` is the gate. It runs on a pull request targeting
`main` or `v2`, a push to `main` or `v2`, and a merge group. `v2` carries the v2
module until `v2.0.0` (see "Branches and releases" below).

`ci-gate` is the only check the ruleset requires. It passes only when every job
it needs succeeded: a skipped or cancelled job fails it. It also fails when a
job in `ci.yml` is missing from its `needs`, so adding a job means adding it
there, and a job cannot land ungated. `release-please` runs only on a push to
`main` or `v2` and releases from that branch.

## What the gate guards beyond the tests

- **The exported API.** `api-diff` writes the difference between the base and
  the pull request into the run summary; `examples/` is a demonstration, not
  API, and is left out. The base is the first parent of the merge commit the
  job tests, so a base that moved after the last push is compared as it is
  now. An incompatible change is declared with `!` in the title
  (`feat(webauthn)!: ...`). While the base's `.release-please-manifest.json`
  holds a pre-release version, an undeclared one is a warning. From the first
  stable release on, an incompatible change fails unless it is declared **and**
  the module moves to its next major path (`/v3`): a declared break on the same
  path would have release-please tag `v3.0.0` on a `/v2` module, which Go
  refuses.
- **What a consumer compiles.** `.dependency-footprint` lists, per importable
  package, every package outside the standard library and this module that it
  compiles in on linux/amd64, darwin/arm64 or windows/amd64. depguard only sees
  this module's own imports, so a dependency upgrade that starts pulling in a
  new package is invisible to it; here it is an added line in the diff.
  Regenerate with `.github/dependency-footprint.sh > .dependency-footprint`.
  `amr` and `store` also have a depguard rule of their own: standard library
  only.
- **The Go floor.** `test` runs on the Go version go.mod declares as well as on
  the newest release, so code that needs a newer standard library fails before
  a consumer on the declared version finds out. For Go module updates, Renovate
  proposes only versions that build on that version (`constraintsFiltering` in
  `renovate.json` on `main`); tool pins in the workflows are not filtered.
- **The release.** Squash merges take the pull request's title and leave the
  body out (the settings below), so the commit release-please reads is exactly
  the title `pr-title` checked.

## The separate modules

Two test suites live in Go modules of their own, so their drivers never enter
the library's dependency graph, its `go.sum`, or `.dependency-footprint`. Both
test the code beside them: `examples/sqlitestore` replaces
`github.com/meysam81/go-auth/v2` with this tree, and the browser test builds
`examples/passkeys` from it. The root `go test ./...` does not reach them; their
jobs run `go vet`, `go mod tidy -diff` and the tests. A change to the root
`go.mod` changes `examples/sqlitestore/go.mod` too: run `go mod tidy` there
(Renovate does it with `gomodTidyAll`).

- `examples/passkeys/e2e` (chromedp) builds and starts the passkeys example and
  drives it in headless Chrome with a CDP virtual authenticator, for a
  device-bound key and a synced passkey: registration, the autofill sign-in the
  page arms afterwards, and the sign-in button. Only a browser shows that what
  `PublicKeyCredential.toJSON` sends is what the library accepts. It refuses to
  run when something already listens on `localhost:8080`, the address the
  example is bound to. Locally: `cd examples/passkeys/e2e && go test ./...`
  (set `CHROME_PATH` if Chrome is not on `PATH`; without a browser it skips,
  unless `CI` is true).
- `examples/sqlitestore` (modernc.org/sqlite) is a reference implementation of
  `store.FlowStore`, `webauthn.CredentialStore` and `webauthn.HandleStore`,
  proven by `authtest.FlowStoreSuite` and `authtest.WebAuthnStoreSuite` plus
  the SQL-specific cases the suites cannot see. It is an example to copy, not a
  supported package.

## The nightly run

`.github/workflows/scheduled.yml` covers what changes without a commit: every
night it runs govulncheck against a current toolchain, the race detector three
times over shuffled tests on the Go version `go.mod` declares and on the newest
release, and every fuzz target for up to ten minutes (40 minutes shared across
all targets) from a corpus carried
between nights, and zizmor's online audits (an action pinned to a commit outside
its repository, an action version with an advisory), which the gate leaves out
so it cannot go red on a network failure. Every Monday the same file runs
mutation testing (gremlins) on `amr` and `webauthn` and writes the test
efficacy and every surviving mutant into the run summary; it is a report, not a
gate. A failure, a timeout included, opens one issue per run and branch,
`nightly: failing on <branch>` or `mutation: failing on <branch>`, and later
failures comment on it; close it once the cause is fixed.

GitHub fires `schedule` only on the default branch, and `workflow_dispatch`
runs a workflow only if a file at the same path exists there. Until `v2.0.0`
the default branch is `main`, which carries v1, so `main` holds its own
`.github/workflows/scheduled.yml` with the same two schedules, whose only job
is `gh workflow run scheduled.yml --ref v2` (with `-f run=mutation` on
Mondays); the dispatched run executes the `v2` copy. When `main` moves to v2,
the `v2` copy replaces it and its own schedule takes over.

## Branch protection

One ruleset, `main` (id `9982355`), covers the default branch and every `v*`
branch (`~DEFAULT_BRANCH` and `refs/heads/v*`), so today `main`, `v1` and `v2`,
and makes `ci-gate` required on all of them. Every branch it covers therefore
carries the job in its own `ci.yml`: a branch without it gets pull requests
that wait for a check that never reports. `main` and `v2` have it; `v1` is
still the v1.1.3 snapshot and gets it when the swap fast-forwards it to `main`
(below), so until then a pull request into `v1` cannot merge.

GitHub offers merge queues only to public repositories owned by an
organization ("Pull request merge queues are available in any public
repository owned by an organization", GitHub Docs, _Managing a merge queue_),
and this repository is owned by a user, so there is no queue. `ci.yml` keeps
its `merge_group` trigger so a queue works the day the repository can have
one; until then the trigger never fires.

Without a queue, a pull request is tested against the base it branched from,
not the base it lands on: two changes that each pass alone can still break
together. The ruleset leaves `strict_required_status_checks_policy` off, so
that gap is open. Turning it on closes it the manual way: a pull request whose
branch is behind its base must be updated ("Update branch") and pass `ci-gate`
again before it can merge. With one maintainer that update is rare, and it is
the queue's guarantee without the queue.

The required check is pinned to the GitHub Actions app (`integration_id` 15368),
so only a job in this repository's workflows can satisfy it: a status named
`ci-gate` posted by another app or token does not count.

There is one maintainer, so a required approval can never be given: every
merge would need the bypass, and the bypass skips the required check as well.
The ruleset therefore requires no approval, and the bypass stays for
emergencies only.

```sh
# 1. Confirm ci-gate is live on each branch the ruleset covers; v1 prints 0
#    until the swap.
for ref in main v1 v2; do
  printf '%s: ' "$ref"
  gh api "repos/meysam81/go-auth/contents/.github/workflows/ci.yml?ref=$ref" \
    --jq '.content' | base64 -d | grep -cE '^  ci-gate:'
done

# 2. Require ci-gate on the default branch and every v* branch. The PUT sends
#    the ruleset back whole, changed only in its include list and its required
#    checks.
gh api repos/meysam81/go-auth/rulesets/9982355 \
  | jq '{name, target, enforcement, bypass_actors,
         conditions: {ref_name: {include: ["~DEFAULT_BRANCH", "refs/heads/v*"], exclude: []}},
         rules: [.rules[] | if .type == "required_status_checks"
                   then .parameters.required_status_checks = [{context: "ci-gate", integration_id: 15368}]
                   else . end]}' \
  | gh api --method PUT repos/meysam81/go-auth/rulesets/9982355 --input -

# 3. A workflow must not be able to approve a pull request.
gh api --method PUT repos/meysam81/go-auth/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false

# 4. A squash commit is the pull request's title and nothing else: release-please
#    also reads the body (extra entries, BREAKING CHANGE footers), which no check
#    sees. A breaking change is declared with `!` in the title instead.
gh api --method PATCH repos/meysam81/go-auth \
  -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=BLANK
```

`required_signatures` holds for squash merges made in the web UI: GitHub signs
the commit it creates.

The gate checks the pull request's own `ci.yml`: a pull request that deletes a
job from the file and from `ci-gate`'s `needs` passes it. A change to the
workflows is a change to the gate, and is reviewed as one.

## After the first merge

Merge each `v2` pull request that changes `scheduled.yml` before the `main`
one that dispatches it: until `v2` has the file, every nightly dispatch fails,
and until it has the `run` input, the Monday mutation dispatch is rejected.
GitHub dispatches a workflow to another branch only once it has run at least
once, so start it by hand once and confirm the run lands on `v2`:

```sh
gh workflow run scheduled.yml --ref main
gh run list --workflow scheduled.yml --branch v2 --limit 1
```

## Branches and releases

v2 is built on the `v2` branch, and its alpha and beta tags are cut there.
`main` keeps v1, and v1 fixes keep landing there, until `v2.0.0`; v1 then
continues on the `v1` branch for twelve months of security fixes.

**Versions.** release-please's `release-as` pins `2.0.0-alpha.1` and
`2.0.0-beta.1`, because prerelease versioning never changes type on its own. A
pin is removed by the first commit after its release PR merges: removing it
while that PR is open rewrites it to `2.0.0-alpha` with no number, and any other
commit first opens a duplicate release PR. `v2.0.0` comes from setting
`"prerelease": false`, which drops the suffix; `versioning` and
`prerelease-type` are removed after it. Removing the prerelease keys without
that step turns a `feat!` into `3.0.0`, and leaving `"prerelease": true` makes
the next fix `2.0.1-beta`.

**The swap**, at `v2.0.0`, in this order:

1. Freeze `main`.
2. Before the `2.0.0` release PR merges, merge `main` into `v2` with a signed
   merge commit, so `v2` contains `main`: v1-only changes resolve as deleted,
   `ci.yml` keeps `v2`'s jobs with the branches `main`, `v1` and `v2` (a push
   runs the workflow in the pushed commit, so dropping `v2` here would leave the
   release PR's merge untagged), and `renovate.json` lists `main` and `v1`.
3. Edit v1's entries out of the release PR's notes and its `CHANGELOG.md`, with
   no other push to `v2` in between, then merge it.
4. Fast-forward `v1` to `main`'s tip and `main` to `v2`, then delete `v2` and
   any release PR left on it, and drop `v2` from `ci.yml` in a later commit on
   `main`.

The merge commit and the fast-forwards need an admin bypass of the
pull-request, squash-only, linear-history and signed-commit rules. Merging
`main` in after `2.0.0` is tagged would make its newer v1 commits releasable
again and open a duplicate `2.0.1` on both branches. A squash instead of the
fast-forward would leave `v2`'s release commits outside `main`'s history, and
release-please would rescan all of `main` and propose `3.0.0`; the fallback then
is a commit setting `last-release-sha` to the squash commit, removed after the
next release. A v1.x release after `v2.0.0` becomes GitHub's "latest" release
(release-please sends no `make_latest`), so the release page is corrected by
hand.

The ruleset needs no change at the swap. It already covers the default branch
and `v1`, and after the swap both carry `ci-gate`: `main` takes `v2`'s `ci.yml`,
and `v1` is fast-forwarded to `main`'s last v1 commit, which has its own copy.
Once `v2` is deleted, `refs/heads/v*` matches `v1` alone.
