# CI and branch protection

`.github/workflows/ci.yml` is the gate. It runs on a pull request targeting
`main` or `v2`, a push to `main` or `v2`, and a merge group. `v2`
carries the v2 module until `v2.0.0` (`docs/v2-design.md` §11).

| Job              | What it gates                                                                    |
| ---------------- | -------------------------------------------------------------------------------- |
| `test`           | `go test ./... -race -covermode=atomic`, plus the per-package coverage floor     |
| `checks`         | `prettier --check`, `go vet`, `gofmt`, `golangci-lint`                           |
| `build`          | `go build ./...`                                                                 |
| `build-examples` | `go build` and `go vet` of `examples/passkeys`                                   |
| `govulncheck`    | the module, scanned with a current toolchain                                     |
| `fuzz`           | every `Fuzz*` target at a bounded budget                                         |
| `ci-gate`        | every job above succeeded; the only check the ruleset requires                   |
| `release-please` | release automation; gated to `push` on `main` or `v2`, released from that branch |

`ci-gate` passes only when every job it needs succeeded: a skipped or cancelled
job fails it. It also fails when a job in `ci.yml` is missing from its `needs`,
so adding a job means adding it there, and a job cannot land ungated.

## The nightly run

`.github/workflows/scheduled.yml` covers what changes without a commit: every
night it runs govulncheck against a current toolchain, the race detector three
times over shuffled tests on the Go version `go.mod` declares and on the newest
release, and every fuzz target for ten minutes from a corpus carried
between nights. A failure opens one issue per branch,
`nightly: failing on <branch>`, and later failures comment on it; close it once
the cause is fixed.

GitHub fires `schedule` only on the default branch, and `workflow_dispatch`
runs a workflow only if a file at the same path exists there. Until `v2.0.0`
the default branch is `main`, which carries v1, so `main` holds its own
`.github/workflows/scheduled.yml` whose only job is
`gh workflow run scheduled.yml --ref v2`; the dispatched run executes the `v2`
copy. When `main` moves to v2, the `v2` copy replaces it and its own schedule
takes over.

## Branch protection

A ruleset on `v2` makes `ci-gate` required. GitHub offers merge queues only to
public repositories owned by an organization ("Pull request merge queues are
available in any public repository owned by an organization", GitHub Docs,
_Managing a merge queue_), and this repository is owned by a user, so there is
no queue. `ci.yml` keeps its `merge_group` trigger so a queue works the day the
repository can have one; until then the trigger never fires.

Without a queue, a pull request is tested against the base it branched from,
not the base it lands on: two changes that each pass alone can still break
together. `strict_required_status_checks_policy: true` closes that gap the
manual way. A pull request whose branch is behind `v2` must be updated ("Update
branch") and pass `ci-gate` again before it can merge. With one maintainer that
update is rare, and it is the queue's guarantee without the queue.

The required check is pinned to the GitHub Actions app (`integration_id` 15368),
so only a job in this repository's workflows can satisfy it: a status named
`ci-gate` posted by another app or token does not count.

There is one maintainer, so a required approval can never be given: every
merge would need the bypass, and the bypass skips the required check as well.
The ruleset below therefore requires no approval, and the bypass stays for
emergencies only.

The `main` ruleset (id `9982355`) still guards v1 on the default branch, whose
workflow has no `ci-gate` job, so it must not require one. Its second include
pattern, `refs/heads/refs/heads/v*`, matches no branch; step 3 replaces it with
`refs/heads/v1`, which protects the v1 branch the swap will move v1 onto.

```sh
# 1. Confirm ci-gate is live on v2.
gh api 'repos/meysam81/go-auth/contents/.github/workflows/ci.yml?ref=v2' \
  --jq '.content' | base64 -d | grep -E '^  ci-gate:'

# 2. Create the v2 ruleset.
gh api --method POST repos/meysam81/go-auth/rulesets --input - <<'JSON'
{
  "name": "v2",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/v2"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "required_signatures" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "required_reviewers": [],
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["squash"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "ci-gate", "integration_id": 15368 }
        ]
      }
    }
  ]
}
JSON

# 3. Point the main ruleset at the default branch and the v1 branch. The PUT
#    sends the ruleset back whole, changed only in its include list.
gh api repos/meysam81/go-auth/rulesets/9982355 \
  | jq '{name, target, enforcement, bypass_actors, rules,
         conditions: {ref_name: {include: ["~DEFAULT_BRANCH", "refs/heads/v1"], exclude: []}}}' \
  | gh api --method PUT repos/meysam81/go-auth/rulesets/9982355 --input -

# 4. A workflow must not be able to approve a pull request.
gh api --method PUT repos/meysam81/go-auth/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

`required_signatures` holds for squash merges made in the web UI: GitHub signs
the commit it creates.

The gate checks the pull request's own `ci.yml`: a pull request that deletes a
job from the file and from `ci-gate`'s `needs` passes it. A change to the
workflows is a change to the gate, and is reviewed as one.

## After the first merge

Merge the `v2` pull request that adds `scheduled.yml` before the `main` one
that dispatches it: until `v2` has the file, every nightly dispatch fails.
GitHub dispatches a workflow to another branch only once it has run at least
once, so start it by hand once and confirm the run lands on `v2`:

```sh
gh workflow run scheduled.yml --ref main
gh run list --workflow scheduled.yml --branch v2 --limit 1
```

## At the swap

When `main` takes the v2 tree, move each ruleset with it: the `v2` ruleset to
the default branch, the `main` ruleset to `v1` alone. Both rulesets requiring an
approval on the same branch would bring back the bypass-on-every-merge problem
above, so the order is: `main` first, then `v2`.

```sh
gh api repos/meysam81/go-auth/rulesets/9982355 \
  | jq '{name, target, enforcement, bypass_actors, rules,
         conditions: {ref_name: {include: ["refs/heads/v1"], exclude: []}}}' \
  | gh api --method PUT repos/meysam81/go-auth/rulesets/9982355 --input -

id=$(gh api repos/meysam81/go-auth/rulesets --jq '.[] | select(.name == "v2") | .id')
gh api "repos/meysam81/go-auth/rulesets/$id" \
  | jq '{name, target, enforcement, bypass_actors, rules,
         conditions: {ref_name: {include: ["~DEFAULT_BRANCH"], exclude: []}}}' \
  | gh api --method PUT "repos/meysam81/go-auth/rulesets/$id" --input -
```
