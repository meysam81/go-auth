# CI and the merge queue

One workflow, `.github/workflows/ci.yml`, runs on three events: a pull request
targeting `main` or `v2`, a push to `main` or `v2`, and a merge group. `v2`
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
times over shuffled tests on the oldest Go that `go.mod` admits and on the
newest release, and every fuzz target for ten minutes from a corpus carried
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

## Why the merge queue exists

A pull request is tested against the `main` it branched from, not the `main` it
will land on. Two changes that each pass alone can still break together — the
classic pair being one that adds a caller and one that changes the callee's
behaviour without changing its signature. Nothing in a per-pull-request check
can see that.

The merge queue closes the gap. GitHub builds a temporary branch
(`gh-readonly-queue/main/...`) holding the queued pull request plus everything
ahead of it in the queue, runs the checks there, and merges only if they pass.
If a later entry fails, it is ejected and the entries ahead of it still merge.

## The rule that makes or breaks it

**Every check named in the ruleset's required list must report on a merge
group.** A required check that does not trigger on `merge_group` never reports
on the temporary branch, and GitHub fails the merge rather than merging
something unverified. That is why `ci.yml` declares:

```yaml
on:
  merge_group:
    types:
      - checks_requested
```

and why the required list holds one check, `ci-gate`, rather than one per job.

This repository also receives checks from third-party apps — `codecov/patch`,
`codecov/project`, `pre-commit.ci`, `Socket Security`, `GitGuardian`. **None of
them may be marked required**, because they report on pull requests and pushes
but not on merge groups. Marking one required stalls every queued pull request
until it times out. They remain visible on the pull request, which is where
they are useful; they simply do not gate the queue.

## Enabling it

The queue is configured on a ruleset, not on legacy branch protection. Two
rules are involved: `merge_queue` turns the queue on, and
`required_status_checks` gives it something to wait for. Without the second,
the queue merges without verifying anything.

Order matters. `ci.yml` must already be on the branch with the `ci-gate` job
and the `merge_group` trigger **before** the queue is switched on — otherwise
the first queued pull request waits for a check that will never run.

Until `v2.0.0` the ruleset that gates v2 work targets `v2` alone. The `main`
ruleset (id `9982355`) still guards v1, whose workflow has no `ci-gate` job, so
it must not require one yet; at the swap the `v2` ruleset's target becomes the
default branch.

There is one maintainer, so a required approval can never be given: every
merge would need the bypass, and the bypass skips the required check as well.
The ruleset below therefore requires no approval, and the bypass stays for
emergencies only.

```sh
# 1. Confirm ci-gate and the trigger are live on v2.
gh api 'repos/meysam81/go-auth/contents/.github/workflows/ci.yml?ref=v2' \
  --jq '.content' | base64 -d | grep -E '^  ci-gate:|merge_group'

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
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [{ "context": "ci-gate" }]
      }
    },
    {
      "type": "merge_queue",
      "parameters": {
        "merge_method": "SQUASH",
        "grouping_strategy": "ALLGREEN",
        "min_entries_to_merge": 1,
        "max_entries_to_merge": 5,
        "min_entries_to_merge_wait_minutes": 5,
        "max_entries_to_build": 5,
        "check_response_timeout_minutes": 60
      }
    }
  ]
}
JSON

# 3. A workflow must not be able to approve a pull request.
gh api --method PUT repos/meysam81/go-auth/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

`merge_method` is `SQUASH` because the ruleset already enforces
`required_linear_history` and the pull-request rule already restricts merges to
squash; a queue configured to produce merge commits would contradict both.

`strict_required_status_checks_policy` is `false` on purpose. It forces a branch
to be up to date with its base before merging, which is the manual chore the
queue exists to replace — leaving it on makes every merge rebase-and-wait again.

`grouping_strategy: ALLGREEN` stops a batch at the first failing entry rather
than merging the entries ahead of it anyway. `HEADGREEN` is the faster,
looser alternative.

At the swap, point the ruleset at the default branch:

```sh
id=$(gh api repos/meysam81/go-auth/rulesets --jq '.[] | select(.name == "v2") | .id')
gh api --method PUT "repos/meysam81/go-auth/rulesets/$id" \
  --input - <<<'{"conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}}}'
```

## After enabling, verify on the first queued pull request

Two things are worth watching once, because they are cheap to confirm and
expensive to discover later:

- **`required_signatures` is on.** Merge-queue commits are created and signed by
  GitHub, so this is expected to hold, but confirm the first queued merge is not
  rejected for an unsigned commit.
- **The check name must match exactly.** A required context that never matches
  a job name looks identical to a check that is merely slow — the queue waits,
  and then times out at `check_response_timeout_minutes`. If a queued pull
  request hangs, compare the required context against `ci-gate` in `ci.yml`
  first.

## Disabling it

Remove the `merge_queue` rule from the ruleset. Leave `required_status_checks`
in place: it is worth having with or without a queue, and dropping it silently
removes the gate on direct pull-request merges.
