# CI and the merge queue

One workflow, `.github/workflows/ci.yml`, runs on three events: a pull request
targeting `main`, a push to `main`, and a merge group.

| Job              | What it gates                                                                |
| ---------------- | ---------------------------------------------------------------------------- |
| `test`           | `go test ./... -race -covermode=atomic`, plus the per-package coverage floor |
| `checks`         | `prettier --check`, `go vet`, `gofmt`, `golangci-lint`                       |
| `build`          | `go build ./...`                                                             |
| `build-examples` | the `examples/complete` module, which has its own `go.mod`                   |
| `govulncheck`    | both modules, scanned with a current toolchain                               |
| `fuzz`           | every `Fuzz*` target at a bounded budget                                     |
| `release-please` | release automation; gated to `push` on `main`                                |

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

**Every check named in the ruleset's required list must be a job in
`ci.yml`.** A required check that does not trigger on `merge_group` never
reports on the temporary branch, and GitHub fails the merge rather than merging
something unverified. That is why `ci.yml` declares:

```yaml
on:
  merge_group:
    types:
      - checks_requested
```

This repository also receives checks from third-party apps — `codecov/patch`,
`codecov/project`, `pre-commit.ci`, `Socket Security`, `GitGuardian`. **None of
them may be marked required**, because they report on pull requests and pushes
but not on merge groups. Marking one required stalls every queued pull request
until it times out. They remain visible on the pull request, which is where
they are useful; they simply do not gate the queue.

## Enabling it

The queue is configured on the `main` ruleset, not on legacy branch protection.
Two rules are involved: `merge_queue` turns the queue on, and
`required_status_checks` gives it something to wait for. Without the second,
the queue merges without verifying anything.

Order matters. `ci.yml` must already be on `main` with the `merge_group`
trigger **before** the queue is switched on — otherwise the first queued pull
request waits for checks that will never run.

```sh
# 1. Confirm the trigger is live on main.
gh api repos/meysam81/go-auth/contents/.github/workflows/ci.yml \
  --jq '.content' | base64 -d | grep -A2 merge_group

# 2. Read the current ruleset, so the merge here is against what is really there.
gh api repos/meysam81/go-auth/rulesets/9982355 > ruleset.json

# 3. Add both rules, keeping the existing ones.
gh api --method PUT repos/meysam81/go-auth/rulesets/9982355 \
  --input - <<'JSON'
{
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "required_signatures" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "required_reviewers": [],
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_review_thread_resolution": false,
        "require_extra_approval_for_unattributed_changes": true,
        "allowed_merge_methods": ["squash"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "test" },
          { "context": "checks" },
          { "context": "build" },
          { "context": "build-examples" },
          { "context": "govulncheck" },
          { "context": "fuzz" }
        ]
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
```

`merge_method` is `SQUASH` because the ruleset already enforces
`required_linear_history` and the pull-request rule already restricts merges to
squash; a queue configured to produce merge commits would contradict both.

`strict_required_status_checks_policy` is `false` on purpose. It forces a branch
to be up to date with `main` before merging, which is the manual chore the queue
exists to replace — leaving it on makes every merge rebase-and-wait again.

`grouping_strategy: ALLGREEN` stops a batch at the first failing entry rather
than merging the entries ahead of it anyway. `HEADGREEN` is the faster,
looser alternative.

## After enabling, verify on the first queued pull request

Two things are worth watching once, because they are cheap to confirm and
expensive to discover later:

- **`required_signatures` is on.** Merge-queue commits are created and signed by
  GitHub, so this is expected to hold, but confirm the first queued merge is not
  rejected for an unsigned commit.
- **Check names must match exactly.** A required context that never matches a
  job name looks identical to a check that is merely slow — the queue waits, and
  then times out at `check_response_timeout_minutes`. If a queued pull request
  hangs, compare the required contexts against the job names in `ci.yml` first.

## Disabling it

Remove the `merge_queue` rule from the ruleset. Leave `required_status_checks`
in place: it is worth having with or without a queue, and dropping it silently
removes the gate on direct pull-request merges.
