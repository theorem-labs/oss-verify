# Starter workflows of the other reviewed repositories

The files here are copies. Each is the workflow `.github/workflows/oss-verify-review.yml` that another repository
whose pull requests and issues OSS Verify reviews runs once it is installed there:

| file | runs in |
| --- | --- |
| `oss-verify-proofs.yml` | theorem-labs/oss-verify-proofs |
| `rocq-linux-process-semantics.yml` | theorem-labs/rocq-linux-process-semantics |

No workflow runs from this directory: GitHub runs only `.github/workflows/`. The copies are here so that this
repository's tests read them (`tools/tests/test_check_checks.py`, class `Starters`). A change to a starter is made in
both places: in the pull request to its repository, and here.

Each starter starts `.github/workflows/build.yaml` of this repository (`-f repo=<name> -f pr=<n> -f head=<commit>`, or
`-f repo=<name> -f issue=<n>`) on its repository's pull request and issue events. It reads the pull request's head
from the API when it runs, so its newest run starts the review of the newest head. It uses a token of the OSS Verify App
for this repository alone, with `actions: write` alone. The App's private key is the secret `OSS_VERIFY_APP_PRIVATE_KEY`
of the environment `oss-verify-starter` of that repository, whose deployment branches are the default branch alone.

Neither starter is installed yet. An administrator installs one only in this order:

1. The change review's and the issue reply's rules (`review-change.md`, `review-issue.md`) say what they check for
   that repository. Today they describe this repository alone, and a review of another repository reads them.
2. A ruleset on the repository's default branch requires a pull request with an approving review, and no writer can
   bypass it. Without it, any writer can push a workflow to the default branch that reads the environment's secret.
3. The environment `oss-verify-starter` and its secret are created, with deployment branches the default branch alone.
4. The starter is copied to `.github/workflows/oss-verify-review.yml` of that repository, by a reviewed pull request.

Until then no review of that repository runs. The key the starters name is the key of the App that posts review
comments and opens the private issues of held findings: whether the starters use it, or an App that can only start
workflow runs in this repository, is decided before step 3.
