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

Neither starter is installed yet, and both stay inert until every condition below holds. An administrator turns one
on only in this order:

1. `review-change.md` and `review-issue.md` cover that repository. Today both are written for this repository alone,
   and each says so in its first paragraph: the change checks name this repository's tests and documents, and an
   issue's reply answers from this repository's files. A review of the other repository reads both files, so it is
   not believed until they say what they check there, or that repository has rules files of its own. Both files
   belong to `@theorem-labs/engineering` (`.github/CODEOWNERS`), whose review a change to them needs.
2. A ruleset on the repository's default branch requires a pull request with an approving review, and no writer can
   bypass it. Without it, any writer can push a workflow to the default branch that reads the environment's secret.
3. A person decides which App's key the starter holds. The key it names is the key of the App that posts review
   comments and opens the private issues of held findings. The other choice is a dedicated App whose only permission
   is `actions: write` on this repository: its client id then goes into both starters, and its bot into
   `ALLOWED_BOTS` of `build.yaml`, or the review's action refuses its runs. Either token can also re-run a Build run
   with debug logging, which `build.yaml` forbids for the review job because that prints a held finding to the public
   log.
4. The environment `oss-verify-starter` and its secret are created, with deployment branches the default branch alone.
5. The starter is copied to `.github/workflows/oss-verify-review.yml` of that repository, by a reviewed pull request.

Until then no starter starts a review of that repository. A person with write access to this repository can still
start one by hand (`gh workflow run build.yaml -f repo=<name> ...`, at the top of `build.yaml`). Condition 1 holds for
that review too: it is not believed until the rules files cover the repository. A review of that repository, by a
starter or by hand, posts nothing there: it stays the artifact `enroll-review-draft` until the list
`post_review_repos` in `build.yaml` names the repository, and an issue's draft reply is never posted.
