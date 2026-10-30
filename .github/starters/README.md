# Starter workflows of the other reviewed repositories

The files here are copies. Each is the workflow `.github/workflows/oss-verify-review.yml` of another repository whose
pull requests and issues OSS Verify reviews:

| file | runs in |
| --- | --- |
| `oss-verify-proofs.yml` | theorem-labs/oss-verify-proofs |
| `rocq-linux-process-semantics.yml` | theorem-labs/rocq-linux-process-semantics |

No workflow runs from this directory: GitHub runs only `.github/workflows/`. The copies are here so that this
repository's tests read them (`tools/tests/test_check_checks.py`, class `Starters`). A change to a starter is made in
both places: in the pull request to its repository, and here.

Each starter starts `.github/workflows/build.yaml` of this repository (`-f repo=<name> -f pr=<n> -f head=<commit>`, or
`-f repo=<name> -f issue=<n>`) on its repository's pull request and issue events, with a token of the OSS Verify App
for this repository alone, with `actions: write` alone. The App's private key is the secret `OSS_VERIFY_APP_PRIVATE_KEY`
of the environment `oss-verify-starter` of that repository, whose deployment branches are the default branch alone. An
administrator of the repository creates the environment and its secret.
