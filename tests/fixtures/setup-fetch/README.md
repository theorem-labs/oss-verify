<!-- Copyright 2026 Theorem Labs, PBC. SPDX-License-Identifier: Apache-2.0 -->
# A fetch job's folder of the form setup-fetch/1

On an owner's repository, the fetch job of `check.yml` writes one folder for the review of a setup pull request.
`.github/scripts/review-gather` reads it, with `KIND=setup FETCHED=<folder>`. The header of the script gives the form.
`tests/test_review_gather_setup.py` runs the script on a copy of this folder. This folder is also an example of the
form for the fetch job.

Most files come from real systems, and each section below gives the command. Three files have no real source yet,
so they are written by hand. No file holds a secret.

The pull request and the repository are not one setup pull request. The folder puts a small pull request of this
repository beside the repository of `projects/libreac/`, so that each file of the form is real where it can be.

## The pull request: theorem-labs/oss-verify#71

A small closed pull request of this repository, read on 2026-11-25. The commands are those of `review-gather` for
an enrollment.

| file | command |
|---|---|
| `pr.json` | `gh pr view 71 -R theorem-labs/oss-verify --json number,title,author,isDraft,createdAt,body,headRefOid,files,commits,comments,reviews > pr.json` |
| `pr.diff` | `gh pr diff 71 -R theorem-labs/oss-verify > pr.diff 2>&1` |
| `review-comments.txt`, `review-comment-authors.txt` | `gh api --paginate "repos/theorem-labs/oss-verify/pulls/71/comments" --jq '.[] \| [(.user.login // "-"), "\(.user.login) \(.path):\(.line) \(.body)"]'`, then the two `jq` commands after it in `review-gather`, which write the two files, each with its last line `(exit status 0)` |
| `last-review-head.txt` | empty: the App wrote no review comment on this pull request |

The folder has no `since-last-review.diff`, because it has no head of a last review. The test adds one where it
needs one.

## The repository: FreeREAC/libreac

The repository of `projects/libreac/`, at the commit that `projects/libreac/project.yaml` names,
`4e09c7d811313828e0aa9ed4d21215cf1c851689`. The fetch job reads these files with `gh api`. For this folder they were
read on 2026-11-25 through the same REST paths with no token: `curl -sSL https://api.github.com/<path>`.

| file | command |
|---|---|
| `repository.json` | `gh api repos/FreeREAC/libreac` |
| `contributors.json` | `gh api "repos/FreeREAC/libreac/contributors?per_page=5"` |
| `source.tar` | `gh api repos/FreeREAC/libreac/tarball/4e09c7d811313828e0aa9ed4d21215cf1c851689`, then cut (below) |

GitHub's tarball of that commit has 529 members, in 866,356 bytes. `source.tar` keeps four small files of it and
their folders: `NOTICE`, `debian/copyright`, `debian/source/format` and `fuzz/corpus/boxreg/find-absent`. It keeps
the top folder `FreeREAC-libreac-4e09c7d/`, the header of each member, and the global header `comment=<commit>`.
Python's `tarfile` cut it in the shape that `git archive` writes, the shape of GitHub's tarball: the global header
first, at byte 0, then each member with its own ustar header alone, with no extended header. It is compressed with
gzip, as GitHub's tarball is.

## `theorem/`: a small `.theorem/` from `projects/libreac/`

- `config.yml`: the fields of `projects/libreac/project.yaml`, with no `repo` and none of its comments.
- `Dockerfile`: `projects/libreac/Dockerfile` with the root of the repository as the build context. It copies the
  source with `COPY . $SRC/libreac`, not with `fetch-commit`, and copies `.theorem/build.sh`.
- `build.sh`, `patch_style.md` and `fuzz_knock_seed_corpus.zip`: as `projects/libreac/` has them.

## Written by hand: `setup.json`, `setup.txt` and `record.json`

These files are the output of `theorem app setup --at <head> --repo FreeREAC/libreac --pr <number> --installer
linuxnow --record record.json --json`. That command does not exist yet. So the files are written by hand, in the
form of the command's design:

- `setup.json`: its standard output. It is one JSON list of objects with the fields `name` and `result`, `pass` or
  `fail`, for the checks `rules`, `statements`, `terms`, `scope`, `name`, `fork`, `license` and `ruleset`. `check.yml`
  adds the check `build`, which is not in this output.
- `setup.txt`: its standard error, the reasons.
- `record.json`: the file of `--record`. It is one JSON object, `{"installer": <login>, "ticked_by": <login> or null}`.

The results agree with the pull request above. Its description has no ticked line of the terms, so `terms` fails and
`ticked_by` is null. It changes a file outside `.theorem/`, so `scope` fails. The Theorem Verify App is not made yet,
so `ruleset` fails.
