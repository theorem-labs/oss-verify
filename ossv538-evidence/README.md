# OSSV-538: the project directories and the evidence of pull request 186

This branch is an archive, not a change: nothing here is meant to merge. It exists because the box that produced
it is ephemeral and these files were on it and nowhere else. dispatch://OSSV-538, pull request 186
(`ossv538/private-library-fetch`, head `55efbd761523c5a62d084f22122c8914a2b60ba6`).

**No token is in this tree, and five lines were redacted to keep it that way.** Every file was checked against
each of the eleven tokens the measured builds actually used: none held one, and the recorded token files
themselves are deliberately absent. Five lines did hold a made-up *token-shaped* string — the value those probes
print on purpose, to see whether the code under test would pass it on — and the shared public-leak check refuses
a token-shaped line on a push to a public repository, which is the right default, since a reader cannot tell a
synthetic one from a real one by looking. Each now reads `<synthetic token, redacted for this archive>`, in
`reviews/round1/base-code-head-tests.log` (two), `reviews/round2/emit-synthetic-error.py`,
`reviews/round3/emit-mint-error.py` and `reviews/round3/emit-synthetic-error.py`. Nothing else in any file was
changed, and no real credential was ever in one.

## `projects/` — the only copy of what was built

`tools/check` takes the path of any directory with a `project.yaml`, so these four were never under `projects/` in
the repository. Enrolling the two real ones is dispatch://OSSV-267 and dispatch://OSSV-518, and whoever does that
will want these as the starting point.

| directory | what it builds |
|---|---|
| `cjson-ossv267` | `theorem-labs/cjson-ossv267#master`, the calibration pair's private copy of cJSON. Its `build.sh` is `projects/cjson`'s; its `Dockerfile` mounts the secret on the fetch. Recorded `acc76239bee01d8e9c858ae2cab296704e52d916`. |
| `theorem-cli` | `theorem-labs/theorem-cli#main`, one fuzz target (`core_argv_fuzzer`) from the CLI's own sources, with the source list and flags its `Makefile` and `verify/container-build.sh` give. Recorded `b9e7947677f353c26a62980aaf6dffbcc57d1503`. **This is not the enrolled build OSSV-518 needs**: the real one reproduces the release's bytes through the recipe's driver, and this one links the builder's. It was written to show the fetch and the recorded commit, and that is all it shows. |
| `cjson-badtoken` | the same as `cjson-ossv267` with the commit pinned in `project.yaml`, so `resolve` does not run and the failure happens inside the build: how the wrong-token message was measured. |
| `cjson-nocommit` | the same, pinned to a commit that is not in the repository: how the missing-commit message was measured. |

## `scripts/` — how to re-run the absence proof rather than take anyone's word

Run a build with `OSS_VERIFY_GIT_TOKEN_COMMAND=scripts/mint-and-record` and `RECORD_TOKEN_TO=<a file>`: it mints
the real read-only token through `infra/github-read-token` and also writes it to that file, so the checks
afterwards know the exact bytes to look for. **That wrapper exists for the measurement only**; nothing in the
repository writes a token to a file, and the file it writes is the one thing from this exercise that must not be
kept.

    scripts/absence.sh <work dir> <token file> <build log>   image history, image inspect, docker save, the
                                                             container's environment and /run/secrets, the
                                                             checkout's remote, the facts, the log
    scripts/layers.sh  <work dir> <token file>               every blob of the saved image, one line each
    scripts/evidence.sh <work dir> <token file> <log> <tag>  the same checks with each command printed as it ran
    scripts/mint-wrong                                       a token command that prints a well-formed WRONG
                                                             token, for the failed-fetch message

`absence.sh` must run after a build, and `layers.sh` after `absence.sh` (it reads the `docker save` output that
`absence.sh` leaves). `absence.sh`'s own per-layer line says `layers: 0`: it looks for members named `*.tar`, and
a modern `docker save` writes an OCI layout whose layers are `blobs/sha256/<digest>`. That is what `layers.sh` is
for, and why both are here.

## `logs/` — the builds these numbers came from

The build logs of every measured run, with the two `evidence-*.txt` files that carry each command and its output.
`ev3-*.log` and `ev4.log` are the last ones, at the heads the pull request's comments cite; the earlier ones are
the rounds before them. Each was checked for its own build's token: zero copies, which is the point.

## `reviews/` — the three non-author rounds

The probe scripts, result files and comment bodies of the three `sol` reviews, whose verdicts are
`issuecomment-6813305547`, `issuecomment-6814323825` and `issuecomment-6815025509` on pull request 186. Only the
files each reviewer left at the top of its own directory are here; the copies of this repository they made to run
base-against-head are not, since this repository is already the copy of itself.

Three of the four worst defects that pull request had passed a careful reading and failed one of these
measurements. That is the reason to keep them.
