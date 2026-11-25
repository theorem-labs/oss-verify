# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The steering files of this repository: the files that can change what a workflow runs, or what Claude Code loads
in the review job. A script in this directory imports it, as enroll-dispatch imports triage:

    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import steering
    steering.is_steering(".github/workflows/build.yaml")  # True

STEERING holds the patterns that .github/CODEOWNERS gave to @theorem-labs/engineering and @theorem-labs/research at
commit 62081ee, in the order of that file, all of /.github/ and /src/ among them. CODEOWNERS no longer owns /src/, on
purpose: a change under src/ needs no code owner's approval to merge, but it is still a steering change, so its Build
run's results wait for a person's approval of its head (below).
CODEOWNERS now owns only some of the files under /.github/ (R10 of dispatch://INFRA-5359/spec: those that can reach a
credential or decide a required check, one line each); this list stays as broad as it was. A test holds it to that
list, and holds each file that CODEOWNERS owns to be a steering file but two, which are no steering files:
docs/seeded-projects.tsv, because take-project and triage.py read it from the base branch, never from the pull request,
and app/sentences.yaml, because only tests read it, as data, and no workflow runs it.
.github/scripts/workflow-credentials matches the patterns of CODEOWNERS with `matches`. The four patterns at the top of
CODEOWNERS (AGENTS.md, CLAUDE.md, SKILL.md and skills/ at any depth) give the same owners and are not in STEERING:
AGENTS*.md and CLAUDE*.md already match each AGENTS.md and CLAUDE.md, and a skill that Claude Code loads in the review
job is under .claude/.

The workflows that start on pull_request run the merge commit's copy of each workflow file and script. For a pull
request that changes no steering file, that merge commit holds main's .github/, src/, infra/ and seeds/, so its Build
run runs main's code. review.yml reads the results of a Build run only for such a pull request
(.github/scripts/take-build-results). Enroll dispatch sends any other pull request only after a person approved its
head (.github/scripts/enroll-dispatch).
"""
from __future__ import annotations

from fnmatch import fnmatchcase

STEERING = (
    "/.github/",
    "/src/",
    "/infra/",
    "/seeds/",
    ".claude/",
    "CLAUDE*.md",
    "AGENTS*.md",
    "/.mcp.json",
    "/*.py",
    "/pytest.ini",
    "/.pytest.ini",
    "/pyproject.toml",
    "/uv.lock",
    "/.python-version",
    "/setup.cfg",
    "/tox.ini",
    "/review.md",
    "/review-change.md",
    "/review-issue.md",
    "/.claude/skills/write-to-maintainer/",
    "/.github/CODEOWNERS",
)


def matches(pattern: str, path: str) -> bool:
    """Whether one pattern of CODEOWNERS gives `path` (a file's path from the top of the repository, as the API lists
    it) an owner, as GitHub matches it, which is as git matches a pattern of .gitignore:

    - A pattern with a `/` at its start or in its middle matches from the top of the repository. Any other pattern
      (`.claude/`, `CLAUDE*.md`) matches at any depth.
    - A pattern that matches a directory matches every file under that directory, at any depth. A pattern with a `/`
      at its end matches a directory only, never a file of that name; so does one that ends in `/**`.
    - `**` as a whole segment matches zero or more segments: `**/SKILL.md` matches SKILL.md and a/b/SKILL.md. `*`
      matches any number of characters but `/`, and so do `**` and `***` inside a segment. The match is
      case-sensitive.

    GitHub's CODEOWNERS reads `[`, `!` and `\\` as git does not, and a pattern that ends in `/*` matches no file deeper
    than that level; no line of CODEOWNERS has one (tests/test_check_checks.py, Owners, compares this with git)."""
    directory = pattern.endswith("/")
    body = pattern.rstrip("/")
    segments = body.lstrip("/").split("/")
    if len(segments) > 1 and segments[-1] == "**":
        segments, directory = segments[:-1], True
    if "/" not in body:
        segments = ["**", *segments]
    parts = path.split("/")
    # Each length k for which the segments so far match parts[:k].
    ends = {0}
    for segment in segments:
        if segment == "**":
            ends = set(range(min(ends), len(parts) + 1)) if ends else set()
        else:
            ends = {k + 1 for k in ends if k < len(parts) and fnmatchcase(parts[k], segment)}
    # A match of every part names the file itself, which a directory's pattern does not match; a match of fewer parts
    # names a directory that holds the file.
    return any(0 < k < len(parts) or (k == len(parts) and not directory) for k in ends)


def is_steering(path: str) -> bool:
    """Whether a pattern of STEERING matches `path` (`matches`)."""
    return any(matches(pattern, path) for pattern in STEERING)
