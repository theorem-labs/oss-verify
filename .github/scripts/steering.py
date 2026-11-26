# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The steering files of this repository: the files that can change what a workflow runs, or what Claude Code loads
in the review job. A script in this directory imports it, as enroll-dispatch imports triage:

    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import steering
    steering.is_steering(".github/workflows/build.yaml")  # True

STEERING holds the patterns that .github/CODEOWNERS gave to @theorem-labs/engineering and @theorem-labs/research at
commit 62081ee, in the order of that file, all of /.github/ and /src/ among them. CODEOWNERS now names an owner only
for itself and the agent instruction files (R10 of dispatch://INFRA-5359/spec): every other file merges through the
change review, whose check review main's ruleset requires, with no code owner's approval. This list stays as broad as
it was: a change under /src/ or /.github/ is still a steering change, so its Build run's results wait for a person's
approval of its head (below). A test holds it to that list, and holds each file that CODEOWNERS owns to be a steering
file. The four patterns at the top of CODEOWNERS (AGENTS.md, CLAUDE.md, SKILL.md and skills/ at any depth) are not in
STEERING: AGENTS*.md and CLAUDE*.md already match each AGENTS.md and CLAUDE.md, and a skill that Claude Code loads in
the review job is under .claude/.

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
    """Whether one pattern, written as a pattern of CODEOWNERS, matches `path` (a file's path from the top of the
    repository, as the API lists it), as GitHub matches a pattern of CODEOWNERS:

    - A pattern with a `/` at its start or in its middle matches from the top of the repository. Any other pattern
      (`.claude/`, `CLAUDE*.md`) matches at any depth.
    - A pattern that matches a directory matches every file under that directory, at any depth. A pattern with a `/`
      at its end matches a directory only, never a file of that name.
    - `*` matches any number of characters but `/`. The match is case-sensitive."""
    directory = pattern.endswith("/")
    body = pattern.rstrip("/")
    segments = body.lstrip("/").split("/")
    parts = path.split("/")
    starts = [0] if "/" in body else range(len(parts))
    for start in starts:
        end = start + len(segments)
        # A match that ends at the last part names the file itself, which a directory's pattern does not match.
        if end > len(parts) or (directory and end == len(parts)):
            continue
        if all(fnmatchcase(part, segment) for part, segment in zip(parts[start:end], segments)):
            return True
    return False


def is_steering(path: str) -> bool:
    """Whether a pattern of STEERING matches `path` (`matches`)."""
    return any(matches(pattern, path) for pattern in STEERING)
