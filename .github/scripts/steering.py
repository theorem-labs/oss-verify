# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The steering files of this repository: the files that can change what a workflow runs, or what Claude Code loads
in the review job. A script in this directory imports it, as enroll-dispatch imports triage:

    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import steering
    steering.is_steering(".github/workflows/build.yaml")  # True

STEERING holds the last patterns of .github/CODEOWNERS, which give a file to @theorem-labs/engineering and
@theorem-labs/research, in the order of that file, as they are at commit 62081ee. A change to one of the two must change
the other: a test compares them. The four patterns above them (AGENTS.md, CLAUDE.md, SKILL.md and skills/ at any depth)
give the same owners and are not in STEERING: AGENTS*.md and CLAUDE*.md already match each AGENTS.md and CLAUDE.md, and
a skill that Claude Code loads in the review job is under .claude/. The lines of CODEOWNERS that name a module of src/
with no team take the code owner off that module (a module of `oss-verify check` that no job holding a token imports),
and give no line of STEERING: every file under src/ stays a steering file.

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
    it) an owner, as GitHub matches it:

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
