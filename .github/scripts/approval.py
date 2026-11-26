# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""A person's approval of one commit of a pull request, the one rule of this repository for it.

.github/scripts/enroll-dispatch reads it before it sends an enrollment that changes a steering file, and
.github/scripts/review-check before the check run `review` passes a choice that review-change.md reserves for a person
(R14 of dispatch://INFRA-5359/spec). A person approval is a review in state APPROVED whose commit_id is the commit, by
an account of type User (an agent acts as an App, type Bot, so it cannot make one) that is not the pull request's
author and whose collaborator permission on the repository is admin or write. That account's newest review in a state
of DECIDING_STATES (by submitted_at, then id) must be that approval: a later CHANGES_REQUESTED, or the dismissal of
the approval, takes it back. A read that fails gives no approval.

Write access, not membership of the organisation: the oss-verify App, whose token review.yml's comment job reads with,
has no permission on the organisation's members (gh api apps/oss-verify, 2026-11-26), so it cannot read a membership
that is private, and GitHub's anonymous answer gives a private member's review the association CONTRIBUTOR. GitHub's
collaborator permission API needs only metadata: read, which every token of the App has.
"""
from __future__ import annotations

import re
import subprocess

# review.yml's rule for trusted accounts takes a login of this shape only.
LOGIN = re.compile(r"[A-Za-z0-9-]+(\[bot\])?")
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# The states of a review that give a reviewer's decision (person_approval). The newest of them is the one that counts.
DECIDING_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})


def time_of(value: object) -> str | None:
    """`value`, when it is a time as GitHub gives it (2026-11-11T20:44:39Z), else None."""
    return value if isinstance(value, str) and TIME.fullmatch(value) else None


def write_access(api, repo: str, login: str) -> bool | None:
    """Whether GitHub's collaborator permission API gives `login` admin or write; None when the read fails or its
    answer is not an object. `api` is artifact.py's Api, or one with its get."""
    try:
        answer = api.get(f"repos/{repo}/collaborators/{login}/permission")
    except (subprocess.CalledProcessError, ValueError):
        return None
    if not isinstance(answer, dict):
        return None
    return answer.get("permission") in ("admin", "write")


def person_approval(api, repo: str, number: int, pull: dict, sha: str) -> str | None:
    """The login of a person who approved the commit `sha` of pull request `number` (`pull`, the API's object of it),
    or None: the rule at the top of this file. `api` is artifact.py's Api, or one with its get and pages."""
    author = str((pull.get("user") or {}).get("login") or "").lower()
    try:
        reviews = [r for page in api.pages(f"repos/{repo}/pulls/{number}/reviews?per_page=100") for r in page
                   if isinstance(r, dict)]
    except (subprocess.CalledProcessError, ValueError):
        return None
    newest = {}   # each reviewer's newest review of DECIDING_STATES, by login in lower case
    for review in reviews:
        login = str((review.get("user") or {}).get("login") or "").lower()
        if not login or review.get("state") not in DECIDING_STATES:
            continue
        order = (time_of(review.get("submitted_at")) or "", review["id"] if isinstance(review.get("id"), int) else -1)
        if login not in newest or order > newest[login][0]:
            newest[login] = (order, review)
    for _, review in sorted(newest.values(), key=lambda found: found[0]):
        user = review.get("user") or {}
        login = str(user.get("login"))
        if review.get("state") != "APPROVED" or review.get("commit_id") != sha or user.get("type") != "User" \
                or login.lower() == author or not LOGIN.fullmatch(login):
            continue
        if write_access(api, repo, login) is True:
            return login
    return None
