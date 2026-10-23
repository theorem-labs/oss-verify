#!/usr/bin/env python3
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: OSS Verify's enrollment files (build.sh, patch_style, harness sources and
# patches beside project.yaml; .oss-verify/ in the project's repository), validation warnings, two new rows (the
# n/a contact of a seeded project on an outside pull request; the project's status in the proofs index), and no
# package-rank row.
"""Write the triage comment for an enrollment pull request, as Markdown on standard output.

    GITHUB_TOKEN=... .github/scripts/triage.py --repo theorem-labs/oss-verify --pr 123

Run by .github/workflows/triage.yaml, or by hand to see what it would say. Prints nothing when the pull request
does not touch projects/.

The pull request is read as data through the GitHub API: nothing from it is checked out or executed, and a read-only
token is enough. The token goes to api.github.com alone, and no other host is contacted. Text from the pull request,
the enrolled repository or the proofs index reaches the comment only through code(), so it cannot inject Markdown.

Not ported from OSS Scanner's triage: the row that ranks the repository's packages among the most downloaded on
PyPI, npm and crates.io. The builder builds only the languages docs/project-yaml.md lists, whose libraries those
registries do not carry today.

Requires PyYAML, as tools/validate.py does.
"""
from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import pathlib
import re
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

# tools/validate.py holds the enrollment rules (and imports PyYAML).
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools"))
import validate

API = "https://api.github.com"
RAW = "application/vnd.github.raw"
MAX_RATE_LIMIT_WAIT = 65  # seconds
# A larger answer is refused. A file we only search (a license, a security policy) is read up to the smaller limit.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
# The workflow finds the comment to update by this first line.
MARKER = "<!-- oss-verify-triage -->"

OK, WARN, FAIL, INFO = "✅", "⚠️", "❌", "ℹ️"
NOW = datetime.now(timezone.utc)
YEAR_AGO = NOW - timedelta(days=365)
# "Established", "active" and "critical" have no published numbers. These only decide when a row gets a warning.
ESTABLISHED_MONTHS = 6
STALE_MONTHS = 12
# How many of a repository's latest issues, and of its latest pull requests, are looked at for who opened them.
RECENT_THREADS = 50
# Whoever wrote this many of the last 100 commits is part of the project, whatever role GitHub shows for them.
REGULAR_COMMITS = 5
# Fewer people than this from outside the project among those who opened the latest issues and pull requests is
# warned about. One person can open hundreds of either in a repository of their own; they cannot be other people.
FEW_OUTSIDERS = 3
# A project below both is warned about. Either alone is not: a busy young project scores well with few stars, and
# a quiet, widely used one has the stars but a middling score.
FEW_STARS = 100
LOW_CRITICALITY = 0.4

GITHUB_REPO = re.compile(r"https://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:#(.+))?")
LOGIN = re.compile(r"[A-Za-z0-9-]+")
# These two run on text anyone can write (a description, a SECURITY.md), so nothing in them is unbounded or
# crosses a line: a long run of one character must not make them slow.
CHECKBOX = re.compile(r"^[ \t]*[-*][ \t]+\[([ xX])\][ \t]+(.+)$", re.MULTILINE)
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}")
# How many OSS-Fuzz projects with a name like the repository's are read to see whether one is for it.
OSS_FUZZ_CANDIDATES = 5
# A GitHub repository as OSS-Fuzz's project.yaml files name it in main_repo: any scheme, often with .git.
MAIN_REPO = re.compile(r"(?:\w+://|git@)?(?:www\.)?github\.com[/:]([^/\s]+/[^/\s#]+?)(?:\.git)?/?")
# Where GitHub looks for a repository's security policy.
SECURITY_POLICY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
# Where a project keeps its OSS Verify files in its own repository, as the README suggests.
IN_REPO_DIRECTORY = ".oss-verify"

# The proofs repository's index of projects: a tab-separated index/projects.tsv whose header row names a `project` and a
# `status` column, and `statements` and `proved`.
PROOFS_REPO = validate.PROOFS_REPO.removeprefix("https://github.com/")
PROOFS_INDEX = "index/projects.tsv"

# GitHub's author_association values that mark a maintainer rather than a contributor, and how the comment words them.
ASSOCIATIONS = {
    "OWNER": "owns the repository",
    "MEMBER": "member of the owning organisation",
    "COLLABORATOR": "collaborator on the repository",
}
# Who merged the repository's latest pull requests.
RECENT_MERGES = """query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) {
  pullRequests(states: MERGED, first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {
    nodes { mergedBy { login } } } } }"""
# Who opened the repository's latest issues and pull requests, and who wrote its latest commits.
PARTICIPANTS = """query($owner: String!, $name: String!, $threads: Int!) { repository(owner: $owner, name: $name) {
  issues(first: $threads, orderBy: {field: CREATED_AT, direction: DESC}) {
    nodes { authorAssociation author { __typename login } } }
  pullRequests(first: $threads, orderBy: {field: CREATED_AT, direction: DESC}) {
    nodes { authorAssociation author { __typename login } } }
  defaultBranchRef { target { ... on Commit { history(first: 100) { nodes { author { user { login } } } } } } } } }"""

# SPDX ids, as GitHub reports them, of the licenses we accept without a second look. BSL-1.0 is the Boost license;
# the Business Source License is BUSL-1.1, which GitHub does not recognise and reports as "Other".
COMMON_LICENSES = {
    "0BSD", "AGPL-3.0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "EPL-2.0", "GPL-2.0", "GPL-3.0",
    "ISC", "LGPL-2.1", "LGPL-3.0", "MIT", "MIT-0", "MPL-2.0", "PostgreSQL", "Unlicense", "Zlib",
}
# Names of source-available licenses, looked for in the license text when GitHub cannot name it.
SOURCE_AVAILABLE = (
    "Business Source License", "Server Side Public License", "Elastic License", "Commons Clause",
    "Functional Source License", "PolyForm", "Sustainable Use License", "Fair Source License",
    "Confluent Community License", "Redis Source Available License", "Attribution-NonCommercial",
    "Innovation-Enabling Source Code License",
)
# Wording of a repository that is open source only in part, such as one with an enterprise directory.
PARTLY_OPEN = ("Enterprise License", "proprietary license", "commercial license")

CRITICALITY_SOURCE = "https://github.com/ossf/criticality_score"
# The signals of the OpenSSF criticality score, each with its (weight, threshold).
CRITICALITY_SIGNALS = {
    "created_since": (1, 120),
    "updated_since": (-1, 120),
    "contributor_count": (2, 5000),
    "org_count": (1, 10),
    "commit_frequency": (1, 1000),
    "recent_releases_count": (0.5, 26),
    "closed_issues_count": (0.5, 5000),
    "updated_issues_count": (0.5, 5000),
    "comment_frequency": (1, 15),
    "dependents_count": (2, 500000),
}
TOP_CONTRIBUTORS = 15
# The company each of these accounts gives on its profile. One request, where the REST API takes one per account:
# the workflow's token is allowed 1,000 requests an hour.
COMPANIES = "query($ids: [ID!]!) { nodes(ids: $ids) { ... on User { company } } }"
# When the repository's latest releases were made. The REST API lists every asset of every release with them: tens
# of megabytes for a project that has many of both.
RECENT_RELEASES = """query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) {
  releases(first: 100, orderBy: {field: CREATED_AT, direction: DESC}) { nodes { createdAt } } } }"""
ISSUE_WINDOW_DAYS = 90


class ApiError(Exception):
    """A request to an API failed. `status` is the HTTP status, or 0 if there was no usable response."""

    def __init__(self, api: str, status: int, path: str, problem: str = ""):
        super().__init__(f"{api}: {problem or status or 'no response'} for {path}")
        self.status = status


def retry_delay(error: urllib.error.HTTPError) -> float | None:
    """Seconds to wait before asking once more, or None if the answer will not change."""
    if error.code >= 500:
        return 2
    if error.code not in (403, 429):
        return None
    # Out of requests, which GitHub says in one of two ways. The search API allows 30 a minute, so that wait is
    # short; the hourly limit is not waited for.
    if (error.headers.get("Retry-After") or "").isdigit():
        delay = int(error.headers["Retry-After"])
    elif error.headers.get("X-RateLimit-Remaining") == "0":
        delay = float(error.headers.get("X-RateLimit-Reset", 0)) - time.time() + 1
    else:
        return None
    return max(delay, 1) if delay <= MAX_RATE_LIMIT_WAIT else None


class StayOnApi(urllib.request.HTTPRedirectHandler):
    """Follow a redirect (a renamed repository) only within the API, so that the token is sent nowhere else."""

    def __init__(self, base: str):
        self.base = base

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if not newurl.startswith(f"{self.base}/"):
            return None  # urllib then raises the redirect as an HTTPError
        return super().redirect_request(request, fp, code, msg, headers, newurl)


class Api:
    """A client for one API that only reads. Callers quote every path segment that comes from a pull request."""

    def __init__(self, name: str, base: str, headers: dict[str, str] | None = None):
        self.name, self.base = name, base
        self.headers = {"User-Agent": "oss-verify-triage", **(headers or {})}
        self.opener = urllib.request.build_opener(StayOnApi(base))

    def fetch(
        self, path: str, accept: str | None = None, body: dict | None = None, whole: bool = False, **params
    ) -> tuple[bytes, str]:
        """GET a path, or POST `body` to it. Return the response's body and its Link header. Of a file asked for
        as text, only the start is read, unless all of it is asked for with `whole`."""
        cut = accept == RAW and not whole
        limit = MAX_TEXT_BYTES if cut else MAX_RESPONSE_BYTES
        query = urlencode({key: value for key, value in params.items() if value is not None})
        headers = {**self.headers, "Accept": accept} if accept else self.headers
        data = json.dumps(body).encode() if body else None
        url = f"{self.base}/{path}{'?' + query if query else ''}"
        request = urllib.request.Request(url, data=data, headers=headers)
        for last_try in (False, True):
            try:
                with self.opener.open(request, timeout=30) as response:
                    answer, length = response.read(limit + 1), response.headers.get("Content-Length")
                    # Unlike a read to the end, a read of n bytes does not notice a connection that was cut off.
                    if length and length.isdigit() and len(answer) < min(int(length), limit):
                        raise http.client.IncompleteRead(answer)
                    # The start of a text is of use, the start of a JSON answer is not: asking again will not help.
                    if len(answer) > limit and not cut:
                        raise ApiError(self.name, 0, path, "answer too large")
                    return answer[:limit], response.headers.get("Link") or ""
            except urllib.error.HTTPError as error:
                delay = retry_delay(error)
                if last_try or delay is None:
                    raise ApiError(self.name, error.code, path) from None
            except (OSError, http.client.HTTPException):
                delay = 2  # a dropped or cut-off connection
                if last_try:
                    raise ApiError(self.name, 0, path) from None
            time.sleep(delay)

    def get(self, path: str, **params):
        """GET a path and parse its JSON. An answer with no body (204) is {}."""
        return json.loads(self.fetch(path, **params)[0] or "{}")

    def find(self, path: str, **params):
        """Like get(), but None when the path does not exist."""
        try:
            return self.get(path, **params)
        except ApiError as error:
            if error.status == 404:
                return None
            raise


class GitHub(Api):
    """api.github.com: the one API, and the one that is sent the token."""

    def __init__(self, token: str | None):
        super().__init__(
            "GitHub API", API, {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        )
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def count(self, path: str, **params) -> int:
        """How many items a list has: asked for one per page, the number of the last page is the count."""
        try:
            body, link = self.fetch(path, per_page=1, **params)
        except ApiError as error:
            if error.status != 404:
                raise
            return 0  # e.g. the comments of a repository with issues turned off
        last = re.search(r'[?&]page=(\d+)[^>]*>; rel="last"', link)
        if not last and 'rel="next"' in link:
            raise ApiError(self.name, 0, path, "no count")  # GitHub leaves the last page out of some expensive listings
        return int(last.group(1)) if last else len(json.loads(body))

    def total(self, kind: str, query: str) -> int:
        """How many results a search for issues or commits has."""
        return self.get(f"search/{kind}", q=query, per_page=1)["total_count"]

    def text(self, path: str, whole: bool = False, **params) -> str | None:
        """The text of a file in a repository (its first 256 KiB, or all of it with `whole`), or None if it is not
        there."""
        try:
            return self.fetch(path, accept=RAW, whole=whole, **params)[0].decode("utf-8", "replace")
        except ApiError as error:
            if error.status == 404:
                return None
            raise

    def graphql(self, query: str, **variables) -> dict:
        """Run a GraphQL query, for what the REST API cannot say in one request."""
        answer = json.loads(self.fetch("graphql", body={"query": query, "variables": variables})[0])
        if not answer.get("data"):
            raise ApiError(self.name, 0, "graphql", "query refused")
        return answer["data"]  # with "errors" beside it when only part could be answered, such as a deleted account


def code(text: object, limit: int = 120) -> str:
    """Untrusted text as a Markdown code span that cannot end the span, the table cell or the comment. A value
    from YAML that is not a string is shown as its type: printing it could be made to take forever."""
    if not isinstance(text, str):
        text = f"<{type(text).__name__}>"
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text).replace("`", "'").replace("|", "¦")
    if len(text) > limit:
        text = text[:limit] + "…"
    return f"`{text or ' '}`"


def parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def months_since(when: datetime) -> int:
    return (NOW - when).days // 30


def ago(when: datetime) -> str:
    days = (NOW - when).days
    if days < 2:
        return "today" if days < 1 else "yesterday"
    if days < 60:
        return f"{days} days ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


# --- reading the pull request and the repository ---


def changed_paths(gh: GitHub, repo: str, number: int) -> list[str]:
    """The paths the pull request touches, a renamed file under both its names. Only the first 100: scope_row()
    refuses a pull request that changes more."""
    files = gh.get(f"repos/{repo}/pulls/{number}/files", per_page=100)
    return [name for file in files for name in (file["filename"], file.get("previous_filename")) if name]


def split_paths(paths: list[str]) -> tuple[list[str], list[str]]:
    """Return the names of the projects touched, and the paths that are not directly inside a projects/<name>/."""
    names, outside = set(), []
    for path in paths:
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "projects":
            names.add(parts[1])
        else:
            outside.append(path)
    return sorted(names), outside


def accepted_limit(name: str, copied: frozenset[str] = frozenset()) -> int | None:
    """The size above which validate.py refuses a file of this name beside project.yaml, or None if it refuses the
    name itself (so that only the name matters, not the bytes). `copied` names the files that `sources` copies, which
    may have any name. A harness source of any language counts: validate.py then judges it by the project's."""
    if name == "project.yaml":
        return validate.MAX_CONFIG_BYTES
    if validate.SEED_CORPUS.fullmatch(name):
        return validate.MAX_CORPUS_BYTES
    if name in copied or name == "build.sh":
        return validate.MAX_SOURCE_BYTES
    if name in validate.FILE_KEYS or name in (validate.SERIES, validate.SOURCES):
        return validate.MAX_FILE_BYTES
    if name.endswith(validate.SOURCE_SUFFIXES) or name.endswith(validate.PATCH_SUFFIX):
        return validate.MAX_SOURCE_BYTES
    return None


def fetch_project(gh: GitHub, repo: str, sha: str, name: str, directory: pathlib.Path) -> bool:
    """Recreate projects/<name>/ as it is at commit `sha` in `directory`, so tools/validate.py can check it like a
    checkout. Return False if the pull request has no such directory (it withdraws the project).

    In a directory with more files than validate.py accepts, only project.yaml is downloaded and the other files are
    only named: validate.py refuses the directory for its size anyway, and a download per file would spend the
    workflow's API requests."""
    listing = f"repos/{repo}/contents/projects/{quote(name, safe='')}"
    entries = gh.find(listing, ref=sha)
    if not isinstance(entries, list):
        return False
    directory.mkdir()
    download = len(entries) <= validate.MAX_FILES + 1  # the files and project.yaml
    # The sources file first: the files it copies may have any name.
    fetched, copied = {}, frozenset()
    for entry in entries:
        if download and entry["name"] == validate.SOURCES and entry["type"] == "file" \
                and entry["size"] <= validate.MAX_FILE_BYTES:
            fetched[validate.SOURCES] = gh.fetch(f"{listing}/{validate.SOURCES}", accept=RAW, ref=sha)[0]
            copied = frozenset(validate.copied_by_sources(
                {validate.SOURCES: fetched[validate.SOURCES].decode("utf-8", "replace")}))
    for entry in entries:
        # The name becomes a path here. Git allows none of these as a name, so this only guards against surprises.
        if "/" in entry["name"] or "\\" in entry["name"] or entry["name"] in (".", ".."):
            continue
        target, limit = directory / entry["name"], accepted_limit(entry["name"], copied)
        if entry["type"] in ("dir", "submodule"):
            target.mkdir()
        elif entry["type"] != "file":
            target.symlink_to("symlink")  # validate.py rejects whatever is not a regular file
        elif limit is None or not (download or entry["name"] == "project.yaml"):
            target.touch()  # not a file we accept, or one too many: only its name matters
        elif entry["size"] > limit:
            target.write_bytes(bytes(limit + 1))  # too large to accept, so not worth downloading
        elif entry["name"] in fetched:
            target.write_bytes(fetched[entry["name"]])
        else:
            target.write_bytes(gh.fetch(f"{listing}/{quote(entry['name'], safe='')}", accept=RAW, ref=sha)[0])
    return True


def read_config(directory: pathlib.Path) -> dict:
    """The parsed project.yaml, or {} if there is none we can use."""
    try:
        config = validate.load(directory)
    except (OSError, ValueError):
        return {}
    return config if isinstance(config, dict) else {}


def top_contributors(gh: GitHub, slug: str, count: int) -> list[dict]:
    """The repository's top contributors. Empty for the few histories so long that GitHub refuses to list them."""
    try:
        return gh.get(f"repos/{slug}/contributors", per_page=count)
    except ApiError as error:
        if error.status != 403:
            raise
        return []


# --- the checks: each returns the mark and the text of one row of the comment ---


def scope_row(names: list[str], outside: list[str], changed_files: int) -> tuple[str, str]:
    problems = []
    if len(names) > 1:
        shown = ", ".join(code(name) for name in names[:5])
        problems.append(f"touches {len(names)} projects ({shown}); one per pull request")
    if outside:
        shown = ", ".join(code(path) for path in outside[:5]) + (" …" if len(outside) > 5 else "")
        problems.append(f"changes files outside `projects/<name>/`: {shown}")
    if changed_files > 100:
        problems.append(f"changes {changed_files} files")
    if problems:
        return FAIL, "; ".join(problems)
    return OK, "only this project's directory"


def validate_row(problems: list[str], warnings: list[str] = ()) -> tuple[str, str]:
    if problems:
        return FAIL, "<br>".join(code(problem, 300) for problem in problems[:10])
    if warnings:
        return WARN, "passes, with warnings:<br>" + "<br>".join(code(warning, 300) for warning in warnings[:10])
    return OK, "passes"


def checklist_row(body: str) -> tuple[str, str]:
    # The template marks the patch style's box as optional: left empty, it is not counted.
    boxes = [(mark, text) for mark, text in CHECKBOX.findall(body) if mark != " " or "optional" not in text]
    unticked = [text for mark, text in boxes if mark == " "]
    if not boxes:
        return WARN, "the pull request template's checklist is missing from the description"
    if unticked:
        shown = "; ".join(code(text, 80) for text in unticked[:5]) + (" …" if len(unticked) > 5 else "")
        return WARN, f"{len(unticked)} of {len(boxes)} not ticked: {shown}"
    return OK, f"all {len(boxes)} ticked"


def seeded_contact_row(config: dict, association: str) -> tuple[str, str]:
    """primary_contact: n/a is how a project we seeded says that no maintainer has adopted it yet. From anyone else,
    an enrollment needs the project's security contact."""
    if association in ASSOCIATIONS:
        return INFO, ("`n/a`: a project seeded by this repository's maintainers, not enrolled by the project's own. It is "
                      "published only while it has no findings, and a finding for it is sent to no one automatically "
                      "(docs/what-gets-proven.md, Findings)")
    return WARN, (
        "`primary_contact` is `n/a`, which only a project seeded by this repository's maintainers may say: an "
        "enrollment names the project's security contact"
    )


def standing_row(meta: dict) -> tuple[str, str]:
    created, pushed = parse_time(meta["created_at"]), parse_time(meta["pushed_at"])
    result = f"created {ago(created)}, last push {ago(pushed)}"
    if meta["archived"]:
        return FAIL, f"archived; {result}"
    concerns = []
    if meta["fork"]:
        concerns.append("a fork of another repository")
    if months_since(created) < ESTABLISHED_MONTHS:
        concerns.append(f"under {ESTABLISHED_MONTHS} months old")
    if months_since(pushed) >= STALE_MONTHS:
        concerns.append(f"no push in {STALE_MONTHS} months")
    if concerns:
        return WARN, f"{'; '.join(concerns)} ({result})"
    return OK, result


def popularity_row(meta: dict) -> tuple[str, str]:
    forks, watchers = meta["forks_count"], meta["subscribers_count"]
    result = f"{meta['stargazers_count']:,} stars · {forks:,} forks · {watchers:,} watching"
    absent = [what for what, count in (("forks", forks), ("watchers", watchers)) if not count]
    if absent:
        return WARN, f"no {' and no '.join(absent)}: little sign that others use it ({result})"
    return INFO, result


def outsiders_row(gh: GitHub, slug: str, meta: dict, login: str) -> tuple[str, str]:
    """How many people from outside the project opened its latest issues and pull requests? Not counted: the
    repository's owner, whoever opened this pull request, anyone GitHub shows as a maintainer, anyone who wrote a
    good share of the latest commits, and bots."""
    owner, name = slug.split("/")
    repository = gh.graphql(PARTICIPANTS, owner=owner, name=name, threads=RECENT_THREADS)["repository"]
    threads = repository["issues"]["nodes"] + repository["pullRequests"]["nodes"]
    if not threads:
        return WARN, "the repository has no issues or pull requests"

    history = ((repository["defaultBranchRef"] or {}).get("target") or {}).get("history") or {"nodes": []}
    wrote = [((commit["author"] or {}).get("user") or {}).get("login", "").lower() for commit in history["nodes"]]
    insiders = {meta["owner"]["login"].lower(), login.lower()}
    insiders |= {person for person in set(wrote) if wrote.count(person) >= REGULAR_COMMITS}
    outsiders, theirs = set(), 0
    for thread in threads:
        author = thread["author"] or {}  # no author: a deleted account
        person = author.get("login", "").lower()
        if author.get("__typename") != "User" or thread["authorAssociation"] in ASSOCIATIONS or person in insiders:
            continue
        outsiders.add(person)
        theirs += 1

    result = f"the last {len(threads)} issues and pull requests"
    if not outsiders:
        return WARN, f"none: {result} were all opened by the project's own people or by bots"
    people = "1 person" if len(outsiders) == 1 else f"{len(outsiders)} people"
    result = f"{people} from outside the project opened {theirs} of {result}"
    return (WARN if len(outsiders) < FEW_OUTSIDERS else INFO), result


def license_row(gh: GitHub, slug: str, meta: dict) -> tuple[str, str]:
    spdx = (meta.get("license") or {}).get("spdx_id")
    if not spdx:
        return FAIL, "GitHub finds no license file"
    if spdx in COMMON_LICENSES:
        return OK, code(spdx)
    if spdx != "NOASSERTION":
        return WARN, f"{code(spdx)} is not on our list of common open-source licenses; check it"
    text = gh.text(f"repos/{slug}/license") or ""
    found = next((name for name in SOURCE_AVAILABLE if name.lower() in text.lower()), None)
    if found:
        return FAIL, f"the license file mentions “{found}”, a source-available license"
    found = next((name for name in PARTLY_OPEN if name.lower() in text.lower()), None)
    if found:
        return WARN, f"the license file mentions “{found}”: part of the repository may not be open source"
    # GitHub also fails to name a plain license with a line added, so show the reviewer what the file says.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    says = next((line for line in lines if "licens" in line.lower()), lines[0] if lines else "nothing")
    return WARN, f"GitHub cannot name the license; its file says {code(says, 80)}"


def maintainer_row(gh: GitHub, slug: str, meta: dict, login: str) -> tuple[str, str]:
    """Is the person who opened the pull request an active maintainer of the repository? Only public signals: a
    role GitHub shows (owner, member, collaborator) or, failing that, having merged recent pull requests."""
    if not LOGIN.fullmatch(login):
        return WARN, "not a user account"

    roles = []
    if meta["owner"]["login"].lower() == login.lower():
        roles.append(ASSOCIATIONS["OWNER"])
    else:
        # GitHub labels each issue and pull request with what its author is to the repository.
        authored = gh.get("search/issues", q=f"repo:{slug} author:{login}", per_page=1)["items"]
        if authored and authored[0]["author_association"] in ASSOCIATIONS:
            roles.append(ASSOCIATIONS[authored[0]["author_association"]])
    organisation = quote(meta["owner"]["login"], safe="")
    if not roles and gh.find(f"orgs/{organisation}/public_members/{login}") is not None:
        roles.append("public member of the owning organisation")

    merged = 0
    if not roles:
        # A private member of the organisation shows no role, but merging takes write access.
        owner, name = slug.split("/")
        merges = gh.graphql(RECENT_MERGES, owner=owner, name=name)["repository"]["pullRequests"]["nodes"]
        merged = sum(1 for pull in merges if ((pull["mergedBy"] or {}).get("login") or "").lower() == login.lower())
        if merged:
            roles.append(f"merged {merged} of the last {len(merges)} pull requests")

    # Listed, not counted: GitHub does not say how many pages a search by author has in a very large repository.
    recent = len(gh.get(f"repos/{slug}/commits", author=login, since=iso(YEAR_AGO), per_page=100))
    commits = f"{recent}+" if recent == 100 else recent
    contributors = [person.get("login", "").lower() for person in top_contributors(gh, slug, 100)]
    if login.lower() in contributors:
        rank = f"#{contributors.index(login.lower()) + 1} contributor"
    else:
        rank = "not in the top 100 contributors" if contributors else "contributor rank unavailable"
    evidence = f"{', '.join(roles) or 'no maintainer role visible'}; {commits} commits in the last 12 months; {rank}"

    if roles and (recent or merged):
        return OK, evidence
    return (WARN if roles or recent else FAIL), evidence


def security_policy(gh: GitHub, slug: str, owner: str) -> tuple[str, str] | None:
    """Find the security policy that applies to the repository: its own, or else the one its owner keeps for all
    their repositories in <owner>/.github. Return the policy's repository and its text, or None."""
    for repo in (slug, f"{quote(owner, safe='')}/.github"):
        for path in SECURITY_POLICY_PATHS:
            text = gh.text(f"repos/{repo}/contents/{path}")
            if text is not None:
                return repo, text
    return None


def contact_row(gh: GitHub, slug: str, meta: dict, config: dict) -> tuple[str, str]:
    """Does the repository's own security policy name the address that reports would go to?"""
    contact = config.get("primary_contact")
    if not isinstance(contact, str):
        return WARN, "project.yaml names no contact"
    if contact == validate.NO_CONTACT:
        return INFO, "project.yaml names no contact (`n/a`), so there is nothing to check"
    policy = security_policy(gh, slug, meta["owner"]["login"])
    if policy is None:
        return INFO, f"no `SECURITY.md` to check {code(contact)} against"
    repo, text = policy
    where = "`SECURITY.md`" if repo == slug else f"`SECURITY.md` of {code(repo)}"
    # Whole addresses are compared, so that security@example.org is not found inside another address.
    given = sorted({address.lower() for address in EMAIL.findall(text)})
    if contact.lower() in given:
        return OK, f"{code(contact)} is in {where}"
    # Many policies ask for reports through GitHub and give no address at all; that is not a mismatch.
    if not given:
        return INFO, f"{where} gives no email address to check {code(contact)} against"
    shown = ", ".join(code(address) for address in given[:3]) + (" …" if len(given) > 3 else "")
    return WARN, f"{code(contact)} is not in {where}, which gives {shown}"


def squash(name: str) -> str:
    """A name reduced to its letters and digits, so that PcapPlusPlus and pcap-plus-plus compare equal."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def likeness(slug: str, name: str) -> int | None:
    """How like the repository's name, or its owner's, the name of a project is: 0 at best, None if not at all."""
    key, (owner, repo) = squash(name), (squash(part) for part in slug.split("/"))
    if key in (repo, owner):
        return 0 if key == repo else 1
    # One name inside the other, unless the inner one is so short that it is there by chance.
    for place, (inner, outer) in enumerate(((repo, key), (key, repo), (owner, key), (key, owner)), start=2):
        if len(inner) >= 4 and inner in outer:
            return place
    return None


def oss_fuzz_candidates(slug: str, names: list[str]) -> list[str]:
    """Of OSS-Fuzz's project names, the few that could be this repository's, likeliest first.

    OSS-Fuzz has no index by repository, and GitHub's code search is closed to the workflow's token. But a project
    is nearly always named after its repository or the repository's owner (bitcoin-core fuzzes bitcoin/bitcoin)."""
    ranked = sorted((place, len(name), name) for name in names if (place := likeness(slug, name)) is not None)
    return [name for _, _, name in ranked[:OSS_FUZZ_CANDIDATES]]


def oss_fuzz_projects(gh: GitHub, slug: str) -> tuple[dict[str, dict], dict[str, object]]:
    """Find the OSS-Fuzz projects that fuzz this repository: each one's name and project.yaml. Also return the
    main_repo of any project named exactly after the repository or its owner that is for some other repository."""
    listing = gh.get("repos/google/oss-fuzz/git/trees/HEAD:projects")["tree"]
    owner, name = (squash(part) for part in slug.split("/"))
    found, namesakes = {}, {}
    for candidate in oss_fuzz_candidates(slug, [entry["path"] for entry in listing if entry["type"] == "tree"]):
        text = gh.text(f"repos/google/oss-fuzz/contents/projects/{quote(candidate, safe='')}/project.yaml")
        try:
            project = validate.yaml.safe_load(text or "")
        except (validate.yaml.YAMLError, RecursionError):
            continue
        # A name is only a guess: main_repo is what says the project is for this repository.
        main_repo = project.get("main_repo") if isinstance(project, dict) else None
        match = MAIN_REPO.fullmatch(main_repo.strip()) if isinstance(main_repo, str) else None
        if match and match.group(1).lower() == slug.lower():
            found[candidate] = project
        elif isinstance(project, dict) and squash(candidate) in (name, owner):
            namesakes[candidate] = main_repo
    return found, namesakes


def oss_fuzz_row(gh: GitHub, slug: str, config: dict) -> tuple[str, str]:
    """Is the repository in OSS-Fuzz, whose fuzz targets we verify, and does OSS-Fuzz report to the same address?"""
    projects, namesakes = oss_fuzz_projects(gh, slug)
    if not projects and namesakes:
        others = "; ".join(f"{code(name)} there is for {code(main_repo)}" for name, main_repo in namesakes.items())
        return INFO, f"no OSS-Fuzz project is for this repository, but {others}"
    if not projects:
        return INFO, "not found in OSS-Fuzz"
    result = f"in OSS-Fuzz as {', '.join(code(name) for name in projects)}"

    contact = config.get("primary_contact")
    if not isinstance(contact, str) or contact == validate.NO_CONTACT:
        return OK, result
    primary, ccs = set(), set()
    for project in projects.values():
        if isinstance(project.get("primary_contact"), str):
            primary.add(project["primary_contact"].lower())
        for key in ("auto_ccs", "vendor_ccs"):
            listed = project.get(key)
            listed = [listed] if isinstance(listed, str) else listed if isinstance(listed, list) else []
            ccs.update(address.lower() for address in listed if isinstance(address, str))
    if contact.lower() in primary:
        return OK, f"{result}, with the same primary contact"
    theirs = ", ".join(code(address) for address in sorted(primary)) or "not given"
    if contact.lower() in ccs:
        return OK, f"{result}, which CCs {code(contact)} (its primary contact is {theirs})"
    return WARN, f"{result}, whose contacts do not include {code(contact)} (its primary contact is {theirs})"


def verifier_files_row(gh: GitHub, slug: str, ref: str | None, config: dict, beside: set[str]) -> tuple[str, str]:
    """Has the project set up .oss-verify/ in its own repository, and are the files project.yaml names there?"""

    def in_repo(path: object) -> bool:
        if not (isinstance(path, str) and validate.REPO_PATH.fullmatch(path)):
            return False
        return gh.find(f"repos/{slug}/contents/{quote(path)}", ref=ref) is not None

    listing = gh.find(f"repos/{slug}/contents/{IN_REPO_DIRECTORY}", ref=ref)
    names = [entry["name"] for entry in listing] if isinstance(listing, list) else []
    result = f"present ({', '.join(code(name) for name in names[:6])})" if names else "not present"

    patch_style = config.get("patch_style")
    if "patch_style.md" not in beside and not (patch_style is not None and in_repo(patch_style)):
        result += "; no patch_style.md (optional)"

    if "Dockerfile" in beside:
        if "build.sh" not in beside:
            return WARN, f"{result}; the Dockerfile is in this pull request, with no build.sh beside it"
        return (OK if names else INFO), f"{result}; the Dockerfile and build.sh are in this pull request"
    dockerfile = config.get("dockerfile")
    if dockerfile is None:
        if config.get("primary_contact") == validate.NO_CONTACT:
            return INFO, f"{result}; no build files yet (a seeded project)"
        return FAIL, f"{result}; no Dockerfile in this pull request, and project.yaml names none in the repository"
    if not in_repo(dockerfile):
        return FAIL, f"{result}; no Dockerfile at {code(dockerfile)}" + (f" on {code(ref)}" if ref else "")
    build_sh = f"{dockerfile.rsplit('/', 1)[0]}/build.sh" if "/" in dockerfile else "build.sh"
    if not in_repo(build_sh):
        return WARN, f"{result}; Dockerfile at {code(dockerfile)}, with no build.sh beside it (it must create one)"
    return OK, f"{result}; Dockerfile at {code(dockerfile)}, with build.sh beside it"


def proofs_index_row(gh: GitHub, name: str) -> tuple[str, str]:
    """The project's row in the proofs repository's index (PROOFS_INDEX), if there is one."""
    text = gh.text(f"repos/{PROOFS_REPO}/contents/{PROOFS_INDEX}", whole=True)
    if text is None:
        return INFO, f"no proofs index yet ({code(PROOFS_REPO + '/' + PROOFS_INDEX)} is not there)"
    lines = text.splitlines()
    header = lines[0].split("\t") if lines else []
    if "project" not in header or "status" not in header:
        return WARN, "the proofs index has no `project` and `status` columns: its layout has changed"
    columns = {column: index for index, column in enumerate(header)}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != len(header) or fields[columns["project"]] != name:
            continue
        result = f"{code(name)} is {code(fields[columns['status']])} in the proofs index"
        if "statements" in columns and "proved" in columns:
            result += f": {code(fields[columns['proved']])} of {code(fields[columns['statements']])} statements proved"
        return INFO, result
    return INFO, f"{code(name)} is not in the proofs index"


def criticality_signals(gh: GitHub, slug: str, meta: dict) -> dict[str, float]:
    """Collect the signals of the OpenSSF criticality score, as its reference implementation defines them."""
    commits = f"repos/{slug}/commits"
    created = parse_time(meta["created_at"])
    try:
        # A repository imported from elsewhere is older than its GitHub creation date: use its first commit.
        first = gh.get(commits, per_page=1, page=gh.count(commits))[0]["commit"]["author"]["date"]
        created = min(created, parse_time(first))
    except (ApiError, IndexError, ValueError):
        pass

    try:
        contributor_count = gh.count(f"repos/{slug}/contributors", anon="true")
    except ApiError as error:
        if error.status != 403:
            raise
        contributor_count = CRITICALITY_SIGNALS["contributor_count"][1]  # GitHub refuses to list very long histories

    organisations = set()
    people = [person["node_id"] for person in top_contributors(gh, slug, TOP_CONTRIBUTORS) if person.get("node_id")]
    # Bots are contributors too: they have no company, and some (Copilot) no profile at all.
    for person in gh.graphql(COMPANIES, ids=people)["nodes"] if people else []:
        company = (person or {}).get("company")
        if company:
            organisations.add(re.sub(r"inc\.|llc|@|\s", "", company.lower()).rstrip(","))

    owner, name = slug.split("/")
    releases = gh.graphql(RECENT_RELEASES, owner=owner, name=name)["repository"]["releases"]["nodes"]
    recent_releases = sum(1 for release in releases if parse_time(release["createdAt"]) > YEAR_AGO)
    if not releases:
        # A project that tags without publishing releases: assume its tags are spread evenly over its life.
        recent_releases = round(gh.count(f"repos/{slug}/tags") / max((NOW - created).days, 1) * 365)

    window = NOW - timedelta(days=ISSUE_WINDOW_DAYS)
    # GitHub lists comments on issues and pull requests together, so the frequency is taken over both.
    updated_threads = gh.total("issues", f"repo:{slug} updated:>={window:%Y-%m-%d}")
    comments = gh.count(f"repos/{slug}/issues/comments", since=iso(window))

    return {
        "created_since": months_since(created),
        "updated_since": months_since(parse_time(meta["pushed_at"])),
        "contributor_count": contributor_count,
        "org_count": len(organisations),
        "commit_frequency": round(gh.count(commits, since=iso(YEAR_AGO)) / 52, 1),
        "recent_releases_count": recent_releases,
        "closed_issues_count": gh.total("issues", f"repo:{slug} is:issue is:closed updated:>={window:%Y-%m-%d}"),
        "updated_issues_count": gh.total("issues", f"repo:{slug} is:issue updated:>={window:%Y-%m-%d}"),
        "comment_frequency": round(comments / updated_threads, 1) if updated_threads else 0,
        # Mentions of owner/repo in commit messages anywhere on GitHub: a dependency count that works for any language.
        "dependents_count": gh.total("commits", f'"{slug}"'),
    }


def criticality_score(signals: dict[str, float]) -> float:
    """The criticality score's formula: each signal on a log scale up to its threshold, averaged by weight. Between 0
    and 1."""
    total = sum(
        weight * math.log(1 + signals[name]) / math.log(1 + max(signals[name], threshold))
        for name, (weight, threshold) in CRITICALITY_SIGNALS.items()
    )
    return round(total / sum(weight for weight, _ in CRITICALITY_SIGNALS.values()), 5)


def criticality_row(gh: GitHub, slug: str, meta: dict) -> tuple[str, str]:
    if meta["fork"]:
        # A fork carries its parent's commits and contributors, and would be given the parent's score.
        parent = (meta.get("parent") or {}).get("full_name")
        return WARN, f"not scored: a fork of {code(parent)}, whose history it carries"
    signals = criticality_signals(gh, slug, meta)
    score = criticality_score(signals)
    result = f"**{score:.2f}** on the [OpenSSF]({CRITICALITY_SOURCE}) scale of 0 to 1"
    low = meta["stargazers_count"] < FEW_STARS and score < LOW_CRITICALITY
    if low:
        result += f": low, and the project has under {FEW_STARS} stars"
    details = ", ".join(f"{name} {value:,}" for name, value in signals.items())
    return (WARN if low else INFO), f"{result}<details><summary>signals</summary>{details}</details>"


# --- putting the comment together ---


def row(check: str, function, *arguments) -> tuple[str, str, str]:
    """One row of the table: (mark, check, result). A check that fails says so, and the others still run."""
    try:
        mark, result = function(*arguments)
    except ApiError as error:
        mark, result = WARN, f"could not be checked: {code(str(error))}"
    except Exception as error:  # an answer shaped as we did not expect: the workflow's log has the traceback
        traceback.print_exc()
        mark, result = WARN, f"could not be checked: {code(type(error).__name__)}"
    return mark, check, result


def repository_rows(gh: GitHub, config: dict, beside: set[str], login: str) -> tuple[str, list[tuple]]:
    """Return a Markdown description of the repository being enrolled, and the rows about it."""
    repo = config.get("repo")
    if not repo:
        return "unknown", [(WARN, "Repository", "no project.yaml that names one")]
    match = GITHUB_REPO.fullmatch(repo) if isinstance(repo, str) else None
    if not match:
        note = "not a github.com repository: check stars, maintainer, license and criticality by hand"
        return code(repo), [(WARN, "Repository", note)]

    owner, name, ref = match.groups()
    try:
        meta = gh.find(f"repos/{quote(owner, safe='')}/{quote(name, safe='')}")
    except ApiError as error:
        return code(repo), [(WARN, "Repository", f"could not be checked: {code(str(error))}")]
    if meta is None:
        return code(repo), [(FAIL, "Repository", "not found on GitHub, or not public")]

    slug = meta["full_name"]  # from GitHub: the canonical name, also after a rename
    return f"[{slug}]({meta['html_url']})" + (f" at {code(ref)}" if ref else ""), [
        row("Repository", standing_row, meta),
        row("Stars / forks", popularity_row, meta),
        row("Outside participants", outsiders_row, gh, slug, meta, login),
        row("Criticality score", criticality_row, gh, slug, meta),
        row("License", license_row, gh, slug, meta),
        row("Opened by an active maintainer", maintainer_row, gh, slug, meta, login),
        row("Contact in `SECURITY.md`", contact_row, gh, slug, meta, config),
        row("OSS-Fuzz", oss_fuzz_row, gh, slug, config),
        row(f"`{IN_REPO_DIRECTORY}/` in the repository", verifier_files_row, gh, slug, ref, config, beside),
    ]


def triage(gh: GitHub, repo: str, number: int) -> str:
    """Return the comment for a pull request, or "" if it does not touch projects/."""
    pull = gh.get(f"repos/{repo}/pulls/{number}")
    names, outside = split_paths(changed_paths(gh, repo, number))
    if not names:
        return ""
    name, login = names[0], pull["user"]["login"]
    heading = f"{MARKER}\n### Enrollment triage: {code('projects/' + name)}\n\n"

    with tempfile.TemporaryDirectory() as scratch:
        directory = pathlib.Path(scratch) / name
        # A name validate.py would refuse is not fetched; check_project() reports it without reading the directory.
        if validate.NAME.fullmatch(name) and not fetch_project(gh, repo, pull["head"]["sha"], name, directory):
            return f"{heading}This pull request removes the project's directory: a withdrawal, nothing to triage.\n"
        problems, warnings, _ = validate.check_project(directory)
        config = read_config(directory)
        beside = {path.name for path in directory.glob("*")}

    described, rows = repository_rows(gh, config, beside, login)
    if config.get("primary_contact") == validate.NO_CONTACT:
        rows.append(row("Seeded contact", seeded_contact_row, config, pull.get("author_association") or ""))
    rows += [
        row("Proofs index", proofs_index_row, gh, name),
        row("Pull request scope", scope_row, names, outside, pull["changed_files"]),
        row("`tools/validate.py`", validate_row, problems, warnings),
        row("Checklist", checklist_row, pull.get("body") or ""),
    ]
    table = "\n".join(f"| {mark} | {check} | {result} |" for mark, check, result in rows)
    return (
        f"{heading}Repository: {described} · opened by {code(login)}\n\n"
        f"| | Check | Result |\n|:-:|---|---|\n{table}\n\n"
        f"<sub>Automated, from public data, to help reviewers. Enrollment is decided case by case "
        f"([how to enroll a project](https://github.com/{repo}#enroll-a-project)). If you think we got something wrong, please "
        f"tell us in a reply.</sub>\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="the repository the pull request is in, as owner/name")
    parser.add_argument("--pr", required=True, type=int, help="the pull request's number")
    options = parser.parse_args()
    sys.stdout.write(triage(GitHub(os.environ.get("GITHUB_TOKEN")), options.repo, options.pr))
    return 0


if __name__ == "__main__":
    sys.exit(main())
