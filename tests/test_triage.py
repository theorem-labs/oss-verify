# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/triage.py, offline, with a fake GitHub API:  uv run pytest"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from oss_verify import validate

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("triage", ROOT / ".github" / "scripts" / "triage.py")
triage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(triage)

REPO = "theorem-labs/oss-verify"
INDEX = f"repos/{triage.PROOFS_REPO}/contents/{triage.PROOFS_INDEX}"
SEEDED = "repo: https://example.invalid/example\nprimary_contact: n/a\nlanguage: c\n"
ENROLLED = "repo: https://example.invalid/example\nprimary_contact: security@libexample.dev\nlanguage: c\n"


class FakeGitHub:
    """Answers from tables: `responses` for JSON (a missing path is a 404), `files` for raw bytes, `texts` for text.
    `fetched` lists the paths asked for as bytes or as text, as GitHub.text() asks through fetch()."""

    def __init__(self, responses=None, files=None, texts=None):
        self.responses, self.files, self.texts = responses or {}, files or {}, texts or {}
        self.fetched = []

    def get(self, path, **params):
        if path not in self.responses:
            raise triage.ApiError("fake", 404, path)
        return self.responses[path]

    def find(self, path, **params):
        return self.responses.get(path)

    def fetch(self, path, accept=None, body=None, whole=False, **params):
        self.fetched.append(path)
        if path not in self.files:
            raise triage.ApiError("fake", 404, path)
        return self.files[path], ""

    def text(self, path, whole=False, **params):
        self.fetched.append(path)
        return self.texts.get(path)

    # The criticality score's and the GraphQL rows' requests: unanswered, as a token without access would see them.
    def graphql(self, query, **variables):
        raise triage.ApiError("fake", 404, "graphql")

    def count(self, path, **params):
        raise triage.ApiError("fake", 404, path)

    def total(self, kind, query):
        raise triage.ApiError("fake", 404, f"search/{kind}")


def entry(name, kind="file", size=None, data=b""):
    return {"name": name, "type": kind, "size": len(data) if size is None else size}


def listing_for(files, extra=()):
    """A contents listing of projects/example and the raw files it names."""
    listing = f"repos/{REPO}/contents/projects/example"
    entries = [entry(name, data=data) for name, data in files.items()] + list(extra)
    raw = {f"{listing}/{name}": data for name, data in files.items()}
    return listing, entries, raw


class Text(unittest.TestCase):
    def test_code_cannot_escape_its_span(self):
        self.assertEqual(triage.code("a`b|c\nd\x1b"), "`a'b¦c d `")
        self.assertEqual(triage.code(""), "` `")
        self.assertEqual(triage.code(42), "`<int>`")
        self.assertEqual(triage.code("x" * 130, 10), "`" + "x" * 10 + "…`")

    def test_accepted_limits(self):
        self.assertEqual(triage.accepted_limit("project.yaml"), validate.MAX_CONFIG_BYTES)
        for name in ("Dockerfile", "series", "sources", "patch_style.md"):
            self.assertEqual(triage.accepted_limit(name), validate.MAX_FILE_BYTES, name)
        for name in ("build.sh", "driver.c", "x.cc", "y.hpp", "fuzz_parse.rs", "fuzz.py", "0001-static.patch"):
            self.assertEqual(triage.accepted_limit(name), validate.MAX_SOURCE_BYTES, name)
        for name in ("threat_model.md", "notes.txt", "CMakeLists.txt", "inputs.zip"):
            self.assertIsNone(triage.accepted_limit(name), name)
        self.assertEqual(triage.accepted_limit("x_fuzzer_seed_corpus.zip"), validate.MAX_CORPUS_BYTES)
        self.assertEqual(triage.accepted_limit("CMakeLists.txt", frozenset({"CMakeLists.txt"})),
                         validate.MAX_SOURCE_BYTES)


class Rows(unittest.TestCase):
    def test_scope(self):
        names, outside = triage.split_paths(["projects/a/project.yaml", "projects/a/build.sh"])
        self.assertEqual((names, outside), (["a"], []))
        self.assertEqual(triage.scope_row(names, outside, 2)[0], triage.OK)
        names, outside = triage.split_paths(["projects/a/x", "projects/b/x", "oss-verify check", "projects/a/sub/x"])
        mark, text = triage.scope_row(names, outside, 4)
        self.assertEqual(mark, triage.FAIL)
        self.assertIn("touches 2 projects", text)
        self.assertIn("`oss-verify check`", text)
        self.assertIn("`projects/a/sub/x`", text)
        self.assertIn("changes 101 files", triage.scope_row(["a"], [], 101)[1])
        # A fork's change to a seeded project: enrollment refuses it, so the row warns, and names the way through.
        mark, text = triage.scope_row(["curl"], [], 2, ["curl"])
        self.assertEqual(mark, triage.WARN)
        self.assertIn("`projects/curl/` is the port of a project that we seeded: `enrollment` refuses", text)
        self.assertIn("For an adoption, tick the box that accepts the OSS Verify terms", text)
        # A problem of scope fails first.
        self.assertEqual(triage.scope_row(["curl", "b"], [], 2, ["curl"])[0], triage.FAIL)

    def test_seeded_names(self):
        with tempfile.TemporaryDirectory() as scratch:
            table = pathlib.Path(scratch) / "seeded-projects.tsv"
            table.write_text("# Written by src/oss_verify/seeded_projects.py; do not edit.\n"
                             "project\tseedable\tbuild\tbuild notes\treason or notes\n"
                             "curl\tyes\treproduces\tall binaries match the release's\t-\n"
                             "sqlpage\tno\t-\t-\tthe release did not build it\n", encoding="utf-8")
            self.assertEqual(triage.seeded_names(table), {"curl"})
            self.assertEqual(triage.seeded_names(pathlib.Path(scratch) / "missing.tsv"), set())

    def test_checklist_with_the_template(self):
        template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        boxes = template.count("- [ ]")
        self.assertGreaterEqual(boxes, 7)
        mark, text = triage.checklist_row(template)
        self.assertEqual(mark, triage.WARN)
        self.assertIn(f"{boxes - 1} of {boxes - 1} not ticked", text)  # the optional box is not counted
        ticked = "\n".join(line.replace("- [ ]", "- [x]") if "optional" not in line else line
                           for line in template.splitlines())
        self.assertEqual(triage.checklist_row(ticked), (triage.OK, f"all {boxes - 1} ticked"))
        self.assertEqual(triage.checklist_row(template.replace("- [ ]", "- [x]"))[1], f"all {boxes} ticked")
        self.assertEqual(triage.checklist_row("no boxes here")[0], triage.WARN)

    def test_validate_row(self):
        self.assertEqual(triage.validate_row([], []), (triage.OK, "passes"))
        mark, text = triage.validate_row([], ["primary_contact is n/a: `x`"])
        self.assertEqual(mark, triage.WARN)
        self.assertIn("passes, with warnings", text)
        self.assertIn("'x'", text)
        mark, text = triage.validate_row(["missing repo", "bad | thing"], ["ignored"])
        self.assertEqual(mark, triage.FAIL)
        self.assertEqual(text, "`missing repo`<br>`bad ¦ thing`")

    def test_seeded_contact(self):
        for association in ("OWNER", "MEMBER", "COLLABORATOR"):
            mark, _ = triage.seeded_contact_row({}, association)
            self.assertEqual(mark, triage.INFO, association)
        for association in ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "NONE", ""):
            mark, _ = triage.seeded_contact_row({}, association)
            self.assertEqual(mark, triage.WARN, association)

    def test_oss_fuzz_does_not_compare_primary_contact(self):
        gh = in_oss_fuzz(FakeGitHub(), {
            "example": "main_repo: https://github.com/owner/example\nprimary_contact: security@libexample.dev\n"})
        facts = {}
        self.assertEqual(
            triage.oss_fuzz_row(gh, "owner/example", facts),
            (triage.OK, "in OSS-Fuzz as `example`"),
        )
        self.assertEqual(facts, {"oss_fuzz": True})

    def test_an_oss_fuzz_project_yaml_with_an_invalid_date_is_skipped(self):
        gh = FakeGitHub(
            responses={"repos/google/oss-fuzz/git/trees/HEAD:projects": {"tree": [
                {"path": "example-other", "type": "tree"},
                {"path": "example", "type": "tree"},
            ]}},
            texts={
                "repos/google/oss-fuzz/contents/projects/example-other/project.yaml": (
                    "main_repo: https://github.com/owner/example-other\nprimary_contact: 2026-02-31\n"
                ),
                "repos/google/oss-fuzz/contents/projects/example/project.yaml": (
                    "main_repo: https://github.com/owner/example\n"
                ),
            },
        )
        self.assertEqual(
            triage.oss_fuzz_row(gh, "owner/example"),
            (triage.OK, "in OSS-Fuzz as `example`"),
        )

    def test_proofs_index(self):
        self.assertEqual(triage.proofs_index_row(FakeGitHub(), "cjson")[0], triage.INFO)
        self.assertIn("no proofs index yet", triage.proofs_index_row(FakeGitHub(), "cjson")[1])
        index = "project\tlanguage\tstatus\tstatements\tproved\ncjson\tc\tavailable\t15\t0\nzlib\tc\tavailable\t9\t1\n"
        gh = FakeGitHub(texts={INDEX: index})
        self.assertEqual(
            triage.proofs_index_row(gh, "zlib"),
            (triage.INFO, "`zlib` is `available` in the proofs index: `1` of `9` statements proved"),
        )
        self.assertEqual(triage.proofs_index_row(gh, "nope"), (triage.INFO, "`nope` is not in the proofs index"))
        self.assertEqual(triage.proofs_index_row(FakeGitHub(texts={INDEX: "name\tstate\n"}), "x")[0], triage.WARN)
        hostile = "project\tstatus\nx\t`</sub>|evil\n"
        self.assertNotIn("`</sub>|", triage.proofs_index_row(FakeGitHub(texts={INDEX: hostile}), "x")[1])

    def test_files_in_the_repository(self):
        slug, ref = "a/b", "v1"
        here = triage.verifier_files_row(FakeGitHub(), slug, ref, {}, {"project.yaml", "Dockerfile", "build.sh"})
        self.assertEqual(here[0], triage.INFO)
        self.assertIn("the Dockerfile and build.sh are in this pull request", here[1])
        self.assertIn("no patch_style.md (optional)", here[1])
        alone = triage.verifier_files_row(FakeGitHub(), slug, ref, {}, {"project.yaml", "Dockerfile"})
        self.assertEqual(alone[0], triage.WARN)
        found = {
            f"repos/{slug}/contents/.oss-verify": [{"name": "Dockerfile"}, {"name": "build.sh"}],
            f"repos/{slug}/contents/.oss-verify/Dockerfile": {}, f"repos/{slug}/contents/.oss-verify/build.sh": {},
        }
        config = {"dockerfile": ".oss-verify/Dockerfile"}
        mark, text = triage.verifier_files_row(FakeGitHub(found), slug, ref, config, {"project.yaml"})
        self.assertEqual(mark, triage.OK)
        self.assertIn("with build.sh beside it", text)
        del found[f"repos/{slug}/contents/.oss-verify/build.sh"]
        self.assertEqual(triage.verifier_files_row(FakeGitHub(found), slug, ref, config, {"project.yaml"})[0], triage.WARN)
        self.assertEqual(triage.verifier_files_row(FakeGitHub(), slug, ref, config, {"project.yaml"})[0], triage.FAIL)
        seeded = triage.verifier_files_row(FakeGitHub(), slug, ref, {"primary_contact": "n/a"}, {"project.yaml"})
        self.assertEqual(seeded, (triage.INFO, "not present; no patch_style.md (optional); no build files yet (a seeded project)"))


class FetchProject(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.scratch.name) / "example"

    def tearDown(self):
        self.scratch.cleanup()

    def test_regular_files_are_downloaded(self):
        listing, entries, raw = listing_for({
            "project.yaml": SEEDED.encode(), "Dockerfile": b"FROM x\n", "build.sh": b"#!/bin/bash\n",
            "driver.c": b"int x;\n", "notes.txt": b"never downloaded",
        })
        gh = FakeGitHub({listing: entries}, files=raw)
        self.assertTrue(triage.fetch_project(gh, REPO, "0" * 40, "example", self.directory))
        self.assertEqual((self.directory / "build.sh").read_bytes(), b"#!/bin/bash\n")
        self.assertEqual((self.directory / "notes.txt").read_bytes(), b"")
        self.assertNotIn(f"{listing}/notes.txt", gh.fetched)
        problems, _, _ = validate.check_project(self.directory)
        self.assertEqual(len(problems), 1)
        self.assertIn("notes.txt: only project.yaml", problems[0])

    def test_the_files_that_sources_copies_are_downloaded(self):
        sources = b"copy\tsrc/CMakeLists.txt\tdep.CMakeLists.txt\n"
        listing, entries, raw = listing_for({
            "project.yaml": SEEDED.encode(), "Dockerfile": b"FROM x\n", "build.sh": b"#!/bin/bash\n" + bytes(70000),
            "sources": sources, "dep.CMakeLists.txt": b"project(dep)\n",
        })
        gh = FakeGitHub({listing: entries}, files=raw)
        triage.fetch_project(gh, REPO, "0" * 40, "example", self.directory)
        self.assertEqual(gh.fetched.count(f"{listing}/sources"), 1)
        self.assertEqual((self.directory / "sources").read_bytes(), sources)
        self.assertEqual((self.directory / "dep.CMakeLists.txt").read_bytes(), b"project(dep)\n")
        self.assertEqual(len((self.directory / "build.sh").read_bytes()), 70012)
        self.assertEqual(validate.check_project(self.directory)[0], [])

    def test_links_directories_and_oversize_files_are_refused(self):
        listing, entries, raw = listing_for(
            {"project.yaml": SEEDED.encode(), "Dockerfile": b"FROM x\n"},
            extra=[entry("build.sh", "symlink"), entry("big.c", size=validate.MAX_SOURCE_BYTES + 1)],
        )
        gh = FakeGitHub({listing: entries}, files=raw)
        triage.fetch_project(gh, REPO, "0" * 40, "example", self.directory)
        self.assertTrue((self.directory / "build.sh").is_symlink())
        self.assertNotIn(f"{listing}/big.c", gh.fetched)
        problems, _, _ = validate.check_project(self.directory)
        self.assertTrue(any("only regular files" in problem for problem in problems), problems)
        (self.directory / "build.sh").unlink()
        problems, _, _ = validate.check_project(self.directory)
        self.assertTrue(any("big.c is larger than 256 KiB" in problem for problem in problems), problems)

    def test_a_directory_entry_is_refused(self):
        listing, entries, raw = listing_for({"project.yaml": SEEDED.encode()}, extra=[entry("sub", "dir")])
        triage.fetch_project(FakeGitHub({listing: entries}, files=raw), REPO, "0" * 40, "example", self.directory)
        problems, _, _ = validate.check_project(self.directory)
        self.assertTrue(any("only regular files" in problem for problem in problems), problems)

    def test_too_many_files_are_only_named(self):
        files = {"project.yaml": SEEDED.encode(), **{f"f{i}.c": b"int x;\n" for i in range(validate.MAX_FILES + 1)}}
        listing, entries, raw = listing_for(files)
        gh = FakeGitHub({listing: entries}, files=raw)
        triage.fetch_project(gh, REPO, "0" * 40, "example", self.directory)
        self.assertEqual(gh.fetched, [f"{listing}/project.yaml"])
        problems, _, _ = validate.check_project(self.directory)
        self.assertTrue(any("at most 64 files" in problem for problem in problems), problems)

    def test_a_removed_directory_is_a_withdrawal(self):
        self.assertFalse(triage.fetch_project(FakeGitHub(), REPO, "0" * 40, "example", self.directory))


# A project.yaml whose repository is on github.com, so that every row of the full table is there.
ON_GITHUB = "repo: https://github.com/someone/libexample\nprimary_contact: n/a\nlanguage: c\n"
META = {"full_name": "someone/libexample", "html_url": "https://github.com/someone/libexample",
        "created_at": "2020-01-01T00:00:00Z", "pushed_at": "2020-01-02T00:00:00Z", "archived": False, "fork": False,
        "stargazers_count": 5, "forks_count": 1, "subscribers_count": 1, "license": {"spdx_id": "MIT"},
        "owner": {"login": "someone"}}
EVERY_ROW = ["Repository", "Stars / forks", "Fork", "Outside participants", "Criticality score", "License",
             "Opened by an active maintainer", "OSS-Fuzz", "`.oss-verify/` in the repository", "Seeded contact",
             "Proofs index", "Pull request scope", "`oss-verify validate`", "Checklist"]


def checks(text):
    """The names of the table's rows, in order."""
    return [line.split(" | ")[1] for line in text.splitlines() if line.startswith("| ") and " | Check | " not in line]


# OSS-Fuzz's list of projects, and signals of the criticality score: FakeGitHub cannot answer the requests that
# collect the signals.
OSS_FUZZ_TREE = "repos/google/oss-fuzz/git/trees/HEAD:projects"
LISTED = "main_repo: https://github.com/someone/libexample.git\n"
SIGNALS = {"created_since": 72, "updated_since": 1, "contributor_count": 40, "org_count": 3, "commit_frequency": 2.5,
           "recent_releases_count": 4, "closed_issues_count": 30, "updated_issues_count": 50, "comment_frequency": 2.1,
           "dependents_count": 120}


def oss_fuzz_project(name):
    return f"repos/google/oss-fuzz/contents/projects/{name}/project.yaml"


def in_oss_fuzz(gh, projects):
    """The fake GitHub, with OSS-Fuzz's projects: each name with the text of its project.yaml."""
    gh.responses[OSS_FUZZ_TREE] = {"tree": [{"path": name, "type": "tree"} for name in projects]}
    gh.texts.update({oss_fuzz_project(name): text for name, text in projects.items()})
    return gh


class Comment(unittest.TestCase):
    @staticmethod
    def pull(yaml_text, association, files=None, changed=None, body=""):
        files = files if files is not None else {"Dockerfile": b"FROM x\n", "build.sh": b"#!/bin/bash\n"}
        listing, entries, raw = listing_for({"project.yaml": yaml_text.encode(), **files})
        changed = changed or [f"projects/example/{name}" for name in ["project.yaml", *files]]
        responses = {
            f"repos/{REPO}/pulls/7": {"user": {"login": "someone"}, "head": {"sha": "1" * 40},
                                     "changed_files": len(changed), "body": body, "author_association": association},
            f"repos/{REPO}/pulls/7/files": [{"filename": path} for path in changed],
            listing: entries,
            "repos/someone/libexample": META,
        }
        return FakeGitHub(responses, files=raw)

    def test_the_comment_has_the_public_rows_and_the_full_table_every_row(self):
        result = triage.triage(self.pull(ON_GITHUB, "NONE"), REPO, 7)
        self.assertEqual(checks(result.comment), list(triage.PUBLIC_ROWS))
        self.assertEqual(checks(result.full), EVERY_ROW)
        self.assertTrue(result.comment.startswith(triage.MARKER + "\n### Enrollment triage: `projects/example`\n\n"))
        self.assertIn("Repository: [someone/libexample](https://github.com/someone/libexample) · opened by `someone`",
                      result.comment)
        self.assertTrue(result.comment.endswith("\n\n<sub>Automated, from public data. It decides nothing.</sub>\n"))
        self.assertIn("| ✅ | License | `MIT` |", result.comment)
        # The full table is never taken for the comment: the workflow finds the comment to update by the marker.
        self.assertNotIn(triage.MARKER, result.full)
        self.assertIn("Repository: [someone/libexample]", result.full)
        self.assertIn("| ℹ️ | Stars / forks | 5 stars · 1 forks · 1 watching |", result.full)
        self.assertIn("| ✅ | Fork | not a fork |", result.comment)

    def test_a_fork_is_in_the_public_comment(self):
        """CONTRIBUTING.md says that we usually do not accept a fork, so the maintainer reads this row too."""
        forked = {**META, "fork": True, "parent": {"full_name": "upstream/libexample"}}
        with mock.patch.dict(META, forked, clear=True):
            result = triage.triage(self.pull(ON_GITHUB, "NONE"), REPO, 7)
        self.assertIn("| ⚠️ | Fork | a fork of [upstream/libexample](https://github.com/upstream/libexample). "
                      "We usually do not accept a fork ([CONTRIBUTING.md](https://github.com/theorem-labs/oss-verify"
                      "/blob/main/CONTRIBUTING.md#review-of-an-enrollment)). A person at Theorem decides |",
                      result.comment)

    def test_a_fork_whose_parent_the_answer_does_not_give(self):
        """GitHub leaves out parent for a fork whose upstream repository is gone or private."""
        with mock.patch.dict(META, {**META, "fork": True}, clear=True):
            result = triage.triage(self.pull(ON_GITHUB, "NONE"), REPO, 7)
        self.assertIn("| ⚠️ | Fork | a fork of another repository. We usually do not accept a fork",
                      result.comment)

    def test_a_seeded_project_from_outside(self):
        result = triage.triage(self.pull(SEEDED, "NONE"), REPO, 7)
        self.assertTrue(result.comment.startswith(triage.MARKER + "\n"))
        self.assertEqual(checks(result.comment), ["Pull request scope", "`oss-verify validate`", "Checklist"])
        self.assertIn("| ✅ | Pull request scope |", result.comment)
        self.assertIn("| ⚠️ | `oss-verify validate` | passes, with warnings", result.comment)
        self.assertNotIn("Seeded contact", result.comment)
        self.assertIn("| ⚠️ | Seeded contact |", result.full)
        self.assertIn("| ℹ️ | Proofs index | no proofs index yet", result.full)
        self.assertIn("| ✅ | Pull request scope |", result.full)
        self.assertIn("| ⚠️ | `oss-verify validate` | passes, with warnings", result.full)
        self.assertIn("not a github.com repository", result.full)
        self.assertIn(f"https://github.com/{REPO}#enroll-a-project", result.full)

    def test_the_full_table_links_a_readme_heading(self):
        full = triage.triage(self.pull(SEEDED, "NONE"), REPO, 7).full
        anchor = re.search(rf"https://github\.com/{re.escape(REPO)}#([a-z0-9-]+)", full)[1]
        headings, fenced = [], False
        for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
            if line.startswith("```"):
                fenced = not fenced
            elif not fenced and line.startswith("## "):
                headings.append(line[3:].strip().lower().replace(" ", "-"))
        self.assertIn(anchor, headings)

    def test_an_enrolled_project(self):
        result = triage.triage(self.pull(ENROLLED, "NONE"), REPO, 7)
        self.assertNotIn("Seeded contact", result.full)
        self.assertIn("| ✅ | `oss-verify validate` | passes |", result.comment)
        result = triage.triage(self.pull(ENROLLED, "NONE", files={}), REPO, 7)
        self.assertIn("| ❌ | `oss-verify validate` | `a Dockerfile is required", result.comment)

    def test_a_seeded_project_from_a_maintainer(self):
        self.assertIn("| ℹ️ | Seeded contact |", triage.triage(self.pull(SEEDED, "MEMBER"), REPO, 7).full)

    def test_nothing_under_projects(self):
        gh = self.pull(SEEDED, "NONE", changed=["README.md"])
        self.assertEqual(triage.triage(gh, REPO, 7), ("", "", None, None))

    def test_a_withdrawal(self):
        gh = self.pull(SEEDED, "NONE")
        del gh.responses[f"repos/{REPO}/contents/projects/example"]
        result = triage.triage(gh, REPO, 7)
        self.assertTrue(result.comment.startswith(triage.MARKER + "\n"))
        self.assertIn("a withdrawal, nothing to triage", result.comment)
        self.assertIn("a withdrawal, nothing to triage", result.full)
        self.assertNotIn(triage.MARKER, result.full)

    def test_a_seeded_project_from_a_fork_and_from_a_branch(self):
        # enrollment refuses a fork's change to a seeded project and takes a branch's (.github/scripts/take-project).
        with mock.patch.object(triage, "seeded_names", return_value={"example"}):
            fork = triage.triage(self.pull(ENROLLED, "NONE"), REPO, 7).comment
            branch = self.pull(ENROLLED, "NONE")
            branch.responses[f"repos/{REPO}/pulls/7"]["head"]["repo"] = {"full_name": REPO}
            branch = triage.triage(branch, REPO, 7).comment
        self.assertIn("| ⚠️ | Pull request scope | `projects/example/` is the port of a project that we seeded", fork)
        self.assertIn("| ✅ | Pull request scope | only this project's directory |", branch)
        # Without the table's mark, a fork's pull request is in scope.
        self.assertIn("| ✅ | Pull request scope | only this project's directory |",
                      triage.triage(self.pull(ENROLLED, "NONE"), REPO, 7).comment)

    def test_a_fork_that_removes_a_seeded_project(self):
        refused = "`enrollment` refuses a pull request from a fork that removes the port of a project that we seeded"
        with mock.patch.object(triage, "seeded_names", return_value={"example"}):
            fork = self.pull(SEEDED, "NONE")
            del fork.responses[f"repos/{REPO}/contents/projects/example"]
            branch = self.pull(SEEDED, "NONE")
            del branch.responses[f"repos/{REPO}/contents/projects/example"]
            branch.responses[f"repos/{REPO}/pulls/7"]["head"]["repo"] = {"full_name": REPO}
            self.assertIn(refused, triage.triage(fork, REPO, 7).comment)
            self.assertNotIn(refused, triage.triage(branch, REPO, 7).comment)

    def test_a_pull_request_that_removes_two_projects_is_a_withdrawal_of_the_first(self):
        gh = self.pull(SEEDED, "NONE")
        del gh.responses[f"repos/{REPO}/contents/projects/example"]
        gh.responses[f"repos/{REPO}/pulls/7/files"] = [
            {"filename": f"projects/{project}/project.yaml"} for project in ["example", "aaa"]]
        result = triage.triage(gh, REPO, 7)
        self.assertTrue(result.comment.startswith(triage.MARKER + "\n### Enrollment triage: `projects/aaa`\n\n"))
        self.assertIn("a withdrawal, nothing to triage", result.comment)

    def test_a_removed_project_beside_an_edited_one_triages_the_edited_one(self):
        gh = self.pull(SEEDED, "NONE")
        gh.responses[f"repos/{REPO}/pulls/7/files"] = [
            {"filename": f"projects/{project}/project.yaml"} for project in ["aaa", "example"]]
        result = triage.triage(gh, REPO, 7)
        self.assertNotIn("withdrawal", result.full)
        self.assertTrue(result.comment.startswith(triage.MARKER + "\n### Enrollment triage: `projects/example`\n\n"))

    def test_a_renamed_project_is_triaged_under_its_new_name(self):
        """GitHub lists a renamed file under both names. The old directory is gone, but nothing is withdrawn."""
        gh = self.pull(SEEDED, "NONE")
        gh.responses[f"repos/{REPO}/pulls/7/files"] = [
            {"filename": f"projects/example/{name}", "previous_filename": f"projects/aaa/{name}"}
            for name in ["project.yaml", "Dockerfile", "build.sh"]]
        result = triage.triage(gh, REPO, 7)
        self.assertNotIn("withdrawal", result.full)
        self.assertTrue(result.comment.startswith(triage.MARKER + "\n### Enrollment triage: `projects/example`\n\n"))
        self.assertIn("| ❌ | Pull request scope | touches 2 projects (`aaa`, `example`); one per pull request |",
                      result.comment)

    def test_a_local_directory_before_the_pull_request(self):
        # No pull request exists yet: nothing about one is asked of GitHub, and the directory is read as it is here.
        with tempfile.TemporaryDirectory() as scratch:
            directory = pathlib.Path(scratch) / "example"
            directory.mkdir()
            for name, text in {"project.yaml": ENROLLED, "Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}.items():
                (directory / name).write_text(text)
            template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
            gh = FakeGitHub()
            comment = triage.triage_local(gh, REPO, directory, "someone", template).comment
            # The pull request it is written for comes from a fork, so a seeded project's row warns.
            with mock.patch.object(triage, "seeded_names", return_value={"example"}):
                seeded = triage.triage_local(FakeGitHub(), REPO, directory, "someone", template).comment
        self.assertTrue(comment.startswith(triage.MARKER + "\n"))
        self.assertIn("opened by `someone`", comment)
        self.assertIn("| ✅ | Pull request scope | only this project's directory |", comment)
        self.assertIn("| ✅ | `oss-verify validate` | passes |", comment)
        self.assertIn("| ⚠️ | Checklist | ", comment)
        self.assertFalse([path for path in gh.fetched if "/pulls/" in path], gh.fetched)
        self.assertIn("| ⚠️ | Pull request scope | `projects/example/` is the port of a project that we seeded", seeded)


class CommandLine(unittest.TestCase):
    """main(): the comment on standard output; --summary appends the full table to a file in the same run; --full
    prints the full table instead; --facts writes the criticality score and OSS-Fuzz to a file in the same run."""

    def run_main(self, *arguments, gh=None):
        gh = gh or Comment.pull(ON_GITHUB, "NONE")
        stdout = io.StringIO()
        argv = ["triage.py", "--repo", REPO, "--pr", "7", *arguments]
        with mock.patch.object(triage, "GitHub", lambda token: gh), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(stdout):
            self.assertEqual(triage.main(), 0)
        return stdout.getvalue(), gh

    def test_the_comment_by_default_and_the_full_table_in_the_summary(self):
        with tempfile.TemporaryDirectory() as scratch:
            summary = pathlib.Path(scratch) / "summary"
            summary.write_text("before\n")
            printed, gh = self.run_main("--summary", str(summary))
            written = summary.read_text()
        self.assertEqual(checks(printed), list(triage.PUBLIC_ROWS))
        self.assertTrue(written.startswith("before\n### Enrollment triage:"), written)
        self.assertEqual(checks(written), EVERY_ROW)
        # One run: the pull request is read once for both.
        self.assertEqual(gh.fetched.count(f"repos/{REPO}/contents/projects/example/project.yaml"), 1)

    def test_full_prints_every_row(self):
        printed, _ = self.run_main("--full")
        self.assertEqual(checks(printed), EVERY_ROW)
        self.assertNotIn(triage.MARKER, printed)

    def test_no_summary_for_a_pull_request_outside_projects(self):
        with tempfile.TemporaryDirectory() as scratch:
            summary = pathlib.Path(scratch) / "summary"
            gh = Comment.pull(SEEDED, "NONE", changed=["README.md"])
            printed, _ = self.run_main("--summary", str(summary), gh=gh)
            self.assertFalse(summary.exists())
        self.assertEqual(printed, "")

    def test_facts_beside_the_full_table(self):
        gh = in_oss_fuzz(Comment.pull(ON_GITHUB, "NONE"), {"libexample": LISTED, "example": "main_repo: x\n"})
        with tempfile.TemporaryDirectory() as scratch, \
                mock.patch.object(triage, "criticality_signals", return_value=SIGNALS) as collect:
            facts = pathlib.Path(scratch) / "facts.json"
            printed, gh = self.run_main("--full", "--facts", str(facts), gh=gh)
            written = json.loads(facts.read_text())
        self.assertEqual(checks(printed), EVERY_ROW)
        self.assertEqual(written, {"criticality_score": triage.criticality_score(SIGNALS), "oss_fuzz": True})
        # One run: the table and the file come from the same requests, and each is made once.
        collect.assert_called_once()
        self.assertEqual(gh.fetched.count(f"repos/{REPO}/contents/projects/example/project.yaml"), 1)
        self.assertEqual([gh.fetched.count(oss_fuzz_project(name)) for name in ("libexample", "example")], [1, 1])

    def test_facts_change_neither_the_output_nor_the_summary(self):
        outputs = []
        for facts in (False, True):
            gh = in_oss_fuzz(Comment.pull(ON_GITHUB, "NONE"), {"libexample": LISTED})
            with tempfile.TemporaryDirectory() as scratch, \
                    mock.patch.object(triage, "criticality_signals", return_value=SIGNALS):
                summary, path = pathlib.Path(scratch) / "summary", pathlib.Path(scratch) / "facts.json"
                printed, _ = self.run_main("--summary", str(summary), *(["--facts", str(path)] if facts else []), gh=gh)
                outputs.append((printed, summary.read_text()))
                self.assertEqual(path.exists(), facts)
        self.assertEqual(outputs[1], outputs[0])
        self.assertEqual(checks(outputs[1][0]), list(triage.PUBLIC_ROWS))
        self.assertEqual(checks(outputs[1][1]), EVERY_ROW)


class Facts(unittest.TestCase):
    """--facts: the values that the rows Criticality score and OSS-Fuzz show, as one JSON object in a file."""

    NOT_KNOWN = {"criticality_score": None, "oss_fuzz": None}
    run_main = CommandLine.run_main

    def facts(self, gh, **collect):
        """Run main() with --full --facts, and return what it printed and the JSON object in the file. `collect` says
        how the stand-in for criticality_signals() answers: with SIGNALS when it is not given."""
        with tempfile.TemporaryDirectory() as scratch, \
                mock.patch.object(triage, "criticality_signals", **(collect or {"return_value": SIGNALS})):
            path = pathlib.Path(scratch) / "facts.json"
            path.write_text("before\n")  # replaced, not appended to
            printed, _ = self.run_main("--full", "--facts", str(path), gh=gh)
            written = path.read_text()
        # One JSON object and a line end, with the two keys and no other.
        self.assertTrue(written.startswith("{") and written.endswith("}\n"), written)
        self.assertEqual(written.count("\n"), 1, written)
        facts = json.loads(written)
        self.assertEqual(sorted(facts), ["criticality_score", "oss_fuzz"])
        return printed, facts

    def test_a_fork_listed_in_oss_fuzz(self):
        gh = in_oss_fuzz(Comment.pull(ON_GITHUB, "NONE"), {"libexample": LISTED})
        forked = {**META, "fork": True, "parent": {"full_name": "upstream/libexample"}}
        gh.responses["repos/someone/libexample"] = forked
        printed, facts = self.facts(gh)
        self.assertEqual(facts, {"criticality_score": None, "oss_fuzz": True})
        self.assertIn("| ⚠️ | Criticality score | not scored: a fork of `upstream/libexample`", printed)

    def test_the_score_that_the_row_shows(self):
        printed, facts = self.facts(in_oss_fuzz(Comment.pull(ON_GITHUB, "NONE"), {}))
        score = triage.criticality_score(SIGNALS)
        self.assertNotEqual(score, round(score, 2))  # the file has more places than the row shows
        self.assertEqual(facts["criticality_score"], score)
        self.assertIn(f"| Criticality score | **{score:.2f}** on the [OpenSSF]", printed)
        self.assertIs(facts["oss_fuzz"], False)

    def test_a_namesake_for_another_repository(self):
        gh = in_oss_fuzz(Comment.pull(ON_GITHUB, "NONE"),
                         {"libexample": "main_repo: https://github.com/other/libexample\n"})
        printed, facts = self.facts(gh)
        self.assertIs(facts["oss_fuzz"], False)
        self.assertIn("| ℹ️ | OSS-Fuzz | no OSS-Fuzz project is for this repository, but `libexample` there is for "
                      "`https://github.com/other/libexample` |", printed)

    def test_a_project_listed_in_oss_fuzz(self):
        printed, facts = self.facts(in_oss_fuzz(Comment.pull(ON_GITHUB, "NONE"), {"libexample": LISTED}))
        self.assertIs(facts["oss_fuzz"], True)
        self.assertIn("| ✅ | OSS-Fuzz | in OSS-Fuzz as `libexample` |", printed)

    def test_rows_that_could_not_be_checked(self):
        # FakeGitHub has no OSS-Fuzz list here: it answers 404.
        printed, facts = self.facts(Comment.pull(ON_GITHUB, "NONE"),
                                    side_effect=triage.ApiError("fake", 404, "graphql"))
        self.assertEqual(facts, self.NOT_KNOWN)
        self.assertIn("| ⚠️ | Criticality score | could not be checked: ", printed)
        self.assertIn("| ⚠️ | OSS-Fuzz | could not be checked: ", printed)

    def test_a_repository_not_on_github(self):
        printed, facts = self.facts(Comment.pull(SEEDED, "NONE"))
        self.assertEqual(facts, self.NOT_KNOWN)
        self.assertIn("not a github.com repository", printed)

    def test_nothing_under_projects(self):
        printed, facts = self.facts(Comment.pull(SEEDED, "NONE", changed=["README.md"]))
        self.assertEqual(facts, self.NOT_KNOWN)
        self.assertEqual(printed, "")

    def test_a_withdrawal(self):
        gh = Comment.pull(SEEDED, "NONE")
        del gh.responses[f"repos/{REPO}/contents/projects/example"]
        printed, facts = self.facts(gh)
        self.assertEqual(facts, self.NOT_KNOWN)
        self.assertIn("a withdrawal, nothing to triage", printed)

    def test_a_local_directory(self):
        # --local goes through the same rows as --pr.
        with tempfile.TemporaryDirectory() as scratch, \
                mock.patch.object(triage, "criticality_signals", return_value=SIGNALS):
            directory = pathlib.Path(scratch) / "example"
            directory.mkdir()
            (directory / "project.yaml").write_text(ON_GITHUB)
            gh = in_oss_fuzz(FakeGitHub({"repos/someone/libexample": META}), {"libexample": LISTED})
            result = triage.triage_local(gh, REPO, directory, "someone", "")
        self.assertEqual((result.criticality_score, result.oss_fuzz), (triage.criticality_score(SIGNALS), True))


class Callers(unittest.TestCase):
    def test_the_workflow_puts_the_full_table_in_the_job_summary_and_the_comment_in_the_output(self):
        # review.yml's triage-gather step, run with stand-ins for dpkg and python3: the stand-in python3 prints a
        # comment and writes a table to the file after --summary, as triage.py does.
        jobs = validate.yaml.safe_load((ROOT / ".github" / "workflows" / "review.yml").read_text())["jobs"]
        [script] = [s["run"] for s in jobs["triage-gather"]["steps"] if s.get("name") == "Write the comment"]
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            bin = scratch / "bin"
            bin.mkdir()
            (bin / "dpkg").write_text("#!/bin/sh\nexit 0\n")
            (bin / "python3").write_text(
                '#!/bin/bash\nprintf "%s\\n" "$@" > "$ARGV"\n'
                'while [ $# -gt 0 ]; do [ "$1" = --summary ] && echo FULL >> "$2"; shift; done\necho COMMENT\n')
            for name in ("dpkg", "python3"):
                (bin / name).chmod(0o755)
            env = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "ARGV": str(scratch / "argv"),
                   "GITHUB_OUTPUT": str(scratch / "output"), "GITHUB_STEP_SUMMARY": str(scratch / "summary"),
                   "REPO": REPO, "PR": "7"}
            run = subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv = (scratch / "argv").read_text().split("\n")
            self.assertEqual(argv[:6], [".github/scripts/triage.py", "--repo", REPO, "--pr", "7", "--summary"])
            self.assertEqual(argv[6], str(scratch / "summary"))
            self.assertEqual((scratch / "summary").read_text(), "FULL\n")
            output = (scratch / "output").read_text().split("\n")
        self.assertTrue(output[0].startswith("comment<<triage-"), output)
        self.assertEqual(output[1:3], ["COMMENT", output[0].removeprefix("comment<<")])


if __name__ == "__main__":
    unittest.main()
