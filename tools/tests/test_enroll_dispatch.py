# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/enroll-dispatch and the jobs around it, offline, with a fake GitHub API:
python3 -m pytest tools/tests/test_enroll_dispatch.py"""
import calendar
import copy
import functools
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
import zipfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
# The workflow tests' expression evaluator and step runner with a stand-in gh: GitHub's expressions, evaluated as
# test_outside_screen.py evaluates them (the dispatch job's if and env, and its steps' if and env).
sys.path.insert(0, str(ROOT / "tools" / "tests"))
from test_outside_screen import WF, Runner, as_text, evaluate  # noqa: E402

LOADER = importlib.machinery.SourceFileLoader("enroll_dispatch", str(ROOT / ".github" / "scripts" / "enroll-dispatch"))
SPEC = importlib.util.spec_from_loader("enroll_dispatch", LOADER)
dispatch = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(dispatch)
ENROLL_DISPATCH = yaml.safe_load((ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text())
# The maintainer check reads the network; every test but those of the class Maintainer sees it pass, and Maintainer
# tests the real one with a stand-in API.
REAL_STANDING = dispatch.standing
STANDING_CALLS = []
dispatch.standing = lambda config, login: STANDING_CALLS.append((config, login)) or ""

REPO = "theorem-labs/oss-verify"
SHA = "7e8e28d95389c7261efeb48e4114cd1186bf8e7e"
NEWER = "1" * 40
MAIN = "8" * 40
PR = 32
ACTIONS = 15368
OSS_VERIFY = 5447700  # the oss-verify App, gh api apps/oss-verify
REQUIRED = ["enrollment", "project-builds", "terms-accepted", "tests"]
# The run of each required check: its id, and the workflow file and event that make it.
RUNS = {"project-builds": (101, ".github/workflows/build.yaml", "pull_request_target"),
        "enrollment": (102, ".github/workflows/validate.yaml", "pull_request_target"),
        "terms-accepted": (103, ".github/workflows/terms.yaml", "pull_request_target"),
        "tests": (104, ".github/workflows/tests.yaml", "pull_request")}
HAND_RUN = 900
MERGED_RUN = 800


def zipped(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def sizes(plain_text=61_316, plain_exec=70_000):
    return {"fuzz_command": {"plain": {"text": plain_text, "exec": plain_exec},
                             "asan": {"text": 454_828, "exec": 2_500_000}},
            "fuzz_config": {"plain": {"text": 58_316, "exec": 66_000}, "asan": {"text": 9, "exec": 9}}}


def record(**change):
    out = {"schema": dispatch.RECORD_SCHEMA, "pr": PR, "project": "plugin-hostd", "sha": SHA, "sizes": sizes()}
    out.update(change)
    return out


def decision_reason(got):
    """decide's reason without the clause that review_passed adds about review-passed."""
    return got["reason"].split(f"; {dispatch.REVIEW_PASSED} ", 1)[0]


class FakeApi:
    """GitHub's API from a table: a path's answer, or a list of answers given one per call (the last one repeats)."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def answer(self, path):
        self.calls.append(path)
        value = self.table[path]
        if isinstance(value, Calls):
            return value.next()
        return copy.deepcopy(value)

    get = pages = raw = answer


class Calls:
    def __init__(self, *answers):
        self.answers = list(answers)

    def next(self):
        return copy.deepcopy(self.answers.pop(0) if len(self.answers) > 1 else self.answers[0])


class World:
    """One enrollment pull request whose four required checks passed at its head commit (SHA unless one is given),
    Build run 101's record of it, and the oss-verify App's check run Enrollment review at that commit, success."""

    def __init__(self, sha=SHA):
        self.sha = sha
        self.checks = []  # check runs at the commit
        self.runs = {}
        self.artifacts = {}
        for i, name in enumerate(REQUIRED):
            run_id, path, event = RUNS[name]
            self.check(500 + i, name, run_id)
            self.run(run_id, path, event, head_sha=sha)
        self.artifacts[101] = record(sha=sha)
        self.review_runs = []  # check runs Enrollment review at the commit
        self.review(400)
        self.files = [{"filename": "projects/plugin-hostd/project.yaml", "status": "added"},
                      {"filename": "projects/plugin-hostd/build.sh", "status": "added"}]
        self.pulls = [self.pull(sha=sha)]
        self.project_yaml = b"repo: https://example.invalid/x\nlanguage: c\n"
        self.required = list(REQUIRED)

    def check(self, check_id, name, run_id, conclusion="success", app=ACTIONS, repo=REPO):
        self.checks.append({"id": check_id, "name": name, "app": {"id": app}, "status": "completed",
                            "conclusion": conclusion,
                            "details_url": f"https://github.com/{repo}/actions/runs/{run_id}/job/{check_id + 9000}"})

    def review(self, check_id, conclusion="success", app=OSS_VERIFY, status="completed", pr=PR):
        """A check run Enrollment review at the commit, as build.yaml's comment job writes it for pull request `pr`,
        whose number is its external_id (another App's, with `app`)."""
        self.review_runs.append({"id": check_id, "name": "Enrollment review", "app": {"id": app}, "status": status,
                                 "conclusion": conclusion, "head_sha": self.sha, "external_id": str(pr)})

    def run(self, run_id, path, event, head_sha=SHA, branch="add-plugin-hostd", head_repo="FreeREAC/oss-verify"):
        self.runs[run_id] = {"id": run_id, "path": path, "event": event, "head_sha": head_sha, "head_branch": branch,
                             "head_repository": {"full_name": head_repo}}

    @staticmethod
    def pull(number=PR, sha=SHA, state="open", base="main", head_repo="FreeREAC/oss-verify",
             branch="add-plugin-hostd", draft=False):
        return {"number": number, "state": state, "draft": draft,
                "head": {"sha": sha, "ref": branch, "repo": {"full_name": head_repo}, "label": f"x:{branch}"},
                "base": {"ref": base, "repo": {"full_name": REPO}}}

    def api(self):
        table = {
            f"repos/{REPO}/rules/branches/main": [
                {"type": "pull_request"},
                {"type": "required_status_checks", "parameters": {"required_status_checks": [
                    {"context": name, "integration_id": ACTIONS} for name in self.required]}}],
            f"repos/{REPO}/commits/{self.sha}/check-runs?filter=all&per_page=100": [{"check_runs": self.checks}],
            # As GitHub answers: every check run with filter=all, and only the newest with its default, latest.
            f"repos/{REPO}/commits/{self.sha}/check-runs?check_name=Enrollment%20review&filter=all&per_page=100":
                [{"check_runs": self.review_runs}],
            f"repos/{REPO}/commits/{self.sha}/check-runs?check_name=Enrollment%20review&per_page=100":
                [{"check_runs": sorted(self.review_runs, key=lambda c: c["id"])[-1:]}],
            f"repos/{REPO}/pulls/{PR}": Calls(*self.pulls),
            f"repos/{REPO}/pulls/{PR}/files?per_page=100": [self.files],
            f"repos/{REPO}/contents/projects/plugin-hostd/project.yaml?ref={self.sha}": self.project_yaml,
            # review-passed's reads: the pull request's events, and this repository's runs at the commit.
            f"repos/{REPO}/issues/{PR}/events?per_page=100": [[]],
            f"repos/{REPO}/actions/runs?head_sha={self.sha}&per_page=100": [{"workflow_runs": [
                run for run in self.runs.values() if run["head_sha"] == self.sha]}],
        }
        # The open pull request of each run's head, for a decision that names none: the last answer of the pull request.
        for run in self.runs.values():
            owner, branch = run["head_repository"]["full_name"].split("/")[0], run["head_branch"]
            table[f"repos/{REPO}/pulls?state=open&base=main&head={owner}:{branch}&per_page=100"] = [self.pulls[-1:]]
        # The author of each answer of the pull request has no write access (build.yaml's rule for trusted accounts).
        for pull in self.pulls:
            login = (pull.get("user") or {}).get("login")
            if login:
                table[f"repos/{REPO}/collaborators/{login}/permission"] = {"permission": "read"}
        for run_id, run in self.runs.items():
            table[f"repos/{REPO}/actions/runs/{run_id}"] = run
            rec = self.artifacts.get(run_id)
            arts = [] if rec is None else [{"id": run_id * 10, "name": dispatch.RECORD_ARTIFACT, "expired": False,
                                            "size_in_bytes": 300}]
            table[f"repos/{REPO}/actions/runs/{run_id}/artifacts?name={dispatch.RECORD_ARTIFACT}&per_page=100"] = \
                [{"artifacts": arts}]
            if rec is not None:
                table[f"repos/{REPO}/actions/artifacts/{run_id * 10}/zip"] = \
                    rec if isinstance(rec, bytes) else zipped({"record.json": json.dumps(rec)})
        return FakeApi(table)

    def decide(self, event="pull_request_target", run_id=104, sha=None):
        return dispatch.decide(self.api(), REPO, run_id, event, self.sha if sha is None else sha)


class Sends(unittest.TestCase):
    def test_an_enrollment_whose_four_checks_passed_is_sent(self):
        got = World().decide()
        self.assertEqual((got["decision"], got["pr"], got["project"], got["sha"]),
                         ("dispatch", "32", "plugin-hostd", SHA), got["reason"])

    def test_a_change_to_a_project_already_enrolled_is_sent_too(self):
        world = World()
        world.files = [{"filename": "projects/plugin-hostd/build.sh", "status": "modified"}]
        self.assertEqual(world.decide()["decision"], "dispatch")

    def test_only_a_pull_requests_run_or_builds_run_by_hand_is_considered(self):
        for event in ("push", "schedule", "workflow_run"):
            self.assertEqual(World().decide(event=event)["decision"], "none", event)


class ForgedChecks(unittest.TestCase):
    """A check run counts only from its bound workflow file and event, in a run of this repository at this commit."""

    def fails_project_builds(self, world):
        world.checks[1]["conclusion"] = "failure"   # the real project-builds failed
        return world

    def assertNotSent(self, world, why):
        got = world.decide()
        self.assertEqual(got["decision"], "none", got["reason"])
        self.assertIn(why, got["reason"])

    def test_a_forks_own_build_yaml_on_pull_request_is_not_project_builds(self):
        world = self.fails_project_builds(World())
        world.run(201, ".github/workflows/build.yaml", "pull_request")
        world.check(600, "project-builds", 201)
        world.artifacts[201] = record(sizes=sizes(1, 1))
        self.assertNotSent(world, "project-builds (failure)")

    def test_a_job_named_project_builds_in_another_workflow_is_not_counted(self):
        world = self.fails_project_builds(World())
        world.run(202, ".github/workflows/tests.yaml", "pull_request")
        world.check(601, "project-builds", 202)
        world.artifacts[202] = record()
        self.assertNotSent(world, "project-builds (failure)")

    def test_a_check_of_a_run_of_another_commit_is_not_counted(self):
        world = World()
        world.runs[101]["head_sha"] = NEWER
        self.assertNotSent(world, "project-builds (not run by .github/workflows/build.yaml on pull_request_target)")

    def test_a_check_whose_run_is_in_another_repository_is_not_counted(self):
        world = self.fails_project_builds(World())
        world.check(602, "project-builds", 101, repo="someone/oss-verify")
        self.assertNotSent(world, "project-builds (failure)")

    def test_a_check_of_another_app_is_not_counted(self):
        world = self.fails_project_builds(World())
        world.check(603, "project-builds", 101, app=1)
        self.assertNotSent(world, "project-builds (failure)")

    def test_a_check_from_a_run_started_by_hand_is_not_a_required_check(self):
        world = World()
        world.checks = [c for c in world.checks if c["name"] != "enrollment"]
        world.run(203, ".github/workflows/validate.yaml", "workflow_dispatch", branch="main",
                  head_repo=REPO)
        world.check(604, "enrollment", 203)
        self.assertNotSent(world, "enrollment (not run by .github/workflows/validate.yaml on pull_request_target)")

    def test_the_record_of_a_forged_run_is_never_read(self):
        world = World()
        del world.artifacts[101]
        world.run(204, ".github/workflows/build.yaml", "pull_request")
        world.check(605, "project-builds", 204)
        world.artifacts[204] = record()
        got = world.decide()
        self.assertEqual(got["decision"], "none")
        self.assertIn("Build run 101 has 0", got["reason"])

    def test_a_required_check_with_no_known_source_is_never_passed(self):
        world = World()
        world.required.append("lint")
        world.run(205, ".github/workflows/lint.yaml", "pull_request_target")
        world.check(606, "lint", 205)
        self.assertNotSent(world, "lint (no known source)")

    def test_a_ruleset_that_requires_less_lowers_no_bar(self):
        world = World()
        world.required = []                          # the ruleset is off, or lists nothing
        world.checks = [c for c in world.checks if c["name"] != "tests"]
        self.assertNotSent(world, "tests (not run")

    def test_the_newest_bound_run_of_a_check_decides(self):
        # an older success, then a newer re-run that failed or is still running: not sent
        for conclusion, status in (("failure", "completed"), (None, "in_progress")):
            world = World()
            world.run(206, ".github/workflows/terms.yaml", "pull_request_target")
            world.check(607, "terms-accepted", 206, conclusion=conclusion)
            world.checks[-1]["status"] = status
            self.assertNotSent(world, "terms-accepted")
        # an older failure, then a newer success: sent
        world = World()
        world.checks[2]["conclusion"] = "failure"
        world.run(207, ".github/workflows/terms.yaml", "pull_request_target")
        world.check(608, "terms-accepted", 207)
        self.assertEqual(world.decide()["decision"], "dispatch")

    def test_a_required_check_not_run_or_not_passed_sends_nothing(self):
        for conclusion in ("failure", "cancelled", None):
            world = World()
            world.checks[2]["conclusion"] = conclusion
            if conclusion is None:
                world.checks[2]["status"] = "in_progress"
            self.assertNotSent(world, "terms-accepted")
        world = World()
        world.checks = [c for c in world.checks if c["name"] != "tests"]
        self.assertNotSent(world, "tests (not run")


class ThePullRequest(unittest.TestCase):
    def test_a_head_that_moved_while_the_files_were_listed_sends_nothing(self):
        # The fork pushes a clean commit after the head was matched: the files listed are not SHA's.
        world = World()
        world.pulls = [World.pull(), World.pull(sha=NEWER)]
        got = world.decide()
        self.assertEqual(got["decision"], "none")
        self.assertIn(f"its head is {NEWER}", got["reason"])

    def test_a_pull_request_not_open_into_main_at_the_commit_sends_nothing(self):
        for pull in (World.pull(state="closed"), World.pull(base="release"), World.pull(sha=NEWER)):
            world = World()
            world.pulls = [pull]
            self.assertEqual(world.decide()["decision"], "none", pull)

    def test_a_draft_pull_request_sends_nothing(self):
        # True, or a pull request whose draft flag the API did not give: neither is known to be ready.
        for draft in (True, None):
            world = World()
            world.pulls = [World.pull(draft=draft)]
            got = world.decide()
            self.assertEqual((got["decision"], got["label"]), ("none", ""), draft)
            self.assertIn("draft", got["reason"])

    def test_a_pull_request_made_a_draft_while_its_files_were_listed_sends_nothing(self):
        world = World()
        world.pulls = [World.pull(), World.pull(draft=True)]
        self.assertEqual(world.decide()["decision"], "none")

    def test_a_draft_marked_ready_is_sent_by_its_ready_for_review_build(self):
        world = World()
        world.pulls = [World.pull(draft=True)]
        self.assertEqual(world.decide()["decision"], "none")
        # Marked ready for review: build.yaml's run on ready_for_review completes at the same commit, and its record,
        # not the draft's Build run's (made oversized here, so that reading it would label), decides.
        world.pulls = [World.pull()]
        world.artifacts[101] = record(sizes=sizes(plain_text=2_000_000))
        world.run(105, ".github/workflows/build.yaml", "pull_request_target")
        world.check(700, "project-builds", 105)
        world.artifacts[105] = record()
        got = world.decide(run_id=105)
        self.assertEqual((got["decision"], got["pr"], got["sha"]), ("dispatch", "32", SHA), got["reason"])

    def test_a_draft_named_by_a_build_by_hand_sends_nothing(self):
        world = World()
        world.run(HAND_RUN, ".github/workflows/build.yaml", "workflow_dispatch", head_sha=MAIN, branch="main",
                  head_repo=REPO)
        world.artifacts[HAND_RUN] = record()
        world.pulls = [World.pull(draft=True)]
        self.assertEqual(world.decide(event="workflow_dispatch", run_id=HAND_RUN, sha=MAIN)["decision"], "none")

    def test_a_file_outside_the_records_project_sends_nothing(self):
        for files in ([{"filename": "projects/plugin-hostd/build.sh", "status": "added"},
                       {"filename": ".github/workflows/tests.yaml", "status": "modified"}],
                      [{"filename": "projects/plugin-hostd/build.sh", "status": "added"},
                       {"filename": "projects/libreac/build.sh", "status": "modified"}],
                      [{"filename": "projects/plugin-hostd/build.sh", "status": "renamed",
                        "previous_filename": ".github/workflows/build.yaml"}],
                      [{"filename": "projects/libreac/build.sh", "status": "added"}],
                      [{"filename": "projects/plugin-hostd/build.sh", "status": "removed"}]):
            world = World()
            world.files = files
            self.assertEqual(world.decide()["decision"], "none", files)

    def other_pull_request(self, world, conclusion):
        """Pull request 77, from someone else's fork, at the same commit: its own Terms and Build runs, newer."""
        world.run(301, ".github/workflows/terms.yaml", "pull_request_target", head_repo="someone/oss-verify",
                  branch="copy")
        world.check(701, "terms-accepted", 301, conclusion=conclusion)
        world.run(302, ".github/workflows/build.yaml", "pull_request_target", head_repo="someone/oss-verify",
                  branch="copy")
        world.check(702, "project-builds", 302, conclusion=conclusion)
        world.artifacts[302] = record(pr=77)
        return world

    def test_a_second_pull_request_at_the_same_commit_neither_blocks_nor_takes_the_first(self):
        for conclusion in ("failure", "success"):
            got = self.other_pull_request(World(), conclusion).decide()
            self.assertEqual((got["decision"], got["pr"]), ("dispatch", "32"), (conclusion, got["reason"]))

    def test_the_second_pull_requests_own_run_speaks_for_it_alone(self):
        world = self.other_pull_request(World(), "success")
        world.pulls = [World.pull(number=77, head_repo="someone/oss-verify", branch="copy")]
        api = world.api()
        api.table[f"repos/{REPO}/pulls/77"] = Calls(*world.pulls)
        api.table[f"repos/{REPO}/pulls/77/files?per_page=100"] = [world.files]
        # its Tests and Validate runs never ran, so the checks of pull request 77's head have not all passed
        got = dispatch.decide(api, REPO, 301, "pull_request_target", SHA)
        self.assertEqual(got["decision"], "none")
        self.assertIn("enrollment (not run", got["reason"])

    def test_the_run_that_completed_must_be_of_the_commit(self):
        world = World()
        world.runs[104]["head_sha"] = NEWER
        self.assertEqual(world.decide()["decision"], "none")

    def test_a_record_of_another_commit_or_shape_sends_nothing(self):
        for change in ({"sha": NEWER}, {"schema": "other"}, {"pr": "32"}, {"pr": True}, {"project": "../x"},
                       {"sizes": {}}, {"sizes": {"t": {"asan": {"text": 1, "exec": 1}}}},
                       {"sizes": {"t": {"plain": {"text": "1", "exec": 1}}}},
                       {"sizes": {"t": {"plain": {"text": -1, "exec": 1}}}},
                       {"sizes": {"t": {"plain": {"text": 1}}}}):
            world = World()
            world.artifacts[101] = record(**change)
            self.assertEqual(world.decide()["decision"], "none", change)

    def test_an_unreadable_record_sends_nothing(self):
        for rec in (b"not a zip", zipped({"record.json": "{}", "x": ""})):
            world = World()
            world.artifacts[101] = rec
            self.assertEqual(world.decide()["decision"], "none")

    def test_the_reason_is_one_line(self):
        world = World()
        world.files = [{"filename": "a\nb\n::error::x", "status": "added"}]
        self.assertNotIn("\n", world.decide()["reason"])


class ByHand(unittest.TestCase):
    """A Build run started by hand on main has its record looked at: the pull request and commit it names."""

    def world(self, **run):
        world = World()
        world.run(HAND_RUN, run.get("path", ".github/workflows/build.yaml"), "workflow_dispatch", head_sha=MAIN,
                  branch=run.get("branch", "main"), head_repo=run.get("repo", REPO))
        world.artifacts[HAND_RUN] = record()
        return world

    def test_the_review_read_is_of_the_commit_the_record_names(self):
        # The run started by hand ran on main; the review that decides is the check run at the pull request's head.
        world = self.world()
        world.review(401, "action_required")
        api = world.api()
        got = dispatch.decide(api, REPO, HAND_RUN, "workflow_dispatch", MAIN)
        self.assertEqual((got["decision"], got["label"], got["sha"]), ("none", "", SHA), got["reason"])
        self.assertIn("its newest Enrollment review check run is action_required, not success", got["reason"])
        self.assertIn(f"repos/{REPO}/commits/{SHA}/check-runs?check_name=Enrollment%20review&filter=all&per_page=100",
                      api.calls)

    def test_a_build_by_hand_on_main_sends_the_pull_request_it_names(self):
        got = self.world().decide(event="workflow_dispatch", run_id=HAND_RUN, sha=MAIN)
        self.assertEqual((got["decision"], got["pr"], got["sha"]), ("dispatch", "32", SHA), got["reason"])

    def test_a_run_by_hand_of_another_file_branch_or_repository_sends_nothing(self):
        for change in ({"path": ".github/workflows/tests.yaml"}, {"branch": "ci-test/x"}, {"repo": "someone/oss-verify"}):
            got = self.world(**change).decide(event="workflow_dispatch", run_id=HAND_RUN, sha=MAIN)
            self.assertEqual(got["decision"], "none", change)

    def test_the_pull_requests_own_checks_must_still_have_passed(self):
        world = self.world()
        world.checks[1]["conclusion"] = "failure"
        self.assertEqual(world.decide(event="workflow_dispatch", run_id=HAND_RUN, sha=MAIN)["decision"], "none")


class Labels(unittest.TestCase):
    """What a person decides: the size line, a paused language, a name the statements repository cannot take."""

    def decide(self, **sizes_):
        world = World()
        world.artifacts[101] = record(sizes=sizes(**sizes_))
        return world.decide()

    def test_every_plain_binary_at_most_the_line_is_sent(self):
        self.assertEqual(self.decide(plain_text=1_000_000, plain_exec=1_000_000)["decision"], "dispatch")

    def test_the_line_is_on_the_larger_of_text_and_executable_bytes(self):
        for text, exe in ((1_000_001, 10), (10, 1_000_001)):
            got = self.decide(plain_text=text, plain_exec=exe)
            self.assertEqual((got["decision"], got["label"]), ("label", "size-review"), (text, exe))
            self.assertIn("fuzz_command.plain", got["reason"])

    def test_a_size_that_could_not_be_read_goes_to_a_person(self):
        for text, exe in ((None, 10), (10, None)):
            got = self.decide(plain_text=text, plain_exec=exe)
            self.assertEqual(got["label"], "size-review")
            self.assertIn("size unknown", got["reason"])

    def test_large_sanitizer_builds_do_not_count(self):
        self.assertEqual(self.decide()["decision"], "dispatch")

    def test_a_binary_the_loader_maps_no_executable_byte_of_goes_to_a_person(self):
        # a build that clears the program headers' executable flag, or their count, after the link
        got = self.decide(plain_text=10, plain_exec=0)
        self.assertEqual((got["decision"], got["label"]), ("label", "size-review"))

    def test_a_project_yaml_that_cannot_be_read_sends_nothing(self):
        world = World()
        api = world.api()

        def refuse(path, raw=api.raw):
            if "/contents/" in path:
                raise subprocess.CalledProcessError(1, ["gh", "api", path])
            return raw(path)
        api.raw = refuse
        got = dispatch.decide(api, REPO, 104, "pull_request_target", SHA)
        self.assertEqual(got["decision"], "none")
        self.assertIn("cannot be read for its language", got["reason"])

    def test_a_paused_language_is_labelled(self):
        for language in ("Python", "go"):
            world = World()
            world.project_yaml = f"repo: https://example.invalid/x\nlanguage: {language}\n".encode()
            got = world.decide()
            self.assertEqual((got["decision"], got["label"]), ("label", "language-paused"), language)

    def test_a_name_with_a_dot_is_labelled(self):
        world = World()
        name = "pdf.js"
        world.files = [{"filename": f"projects/{name}/build.sh", "status": "added"}]
        world.artifacts[101] = record(project=name)
        api = world.api()
        api.table[f"repos/{REPO}/contents/projects/{name}/project.yaml?ref={SHA}"] = b"language: c\n"
        got = dispatch.decide(api, REPO, 104, "pull_request_target", SHA)
        self.assertEqual((got["decision"], got["label"], got["project"]), ("label", "name-review", name))


class Review(unittest.TestCase):
    """c2: the newest check run Enrollment review of the oss-verify App at the head. Anything but success, or no such
    check run, sends nothing, puts no label on, and names why in the run summary."""
    WHERE = f"pull request 32: projects/plugin-hostd/ at {SHA[:7]}"

    def reviewed(self, *conclusions, app=OSS_VERIFY):
        """A world whose only Enrollment review check runs are these, oldest first."""
        world = World()
        world.review_runs = []
        for i, conclusion in enumerate(conclusions):
            world.review(401 + i, conclusion, app=app)
        return world

    def assertNotSent(self, world, reason):
        got = world.decide()
        self.assertEqual((got["decision"], got["label"], got["pr"], got["sha"]), ("none", "", "32", SHA), got["reason"])
        self.assertEqual(got["reason"], reason)

    def test_a_review_that_passed_is_sent(self):
        # c2 (a)
        got = World().decide()
        self.assertEqual((got["decision"], got["label"], got["pr"], got["project"], got["sha"]),
                         ("dispatch", "", "32", "plugin-hostd", SHA), got["reason"])
        self.assertEqual(decision_reason(got), f"{self.WHERE} passed every required check, each plain binary has at "
                                               "most 1,000,000 bytes of .text and of executable segments, and its "
                                               "author maintains its repository")

    def test_a_review_that_is_not_success_sends_nothing(self):
        # c2 (b), and every other conclusion a check run can have
        for conclusion in ("action_required", "failure", "neutral", "cancelled", "timed_out", "skipped", "stale"):
            self.assertNotSent(self.reviewed(conclusion), f"{self.WHERE}: its newest Enrollment review check run is "
                                                          f"{conclusion}, not success")

    def test_a_review_still_running_sends_nothing(self):
        world = World()
        world.review(401, None, status="in_progress")
        self.assertNotSent(world, f"{self.WHERE}: its newest Enrollment review check run is in_progress, not success")

    def test_another_apps_check_run_of_the_same_name_is_not_counted(self):
        # c2 (c): another App's success alone is no review ...
        self.assertNotSent(self.reviewed("success", app=ACTIONS),
                           f"{self.WHERE}: not yet reviewed: the oss-verify App wrote no Enrollment review check run "
                           "on it")
        # ... and a newer one does not stand over the oss-verify App's action_required.
        world = self.reviewed("action_required")
        world.review(402, "success", app=ACTIONS)
        self.assertNotSent(world, f"{self.WHERE}: its newest Enrollment review check run is action_required, not "
                                  "success")

    def test_another_pull_requests_review_at_the_same_commit_is_not_counted(self):
        # A second pull request at the same commit has its own check run, external_id its number: the oss-verify App's
        # newer success there does not stand over pull request 32's own failure, or stand in for its missing review.
        for own, reason in ((("failure",), f"{self.WHERE}: its newest Enrollment review check run is failure, not "
                                           "success"),
                            ((), f"{self.WHERE}: not yet reviewed: the oss-verify App wrote no Enrollment review "
                                 "check run on it")):
            world = self.reviewed(*own)
            world.review(402, "success", pr=77)
            self.assertNotSent(world, reason)

    def test_the_pull_requests_own_review_decides_over_another_pull_requests_newer_one(self):
        world = self.reviewed("success")
        world.review(402, "action_required", pr=77)
        got = world.decide()
        self.assertEqual((got["decision"], got["pr"], got["sha"]), ("dispatch", "32", SHA), got["reason"])

    def test_a_head_with_no_review_sends_nothing(self):
        self.assertNotSent(self.reviewed(), f"{self.WHERE}: not yet reviewed: the oss-verify App wrote no Enrollment "
                                            "review check run on it")

    def test_the_newest_review_decides(self):
        # By id, not by the order the API lists them in.
        self.assertNotSent(self.reviewed("success", "action_required"),
                           f"{self.WHERE}: its newest Enrollment review check run is action_required, not success")
        world = self.reviewed("action_required", "success")
        world.review_runs.reverse()
        self.assertEqual(world.decide()["decision"], "dispatch")

    def test_a_binary_over_the_line_is_labelled_after_a_review_that_passed(self):
        # c2 (e)
        world = World()
        world.artifacts[101] = record(sizes=sizes(plain_text=2_000_000))
        got = world.decide()
        self.assertEqual((got["decision"], got["label"], got["pr"], got["sha"]), ("label", "size-review", "32", SHA))
        self.assertEqual(got["reason"], f"{self.WHERE} has a plain binary above 1,000,000 bytes: fuzz_command.plain "
                                        "(2,000,000 bytes of .text, 70,000 executable bytes)")

    def test_the_review_comes_before_every_label(self):
        # A label that a person lifts by hand is never put on a pull request whose review did not pass.
        world = self.reviewed("failure")
        world.artifacts[101] = record(sizes=sizes(plain_text=2_000_000))
        world.project_yaml = b"repo: https://example.invalid/x\nlanguage: go\n"
        got = world.decide()
        self.assertEqual((got["decision"], got["label"]), ("none", ""), got["reason"])
        self.assertIn("its newest Enrollment review check run is failure", got["reason"])

    def test_only_the_heads_review_is_read(self):
        api = World().api()
        dispatch.decide(api, REPO, 104, "pull_request_target", SHA)
        self.assertEqual(
            [c for c in api.calls if "check_name=" in c],
            [f"repos/{REPO}/commits/{SHA}/check-runs?check_name=Enrollment%20review&filter=all&per_page=100"])


class Maintainer(unittest.TestCase):
    """The author must be shown to maintain the repository `repo` names, by triage.py's maintainer check; anything
    else labels the pull request maintainer-review and sends nothing."""
    GITHUB = {"repo": "https://github.com/FreeREAC/plugin-hostd", "language": "c"}
    META = {"full_name": "FreeREAC/plugin-hostd", "owner": {"login": "FreeREAC"}, "fork": False}

    def standing(self, config, mark=None, error=None, meta=META):
        seen = {}

        class Fake:
            def __init__(self, token):
                seen["token"] = token

            def find(self, path):
                if error:
                    raise error
                seen["find"] = path
                return meta

        def row(gh, slug, meta_, login):
            seen["row"] = (slug, login)
            return mark, "evidence"
        old = dispatch.triage.GitHub, dispatch.triage.maintainer_row
        dispatch.triage.GitHub, dispatch.triage.maintainer_row = Fake, row
        try:
            return REAL_STANDING(config, "linuxnow"), seen
        finally:
            dispatch.triage.GitHub, dispatch.triage.maintainer_row = old

    def test_ok_passes_and_reads_the_authors_role_on_the_upstream(self):
        why, seen = self.standing(self.GITHUB, dispatch.triage.OK)
        self.assertEqual(why, "")
        self.assertEqual(seen["find"], "repos/FreeREAC/plugin-hostd")
        self.assertEqual(seen["row"], ("FreeREAC/plugin-hostd", "linuxnow"))

    def test_warn_and_fail_do_not_pass(self):
        for mark in (dispatch.triage.WARN, dispatch.triage.FAIL):
            why, _ = self.standing(self.GITHUB, mark)
            self.assertIn("is not shown to maintain FreeREAC/plugin-hostd", why, mark)

    def test_a_repository_not_on_github_does_not_pass(self):
        for repo in ("https://gitlab.com/x/y", "https://example.invalid/x", None, 7):
            why, seen = self.standing({"repo": repo}, dispatch.triage.OK)
            self.assertIn("not a github.com repository", why, repo)
            self.assertNotIn("row", seen)

    def test_a_read_that_fails_or_finds_nothing_does_not_pass(self):
        why, _ = self.standing(self.GITHUB, dispatch.triage.OK, error=dispatch.triage.ApiError("x", 403, "p"))
        self.assertIn("could not be read", why)
        why, _ = self.standing(self.GITHUB, dispatch.triage.OK, meta=None)
        self.assertIn("not found on GitHub", why)

    def test_decide_labels_maintainer_review_and_sends_nothing(self):
        world = World()
        world.pulls = [dict(world.pull(), user={"login": "someone"})]
        old = dispatch.standing
        dispatch.standing = lambda config, login: f"{login} is not shown to maintain it"
        try:
            got = world.decide()
        finally:
            dispatch.standing = old
        self.assertEqual((got["decision"], got["label"]), ("label", "maintainer-review"))
        self.assertIn("someone is not shown to maintain it", got["reason"])

    def test_decide_asks_about_the_author_and_the_project_yaml(self):
        world = World()
        world.pulls = [dict(world.pull(), user={"login": "linuxnow"})]
        STANDING_CALLS.clear()
        self.assertEqual(world.decide()["decision"], "dispatch")
        self.assertEqual(STANDING_CALLS, [({"repo": "https://example.invalid/x", "language": "c"}, "linuxnow")])

    def test_a_fork_does_not_pass_whoever_owns_it(self):
        fork = {"full_name": "someone/plugin-hostd", "owner": {"login": "someone"}, "fork": True,
                "parent": {"full_name": "FreeREAC/plugin-hostd"}}
        why, seen = self.standing(self.GITHUB, dispatch.triage.OK, meta=fork)
        self.assertEqual(why, "someone/plugin-hostd is a fork of FreeREAC/plugin-hostd, so owning it shows nothing")
        self.assertNotIn("row", seen)
        why, _ = self.standing(self.GITHUB, dispatch.triage.OK, meta={**self.META, "fork": None})
        self.assertIn("is a fork of another repository", why)

    def confirmed(self, labeller, label="maintainer-confirmed", events=True, at="2026-10-28T05:00:00Z", run_id=104):
        world = World()
        world.runs[101]["created_at"] = "2026-10-28T04:00:00Z"  # the Build run of the head commit, made at its push
        # The run of maintainer-confirmed.yml that the label started, after the Build run.
        world.run(700, dispatch.CONFIRMED_WORKFLOW, "pull_request_target")
        world.runs[700].update(conclusion="success", created_at="2026-10-28T05:00:02Z")
        world.pulls = [dict(world.pull(), user={"login": "someone"}, labels=[{"name": label}])]
        api = world.api()
        api.table[f"repos/{REPO}/issues/{PR}/events?per_page=100"] = [[
            {"event": "labeled", "label": {"name": label}, "actor": {"login": labeller}, "created_at": at}]
            if events else []]
        old = dispatch.standing
        dispatch.standing = lambda config, login: f"{login} is not shown to maintain it"
        try:
            return dispatch.decide(api, REPO, run_id, "pull_request_target", SHA)
        finally:
            dispatch.standing = old

    def test_the_label_put_by_someone_else_lifts_the_hold(self):
        got = self.confirmed("a-member")
        self.assertEqual(got["decision"], "dispatch", got["reason"])
        self.assertIn("a-member labelled it maintainer-confirmed", got["reason"])

    def test_the_maintainer_confirmed_run_after_the_build_run_dispatches(self):
        # c2 (i): the author is not shown to maintain the project, a-member put maintainer-confirmed on after the head
        # commit, and the newest Enrollment review is success. The run of maintainer-confirmed.yml completes after the
        # head's Build run, and its completion sends the head.
        got = self.confirmed("a-member", run_id=700)
        self.assertEqual((got["decision"], got["label"], got["pr"], got["project"], got["sha"]),
                         ("dispatch", "", "32", "plugin-hostd", SHA), got["reason"])
        self.assertEqual(decision_reason(got), f"pull request 32: projects/plugin-hostd/ at {SHA[:7]} passed every "
                                               "required check, each plain binary has at most 1,000,000 bytes of "
                                               ".text and of executable segments, and a-member labelled it "
                                               "maintainer-confirmed")

    def test_the_label_put_by_the_author_or_with_no_record_or_another_label_does_not(self):
        for case in ({"labeller": "someone"}, {"labeller": "SomeOne"}, {"labeller": "a-member", "events": False},
                     {"labeller": "a-member", "label": "other"},
                     # put on before the head commit was pushed: it saw another commit, maybe another `repo`
                     {"labeller": "a-member", "at": "2026-10-28T03:59:59Z"}, {"labeller": "a-member", "at": None}):
            got = self.confirmed(**case)
            self.assertEqual((got["decision"], got["label"]), ("label", "maintainer-review"), case)

    def test_a_skipped_maintainer_confirmed_run_decides_nothing(self):
        world = World()
        world.run(700, dispatch.CONFIRMED_WORKFLOW, "pull_request_target")
        world.runs[700]["conclusion"] = "skipped"
        got = world.decide(run_id=700)
        self.assertEqual(got["decision"], "none")
        self.assertIn("a label other than maintainer-confirmed", got["reason"])
        world.runs[700]["conclusion"] = "success"
        self.assertEqual(world.decide(run_id=700)["decision"], "dispatch")


class Merged(unittest.TestCase):
    """A merge of an enrollment pull request: Enrollment merged's run completes, and the pull request's head is sent
    when its required checks passed and the size line, the language and the name allow statements. The review and the
    maintainer check are not asked: the person who merged decided them."""

    def world(self, event="pull_request_target", conclusion="success", title=f"merged #{PR}", branch=None, repo=None):
        world = World()
        if event == "workflow_dispatch":   # the replay of a merge: gh workflow run enroll-merged.yml -f pr=<n>, on main
            world.run(MERGED_RUN, ".github/workflows/enroll-merged.yml", event, head_sha=MAIN, branch=branch or "main",
                      head_repo=repo or REPO)
        else:
            world.run(MERGED_RUN, ".github/workflows/enroll-merged.yml", event)
        world.runs[MERGED_RUN].update(conclusion=conclusion, display_title=title)
        world.pulls = [dict(World.pull(state="closed"), merged=True, merged_by={"login": "a-member"},
                            user={"login": "someone"})]
        return world

    def decide(self, world):
        run = world.runs[MERGED_RUN]
        return world.decide(event=run["event"], run_id=MERGED_RUN, sha=run["head_sha"])

    def test_a_merged_enrollment_is_sent_for_its_head(self):
        for event in ("pull_request_target", "workflow_dispatch"):
            got = self.decide(self.world(event))
            self.assertEqual((got["decision"], got["pr"], got["project"], got["sha"], got.get("merged")),
                             ("dispatch", "32", "plugin-hostd", SHA, "true"), (event, got["reason"]))
            self.assertEqual(got["reason"], "pull request 32 was merged by a-member: the merge decides the review and "
                                            "the maintainer check")

    def test_a_pull_request_closed_without_a_merge_sends_nothing_and_takes_off_review_passed(self):
        # Its job skips (the run does not succeed); and a replay of a pull request that was closed without a merge. Each
        # sends nothing, and takes review-passed off the closed pull request when it carries it.
        for labels in ([{"name": "review-passed"}], []):
            skipped = self.world(conclusion="skipped")
            skipped.pulls = [dict(World.pull(state="closed"), merged=False, merged_by=None, labels=labels)]
            replay = self.world("workflow_dispatch")
            replay.pulls = [dict(World.pull(state="closed"), merged=False, merged_by=None, labels=labels)]
            for world, why in ((skipped, "not success"), (replay, "pull request 32 is not merged")):
                got = self.decide(world)
                self.assertEqual((got["decision"], got["label"]), ("none", ""), got["reason"])
                self.assertIn(why, got["reason"])
                self.assertEqual((got["review_passed"], got["review_passed_at"], got["label_at"]),
                                 ("off", "closed", "") if labels else ("", "", ""), (labels, got["reason"]))
                if labels:
                    self.assertEqual(got["pr"], "32", got["reason"])

    def test_a_merge_does_not_wait_for_the_review(self):
        # c2 (d): the Enrollment review check run is not read.
        for case in ("action_required", "failure", None):
            world = self.world()
            world.review_runs = []
            if case:
                world.review(401, case)
            api = world.api()
            got = dispatch.decide(api, REPO, MERGED_RUN, "pull_request_target", SHA)
            self.assertEqual((got["decision"], got["label"], got["sha"], got.get("merged")),
                             ("dispatch", "", SHA, "true"), (case, got["reason"]))
            self.assertEqual(got["reason"], "pull request 32 was merged by a-member: the merge decides the review and "
                                            "the maintainer check")
            self.assertEqual([c for c in api.calls if "check_name=" in c], [], case)

    def test_a_merge_does_not_wait_for_the_maintainer_check(self):
        asked = []
        old = dispatch.standing
        dispatch.standing = lambda config, login: asked.append(login) or f"{login} is not shown to maintain it"
        try:
            got = self.decide(self.world())
        finally:
            dispatch.standing = old
        self.assertEqual((got["decision"], got["label"]), ("dispatch", ""), got["reason"])
        self.assertEqual(asked, [])

    def test_a_merged_enrollment_over_the_size_line_is_labelled(self):
        world = self.world()
        world.artifacts[101] = record(sizes=sizes(plain_text=2_000_000))
        got = self.decide(world)
        self.assertEqual((got["decision"], got["label"], got["pr"], got["sha"]), ("label", "size-review", "32", SHA),
                         got["reason"])
        self.assertIn("fuzz_command.plain", got["reason"])

    def test_a_merged_python_enrollment_is_paused(self):
        world = self.world()
        world.project_yaml = b"repo: https://example.invalid/x\nlanguage: python\n"
        got = self.decide(world)
        self.assertEqual((got["decision"], got["label"]), ("label", "language-paused"), got["reason"])

    def test_a_merged_change_that_is_no_enrollment_decides_nothing(self):
        for files in ([{"filename": "README.md", "status": "modified"}],
                      [{"filename": "projects/plugin-hostd/build.sh", "status": "added"},
                       {"filename": ".github/workflows/build.yaml", "status": "modified"}]):
            world = self.world()
            world.files = files
            got = self.decide(world)
            self.assertEqual((got["decision"], got["label"]), ("none", ""), files)
            self.assertIn("pull request 32 is not one enrollment", got["reason"])

    def test_a_merge_whose_checks_did_not_pass_decides_nothing(self):
        # The replay binds the checks to the pull request's head, not to the main commit it ran on.
        for event in ("pull_request_target", "workflow_dispatch"):
            world = self.world(event)
            world.checks[1]["conclusion"] = "failure"   # project-builds
            got = self.decide(world)
            self.assertEqual((got["decision"], got["label"]), ("none", ""), event)
            self.assertIn(f"required checks not passed at {SHA[:7]}: project-builds (failure)", got["reason"])

    def test_a_pull_request_merged_into_another_branch_decides_nothing(self):
        world = self.world()
        world.pulls = [dict(World.pull(state="closed", base="release"), merged=True, merged_by={"login": "a-member"})]
        got = self.decide(world)
        self.assertEqual((got["decision"], got["label"]), ("none", ""), got["reason"])
        self.assertIn("pull request 32 was merged into 'release', not main", got["reason"])

    def test_a_merged_record_of_another_pull_request_or_project_decides_nothing(self):
        # The bound project-builds run's record must be this pull request's, of the project its files change.
        for change, why in (({"pr": 77}, "of pull request 77 and projects/plugin-hostd/"),
                            ({"project": "libreac"}, "of pull request 32 and projects/libreac/")):
            world = self.world()
            world.artifacts[101] = record(**change)
            got = self.decide(world)
            self.assertEqual((got["decision"], got["label"]), ("none", ""), change)
            self.assertIn(f"pull request 32: the build record is {why}", got["reason"], change)

    def test_a_merged_name_with_a_dot_is_labelled(self):
        name = "pdf.js"
        world = self.world()
        world.files = [{"filename": f"projects/{name}/build.sh", "status": "added"}]
        world.artifacts[101] = record(project=name)
        api = world.api()
        api.table[f"repos/{REPO}/contents/projects/{name}/project.yaml?ref={SHA}"] = b"language: c\n"
        got = dispatch.decide(api, REPO, MERGED_RUN, "pull_request_target", SHA)
        self.assertEqual((got["decision"], got["label"], got["project"]), ("label", "name-review", name), got["reason"])

    def test_a_forged_or_untitled_merged_run_decides_nothing(self):
        # A fork's own copy of the file on its pull request, a replay from another branch's or repository's copy, and a
        # title that names no pull request.
        neither = "is neither the base branch's"
        for case, why in (({"event": "pull_request"}, neither),
                          ({"event": "workflow_dispatch", "branch": "ci/x"}, neither),
                          ({"event": "workflow_dispatch", "repo": "someone/oss-verify"}, neither),
                          ({"title": "merged #0"}, "names no pull request"),
                          ({"title": f"merged #{PR} again"}, "names no pull request"),
                          ({"title": f"Merged #{PR}"}, "names no pull request"),
                          ({"title": None}, "names no pull request")):
            got = self.decide(self.world(**case))
            self.assertEqual((got["decision"], got["label"]), ("none", ""), case)
            self.assertIn(why, got["reason"], case)

    def test_the_send_step_says_merged_only_for_a_merge(self):
        if not shutil.which("jq"):
            self.skipTest("jq is not installed")
        steps = yaml.safe_load((ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text())["jobs"][
            "dispatch"]["steps"]
        script = [s for s in steps if s.get("name") == "Send enrollment-checked to the private repository"][0]["run"]
        sent = {}
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            (bin / "gh").write_text(f'#!/bin/bash\nprintf "%s\\n" "$*" > {directory}/argv\ncat > {directory}/body\n')
            (bin / "gh").chmod(0o755)
            for merged in ("", "true"):
                env = dict(os.environ, PATH=f"{bin}:{os.environ['PATH']}", PROJECT="plugin-hostd", SHA=SHA,
                           PR=str(PR), MERGED=merged, INTERNAL_ID="1425069221",
                           GITHUB_STEP_SUMMARY=str(directory / "summary"))
                run = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual((directory / "argv").read_text(),
                                 "api --method POST repositories/1425069221/dispatches --input -\n")
                sent[merged] = json.loads((directory / "body").read_text())
        payload = {"pr": PR, "sha": SHA, "project": "plugin-hostd"}
        self.assertEqual(sent[""], {"event_type": "enrollment-checked", "client_payload": payload})
        self.assertEqual(sent["true"], {"event_type": "enrollment-checked",
                                        "client_payload": {**payload, "merged": True}})


class TheRecord(unittest.TestCase):
    """build.yaml's own code, run here: binary-sizes on a work directory, then the record job's script, then the
    record read back as enroll-dispatch reads it."""

    def test_binary_sizes_and_the_record_job_make_a_record_enroll_dispatch_takes(self):
        if not shutil.which("jq"):
            self.skipTest("jq is not installed")
        from test_manifest import elf, PT_LOAD
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory, "work")
            targets = {}
            for target, exe in (("fuzz_a", 3000), ("fuzz_b", 1_200_000)):
                builds = {}
                for build in ("plain", "asan"):
                    path = work / "out" / target / f"{target}.{build}"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(elf(symtab=False, sections=[(".text", 100)], segments=[(PT_LOAD, 5, exe)]))
                    builds[build] = {"file": path.name, "bytes": path.stat().st_size, "sha256": "0" * 64}
                targets[target] = {"builds": builds}
            (work / "manifest.yaml").write_text(yaml.safe_dump({"targets": targets}))
            sizes_line = subprocess.run([sys.executable, str(ROOT / ".github" / "scripts" / "binary-sizes"), str(work)],
                                        capture_output=True, text=True, check=True).stdout.strip()
            script = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]["record"][
                "steps"][0]["run"]
            env = dict(os.environ, PR=str(PR), NAME="plugin-hostd", SHA=SHA, SIZES=sizes_line, RUNNER_TEMP=directory)
            subprocess.run(["bash", "-c", script], env=env, check=True)
            rec = json.loads(pathlib.Path(directory, "record", "record.json").read_text())
        self.assertEqual(dispatch.record_problem(rec, SHA), "")
        self.assertEqual(rec["sizes"]["fuzz_a"]["plain"], {"text": 100, "exec": 3000})
        self.assertEqual(dispatch.oversized(rec), ["fuzz_b.plain (100 bytes of .text, 1,200,000 executable bytes)"])


class Jobs(unittest.TestCase):
    """What enroll-dispatch.yml names."""

    def test_the_workflow_names_no_other_theorem_labs_repository(self):
        # The event's target is named by its id alone, so that this public file and its log name no private
        # repository.
        text = (ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text()
        named = set(re.findall(r"theorem-labs/([A-Za-z0-9._-]+)", text))
        self.assertLessEqual(named, {"oss-verify"}, named)


def concurrency_group(run):
    """enroll-dispatch.yml's concurrency group for the run whose completion starts it, as GitHub evaluates it."""
    ctx = {f"github.event.workflow_run.{key}": value for key, value in run.items() if not isinstance(value, dict)}
    ctx["github.event.workflow_run.head_repository.full_name"] = (run.get("head_repository") or {}).get("full_name")
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: as_text(evaluate(m.group(1), ctx)),
                  ENROLL_DISPATCH["concurrency"]["group"], flags=re.S)


class Concurrency(unittest.TestCase):
    """enroll-dispatch.yml's concurrency group, evaluated for the runs whose completion starts it."""

    def test_two_pull_requests_at_once_run_both(self):
        # c2 (h): Build runs of two pull requests complete together. Their Enroll dispatch runs are in two groups, and
        # no run in a group cancels one in progress: neither is cancelled.
        world = World()
        world.run(301, ".github/workflows/build.yaml", "pull_request_target", head_sha=NEWER, branch="add-libx",
                  head_repo="someone/oss-verify")
        first, second = concurrency_group(world.runs[101]), concurrency_group(world.runs[301])
        self.assertEqual(first, f"enroll-dispatch:{SHA}:FreeREAC/oss-verify:add-plugin-hostd")
        self.assertEqual(second, f"enroll-dispatch:{NEWER}:someone/oss-verify:add-libx")
        self.assertIs(ENROLL_DISPATCH["concurrency"]["cancel-in-progress"], False)

    def test_a_pull_requests_runs_share_a_group_and_another_head_at_the_same_commit_does_not(self):
        world = World()
        world.run(301, ".github/workflows/build.yaml", "pull_request_target", head_repo="someone/oss-verify",
                  branch="copy")
        self.assertEqual({concurrency_group(world.runs[run_id]) for run_id in (101, 102, 103, 104)},
                         {f"enroll-dispatch:{SHA}:FreeREAC/oss-verify:add-plugin-hostd"})
        self.assertEqual(concurrency_group(world.runs[301]), f"enroll-dispatch:{SHA}:someone/oss-verify:copy")

    def test_a_merge_and_a_build_by_hand_each_have_a_group_of_their_own(self):
        world = World()
        world.run(MERGED_RUN, ".github/workflows/enroll-merged.yml", "pull_request_target")
        world.run(HAND_RUN, ".github/workflows/build.yaml", "workflow_dispatch", head_sha=MAIN, branch="main",
                  head_repo=REPO)
        self.assertEqual(concurrency_group(world.runs[MERGED_RUN]), f"enroll-dispatch:{MERGED_RUN}")
        self.assertEqual(concurrency_group(world.runs[HAND_RUN]), f"enroll-dispatch:{HAND_RUN}")


def dispatch_step(name):
    [found] = [s for s in ENROLL_DISPATCH["jobs"]["dispatch"]["steps"] if s.get("name") == name]
    return found["run"]


class DispatchJob(Runner):
    """enroll-dispatch.yml's dispatch job: its label steps, run with a stand-in gh."""
    LABELS = f"repos/{REPO}/issues/{PR}/labels"

    def setUp(self):
        if not shutil.which("jq"):
            self.skipTest("jq is not installed")
        super().setUp()
        self.summary = self.dir / "summary"
        # GitHub sets each env value of the job, empty when decide gave no such output.
        self.env.update(PR=str(PR), PROJECT="plugin-hostd", SHA=SHA, GITHUB_STEP_SUMMARY=str(self.summary), MERGED="",
                        REVIEW_PASSED="", REVIEW_PASSED_AT="", LABEL_AT="")

    def labelled(self, *names):
        self.serve(self.LABELS, [{"name": name} for name in names])

    def writes(self):
        """The calls that change the pull request: (method, endpoint)."""
        return [(c[c.index("--method") + 1], c[c.index("--method") + 2]) for c in self.calls() if "--method" in c]

    def test_the_decisions_label_is_put_on(self):
        self.labelled("maintainer-review")  # GitHub's answer to the POST: the labels the pull request has now
        code, out, _ = self.run_script(dispatch_step("Label the pull request"), DECISION="label",
                                       LABEL="maintainer-review")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.writes(), [("POST", self.LABELS)])
        self.assertEqual(json.loads((self.api / "input.1").read_text()), {"labels": ["maintainer-review"]})
        self.assertEqual(self.summary.read_text(), f"pull request {PR}: labelled maintainer-review; no statements are "
                                                   f"started for plugin-hostd at {SHA}\n")

    def test_the_decisions_values_admit_only_this_workflows_labels(self):
        script = dispatch_step("Check the decision's values")
        for decision, label in (("dispatch", ""), ("label", "size-review"), ("label", "language-paused"),
                                ("label", "name-review"), ("label", "maintainer-review")):
            code, out, _ = self.run_script(script, DECISION=decision, LABEL=label)
            self.assertEqual(code, 0, (label, out))
        for label in ("review-pending", "review-blocking", "review-held"):
            code, out, _ = self.run_script(script, DECISION="label", LABEL=label)
            self.assertEqual(code, 1, label)
            self.assertIn(f"::error::not a decision: 'label' '{label}'", out)

    def test_a_send_takes_off_only_the_labels_this_workflow_puts_on(self):
        names = ("size-review", "review-pending", "review-blocking", "maintainer-review", "checks-failing")
        self.labelled(*names)
        for name in names:
            self.serve(f"{self.LABELS}/{name}", [])
        code, out, _ = self.run_script(dispatch_step("Take off the labels an earlier commit got"), DECISION="dispatch")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.writes(), [("DELETE", f"{self.LABELS}/size-review"),
                                         ("DELETE", f"{self.LABELS}/maintainer-review")])


class AppToken(unittest.TestCase):
    """.github/scripts/app-token, with a stand-in curl: the request it makes, and no secret in any argument."""

    def test_a_token_for_one_repository_by_id_with_one_permission(self):
        if not shutil.which("openssl") or not shutil.which("jq"):
            self.skipTest("openssl or jq is not installed")
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            key = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True, text=True).stdout
            bin = directory / "bin"
            bin.mkdir()
            (bin / "curl").write_text(
                "#!/bin/bash\n"
                f"printf '%s\\n' \"$@\" >> {directory}/curl-argv\n"
                f"for a in \"$@\"; do case $a in @/dev/fd/*|@/proc/*) cat \"${{a#@}}\" >> {directory}/curl-headers;; "
                "esac; done\n"
                "case \"${@: -1}\" in\n"
                f"  */installation) echo '{{\"id\": 174627013}}' ;;\n"
                f"  */access_tokens) cat > {directory}/body; echo '{{\"token\": \"ghs_stand-in\"}}' ;;\n"
                "esac\n")
            (bin / "curl").chmod(0o755)
            env = {"PATH": f"{bin}:{os.environ['PATH']}", "APP_KEY": key, "CLIENT_ID": "Iv23liAWPMahJZYsw3un",
                   "REPOSITORY_ID": "1425069221", "PERMISSION": "contents", "ACCESS": "write",
                   "GITHUB_OUTPUT": str(directory / "output"), "GITHUB_REPOSITORY": REPO}
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "app-token")], env=env, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual((directory / "output").read_text(), "token=ghs_stand-in\n")
            self.assertEqual(json.loads((directory / "body").read_text()),
                             {"repository_ids": [1425069221], "permissions": {"contents": "write"}})
            argv = (directory / "curl-argv").read_text()
            self.assertIn("https://api.github.com/app/installations/174627013/access_tokens", argv)
            self.assertNotIn("Bearer", argv)
            self.assertNotIn("PRIVATE KEY", argv)
            self.assertIn("Authorization: Bearer ey", (directory / "curl-headers").read_text())
            self.assertIn("::add-mask::ghs_stand-in", run.stdout)

    def test_a_repository_that_is_not_an_id_is_refused(self):
        env = {"PATH": os.environ["PATH"], "APP_KEY": "x", "CLIENT_ID": "x", "REPOSITORY_ID": "theorem-labs/x",
               "PERMISSION": "contents", "ACCESS": "write", "GITHUB_OUTPUT": os.devnull, "GITHUB_REPOSITORY": REPO}
        run = subprocess.run([str(ROOT / ".github" / "scripts" / "app-token")], env=env, capture_output=True)
        self.assertEqual(run.returncode, 2)


# review-passed (dispatch://OSSV-496). The dispatch job's steps that check decide's values and write the label.
CHECK, TAKE_OFF, PUT_ON = "Check the decision's values", "Take off review-passed", "Put on review-passed"
REVIEW_PASSED = dispatch.REVIEW_PASSED
DESCRIPTION = "Checks and CI review passed; statements started. No plan to merge or prove this project now."
EPOCH = calendar.timegm((2026, 11, 11, 21, 0, 0))
STAND_IN_GH = r'''
"""A stand-in for `gh api`, for the steps of enroll-dispatch.yml that write review-passed and for build.yaml's bash
function trusted. It keeps one JSON state file, $GH_STATE:

    {"labels": [{"name", "color", "description"}, ...],   the repository's labels
     "pulls": {"<n>": {"state", "head_sha", "labels": [<name>, ...]}},
     "events": {"<n>": [{"event", "label": {"name"}, "actor": {"login"}, "created_at"}, ...]},
     "collaborators": {"<login>": "<permission>"},
     "clock": <the Unix time of the next event>,
     "after_add": {"<n>": {"head_sha"}}   applied to the pull request just after a label is put on it: a push that
                                          lands between the put-on and the read after it
     "calls": ["<METHOD> <path>", ...]}   every request, in order

What GitHub refuses it answers as gh does: the body on standard output, `gh: <message> (HTTP <status>)` on standard
error, exit 1. --jq runs `jq -r` on the answer, on each page with --paginate (the events come two to a page). A request
it does not know stops it."""
import json
import os
import subprocess
import sys
import time

APP = "oss-verify[bot]"   # the account whose token the steps write with
MESSAGES = {404: "Not Found", 422: "Validation Failed"}
with open(os.environ["GH_STATE"]) as file:
    state = json.load(file)


def save():
    with open(os.environ["GH_STATE"], "w") as file:
        json.dump(state, file)


def refuse(status):
    print(json.dumps({"message": MESSAGES[status], "status": str(status)}))
    print(f"gh: {MESSAGES[status]} (HTTP {status})", file=sys.stderr)
    save()
    sys.exit(1)


def stop(why):
    save()
    sys.exit(f"stand-in gh: {why}")


def event(number, kind, name):
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(state["clock"]))
    state["clock"] += 1
    state["events"].setdefault(number, []).append(
        {"event": kind, "label": {"name": name}, "actor": {"login": APP}, "created_at": created})


def label(name):
    return next((found for found in state["labels"] if found["name"] == name), None)


def pull(number):
    found = state["pulls"][number]
    return {"number": int(number), "state": found["state"], "head": {"sha": found["head_sha"]},
            "labels": [label(name) or {"name": name} for name in found["labels"]]}


args = sys.argv[1:]
method, paginate, body, jq, path = "GET", False, None, None, None
if args[:1] != ["api"]:
    stop(f"not a gh api command: {args}")
args.pop(0)
while args:
    arg = args.pop(0)
    if arg == "--method":
        method = args.pop(0)
    elif arg == "--paginate":
        paginate = True
    elif arg == "--input" and args[:1] == ["-"]:
        args.pop(0)
        body = json.load(sys.stdin)
    elif arg == "--jq":
        jq = args.pop(0)
    elif arg.startswith("-") or path is not None:
        stop(f"an argument it does not know: {arg!r}")
    else:
        path = arg
state["calls"].append(f"{method} {path}")
prefix = "repos/theorem-labs/oss-verify/"
if path is None or not path.startswith(prefix):
    stop(f"no such request: {method} {path}")
parts, pages = path[len(prefix):].split("?")[0].split("/"), None
if parts[0] == "labels" and len(parts) == 2 and method in ("GET", "PATCH"):
    answer = label(parts[1])
    if answer is None:
        refuse(404)
    if method == "PATCH":
        answer.update(body)
elif parts == ["labels"] and method == "POST":
    if label(body["name"]) is not None:
        refuse(422)
    answer = {"name": body["name"], "color": body.get("color", "ededed"), "description": body.get("description", "")}
    state["labels"].append(answer)
elif parts[0] == "pulls" and len(parts) == 2 and method == "GET":
    answer = pull(parts[1])
elif parts[0] == "issues" and parts[2:] == ["events"] and method == "GET":
    events = state["events"].get(parts[1], [])
    pages = [events[i:i + 2] for i in range(0, len(events), 2)] or [[]]
    pages = pages if paginate else pages[:1]
elif parts[0] == "issues" and parts[2:] == ["labels"] and method == "POST":
    number = parts[1]
    for name in body["labels"]:
        if label(name) is None:   # GitHub makes a label it does not have, with no description
            state["labels"].append({"name": name, "color": "ededed", "description": ""})
        if name not in state["pulls"][number]["labels"]:
            state["pulls"][number]["labels"].append(name)
            event(number, "labeled", name)
    state["pulls"][number].update(state["after_add"].pop(number, {}))
    answer = pull(number)["labels"]
elif parts[0] == "issues" and len(parts) == 4 and parts[2] == "labels" and method == "DELETE":
    number, name = parts[1], parts[3]
    if name not in state["pulls"][number]["labels"]:
        refuse(404)
    state["pulls"][number]["labels"].remove(name)
    event(number, "unlabeled", name)
    answer = pull(number)["labels"]
elif parts[0] == "collaborators" and parts[2:] == ["permission"] and method == "GET":
    if parts[1] not in state["collaborators"]:
        refuse(404)
    answer = {"permission": state["collaborators"][parts[1]]}
else:
    stop(f"no such request: {method} {path}")
save()
for page in [answer] if pages is None else pages:
    if jq is None:
        print(json.dumps(page))
    else:
        sys.stdout.write(subprocess.run(["jq", "-r", jq], input=json.dumps(page), capture_output=True, text=True,
                                        check=True).stdout)
'''


def stand_in_gh(directory):
    """Writes the stand-in gh into `directory`/bin, and gives that directory."""
    bin = directory / "bin"
    bin.mkdir()
    (bin / "gh").write_text(f"#!{sys.executable}{STAND_IN_GH}")
    (bin / "gh").chmod(0o755)
    return bin


@functools.cache
def enroll_dispatch_jobs():
    """enroll-dispatch.yml's decide and dispatch jobs."""
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text())["jobs"]
    names = [step.get("name") for step in jobs["dispatch"]["steps"]]
    if any(names.count(name) != 1 for name in (CHECK, TAKE_OFF, PUT_ON)):
        raise AssertionError(f"the dispatch job's steps are {names}")
    return jobs["decide"], jobs["dispatch"]


def at(seconds):
    """A Unix time as GitHub gives a time."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


class LabelApi(FakeApi):
    """FakeApi, where each path of `failing` fails as gh does, and the pull_request_target runs from a branch made at or
    after a time (actions/runs?branch=<branch>&event=pull_request_target&created=>=<time>) are those of `runs`."""
    LATER = re.compile(rf"repos/{re.escape(REPO)}/actions/runs\?branch=([^&]+)&event=pull_request_target"
                       r"&created=%3E%3D([^&]+)&per_page=100")

    def __init__(self, table, runs=(), failing=()):
        super().__init__(table)
        self.runs, self.failing = runs, failing

    def answer(self, path):
        later = self.LATER.fullmatch(path)
        if path not in self.failing and not later:
            return super().answer(path)
        self.calls.append(path)
        if path in self.failing:
            raise subprocess.CalledProcessError(1, ["gh", "api", path])
        branch, since = urllib.parse.unquote(later.group(1)), later.group(2)
        return [{"workflow_runs": [copy.deepcopy(run) for run in self.runs
                                   if run["head_branch"] == branch and run["event"] == "pull_request_target"
                                   and run["created_at"] >= since]}]

    get = pages = raw = answer


class Timeline:
    """Pull request PR, from FreeREAC/oss-verify:add-plugin-hostd, over time: its head, commits, state, labels, events
    and author, the Actions runs from its head, and the repository's labels. One clock gives each run and event a later
    time. decide reads a World of the completed run's commit, with the pull request, its commits, its events and the
    runs as they are then. job runs the dispatch job's steps that write review-passed against the stand-in gh, whose
    state is made from this one, and reads back what they wrote. Each labeled event starts a run of
    maintainer-confirmed.yml, on pull_request_target, at the head of that moment, a few seconds after it, unless
    confirmed_runs is False. A push adds its commit to the pull request's commits, and a force push makes it the only
    one."""
    BRANCH, HEAD_REPO = "add-plugin-hostd", "FreeREAC/oss-verify"

    def __init__(self, author="linuxnow", permission="read", repo_labels=None, confirmed_runs=True):
        self.clock = EPOCH
        self.head, self.commits, self.state, self.merged = None, [], "open", False
        self.author = author
        self.collaborators = {} if author.endswith("[bot]") else {author: permission}
        self.repo_labels = [{"name": REVIEW_PASSED, "color": "0E8A16", "description": DESCRIPTION}] \
            if repo_labels is None else repo_labels
        self.labels, self.events, self.runs = [], [], []
        self.failing = set()   # the paths whose read fails in decide
        self.calls = []        # decide's paths, and the steps' "<METHOD> <path>"
        self.confirmed_runs = confirmed_runs

    def tick(self, seconds=1):
        self.clock += seconds
        return at(self.clock - seconds)

    def add_run(self, sha, path, event):
        self.runs.append({"id": 1000 + len(self.runs), "path": path, "event": event, "head_sha": sha,
                          "head_branch": self.BRANCH, "head_repository": {"full_name": self.HEAD_REPO},
                          "created_at": self.tick()})

    def push(self, sha, force=False):
        """The head becomes `sha`, by a force push or not, and the runs of the four required checks start."""
        if force:
            self.events.append({"event": "head_ref_force_pushed", "actor": {"login": self.author},
                                "created_at": self.tick()})
        self.head = sha
        self.commits = [sha] if force else self.commits + [sha]
        for name in REQUIRED:
            self.add_run(sha, *RUNS[name][1:])

    def confirmed_run(self):
        if self.confirmed_runs:
            self.tick(3)
            self.add_run(self.head, dispatch.CONFIRMED_WORKFLOW, "pull_request_target")

    def put_on(self, actor, name=REVIEW_PASSED):
        """`actor` puts the label on, by the name `name` (it is review-passed now, whatever it was then)."""
        self.events.append({"event": "labeled", "label": {"name": name}, "actor": {"login": actor},
                            "created_at": self.tick()})
        self.labels.append(REVIEW_PASSED)
        self.confirmed_run()

    def take_off(self, actor, name=REVIEW_PASSED):
        self.events.append({"event": "unlabeled", "label": {"name": name}, "actor": {"login": actor},
                            "created_at": self.tick()})
        self.labels.remove(REVIEW_PASSED)

    def close(self, merged):
        self.state, self.merged = "closed", merged

    def pull(self):
        return dict(World.pull(sha=self.head, state=self.state), user={"login": self.author}, merged=self.merged,
                    merged_by={"login": "a-member"} if self.merged else None,
                    labels=[{"name": name} for name in self.labels])

    def world(self, sha, review="success", files=None, oversize=False, failed_check=False):
        """A World of the commit `sha`: the conclusion of the review's check run Enrollment review (success unless
        given; None: there is none), the pull request's files, a plain binary above the size line (oversize), or
        project-builds failed (failed_check)."""
        world = World(sha)
        created = max(run["created_at"] for run in self.runs if run["head_sha"] == sha)
        for run in world.runs.values():
            run["created_at"] = created
        world.review_runs = []
        if review is not None:
            world.review(400, review)
        if files is not None:
            world.files = files
        if oversize:
            world.artifacts[101] = record(sha=sha, sizes=sizes(plain_text=2_000_000))
        if failed_check:
            world.checks[1]["conclusion"] = "failure"
        return world

    def decide(self, sha=None, standing="", **change):
        """What decide gives at the completion of the Tests run of `sha` (the head unless given), in a World of that
        commit with `change` (world's), and with the maintainer check's answer `standing`."""
        return self.run_decide(self.world(self.head if sha is None else sha, **change), 104, standing)

    def decide_merged(self, conclusion="success", **change):
        """What decide gives at the completion of an Enrollment merged run for the head, of that conclusion."""
        world = self.world(self.head, **change)
        world.run(MERGED_RUN, dispatch.MERGED_WORKFLOW, "pull_request_target", head_sha=self.head)
        world.runs[MERGED_RUN].update(conclusion=conclusion, display_title=f"merged #{PR}", created_at=self.tick())
        return self.run_decide(world, MERGED_RUN, "")

    def run_decide(self, world, run_id, standing):
        table = world.api().table
        table[f"repos/{REPO}/pulls/{PR}"] = self.pull()
        table[f"repos/{REPO}/pulls?state=open&base=main&head=FreeREAC:{self.BRANCH}&per_page=100"] = \
            [[self.pull()] if self.state == "open" else []]
        table[f"repos/{REPO}/issues/{PR}/events?per_page=100"] = \
            [self.events[i:i + 2] for i in range(0, len(self.events), 2)] or [[]]
        table[f"repos/{REPO}/pulls/{PR}/commits?per_page=100"] = \
            [[{"sha": sha} for sha in self.commits[i:i + 2]] for i in range(0, len(self.commits), 2)] or [[]]
        for sha in {run["head_sha"] for run in self.runs}:
            table[f"repos/{REPO}/actions/runs?head_sha={sha}&per_page=100"] = \
                [{"workflow_runs": [run for run in self.runs if run["head_sha"] == sha]}]
        for login, permission in self.collaborators.items():
            table[f"repos/{REPO}/collaborators/{login}/permission"] = {"permission": permission}
        api = LabelApi(table, self.runs, self.failing)
        old = dispatch.standing
        dispatch.standing = lambda config, login: standing
        try:
            return dispatch.decide(api, REPO, run_id, "pull_request_target", world.sha)
        finally:
            dispatch.standing = old
            self.calls += api.calls

    def job(self, out, push_after_label=None):
        """The dispatch job after decide gave `out`, as GitHub runs it: decide's outputs go through the decide job's
        outputs into the dispatch job's env; the job runs when its if is true; and of its steps, in order, those that
        check the values and write review-passed run when their if is true, until one fails. push_after_label is a
        commit pushed just after a label is put on, which is recorded after the step. Gives (name, process) of each
        step run."""
        decide, job = enroll_dispatch_jobs()
        ctx = {f"steps.decide.outputs.{key}": value for key, value in out.items()}
        ctx = {f"needs.decide.outputs.{key}": as_text(evaluate(value, ctx)) for key, value in decide["outputs"].items()}
        if not evaluate(job["if"], ctx):
            return []
        ctx.update({"github.repository": REPO, "steps.label-token.outputs.token": "stand-in"})

        def values(env):
            return {key: as_text(evaluate(value, ctx)) if "${{" in str(value) else str(value)
                    for key, value in (env or {}).items()}
        env = values(job["env"])
        state = {"labels": self.repo_labels, "events": {str(PR): self.events}, "collaborators": self.collaborators,
                 "pulls": {str(PR): {"state": self.state, "head_sha": self.head, "labels": self.labels}},
                 "clock": self.clock, "calls": [],
                 "after_add": {str(PR): {"head_sha": push_after_label}} if push_after_label else {}}
        ran = []
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = stand_in_gh(directory)
            (directory / "state.json").write_text(json.dumps(state))
            for step in job["steps"]:
                if step.get("name") not in (CHECK, TAKE_OFF, PUT_ON) \
                        or "if" in step and not evaluate(step["if"], {f"env.{k}": v for k, v in env.items()}):
                    continue
                ran.append((step["name"], subprocess.run(
                    ["bash", "-c", step["run"]], capture_output=True, text=True,
                    env={**os.environ, **env, **values(step.get("env")), "PATH": f"{bin}:{os.environ['PATH']}",
                         "GH_STATE": str(directory / "state.json"),
                         "GITHUB_STEP_SUMMARY": str(directory / "summary")})))
                if ran[-1][1].returncode != 0:
                    break
            state = json.loads((directory / "state.json").read_text())
        added = [e for e in state["events"][str(PR)][len(self.events):] if e["event"] == "labeled"]
        pull = state["pulls"][str(PR)]
        self.repo_labels, self.labels, self.events = state["labels"], pull["labels"], state["events"][str(PR)]
        self.clock, self.calls = state["clock"], self.calls + state["calls"]
        if pull["head_sha"] != self.head:
            self.push(pull["head_sha"])
        for _ in added:
            self.confirmed_run()
        return ran


class ReviewPassed(unittest.TestCase):
    """review-passed: each case runs decide on a Timeline of the pull request, and then, as the job would,
    enroll-dispatch.yml's steps that check decide's values and write the label, against the stand-in gh. Each asserts
    the pull request's labels after the runs, and that no request touched a comment."""
    A, B, C, H = SHA, NEWER, "c" * 40, "d" * 40

    def setUp(self):
        if not shutil.which("jq"):
            self.skipTest("jq is not installed")

    def job(self, line, out, **change):
        """The steps the job ran for `out`, each of which must succeed."""
        ran = line.job(out, **change)
        for name, run in ran:
            self.assertEqual(run.returncode, 0, f"{name}: {run.stdout}{run.stderr}")
        return [name for name, _ in ran]

    def assertLabels(self, line, labels):
        self.assertEqual(line.labels, labels, line.events)
        self.assertEqual([call for call in line.calls if "comments" in call], [])

    def labelled(self, **timeline):
        """(a): the run for head A sends an enrollment whose author has no write access, and the label goes on."""
        line = Timeline(**timeline)
        line.push(self.A)
        out = line.decide()
        self.assertEqual((out["decision"], out["review_passed"], out["review_passed_at"]), ("dispatch", "on", ""),
                         out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        self.assertLabels(line, [REVIEW_PASSED])
        return line

    def newest_label(self, line):
        return max(e["created_at"] for e in line.events if e["event"] == "labeled")

    def test_a_an_enrollment_sent_for_an_author_without_write_access_gets_the_label(self):
        for permission in ("read", "none"):
            with self.subTest(permission=permission):
                self.labelled(permission=permission)

    def test_b_a_new_pin_of_a_project_on_main_gets_the_label(self):
        line = Timeline()
        line.push(self.A)
        out = line.decide(files=[{"filename": "projects/plugin-hostd/project.yaml", "status": "modified"}])
        self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "on"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        self.assertLabels(line, [REVIEW_PASSED])

    def test_c_a_new_head_labelled_for_a_person_or_whose_review_is_not_success_loses_the_label(self):
        # After pull request #177, a review that is not success is the decision none, as in (d).
        for change, decision in (({"oversize": True}, ("label", "size-review")),
                                 ({"review": "action_required"}, ("none", ""))):
            with self.subTest(decision=decision):
                line = self.labelled()
                line.push(self.B)
                out = line.decide(**change)
                self.assertEqual((out["decision"], out["label"], out["review_passed"], out["review_passed_at"]),
                                 (*decision, "off", "head"), out["reason"])
                self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
                self.assertLabels(line, [])

    def test_d_a_new_head_whose_required_check_failed_loses_the_label(self):
        line = self.labelled()
        line.push(self.B)
        out = line.decide(failed_check=True)
        self.assertEqual((out["decision"], out["project"], out["review_passed"]), ("none", "", "off"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
        self.assertLabels(line, [])

    def test_e_a_new_head_that_is_sent_and_passes_again_has_the_label(self):
        line = self.labelled()
        line.push(self.B)
        pushed = line.runs[-1]["created_at"]
        out = line.decide()
        self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "on"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        self.assertLabels(line, [REVIEW_PASSED])
        self.assertGreater(self.newest_label(line), pushed)   # put on for B

    def test_f_a_label_a_person_took_off_is_not_put_back(self):
        for name in (REVIEW_PASSED, "passes-not-merging"):
            with self.subTest(name=name):
                line = Timeline()
                line.push(self.A)
                line.put_on(dispatch.APP_LOGIN, name)
                line.take_off("sjawhar", name)
                out = line.decide()
                self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", ""), out["reason"])
                self.assertEqual(self.job(line, out), [CHECK])
                self.assertLabels(line, [])

    def test_f_negative_control_a_label_the_app_took_off_is_put_back(self):
        line = Timeline()
        line.push(self.A)
        line.put_on(dispatch.APP_LOGIN)
        line.take_off(dispatch.APP_LOGIN)
        out = line.decide()
        self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "on"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        self.assertLabels(line, [REVIEW_PASSED])

    def test_g_a_trusted_author_does_not_get_the_label(self):
        self.assertIn("sjawhar-agent[bot]", WF["env"]["ALLOWED_BOTS"].split(","))
        for author, permission in (("a-writer", "write"), ("an-admin", "admin"), ("sjawhar-agent[bot]", None)):
            with self.subTest(author=author):
                line = Timeline(author=author, permission=permission)
                line.push(self.A)
                out = line.decide()
                self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", ""), out["reason"])
                self.assertEqual(self.job(line, out), [CHECK])
                self.assertLabels(line, [])

    def test_h_a_merge_or_a_close_takes_the_label_off(self):
        for merged, change, decision in ((True, {}, ("dispatch", "", "true")),
                                         (True, {"oversize": True}, ("label", "size-review", "")),
                                         (True, {"failed_check": True}, ("none", "", "")),
                                         (False, {}, ("none", "", ""))):
            with self.subTest(merged=merged, decision=decision):
                line = self.labelled()
                line.close(merged)
                out = line.decide_merged("success" if merged else "skipped", **change)
                self.assertEqual((out["decision"], out["label"], out.get("merged", "")), decision, out["reason"])
                self.assertEqual((out["pr"], out["review_passed"], out["review_passed_at"]), (str(PR), "off", "closed"))
                self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
                self.assertLabels(line, [])

    def test_i_the_label_is_made_or_given_its_description(self):
        other = {"name": "size-review", "color": "ededed", "description": ""}
        for repo_labels in ([other], [other, {"name": REVIEW_PASSED, "color": "0E8A16", "description": "Passes."}]):
            with self.subTest(repo_labels=repo_labels):
                line = self.labelled(repo_labels=copy.deepcopy(repo_labels))
                self.assertEqual([label for label in line.repo_labels if label["name"] == REVIEW_PASSED],
                                 [{"name": REVIEW_PASSED, "color": "0E8A16", "description": DESCRIPTION}])
                self.assertIn(other, line.repo_labels)
                self.assertLabels(line, [REVIEW_PASSED])

    def test_j_a_review_that_is_not_success_gets_no_label_and_an_optional_fail_does(self):
        for review in ("failure", "action_required", None):
            with self.subTest(review=review):
                line = Timeline()
                line.push(self.A)
                out = line.decide(review=review)
                self.assertEqual((out["decision"], out["review_passed"]), ("none", ""), out["reason"])
                self.assertEqual(self.job(line, out), [])
                self.assertLabels(line, [])
        with self.subTest(review="success, with an optional fail of F5 or F8"):
            line = Timeline()
            line.push(self.A)
            out = line.decide(review="success")
            self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "on"), out["reason"])
            self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
            self.assertLabels(line, [REVIEW_PASSED])

    def test_k_a_late_run_for_an_old_head_leaves_the_label(self):
        line = self.labelled()
        line.push(self.B)
        out = line.decide()
        self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "on"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        out = line.decide(sha=self.A)
        self.assertEqual((out["decision"], out["review_passed"]), ("none", ""), out["reason"])
        self.assertEqual(self.job(line, out), [])
        self.assertLabels(line, [REVIEW_PASSED])

    def test_l_a_label_that_lands_after_a_push_comes_off(self):
        line = Timeline()
        line.push(self.A)
        out = line.decide()
        self.assertEqual(out["review_passed"], "on", out["reason"])
        self.assertEqual(self.job(line, out, push_after_label=self.B), [CHECK, PUT_ON])
        self.assertEqual(line.head, self.B)
        self.assertEqual([e["event"] for e in line.events], ["labeled", "unlabeled"])
        self.assertLabels(line, [])

    def test_m_a_new_head_whose_review_is_not_success_loses_the_label(self):
        line = self.labelled()
        line.push(self.B)
        out = line.decide(review="failure")
        self.assertEqual((out["decision"], out["review_passed"], out["review_passed_at"]), ("none", "off", "head"),
                         out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
        self.assertLabels(line, [])

    def test_n_a_label_put_on_by_hand_under_its_former_name_stays_whatever_its_head_decides(self):
        # Pull request #124: one labeled passes-not-merging by sjawhar-agent[bot] after its head's first run, and a
        # review whose F5 and F8 fails are optional, so its check run Enrollment review is success.
        line = Timeline()
        line.push(self.A)
        line.put_on("sjawhar-agent[bot]", "passes-not-merging")
        for change, decision, steps in (({}, ("dispatch", ""), [CHECK]),
                                        ({"standing": "not shown to maintain it"}, ("label", "maintainer-review"),
                                         [CHECK]),
                                        ({"failed_check": True}, ("none", ""), []),
                                        ({"review": "action_required"}, ("none", ""), [])):
            with self.subTest(decision=decision, change=change):
                out = line.decide(**change)
                self.assertEqual((out["decision"], out["label"], out["review_passed"]), (*decision, ""), out["reason"])
                self.assertEqual(self.job(line, out), steps)
                self.assertLabels(line, [REVIEW_PASSED])

    def test_p_a_take_off_for_a_head_that_moved_meanwhile_leaves_the_label(self):
        line = self.labelled()
        line.push(self.B)
        out = line.decide(failed_check=True)
        self.assertEqual((out["sha"], out["review_passed"]), (self.B, "off"), out["reason"])
        line.push(self.C)
        self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
        self.assertLabels(line, [REVIEW_PASSED])

    def test_q_a_trusted_or_unknown_author_loses_the_label_at_a_new_head(self):
        with self.subTest(author="trusted"):
            line = Timeline(author="a-writer", permission="write")
            line.push(self.A)
            line.put_on(dispatch.APP_LOGIN)
            line.push(self.B)
            out = line.decide()
            self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "off"), out["reason"])
            self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
            self.assertLabels(line, [])
        with self.subTest(author="a trust read that fails"):
            line = self.labelled()
            line.push(self.B)
            line.failing.add(f"repos/{REPO}/collaborators/linuxnow/permission")
            out = line.decide()
            self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", "off"), out["reason"])
            self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
            self.assertLabels(line, [])

    def test_r_a_new_head_with_a_file_outside_projects_loses_the_label(self):
        line = self.labelled()
        line.push(self.B)
        out = line.decide(files=[{"filename": "projects/plugin-hostd/build.sh", "status": "added"},
                                 {"filename": "README.md", "status": "modified"}])
        self.assertEqual((out["decision"], out["review_passed"]), ("none", "off"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
        self.assertLabels(line, [])

    def test_s_a_head_pushed_again_by_force_loses_the_label_of_the_head_between(self):
        # No maintainer-confirmed.yml runs here: the force push alone shows that the label is older than A (v has the
        # run that a label starts).
        line = self.labelled(confirmed_runs=False)
        line.push(self.B)
        out = line.decide()
        self.assertEqual(out["review_passed"], "on", out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        line.push(self.A, force=True)
        out = line.decide(failed_check=True)
        self.assertEqual((out["decision"], out["review_passed"]), ("none", "off"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
        self.assertLabels(line, [])

    def test_t_a_take_off_decided_before_a_renewal_leaves_the_label(self):
        line = self.labelled()
        line.push(self.B)
        none = line.decide(failed_check=True)
        sent = line.decide()
        self.assertEqual((none["review_passed"], sent["review_passed"]), ("off", "on"),
                         (none["reason"], sent["reason"]))
        self.assertEqual(self.job(line, sent), [CHECK, PUT_ON])
        self.assertGreater(self.newest_label(line), none["label_at"])   # put on again
        self.assertEqual(self.job(line, none), [CHECK, TAKE_OFF])
        self.assertLabels(line, [REVIEW_PASSED])

    def test_u_a_failed_read_of_the_events_changes_nothing(self):
        events = f"repos/{REPO}/issues/{PR}/events?per_page=100"
        with self.subTest(label="on, at a new head"):
            line = self.labelled()
            line.push(self.B)
            line.failing.add(events)
            out = line.decide(oversize=True)
            self.assertEqual((out["decision"], out["review_passed"]), ("label", ""), out["reason"])
            self.assertEqual(self.job(line, out), [CHECK])
            self.assertLabels(line, [REVIEW_PASSED])
        with self.subTest(label="off, on a passing run"):
            line = Timeline()
            line.push(self.A)
            line.failing.add(events)
            out = line.decide()
            self.assertEqual((out["decision"], out["review_passed"]), ("dispatch", ""), out["reason"])
            self.assertEqual(self.job(line, out), [CHECK])
            self.assertLabels(line, [])

    def test_v_a_head_pushed_again_without_a_force_push_loses_a_label_put_on_at_another_head(self):
        # H, a force push back to A, A labelled (which starts a maintainer-confirmed.yml run at A), H pushed again.
        line = Timeline()
        line.push(self.H)
        line.push(self.A, force=True)
        out = line.decide()
        self.assertEqual(out["review_passed"], "on", out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
        self.assertTrue(any(run["head_sha"] == self.A and run["path"] == dispatch.CONFIRMED_WORKFLOW
                            and run["created_at"] > self.newest_label(line) for run in line.runs))
        line.push(self.H)
        out = line.decide(failed_check=True)
        self.assertEqual((out["decision"], out["review_passed"]), ("none", "off"), out["reason"])
        self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
        self.assertLabels(line, [])

    def test_w_a_label_a_person_takes_off_after_decide_is_not_put_back(self):
        labels = f"POST repos/{REPO}/issues/{PR}/labels"
        with self.subTest(change="a renewal"):
            line = self.labelled()
            line.push(self.B)
            out = line.decide()
            self.assertEqual((out["decision"], out["review_passed"], out["review_passed_at"]),
                             ("dispatch", "on", "head"), out["reason"])
            line.take_off("sjawhar")   # after decide read the events, before the job runs
            before = len(line.calls)
            self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
            self.assertNotIn(labels, line.calls[before:])
            self.assertLabels(line, [])
        with self.subTest(change="a first put-on"):
            line = Timeline()
            line.push(self.A)
            out = line.decide()
            self.assertEqual((out["decision"], out["review_passed"], out["review_passed_at"]), ("dispatch", "on", ""),
                             out["reason"])
            line.put_on("a-member")   # after decide, someone puts it on and a person takes it off
            line.take_off("sjawhar")
            before = len(line.calls)
            self.assertEqual(self.job(line, out), [CHECK, PUT_ON])
            self.assertNotIn(labels, line.calls[before:])
            self.assertLabels(line, [])

    def test_x_a_run_of_another_pull_request_from_the_same_branch_leaves_the_label(self):
        # The branch was the head of a pull request closed before, at E, which is not among this one's commits. A label
        # event on that one starts a maintainer-confirmed.yml run at E, after this one's label.
        E = "e" * 40
        commits = f"repos/{REPO}/pulls/{PR}/commits?per_page=100"
        for change, decision, steps in (({"review": "action_required"}, ("none", ""), []),
                                        ({"failed_check": True}, ("none", ""), [])):
            with self.subTest(change=change):
                line = self.labelled()
                line.tick(3)
                line.add_run(E, dispatch.CONFIRMED_WORKFLOW, "pull_request_target")
                out = line.decide(**change)
                self.assertEqual((out["decision"], out["label"], out["review_passed"]), (*decision, ""), out["reason"])
                self.assertIn(commits, line.calls)
                self.assertEqual(self.job(line, out), steps)
                self.assertLabels(line, [REVIEW_PASSED])
        with self.subTest(change="GitHub lists 250 commits, so every run at another commit counts"):
            line = self.labelled()
            line.commits += [f"{i:040x}" for i in range(249)]
            line.add_run(E, dispatch.CONFIRMED_WORKFLOW, "pull_request_target")
            out = line.decide(failed_check=True)
            self.assertEqual((out["decision"], out["review_passed"]), ("none", "off"), out["reason"])
            self.assertEqual(self.job(line, out), [CHECK, TAKE_OFF])
            self.assertLabels(line, [])


class TrustRule(unittest.TestCase):
    """enroll-dispatch's trusted, the port of build.yaml's bash function trusted, gives its answers."""

    def test_trusted_answers_as_build_yamls_trusted(self):
        if not shutil.which("jq"):
            self.skipTest("jq is not installed")
        copies = {found for job in WF["jobs"].values() for step in job.get("steps") or []
                  for found in re.findall(r"# trusted\n(.*?)# end of trusted\n", step.get("run") or "", re.S)}
        self.assertEqual(len(copies), 1, copies)
        script = "set -uo pipefail\n" + copies.pop() + 'trusted "$1"\n'
        bots = WF["env"]["ALLOWED_BOTS"]
        collaborators = {"an-admin": "admin", "a-writer": "write", "a-reader": "read", "no-access": "none"}
        api = LabelApi({f"repos/{REPO}/collaborators/{login}/permission": {"permission": permission}
                        for login, permission in collaborators.items()},
                       failing={f"repos/{REPO}/collaborators/a-failure/permission"})
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = stand_in_gh(directory)
            (directory / "state.json").write_text(json.dumps({"labels": [], "pulls": {}, "events": {},
                                                              "collaborators": collaborators, "calls": []}))
            for login, want in (("sjawhar-agent[bot]", True), ("dependabot[bot]", False), ("Sjawhar-Agent[bot]", False),
                                ("an-admin", True), ("a-writer", True), ("a-reader", False), ("no-access", False),
                                ("not a login", False), ("x/y", False), ("", False), ("a-failure", None)):
                with self.subTest(login=login):
                    run = subprocess.run(["bash", "-c", script, "trusted", login], capture_output=True, text=True,
                                         env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "REPO": REPO,
                                              "GH_STATE": str(directory / "state.json"), "ALLOWED_BOTS": bots})
                    self.assertIn(run.returncode, (0, 1, 2), run.stderr)
                    self.assertEqual((dispatch.trusted(api, REPO, login), {0: True, 1: False, 2: None}[run.returncode]),
                                     (want, want), run.stderr)


if __name__ == "__main__":
    unittest.main()
