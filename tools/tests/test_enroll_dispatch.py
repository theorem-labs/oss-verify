# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/enroll-dispatch and the jobs around it, offline, with a fake GitHub API:
python3 -m pytest tools/tests/test_enroll_dispatch.py"""
import copy
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
import unittest
import zipfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
LOADER = importlib.machinery.SourceFileLoader("enroll_dispatch", str(ROOT / ".github" / "scripts" / "enroll-dispatch"))
SPEC = importlib.util.spec_from_loader("enroll_dispatch", LOADER)
dispatch = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(dispatch)
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
REQUIRED = ["enrollment", "project-builds", "terms-accepted", "tests"]
# The run of each required check: its id, and the workflow file and event that make it.
RUNS = {"project-builds": (101, ".github/workflows/build.yaml", "pull_request_target"),
        "enrollment": (102, ".github/workflows/validate.yaml", "pull_request_target"),
        "terms-accepted": (103, ".github/workflows/terms.yaml", "pull_request_target"),
        "tests": (104, ".github/workflows/tests.yaml", "pull_request")}
HAND_RUN = 900


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
    """One enrollment pull request whose four required checks passed at SHA, and Build run 101's record of it."""

    def __init__(self):
        self.checks = []  # check runs at SHA
        self.runs = {}
        self.artifacts = {}
        for i, name in enumerate(REQUIRED):
            run_id, path, event = RUNS[name]
            self.check(500 + i, name, run_id)
            self.run(run_id, path, event)
        self.artifacts[101] = record()
        self.files = [{"filename": "projects/plugin-hostd/project.yaml", "status": "added"},
                      {"filename": "projects/plugin-hostd/build.sh", "status": "added"}]
        self.pulls = [self.pull()]
        self.project_yaml = b"repo: https://example.invalid/x\nlanguage: c\n"
        self.required = list(REQUIRED)

    def check(self, check_id, name, run_id, conclusion="success", app=ACTIONS, repo=REPO):
        self.checks.append({"id": check_id, "name": name, "app": {"id": app}, "status": "completed",
                            "conclusion": conclusion,
                            "details_url": f"https://github.com/{repo}/actions/runs/{run_id}/job/{check_id + 9000}"})

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
            f"repos/{REPO}/commits/{SHA}/check-runs?filter=all&per_page=100": [{"check_runs": self.checks}],
            f"repos/{REPO}/pulls/{PR}": Calls(*self.pulls),
            f"repos/{REPO}/pulls/{PR}/files?per_page=100": [self.files],
            f"repos/{REPO}/contents/projects/plugin-hostd/project.yaml?ref={SHA}": self.project_yaml,
        }
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

    def decide(self, event="pull_request_target", run_id=104, sha=SHA):
        return dispatch.decide(self.api(), REPO, run_id, event, sha)


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

    def test_the_workflow_takes_the_label_and_takes_it_off_when_sent(self):
        text = (ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text()
        self.assertIn("label/maintainer-review)", text)
        self.assertIn("size-review|language-paused|name-review|maintainer-review)", text)

    def test_a_fork_does_not_pass_whoever_owns_it(self):
        fork = {"full_name": "someone/plugin-hostd", "owner": {"login": "someone"}, "fork": True,
                "parent": {"full_name": "FreeREAC/plugin-hostd"}}
        why, seen = self.standing(self.GITHUB, dispatch.triage.OK, meta=fork)
        self.assertEqual(why, "someone/plugin-hostd is a fork of FreeREAC/plugin-hostd, so owning it shows nothing")
        self.assertNotIn("row", seen)
        why, _ = self.standing(self.GITHUB, dispatch.triage.OK, meta={**self.META, "fork": None})
        self.assertIn("is a fork of another repository", why)

    def confirmed(self, labeller, label="maintainer-confirmed", events=True, at="2026-10-28T05:00:00Z"):
        world = World()
        world.runs[101]["created_at"] = "2026-10-28T04:00:00Z"  # the Build run of the head commit, made at its push
        world.pulls = [dict(world.pull(), user={"login": "someone"}, labels=[{"name": label}])]
        api = world.api()
        api.table[f"repos/{REPO}/issues/{PR}/events?per_page=100"] = [[
            {"event": "labeled", "label": {"name": label}, "actor": {"login": labeller}, "created_at": at}]
            if events else []]
        old = dispatch.standing
        dispatch.standing = lambda config, login: f"{login} is not shown to maintain it"
        try:
            return dispatch.decide(api, REPO, 104, "pull_request_target", SHA)
        finally:
            dispatch.standing = old

    def test_the_label_put_by_someone_else_lifts_the_hold(self):
        got = self.confirmed("a-member")
        self.assertEqual(got["decision"], "dispatch", got["reason"])
        self.assertIn("a-member labelled it maintainer-confirmed", got["reason"])

    def test_the_label_put_by_the_author_or_with_no_record_or_another_label_does_not(self):
        for case in ({"labeller": "someone"}, {"labeller": "SomeOne"}, {"labeller": "a-member", "events": False},
                     {"labeller": "a-member", "label": "other"},
                     # put on before the head commit was pushed: it saw another commit, maybe another `repo`
                     {"labeller": "a-member", "at": "2026-10-28T03:59:59Z"}, {"labeller": "a-member", "at": None}):
            got = self.confirmed(**case)
            self.assertEqual((got["decision"], got["label"]), ("label", "maintainer-review"), case)

    def test_a_label_run_that_was_skipped_decides_nothing(self):
        world = World()
        world.run(700, dispatch.CONFIRMED_WORKFLOW, "pull_request_target")
        world.runs[700]["conclusion"] = "skipped"
        got = world.decide(run_id=700)
        self.assertEqual(got["decision"], "none")
        self.assertIn("a label other than maintainer-confirmed", got["reason"])
        world.runs[700]["conclusion"] = "success"
        self.assertEqual(world.decide(run_id=700)["decision"], "dispatch")

    def test_putting_the_label_on_runs_the_decision_again(self):
        confirmed = yaml.safe_load((ROOT / ".github" / "workflows" / "maintainer-confirmed.yml").read_text())
        self.assertEqual(confirmed[True], {"pull_request_target": {"types": ["labeled"]}})
        self.assertEqual(confirmed["permissions"], {})
        self.assertEqual(confirmed["name"], "Maintainer confirmed")
        dispatch_flow = yaml.safe_load((ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text())
        self.assertIn("Maintainer confirmed", dispatch_flow[True]["workflow_run"]["workflows"])


class TheRecord(unittest.TestCase):
    """build.yaml's own code, run here: binary-sizes on a work directory, then the record job's script, then the
    record read back as enroll-dispatch reads it."""

    def test_binary_sizes_and_the_record_job_make_a_record_enroll_dispatch_takes(self):
        if not shutil.which("jq"):
            self.skipTest("jq is not installed")
        sys.path.insert(0, str(ROOT / "tools" / "tests"))
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
    """Which jobs hold what: the lines of the workflows' headers, as tests."""

    def jobs(self, name):
        return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())["jobs"]

    def test_marking_a_draft_ready_runs_build_and_its_completion_runs_enroll_dispatch(self):
        # A draft is never sent, so ready_for_review must start a run whose completion decides again.
        def on(name):
            data = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())
            return data.get("on", data.get(True))
        self.assertIn("ready_for_review", on("build.yaml")["pull_request_target"]["types"])
        build_name = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["name"]
        self.assertIn(build_name, on("enroll-dispatch.yml")["workflow_run"]["workflows"])
        self.assertIn("pull_request_target", dispatch.REQUIRED_SOURCES["project-builds"])

    def test_only_the_dispatch_job_reads_the_app_key(self):
        jobs = self.jobs("enroll-dispatch.yml")
        self.assertEqual({n for n, j in jobs.items() if (j.get("permissions") or {}).get("id-token") == "write"},
                         {"dispatch"})
        self.assertEqual({n: j.get("environment") for n, j in jobs.items() if "environment" in j},
                         {"dispatch": {"name": "comment", "deployment": False}})
        steps = jobs["dispatch"]["steps"]
        checkouts = [s["with"] for s in steps if str(s.get("uses", "")).startswith("actions/checkout")]
        self.assertEqual(checkouts, [{"persist-credentials": False, "sparse-checkout": ".github/scripts"}])
        self.assertEqual([s["run"] for s in steps if "run" in s and ".github/scripts" in s["run"]],
                         [".github/scripts/app-token"])
        self.assertNotIn("write", (jobs["decide"].get("permissions") or {}).values())

    def test_the_workflow_names_no_other_theorem_labs_repository(self):
        # The event's target is named by its id alone, so that this public file and its log name no private
        # repository.
        text = (ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text()
        named = set(re.findall(r"theorem-labs/([A-Za-z0-9._-]+)", text))
        self.assertLessEqual(named, {"oss-verify"}, named)
        self.assertIn('INTERNAL_ID: "1425069221"', text)

    def test_the_record_job_runs_no_code_of_the_pull_request_and_holds_nothing(self):
        job = self.jobs("build.yaml")["record"]
        self.assertEqual(job["permissions"], {})
        self.assertNotIn("environment", job)
        uses = [s["uses"].split("@")[0] for s in job["steps"] if "uses" in s]
        self.assertEqual(uses, ["actions/upload-artifact"])
        # A re-run of the job replaces the record, so that enroll-dispatch finds exactly one.
        self.assertIs([s for s in job["steps"] if "uses" in s][0]["with"]["overwrite"], True)
        self.assertNotIn("secrets.", yaml.safe_dump(job))


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


if __name__ == "__main__":
    unittest.main()
