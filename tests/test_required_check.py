# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/required-check and .github/workflows/required-checks.yml, offline, with a fake GitHub API:
uv run pytest tests/test_required_check.py

The workflow posts main's four required checks as the oss-verify App, each with the conclusion of the job of that name
in the newest pull_request run of the check's own workflow file at the pull request's head, or in the run GitHub kept
when it cancelled that one for a run created in the same second. These test what the script decides from the API's
answers, for a run of a head and for a run by hand with a head_sha, the read job's condition on the event, what each
job holds, and the steps that read, check and post, run with a stand-in gh.
"""
import copy
import importlib.machinery
import importlib.util
import json
import pathlib

import pytest

from test_outside_screen import Runner, evaluate, interpolated, read_workflow

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("required_check", str(ROOT / ".github" / "scripts" / "required-check"))
SPEC = importlib.util.spec_from_loader("required_check", LOADER)
required = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(required)
WORKFLOW = read_workflow("required-checks.yml")
READ = WORKFLOW["jobs"]["read"]
POST = WORKFLOW["jobs"]["post"]

REPO = "theorem-labs/oss-verify"
SHA = "7e8e28d95389c7261efeb48e4114cd1186bf8e7e"
NEWER = "1" * 40
FORK = "mallory/oss-verify"
BRANCH = "add-libx"
PR = 7
APP = 5447700
# Each required check's workflow file, by its check.
FILES = {"project-builds": ".github/workflows/build.yaml", "enrollment": ".github/workflows/validate.yaml",
         "tests": ".github/workflows/tests.yaml", "terms-accepted": ".github/workflows/terms.yaml"}
CHECKS = list(FILES)


class FakeApi:
    """GitHub's API from a table of answers by path; a path not in it fails, as a 404 makes gh fail."""

    def __init__(self, table):
        self.table, self.calls = table, []

    def pages(self, path):
        self.calls.append(path)
        if path not in self.table:
            raise AssertionError(f"an unexpected read: {path}")
        return copy.deepcopy(self.table[path])


class World:
    """Pull request `number` (7) from mallory/oss-verify's branch `branch` (add-libx) into main, at `sha` (SHA). Each of
    the four workflow files has one run on pull_request at that commit from that head, completed, whose job of the
    check's name passed beside one other job; the App has posted no check at that commit. Run and job ids start after
    `base`, so that two worlds can share one API."""

    def __init__(self, sha=SHA, number=PR, branch=BRANCH, base=0):
        self.sha, self.number, self.branch = sha, number, branch
        self.pulls = [self.pull(sha=sha, branch=branch, number=number)]
        self.runs = {path: [] for path in FILES.values()}
        self.jobs = {}
        self.app_checks = []
        for i, name in enumerate(CHECKS):
            self.run(base + 101 + i, FILES[name])
            self.job(base + 101 + i, base + 1001 + i, name)
            self.job(base + 101 + i, base + 2001 + i, f"{name}-helper")

    @staticmethod
    def pull(sha=SHA, state="open", base="main", head_repo=FORK, branch=BRANCH, number=PR):
        return {"number": number, "state": state, "head": {"sha": sha, "ref": branch, "repo": {"full_name": head_repo}},
                "base": {"ref": base, "repo": {"full_name": REPO}}}

    def run(self, run_id, path, status="completed", conclusion: str | None = "success", event="pull_request", sha=None,
            head_repo=FORK, branch=None, attempt=1, listed_under=None, created=None):
        """A run of `path`, listed in the answer for the file `listed_under` (`path` unless given): GitHub lists the runs
        of one workflow, and a test gives an answer that holds a run of another file too. `created` is its created_at,
        which GitHub gives to the second; a run with none has none."""
        self.runs.setdefault(listed_under or path, []).append(
            {"id": run_id, "path": path, "event": event, "head_sha": sha or self.sha,
             "head_branch": branch or self.branch, "head_repository": {"full_name": head_repo},
             "run_attempt": attempt, "status": status, "conclusion": conclusion,
             **({"created_at": created} if created else {})})
        self.jobs.setdefault(run_id, [])

    def job(self, run_id, job_id, name, status="completed", conclusion="success", url=None):
        self.jobs.setdefault(run_id, []).append(
            {"id": job_id, "name": name, "status": status, "conclusion": conclusion if status == "completed" else None,
             "html_url": url or f"https://github.com/{REPO}/actions/runs/{run_id}/job/{job_id}"})

    def app_check(self, check_id, name, external_id, status="completed", conclusion="success", app=APP):
        self.app_checks.append({"id": check_id, "name": name, "app": {"id": app}, "status": status,
                                "conclusion": conclusion if status == "completed" else None,
                                "external_id": external_id})

    def table(self):
        table = {
            f"repos/{REPO}/pulls?state=open&base=main&head=mallory:{self.branch}&per_page=100": [self.pulls],
            f"repos/{REPO}/commits/{self.sha}/check-runs?app_id={APP}&filter=all&per_page=100":
                [{"check_runs": self.app_checks}],
        }
        for path, runs in self.runs.items():
            name = path.rsplit("/", 1)[1]
            table[f"repos/{REPO}/actions/workflows/{name}/runs?event=pull_request&head_sha={self.sha}&per_page=100"] = \
                [{"workflow_runs": runs}]
        for run_id, jobs in self.jobs.items():
            table[f"repos/{REPO}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"] = [{"jobs": jobs}]
        return table

    def api(self):
        return FakeApi(self.table())

    def decide(self, path=FILES["tests"], event="pull_request", sha=SHA, head=(FORK, BRANCH)):
        api = self.api()
        posts, lines = required.decide(api, REPO, event, path, sha, head)
        return posts, lines, api


# The read of every open pull request into main, which a run by hand makes to find the one at its head_sha.
OPEN_PULLS = f"repos/{REPO}/pulls?state=open&base=main&per_page=100"


def open_api(*worlds, extra=()):
    """One API for the pull requests of `worlds` and the pull requests `extra`, as a run by hand reads them."""
    table = {}
    for world in worlds:
        table.update(world.table())
    table[OPEN_PULLS] = [[p for world in worlds for p in world.pulls] + list(extra)]
    return FakeApi(table)


def by_name(posts):
    return {p["name"]: p for p in posts}


def step(name):
    """The step `name` of the job read or the job post: each name is one step of the two."""
    found = [s for job in (READ, POST) for s in job["steps"] if s.get("name") == name]
    assert len(found) == 1, (name, len(found))
    return found[0]


# The second in which #317's two Terms runs, 45815765408 and 45815765694, were both created; and two seconds later.
SECOND, LATER = "2026-11-26T12:01:15Z", "2026-11-26T12:01:17Z"


def two_runs(name, older, newer, newer_created=SECOND, **older_run):
    """World, where the check `name`'s file lists its run 101 + i (job 1001 + i), created at SECOND, ended `older`
    (in_progress: not ended), and its newer run 201 (job 3001), created at `newer_created`, ended `newer`. Each
    conclusion is its run's and its job's. `older_run` changes the older run (its event or path, say)."""
    world = World()
    i = CHECKS.index(name)
    ended = older != "in_progress"
    world.runs[FILES[name]][0].update(created_at=SECOND, status="completed" if ended else "in_progress",
                                      conclusion=older if ended else None, **older_run)
    world.jobs[101 + i][0].update(status="completed" if ended else "in_progress", conclusion=older if ended else None)
    world.run(201, FILES[name], conclusion=newer, created=newer_created)
    world.job(201, 3001, name, conclusion=newer)
    return world, f"job {1001 + i}"


@pytest.mark.parametrize("name", CHECKS)
def test_of_two_runs_created_in_one_second_the_one_github_kept_gives_the_check(name):
    # #317: GitHub cancelled the newer run and kept the older, which passed.
    world, older_job = two_runs(name, "success", "cancelled")
    got = by_name(world.decide()[0])[name]
    assert (got["conclusion"], got["external_id"]) == ("success", older_job)
    # #303 (Tests runs 45289626179 and 45289627860, both created at 23:32:03Z): GitHub cancelled the older, and the
    # newer failed.
    world, _ = two_runs(name, "cancelled", "failure")
    got = by_name(world.decide()[0])[name]
    assert (got["conclusion"], got["external_id"]) == ("failure", "job 3001")


@pytest.mark.parametrize("name", CHECKS)
@pytest.mark.parametrize("older, newer_created, older_run", [
    # Created two seconds apart: the older can have read an older input.
    ("success", LATER, {}),
    # Created in one second, but the older was cancelled too, or has not ended.
    ("cancelled", SECOND, {}),
    ("in_progress", SECOND, {}),
    # Created in one second, but the older is a run of another event, or of another file with the check's workflow
    # name, that GitHub lists under the check's file.
    ("success", SECOND, {"event": "pull_request_target"}),
    ("success", SECOND, {"path": ".github/workflows/other.yaml"}),
])
def test_a_cancelled_newest_run_stands_without_a_twin_that_ended_otherwise(name, older, newer_created, older_run):
    world, _ = two_runs(name, older, "cancelled", newer_created, **older_run)
    got = by_name(world.decide()[0])[name]
    assert (got["conclusion"], got["external_id"]) == ("cancelled", "job 3001")


def test_runs_with_no_creation_time_are_no_twins():
    world, _ = two_runs("tests", "success", "cancelled", newer_created=None)
    world.runs[FILES["tests"]][0].pop("created_at")
    got = by_name(world.decide()[0])["tests"]
    assert (got["conclusion"], got["external_id"]) == ("cancelled", "job 3001")


class TestPosts:
    def test_a_head_whose_four_runs_ended_gets_the_four_checks_of_their_jobs(self):
        posts, lines, _ = World().decide()
        assert [p["name"] for p in posts] == CHECKS, lines
        for i, name in enumerate(CHECKS):
            run_id, job_id = 101 + i, 1001 + i
            assert posts[i] == {
                "name": name, "head_sha": SHA, "status": "completed", "conclusion": "success",
                "details_url": f"https://github.com/{REPO}/actions/runs/{run_id}/job/{job_id}",
                "external_id": f"job {job_id}",
                "output": {"title": f"{name}: success",
                           "summary": f"[The job `{name}`](https://github.com/{REPO}/actions/runs/{run_id}/job/{job_id})"
                                      f" of run [{run_id}](https://github.com/{REPO}/actions/runs/{run_id}), attempt 1,"
                                      f" of `{FILES[name]}` on pull request #{PR} at `{SHA}` ended `success`."}}

    def test_every_run_of_the_workflow_reads_all_four_checks(self):
        # The run of any of the four files posts what is due for each, so a lost run of the workflow costs nothing.
        for path in FILES.values():
            posts, lines, _ = World().decide(path=path)
            assert [p["name"] for p in posts] == CHECKS, (path, lines)

    def test_what_the_app_already_says_is_not_posted_again(self):
        world = World()
        for i, name in enumerate(CHECKS):
            world.app_check(500 + i, name, f"job {1001 + i}")
        posts, lines, _ = world.decide()
        assert posts == [], lines
        assert "tests: the App's check already says success for job 1003." in lines
        # Another conclusion, an older job, or another App's check of the name: posted.
        world.app_check(600, "tests", "job 1003", conclusion="failure")
        world.app_check(601, "enrollment", "job 999")
        world.app_check(602, "terms-accepted", "job 1004", conclusion="failure")
        world.app_check(603, "terms-accepted", "job 1004", app=15368)
        posts, lines, _ = world.decide()
        assert [p["name"] for p in posts] == ["enrollment", "tests", "terms-accepted"], lines
        # GitHub gives newest-first answers too. The id, not either end of the list, decides.
        world.app_checks.reverse()
        posts, lines, _ = world.decide()
        assert [p["name"] for p in posts] == ["enrollment", "tests", "terms-accepted"], lines

    def test_the_check_is_the_jobs_conclusion_not_the_runs(self):
        # tests.yaml's run failed in another job, and its job tests passed: GitHub Actions' check tests passed too.
        world = World()
        world.runs[FILES["tests"]][0]["conclusion"] = "failure"
        world.jobs[103][1]["conclusion"] = "failure"
        assert by_name(world.decide()[0])["tests"]["conclusion"] == "success"
        world.runs[FILES["tests"]][0].update(status="in_progress", conclusion=None)
        assert by_name(world.decide()[0])["tests"]["conclusion"] == "success"
        # The job failed, was skipped, or ended with a conclusion GitHub does not name for a check run.
        for conclusion, want in (("failure", "failure"), ("skipped", "skipped"), ("cancelled", "cancelled"),
                                 ("neutral", "neutral"), ("action_required", "action_required"),
                                 ("timed_out", "timed_out"), ("startup_failure", "failure"), (None, "failure")):
            world = World()
            world.jobs[103][0]["conclusion"] = conclusion
            assert by_name(world.decide()[0])["tests"]["conclusion"] == want, conclusion

    def test_the_newest_run_of_the_file_at_the_head_decides(self):
        world = World()
        world.run(201, FILES["tests"], conclusion="failure")
        world.job(201, 3001, "tests", conclusion="failure")
        got = by_name(world.decide()[0])["tests"]
        assert (got["conclusion"], got["external_id"]) == ("failure", "job 3001")
        world.runs[FILES["tests"]].reverse()
        got = by_name(world.decide()[0])["tests"]
        assert (got["conclusion"], got["external_id"]) == ("failure", "job 3001")
        # A newer re-run of the same run (attempt 2) is the run's latest attempt, whose jobs the API gives.
        world = World()
        world.runs[FILES["tests"]][0]["run_attempt"] = 2
        world.jobs[103][0].update(id=4001, conclusion="failure",
                                  html_url=f"https://github.com/{REPO}/actions/runs/103/job/4001")
        got = by_name(world.decide()[0])["tests"]
        assert (got["conclusion"], got["external_id"]) == ("failure", "job 4001")
        assert "attempt 2" in got["output"]["summary"]

    def test_the_matching_run_and_job_can_be_on_a_later_page(self):
        world = World()
        world.jobs[103][0]["conclusion"] = "failure"
        world.run(301, FILES["tests"], branch="another-head")
        api = world.api()
        api.table[f"repos/{REPO}/actions/workflows/tests.yaml/runs?event=pull_request&head_sha={SHA}&per_page=100"] = [
            {"workflow_runs": [world.runs[FILES["tests"]][1]]},
            {"workflow_runs": [world.runs[FILES["tests"]][0]]},
        ]
        api.table[f"repos/{REPO}/actions/runs/103/jobs?filter=latest&per_page=100"] = [
            {"jobs": [world.jobs[103][1]]}, {"jobs": [world.jobs[103][0]]},
        ]
        posts, _ = required.decide(api, REPO, "pull_request", FILES["tests"], SHA, (FORK, BRANCH))
        got = by_name(posts)["tests"]
        assert (got["conclusion"], got["external_id"]) == ("failure", "job 1003")

    def test_a_check_with_no_eligible_run_does_not_stop_the_other_three(self):
        world = World()
        world.runs[FILES["tests"]][0]["event"] = "push"
        posts, lines, api = world.decide()
        assert [p["name"] for p in posts] == ["project-builds", "enrollment", "terms-accepted"], lines
        assert f"tests: no run at {SHA} for pull request #{PR}; nothing is posted." in lines
        assert f"repos/{REPO}/actions/runs/103/jobs?filter=latest&per_page=100" not in api.calls

    def test_a_newer_run_that_is_not_the_files_or_the_heads_is_not_read(self):
        # Each newer run below passed where the real run of tests.yaml failed: none of them stands for it.
        others = (
            dict(path=".github/workflows/other.yaml", listed_under=FILES["tests"]),  # another file named Tests
            dict(path=".github/workflows/TESTS.yaml", listed_under=FILES["tests"]),  # GitHub's == ignores case
            dict(path=FILES["tests"], event="workflow_dispatch"),
            dict(path=FILES["tests"], event="push"),
            dict(path=FILES["tests"], sha=NEWER),
            dict(path=FILES["tests"], head_repo="someone/oss-verify"),
            dict(path=FILES["tests"], branch="copy"),
        )
        for other in others:
            world = World()
            world.jobs[103][0]["conclusion"] = "failure"
            world.run(300, **other)
            world.job(300, 3000, "tests")
            got = by_name(world.decide()[0])["tests"]
            assert (got["conclusion"], got["external_id"]) == ("failure", "job 1003"), other

    def test_a_run_that_has_not_ended_withdraws_only_a_result_that_stands(self):
        world = World()
        world.run(201, FILES["terms-accepted"], status="in_progress", conclusion=None)
        world.job(201, 3001, "terms-accepted", status="in_progress")
        # No check of the App's yet: nothing for terms-accepted.
        posts, lines, _ = world.decide()
        assert "terms-accepted" not in by_name(posts)
        assert ("terms-accepted: job 3001 has not ended, and no result of the App stands to withdraw; nothing "
                "is posted.") in lines
        # The App's result of the older run stands: the newer run withdraws it.
        world.app_check(500, "terms-accepted", "job 1004")
        got = by_name(world.decide()[0])["terms-accepted"]
        assert {k: got[k] for k in ("status", "external_id", "details_url")} == {
            "status": "in_progress", "external_id": "job 3001",
            "details_url": f"https://github.com/{REPO}/actions/runs/201/job/3001"}
        assert "conclusion" not in got
        # Withdrawn already: not posted again.
        world.app_check(501, "terms-accepted", "job 3001", status="in_progress")
        assert "terms-accepted" not in by_name(world.decide()[0])
        # A run that has no job yet withdraws it too, with the run's page.
        world = World()
        world.run(202, FILES["terms-accepted"], status="queued", conclusion=None)
        world.app_check(500, "terms-accepted", "job 1004")
        got = by_name(world.decide()[0])["terms-accepted"]
        assert (got["status"], got["external_id"], got["details_url"]) == \
            ("in_progress", "run 202 attempt 1", f"https://github.com/{REPO}/actions/runs/202")

    def test_a_withdrawn_result_is_completed_and_then_deduplicated(self):
        world = World()
        world.run(201, FILES["terms-accepted"], status="in_progress", conclusion=None)
        world.job(201, 3001, "terms-accepted", status="in_progress")
        world.app_check(500, "terms-accepted", "job 1004")
        assert by_name(world.decide()[0])["terms-accepted"]["status"] == "in_progress"
        world.app_check(501, "terms-accepted", "job 3001", status="in_progress")
        world.runs[FILES["terms-accepted"]][-1].update(status="completed", conclusion="failure")
        world.jobs[201][0].update(status="completed", conclusion="failure")
        got = by_name(world.decide()[0])["terms-accepted"]
        assert (got["status"], got["conclusion"], got["external_id"]) == ("completed", "failure", "job 3001")
        world.app_check(502, "terms-accepted", "job 3001", conclusion="failure")
        assert "terms-accepted" not in by_name(world.decide()[0])

    def test_a_held_run_posts_nothing(self):
        # GitHub holds the runs of a first-time contributor's pull request: completed, action_required, no job.
        world = World()
        world.runs[FILES["tests"]][0].update(conclusion="action_required")
        world.jobs[103] = []
        posts, lines, _ = world.decide()
        assert "tests" not in by_name(posts)
        assert (f"tests: run 103 is held for a maintainer's approval (action_required) at {SHA} for pull request "
                f"#{PR}; nothing is posted.") in lines

    def test_a_run_that_ended_with_no_job_of_the_name_fails_the_check(self):
        for conclusion, want in (("cancelled", "cancelled"), ("failure", "failure"), ("startup_failure", "failure"),
                                 ("success", "failure")):
            world = World()
            world.runs[FILES["tests"]][0]["conclusion"] = conclusion
            world.jobs[103] = [j for j in world.jobs[103] if j["name"] != "tests"]
            got = by_name(world.decide()[0])["tests"]
            assert (got["status"], got["conclusion"], got["details_url"], got["external_id"]) == \
                ("completed", want, f"https://github.com/{REPO}/actions/runs/103", "run 103 attempt 1"), conclusion

    def test_two_jobs_of_the_name_fail_the_check(self):
        world = World()
        world.job(103, 3001, "tests")
        got = by_name(world.decide()[0])["tests"]
        assert (got["conclusion"], got["output"]["title"]) == ("failure", "tests: failure")
        assert "2 jobs of run [103]" in got["output"]["summary"]

    @pytest.mark.parametrize("url", ["https://example.invalid/x",
                                     f"https://github.com/{REPO}/actions/runs/999/job/1003",
                                     "https://github.com/another/repository/actions/runs/103/job/1003", None])
    def test_a_job_page_elsewhere_is_replaced_by_the_runs_page(self, url):
        world = World()
        world.jobs[103][0]["html_url"] = url
        got = by_name(world.decide()[0])["tests"]
        assert got["details_url"] == f"https://github.com/{REPO}/actions/runs/103"

    def test_a_head_that_moved_or_a_pull_request_not_open_into_main_posts_nothing(self):
        for pull in (World.pull(sha=NEWER), World.pull(state="closed"), World.pull(base="release"),
                     World.pull(head_repo="someone/oss-verify"), World.pull(branch="copy")):
            world = World()
            world.pulls = [pull]
            posts, lines, api = world.decide()
            assert posts == [], pull
            assert "the head moved, or the pull request is closed or into another branch" in lines[0]
            # Nothing else is read.
            assert len(api.calls) == 1, api.calls

    def test_a_head_that_moves_while_the_runs_are_read_posts_nothing(self):
        world = World()

        class MovingApi(FakeApi):
            def pages(self, path):
                answer = super().pages(path)
                if "/actions/workflows/" in path:
                    world.pulls[0]["head"]["sha"] = NEWER
                return answer

        api = MovingApi(world.api().table)
        posts, lines = required.decide(api, REPO, "pull_request", FILES["tests"], SHA, (FORK, BRANCH))
        assert posts == [], lines
        assert "moved or closed while its runs were read" in lines[-1]

    def test_only_a_pull_request_run_of_the_four_files_counts(self):
        for event, path in (("push", FILES["tests"]), ("workflow_dispatch", FILES["tests"]),
                            ("pull_request", ".github/workflows/TESTS.yaml"),
                            ("pull_request", ".github/workflows/tests.yml"),
                            ("pull_request", ".github/workflows/review.yml"), ("pull_request", "")):
            posts, lines, api = World().decide(path=path, event=event)
            assert (posts, api.calls) == ([], []), (event, path)
            assert "not a run on pull_request of one of the four files" in lines[0]

    def test_a_head_with_no_repository_or_branch_posts_nothing(self):
        # A deleted fork gives no head repository.
        for head, sha in (((None, BRANCH), SHA), (("", BRANCH), SHA), ((FORK, ""), SHA), ((FORK, None), SHA),
                          (("x", BRANCH), SHA), ((FORK, BRANCH), "main")):
            posts, lines, api = World().decide(head=head, sha=sha)
            assert (posts, api.calls) == ([], []), head

    def test_a_branch_name_is_quoted_in_the_read_of_the_pull_request(self):
        world = World()
        api = world.api()
        branch = "feature/a&b"
        api.table[f"repos/{REPO}/pulls?state=open&base=main&head=mallory:feature%2Fa%26b&per_page=100"] = [[]]
        posts, lines = required.decide(api, REPO, "pull_request", FILES["tests"], SHA, (FORK, branch))
        assert posts == []
        assert api.calls == [f"repos/{REPO}/pulls?state=open&base=main&head=mallory:feature%2Fa%26b"
                             "&per_page=100"]


class TestByHand:
    """A run by hand on main with the input head_sha: the four checks of the open pull request at that commit."""

    def test_the_open_pull_request_at_the_commit_gets_its_four_checks(self):
        first, second = World(), World(sha=NEWER, number=8, branch="other", base=50)
        api = open_api(first, second, extra=[World.pull(sha="3" * 40, number=10, base="release")])
        posts, lines = required.decide_by_hand(api, REPO, NEWER)
        assert [(p["head_sha"], p["name"]) for p in posts] == [(NEWER, name) for name in CHECKS], lines
        assert by_name(posts)["tests"]["external_id"] == "job 1053"
        # As a run of the head's own events: what the App already says is not posted again.
        for i, name in enumerate(CHECKS):
            second.app_check(600 + i, name, f"job {1051 + i}")
        assert required.decide_by_hand(open_api(first, second), REPO, NEWER)[0] == []

    def test_no_open_pull_request_or_two_at_the_commit_post_nothing(self):
        first = World()
        twin = World.pull(sha=SHA, number=9, head_repo="someone/oss-verify", branch="copy")
        deleted = World.pull(sha=SHA, number=11)
        deleted["head"]["repo"] = None
        for extra, sha, why in (([], NEWER, "0 open pull requests into main are at"),
                                ([twin], SHA, "2 open pull requests into main are at"),
                                ([World.pull(sha=SHA, number=12, base="release")], NEWER, "0 open pull requests")):
            api = open_api(first, extra=extra)
            posts, lines = required.decide_by_hand(api, REPO, sha)
            assert posts == [], (why, sha)
            assert why in lines[0], (why, sha)
            assert api.calls == [OPEN_PULLS], (why, sha)
        api = open_api(extra=[deleted])
        posts, lines = required.decide_by_hand(api, REPO, SHA)
        assert posts == []
        assert "names no head repository and branch" in lines[0]

    @pytest.mark.parametrize("sha", [pytest.param("", id="empty"), "main", SHA.upper(), SHA + "0", "'; rm -rf / #"])
    def test_a_head_sha_that_is_no_commit_id_reads_nothing(self, sha):
        api = open_api(World())
        posts, lines = required.decide_by_hand(api, REPO, sha)
        assert (posts, api.calls) == ([], [])
        assert "is no commit id: nothing is posted." in lines[0]

    @pytest.mark.parametrize("later", [[World.pull(sha=NEWER)], []], ids=["moved", "closed"])
    def test_a_pull_request_that_moved_or_closed_during_the_reads_gets_nothing(self, later):
        world = World()
        api = world.api()
        api.table[OPEN_PULLS] = [world.pulls]
        head = f"repos/{REPO}/pulls?state=open&base=main&head=mallory:{BRANCH}&per_page=100"
        api.table[head] = [later]
        posts, lines = required.decide_by_hand(api, REPO, SHA)
        assert posts == [], lines
        assert "Pull request #7 moved or closed while its runs were read; nothing is posted." in lines

    def test_main_writes_one_line_of_at_most_four_bodies_far_under_the_limits(self, tmp_path):
        # The bodies reach the job post as one environment variable, which Linux holds to 128 KiB, and as a job output,
        # which GitHub holds to 1 MB a job: a run of one head lists at most four.
        output = tmp_path / "output"
        output.write_text("")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(required, "Api", lambda: open_api(World()))
            patch.setenv("REPO", REPO)
            patch.setenv("EVENT_NAME", "workflow_dispatch")
            patch.setenv("HEAD_SHA", SHA)
            patch.setenv("GITHUB_OUTPUT", str(output))
            assert required.main() == 0
        written = output.read_text().splitlines()
        assert written[0] == "post=true"
        assert written[1].startswith("bodies=")
        assert len(json.loads(written[1][len("bodies="):])) == 4
        assert len(written[1]) < 8 * 1024


class TestCondition:
    """The read job's if on the event, as GitHub evaluates it; the post job runs only when read has a list."""

    def runs(self, action, path, event="pull_request", event_name="workflow_run", ref="refs/heads/main"):
        return bool(evaluate(READ["if"], {"github.event_name": event_name, "github.ref": ref,
                                          "github.event.action": action, "github.event.workflow_run.path": path,
                                          "github.event.workflow_run.event": event}))

    def test_the_end_of_a_pull_request_run_of_the_four_files_and_the_start_of_terms(self):
        for path in FILES.values():
            assert self.runs("completed", path), path
            assert self.runs("requested", path) == (path == FILES["terms-accepted"]), path
            assert not self.runs("in_progress", path), path
            for event in ("push", "workflow_dispatch", "pull_request_target", "merge_group"):
                assert not self.runs("completed", path, event), (path, event)
        for path in (".github/workflows/other.yaml", ".github/workflows/review.yml", ""):
            assert not self.runs("completed", path), path

    def test_a_run_by_hand_on_main_alone(self):
        assert self.runs(None, None, None, event_name="workflow_dispatch")
        for ref in ("refs/heads/feature", "refs/tags/main", "refs/pull/1/merge"):
            assert not self.runs(None, None, None, event_name="workflow_dispatch", ref=ref), ref
        for event_name in ("push", "schedule", "repository_dispatch"):
            assert not self.runs("completed", FILES["tests"], event_name=event_name), event_name

    def test_the_condition_ignores_case_and_the_script_does_not(self):
        # GitHub's == compares strings without case, so the job runs for .github/workflows/TESTS.yaml, a file of
        # another path; the script then posts nothing (TestPosts.test_only_a_pull_request_run_of_the_four_files_counts).
        assert self.runs("completed", ".github/workflows/TESTS.yaml")
        assert ".github/workflows/TESTS.yaml" not in required.CHECKS

    def test_post_runs_after_read_and_only_with_a_list(self):
        assert POST["needs"] == "read"
        for post, want in (("true", True), ("false", False), ("", False)):
            assert bool(evaluate(POST["if"], {"needs.read.outputs.post": post})) == want, post


class TestHolds:
    """What each job holds, and from where."""

    def test_the_triggers_and_the_runs_of_one_head_one_at_a_time(self):
        on = WORKFLOW.get("on", WORKFLOW.get(True))
        assert on == {"workflow_run": {"workflows": ["Build", "Validate", "Tests", "Terms"],
                                       "types": ["requested", "completed"]},
                      "workflow_dispatch": {"inputs": {"head_sha": {
                          "description": "The head commit of the open pull request into main whose four checks to post",
                          "required": True, "type": "string"}}}}
        # The whole run, read and post, waits for the run before it for the same head, a run by hand for that head
        # included: so a run by hand cannot post an older answer over a newer run of the head's own events.
        concurrency = WORKFLOW["concurrency"]
        assert {k: v for k, v in concurrency.items() if k != "group"} == {"cancel-in-progress": False, "queue": "max"}
        of_event = interpolated(concurrency["group"], {"github.event.workflow_run.head_sha": SHA})
        by_hand = interpolated(concurrency["group"], {"inputs.head_sha": SHA})
        assert (of_event, by_hand) == (f"required-checks-{SHA}", f"required-checks-{SHA}")
        assert interpolated(concurrency["group"], {"inputs.head_sha": NEWER}) != of_event
        assert "concurrency" not in READ
        assert "concurrency" not in POST
        # Each name is the name of the file of its check.
        for name, path in zip(on["workflow_run"]["workflows"], FILES.values(), strict=True):
            assert read_workflow(path.rsplit("/", 1)[1])["name"] == name
        # The job of each file whose name is its check exists.
        for check, path in FILES.items():
            jobs = read_workflow(path.rsplit("/", 1)[1])["jobs"]
            assert len([j for j, job in jobs.items() if job.get("name", j) == check]) == 1, check

    def test_read_holds_reads_alone_and_post_holds_the_key_and_no_read(self):
        assert set(WORKFLOW["jobs"]) == {"read", "post"}
        assert WORKFLOW["permissions"] == {}
        assert READ["permissions"] == {"actions": "read", "checks": "read", "contents": "read",
                                       "pull-requests": "read"}
        assert "environment" not in READ
        assert "env" not in READ
        assert READ["outputs"] == {"post": "${{ steps.read.outputs.post }}",
                                   "bodies": "${{ steps.read.outputs.bodies }}"}
        assert POST["permissions"] == {"id-token": "write"}
        assert POST["environment"] == {"name": "required-checks", "deployment": False}
        assert POST["env"]["GCP_SERVICE_ACCOUNT"] == "ossv-required-checks@theorem-agent-root.iam.gserviceaccount.com"
        app = step("Get the App's token for this repository's checks")
        assert app["with"] == {"client-id": "Iv23liAWPMahJZYsw3un", "private-key": "${{ steps.key.outputs.key }}",
                               "permission-checks": "write"}
        # The list is checked before any credential.
        assert [s.get("name") for s in POST["steps"]] == [
            "Check the list of check runs", "Sign in to Google Cloud", "Read the oss-verify App's key",
            "Get the App's token for this repository's checks", "Post the checks"]

    def test_no_step_checks_out_or_runs_the_pull_requests_code(self):
        checkout = READ["steps"][0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"] == {"persist-credentials": False, "sparse-checkout": ".github/scripts"}
        assert [s for job in (READ, POST) for s in job["steps"]
                if str(s.get("uses", "")).startswith("actions/checkout@")] == [checkout]
        # Every value of the event reaches a step through env, never by ${{ }} in its script.
        for s in READ["steps"] + POST["steps"]:
            assert "${{" not in str(s.get("run", "")), s.get("name")


class TestSteps(Runner):
    """The steps Read the runs of the four checks, Check the list of check runs and Post the checks, with a stand-in
    gh, given the values the workflow's own expressions give them."""

    def setUp(self):
        super().setUp()
        app_id = step("Get the App's token for this repository's checks")["id"]
        self.context = {
            "github.repository": REPO, "github.sha": "8" * 40, "github.event_name": "workflow_run",
            "github.ref": "refs/heads/main", "github.token": "read-token", "runner.temp": str(self.temp),
            "github.event.workflow_run.event": "pull_request", "github.event.workflow_run.path": FILES["tests"],
            "github.event.workflow_run.head_sha": SHA, "github.event.workflow_run.head_repository.full_name": FORK,
            "github.event.workflow_run.head_branch": BRANCH,
            f"steps.{app_id}.outputs.token": "app-token",
        }
        gh = self.dir / "bin" / "gh"
        gh.write_text("#!/usr/bin/env bash\n"
                      '[ "$GH_TOKEN" = "$EXPECTED_GH_TOKEN" ] || { echo "gh: wrong token" >&2; exit 1; }\n'
                      + gh.read_text())

    def by_hand(self, sha=SHA):
        """A run by hand on main with the input head_sha `sha`: the event names no run."""
        for key in [k for k in self.context if k.startswith("github.event.workflow_run.")]:
            del self.context[key]
        self.context["github.event_name"] = "workflow_dispatch"
        self.context["inputs.head_sha"] = sha

    def workflow_env(self, name):
        return {key: interpolated(str(value), self.context) for key, value in step(name)["env"].items()}

    def serve_table(self, table):
        for path, answer in table.items():
            self.serve(path, answer)

    def read(self, **env):
        name = "Read the runs of the four checks"
        given = self.workflow_env(name)
        given.update(env)
        result = self.run_script(step(name)["run"], cwd=ROOT, EXPECTED_GH_TOKEN="read-token", **given)
        for key, value in result[2].items():
            self.context[f"steps.{step(name)['id']}.outputs.{key}"] = value
        for key, value in READ["outputs"].items():
            self.context[f"needs.read.outputs.{key}"] = interpolated(value, self.context)
        return result

    def check(self, bodies=None):
        if bodies is not None:
            self.context["needs.read.outputs.bodies"] = json.dumps(bodies)
        name = "Check the list of check runs"
        return self.run_script(step(name)["run"], **self.workflow_env(name))

    def post(self, respond=True, **env):
        if respond:
            self.serve(f"repos/{REPO}/check-runs", {"id": 9, "name": "tests", "head_sha": SHA, "status": "completed",
                                                   "conclusion": "success"})
        name = "Post the checks"
        given = self.workflow_env(name)
        given.update(env)
        return self.run_script(step(name)["run"], EXPECTED_GH_TOKEN="app-token", **given)

    def posted(self):
        return [json.loads((self.api / f"input.{n}").read_text())
                for n, call in enumerate(self.calls(), 1) if "POST" in call]

    def test_the_read_lists_what_to_post_and_the_post_sends_each(self):
        self.serve_table(World().table())
        rc, out, got = self.read()
        assert (rc, got["post"]) == (0, "true"), out
        assert "tests: posts success from job 1003 of run 103." in out
        bodies = json.loads(self.context["needs.read.outputs.bodies"])
        assert [b["name"] for b in bodies] == CHECKS
        assert evaluate(POST["if"], self.context)
        assert self.check()[:2] == (0, "")
        before = len(self.calls())
        rc, out, _ = self.post()
        assert rc == 0, out
        assert out.count(f"Posted the check run tests at {SHA} (9): success.") == 4, out
        assert self.posted() == bodies
        assert self.calls()[before:] == \
            [["--method", "POST", f"repos/{REPO}/check-runs", "--input", "-", "--jq",
              '"Posted the check run \\(.name) at \\(.head_sha) (\\(.id)): \\(.conclusion // .status)."']] * 4

    def test_a_run_by_hand_lists_the_checks_of_its_head_alone(self):
        first, second = World(), World(sha=NEWER, number=8, branch="other", base=50)
        self.serve_table(open_api(first, second).table)
        self.by_hand(NEWER)
        rc, out, got = self.read()
        assert (rc, got["post"]) == (0, "true"), out
        bodies = json.loads(self.context["needs.read.outputs.bodies"])
        assert [b["head_sha"] for b in bodies] == [NEWER] * 4
        assert self.check()[0] == 0
        # The same list does not pass for a run by hand of another head.
        self.context["inputs.head_sha"] = SHA
        rc, out, _ = self.check()
        assert rc == 1, out

    def test_a_read_with_nothing_to_post_says_so(self):
        world = World()
        world.pulls = [World.pull(sha=NEWER)]
        self.serve_table(world.table())
        rc, out, got = self.read()
        assert (rc, got["post"], json.loads(got["bodies"])) == (0, "false", []), out
        assert not evaluate(POST["if"], self.context)

    def test_a_read_that_fails_fails_the_step(self):
        # No answer for the runs of tests.yaml: gh fails, as on GitHub's 404 or 500.
        self.serve_table(World().table())
        (self.api / (f"repos/{REPO}/actions/workflows/tests.yaml/runs?event=pull_request&head_sha={SHA}"
                     "&per_page=100".replace("/", "_") + ".json")).unlink()
        rc, out, got = self.read()
        assert rc != 0, out
        assert got.get("post") != "true"
        assert not evaluate(POST["if"], self.context)

    def test_a_failed_post_fails_the_step_and_sends_no_later_check(self):
        self.serve_table(World().table())
        rc, out, _ = self.read()
        assert rc == 0, out
        before = len(self.calls())
        rc, out, _ = self.post(respond=False)
        assert rc != 0, out
        assert len(self.calls()[before:]) == 1, out
        assert [body["name"] for body in self.posted()] == ["project-builds"]

    def test_the_check_refuses_a_list_for_another_head_or_check(self):
        good = {"name": "tests", "head_sha": SHA}
        for bad in ({"name": "tests", "head_sha": NEWER}, {"name": "build", "head_sha": SHA},
                    {"name": "tests", "head_sha": "main"}, {"name": "tests"}, {"name": "tests", "head_sha": SHA},
                    "tests", None):
            rc, out, _ = self.check([good, bad])
            assert rc == 1, (bad, out)
            assert ("The list holds no check run, or one that is not one of the four checks at this run's "
                    "head.") in out, bad
        four = [{"name": name, "head_sha": SHA} for name in CHECKS]
        for bodies in ([], {"name": "tests", "head_sha": SHA}, four + [good]):
            assert self.check(bodies)[0] == 1, bodies
        assert self.check([good])[0] == 0
        assert self.check(four)[0] == 0
        # A run by hand posts to its head_sha alone, which must be a commit id.
        self.by_hand(NEWER)
        assert self.check([good])[0] == 1
        assert self.check([{"name": "tests", "head_sha": NEWER}])[0] == 0
        self.by_hand("main")
        assert self.check([{"name": "tests", "head_sha": "main"}])[0] == 1
        assert self.calls() == []
