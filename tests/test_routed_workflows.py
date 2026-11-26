# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the routed workflows (build.yaml, review.yml) and their collector, .github/scripts/collect, for tests.yaml
and validate.yaml, which report a required check with no route, and for the condition of triage.yaml's one job:
uv run pytest

A routed workflow has a route job that decides which jobs the run needs, and a collector job that always runs last,
collects every result with the collector, and reports the workflow's one check: build.yaml's job required reports the
check that the ruleset requires, and review.yml's job collect the check review jobs, which no ruleset requires. These
check the collector's verdicts, the shape every routed workflow keeps (the collector waits for every job, and no job a
route may skip reports a required check), and the routes' own steps, run on made-up changes. validate.yaml has one
job, which reports its required check and runs on every event. tests.yaml has the jobs suite and docker, which run on
every event, and the job tests, which reports the required check after both. These also run the steps of tests.yaml's
jobs: the checks of a pull request's base, the step that keeps a fork's change to projects/ from running any code, the
steps that run the tests, and the step of the job tests. And the concurrency of the four workflows of the required
checks, terms.yaml's included: two runs at one head from two actions cancel neither, and a push cancels the run of the
older head, but in a workflow of one job of seconds, which cancels no run.
"""
import importlib.util
import itertools
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from test_outside_screen import evaluate, interpolated, read_workflow as workflow
from test_required_check import required as required_check
from test_take_project import git, isolated_git_env

ROOT = pathlib.Path(__file__).resolve().parents[1]
COLLECT = ROOT / ".github" / "scripts" / "collect"
WORKFLOWS = ROOT / ".github" / "workflows"
# The workflow that reports each required check but terms-accepted (the default branch's ruleset requires
# project-builds, enrollment and tests).
REQUIRED = {"build.yaml": "project-builds", "validate.yaml": "enrollment", "tests.yaml": "tests"}
# Each routed workflow's collector job, and the check it reports: build.yaml's is the required check project-builds, and
# review.yml's is no required check: a check of a workflow_run or workflow_dispatch run never satisfies one.
COLLECTORS = {"build.yaml": ("required", REQUIRED["build.yaml"]), "review.yml": ("collect", "review jobs")}
# Each workflow of one job, and the required check that its job reports.
ONE_JOB = {"validate.yaml": REQUIRED["validate.yaml"]}
# The checks the default branch's ruleset requires.
RULESET = {"enrollment", "project-builds", "terms-accepted", "tests"}


def step(job, name):
    matches = [s for s in job["steps"] if s.get("name") == name]
    assert len(matches) == 1, f"{len(matches)} steps named {name!r}"
    return matches[0]


def collect(tmp_path, *arguments):
    summary = tmp_path / "summary"
    run = subprocess.run([str(COLLECT), *arguments], capture_output=True, text=True,
                         env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary)})
    return run.returncode, run.stdout, summary.read_text() if summary.exists() else ""


# --- the collector ---


@pytest.mark.parametrize("arguments", [
    ("success", "build:success:true", "review:success:true", "comment:success:true"),
    # route asked for nothing: every other job skipped.
    ("success", "build:skipped:false", "review:skipped:false", "comment:skipped:false"),
    ("success", "suite:skipped:false", "docs:success:true"),
    ("success",),
])
def test_the_collector_passes_when_route_passed_and_each_job_did_as_route_asked(tmp_path, arguments):
    code, out, summary = collect(tmp_path, *arguments)
    assert code == 0, out
    assert out.startswith("Passed:") and summary.startswith("Passed:")


@pytest.mark.parametrize("arguments, error", [
    # A job route asked for that failed, was cancelled, or was skipped: a skipped job is never a pass of one asked for.
    (("success", "build:failure:true", "review:success:true"), "build: failure, where the run asks for success"),
    (("success", "build:cancelled:true"), "build: cancelled, where the run asks for success"),
    (("success", "build:skipped:true"), "build: skipped, where the run asks for success"),
    (("success", "suite:skipped:false", "docs:failure:true"), "docs: failure, where the run asks for success"),
    # A job route did not ask for that ran, even one that passed.
    (("success", "build:success:false"), "build: success, where the run asks for skipped"),
    (("success", "build:failure:false"), "build: failure, where the run asks for skipped"),
    # route itself did not pass: its jobs are then skipped, which must not read as nothing to do.
    (("failure", "build:skipped:false"), "route: failure"),
    (("cancelled", "validate:skipped:false"), "route: cancelled"),
    (("", "validate:skipped:false"), "route: no result"),
    (("success", "validate::true"), "validate: no result, where the run asks for success"),
])
def test_the_collector_fails_on_every_job_that_did_not_do_as_route_asked(tmp_path, arguments, error):
    code, out, summary = collect(tmp_path, *arguments)
    assert code == 1
    assert f"::error::{error}\n" in out
    assert summary.startswith("### Not passed") and f"- {error}\n" in summary


def test_the_collector_names_every_failure_at_once(tmp_path):
    code, out, _ = collect(tmp_path, "failure", "suite:failure:true", "docs:success:false")
    assert code == 1
    assert out.count("::error::") == 3


# --- the shape of each routed workflow ---


@pytest.mark.parametrize("name", sorted(COLLECTORS))
def test_only_the_required_job_reports_the_required_check(name):
    jobs = workflow(name)["jobs"]
    collector, check = COLLECTORS[name]
    assert jobs[collector].get("name", collector) == check
    for job_id, job in jobs.items():
        if job_id == collector:
            continue
        # A job's check is its name, or its id when it has none. Any job but the collector may be skipped by route.
        assert job.get("name", job_id) != check, f"{name}: the job {job_id} reports {check}"
    # Every job but route and the collector runs only when route asks for it (directly, or through the job it needs).
    for job_id, job in jobs.items():
        if job_id not in ("route", collector):
            assert "if" in job, f"{name}: {job_id} runs whatever route decides"


@pytest.mark.parametrize("name", sorted(ONE_JOB))
def test_a_workflow_of_one_job_reports_its_required_check_on_every_run(name):
    jobs = workflow(name)["jobs"]
    assert len(jobs) == 1, f"{name}: the jobs {sorted(jobs)}, not one"
    [(job_id, job)] = jobs.items()
    assert job.get("name", job_id) == ONE_JOB[name]
    # GitHub counts a skipped job as a pass where a check is required: the job has no condition, and waits for no job.
    assert "if" not in job and "needs" not in job, f"{name}: the job {job_id} can be skipped"


def test_every_required_check_has_a_static_name():
    # GitHub reads a required check from the newest run of its workflow on the head. A job whose name is an expression
    # can report another name on some event, and the newest run then has no required check: the pull request is
    # blocked until a push. So each required check is reported by exactly one job, under a plain name.
    reporters = {}
    for path in sorted([*WORKFLOWS.glob("*.yaml"), *WORKFLOWS.glob("*.yml")]):
        for job_id, job in workflow(path.name)["jobs"].items():
            name = str(job.get("name", job_id))
            # An expression that can give a required name, such as `... && 'other' || 'tests'`.
            literals = set(re.findall(r"'([^']*)'", name)) if "${{" in name else set()
            assert not literals & RULESET, (path.name, job_id, name)
            if name in RULESET:
                reporters.setdefault(name, []).append(f"{path.name}:{job_id}")
    assert sorted(reporters) == sorted(RULESET)
    assert all(len(jobs) == 1 for jobs in reporters.values()), reporters


# A stand-in for gh's Users API, as .github/scripts/actor-kind calls it (`gh api users/<login> --jq .type`): Copilot
# is an App with no user account (404, as GitHub answers for it), a login with [bot] is an App, any other a User.
USERS_GH = ('*" users/"*) all="$*"; login=${all##*users/}; login=${login%% *}\n'
            '  case $login in Copilot) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;; *"[bot]") echo Bot ;; '
            '*) echo User ;; esac ;;\n')


def literal_env(flow, decide):
    """The workflow's and the step's own literal env (ALLOWED_BOTS): inputs of the run, given as they are."""
    pairs = {**(flow.get("env") or {}), **(decide.get("env") or {})}
    return {k: str(v) for k, v in pairs.items() if "${{" not in str(v)}


def pull_request(files, changed=None, base="main"):
    """Pull request 8 of mallory, from the branch main of the fork mallory/libx into `base`, at the head a*40, as
    GitHub's pulls API gives it: changed_files is `changed`, by default the number of `files`."""
    return {"number": 8, "state": "open", "user": {"login": "mallory"},
            "head": {"sha": "a" * 40, "ref": "main", "repo": {"full_name": "mallory/libx"}},
            "base": {"ref": base, "repo": {"full_name": "o/r", "default_branch": "main"}},
            "changed_files": len(files) if changed is None else changed}


def files_of(files):
    """The pulls API's files: each a path, or a (new, old) pair for a rename."""
    return [{"filename": f} if isinstance(f, str) else {"filename": f[0], "previous_filename": f[1]} for f in files]


def route_build(tmp_path, files, changed=None, base="main", fail=False):
    """Run build.yaml's route step with a fake gh whose pull request 8 into `base` lists `files` (pull_request), or
    fails to list them when `fail`, and applies the step's --jq filter as gh does. Return its exit status and its
    outputs, one line each."""
    bin = tmp_path / "bin"
    bin.mkdir()
    (tmp_path / "pull.json").write_text(json.dumps(pull_request(files, changed, base)))
    (tmp_path / "files.json").write_text(json.dumps(files_of(files)))
    listed = "exit 1" if fail else f'jq -r "$filter" {tmp_path}/files.json'
    (bin / "gh").write_text('#!/bin/bash\nfilter=""; for a; do [ "$prev" = --jq ] && filter=$a; prev=$a; done\n'
                            f'case " $*" in *"/files"*) {listed} ;;\n'
                            f'  *) cat {tmp_path}/pull.json ;; esac\n')
    (bin / "gh").chmod(0o755)
    written = tmp_path / "output"
    decide = step(workflow("build.yaml")["jobs"]["route"], "An enrollment or a change")
    run = subprocess.run(["bash", "-e", "-c", decide["run"]], capture_output=True, text=True, cwd=ROOT,
                         env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                              "PR": "8", "GITHUB_OUTPUT": str(written),
                              "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")})
    return run.returncode, written.read_text().splitlines() if written.exists() else []


@pytest.mark.parametrize("files, changed, base, want", [
    # Tooling and documentation only, as from a fork: a change, which review.yml reviews, and no build.
    (["src/oss_verify/check.py", "docs/build-contract.md", "tests/test_check.py"], None, "main", []),
    (["README.md"], None, "main", []),
    # Into another branch: the build, where take-project refuses it, as before.
    (["README.md"], None, "ci/other", ["build=true"]),
    # A file under projects/, alone or beside others (a fork's mixed change then fails in take-project, as before),
    # or a rename out of projects/ (both names are listed): an enrollment, built.
    (["projects/p/project.yaml"], None, "main", ["build=true"]),
    (["projects/p/project.yaml", "src/oss_verify/check.py"], None, "main", ["build=true"]),
    (["src/x.yaml", "projects/p/x.yaml"], None, "main", ["build=true"]),
    ([("src/x.yaml", "projects/p/x.yaml")], None, "main", ["build=true"]),
    # No file, or more files than the API lists: the list decides nothing, and take-project judges it.
    ([], None, "main", ["build=true"]),
    (["src/oss_verify/check.py"], 3001, "main", ["build=true"]),
])
def test_builds_route_builds_every_pull_request_but_a_change(tmp_path, files, changed, base, want):
    assert route_build(tmp_path, files, changed, base=base) == (0, want)


def test_builds_route_fails_when_it_cannot_read_the_files(tmp_path):
    code, outputs = route_build(tmp_path, ["projects/p/project.yaml"], fail=True)
    assert code != 0 and outputs == []


def route_review(tmp_path, files, changed=None, actor="someone", event="workflow_run",
                 run_path=".github/workflows/build.yaml", run_event="pull_request", conclusion="success", pulls=None,
                 held=(), builds=(), fail=False, run_actor=("a-maintainer", "User"), permission="write"):
    """Run review.yml's route step on main, started by `actor`, with a fake gh that applies the step's --jq filter as
    gh does. On workflow_run, after run 900 of `run_path` on `run_event` that ended `conclusion`, at the head a*40 of
    mallory/libx's branch main; on workflow_dispatch, a run by hand of pull request 8. The gh gives as the open pull
    requests of that head `pulls` (by default pull request 8 into main), pull request 8 and its `files` (or fails to
    list them when `fail`), the runs GitHub holds at its head (`held`, their ids), and the completed Build runs of the
    head in `builds`, each a pair (the run, the artifacts named build-results that it lists), by default none.
    `run_actor` is the run's triggering account and its type, and `permission` that account's collaborator permission
    (None: the read fails). Return its exit status, its outputs (one line each), and the gh calls."""
    bin = tmp_path / "bin"
    bin.mkdir()
    pull = pull_request(files, changed)
    answers = {"pulls": [pull] if pulls is None else pulls, "pull": pull,
               "builds": {"workflow_runs": [run for run, _ in builds]},
               "held": {"workflow_runs": [{"id": i, "status": "completed", "conclusion": "action_required",
                                           "head_sha": "a" * 40, "head_branch": "main",
                                           "head_repository": {"full_name": "mallory/libx"}} for i in held]}}
    answers.update({f"artifacts-{run['id']}": {"artifacts": list(artifacts)} for run, artifacts in builds})
    if permission is not None:
        answers["permission"] = {"permission": permission}
    if not fail:
        answers["files"] = files_of(files)
    for name, answer in answers.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(answer))
    (bin / "gh").write_text('#!/bin/bash\nfilter=.; for a; do [ "$prev" = --jq ] && filter=$a; prev=$a; done\n'
                            f'echo "$*" >> {tmp_path}/calls\n'
                            'serve() {\n'
                            f'  [ -f {tmp_path}/$1.json ] || {{ echo "gh: Server Error (HTTP 502)" >&2; exit 1; }}\n'
                            f'  jq -r "$filter" {tmp_path}/$1.json\n}}\n'
                            f'case " $*" in {USERS_GH}'
                            '  *"/pulls?"*) serve pulls ;;\n'
                            '  *"/collaborators/"*) serve permission ;;\n'
                            '  *"/files"*) serve files ;;\n'
                            '  *"/pulls/"*) serve pull ;;\n'
                            '  *"status=action_required"*) serve held ;;\n'
                            '  *"/build.yaml/runs"*) serve builds ;;\n'
                            '  *"/artifacts?name=build-results"*) all="$*"; id=${all##*/actions/runs/}; '
                            'serve "artifacts-${id%%/*}" ;;\n'
                            '  *) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;; esac\n')
    (bin / "gh").chmod(0o755)
    written = tmp_path / "output"
    flow = workflow("review.yml")
    decide = step(flow["jobs"]["route"], "An enrollment, a change or an issue")
    env = {**os.environ, **literal_env(flow, decide), "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x",
           "REPO": "o/r", "EVENT": event, "REF": "refs/heads/main", "ACTOR": actor, "PR": "", "ISSUE": "",
           "SENDER": actor, "AUTHOR": "", "ASSOCIATION": "", "MEASURE": "", "DEFAULT_BRANCH": "main",
           "GITHUB_OUTPUT": str(written), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")}
    if event == "workflow_run":
        env.update(RUN_ID="900", RUN_EVENT=run_event, RUN_PATH=run_path, RUN_CONCLUSION=conclusion,
                   RUN_HEAD_SHA="a" * 40, RUN_HEAD_REPOSITORY="mallory/libx", RUN_HEAD_BRANCH="main",
                   RUN_ACTOR=run_actor[0], RUN_ACTOR_TYPE=run_actor[1])
    else:
        env["PR"] = "8"
    run = subprocess.run(["bash", "-e", "-c", decide["run"]], capture_output=True, text=True, cwd=ROOT, env=env)
    calls = (tmp_path / "calls").read_text().splitlines() if (tmp_path / "calls").exists() else []
    return run.returncode, written.read_text().splitlines() if written.exists() else [], calls


# route's outputs for pull request 8 at its head, and for an enrollment after Build run 900, whose results it reads.
PULL = ["pr=8", f"sha={'a' * 40}", "author=mallory"]
ENROLLMENT = ["kind=enrollment", "build_run=900"]


@pytest.mark.parametrize("files, changed, want", [
    # Tooling and documentation only, as from a fork: a change review.
    (["src/oss_verify/check.py", "docs/build-contract.md", "tests/test_check.py"], None, ["kind=change"]),
    (["README.md"], None, ["kind=change"]),
    # A file under projects/, alone or beside others, or a rename out of projects/ (both names are listed): an
    # enrollment, reviewed with the results of the Build run.
    (["projects/p/project.yaml"], None, ENROLLMENT),
    (["projects/p/project.yaml", "src/oss_verify/check.py"], None, ENROLLMENT),
    (["src/x.yaml", "projects/p/x.yaml"], None, ENROLLMENT),
    ([("src/x.yaml", "projects/p/x.yaml")], None, ENROLLMENT),
    # No file, or more files than the API lists: the list decides nothing, and take-project judges it.
    ([], None, ENROLLMENT),
    (["src/oss_verify/check.py"], 3001, ENROLLMENT),
])
def test_reviews_route_reviews_a_pull_request_with_no_file_under_projects_as_a_change(tmp_path, files, changed, want):
    code, outputs, _ = route_review(tmp_path, files, changed)
    assert (code, outputs) == (0, PULL + want)


@pytest.mark.parametrize("actor, want", [
    ("someone", ["kind=change"]), ("sjawhar-agent[bot]", ["kind=change"]), ("oss-verify[bot]", ["kind=change"]),
    # Dependabot, whose pull requests bump the pinned actions: admitted, so its change gets the change review.
    ("dependabot[bot]", ["kind=change"]),
    # An App the action refuses (src/github/validation/actor.ts) would fail the review, and so the check review jobs:
    # by its account type, so Copilot, whose login has no [bot] and which the Users API does not find, too.
    # route says so (refused), so that the gather job gives it no kind when take-project takes no project.
    ("oss-verify[bot]x[bot]", ENROLLMENT + ["refused=true"]), ("Copilot", ENROLLMENT + ["refused=true"]),
])
def test_a_change_that_an_app_the_review_refuses_started_is_an_enrollment_as_before(tmp_path, actor, want):
    code, outputs, _ = route_review(tmp_path, [".github/workflows/build.yaml"], actor=actor)
    assert (code, outputs) == (0, PULL + want)


def test_a_refused_apps_pull_request_is_marked_refused_whatever_it_changes(tmp_path):
    """The refusal does not depend on the files: a change of two projects (which take-project takes no project from)
    is marked too, so that the gather job gives it no kind."""
    for files in (["projects/p/project.yaml", "projects/q/project.yaml"], ["projects/p/project.yaml"]):
        (tmp_path / str(len(files))).mkdir()
        code, outputs, _ = route_review(tmp_path / str(len(files)), files, actor="Copilot")
        assert (code, outputs) == (0, PULL + ENROLLMENT + ["refused=true"]), files
    (tmp_path / "writer").mkdir()
    code, outputs, _ = route_review(tmp_path / "writer", ["projects/p/project.yaml", "projects/q/project.yaml"])
    assert (code, outputs) == (0, PULL + ENROLLMENT)


def merged(base, change):
    """`base` with the values of `change`, key by key."""
    return {k: merged(v, change[k]) if isinstance(v, dict) and k in change else change.get(k, v)
            for k, v in base.items()}


@pytest.mark.parametrize("change", [
    # The open pull request into main at the run's head commit, from its head repository and branch.
    {},
    # The head moved after the run: the run of the new head reviews it.
    {"head": {"sha": "b" * 40}},
    # A branch of the same name in another repository, or another branch.
    {"head": {"repo": {"full_name": "eve/libx"}}},
    {"head": {"ref": "other"}},
    # Into another branch, or closed.
    {"base": {"ref": "ci/other"}},
    {"state": "closed"},
])
def test_reviews_route_reads_the_open_pull_request_at_the_runs_head(tmp_path, change):
    """A fork's pull request is not in a workflow_run event: route asks the API for the open pull requests into main
    of the run's head repository and branch, and keeps only the one at the run's head commit. With none, nothing runs,
    and route reads no pull request."""
    files = ["projects/p/project.yaml"]
    code, outputs, calls = route_review(tmp_path, files, pulls=[merged(pull_request(files), change)])
    assert calls[0] == "api repos/o/r/pulls?state=open&base=main&head=mallory:main&per_page=100"
    if change:
        assert (code, outputs) == (0, [])
        assert [c for c in calls if "repos/o/r/pulls/" in c] == []
    else:
        assert (code, outputs) == (0, PULL + ENROLLMENT)


@pytest.mark.parametrize("run_path, run_event, conclusion, want", [
    # A Build run that ended success or failure: its pull request is reviewed.
    (".github/workflows/build.yaml", "pull_request", "success", PULL + ENROLLMENT),
    (".github/workflows/build.yaml", "pull_request", "failure", PULL + ENROLLMENT),
    # A Build run that ended otherwise (cancelled by a newer push, say), a Triage run that did not end success, a run
    # of another file (a pull request can name a workflow of its own Build), or a run on another event: nothing.
    (".github/workflows/build.yaml", "pull_request", "cancelled", []),
    (".github/workflows/build.yaml", "pull_request", "skipped", []),
    (".github/workflows/build.yaml", "pull_request", "", []),
    (".github/workflows/triage.yaml", "pull_request", "failure", []),
    (".github/workflows/triage.yaml", "pull_request", "cancelled", []),
    (".github/workflows/other.yml", "pull_request", "success", []),
    (".github/workflows/build.yaml", "pull_request_target", "success", []),
    (".github/workflows/build.yaml", "push", "success", []),
    # A Review approvals run on pull_request_review that ended success: route asks for the comment job's refresh of
    # the pull request's check run review alone, with no kind. On another event, or ended otherwise: nothing.
    (".github/workflows/review-approvals.yml", "pull_request_review", "success", PULL + ["refresh=true"]),
    (".github/workflows/review-approvals.yml", "pull_request", "success", []),
    (".github/workflows/review-approvals.yml", "pull_request_review", "skipped", []),
    (".github/workflows/review-approvals.yml", "pull_request_review", "failure", []),
    (".github/workflows/review-approvals.yml", "pull_request_review", "", []),
    (".github/workflows/build.yaml", "pull_request_review", "success", []),
])
def test_reviews_route_reads_only_a_build_or_triage_run_of_a_pull_request_that_ended_so(tmp_path, run_path, run_event,
                                                                                        conclusion, want):
    code, outputs, calls = route_review(tmp_path, ["projects/p/project.yaml"], run_path=run_path, run_event=run_event,
                                        conclusion=conclusion)
    assert (code, outputs) == (0, want)
    # A run it does not read stops route before any read of GitHub.
    assert bool(calls) == bool(want), calls


@pytest.mark.parametrize("run_actor, permission, want", [
    (("a-maintainer", "User"), "write", PULL + ["refresh=true"]),
    (("a-maintainer", "User"), "admin", PULL + ["refresh=true"]),
    # An App: only its installation on this repository lets it review or dismiss here.
    (("sjawhar-agent[bot]", "Bot"), None, PULL + ["refresh=true"]),
    # Any other account's review changes no person's approval: nothing runs, and no job that reads the App's key.
    (("someone", "User"), "read", []),
    (("someone", "User"), "triage", []),
    (("someone", "User"), None, []),
    (("some-org", "Organization"), None, []),
    (("", ""), None, []),
    (("someone;id", "User"), "write", []),
], ids=["a writer", "an admin", "an App", "a reader", "a triager", "an unreadable permission", "an organization",
        "no account", "a login of another shape"])
def test_a_review_approvals_run_refreshes_only_for_a_writer_or_an_app(tmp_path, run_actor, permission, want):
    code, outputs, calls = route_review(tmp_path, ["projects/p/project.yaml"],
                                        run_path=".github/workflows/review-approvals.yml",
                                        run_event="pull_request_review", run_actor=run_actor, permission=permission)
    assert (code, outputs) == (0, want), calls
    if not want:
        # It stops before it reads the pull request, and asks for no job: the comment job, which signs in, does not
        # run (its if needs route's refresh, kind, replay or a held head).
        assert [c for c in calls if "/pulls" in c] == [], calls
        comment_if = workflow("review.yml")["jobs"]["comment"]["if"]
        context = {"github.event_name": "workflow_run", "github.ref": "refs/heads/main",
                   "needs.route.result": "success"}
        assert not evaluate(comment_if, context)


def actor_kind(tmp_path, login, allowed="sjawhar-agent[bot],oss-verify[bot]", answer=None):
    """.github/scripts/actor-kind on `login`, with a stand-in gh: USERS_GH, or `answer` (a status and an error) for
    every read. Return its exit status and output."""
    bin = tmp_path / "bin"
    bin.mkdir(exist_ok=True)
    users = USERS_GH if answer is None else f'*) echo {answer[1]!r} >&2; exit {answer[0]} ;;\n'
    (bin / "gh").write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/calls\ncase " $*" in {users}esac\n')
    (bin / "gh").chmod(0o755)
    run = subprocess.run([str(ROOT / ".github" / "scripts" / "actor-kind"), login], capture_output=True, text=True,
                         env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x",
                              "ALLOWED_BOTS": allowed})
    return run.returncode, run.stdout.strip()


@pytest.mark.parametrize("login, allowed, want", [
    ("someone", "sjawhar-agent[bot],oss-verify[bot]", "person"),
    # A User is a person whatever the list says: the list is only for Apps.
    ("someone", "someone", "person"),
    ("oss-verify[bot]", "sjawhar-agent[bot],oss-verify[bot]", "allowed"),
    # Without case and without [bot], as the action compares, with spaces around the names.
    ("OSS-Verify[bot]", " sjawhar-agent[bot] , oss-verify ", "allowed"),
    ("dependabot[bot]", "sjawhar-agent[bot],oss-verify[bot]", "refused"),
    # Copilot: not found by the Users API, an App with no user account, refused unless the list names it.
    ("Copilot", "sjawhar-agent[bot],oss-verify[bot]", "refused"),
    ("Copilot", "copilot", "allowed"),
    ("dependabot[bot]", "*", "allowed"),
    ("renovate[bot]", "", "refused"),
    # No login GitHub can give: refused, with no read.
    ("a b", "a b", "refused"),
    ("$(touch pwned)", "*", "refused"),
])
def test_actor_kind_decides_as_the_action_does(tmp_path, login, allowed, want):
    assert actor_kind(tmp_path, login, allowed) == (0, want)
    assert not (tmp_path / "pwned").exists() and not (ROOT / "pwned").exists()


def test_actor_kind_fails_on_a_read_that_is_not_a_404(tmp_path):
    assert actor_kind(tmp_path, "someone", answer=(1, "gh: Server Error (HTTP 502)"))[0] == 1


def route_issue(tmp_path, pr, issue, is_pull=False, event="workflow_dispatch", sender="someone", author="",
                association=""):
    """Run review.yml's route step on main, on an `event`: a run started by hand with the inputs `pr` and `issue` (""
    when not given), or an issue's own event for issue `issue`, sent by `sender`, whose author is `author` with
    GitHub's `association`. Its fake gh's number is an issue, or a pull request when `is_pull`. Return its exit status
    and outputs."""
    bin = tmp_path / "bin"
    bin.mkdir()
    pull = {"pull_request": {"url": "x"}} if is_pull else {}
    (tmp_path / "issue.json").write_text(json.dumps({"number": 5, **pull}))
    (bin / "gh").write_text('#!/bin/bash\nfilter=""; for a; do [ "$prev" = --jq ] && filter=$a; prev=$a; done\n'
                            f'echo "$*" >> {tmp_path}/calls\n'
                            f'case " $*" in {USERS_GH}'
                            f'  *"repos/o/r/issues/5"*) jq -r "$filter" {tmp_path}/issue.json ;;\n'
                            '  *) exit 1 ;; esac\n')
    (bin / "gh").chmod(0o755)
    written = tmp_path / "output"
    flow = workflow("review.yml")
    decide = step(flow["jobs"]["route"], "An enrollment, a change or an issue")
    run = subprocess.run(["bash", "-e", "-c", decide["run"]], capture_output=True, text=True, cwd=ROOT,
                         env={**os.environ, **literal_env(flow, decide),
                              "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                              "PR": pr, "ISSUE": issue, "ACTOR": sender, "EVENT": event, "REF": "refs/heads/main",
                              "SENDER": sender, "AUTHOR": author, "ASSOCIATION": association,
                              "GITHUB_OUTPUT": str(written), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")})
    return run.returncode, written.read_text().splitlines() if written.exists() else []


def test_a_run_for_an_issue_asks_for_the_review_alone(tmp_path):
    assert route_issue(tmp_path, "", "5") == (0, ["kind=issue", "issue=5"])


@pytest.mark.parametrize("pr, issue, is_pull", [
    ("8", "5", False),  # both
    ("", "", False),  # neither
    ("", "5", True),  # a pull request given as an issue
    ("", "5x", False),
])
def test_route_refuses_both_inputs_neither_or_a_pull_request_as_an_issue(tmp_path, pr, issue, is_pull):
    code, outputs = route_issue(tmp_path, pr, issue, is_pull)
    assert code != 0 and outputs == []


@pytest.mark.parametrize("action_sender, association", [
    ("alice", "NONE"),  # opened, or edited by its author
    ("alice", "CONTRIBUTOR"),
    ("alice", "COLLABORATOR"),
])
def test_an_issue_that_waits_for_us_starts_one_review_on_its_event(tmp_path, action_sender, association):
    assert route_issue(tmp_path, "", "5", event="issues", sender=action_sender, author="alice",
                       association=association) == (0, ["kind=issue", "issue=5"])
    assert "repos/o/r/issues/5" in (tmp_path / "calls").read_text()


@pytest.mark.parametrize("sender, author, association", [
    ("carol", "carol", "MEMBER"),  # an issue a member of the organization opened or edited
    ("o", "o", "OWNER"),
    ("oss-verify[bot]", "oss-verify[bot]", "NONE"),  # our two bots
    ("sjawhar-agent[bot]", "sjawhar-agent[bot]", "NONE"),
    ("renovate[bot]", "renovate[bot]", "NONE"),  # an App the review action refuses
    ("Copilot", "Copilot", "NONE"),  # an App with no [bot] and no user account
    ("carol", "alice", "NONE"),  # someone else edited or reopened alice's issue: only a person with access can
])
def test_an_issues_event_that_is_ours_starts_nothing(tmp_path, sender, author, association):
    assert route_issue(tmp_path, "", "5", event="issues", sender=sender, author=author,
                       association=association) == (0, [])
    calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
    assert "repos/o/r/issues/5" not in calls
    assert "nothing runs" in (tmp_path / "summary").read_text()


@pytest.mark.parametrize("sender, author, association", [
    ("alice", "$(touch pwned-a)", "NONE"),
    ("`touch pwned-b`", "`touch pwned-b`", "NONE"),
    ("alice", "alice", '"; touch pwned-c; "'),
])
def test_an_issues_event_reaches_route_only_as_data(tmp_path, sender, author, association):
    # route takes the event's sender, author and association from env, never inline in its script: shell text there
    # runs nothing.
    code, outputs = route_issue(tmp_path, "", "5", event="issues", sender=sender, author=author,
                                association=association)
    assert code == 0
    for where in (tmp_path, ROOT):
        assert sorted(where.glob("pwned-*")) == []


# --- tests.yaml's job, its steps run on made-up commits ---


def write_files(directory, files):
    """Write `files` ({path: text, or None for no file}) under `directory`."""
    for path, text in files.items():
        file = directory / path
        if text is None:
            file.unlink()
            continue
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)


def commit(directory, environment, files):
    write_files(directory, files)
    git("add", "-A", cwd=directory, env=environment)
    git("commit", "-q", "--allow-empty", "-m", "change", cwd=directory, env=environment)
    return git("rev-parse", "HEAD", cwd=directory, env=environment)


TREE = {"README.md": "x\n", "docs/a.md": "x\n", "src/t.py": "x\n", "projects/p/project.yaml": "x\n"}
# tests.yaml's step that keeps a fork's change to projects/ from running code, in its jobs suite and docker, and the steps
# before it in each job, which run only git, gh and jq, or check out the commit (each by its name, or by its action).
FORK_STEP = "A fork's change to projects/ runs no code here"
BEFORE_FORK_STEP = {"suite": ["The pull request targets the default branch", "actions/checkout",
                              "The checkout is the merge into the base branch"],
                    "docker": ["actions/checkout"]}
# A class of the Docker tests: it skips unless OV_DOCKER_TESTS is 1, by unittest's skipUnless or by pytest's skipif. The
# unittest form goes when the last test file that is a unittest.TestCase is converted to pytest.
DOCKER_CLASS = re.compile(r'@unittest\.skipUnless\(os\.environ\.get\("OV_DOCKER_TESTS"\) == "1"'
                          r'|@pytest\.mark\.skipif\(os\.environ\.get\("OV_DOCKER_TESTS"\) != "1"')


# A stand-in gh: it logs its arguments, one call to a line, and answers the compare API's status with $STATUS, or fails
# as on an error of the API when $STATUS is error.
COMPARE_GH = ('#!/bin/sh\necho "$*" >> "$GH_LOG"\n'
              '[ "$STATUS" = error ] && { echo "gh: Server Error (HTTP 502)" >&2; exit 1; }\necho "$STATUS"\n')
# A file of the checkout: it logs its path when it runs.
TRAP = '#!/bin/sh\necho "$0" >> "$TRAPPED"\n'


def job_of_tests(job="suite"):
    return workflow("tests.yaml")["jobs"][job]


def fork_step(tmp_path, change):
    """Run tests.yaml's FORK_STEP, as on a fork's run, on a commit that makes `change` to TREE, its first parent, as
    GitHub's merge is made on the base branch's commit. Each file of TREE is a TRAP, and none may run. Return the
    step's outputs and its summary."""
    # git with no configuration from this machine, as in test_take_project.py.
    isolated = isolated_git_env(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo, env=isolated)
    commit(repo, isolated, {path: TRAP for path in TREE})
    commit(repo, isolated, change)
    for path in TREE:
        if (repo / path).exists():
            (repo / path).chmod(0o755)
    output, summary = tmp_path / "output", tmp_path / "summary"
    environment = {**isolated, "FORK": "true", "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
                   "RUNNER_TEMP": str(tmp_path), "TRAPPED": str(tmp_path / "trapped")}
    run = subprocess.run(["bash", "-e", "-c", step(job_of_tests(), FORK_STEP)["run"]], cwd=repo, env=environment,
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert not (tmp_path / "trapped").exists(), (tmp_path / "trapped").read_text()
    outputs = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
    return outputs, summary.read_text()


@pytest.mark.parametrize("change, enrollment", [
    # An enrollment, or any change under projects/, alone or beside others, or a rename out of projects/ (both names
    # count): no step after this one runs, but suite's CREDENTIALS_STEP (below), which runs no file of the fork.
    ({"projects/p/project.yaml": "y\n"}, True),
    ({"projects/q/build.sh": "y\n"}, True),
    ({"projects/p/project.yaml": "y\n", "src/t.py": "y\n"}, True),
    ({"projects/p/project.yaml": None, "src/p.yaml": "x\n"}, True),
    # No file under projects/: tested as a branch of this repository is.
    ({"src/t.py": "y\n"}, False),
    ({".github/workflows/tests.yaml": "y\n"}, False),
    ({"docs/a.md": "y\n"}, False),
    ({"src/projects/x": "y\n"}, False),
    ({}, False),
])
def test_a_forks_change_to_projects_is_an_enrollment(tmp_path, change, enrollment):
    outputs, summary = fork_step(tmp_path, change)
    assert outputs == ({"enrollment": "true"} if enrollment else {})
    assert ("Not run: this pull request is from a fork" in summary) == enrollment


def guard_step(tmp_path, name, base="main", status="ahead"):
    """Run tests.yaml's step `name`, one of the steps before FORK_STEP, as on a pull request into `base` from a fork,
    in a checkout of a merge commit whose first parent is main's commit. Each file of the checkout is a TRAP, the
    stand-in COMPARE_GH answers `status`, and the default branch is main. Return the step's exit status, its output,
    gh's calls, the traps that ran, and the merge's first parent."""
    isolated = isolated_git_env(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo, env=isolated)
    commit(repo, isolated, {path: TRAP for path in TREE})
    git("checkout", "-q", "-b", "pull", cwd=repo, env=isolated)
    commit(repo, isolated, {"src/t.py": TRAP + "# changed\n"})
    git("checkout", "-q", "--detach", "main", cwd=repo, env=isolated)
    git("merge", "-q", "--no-ff", "-m", "merge", "pull", cwd=repo, env=isolated)
    for path in TREE:
        (repo / path).chmod(0o755)
    bin = tmp_path / "bin"
    bin.mkdir()
    (bin / "gh").write_text(COMPARE_GH)
    (bin / "gh").chmod(0o755)
    environment = {**isolated, "PATH": f"{bin}:{isolated['PATH']}", "GH_TOKEN": "x", "REPO": "o/r", "BASE": base,
                   "DEFAULT": "main", "STATUS": status, "GH_LOG": str(tmp_path / "gh.log"),
                   "TRAPPED": str(tmp_path / "trapped")}
    run = subprocess.run(["bash", "-e", "-c", step(job_of_tests(), name)["run"]], cwd=repo, env=environment,
                         capture_output=True, text=True)
    calls = (tmp_path / "gh.log").read_text().splitlines() if (tmp_path / "gh.log").exists() else []
    trapped = (tmp_path / "trapped").read_text().splitlines() if (tmp_path / "trapped").exists() else []
    return run.returncode, run.stdout + run.stderr, calls, trapped, git("rev-parse", "HEAD^1", cwd=repo, env=isolated)


@pytest.mark.parametrize("base, passes", [("main", True), ("ci/other", False)])
def test_a_pull_request_into_another_branch_fails_the_check(tmp_path, base, passes):
    code, out, calls, trapped, _ = guard_step(tmp_path, "The pull request targets the default branch", base=base)
    assert (code == 0) == passes, out
    assert ("::error::This pull request targets ci/other, not main" in out) == (not passes), out
    assert (calls, trapped) == ([], [])


@pytest.mark.parametrize("status, passes", [
    # The merge's first parent is in the history of the base branch: the run checked out a merge into it.
    ("identical", True), ("ahead", True),
    # A merge into an earlier base (after a change of base), or a compare that fails.
    ("behind", False), ("diverged", False), ("error", False),
])
def test_the_check_fails_unless_the_checkout_is_the_merge_into_the_base_branch(tmp_path, status, passes):
    code, out, calls, trapped, parent = guard_step(tmp_path, "The checkout is the merge into the base branch",
                                                   base="a/b c", status=status)
    assert (code == 0) == passes, out
    assert ("Push a commit to the branch" in out) == (status in ("behind", "diverged")), out
    # One compare, of the merge's first parent with the base branch, its name encoded for the URL.
    assert calls == [f"api repos/o/r/compare/{parent}...a%2Fb%20c --jq .status"]
    assert trapped == []


# The step of suite after the fork step: the one step that runs for a fork's enrollment.
CREDENTIALS_STEP = "Each workflow has a code owner, and no pull_request job holds a credential"
# The contexts of a run on pull_request, as the steps after the fork step see them: (env.FORK, the fork step's
# enrollment output, whether such a step runs). A fork's enrollment runs none of them; a fork's other change, whose
# fork step gives no output, and a branch of this repository, whose fork step is skipped, run them all.
RUNS_AFTER_THE_FORK_STEP = (("true", "true", False), ("true", "", True), ("false", "", True))


def runs_after_the_fork_step(later):
    """For each of RUNS_AFTER_THE_FORK_STEP, whether the step `later` of tests.yaml runs: its if, if it has one."""
    return [bool(evaluate(later["if"], {"env.FORK": fork, "steps.fork.outputs.enrollment": found,
                                        "github.event_name": "pull_request"})) if "if" in later else True
            for fork, found, _ in RUNS_AFTER_THE_FORK_STEP]


@pytest.mark.parametrize("job", sorted(BEFORE_FORK_STEP))
def test_no_step_after_the_fork_step_runs_for_a_forks_enrollment(job):
    steps = job_of_tests(job)["steps"]
    names = [s.get("name") or s["uses"].split("@")[0] for s in steps]
    at = names.index(FORK_STEP)
    # Before it, only steps that run no file of the checkout.
    assert names[:at] == BEFORE_FORK_STEP[job]
    fork = steps[at]
    # docker's copy of the step is suite's, which the tests above run.
    assert fork == step(job_of_tests("suite"), FORK_STEP)
    assert fork["id"] == "fork"
    assert [bool(evaluate(fork["if"], {"env.FORK": value})) for value in ("true", "false")] == [True, False]
    assert steps[at + 1:], "no step after the fork step"
    later_steps = steps[at + 1:]
    if job == "suite":
        # The one step after it that runs for a fork's enrollment: workflow-credentials reads files only, and a fork's
        # run takes the script from the merge's first parent (tests.yaml's top), so it runs no code of the fork.
        credentials, *later_steps = later_steps
        assert credentials.get("name") == CREDENTIALS_STEP, credentials.get("name")
        assert "if" not in credentials, f"{CREDENTIALS_STEP} must run for a fork's enrollment too"
    assert CREDENTIALS_STEP not in [s.get("name") for s in later_steps]
    for later in later_steps:
        assert runs_after_the_fork_step(later) == [runs for _, _, runs in RUNS_AFTER_THE_FORK_STEP], later.get("name")


@pytest.mark.parametrize("condition", [
    None,
    "env.FORK == 'true'",
    "steps.fork.outputs.enrollment != 'true' || env.FORK == 'true'",
    "always()",
])
def test_control_a_step_that_runs_for_a_forks_enrollment(condition):
    # Each of these ifs, or none, lets a step after the fork step run for a fork's enrollment: the case above names it.
    later = {"name": "a step", "run": "true", **({"if": condition} if condition else {})}
    assert runs_after_the_fork_step(later)[0] is True


# A fork's file that runs as Python: it logs its path when it runs, and then fails.
PYTHON_TRAP = 'import os, sys\nopen(os.environ["TRAPPED"], "a").write(__file__ + "\\n")\nsys.exit(9)\n'


def credentials_step(tmp_path, run):
    """Run suite's CREDENTIALS_STEP, its script `run`, as on a fork's run with the job's PYTHONPATH (the merge's
    src/), in a checkout of a merge whose first parent holds this tree's .github/, the files the script reads, and
    whose second side replaces .github/scripts/workflow-credentials and adds src/yaml.py, each a
    PYTHON_TRAP, and changes a file under projects/ (an enrollment). A stand-in dpkg says PyYAML is installed, and
    python3 is the interpreter of these tests. Return the step's exit status, its output, and the traps that ran."""
    isolated = isolated_git_env(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo, env=isolated)
    tracked = subprocess.run(["git", "ls-files", "-z", "--", ".github"], cwd=ROOT, capture_output=True, text=True,
                             check=True).stdout.split("\0")
    commit(repo, isolated, {name: (ROOT / name).read_text() for name in tracked if name})
    commit(repo, isolated, {".github/scripts/workflow-credentials": PYTHON_TRAP, "src/yaml.py": PYTHON_TRAP,
                            "projects/p/project.yaml": "x\n"})
    bin = tmp_path / "bin"
    bin.mkdir()
    (bin / "dpkg").write_text("#!/bin/sh\nexit 0\n")
    (bin / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    for tool in ("dpkg", "python3"):
        (bin / tool).chmod(0o755)
    environment = {**isolated, "FORK": "true", "PYTHONPATH": str(repo / "src"), "TRAPPED": str(tmp_path / "trapped"),
                   "PATH": f"{bin}{os.pathsep}{isolated.get('PATH', os.environ['PATH'])}"}
    result = subprocess.run(["bash", "-e", "-c", run], cwd=repo, env=environment, capture_output=True, text=True)
    trapped = tmp_path / "trapped"
    return result.returncode, result.stdout + result.stderr, trapped.read_text() if trapped.exists() else ""


def test_the_credentials_step_runs_the_base_branchs_script_and_no_code_of_a_fork(tmp_path):
    run = step(job_of_tests(), CREDENTIALS_STEP)["run"]
    code, out, trapped = credentials_step(tmp_path, run)
    assert trapped == "", trapped
    assert code == 0, out
    assert out.startswith("Read "), out


def test_control_the_credentials_step_with_python3_p_runs_the_forks_yaml(tmp_path):
    # -P keeps PYTHONPATH, which names the merge's src/: the fork's src/yaml.py shadows PyYAML.
    run = step(job_of_tests(), CREDENTIALS_STEP)["run"]
    assert run.count("python3 -I ") == 2, run
    code, out, trapped = credentials_step(tmp_path, run.replace("python3 -I ", "python3 -P "))
    assert code != 0, out
    assert trapped.strip().endswith("src/yaml.py"), trapped


# The step of each of tests.yaml's jobs suite and docker that runs pytest.
TESTS_STEP = {"suite": "The tests in tests/", "docker": "The Docker tests"}


def shards():
    """tests.yaml's shards of the job docker: [(shard, its pytest-xdist workers, its tests)]."""
    return [(entry["shard"], entry["workers"], entry["tests"].split())
            for entry in job_of_tests("docker")["strategy"]["matrix"]["include"]]


def run_the_tests_step(tmp_path, last_line, status=0, job="suite", shard=None):
    """Run the TESTS_STEP of tests.yaml's `job`, with its own env, the workflow's DOCKER_TESTS and, for docker, the
    matrix values of `shard` (the first by default), a stand-in nproc that says 3, and a stand-in python3 that records
    its arguments and the PYTHONSAFEPATH it gets, prints `last_line` as pytest's last line, and exits `status`. Each
    pytest-xdist worker inherits that environment (the step's comment). Return the step's exit status, its output, and
    pytest's arguments after -m pytest."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin = tmp_path / "bin"
    bin.mkdir()
    (bin / "nproc").write_text("#!/bin/sh\necho 3\n")
    (bin / "python3").write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV"\n'
                                 'printf "%s\\n" "${PYTHONSAFEPATH-unset}" > "$ARGV.safepath"\n'
                                 f'echo "SKIPPED [1] tests/test_x.py:1: a reason"\necho {last_line!r}\nexit {status}\n')
    for name in ("nproc", "python3"):
        (bin / name).chmod(0o755)
    flow = workflow("tests.yaml")
    tests = step(flow["jobs"][job], TESTS_STEP[job])
    matrix = {}
    if job == "docker":
        [entry] = [e for e in flow["jobs"]["docker"]["strategy"]["matrix"]["include"]
                   if e["shard"] == (shard or shards()[0][0])]
        matrix = {"${{ matrix.tests }}": entry["tests"], "${{ matrix.workers }}": str(entry["workers"])}
    env = {name: matrix.get(value, value) for name, value in tests["env"].items()}
    ambient = {name: value for name, value in os.environ.items() if name != "PYTHONSAFEPATH"}
    run = subprocess.run(["bash", "-e", "-c", tests["run"]], cwd=tmp_path, capture_output=True, text=True,
                         env={**ambient, **env, "DOCKER_TESTS": flow["env"]["DOCKER_TESTS"],
                              "PATH": f"{bin}:{os.environ['PATH']}", "ARGV": str(tmp_path / "argv"),
                              "RUNNER_TEMP": str(tmp_path)})
    argv = (tmp_path / "argv").read_text().splitlines()
    assert argv[:3] == ["-P", "-m", "pytest"], argv
    assert (tmp_path / "argv.safepath").read_text() == "1\n"
    return run.returncode, run.stdout + run.stderr, argv[3:]


def test_the_tests_run_on_every_core_and_all_but_the_docker_tests_run(tmp_path):
    code, out, argv = run_the_tests_step(tmp_path, "5 passed in 1.00s")
    assert code == 0, out
    assert argv[argv.index("-n") + 1] == "3" and argv[argv.index("--dist") + 1] == "worksteal", argv
    assert "--durations=30" in argv, argv
    # No test is chosen by name, path, keyword or marker: only the Docker tests' files are left out, with --ignore.
    assert not [a for a in argv if a.startswith(("tests", "--deselect", "-k", "-m"))], argv
    docker = workflow("tests.yaml")["env"]["DOCKER_TESTS"].split()
    assert [a for a in argv if a.startswith("--ignore")] == [f"--ignore={path}" for path in docker]
    # The Docker tests are the files of tests/ with a class that skips unless OV_DOCKER_TESTS is 1.
    marked = sorted(f"tests/{path.name}" for path in (ROOT / "tests").glob("test_*.py")
                    if DOCKER_CLASS.search(path.read_text()))
    assert sorted(docker) == marked


@pytest.mark.parametrize("shard, workers, tests", shards())
def test_each_docker_shard_runs_its_tests_on_its_workers(tmp_path, shard, workers, tests):
    code, out, argv = run_the_tests_step(tmp_path, "5 passed in 1.00s", job="docker", shard=shard)
    assert code == 0, out
    # The shard's workers, whatever the runner's cores (the job's comment says why), each with whole classes.
    assert argv[argv.index("-n") + 1] == str(workers) and argv[argv.index("--dist") + 1] == "loadscope", argv
    assert "--durations=30" in argv, argv
    # The shard's classes and files, and nothing left out or chosen by keyword or marker.
    assert [a for a in argv if a.startswith("tests")] == tests
    assert not [a for a in argv if a.startswith(("--ignore", "--deselect", "-k", "-m"))], argv
    env = step(job_of_tests("docker"), TESTS_STEP["docker"])["env"]
    assert env["OV_DOCKER_TESTS"] == "1", env
    assert env["OV_FP_TOOLCHAIN_C"] == "${{ steps.images.outputs.c }}", env
    assert env["OV_FP_TOOLCHAIN_RUST"] == "${{ steps.images.outputs.rust }}", env


def twice_or_never(groups, docker):
    """The tests of `docker` (a set of node ids) that no group of `groups` (sets of node ids) holds, and those that two
    or more hold, and the tests the groups hold that are not of `docker`."""
    counts = {}
    for group in groups:
        for test in group:
            counts[test] = counts.get(test, 0) + 1
    return docker - set(counts), {t for t, n in counts.items() if n > 1}, set(counts) - docker


def test_every_docker_test_is_in_exactly_one_shard():
    """The shards of the job docker partition the tests of DOCKER_TESTS: none is in no shard, none in two, and no shard
    runs a test of another file. Controls: a class left out of every shard is found, and so is one in two shards."""
    docker = collected(*workflow("tests.yaml")["env"]["DOCKER_TESTS"].split())
    groups = {shard: collected(*tests) for shard, _, tests in shards()}
    assert twice_or_never(groups.values(), docker) == (set(), set(), set())
    python = {test for test in groups["python"]}
    assert python and all("::PythonBuilder::" in test for test in python), python
    left_out = twice_or_never([g for shard, g in groups.items() if shard != "python"], docker)
    assert left_out == (python, set(), set()), left_out
    doubled = twice_or_never([*groups.values(), python], docker)
    assert doubled == (set(), python, set()), doubled


def collected(*arguments):
    """The node ids that pytest collects from this repository with `arguments`, as tests.yaml runs it (-P, -c
    pyproject.toml), with OV_DOCKER_TESTS unset: collection runs no test."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("OV_")}
    run = subprocess.run([sys.executable, "-P", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "-c",
                          "pyproject.toml", *arguments], cwd=ROOT, env=environment, capture_output=True, text=True,
                         timeout=300)
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-2000:]
    ids = {line for line in run.stdout.splitlines() if "::" in line}
    assert ids, run.stdout[-4000:]
    return ids


# The step of tests.yaml's docker that pulls the toolchain images of its shard and makes its frame-pointer images.
IMAGES_STEP = "Pull the toolchain images, and make the frame-pointer images"
# Stand-ins for that step and for the Docker tests' skip conditions. docker: `docker pull --quiet <image>` adds the image
# to the file $PULLED, and `docker image inspect <image>` (docker_ready and toolchain_ready in tests/test_builder.py)
# finds only an image listed there. crane: `crane mutate ... -t <tag>` names the image it made by a digest.
IMAGES_DOCKER = ('#!/bin/bash\ncase "$1 $2" in\n'
                 '  "pull --quiet") echo "$3" >> "$PULLED" ;;\n'
                 '  "image inspect") grep -qxF -- "$3" "$PULLED" ;;\n'
                 '  *) exit 1 ;;\nesac\n')
IMAGES_CRANE = ('#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = -t ] && tag=$2; shift; done\n'
                'echo "${tag%:*}@sha256:$(printf %064d 0)"\n')
# Run with the node ids of the Docker tests' classes, or their files: for each class that pytest collects there, a line
# "<class node id>\t<why the class, or a test of it, skips>", empty where none skips. Collecting imports each file,
# which evaluates its skip conditions. A test's skips are the skip and skipif marks that pytest finds on it (its module,
# its class and the class's bases, the test), read as pytest's skipping plugin reads them, except that a condition given
# as a string counts as true: write it as a value; and, for a test of a unittest.TestCase, unittest's own
# (__unittest_skip__). The unittest branch goes when the last test file that is a unittest.TestCase is converted.
SKIPS = r"""
import sys, unittest
import pytest


def marked(item):
    for mark in item.iter_markers("skip"):
        return mark.kwargs.get("reason") or (mark.args[0] if mark.args else "") or "skip"
    for mark in item.iter_markers("skipif"):
        conditions = (mark.kwargs["condition"],) if "condition" in mark.kwargs else mark.args
        if not conditions or any(conditions):
            return mark.kwargs.get("reason") or "skipif"
    return ""


class Collected:
    def pytest_collection_finish(self, session):
        self.items = session.items


collected = Collected()
code = pytest.main(["--collect-only", "-p", "no:terminal", "-p", "no:cacheprovider", "-c", "pyproject.toml",
                    *sys.argv[1:]], plugins=[collected])
if code != 0:
    sys.exit(f"pytest collected {sys.argv[1:]} with exit status {code}")
reasons = {}
for item in collected.items:
    found = reasons.setdefault("::".join(item.nodeid.split("::")[:2]), [])
    if isinstance(item.cls, type) and issubclass(item.cls, unittest.TestCase):
        if getattr(item.cls, "__unittest_skip__", False) and item.cls.__unittest_skip_why__ not in found:
            found.insert(0, item.cls.__unittest_skip_why__)
        if getattr(item.obj, "__unittest_skip__", False):
            found.append(f"{item.name}: {item.obj.__unittest_skip_why__}")
    if why := marked(item):
        found.append(f"{item.name}: {why}")
for name, found in reasons.items():
    print(f"{name}\t{'; '.join(found)}")
"""


def shard_skips(tmp_path, shard, edit=lambda text: text, **change):
    """Run tests.yaml's IMAGES_STEP (its script through `edit`) as in the docker shard `shard`, with `change` to its
    matrix entry, on IMAGES_DOCKER and IMAGES_CRANE, and check that it pulled each frame-pointer image that it names in
    its outputs; then, where Docker has only the images that the step pulled and with the env of the shard's TESTS_STEP
    (the step's outputs filled in), and a stand-in qemu-riscv64-static, read the skip conditions of the shard's classes
    (SKIPS). Return {class node id: why it, or a test of it, skips, or ""}."""
    tmp_path.mkdir(parents=True)
    bin = tmp_path / "bin"
    bin.mkdir()
    for name, text in (("docker", IMAGES_DOCKER), ("crane", IMAGES_CRANE), ("qemu-riscv64-static", "#!/bin/sh\n"),
                       ("python3", f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')):
        (bin / name).write_text(text)
        (bin / name).chmod(0o755)
    docker = job_of_tests("docker")
    [entry] = [e for e in docker["strategy"]["matrix"]["include"] if e["shard"] == shard]
    ctx = {f"matrix.{key}": str(value) for key, value in {**entry, **change}.items()}
    pulled, outputs = tmp_path / "pulled", tmp_path / "outputs"
    pulled.touch()
    outputs.touch()
    ambient = {name: value for name, value in os.environ.items() if not name.startswith("OV_")}
    standing = {**ambient, "PATH": f"{bin}:{os.environ['PATH']}", "PULLED": str(pulled)}
    images = step(docker, IMAGES_STEP)
    env = {name: interpolated(str(value), ctx) for name, value in images["env"].items()}
    run = subprocess.run(["bash", "-e", "-c", edit(images["run"])], cwd=ROOT, capture_output=True, text=True,
                         env={**standing, **env, "GITHUB_OUTPUT": str(outputs), "PYTHONPATH": str(ROOT / "src")})
    assert run.returncode == 0, run.stdout + run.stderr
    made = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    # FramePointers skips only without the base image or the variable, so this checks the frame-pointer image itself.
    assert set(made.values()) <= set(pulled.read_text().split()), ("a frame-pointer image not pulled", made)
    ctx.update((f"steps.images.outputs.{name}", image) for name, image in made.items())
    env = {name: interpolated(str(value), ctx) for name, value in step(docker, TESTS_STEP["docker"])["env"].items()}
    run = subprocess.run([sys.executable, "-P", "-c", SKIPS, *ctx["matrix.tests"].split()], cwd=ROOT,
                         capture_output=True, text=True, timeout=300,
                         env={**standing, **env, "PYTHONPATH": f"{ROOT / 'src'}{os.pathsep}{ROOT / 'tests'}"})
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-4000:]
    return dict(line.split("\t", 1) for line in run.stdout.splitlines())


def test_each_class_of_a_docker_shard_finds_the_images_it_needs_there(tmp_path):
    """Each shard of docker pulls the toolchain images, and makes the frame-pointer images, that its classes need: where
    Docker has only the images that the shard's IMAGES_STEP pulled, with its TESTS_STEP's env, no class of the shard,
    and no test of one, skips. Each class asks Docker for the images it needs in its own skipUnless or skipif, so this
    reads its need from there. The classes read are all that pytest collects of the shard. Controls: the shard python
    without the Python image, and the shard c without its frame-pointer row, are found, and so is a step that makes a
    frame-pointer image and does not pull it."""
    for shard, _, tests in shards():
        skips = shard_skips(tmp_path / shard, shard)
        assert set(skips) == {"::".join(test.split("::")[:2]) for test in collected(*tests)}, (shard, skips)
        assert {name: why for name, why in skips.items() if why} == {}, shard
    python = shard_skips(tmp_path / "python-on-c", "python", languages="c")
    assert list(python) == ["tests/test_builder.py::PythonBuilder"], python
    assert "the Python toolchain image" in python["tests/test_builder.py::PythonBuilder"], python
    c = shard_skips(tmp_path / "c-without-frame-pointers", "c", frame_pointers="")
    assert {name for name, why in c.items() if why} == {"tests/test_builder.py::FramePointersC"}, c
    assert "OV_FP_TOOLCHAIN_C" in c["tests/test_builder.py::FramePointersC"], c
    with pytest.raises(AssertionError, match="a frame-pointer image not pulled"):
        shard_skips(tmp_path / "rust-made-not-pulled", "rust",
                    edit=lambda text: text.replace('docker pull --quiet "$ref" > /dev/null\n', ""))


def test_the_skip_reader_finds_each_form_of_skip(tmp_path):
    """SKIPS, on made-up test files: each skip of a pytest test is found, whatever its form and wherever pytest finds
    it (the module, a base class, the class, the test), with its reason or a stand-in for an empty one; and so is each
    skip of a unittest.TestCase, unittest's or pytest's. A skipif whose conditions are all false is not."""
    test = "    def test_a(self):\n        pass\n"
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    (tmp_path / "test_marks.py").write_text(
        "import pytest\n\n\n"
        f"@pytest.mark.skip\nclass TestBare:\n{test}\n\n"
        f"@pytest.mark.skip('positional')\nclass TestPositional:\n{test}\n\n"
        f"@pytest.mark.skipif(True, reason='')\nclass TestEmpty:\n{test}\n\n"
        f"@pytest.mark.skipif(condition=True, reason='by keyword')\nclass TestKeyword:\n{test}\n\n"
        f"@pytest.mark.skipif(False, True, reason='second')\nclass TestSecond:\n{test}\n\n"
        "@pytest.mark.skipif(True, reason='base')\nclass Base:\n    pass\n\n\n"
        f"@pytest.mark.usefixtures()\nclass TestInherited(Base):\n{test}\n\n"
        f"class TestMethod:\n    @pytest.mark.skipif(True, reason='method')\n{test}\n    def test_b(self):\n"
        "        pass\n\n\n"
        f"@pytest.mark.skipif(False, reason='false')\nclass TestRuns:\n{test}")
    (tmp_path / "test_module.py").write_text(
        f"import pytest\n\npytestmark = pytest.mark.skipif(True, reason='module')\n\n\nclass TestA:\n{test}")
    (tmp_path / "test_case.py").write_text(
        f"import pytest\nimport unittest\n\n\n@unittest.skipUnless(False, 'class')\nclass Case(unittest.TestCase):\n"
        f"{test}\n\nclass Method(unittest.TestCase):\n    @unittest.skipIf(True, 'method')\n{test}\n\n"
        f"@pytest.mark.skipif(True, reason='a pytest mark')\nclass Marked(unittest.TestCase):\n{test}")
    run = subprocess.run([sys.executable, "-P", "-c", SKIPS, "test_marks.py", "test_module.py", "test_case.py"],
                         cwd=tmp_path, capture_output=True, text=True, timeout=300)
    assert run.returncode == 0, run.stdout + run.stderr
    assert dict(line.split("\t", 1) for line in run.stdout.splitlines()) == {
        "test_marks.py::TestBare": "test_a: skip", "test_marks.py::TestPositional": "test_a: positional",
        "test_marks.py::TestEmpty": "test_a: skipif", "test_marks.py::TestKeyword": "test_a: by keyword",
        "test_marks.py::TestSecond": "test_a: second", "test_marks.py::TestInherited": "test_a: base",
        "test_marks.py::TestMethod": "test_a: method", "test_marks.py::TestRuns": "",
        "test_module.py::TestA": "test_a: module",
        "test_case.py::Case": "class", "test_case.py::Method": "test_a: method",
        "test_case.py::Marked": "test_a: a pytest mark",
    }


def selection(tmp_path, job):
    """The arguments of pytest that choose the tests in the TESTS_STEP of tests.yaml's `job`, as run_the_tests_step
    finds them (for docker, those of every shard together): its arguments but -n, --dist, --durations, -q and -rs,
    which choose how the tests run and what pytest prints, not which tests run."""
    chosen = []
    for shard in ([name for name, _, _ in shards()] if job == "docker" else [None]):
        _, _, argv = run_the_tests_step(tmp_path / job / (shard or "all"), "1 passed in 1.00s", job=job, shard=shard)
        skip = False
        for argument in argv:
            if skip:
                skip = False
            elif argument in ("-n", "--dist"):
                skip = True
            elif not argument.startswith("--durations=") and argument not in ("-q", "-rs"):
                chosen.append(argument)
    return chosen


def test_every_test_runs_in_suite_or_in_docker(tmp_path):
    """Each test that pytest collects under tests/ is one that suite or docker runs: no selection of one job leaves
    out a test that the other does not run. A control leaves a class out of both, and finds it."""
    for job in TESTS_STEP:
        (tmp_path / job).mkdir()
    suite, docker = selection(tmp_path, "suite"), selection(tmp_path, "docker")
    everything, in_docker = collected(), collected(*docker)
    assert everything - collected(*suite) - in_docker == set()
    left_out = "tests/test_no_frame_pointer_image.py::TestNoFramePointerImage"
    found = everything - collected(*suite, "--deselect", left_out) - in_docker
    assert found == {f"{left_out}::test_frame_pointers_skips_when_no_frame_pointer_image_is_named"}, found


@pytest.mark.parametrize("job", sorted(TESTS_STEP))
@pytest.mark.parametrize("last_line, status, fails", [
    ("5 passed in 1.00s", 0, False),
    ("5 passed, 2 deselected in 1.00s", 0, False),
    # A test that skipped fails the step, as does pytest's own failure.
    ("5 passed, 1 skipped in 1.00s", 0, True),
    ("1 skipped in 1.00s", 0, True),
    ("1 failed, 4 passed in 1.00s", 1, True),
])
def test_the_tests_step_fails_when_a_test_skips(tmp_path, job, last_line, status, fails):
    code, out, _ = run_the_tests_step(tmp_path, last_line, status, job=job)
    assert (code != 0) == fails, out
    assert ("::error::A test skipped here" in out) == (fails and status == 0), out


# The workflow files of main's four required checks, as .github/scripts/required-check names them (its CHECKS).
CHECK_WORKFLOWS = tuple(path.removeprefix(".github/workflows/") for path in required_check.CHECKS)
# opened and synchronize share the group that cancels an older push. Every other documented pull_request action is
# kept apart, including actions that the workflows do not currently take.
# https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request
PUSHES = ("opened", "synchronize")
SAME_HEAD = ("assigned", "unassigned", "labeled", "unlabeled", "edited", "closed", "reopened", "converted_to_draft",
             "locked", "unlocked", "enqueued", "dequeued", "milestoned", "demilestoned", "ready_for_review",
             "review_requested", "review_request_removed", "auto_merge_enabled", "auto_merge_disabled")
# The workflows of one job of seconds, which have no concurrency group and so cancel no run (each file says why).
NO_CANCEL = {"validate.yaml", "terms.yaml"}


def group_of(flow, action, head, number=7, run_id=101, merge_sha="c" * 40):
    """The pull request's concurrency group, or None when the workflow has none. Even cancel-in-progress: false can
    cancel a pending run, so sharing any group counts as a conflict here."""
    concurrency = flow.get("concurrency")
    if concurrency is None:
        return None
    return interpolated(concurrency["group"], {
        "github.event_name": "pull_request", "github.event.action": action, "github.ref": f"refs/pull/{number}/merge",
        "github.run_id": run_id, "github.sha": merge_sha,
        "github.event.pull_request.number": number, "github.event.pull_request.head.sha": head})


def assert_independent_groups(groups):
    # GitHub compares group names without case. An empty enumeration is no evidence of independence.
    assert groups
    assert set(groups) == {None} or len({g.lower() for g in groups}) == len(groups), groups


def test_a_newer_run_of_a_pull_request_or_of_main_cancels_the_older():
    # The pushes of a pull request: test_a_push_cancels_the_run_of_the_older_head.
    flow = workflow("tests.yaml")
    assert flow["concurrency"]["cancel-in-progress"] is True

    def main(sha, run_id):
        # A push has neither an action nor a pull_request object.
        return interpolated(flow["concurrency"]["group"],
                            {"github.event_name": "push", "github.ref": "refs/heads/main", "github.sha": sha,
                             "github.run_id": run_id})

    older, newer = "a" * 40, "b" * 40
    assert main(older, 101) == main(newer, 102)
    for action in PUSHES + SAME_HEAD:
        assert main(older, 101) != group_of(flow, action, older, run_id=103), action


@pytest.mark.parametrize("name", CHECK_WORKFLOWS)
def test_two_runs_at_one_head_from_two_actions_cancel_neither(name):
    # On #317 a push and an edit of the description in one second started two Terms runs at 003eaa4 in one group, and
    # GitHub cancelled the newer, 45815765694, and kept the older, 45815765408. required-check posts the job of the
    # newest run, so the App posted terms-accepted cancelled. A push, an edit, a reopen or a draft marked ready at one
    # head are in no shared group.
    flow = workflow(name)
    on = flow.get("on", flow.get(True))
    actions = set(on["pull_request"]["types"])
    assert {"opened", "reopened", "synchronize"} <= actions <= set(PUSHES + SAME_HEAD), on
    if name == "terms.yaml":
        assert "edited" in actions, on
    if name == "build.yaml":
        assert "ready_for_review" in actions, on
    # group_of reads the workflow's group only: a job's own group would cancel that job of a run at the same head.
    assert [job for job, body in flow["jobs"].items() if "concurrency" in body] == [], name
    # The incident's original Terms group must fail this same assertion before the changed workflows can pass it. The
    # groups are evaluated outside pytest.raises, so that an AssertionError of the evaluator cannot stand in for one.
    shared = {"concurrency": {"group": "terms-${{ github.event_name }}-${{ github.event.pull_request.number }}"}}
    incident = [group_of(shared, action, "a" * 40) for action in ("synchronize", "edited")]
    with pytest.raises(AssertionError):
        assert_independent_groups(incident)
    # A missing head or action evaluates to an empty string, not an unevaluated expression. Neither removes the
    # action's separation from the pushes. Missing and empty values have the same GitHub string representation.
    for head, push in itertools.product(("a" * 40, None, ""), PUSHES):
        groups = [group_of(flow, action, head, run_id=run_id)
                  for run_id, action in enumerate((push, *SAME_HEAD, None), 101)]
        assert_independent_groups(groups)


@pytest.mark.parametrize("name", sorted(set(CHECK_WORKFLOWS) - NO_CANCEL))
def test_two_runs_at_one_head_keep_other_actions_apart_at_different_heads(name):
    # Dropping head.sha from the non-push suffix must not let a late reopen cancel the run at a different head.
    flow = workflow(name)
    for action in SAME_HEAD:
        groups = [group_of(flow, action, head) for head in ("a" * 40, "b" * 40)]
        assert groups[0] != groups[1], (action, groups)
        assert group_of(flow, action, "a" * 40, number=8) not in groups, action


@pytest.mark.parametrize("name", sorted(set(CHECK_WORKFLOWS) - NO_CANCEL))
def test_a_push_cancels_the_run_of_the_older_head(name):
    # R6 of dispatch://INFRA-5359/spec: no run for a replaced push.
    flow = workflow(name)
    assert flow["concurrency"]["cancel-in-progress"] is True
    older, newer = "a" * 40, "b" * 40
    runs = [(action, head, run_id) for run_id, (action, head)
            in enumerate(itertools.product(PUSHES, (older, newer)), 101)]

    def groups(current):
        return {group_of(current, action, head, run_id=run_id, merge_sha=f"{run_id:040x}")
                for action, head, run_id in runs}

    # A group keyed by the run id cannot cancel an older head. This control would pass if the contexts omitted it.
    distinct_runs = {"concurrency": {"group": flow["concurrency"]["group"] + "-${{ github.run_id }}"}}
    assert len(groups(distinct_runs)) == 4
    shared = groups(flow)
    assert len(shared) == 1, shared
    # Another pull request's push cancels neither.
    assert group_of(flow, "synchronize", newer, number=8, run_id=105, merge_sha="d" * 40) not in shared


def test_only_a_workflow_of_one_job_cancels_no_run():
    assert set(CHECK_WORKFLOWS) == {"build.yaml", "tests.yaml", "validate.yaml", "terms.yaml"}
    assert {name for name in CHECK_WORKFLOWS if "concurrency" not in workflow(name)} == NO_CANCEL
    for name in NO_CANCEL:
        assert len(workflow(name)["jobs"]) == 1, name


def test_the_required_check_tests_passes_only_when_suite_and_docker_passed(tmp_path):
    job = workflow("tests.yaml")["jobs"]["tests"]
    # It always runs, after both, and runs nothing of the checkout: one run step, with no token.
    assert (job["needs"], job["if"], job["permissions"]) == (["suite", "docker"], "always()", {})
    [gate] = job["steps"]
    assert set(gate) == {"name", "env", "run"}, gate
    assert gate["env"] == {"SUITE": "${{ needs.suite.result }}", "DOCKER": "${{ needs.docker.result }}"}
    results = ("success", "failure", "cancelled", "skipped", "")
    for suite, docker in itertools.product(results, repeat=2):
        summary = tmp_path / f"summary-{suite}-{docker}"
        run = subprocess.run(["bash", "-e", "-c", gate["run"]], capture_output=True, text=True,
                             env={**os.environ, "SUITE": suite, "DOCKER": docker, "GITHUB_STEP_SUMMARY": str(summary)})
        passes = suite == docker == "success"
        assert (run.returncode == 0) == passes, (suite, docker, run.stdout)
        errors = [line for line in run.stdout.splitlines() if line.startswith("::error::")]
        assert len(errors) == (suite != "success") + (docker != "success"), (suite, docker, run.stdout)


def test_the_docker_job_runs_for_every_event_but_a_pull_request_into_another_branch():
    condition = workflow("tests.yaml")["jobs"]["docker"]["if"]
    for ctx, runs in (({"github.event_name": "push"}, True),
                      ({"github.event_name": "pull_request", "github.event.pull_request.base.ref": "main",
                        "github.event.pull_request.base.repo.default_branch": "main"}, True),
                      ({"github.event_name": "pull_request", "github.event.pull_request.base.ref": "ci/other",
                        "github.event.pull_request.base.repo.default_branch": "main"}, False)):
        assert bool(evaluate(condition, ctx)) == runs, ctx


@pytest.mark.parametrize("name", ["tests.yaml", "validate.yaml"])
def test_no_job_reads_or_writes_the_actions_cache(name):
    # GitHub gives a pull_request job write access to its merge ref's cache unless cache-mode says otherwise.
    flow = workflow(name)
    assert flow["cache-mode"] == "none"
    assert [job for job, spec in flow["jobs"].items() if "cache-mode" in spec] == []


@pytest.mark.parametrize("name, tools", [
    ("actionlint and shellcheck pass the workflows", ("ACTIONLINT", "SHELLCHECK")),
    ("The package builds, installs and runs", ("UV",)),
])
def test_the_suite_checks_each_tool_it_fetches_by_its_sha256(name, tools):
    checks = step(job_of_tests("suite"), name)
    for tool in tools:
        assert re.fullmatch(r"\d+\.\d+\.\d+", str(checks["env"][f"{tool}_VERSION"])), tool
        assert re.fullmatch(r"[0-9a-f]{64}", checks["env"][f"{tool}_SHA256"]), tool
        # Checked before the archive is unpacked.
        run = checks["run"]
        assert -1 < run.index(f'echo "${tool}_SHA256  ') < run.index("tar -x", run.index(f"${tool}_VERSION")), tool


def test_the_package_check_builds_with_uvs_own_backend_and_runs_the_installed_package():
    run = step(job_of_tests("suite"), "The package builds, installs and runs")["run"]
    # uv builds offline only with the backend it bundles: the version that pyproject.toml's uv_build range names.
    version = step(job_of_tests("suite"), "The package builds, installs and runs")["env"]["UV_VERSION"]
    pyproject = (ROOT / "pyproject.toml").read_text()
    low, high = re.search(r'requires = \["uv_build>=([\d.]+),<([\d.]+)"\]', pyproject).groups()
    as_tuple = lambda text: tuple(int(part) for part in text.split("."))
    assert as_tuple(low) <= as_tuple(version) < as_tuple(high), (version, low, high)
    assert "uv build --offline --wheel" in run
    assert "--require-hashes -r" in run
    assert 'env -u PYTHONPATH "$package/venv/bin/oss-verify" --help' in run


def test_the_docker_job_makes_the_images_as_toolchain_images_yaml_does():
    """docker's crane and registry are toolchain-images.yaml's, and its shards make the frame-pointer images of the base
    rows that tests/test_builder.py's FramePointersC and FramePointersRust build on, each row in one shard: the step
    makes those of its shard's frame_pointers."""
    from test_builder import FRAME_POINTER_IMAGES

    tests, images = workflow("tests.yaml"), workflow("toolchain-images.yaml")
    for name in ("CRANE_VERSION", "CRANE_SHA256", "CRANE_ARCHIVE"):
        assert tests["env"][name] == images["env"][name], name
    assert tests["jobs"]["docker"]["services"]["registry"] == images["jobs"]["make"]["services"]["registry"]
    pull = step(tests["jobs"]["docker"], IMAGES_STEP)
    assert pull["env"]["FRAME_POINTERS"] == "${{ matrix.frame_pointers }}", pull["env"]
    rows = re.findall(r"(?m)^for row in (.+); do$", pull["run"])
    assert rows == ['"${rows[@]}"'], pull["run"]
    made = [row for entry in tests["jobs"]["docker"]["strategy"]["matrix"]["include"]
            for row in entry["frame_pointers"].split()]
    assert sorted(made) == sorted(row for row, _ in FRAME_POINTER_IMAGES.values())


# --- the triage comment: triage.yaml's one job, and review.yml's route after it ---


@pytest.mark.parametrize("action, changes, runs", [
    ("opened", {}, True), ("reopened", {}, True), ("synchronize", {}, True),
    # An edit of the description, which the comment reports on (its checklist), or a change of base.
    ("edited", {"body": {"from": "x"}}, True),
    ("edited", {"base": {"ref": {"from": "other"}}}, True),
    # An edit of the title alone, which the comment does not show: no job, so no run that ends success.
    ("edited", {"title": {"from": "x"}}, False),
])
def test_triages_job_runs_unless_the_edit_is_of_the_title_alone(action, changes, runs):
    jobs = workflow("triage.yaml")["jobs"]
    assert sorted(jobs) == ["triage"]
    ctx = {"github.event_name": "pull_request", "github.event.action": action,
           **{f"github.event.changes.{k}": v for k, v in changes.items()}}
    assert bool(evaluate(jobs["triage"]["if"], ctx)) == runs


def test_triage_starts_only_for_projects_and_no_required_check_is_path_filtered_on_a_pull_request():
    """triage.yaml's paths filter: GitHub starts Triage only for a pull request into main that changes a file under
    projects/, the only pull request that review.yml writes a triage comment for, on each of its four event types. A
    workflow that its paths filter skips leaves its checks pending, which blocks a merge only when the ruleset requires
    one: triage is no required check, and no workflow that reports one has a paths filter on a pull request's event.
    A filter on a push (tests.yaml's, for a fork's enrollment) leaves no pull request waiting: the pull request's own
    run reports the check."""
    triage = workflow("triage.yaml")
    assert triage[True]["pull_request"] == {"branches": ["main"], "paths": ["projects/**"],
                                            "types": ["opened", "edited", "reopened", "synchronize"]}
    assert {job.get("name", name) for name, job in triage["jobs"].items()}.isdisjoint(RULESET)
    reporters = {**REQUIRED, "terms.yaml": "terms-accepted"}
    assert set(reporters.values()) == RULESET
    for name, check in reporters.items():
        assert check in {job.get("name", key) for key, job in workflow(name)["jobs"].items()}, name
        for event, spec in workflow(name)[True].items():
            if event != "push":
                assert not {"paths", "paths-ignore"} & set(spec or {}), f"{name}: {event} has a paths filter"


@pytest.mark.parametrize("files, want", [
    (["projects/p/project.yaml"], ["triage=true"]),
    (["README.md", "projects/p/build.sh"], ["triage=true"]),
    ([("src/x.yaml", "projects/p/x.yaml")], ["triage=true"]),
    (["README.md", "src/t.py"], None),
])
def test_reviews_route_asks_for_the_triage_comment_after_a_triage_run_that_touches_projects(tmp_path, files, want):
    """After a Triage run that ended success, the triage comment alone (no kind, so no review), and only for a pull
    request that touches projects/."""
    code, outputs, _ = route_review(tmp_path, files, run_path=".github/workflows/triage.yaml")
    assert (code, outputs) == (0, PULL + want if want else [])


@pytest.mark.parametrize("actor, held, want", [
    # A person's run by hand writes the triage comment too, whatever the review does: here no Build run of the head
    # wrote results, so no review runs.
    ("alice", (), ["triage=true"]),
    # Held runs' run for a held head screens it alone: the Triage run that its approval lets complete has the comment
    # written.
    ("github-actions[bot]", (51,), ["kind=enrollment", "held=true"]),
    # Held runs' run for a head that is no longer held: nothing.
    ("github-actions[bot]", (), None),
])
def test_a_run_by_hand_that_a_person_starts_writes_the_triage_comment(tmp_path, actor, held, want):
    code, outputs, _ = route_review(tmp_path, ["projects/p/project.yaml"], actor=actor, event="workflow_dispatch",
                                    held=held)
    assert (code, outputs) == (0, PULL + want if want else [])


def build_run(run_id, head_sha="a" * 40, repository="mallory/libx", branch="main"):
    """A completed Build run on pull_request: by default of pull request 8's head commit, repository and branch."""
    return {"id": run_id, "path": ".github/workflows/build.yaml", "event": "pull_request", "status": "completed",
            "head_sha": head_sha, "head_repository": {"full_name": repository}, "head_branch": branch}


# The artifact build-results of a Build run, not expired.
RESULTS = {"id": 1, "name": "build-results", "expired": False}


@pytest.mark.parametrize("builds, want", [
    # One completed Build run of the head, with one build-results.
    ([(build_run(901), [RESULTS])], "901"),
    # Of two such runs, the newer.
    ([(build_run(901), [RESULTS]), (build_run(902), [RESULTS])], "902"),
    # A newer run of another repository, branch or head commit is not taken.
    ([(build_run(901), [RESULTS]), (build_run(902, repository="eve/libx"), [RESULTS])], "901"),
    ([(build_run(901), [RESULTS]), (build_run(902, branch="other"), [RESULTS])], "901"),
    ([(build_run(901), [RESULTS]), (build_run(902, head_sha="b" * 40), [RESULTS])], "901"),
    # No build-results, two of them, or one that expired: no run wrote results.
    ([(build_run(901), [])], None),
    ([(build_run(901), [RESULTS, dict(RESULTS, id=2)])], None),
    ([(build_run(901), [dict(RESULTS, expired=True)])], None),
])
def test_a_persons_run_by_hand_of_an_enrollment_reads_the_newest_build_run_that_wrote_results(tmp_path, builds, want):
    """A run by hand that a person starts, for an enrollment whose runs GitHub does not hold: the review reads the
    results of the newest completed Build run of the head, from its repository and branch, that lists exactly one
    build-results that has not expired. With no such run, there is no kind, so no review runs, and the summary says
    why."""
    code, outputs, _ = route_review(tmp_path, ["projects/p/project.yaml"], actor="alice", event="workflow_dispatch",
                                    builds=builds)
    if want:
        assert (code, outputs) == (0, PULL + ["kind=enrollment", f"build_run={want}", "triage=true"])
    else:
        assert (code, outputs) == (0, PULL + ["triage=true"])
        assert "No Build run of this head wrote results: a push, or a close and a reopen, builds it." in \
            (tmp_path / "summary").read_text()


@pytest.mark.parametrize("run_path", [".github/workflows/build.yaml", ".github/workflows/triage.yaml"])
def test_reviews_route_fails_when_it_cannot_read_the_files(tmp_path, run_path):
    code, outputs, _ = route_review(tmp_path, ["projects/p/project.yaml"], run_path=run_path, fail=True)
    assert code != 0 and outputs == []


def test_reviews_route_asks_for_the_triage_comment_whenever_triage_py_would_comment():
    # triage.py writes a comment only when split_paths names a project; route asks for the comment when a path matches
    # its grep pattern. Over every path of up to four segments from a set that includes near misses, the first must
    # imply the second, so that a change to either rule that lets them drift apart fails here.
    spec = importlib.util.spec_from_file_location("triage", ROOT / ".github" / "scripts" / "triage.py")
    triage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(triage)
    run = step(workflow("review.yml")["jobs"]["route"], "An enrollment, a change or an issue")["run"]
    patterns = re.findall(r"grep -q '([^']+)' <<< \"\$paths\"", run)
    assert len(patterns) == 1, patterns
    asks = re.compile(patterns[0])
    segments = ["projects", "Projects", "project", "docs", "p", "x.md", ".github", ""]
    paths = ["/".join(parts) for size in range(1, 5) for parts in itertools.product(segments, repeat=size)]
    named = [path for path in paths if triage.split_paths([path])[0]]
    assert "projects/p/x.md" in named
    assert [path for path in named if not asks.search(path)] == []
