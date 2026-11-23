# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the routed workflows (build.yaml, review.yml) and their collector, .github/scripts/collect, for the
workflows of one job that report a required check (tests.yaml, validate.yaml), and for the condition of triage.yaml's
one job:  uv run pytest

A routed workflow has a route job that decides which jobs the run needs, and a collector job that always runs last,
collects every result with the collector, and reports the workflow's one check: build.yaml's job required reports the
check that the ruleset requires, and review.yml's job collect the check review jobs, which no ruleset requires. These
check the collector's verdicts, the shape every routed workflow keeps (the collector waits for every job, and no job a
route may skip reports a required check), and the routes' own steps, run on made-up changes. tests.yaml and
validate.yaml have one job each, which reports their required check and runs on every event. These also run the steps
of tests.yaml's job: the step that keeps a fork's change to projects/ from running any code, and the step that runs the
tests.
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
ONE_JOB = {name: REQUIRED[name] for name in ("tests.yaml", "validate.yaml")}
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
                 held=(), builds=(), fail=False):
    """Run review.yml's route step on main, started by `actor`, with a fake gh that applies the step's --jq filter as
    gh does. On workflow_run, after run 900 of `run_path` on `run_event` that ended `conclusion`, at the head a*40 of
    mallory/libx's branch main; on workflow_dispatch, a run by hand of pull request 8. The gh gives as the open pull
    requests of that head `pulls` (by default pull request 8 into main), pull request 8 and its `files` (or fails to
    list them when `fail`), the runs GitHub holds at its head (`held`, their ids), and the completed Build runs of the
    head in `builds`, each a pair (the run, the artifacts named build-results that it lists), by default none.
    Return its exit status, its outputs (one line each), and the gh calls."""
    bin = tmp_path / "bin"
    bin.mkdir()
    pull = pull_request(files, changed)
    answers = {"pulls": [pull] if pulls is None else pulls, "pull": pull,
               "builds": {"workflow_runs": [run for run, _ in builds]},
               "held": {"workflow_runs": [{"id": i, "status": "completed", "conclusion": "action_required",
                                           "head_sha": "a" * 40, "head_branch": "main",
                                           "head_repository": {"full_name": "mallory/libx"}} for i in held]}}
    answers.update({f"artifacts-{run['id']}": {"artifacts": list(artifacts)} for run, artifacts in builds})
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
                   RUN_HEAD_SHA="a" * 40, RUN_HEAD_REPOSITORY="mallory/libx", RUN_HEAD_BRANCH="main")
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
    # An App the action refuses (src/github/validation/actor.ts) would fail the review, and so the check review jobs:
    # by its account type, so Copilot, whose login has no [bot] and which the Users API does not find, too.
    ("dependabot[bot]", ENROLLMENT), ("oss-verify[bot]x[bot]", ENROLLMENT), ("Copilot", ENROLLMENT),
])
def test_a_change_that_an_app_the_review_refuses_started_is_an_enrollment_as_before(tmp_path, actor, want):
    code, outputs, _ = route_review(tmp_path, [".github/workflows/build.yaml"], actor=actor)
    assert (code, outputs) == (0, PULL + want)


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
])
def test_reviews_route_reads_only_a_build_or_triage_run_of_a_pull_request_that_ended_so(tmp_path, run_path, run_event,
                                                                                        conclusion, want):
    code, outputs, calls = route_review(tmp_path, ["projects/p/project.yaml"], run_path=run_path, run_event=run_event,
                                        conclusion=conclusion)
    assert (code, outputs) == (0, want)
    # A run it does not read stops route before any read of GitHub.
    assert bool(calls) == bool(want), calls


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
# tests.yaml's step that keeps a fork's change to projects/ from running code, and the steps before it, which run only
# git, gh and jq, or check out the commit (each by its name, or by its action).
FORK_STEP = "A fork's change to projects/ runs no code here"
BEFORE_FORK_STEP = ["The pull request targets the default branch", "actions/checkout",
                    "The checkout is the merge into the base branch"]
# A class of the Docker tests: it skips unless OV_DOCKER_TESTS is 1.
DOCKER_CLASS = re.compile(r'@unittest\.skipUnless\(os\.environ\.get\("OV_DOCKER_TESTS"\) == "1"')


# A stand-in gh: it logs its arguments, one call to a line, and answers the compare API's status with $STATUS, or fails
# as on an error of the API when $STATUS is error.
COMPARE_GH = ('#!/bin/sh\necho "$*" >> "$GH_LOG"\n'
              '[ "$STATUS" = error ] && { echo "gh: Server Error (HTTP 502)" >&2; exit 1; }\necho "$STATUS"\n')
# A file of the checkout: it logs its path when it runs.
TRAP = '#!/bin/sh\necho "$0" >> "$TRAPPED"\n'


def job_of_tests():
    return workflow("tests.yaml")["jobs"]["tests"]


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
    # count): no step after this one runs.
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



def test_no_step_after_the_fork_step_runs_for_a_forks_enrollment():
    steps = job_of_tests()["steps"]
    names = [s.get("name") or s["uses"].split("@")[0] for s in steps]
    at = names.index(FORK_STEP)
    # Before it, only steps that run no file of the checkout.
    assert names[:at] == BEFORE_FORK_STEP
    fork = steps[at]
    assert fork["id"] == "fork"
    assert [bool(evaluate(fork["if"], {"env.FORK": value})) for value in ("true", "false")] == [True, False]
    assert steps[at + 1:], "no step after the fork step"
    for later in steps[at + 1:]:
        assert "if" in later, f"{later.get('name')} runs for a fork's enrollment"
        for found, runs in (("true", False), ("", True)):
            ctx = {"steps.fork.outputs.enrollment": found, "github.event_name": "pull_request"}
            assert bool(evaluate(later["if"], ctx)) == runs, (later.get("name"), found)


def run_the_tests_step(tmp_path, last_line, status=0):
    """Run tests.yaml's step "The tests in tests/", with its own env and the workflow's DOCKER_TESTS, a stand-in nproc
    that says 3, and a stand-in python3 that records its arguments and the PYTHONSAFEPATH it gets, prints `last_line`
    as pytest's last line, and exits `status`. Each pytest-xdist worker inherits that environment (the step's comment).
    Return the step's exit status, its output, and pytest's arguments after -m pytest."""
    bin = tmp_path / "bin"
    bin.mkdir()
    (bin / "nproc").write_text("#!/bin/sh\necho 3\n")
    (bin / "python3").write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV"\n'
                                 'printf "%s\\n" "${PYTHONSAFEPATH-unset}" > "$ARGV.safepath"\n'
                                 f'echo "SKIPPED [1] tests/test_x.py:1: a reason"\necho {last_line!r}\nexit {status}\n')
    for name in ("nproc", "python3"):
        (bin / name).chmod(0o755)
    flow = workflow("tests.yaml")
    tests = step(flow["jobs"]["tests"], "The tests in tests/")
    ambient = {name: value for name, value in os.environ.items() if name != "PYTHONSAFEPATH"}
    run = subprocess.run(["bash", "-e", "-c", tests["run"]], cwd=tmp_path, capture_output=True, text=True,
                         env={**ambient, **tests["env"], "DOCKER_TESTS": flow["env"]["DOCKER_TESTS"],
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


@pytest.mark.parametrize("last_line, status, fails", [
    ("5 passed in 1.00s", 0, False),
    ("5 passed, 2 deselected in 1.00s", 0, False),
    # A test that skipped fails the step, as does pytest's own failure.
    ("5 passed, 1 skipped in 1.00s", 0, True),
    ("1 skipped in 1.00s", 0, True),
    ("1 failed, 4 passed in 1.00s", 1, True),
])
def test_the_tests_step_fails_when_a_test_skips(tmp_path, last_line, status, fails):
    code, out, _ = run_the_tests_step(tmp_path, last_line, status)
    assert (code != 0) == fails, out
    assert ("::error::A test skipped here" in out) == (fails and status == 0), out


# The Docker tests' files, which no job of tests.yaml runs yet: the pull request of the branch INFRA-5359-docker-job
# adds the job docker, which runs them, and empties this list.
RUN_BY_NO_JOB_YET = ["tests/test_builder.py", "tests/test_append_docker.py", "tests/test_binary_checks_docker.py",
                     "tests/test_seed_runs_docker.py", "tests/test_target_settings_docker.py"]


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


def selection(tmp_path):
    """The arguments of pytest that choose the tests of the job tests, as run_the_tests_step finds them: its arguments
    but -n, --dist, --durations, -q and -rs, which choose how the tests run and what pytest prints, not which."""
    _, _, argv = run_the_tests_step(tmp_path, "1 passed in 1.00s")
    chosen, skip = [], False
    for argument in argv:
        if skip:
            skip = False
        elif argument in ("-n", "--dist"):
            skip = True
        elif not argument.startswith("--durations=") and argument not in ("-q", "-rs"):
            chosen.append(argument)
    return chosen


def test_every_test_runs_in_the_job_tests_or_is_listed_as_run_by_no_job_yet(tmp_path):
    """Each test that pytest collects under tests/ is one that the job tests runs, or one of RUN_BY_NO_JOB_YET's files:
    no selection leaves out a test unnoticed. A control leaves a class out of the job's selection, and finds it."""
    assert RUN_BY_NO_JOB_YET == workflow("tests.yaml")["env"]["DOCKER_TESTS"].split()
    chosen, everything, listed = selection(tmp_path), collected(), collected(*RUN_BY_NO_JOB_YET)
    assert everything - collected(*chosen) - listed == set()
    left_out = "tests/test_no_frame_pointer_image.py::NoFramePointerImage"
    found = everything - collected(*chosen, "--deselect", left_out) - listed
    assert found == {f"{left_out}::test_frame_pointers_skips_when_no_frame_pointer_image_is_named"}, found


def test_a_newer_run_of_a_pull_request_or_of_main_cancels_the_older():
    concurrency = workflow("tests.yaml")["concurrency"]
    assert concurrency["cancel-in-progress"] is True

    def group(event, ref, sha, number=None):
        return interpolated(concurrency["group"], {"github.event_name": event, "github.ref": ref, "github.sha": sha,
                                                   "github.event.pull_request.number": number})

    older, newer = "a" * 40, "b" * 40
    # Two pushes to main share one group, as do two pushes of one pull request.
    assert group("push", "refs/heads/main", older) == group("push", "refs/heads/main", newer)
    assert group("pull_request", "refs/pull/7/merge", older, 7) == group("pull_request", "refs/pull/7/merge", newer, 7)
    # Another pull request, and a run by hand on main, cancel neither.
    groups = {group("push", "refs/heads/main", older), group("pull_request", "refs/pull/7/merge", older, 7),
              group("pull_request", "refs/pull/8/merge", older, 8), group("workflow_dispatch", "refs/heads/main", older)}
    assert len(groups) == 4, groups


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
def test_the_job_checks_each_tool_it_fetches_by_its_sha256(name, tools):
    checks = step(job_of_tests(), name)
    for tool in tools:
        assert re.fullmatch(r"\d+\.\d+\.\d+", str(checks["env"][f"{tool}_VERSION"])), tool
        assert re.fullmatch(r"[0-9a-f]{64}", checks["env"][f"{tool}_SHA256"]), tool
        # Checked before the archive is unpacked.
        run = checks["run"]
        assert -1 < run.index(f'echo "${tool}_SHA256  ') < run.index("tar -x", run.index(f"${tool}_VERSION")), tool


def test_the_package_check_builds_with_uvs_own_backend_and_runs_the_installed_package():
    run = step(job_of_tests(), "The package builds, installs and runs")["run"]
    # uv builds offline only with the backend it bundles: the version that pyproject.toml's uv_build range names.
    version = step(job_of_tests(), "The package builds, installs and runs")["env"]["UV_VERSION"]
    pyproject = (ROOT / "pyproject.toml").read_text()
    low, high = re.search(r'requires = \["uv_build>=([\d.]+),<([\d.]+)"\]', pyproject).groups()
    as_tuple = lambda text: tuple(int(part) for part in text.split("."))
    assert as_tuple(low) <= as_tuple(version) < as_tuple(high), (version, low, high)
    assert "uv build --offline --wheel" in run
    assert "--require-hashes -r" in run
    assert 'env -u PYTHONPATH "$package/venv/bin/oss-verify" --help' in run


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


def test_triage_starts_only_for_a_pull_request_that_changes_projects_and_no_required_check_is_path_filtered():
    """triage.yaml's paths filter: GitHub starts Triage only for a pull request into main that changes a file under
    projects/, the only pull request that review.yml writes a triage comment for, on each of its four event types. A
    workflow that its paths filter skips leaves its checks pending, which blocks a merge only when the ruleset requires
    one: triage is no required check, and no workflow that reports one has a paths filter."""
    triage = workflow("triage.yaml")
    assert triage[True]["pull_request"] == {"branches": ["main"], "paths": ["projects/**"],
                                            "types": ["opened", "edited", "reopened", "synchronize"]}
    assert {job.get("name", name) for name, job in triage["jobs"].items()}.isdisjoint(RULESET)
    reporters = {**REQUIRED, "terms.yaml": "terms-accepted"}
    assert set(reporters.values()) == RULESET
    for name, check in reporters.items():
        assert check in {job.get("name", key) for key, job in workflow(name)["jobs"].items()}, name
        for event, spec in workflow(name)[True].items():
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
