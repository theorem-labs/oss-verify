# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the routed workflows (build.yaml, validate.yaml, tests.yaml, triage.yaml) and their collector,
.github/scripts/collect:  python3 -m pytest tools/tests

Each workflow has a route job that decides which jobs the run needs, and a job named required that always runs last,
collects every result with the collector, and reports the workflow's one required check. These check the collector's
verdicts, the shape every routed workflow keeps (the collector waits for every job, and no job a route may skip reports
a required check), and the routes' own steps, run on made-up changes.
"""
import importlib.util
import itertools
import json
import os
import pathlib
import re
import subprocess

import pytest
import yaml

from test_take_project import git, isolated_git_env

ROOT = pathlib.Path(__file__).resolve().parents[2]
COLLECT = ROOT / ".github" / "scripts" / "collect"
WORKFLOWS = ROOT / ".github" / "workflows"
# Each routed workflow, and the check its required job reports (the default branch's ruleset requires project-builds,
# enrollment and tests; triage is required by none).
REQUIRED = {"build.yaml": "project-builds", "validate.yaml": "enrollment", "tests.yaml": "tests", "triage.yaml": "triage"}
# The checks the default branch's ruleset requires.
RULESET = {"enrollment", "project-builds", "terms-accepted", "tests"}


def workflow(name):
    return yaml.safe_load((WORKFLOWS / name).read_text())


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


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_the_required_job_waits_for_every_job_and_collects_each(name):
    jobs = workflow(name)["jobs"]
    assert set(jobs) >= {"route", "required"}
    required = jobs["required"]
    assert sorted(required["needs"]) == sorted(set(jobs) - {"required"})
    # The collector is given route's result and, for every other job, its result and whether route asked for it.
    run = step(required, "Every job route asked for passed, and no other ran")["run"]
    collected = re.findall(r'"(\w[\w-]*):\$\w+:\$\w+"', run)
    # build.yaml's build job keeps the id project-builds, which the other jobs read its outputs by.
    named = {"project-builds": "build"}
    assert sorted(collected) == sorted(named.get(job, job) for job in set(jobs) - {"route", "required"})
    # It holds no secret.
    assert not [s for s in required["steps"] if "secrets." in str(s)]


def bare(expression):
    """An expression without its ${{ }} and without a leading !cancelled() && (the collector runs on always())."""
    text = str(expression).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return text.removeprefix("!cancelled() && ").strip()


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_the_collector_reads_each_jobs_own_result_and_asks_on_that_jobs_own_condition(name):
    # The collector is given each job's own result, and whether the run asked for it as the same expression as the
    # job's if:, so that it never wants a job to pass that did not run, nor wants one skipped that ran.
    jobs = workflow(name)["jobs"]
    collector = step(jobs["required"], "Every job route asked for passed, and no other ran")
    by_name = {job.get("name", job_id): job_id for job_id, job in jobs.items()}
    for collected, result, asked in re.findall(r'"(\w[\w-]*):\$(\w+):\$(\w+)"', collector["run"]):
        job_id = by_name.get(collected, collected)
        assert collector["env"][result] == f"${{{{ needs.{job_id}.result }}}}", (name, collected)
        assert bare(collector["env"][asked]) == bare(jobs[job_id]["if"]), (name, collected)


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_only_the_required_job_reports_the_required_check(name):
    jobs = workflow(name)["jobs"]
    check = REQUIRED[name]
    for job_id, job in jobs.items():
        if job_id == "required":
            continue
        # A job's check is its name, or its id when it has none. Any job but required may be skipped by route.
        assert job.get("name", job_id) != check, f"{name}: the job {job_id} reports {check}"
    # Every job but route and required runs only when route asks for it (directly, or through the job it needs).
    for job_id, job in jobs.items():
        if job_id not in ("route", "required"):
            assert "if" in job, f"{name}: {job_id} runs whatever route decides"


def test_every_required_check_has_a_static_name():
    # GitHub reads a required check from the newest run of its workflow on the head. A job whose name is an expression
    # can report another name on some event, and the newest run then has no required check: the pull request is
    # blocked until a push. So each required check is reported by exactly one job, under a plain name.
    reporters = {}
    for path in sorted([*WORKFLOWS.glob("*.yaml"), *WORKFLOWS.glob("*.yml")]):
        for job_id, job in yaml.safe_load(path.read_text())["jobs"].items():
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


def route_build(tmp_path, files, changed=None, base="main", actor="someone"):
    """Run build.yaml's route step, started by `actor`, with a fake gh whose pull request into `base` lists `files` (a
    path, or a (new, old) pair for a rename; changed_files: `changed`, by default their number), and applies the step's
    --jq filter as gh does. Return its outputs, one line each."""
    bin = tmp_path / "bin"
    bin.mkdir()
    (tmp_path / "pull.json").write_text(json.dumps({"head": {"sha": "a" * 40},
                                                    "base": {"ref": base, "repo": {"default_branch": "main"}},
                                                    "changed_files": len(files) if changed is None else changed}))
    (tmp_path / "files.json").write_text(json.dumps(
        [{"filename": f} if isinstance(f, str) else {"filename": f[0], "previous_filename": f[1]} for f in files]))
    (bin / "gh").write_text('#!/bin/bash\nfilter=""; for a; do [ "$prev" = --jq ] && filter=$a; prev=$a; done\n'
                            f'case " $*" in {USERS_GH}  *"/files"*) jq -r "$filter" {tmp_path}/files.json ;;\n'
                            f'  *) cat {tmp_path}/pull.json ;; esac\n')
    (bin / "gh").chmod(0o755)
    written = tmp_path / "output"
    flow = workflow("build.yaml")
    decide = step(flow["jobs"]["route"], "An enrollment, a change or an issue")
    run = subprocess.run(["bash", "-e", "-c", decide["run"]], capture_output=True, text=True, cwd=ROOT,
                         env={**os.environ, **literal_env(flow, decide),
                              "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                              "PR": "8", "HEAD_SHA": "", "ACTOR": actor, "GITHUB_OUTPUT": str(written),
                              "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")})
    assert run.returncode == 0, run.stderr
    return written.read_text().splitlines()


@pytest.mark.parametrize("files, changed, base, want", [
    # Tooling and documentation only, as from a fork: a change review, and no build.
    (["tools/check", "docs/build-contract.md", "tools/tests/test_check.py"], None, "main", "kind=change"),
    (["README.md"], None, "main", "kind=change"),
    # Into another branch: the build, where take-project refuses it, as before.
    (["README.md"], None, "ci/other", "kind=enrollment"),
    # A file under projects/, alone or beside others (a fork's mixed change then fails in take-project, as before),
    # or a rename out of projects/ (both names are listed): an enrollment, built.
    (["projects/p/project.yaml"], None, "main", "kind=enrollment"),
    (["projects/p/project.yaml", "tools/check"], None, "main", "kind=enrollment"),
    (["tools/x.yaml", "projects/p/x.yaml"], None, "main", "kind=enrollment"),
    ([("tools/x.yaml", "projects/p/x.yaml")], None, "main", "kind=enrollment"),
    # No file, or more files than the API lists: the list decides nothing, and take-project judges it.
    ([], None, "main", "kind=enrollment"),
    (["tools/check"], 3001, "main", "kind=enrollment"),
])
def test_builds_route_reviews_a_pull_request_with_no_file_under_projects_as_a_change(tmp_path, files, changed, base,
                                                                                     want):
    assert route_build(tmp_path, files, changed, base=base) == [f"sha={'a' * 40}", want]


@pytest.mark.parametrize("actor, want", [
    ("someone", "kind=change"), ("sjawhar-agent[bot]", "kind=change"), ("oss-verify[bot]", "kind=change"),
    # An App the action refuses (src/github/validation/actor.ts) would fail the review, and so the required check:
    # by its account type, so Copilot, whose login has no [bot] and which the Users API does not find, too.
    ("dependabot[bot]", "kind=enrollment"), ("oss-verify[bot]x[bot]", "kind=enrollment"),
    ("Copilot", "kind=enrollment"),
])
def test_a_change_that_an_app_the_review_refuses_started_is_built_as_before(tmp_path, actor, want):
    assert route_build(tmp_path, [".github/workflows/build.yaml"], actor=actor)[-1] == want


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
    """Run build.yaml's route step on an `event`: a run started by hand with the inputs `pr` and `issue` ("" when not
    given), or an issue's own event for issue `issue`, sent by `sender`, whose author is `author` with GitHub's
    `association`. Its fake gh's number is an issue, or a pull request when `is_pull`. Return its exit status and
    outputs."""
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
    flow = workflow("build.yaml")
    decide = step(flow["jobs"]["route"], "An enrollment, a change or an issue")
    run = subprocess.run(["bash", "-e", "-c", decide["run"]], capture_output=True, text=True, cwd=ROOT,
                         env={**os.environ, **literal_env(flow, decide),
                              "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                              "PR": pr, "ISSUE": issue, "HEAD_SHA": "", "ACTOR": sender, "EVENT": event,
                              "SENDER": sender, "AUTHOR": author, "ASSOCIATION": association,
                              "GITHUB_OUTPUT": str(written), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")})
    return run.returncode, written.read_text().splitlines() if written.exists() else []


def test_a_run_for_an_issue_asks_for_the_review_alone(tmp_path):
    assert route_issue(tmp_path, "", "5") == (0, ["kind=issue"])


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
                       association=association) == (0, ["kind=issue"])
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


# --- tests.yaml's route, run on made-up commits ---


def commit(directory, environment, files):
    for path, text in files.items():
        file = directory / path
        if text is None:
            file.unlink()
            continue
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
    git("add", "-A", cwd=directory, env=environment)
    git("commit", "-q", "--allow-empty", "-m", "change", cwd=directory, env=environment)
    return git("rev-parse", "HEAD", cwd=directory, env=environment)


TREE = {"README.md": "x\n", "AGENTS.md": "x\n", "docs/a.md": "x\n", "tools/t.py": "x\n", "projects/p/project.yaml": "x\n"}


def route_tests(tmp_path, change, event="pull_request", before=None):
    """Run tests.yaml's "Which jobs the changes need" on a commit that makes `change` to TREE. Return its outputs."""
    # git with no configuration from this machine, as in test_take_project.py.
    isolated = isolated_git_env(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo, env=isolated)
    first = commit(repo, isolated, TREE)
    commit(repo, isolated, change)
    git("remote", "add", "origin", f"file://{repo}", cwd=repo, env=isolated)
    paths = step(workflow("tests.yaml")["jobs"]["route"], "Which jobs the changes need")
    output, summary = tmp_path / "output", tmp_path / "summary"
    environment = {**isolated, "EVENT": event, "BEFORE": first if before is None else before,
                   "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary), "RUNNER_TEMP": str(tmp_path)}
    run = subprocess.run(["bash", "-e", "-c", paths["run"]], cwd=repo, env=environment, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    return dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}


@pytest.mark.parametrize("change, outputs", [
    # Documentation only: the tests that read it.
    ({"docs/a.md": "y\n"}, {"docs": "true"}),
    ({"docs/new/b.txt": "y\n", "AGENTS.md": "y\n", "CONTRIBUTING.md": "y\n"}, {"docs": "true"}),
    ({"docs/a.md": None}, {"docs": "true"}),
    # README.md is read by a test; a Markdown file below the top is not documentation; and anything else runs it all.
    ({"README.md": "y\n"}, {"suite": "true"}),
    ({"tools/notes.md": "y\n"}, {"suite": "true"}),
    ({"docs/a.md": "y\n", "tools/t.py": "y\n"}, {"suite": "true"}),
    ({"projects/p/project.yaml": "y\n"}, {"suite": "true"}),
    ({".github/workflows/tests.yaml": "y\n"}, {"suite": "true"}),
    # A rename out of the documentation is a change to both names.
    ({"docs/a.md": None, "tools/a.md": "x\n"}, {"suite": "true"}),
    # No change: nothing to run.
    ({}, {}),
])
def test_tests_route_asks_for_the_jobs_a_pull_requests_changes_need(tmp_path, change, outputs):
    assert route_tests(tmp_path, change) == outputs


def test_tests_route_compares_a_push_with_the_commit_before_it(tmp_path):
    assert route_tests(tmp_path, {"docs/a.md": "y\n"}, event="push") == {"docs": "true"}


@pytest.mark.parametrize("event, before", [
    ("push", "0" * 40),  # a new branch: no earlier commit
    ("push", "1" * 40),  # an earlier commit that cannot be fetched
    ("push", ""),
    ("workflow_dispatch", ""),
])
def test_tests_route_runs_everything_with_nothing_to_compare_with(tmp_path, event, before):
    assert route_tests(tmp_path, {"docs/a.md": "y\n"}, event=event, before=before) == {"suite": "true"}


def test_the_docs_job_runs_the_tests_it_names(tmp_path):
    run = step(workflow("tests.yaml")["jobs"]["docs"], "The tests that read the documentation")["run"]
    nodes = re.findall(r'"(tools/tests/[^"]+)"', run)
    assert nodes
    for node in nodes:
        file, cls, test = node.split("::")
        source = (ROOT / file).read_text()
        assert re.search(rf"^class {cls}\b", source, re.M) and re.search(rf"^    def {test}\(", source, re.M), node


# --- triage.yaml's route, run with a made-up gh ---


def route_triage(tmp_path, files, event="pull_request_target", title_only="false", fail=False):
    bin = tmp_path / "bin"
    bin.mkdir()
    (tmp_path / "files").write_text("".join(f"{path}\n" for path in files))
    (bin / "gh").write_text("#!/bin/bash\n" + ("exit 1\n" if fail else f"cat {tmp_path / 'files'}\n"))
    (bin / "gh").chmod(0o755)
    route = step(workflow("triage.yaml")["jobs"]["route"], "Whether the comment can change")
    output = tmp_path / "output"
    environment = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r", "PR": "8",
                   "EVENT": event, "TITLE_ONLY": title_only, "GITHUB_OUTPUT": str(output),
                   "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"), "RUNNER_TEMP": str(tmp_path)}
    run = subprocess.run(["bash", "-e", "-c", route["run"]], env=environment, capture_output=True, text=True)
    return run.returncode, output.read_text() if output.exists() else ""


@pytest.mark.parametrize("files, event, title_only, gather", [
    (["projects/p/project.yaml"], "pull_request_target", "false", True),
    (["README.md", "projects/p/build.sh"], "pull_request_target", "false", True),
    (["README.md", "tools/t.py"], "pull_request_target", "false", False),
    (["projects/p/project.yaml"], "pull_request_target", "true", False),
    ([], "workflow_dispatch", "false", True),
])
def test_triage_route_asks_for_gather_only_when_the_comment_can_change(tmp_path, files, event, title_only, gather):
    code, output = route_triage(tmp_path, files, event, title_only)
    assert code == 0
    assert output == ("gather=true\n" if gather else "")


def test_triage_route_fails_when_it_cannot_read_the_files(tmp_path):
    code, output = route_triage(tmp_path, [], fail=True)
    assert code != 0 and output == ""


def test_triage_route_asks_for_gather_whenever_triage_py_would_comment():
    # triage.py writes a comment only when split_paths names a project; route asks for gather when a path matches its
    # grep pattern. Over every path of up to four segments from a set that includes near misses, the first must imply
    # the second, so that a change to either rule that lets them drift apart fails here.
    spec = importlib.util.spec_from_file_location("triage", ROOT / ".github" / "scripts" / "triage.py")
    triage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(triage)
    run = step(workflow("triage.yaml")["jobs"]["route"], "Whether the comment can change")["run"]
    patterns = re.findall(r"grep -q '([^']+)' \"\$RUNNER_TEMP/paths\"", run)
    assert len(patterns) == 1, patterns
    asks = re.compile(patterns[0])
    segments = ["projects", "Projects", "project", "docs", "p", "x.md", ".github", ""]
    paths = ["/".join(parts) for size in range(1, 5) for parts in itertools.product(segments, repeat=size)]
    named = [path for path in paths if triage.split_paths([path])[0]]
    assert "projects/p/x.md" in named
    assert [path for path in named if not asks.search(path)] == []
