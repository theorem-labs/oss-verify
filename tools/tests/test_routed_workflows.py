# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the routed workflows (validate.yaml, tests.yaml, triage.yaml) and their collector,
.github/scripts/collect:  python3 -m pytest tools/tests

Each workflow has a route job that decides which jobs the run needs, and a job named required that always runs last,
collects every result with the collector, and reports the workflow's one required check. These check the collector's
verdicts, the shape every routed workflow keeps (the collector waits for every job, and no job a route may skip reports
a required check), and the routes' own steps, run on made-up changes.
"""
import importlib.util
import itertools
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
# Each routed workflow, and the check its required job reports (the default branch's ruleset requires enrollment and
# tests; triage is required by none).
REQUIRED = {"validate.yaml": "enrollment", "tests.yaml": "tests", "triage.yaml": "triage"}
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
    (("success", "build:failure:true", "review:success:true"), "build: failure, where route asks for success"),
    (("success", "build:cancelled:true"), "build: cancelled, where route asks for success"),
    (("success", "build:skipped:true"), "build: skipped, where route asks for success"),
    (("success", "suite:skipped:false", "docs:failure:true"), "docs: failure, where route asks for success"),
    # A job route did not ask for that ran, even one that passed.
    (("success", "build:success:false"), "build: success, where route asks for skipped"),
    (("success", "build:failure:false"), "build: failure, where route asks for skipped"),
    # route itself did not pass: its jobs are then skipped, which must not read as nothing to do.
    (("failure", "build:skipped:false"), "route: failure"),
    (("cancelled", "validate:skipped:false"), "route: cancelled"),
    (("", "validate:skipped:false"), "route: no result"),
    (("success", "validate::true"), "validate: no result, where route asks for success"),
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
def test_the_required_job_waits_for_every_job_and_always_runs(name):
    jobs = workflow(name)["jobs"]
    assert set(jobs) >= {"route", "required"}
    required = jobs["required"]
    assert required["if"] == "always()"
    assert sorted(required["needs"]) == sorted(set(jobs) - {"required"})
    # The collector is given route's result and, for every other job, its result and whether route asked for it.
    run = step(required, "Every job route asked for passed, and no other ran")["run"]
    assert run.startswith('.github/scripts/collect "$ROUTE" ')
    collected = re.findall(r'"(\w[\w-]*):\$\w+:\$\w+"', run)
    assert sorted(collected) == sorted(set(jobs) - {"route", "required"})
    assert step(required, "Every job route asked for passed, and no other ran")["env"]["ROUTE"] == \
        "${{ needs.route.result }}"
    # It holds no credential: a read of .github/scripts at most.
    assert required["permissions"] == {"contents": "read"}
    assert not [s for s in required["steps"] if "secrets." in str(s)]


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


@pytest.mark.parametrize("name", ["validate.yaml", "tests.yaml"])
def test_tests_and_validate_never_run_on_an_edit(name):
    # An edit of the title or description changes nothing these judge. (A change of base does, and is sent as edited
    # too; a push runs them again after one.)
    on = workflow(name)[True]  # YAML 1.1 reads the key `on` as True
    event = "pull_request" if name == "tests.yaml" else "pull_request_target"
    assert on[event]["types"] == ["opened", "reopened", "synchronize"]


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


def test_triage_skips_only_an_edit_of_the_title_alone():
    flow = workflow("triage.yaml")
    title_only = "github.event.action == 'edited' && !github.event.changes.body && !github.event.changes.base"
    assert flow["concurrency"]["group"].startswith(f"${{{{ {title_only} && format('triage-edited-{{0}}', github.run_id)")
    route = step(flow["jobs"]["route"], "Whether the comment can change")
    assert route["env"]["TITLE_ONLY"] == f"${{{{ {title_only} }}}}"


def test_a_push_to_main_is_never_cancelled_by_a_later_push():
    # route compares a push with the commit before it, so a cancelled push's changes would never be tested.
    group = workflow("tests.yaml")["concurrency"]["group"]
    assert group.startswith("${{ github.event_name == 'push' && format('tests-push-{0}', github.sha) ||")


def test_a_forks_tests_collector_runs_the_default_branchs_script():
    # A fork's run takes the collector from the default branch's tip, never from the event's base.sha, which can be a
    # commit from before .github/scripts/collect existed (it stays the base the fork last synced with).
    flow = workflow("tests.yaml")
    fork = "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository"
    assert flow["env"]["FORK"] == f"${{{{ {fork} }}}}"
    checkout = flow["jobs"]["required"]["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["ref"] == "${{ env.FORK == 'true' && github.event.repository.default_branch || '' }}"
    # route, the one other job a fork's run starts, runs none of its code.
    route = flow["jobs"]["route"]["steps"]
    assert all(s.get("if", "").count("env.FORK != 'true'") for s in route if "uses" in s or s.get("id") == "paths")


def test_validate_route_asks_for_validate(tmp_path):
    jobs = workflow("validate.yaml")["jobs"]
    decide = step(jobs["route"], "Every event here asks for validate")
    output = tmp_path / "output"
    run = subprocess.run(["bash", "-e", "-c", decide["run"]], capture_output=True, text=True,
                         env={**os.environ, "GITHUB_OUTPUT": str(output),
                              "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")})
    assert run.returncode == 0, run.stderr
    assert output.read_text() == "validate=true\n"
    # validate takes the project once, itself, and runs only when route asks for it.
    assert jobs["validate"]["needs"] == "route"
    assert jobs["validate"]["if"] == "needs.route.outputs.validate == 'true'"
    assert sum(s.get("run") == ".github/scripts/take-project validate" for job in jobs.values() for s in job["steps"]) == 1


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
    # Documentation only: the one test that reads it.
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


def test_the_docs_job_runs_the_test_it_names(tmp_path):
    run = step(workflow("tests.yaml")["jobs"]["docs"], "The tests that read the documentation")["run"]
    node = re.search(r'"(tools/tests/[^"]+)"', run).group(1)
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
