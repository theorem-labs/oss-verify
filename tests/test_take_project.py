# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/take-project, which takes projects/<name>/ from a pull request:  uv run pytest

Each runs the script in a clone of a local repository whose main has one project, with gh answering from a made-up pull
request and the pull request's commit fetched with git. They cover what the pull requests of this repository cannot
show: a pull request from a fork, one that is not an enrollment, one that changes more files than one page lists, and
one whose head moves while the script reads it.
"""
import itertools
import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "take-project"
REPO = "theorem-labs/oss-verify"
PROJECT = "repo: https://github.com/example/project#v1.0\nprimary_contact: security@example.org\nlanguage: c\n"
# git with no configuration from this machine.
GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.org",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.org"}
# gh api, answered from the files the test wrote: the pull request, the compare of the base branch and the head (for
# its merge base), and one file per page of its changed files. --paginate reads every page. Only what take-project
# calls is answered. A pull.after.json is a push while the files are listed: every later read of the pull request
# gets it. A fail.after makes every later read fail, as an API error.
STUB_GH = r"""#!/usr/bin/env bash
set -eu
[ "$1" = api ] || exit 2
if [ "$2" = --paginate ]; then
  for page in "$STUB_GH"/page.*; do cat "$page"; done
  if [ -e "$STUB_GH/pull.after.json" ]; then mv "$STUB_GH/pull.after.json" "$STUB_GH/pull.json"; fi
  if [ -e "$STUB_GH/fail.after" ]; then mv "$STUB_GH/fail.after" "$STUB_GH/fail"; fi
elif [ -e "$STUB_GH/fail" ]; then
  echo "gh: HTTP 502: Bad Gateway" >&2
  exit 1
elif [[ $2 == */compare/* ]]; then
  cat "$STUB_GH/compare.json"
else
  cat "$STUB_GH/pull.json"
fi
"""
# git, first on PATH: it logs the arguments of each call to $STUB_GIT_LOG, each ended by NUL and the call by \1, and
# runs the real git, $STUB_GIT_REAL.
STUB_GIT = r"""#!/usr/bin/env bash
{ printf '%s\0' "$@"; printf '\1'; } >> "$STUB_GIT_LOG"
exec "$STUB_GIT_REAL" "$@"
"""
# The checkouts in which take-project runs (PullRequest).
CHECKOUTS = ("main", "first parent")

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="take-project needs jq, as on GitHub's runners")


def git(*args, cwd=None, env=None):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def isolated_git_env(tmp_path):
    """An environment in which git reads no configuration of this machine: an empty HOME under tmp_path."""
    home = tmp_path / "home"
    home.mkdir()
    return {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_GLOBAL": str(home / "gitconfig"), **GIT_ENV}


class PullRequest:
    """A repository whose main has projects/other/, a pull request's commit on it, and the checkout of main.

    `removed` are paths the pull request deletes. `parent` is the files of a stacked branch's parent, committed on the
    branch first. `landed` is the files main gets after the branch has left it (default: the parent's, squash-merged),
    for a parent that changed in review, or another pull request that landed first, and `renamed` a (source,
    destination) that main moves with git mv in the same commit. Either way the API's list is what
    GitHub's is, the three-dot diff from the merge base, with a renamed file under both names, and the API's merge
    base is git's.

    `checkout` is the checkout in which take-project runs:
      - main: main alone at depth 1, as actions/checkout makes a checkout of one commit. The pull request's commit and
        the merge base are there only once take-project fetches them.
      - first parent: the checkout of build.yaml's project-builds job and of validate.yaml. refs/pull/7/merge is
        GitHub's merge of the pull request's commit into main: main is its first parent, and the pull request's commit
        its second. actions/checkout fetches it at depth 2 and checks it out, and then the job's step with id: parent
        checks out its first parent, main. The pull request's commit is there already, as the merge's second parent.

    The repositories are built once per pytest process (each xdist worker is one) for each set of arguments, and each
    test takes its own copy of them in its tmp_path: building them is about 15 git processes, the larger part of a
    test's time, and many tests take the same pull request. Main's first commit, which depends only on `on_main`, is
    built once too, and each pull request's origin starts as a copy of it."""

    # The pull requests built so far, by their arguments: each a PullRequest in its own directory.
    built = {}
    # Main's first commit, by `on_main`: the directory of a repository that holds it, and its commit.
    mains = {}
    # The directory they are built in; the fixture pull_requests_built_once sets it.
    root = None
    # The names of their directories. Never the count of `built`: a build that fails stores nothing, and the next
    # build would take its name and fail on the directory it left.
    names = itertools.count()

    def __init__(self, tmp_path, files, removed=(), parent=None, landed=None, renamed=None, on_main=None,
                 checkout="main"):
        key = json.dumps([files, list(removed), parent, landed, renamed, on_main, checkout])
        if key not in self.built:
            built = object.__new__(PullRequest)
            built.build(self.root / str(next(self.names)), files, removed, parent, landed, renamed, on_main, checkout)
            self.built[key] = built
        built = self.built[key]
        self.tmp = tmp_path
        self.env = isolated_git_env(tmp_path)
        self.origin, self.checkout = tmp_path / "origin", tmp_path / "checkout"
        shutil.copytree(built.origin, self.origin, symlinks=True)
        shutil.copytree(built.checkout, self.checkout, symlinks=True)
        # The checkout fetches from this test's origin, not from the one it was copied from. git writes the setting,
        # as it escapes a path that holds a quote or a backslash.
        git("config", "remote.origin.url", f"file://{self.origin}", cwd=self.checkout, env=self.env)
        self.other, self.sha, self.merge_base, self.paths = built.other, built.sha, built.merge_base, list(built.paths)

    def first_commit(self, on_main):
        """A repository whose main is main's first commit: projects/other/ and the files `on_main`."""
        key = json.dumps(on_main)
        if key not in self.mains:
            directory = self.root / f"main-{next(self.names)}"
            directory.mkdir()
            env = isolated_git_env(directory)
            origin = directory / "origin"
            git("init", "-q", "-b", "main", str(origin), env=env)
            (origin / "projects" / "other").mkdir(parents=True)
            (origin / "projects" / "other" / "project.yaml").write_text(PROJECT)
            # More files in main's first commit, before the branch leaves it.
            for path, text in (on_main or {}).items():
                (origin / path).parent.mkdir(parents=True, exist_ok=True)
                (origin / path).write_text(text)
            git("add", "-A", cwd=origin, env=env)
            git("commit", "-q", "-m", "main", cwd=origin, env=env)
            self.mains[key] = origin, git("rev-parse", "main", cwd=origin, env=env)
        return self.mains[key]

    def build(self, directory, files, removed, parent, landed, renamed, on_main, checkout):
        directory.mkdir()
        self.tmp = directory
        self.env = isolated_git_env(directory)
        self.origin = origin = directory / "origin"
        # self.other: another commit the pull request's head can move to.
        first, self.other = self.first_commit(on_main)
        shutil.copytree(first, origin, symlinks=True)
        git("checkout", "-q", "-b", "pull", cwd=origin, env=self.env)
        if parent:
            self.commit(parent, "parent")
        for path in removed:
            git("rm", "-r", "-q", path, cwd=origin, env=self.env)
        self.commit(files, "pull request")
        self.sha = git("rev-parse", "HEAD", cwd=origin, env=self.env)
        git("checkout", "-q", "main", cwd=origin, env=self.env)
        if renamed:
            # git mv on main after the branch has left it.
            git("mv", *renamed, cwd=origin, env=self.env)
        if parent or landed or renamed:
            self.commit((parent if landed is None else landed) or {}, "landed on main after the branch left it")
        self.merge_base = git("merge-base", "main", "pull", cwd=origin, env=self.env)
        self.checkout = directory / "checkout"
        if checkout == "main":
            git("clone", "-q", "--single-branch", "--branch", "main", "--depth", "1", f"file://{origin}",
                str(self.checkout), env=self.env)
            assert subprocess.run(["git", "cat-file", "-e", self.sha], cwd=self.checkout, env=self.env,
                                  capture_output=True).returncode != 0, \
                "the checkout already has the pull request's commit"
        else:
            assert checkout == "first parent", checkout
            main = git("rev-parse", "main", cwd=origin, env=self.env)
            tree = git("merge-tree", "--write-tree", "main", self.sha, cwd=origin, env=self.env)
            merge = git("commit-tree", tree, "-p", main, "-p", self.sha, "-m", f"Merge {self.sha} into {main}",
                        cwd=origin, env=self.env)
            git("update-ref", "refs/pull/7/merge", merge, cwd=origin, env=self.env)
            git("init", "-q", str(self.checkout), env=self.env)
            git("remote", "add", "origin", f"file://{origin}", cwd=self.checkout, env=self.env)
            git("fetch", "-q", "--no-tags", "--depth=2", "origin", "+refs/pull/7/merge:refs/remotes/pull/7/merge",
                cwd=self.checkout, env=self.env)
            git("checkout", "-q", "--detach", "refs/remotes/pull/7/merge", cwd=self.checkout, env=self.env)
            git("checkout", "-q", "--detach", "HEAD^1", cwd=self.checkout, env=self.env)
            assert git("rev-parse", "HEAD", cwd=self.checkout, env=self.env) == main, "the checkout is not main"
        if removed or parent or landed or renamed:
            self.paths = git("diff", "--no-renames", "--name-only", "main...pull", cwd=origin, env=self.env).split("\n")
        else:
            self.paths = list(files)

    def commit(self, files, message):
        for path, text in files.items():
            (self.origin / path).parent.mkdir(parents=True, exist_ok=True)
            (self.origin / path).write_text(text)
        git("add", "-A", cwd=self.origin, env=self.env)
        git("commit", "-q", "--allow-empty", "-m", message, cwd=self.origin, env=self.env)

    def run(self, head_repository, listed=None, changed=None, event=None, api=None, api_after=None, base="main",
            base_after=None, fails_after=False):
        """Run take-project validate. The API lists `listed` (default: the pull request's paths), 100 to a page, and
        says it changes `changed` files (default: as many as it lists). `event` is the event's head ("" on a run
        started by hand; default: the commit), `api` the head the API gives (default: the commit), and `base` the
        branch the pull request targets; main is the default branch. `api_after` and `base_after` are the head and
        base it gives once the files are listed (default: no change), and `fails_after` makes its later answers fail.
        Return (exit code, output, outputs, summary). git_calls() then gives the run's calls of git."""
        answers = self.tmp / "gh"
        stubs = self.tmp / "stubs"
        for directory in (answers, stubs):
            shutil.rmtree(directory, ignore_errors=True)
            directory.mkdir()
        for name, text in (("gh", STUB_GH), ("git", STUB_GIT)):
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)
        listed = self.paths if listed is None else listed
        head = {"full_name": head_repository} if head_repository else None
        changed = len(listed) if changed is None else changed

        def pull(sha, ref):
            return json.dumps({"head": {"sha": sha, "repo": head}, "changed_files": changed,
                               "base": {"ref": ref, "repo": {"full_name": REPO, "default_branch": "main"}}})

        (answers / "pull.json").write_text(pull(api or self.sha, base))
        (answers / "compare.json").write_text(json.dumps({"merge_base_commit": {"sha": self.merge_base}}))
        if api_after or base_after:
            (answers / "pull.after.json").write_text(pull(api_after or api or self.sha, base_after or base))
        if fails_after:
            (answers / "fail.after").write_text("")
        for start in range(0, max(len(listed), 1), 100):
            (answers / f"page.{start // 100:04d}").write_text(
                "".join(f"{path}\n" for path in listed[start:start + 100]))
        temp = self.tmp / "runner-temp"
        shutil.rmtree(temp, ignore_errors=True)
        temp.mkdir()
        outputs, summary = self.tmp / "output", self.tmp / "summary"
        outputs.write_text("")
        summary.write_text("")
        self.git_log = self.tmp / "git-calls"
        self.git_log.write_text("")
        env = {**self.env, "PATH": f"{stubs}{os.pathsep}{self.env['PATH']}", "STUB_GH": str(answers),
               "STUB_GIT_LOG": str(self.git_log), "STUB_GIT_REAL": shutil.which("git", path=self.env["PATH"]),
               "GH_TOKEN": "stub-token", "REPO": REPO, "PR": "7", "HEAD_SHA": self.sha if event is None else event,
               "RUNNER_TEMP": str(temp), "GITHUB_OUTPUT": str(outputs), "GITHUB_STEP_SUMMARY": str(summary)}
        done = subprocess.run([str(SCRIPT), "validate"], cwd=self.checkout, env=env, capture_output=True, text=True,
                              check=False)
        values = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
        return done.returncode, done.stdout + done.stderr, values, summary.read_text()

    def git_calls(self):
        """The arguments of each call of git in the last run."""
        return [call.split("\0")[:-1] for call in self.git_log.read_text().split("\1")[:-1]]


# Session, not module: a worker of pytest-xdist can run this module's tests between other modules' tests, and each
# return to the module would otherwise build every pull request again.
@pytest.fixture(scope="session", autouse=True)
def pull_requests_built_once(tmp_path_factory):
    """The directory in which PullRequest builds each pull request once."""
    PullRequest.root = tmp_path_factory.mktemp("pull-requests")
    yield
    PullRequest.built.clear()
    PullRequest.mains.clear()


ENROLLMENT = {"projects/demo/project.yaml": PROJECT, "projects/demo/Dockerfile": "FROM x\n",
              "projects/demo/build.sh": "#!/bin/bash\n"}
MAINTENANCE = {"projects/demo/project.yaml": PROJECT, "projects/other/project.yaml": PROJECT + "# edited\n",
               "tools/notes.txt": "a maintainer's change\n"}
# Two projects and no other file.
TWO_PROJECTS = {**ENROLLMENT, "projects/second/project.yaml": PROJECT}
# Changes no project's own files: a tool, a workflow, a file in a subdirectory of a project.
NOT_A_PROJECT = {
    "tools": {"oss-verify validate": "# rewritten\n"},
    "workflow": {".github/workflows/build.yaml": "name: rewritten\n"},
    "subdirectory": {"projects/demo/sub/build.sh": "#!/bin/bash\n"},
}
# Of those, the ones with no file under projects/: a fork's such pull request is not an enrollment.
OUTSIDE_PROJECTS = ("tools", "workflow")
# An enrollment with one more file outside its project: a line of STATUS.md, the project's row in
# docs/seeded-projects.tsv.
WITH_ANOTHER_FILE = {
    "status": {**ENROLLMENT, "STATUS.md": "# Status\n"},
    "seeded": {**ENROLLMENT, "docs/seeded-projects.tsv": "demo\n"},
}
# docs/seeded-projects.tsv on main, in the form that src/oss_verify/seeded_projects.py writes: curl is seeded, and
# sqlpage is not. Main has a port of each.
SEEDED_TABLE = ("# Written by src/oss_verify/seeded_projects.py; do not edit.\n"
                "project\tseedable\tbuild\tbuild notes\treason or notes\n"
                "curl\tyes\treproduces\tall binaries match the release's\tfuzz_a: the release modified this harness\n"
                "sqlpage\tno\t-\t-\tthe release did not build it\n")
SEEDED_MAIN = {"docs/seeded-projects.tsv": SEEDED_TABLE, "projects/curl/project.yaml": PROJECT,
               "projects/curl/build.sh": "#!/bin/bash\n", "projects/sqlpage/project.yaml": PROJECT,
               "projects/sqlpage/build.sh": "#!/bin/bash\n"}
NO_TABLE = {path: text for path, text in SEEDED_MAIN.items() if path != "docs/seeded-projects.tsv"}
# A change to the build.sh of a port.
CHANGED_BUILD = "#!/bin/bash\nmake\n"
SEEDED_REFUSED = ("A maintainer of this repository carries such a change on a branch of this repository, where the "
                  "tests check runs the test of the table.")
# Branches whose three-dot list names a project that merging does not change, built from real commits. Each is
# (files, removed, parent, landed) for PullRequest, and the one project merging changes.
GIT = {"projects/git/project.yaml": PROJECT, "projects/git/Dockerfile": "FROM x\n",
       "projects/git/build.sh": "#!/bin/bash\nexit 1\n"}
MAKE = {"projects/make/project.yaml": PROJECT, "projects/make/build.sh": "#!/bin/bash\n"}
# projects/other/project.yaml with its first line changed, and with its last line changed too.
OTHER_FIRST = PROJECT.replace("#v1.0", "#v1.1")
OTHER_BOTH = OTHER_FIRST.replace("language: c", "language: c++")
LISTED_BUT_NOT_MERGED = {
    # Its parent added projects/make/ and was squash-merged into main after this branch left it.
    "stacked on a squash-merged parent": (GIT, (), MAKE, None, "git"),
    # The same, but the parent gained a file in review before its squash, so projects/make/ on main is not the
    # branch's: the branch's make files still match main's.
    "stacked on a parent that changed in review": (GIT, (), MAKE, {**MAKE, "projects/make/sources": "make 4.4.1\n"},
                                                   "git"),
    # Its parent edited an existing project's file, then got a review fix to the same file before its squash: the
    # listed file differs from main's, and merging leaves main's.
    "stacked on a parent whose edit to another project was fixed in review": (
        ENROLLMENT, (), {"projects/other/project.yaml": "# top\n" + PROJECT},
        {"projects/other/project.yaml": "# top\n" + PROJECT + "# bottom\n"}, "demo"),
    # No stack: the branch edits another project's first line, and main has since landed that edit and one more.
    "another project's edit landed on main with a further edit": (
        {**ENROLLMENT, "projects/other/project.yaml": OTHER_FIRST}, (), None,
        {"projects/other/project.yaml": OTHER_BOTH}, "demo"),
    # git mv projects/other projects/demo, and a build.sh changed.
    "a renamed project": ({"projects/demo/project.yaml": PROJECT, "projects/demo/build.sh": "#!/bin/bash\nexit 0\n"},
                          ("projects/other",), None, None, "demo"),
    "a removed project and a new one": (ENROLLMENT, ("projects/other",), None, None, "demo"),
}


@pytest.mark.parametrize("checkout", CHECKOUTS)
@pytest.mark.parametrize("head", [REPO, "someone/oss-verify"])
def test_an_enrollment_is_taken(tmp_path, head, checkout):
    pull = PullRequest(tmp_path, ENROLLMENT, checkout=checkout)
    code, log, values, _ = pull.run(head)
    assert code == 0, log
    assert values["name"] == "demo"
    assert values["same_repository"] == ("true" if head == REPO else "false")
    for path, text in ENROLLMENT.items():
        assert (pull.checkout / path).read_text() == text
    # take-project fetched the pull request's commit once: the git stand-in logs each call.
    assert len([call for call in pull.git_calls() if "fetch" in call]) == 1, pull.git_calls()
    # The token authorized the fetch alone: no git configuration keeps it.
    found = subprocess.run(["git", "config", "--show-origin", "--get-regexp", "extraheader"], cwd=pull.checkout,
                           env=pull.env, capture_output=True, text=True, check=False)
    assert (found.returncode, found.stdout) == (1, "")
    home = pull.tmp / "home"
    for config in [pull.checkout / ".git" / "config", *(path for path in home.rglob("*") if path.is_file())]:
        assert "stub-token" not in config.read_text(errors="replace"), config


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])  # "": a deleted fork's pull request has no head repository
def test_a_fork_that_changes_more_than_one_project_fails(tmp_path, head):
    code, log, values, _ = PullRequest(tmp_path, MAINTENANCE).run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert values["same_repository"] == "false"
    assert "outside projects/<name>/: tools/notes.txt" in log


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
def test_a_fork_that_changes_two_projects_and_nothing_else_fails(tmp_path, head):
    # No file outside a project: the one-project rule alone must stop it, or projects/second/ is never checked.
    pull = PullRequest(tmp_path, TWO_PROJECTS)
    code, log, values, _ = pull.run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "This pull request changes more than one project. One project per pull request." in log
    assert not (pull.checkout / "projects" / "demo").exists()


@pytest.mark.parametrize("checkout", CHECKOUTS)
@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("change", OUTSIDE_PROJECTS)
def test_a_fork_that_changes_no_file_under_projects_is_not_an_enrollment(tmp_path, head, change, checkout):
    # tests.yaml runs this repository's tests on it, and review.yml gives it a change review.
    pull = PullRequest(tmp_path, NOT_A_PROJECT[change], checkout=checkout)
    code, log, values, summary = pull.run(head)
    assert code == 0, log
    assert values.get("name", "") == ""
    assert values["same_repository"] == "false"
    expected = ("Not an enrollment (it lists 1 path, none under projects/): nothing to validate. The tests check "
                "(tests.yaml) runs this repository's tests on it.")
    assert expected in log
    assert expected in summary
    # Its paths are not refused as outside a project.
    assert "outside projects/<name>/" not in log
    # Nothing of the fork is fetched: take-project runs no git fetch. In the checkout of main alone, the fork's commit
    # is not there either. In the first parent's checkout, actions/checkout put it there as the merge's second parent.
    assert [call for call in pull.git_calls() if "fetch" in call] == [], pull.git_calls()
    if checkout == "main":
        assert subprocess.run(["git", "cat-file", "-e", pull.sha], cwd=pull.checkout, env=pull.env,
                              capture_output=True).returncode != 0


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("listed", [["projects/demo/sub/build.sh"], ["tools/x.yaml", "projects/demo/x.yaml"],
                                    ["projects/README.md"]],
                         ids=["a subdirectory of a project", "a rename out of projects/", "a file directly in projects/"])
def test_a_fork_that_changes_a_file_under_projects_and_other_files_fails(tmp_path, head, listed):
    # A path under projects/, of any shape, makes it an enrollment, which must change only one projects/<name>/: it
    # must not pass as "nothing to validate".
    code, log, values, summary = PullRequest(tmp_path, NOT_A_PROJECT["subdirectory"]).run(head, listed=listed)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "outside projects/<name>/: " in log
    assert "nothing to validate" not in log + summary
    assert "Not an enrollment" not in log + summary


def test_a_branch_of_this_repository_that_is_not_an_enrollment_says_so(tmp_path):
    code, log, values, summary = PullRequest(tmp_path, MAINTENANCE).run(REPO)
    assert code == 0, log
    assert values.get("name", "") == ""
    expected = ("Not an enrollment (it changes 2 projects and 1 file outside projects/<name>/): nothing to validate. "
                "The tests check (tests.yaml) validates every project.")
    assert expected in log
    assert expected in summary


def test_a_branch_of_this_repository_that_changes_only_tools_says_so(tmp_path):
    code, log, values, summary = PullRequest(tmp_path, NOT_A_PROJECT["tools"]).run(REPO)
    assert code == 0, log
    assert values.get("name", "") == ""
    assert "Not an enrollment (it changes 0 projects and 1 file outside projects/<name>/)" in summary


@pytest.mark.parametrize("change", list(WITH_ANOTHER_FILE))
def test_a_branch_of_this_repository_that_changes_one_project_and_other_files_takes_the_project(tmp_path, change):
    # Its project is built and validated, as an enrollment's is: the other files do not make it "not an enrollment".
    files = WITH_ANOTHER_FILE[change]
    pull = PullRequest(tmp_path, files)
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values["name"] == "demo"
    for path, text in ENROLLMENT.items():
        assert (pull.checkout / path).read_text() == text
    other = next(path for path in files if path not in ENROLLMENT)
    assert not (pull.checkout / other).exists(), "a file outside the project was taken"
    assert "This pull request also changes 1 file outside projects/demo/, not taken" in summary
    assert "Not an enrollment" not in log + summary


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("change", list(WITH_ANOTHER_FILE))
def test_a_fork_that_changes_one_project_and_other_files_fails(tmp_path, head, change):
    files = WITH_ANOTHER_FILE[change]
    code, log, values, _ = PullRequest(tmp_path, files).run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert f"outside projects/<name>/: {next(path for path in files if path not in ENROLLMENT)}" in log


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("removed", [(), ("projects/curl",)], ids=["changes the port", "removes the port"])
def test_a_fork_that_changes_the_port_of_a_seeded_project_fails(tmp_path, head, removed):
    # docs/seeded-projects.tsv depends on the port of curl. A fork can change no file outside projects/curl/, and the
    # tests check runs no test on it, so a maintainer carries the change on a branch of this repository.
    pull = PullRequest(tmp_path, {} if removed else {"projects/curl/build.sh": CHANGED_BUILD}, removed=removed,
                       on_main=SEEDED_MAIN)
    code, log, values, summary = pull.run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert ("::error::projects/curl/ is the port of a project that we seeded: docs/seeded-projects.tsv marks it "
            "seeded.") in log
    assert SEEDED_REFUSED in log
    assert "nothing to validate" not in log + summary
    assert (pull.checkout / "projects" / "curl" / "build.sh").read_text() == "#!/bin/bash\n"


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("name, on_main", [("sqlpage", SEEDED_MAIN), ("curl", NO_TABLE)],
                         ids=["a project that the table does not mark seeded", "a project with no table on main"])
def test_a_fork_that_changes_the_port_of_a_project_that_is_not_seeded_is_taken(tmp_path, head, name, on_main):
    pull = PullRequest(tmp_path, {f"projects/{name}/build.sh": CHANGED_BUILD}, on_main=on_main)
    code, log, values, _ = pull.run(head)
    assert code == 0, log
    assert values["name"] == name
    assert (pull.checkout / "projects" / name / "build.sh").read_text() == CHANGED_BUILD


def test_a_branch_of_this_repository_that_changes_the_port_of_a_seeded_project_takes_it(tmp_path):
    # The tests check runs Committed on the branch, so the branch carries the change to the port.
    pull = PullRequest(tmp_path, {"projects/curl/build.sh": CHANGED_BUILD}, on_main=SEEDED_MAIN)
    code, log, values, _ = pull.run(REPO)
    assert code == 0, log
    assert values["name"] == "curl"
    assert SEEDED_REFUSED not in log
    assert (pull.checkout / "projects" / "curl" / "build.sh").read_text() == CHANGED_BUILD


@pytest.mark.parametrize("head", [REPO, "someone/oss-verify"])
@pytest.mark.parametrize("files", [{**ENROLLMENT, "projects/demo/sub/notes.txt": "notes\n"},
                                   {"projects/demo/sub/notes.txt": "notes\n"}], ids=["with the project", "alone"])
def test_a_file_in_a_subdirectory_of_the_project_fails(tmp_path, head, files):
    # A fork fails when the files are listed. A file in projects/demo/sub/ is a change to projects/demo/, so a branch
    # of this repository has that project taken, and the subdirectory then fails it: it is never "not an enrollment".
    code, log, values, _ = PullRequest(tmp_path, files).run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "Not an enrollment" not in log
    if head == REPO:
        assert "projects/demo/ may hold only regular files with plain names" in log
    else:
        assert "outside projects/<name>/: projects/demo/sub/notes.txt" in log


# Every case in the checkout of main alone, and two in the first parent's: a stacked branch whose parent landed, and a
# branch that removes one project and adds another.
@pytest.mark.parametrize("case, checkout", [(case, "main") for case in LISTED_BUT_NOT_MERGED]
                         + [(case, "first parent") for case in ("stacked on a squash-merged parent",
                                                                "a removed project and a new one")])
def test_a_branch_of_this_repository_whose_merge_changes_one_project_takes_it(tmp_path, case, checkout):
    # GitHub lists the three-dot diff, which names two projects; merging changes one, and that one is taken.
    files, removed, parent, landed, name = LISTED_BUT_NOT_MERGED[case]
    pull = PullRequest(tmp_path, files, removed=removed, parent=parent, landed=landed, checkout=checkout)
    assert len({path.split("/")[1] for path in pull.paths}) == 2, pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values["name"] == name
    for path, text in files.items():
        if path.startswith(f"projects/{name}/"):
            assert (pull.checkout / path).read_text() == text
    assert "This pull request lists 1 project that merging removes or leaves as on the base branch: not counted." in summary
    assert "Not an enrollment" not in log + summary


@pytest.mark.parametrize("files, removed", [
    (ENROLLMENT, ()), ({**ENROLLMENT, "tools/notes.txt": "a maintainer's change\n"}, ()),
    (ENROLLMENT, ("projects/other",))],
    ids=["the project alone", "with a file outside projects/", "removing another project"])
def test_outside_counts_each_path_the_merge_changes_but_the_taken_projects_files(tmp_path, files, removed):
    """review.yml judges these files by review-change.md: another project's files, a removed one's too, are outside
    the taken project, though the build counts no project but the one it takes."""
    pull = PullRequest(tmp_path, files, removed=removed)
    code, log, values, _ = pull.run(REPO)
    assert code == 0, log
    want = [path for path in pull.paths if not re.fullmatch(r"projects/demo/[^/]+", path)]
    assert (values["name"], values["outside"]) == ("demo", str(len(want))), pull.paths
    assert values["outside"] != "0" or not want


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("case", list(LISTED_BUT_NOT_MERGED))
def test_a_fork_whose_list_names_two_projects_fails(tmp_path, head, case):
    # A fork is judged on the list as GitHub gives it, renamed and removed projects included.
    files, removed, parent, landed, _ = LISTED_BUT_NOT_MERGED[case]
    code, log, values, _ = PullRequest(tmp_path, files, removed=removed, parent=parent, landed=landed).run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "This pull request changes more than one project. One project per pull request." in log


@pytest.mark.parametrize("head", [REPO, "someone/oss-verify", ""])
def test_a_project_the_base_branch_renamed_is_taken_as_the_merge_has_it(tmp_path, head):
    # The branch edits projects/other/build.sh; main has since renamed projects/other to projects/renamed. A branch
    # here is taken as GitHub's merge has it: projects/renamed/ with the branch's build.sh, which then fails to build.
    # A fork is taken from its head, as projects/other/.
    failing = "#!/bin/bash\nexit 1\n"
    pull = PullRequest(tmp_path, {"projects/other/build.sh": failing}, renamed=("projects/other", "projects/renamed"),
                       on_main={"projects/other/build.sh": "#!/bin/bash\n"})
    assert pull.paths == ["projects/other/build.sh"], pull.paths
    code, log, values, _ = pull.run(head)
    assert code == 0, log
    name = "renamed" if head == REPO else "other"
    assert values["name"] == name
    assert (pull.checkout / "projects" / name / "build.sh").read_text() == failing
    assert (pull.checkout / "projects" / name / "project.yaml").read_text() == PROJECT
    assert f"This pull request removes projects/{name}/" not in log
    assert f"Validating projects/{name}/ as it is" in log


def test_a_branch_of_this_repository_stacked_on_a_merged_parent_that_changes_only_status_is_not_an_enrollment(
        tmp_path):
    # The list names the parent's project and STATUS.md; merging changes only STATUS.md, so no project is taken.
    pull = PullRequest(tmp_path, {"STATUS.md": "# Status\n"}, parent=MAKE)
    assert {path.split("/")[0] for path in pull.paths} == {"projects", "STATUS.md"}, pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values.get("name", "") == ""
    assert "This pull request lists 1 project that merging removes or leaves as on the base branch: not counted." in summary
    assert "Not an enrollment (it changes 0 projects and 1 file outside projects/<name>/)" in summary


def test_a_listed_project_named_only_by_a_nested_path_is_counted_as_not_merged(tmp_path):
    # The merged parent added projects/make/sub/notes.txt, the list's only path in make; merging leaves it as on main.
    pull = PullRequest(tmp_path, GIT, parent={"projects/make/sub/notes.txt": "notes\n"})
    assert {path.split("/")[1] for path in pull.paths} == {"git", "make"}, pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values["name"] == "git"
    assert "This pull request lists 1 project that merging removes or leaves as on the base branch: not counted." in summary


def test_a_branch_of_this_repository_whose_merge_changes_no_file_has_nothing_to_do(tmp_path):
    # A stacked branch with no commit of its own beyond its merged parent: the list names the parent's files.
    pull = PullRequest(tmp_path, {}, parent=MAKE)
    assert pull.paths == sorted(MAKE), pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values.get("name", "") == ""
    assert "Merged, this pull request changes no file on the base branch: nothing to validate." in summary


@pytest.mark.parametrize("head", [REPO, "someone/oss-verify"])
def test_a_branch_whose_merge_conflicts_fails(tmp_path, head):
    # The parent's build.sh was changed in review before its squash, and this branch still has the old one.
    pull = PullRequest(tmp_path, GIT, parent=MAKE, landed={**MAKE, "projects/make/build.sh": "#!/bin/bash\nmake\n"})
    code, log, values, _ = pull.run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    if head == REPO:
        assert "conflict: projects/make/build.sh" in log
        assert "does not merge cleanly into the base branch" in log
    else:
        assert "changes more than one project" in log


def test_a_branch_of_this_repository_that_changes_two_projects_is_not_an_enrollment(tmp_path):
    # Both differ from main once merged, so neither is dropped.
    code, log, values, summary = PullRequest(tmp_path, TWO_PROJECTS).run(REPO)
    assert code == 0, log
    assert values.get("name", "") == ""
    assert "Not an enrollment (it changes 2 projects and 0 files outside projects/<name>/)" in summary
    assert "not counted" not in summary


def test_a_branch_of_this_repository_whose_merge_only_removes_projects_has_nothing_to_do(tmp_path):
    # It removes projects/other/, and its stacked parent's projects/second/ is on main already.
    pull = PullRequest(tmp_path, {}, removed=("projects/other",), parent={"projects/second/project.yaml": PROJECT})
    assert {path.split("/")[1] for path in pull.paths} == {"other", "second"}, pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values.get("name", "") == ""
    assert "Merged, this pull request only removes projects: nothing to validate." in summary


def test_an_api_error_after_the_list_is_not_a_moved_head(tmp_path):
    code, log, values, _ = PullRequest(tmp_path, ENROLLMENT).run(REPO, fails_after=True)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "gh: HTTP 502" in log
    assert "moved" not in log


@pytest.mark.parametrize("head", [REPO, "someone/oss-verify"])
def test_an_empty_file_list_decides_only_for_a_fork(tmp_path, head):
    # The API lists no file, but the commit adds projects/demo/. A fork is judged on the list and has nothing to do; a
    # branch here is judged on the merge, which changes projects/demo/, so it is taken.
    code, log, values, summary = PullRequest(tmp_path, ENROLLMENT).run(head, listed=[], changed=0)
    assert code == 0, log
    if head == REPO:
        assert values["name"] == "demo"
        assert "changes no file" not in log + summary
    else:
        assert values.get("name", "") == ""
        assert "This pull request changes no file: nothing to validate." in summary


def test_a_run_started_by_hand_takes_the_apis_head(tmp_path):
    pull = PullRequest(tmp_path, ENROLLMENT)
    code, log, values, _ = pull.run(REPO, event="")
    assert code == 0, log
    assert values["sha"] == pull.sha
    assert values["name"] == "demo"


@pytest.mark.parametrize("moves", ["before", "while the files are listed", "before, with more files than listed"])
def test_a_head_that_moves_fails(tmp_path, moves):
    # The API answers for the head as it is when asked, which must be the event's: the files it lists, and how many.
    pull = PullRequest(tmp_path, ENROLLMENT)
    if moves == "before":
        code, log, values, _ = pull.run(REPO, api=pull.other)
    elif moves == "while the files are listed":
        code, log, values, _ = pull.run(REPO, api_after=pull.other)
    else:
        code, log, values, _ = pull.run(REPO, api=pull.other, changed=3001)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "The pull request's head moved while this run read it." in log


TARGETS_ANOTHER_BRANCH = "This pull request targets licence/driver-mit-or-apache, not main: its checks are for main only."


@pytest.mark.parametrize("head", [REPO, "someone/oss-verify", ""])
@pytest.mark.parametrize("change", ["enrollment", "maintenance", "no file", "more files than listed"])
def test_a_pull_request_into_another_branch_fails(tmp_path, head, change):
    # Whatever it changes, and whoever opens it: a pass here would stand once its base is changed to main.
    pull = PullRequest(tmp_path, MAINTENANCE if change == "maintenance" else ENROLLMENT)
    listed = [] if change == "no file" else None
    changed = 3001 if change == "more files than listed" else None
    code, log, values, summary = pull.run(head, listed=listed, changed=changed, base="licence/driver-mit-or-apache")
    assert code == 1, log
    assert values.get("name", "") == ""
    assert TARGETS_ANOTHER_BRANCH in log
    assert "nothing to validate" not in log + summary


def test_a_pull_request_whose_base_changes_to_main_is_taken(tmp_path):
    # After a change of base, the next run (a push) against main takes the project as for any enrollment.
    pull = PullRequest(tmp_path, ENROLLMENT)
    code, log, _, _ = pull.run("someone/oss-verify", base="licence/driver-mit-or-apache")
    assert code == 1, log
    code, log, values, _ = pull.run("someone/oss-verify", base="main")
    assert code == 0, log
    assert values["name"] == "demo"
    for path, text in ENROLLMENT.items():
        assert (pull.checkout / path).read_text() == text


def test_a_base_that_changes_while_the_files_are_listed_fails(tmp_path):
    # The list was of the pull request into main; the next run, after the change of base, checks it again.
    code, log, values, _ = PullRequest(tmp_path, ENROLLMENT).run(
        REPO, base="main", base_after="licence/driver-mit-or-apache")
    assert code == 1, log
    assert values.get("name", "") == ""
    assert TARGETS_ANOTHER_BRANCH in log


def test_every_page_of_the_changed_files_is_read(tmp_path):
    # The one file outside projects/demo/ is on the third page.
    pull = PullRequest(tmp_path, ENROLLMENT)
    listed = [*(f"projects/demo/file{index}" for index in range(250)), "tools/third-page.txt"]
    code, log, _, _ = pull.run("someone/oss-verify", listed=listed)
    assert code == 1, log
    assert "outside projects/<name>/: tools/third-page.txt" in log


def test_more_files_than_the_api_lists(tmp_path):
    # A fork is judged on the list, which cannot hold its files, so it fails. A branch here is judged on the merge,
    # which git reads whole, so a stacked child of a parent that added thousands of files still has its own project
    # built; only the count of listed projects the merge leaves alone goes unreported.
    pull = PullRequest(tmp_path, ENROLLMENT)
    code, log, _, _ = pull.run("someone/oss-verify", changed=3001)
    assert code == 1, log
    assert "changes 3001 files" in log
    code, log, values, summary = pull.run(REPO, changed=3001)
    assert code == 0, log
    assert values["name"] == "demo"
    assert "not counted" not in summary


def test_a_branch_of_this_repository_over_the_api_limit_is_judged_on_the_merge(tmp_path):
    # Its merged parent added more files than the API lists; merging changes only this branch's project.
    pull = PullRequest(tmp_path, GIT, parent=MAKE)
    code, log, values, summary = pull.run(REPO, changed=3001)
    assert code == 0, log
    assert values["name"] == "git"
    assert "Not an enrollment" not in log + summary


def test_a_project_whose_name_holds_a_newline_fails_the_name_rule(tmp_path):
    # Counted by NUL: one project, whose name the NAME rule then rejects. Counted by line it would be two, and the
    # pull request would pass as "Not an enrollment" with nothing checked.
    pull = PullRequest(tmp_path, {"projects/de\nmo/project.yaml": PROJECT})
    assert pull.paths == ["projects/de\nmo/project.yaml"], pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert "The directory name under projects/ must be a-z 0-9 . _ -" in log
    assert "Not an enrollment" not in log + summary
