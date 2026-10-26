# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/take-project, which takes projects/<name>/ from a pull request:  python3 -m pytest tools/tests

Each runs the script in a clone of a local repository whose main has one project, with gh answering from a made-up pull
request and the pull request's commit fetched with git. They cover what the pull requests of this repository cannot
show: a pull request from a fork, one that is not an enrollment, one that changes more files than one page lists, and
one whose head moves while the script reads it.
"""
import json
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
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
    base is git's. The checkout is main alone at depth 1, as actions/checkout makes it, so the pull request's commit
    and the merge base are there only once take-project fetches them."""

    def __init__(self, tmp_path, files, removed=(), parent=None, landed=None, renamed=None, on_main=None):
        self.tmp = tmp_path
        self.env = isolated_git_env(tmp_path)
        self.origin = origin = tmp_path / "origin"
        git("init", "-q", "-b", "main", str(origin), env=self.env)
        (origin / "projects" / "other").mkdir(parents=True)
        (origin / "projects" / "other" / "project.yaml").write_text(PROJECT)
        # More files in main's first commit, before the branch leaves it.
        for path, text in (on_main or {}).items():
            (origin / path).parent.mkdir(parents=True, exist_ok=True)
            (origin / path).write_text(text)
        git("add", "-A", cwd=origin, env=self.env)
        git("commit", "-q", "-m", "main", cwd=origin, env=self.env)
        # Another commit the pull request's head can move to.
        self.other = git("rev-parse", "main", cwd=origin, env=self.env)
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
        self.checkout = tmp_path / "checkout"
        git("clone", "-q", "--single-branch", "--branch", "main", "--depth", "1", f"file://{origin}",
            str(self.checkout), env=self.env)
        assert subprocess.run(["git", "cat-file", "-e", self.sha], cwd=self.checkout, env=self.env,
                              capture_output=True).returncode != 0, "the checkout already has the pull request's commit"
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
        Return (exit code, output, outputs, summary)."""
        answers = self.tmp / "gh"
        stubs = self.tmp / "stubs"
        for directory in (answers, stubs):
            shutil.rmtree(directory, ignore_errors=True)
            directory.mkdir()
        (stubs / "gh").write_text(STUB_GH)
        (stubs / "gh").chmod(0o755)
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
        env = {**self.env, "PATH": f"{stubs}{os.pathsep}{self.env['PATH']}", "STUB_GH": str(answers),
               "GH_TOKEN": "stub-token", "REPO": REPO, "PR": "7", "HEAD_SHA": self.sha if event is None else event,
               "RUNNER_TEMP": str(temp), "GITHUB_OUTPUT": str(outputs), "GITHUB_STEP_SUMMARY": str(summary)}
        done = subprocess.run([str(SCRIPT), "validate"], cwd=self.checkout, env=env, capture_output=True, text=True,
                              check=False)
        values = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
        return done.returncode, done.stdout + done.stderr, values, summary.read_text()


ENROLLMENT = {"projects/demo/project.yaml": PROJECT, "projects/demo/Dockerfile": "FROM x\n",
              "projects/demo/build.sh": "#!/bin/bash\n"}
MAINTENANCE = {"projects/demo/project.yaml": PROJECT, "projects/other/project.yaml": PROJECT + "# edited\n",
               "tools/notes.txt": "a maintainer's change\n"}
# Two projects and no other file.
TWO_PROJECTS = {**ENROLLMENT, "projects/second/project.yaml": PROJECT}
# Changes no project's own files: a tool, a workflow, a file in a subdirectory of a project.
NOT_A_PROJECT = {
    "tools": {"tools/validate.py": "# rewritten\n"},
    "workflow": {".github/workflows/build.yaml": "name: rewritten\n"},
    "subdirectory": {"projects/demo/sub/build.sh": "#!/bin/bash\n"},
}
# An enrollment with one more file outside its project: a line of STATUS.md, the project's row in
# docs/seeded-projects.tsv.
WITH_ANOTHER_FILE = {
    "status": {**ENROLLMENT, "STATUS.md": "# Status\n"},
    "seeded": {**ENROLLMENT, "docs/seeded-projects.tsv": "demo\n"},
}
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


@pytest.mark.parametrize("head", [REPO, "someone/oss-verify"])
def test_an_enrollment_is_taken(tmp_path, head):
    pull = PullRequest(tmp_path, ENROLLMENT)
    code, log, values, _ = pull.run(head)
    assert code == 0, log
    assert values["name"] == "demo"
    assert values["same_repository"] == ("true" if head == REPO else "false")
    for path, text in ENROLLMENT.items():
        assert (pull.checkout / path).read_text() == text
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


@pytest.mark.parametrize("head", ["someone/oss-verify", ""])
@pytest.mark.parametrize("change", list(NOT_A_PROJECT))
def test_a_fork_that_changes_no_project_but_other_files_fails(tmp_path, head, change):
    # It must not pass as "nothing to validate": a fork's tests check runs none of its code, so these checks are the only
    # ones that judge it.
    files = NOT_A_PROJECT[change]
    code, log, values, summary = PullRequest(tmp_path, files).run(head)
    assert code == 1, log
    assert values.get("name", "") == ""
    assert f"outside projects/<name>/: {next(iter(files))}" in log
    assert "nothing to validate" not in log + summary


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


@pytest.mark.parametrize("case", list(LISTED_BUT_NOT_MERGED))
def test_a_branch_of_this_repository_whose_merge_changes_one_project_takes_it(tmp_path, case):
    # GitHub lists the three-dot diff, which names two projects; merging changes one, and that one is taken.
    files, removed, parent, landed, name = LISTED_BUT_NOT_MERGED[case]
    pull = PullRequest(tmp_path, files, removed=removed, parent=parent, landed=landed)
    assert len({path.split("/")[1] for path in pull.paths}) == 2, pull.paths
    code, log, values, summary = pull.run(REPO)
    assert code == 0, log
    assert values["name"] == name
    for path, text in files.items():
        if path.startswith(f"projects/{name}/"):
            assert (pull.checkout / path).read_text() == text
    assert "This pull request lists 1 project that merging removes or leaves as on the base branch: not counted." in summary
    assert "Not an enrollment" not in log + summary


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
    # Changing the base sends edited, and this run against main takes the project as for any enrollment.
    pull = PullRequest(tmp_path, ENROLLMENT)
    code, log, _, _ = pull.run("someone/oss-verify", base="licence/driver-mit-or-apache")
    assert code == 1, log
    code, log, values, _ = pull.run("someone/oss-verify", base="main")
    assert code == 0, log
    assert values["name"] == "demo"
    for path, text in ENROLLMENT.items():
        assert (pull.checkout / path).read_text() == text


def test_a_base_that_changes_while_the_files_are_listed_fails(tmp_path):
    # The list was of the pull request into main; the run for the new base checks it again.
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
