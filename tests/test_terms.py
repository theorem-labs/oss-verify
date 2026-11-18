# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for terms.yaml's check terms-accepted, its step run with a made-up gh:  uv run pytest

The check needs the box that accepts the OSS Verify terms in an enrollment's description, and no box for a pull request
that changes no file under projects/, which enrolls nothing. A branch of this repository that adopts a seeded project
names the adopter's pull request from their fork, which ticks the box: their record that they accept the terms.
"""
import json
import os
import pathlib
import shutil
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = "theorem-labs/oss-verify"
HEAD = "a" * 40
BASE = "c" * 40
TICKED = "- [x] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).\n"
UNTICKED = "- [ ] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).\n"
# docs/seeded-projects.tsv of the base, in the form that src/oss_verify/seeded_projects.py writes: curl is seeded, and
# sqlpage is not.
TABLE = ("# Written by src/oss_verify/seeded_projects.py; do not edit.\t\n"
         "project\tseedable\tbuild\tbuild notes\treason or notes\n"
         "curl\tyes\treproduces\tall binaries match the release's\t-\n"
         "sqlpage\tno\t-\t-\tthe release did not build it\n")
# The description of a branch that carries the adoption of curl, and names the adopter's pull request 9.
CARRIED = "Carries the adoption of curl from the adopter's pull request.\n\nAdoption: #9\n"
NO_ADOPTION = "Opened from this repository, and it adopts no seeded project: no terms box needed."
RECORDED = ("Pull request #9, from a fork by adopter, accepts the OSS Verify terms and sets the same primary_contact "
            "for curl: the adoption is recorded.")
NO_RECORD = "::error::This branch adopts curl, which docs/seeded-projects.tsv marks seeded."
NOT_READ = "::error::The files of this pull request could not be read for certain."

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="the check needs jq, as on GitHub's runners")

# gh api, answered by the path it is given from the files the test wrote: pull request <n> (pull.<n>.json, and
# pull.<n>.after.json for every read after the first, a push while the step reads), its files (files.<n>.json, with the
# step's --jq filter applied as gh applies it), and docs/seeded-projects.tsv at the base (table.tsv, as text only for
# the raw media type, as the API gives it). A file that the test did not write is a 404. Each call is appended to
# `calls`. A file `fail` makes every call fail, as an API error.
STUB_GH = r"""#!/bin/bash
echo "$*" >> "$STUB/calls"
[ -e "$STUB/fail" ] && { echo "gh: Server Error (HTTP 502)" >&2; exit 1; }
missing() { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
filter=""; path=""; raw=""
for a; do
  [ "$prev" = --jq ] && filter=$a
  [ "$prev" = -H ] && [ "$a" = "Accept: application/vnd.github.raw" ] && raw=1
  case $a in repos/*) path=${a#repos/theorem-labs/oss-verify/} ;; esac
  prev=$a
done
case "$path" in
  "contents/docs/seeded-projects.tsv?ref=$STUB_BASE")
    [ -e "$STUB/table.tsv" ] || missing
    if [ -n "$raw" ]; then cat "$STUB/table.tsv"
    else jq -n --rawfile table "$STUB/table.tsv" '{encoding: "base64", content: ($table | @base64)}'; fi ;;
  pulls/*/files\?per_page=100)
    n=${path#pulls/}; n=${n%%/*}
    [ -e "$STUB/files.$n.json" ] || missing
    jq -r "$filter" "$STUB/files.$n.json" ;;
  pulls/*)
    n=${path#pulls/}
    pull=$STUB/pull.$n.json
    [ -e "$pull" ] || missing
    if [ -e "$STUB/read.$n" ] && [ -e "$STUB/pull.$n.after.json" ]; then pull=$STUB/pull.$n.after.json; fi
    : > "$STUB/read.$n"
    if [ -n "$filter" ]; then jq -r "$filter" "$pull"; else cat "$pull"; fi ;;
  *) missing ;;
esac
"""


def entry(file):
    """The API's entry for a file: a path, a (new, old) pair for a rename, or the entry itself."""
    if isinstance(file, str):
        return {"filename": file}
    if isinstance(file, tuple):
        return {"filename": file[0], "previous_filename": file[1]}
    return file


def terms(tmp_path, files, body=UNTICKED, head_repository="someone/oss-verify", association="NONE",
          author="someone", changed=None, api_head=HEAD, after_head=None, fail=False, table=TABLE, others=None):
    """Run the check's step on pull request 7 from `head_repository` whose description is `body` and that changes
    `files` (each as `entry` takes it; changed_files: `changed`, by default their number). The API gives `api_head` as
    its head, and `after_head` on every later read, docs/seeded-projects.tsv of the base as `table` (None: a 404), and
    each other pull request of `others`, {number: (pull request, files)}. Return (exit code, output, calls)."""
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "gh").write_text(STUB_GH)
    (stub / "gh").chmod(0o755)

    def pull(head):
        return json.dumps({"number": 7, "head": {"sha": head, "repo": {"full_name": head_repository}},
                           "user": {"login": author}, "body": body,
                           "changed_files": len(files) if changed is None else changed})

    (stub / "pull.7.json").write_text(pull(api_head))
    if after_head:
        (stub / "pull.7.after.json").write_text(pull(after_head))
    (stub / "files.7.json").write_text(json.dumps([entry(f) for f in files]))
    for number, (other, other_files) in (others or {}).items():
        (stub / f"pull.{number}.json").write_text(json.dumps(other))
        (stub / f"files.{number}.json").write_text(json.dumps([entry(f) for f in other_files]))
    if table is not None:
        (stub / "table.tsv").write_text(table)
    if fail:
        (stub / "fail").write_text("")
    (stub / "calls").write_text("")
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "terms.yaml").read_text())
    [step] = flow["jobs"]["terms-accepted"]["steps"]
    env = {**os.environ, "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}", "STUB": str(stub), "STUB_BASE": BASE,
           "BODY": body, "AUTHOR": author, "ASSOCIATION": association, "HEAD_REPOSITORY": head_repository,
           "REPOSITORY": REPOSITORY, "GH_TOKEN": "x", "PR": "7", "HEAD_SHA": HEAD, "BASE_SHA": BASE}
    # bash -e, as GitHub runs a step's run.
    run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True)
    return run.returncode, run.stdout + run.stderr, (stub / "calls").read_text().splitlines()


def adoption(name="curl", contact="security@curl.example", status="modified"):
    """The API's entry for projects/<name>/project.yaml whose patch adopts the seeded port: it removes the two comment
    lines, and replaces primary_contact n/a with `contact`."""
    return {"filename": f"projects/{name}/project.yaml", "status": status, "patch": (
        "@@ -1,6 +1,4 @@\n"
        "-# Seeded by Theorem from the oss-fuzz-theorems 2026.10 release, not enrolled by the project's\n"
        "-# maintainers: provisional. To adopt it, set primary_contact and remove these lines (docs/project-yaml.md).\n"
        f" repo: https://github.com/{name}/{name}\n"
        "-primary_contact: n/a\n"
        f"+primary_contact: {contact}\n"
        f" homepage: https://{name}.example\n")}


def adopter(body=TICKED, head_repository="adopter/oss-verify", author="adopter", files=None, number=9):
    """For `others`: pull request `number` from `head_repository` (None: a deleted fork), opened by `author`, whose
    description is `body` and that changes `files`, by default the adoption of curl and its build.sh."""
    head = {"sha": "d" * 40, "repo": None if head_repository is None else {"full_name": head_repository}}
    pull = {"number": number, "head": head, "user": {"login": author}, "body": body, "changed_files": 2}
    return {number: (pull, [adoption(), "projects/curl/build.sh"] if files is None else files)}


def branch(tmp_path, files=None, body=CARRIED, others=None, **arguments):
    """Run the step on pull request 7 from a branch of this repository, opened by a maintainer, that changes `files`,
    by default the adoption of curl and its build.sh, and whose description is `body`."""
    return terms(tmp_path, [adoption(), "projects/curl/build.sh"] if files is None else files, body=body,
                 head_repository=REPOSITORY, association="MEMBER", author="maintainer", others=others, **arguments)


@pytest.mark.parametrize("files", [
    ["oss-verify check"],
    ["docs/build-contract.md", "oss-verify validate", "tests/test_validate.py"],
    [".github/workflows/build.yaml"],
    ["README.md"],
    [],
])
def test_a_pull_request_that_changes_no_file_under_projects_needs_no_box(tmp_path, files):
    code, out, calls = terms(tmp_path, files)
    assert code == 0, out
    assert "Not an enrollment: this pull request changes no file under projects/, so no terms box is needed." in out


@pytest.mark.parametrize("files", [
    ["projects/demo/project.yaml"],
    ["projects/demo/project.yaml", "oss-verify check"],
    [("tools/x.yaml", "projects/demo/x.yaml")],
    ["projects/README.md"],
], ids=["an enrollment", "an enrollment and a tool", "a rename out of projects/", "a file directly in projects/"])
def test_a_pull_request_that_changes_a_file_under_projects_needs_the_box(tmp_path, files):
    code, out, _ = terms(tmp_path, files)
    assert code == 1, out
    assert "::error::Tick 'I accept the OSS Verify terms' in the pull request description." in out
    (tmp_path / "ticked").mkdir()
    code, out, calls = terms(tmp_path / "ticked", files, body=TICKED)
    assert code == 0, out
    assert "The OSS Verify terms are accepted in the description." in out
    # A ticked box decides without the API.
    assert calls == []


@pytest.mark.parametrize("case", ["over the API's list", "head moved before", "head moved after", "API error"])
def test_a_list_that_cannot_decide_needs_the_box(tmp_path, case):
    arguments = {"over the API's list": {"changed": 3001},
                 "head moved before": {"api_head": "b" * 40},
                 "head moved after": {"after_head": "b" * 40},
                 "API error": {"fail": True}}[case]
    code, out, _ = terms(tmp_path, ["oss-verify check"], **arguments)
    assert code == 1, out
    assert "Not an enrollment" not in out
    assert "::error::Tick 'I accept the OSS Verify terms' in the pull request description." in out


@pytest.mark.parametrize("arguments", [
    {"association": "MEMBER"},
    {"author": "dependabot[bot]"},
])
def test_a_maintainer_or_a_bot_needs_no_box_and_no_api(tmp_path, arguments):
    code, out, calls = terms(tmp_path, ["projects/demo/project.yaml"], **arguments)
    assert code == 0, out
    assert calls == []


@pytest.mark.parametrize("files", [["projects/demo/build.sh"], ["projects/demo/project.yaml"], ["README.md"]],
                         ids=["a build file", "a project.yaml with no patch, of a project that is not seeded",
                              "no file under projects/"])
def test_a_branch_that_adopts_nothing_needs_no_box_after_it_reads_its_files(tmp_path, files):
    code, out, calls = branch(tmp_path, files=files, body=UNTICKED)
    assert code == 0, out
    assert NO_ADOPTION in out
    assert f"api --paginate repos/{REPOSITORY}/pulls/7/files?per_page=100" in " ".join(calls)


@pytest.mark.parametrize("body", [
    CARRIED,
    "Carries the adoption of curl.\n\nAdoption: https://github.com/theorem-labs/oss-verify/pull/9  \n",
    CARRIED.replace("\n", "\r\n"),
    "Adoption: #9",
], ids=["the number", "the URL, with spaces after it", "CRLF line ends", "the last line, with no line end"])
def test_a_branch_that_adopts_a_seeded_project_passes_with_the_adopters_record(tmp_path, body):
    code, out, calls = branch(tmp_path, body=body, others=adopter())
    assert code == 0, out
    assert RECORDED in out
    assert (f"api -H Accept: application/vnd.github.raw repos/{REPOSITORY}/contents/docs/seeded-projects.tsv"
            f"?ref={BASE}") in calls


@pytest.mark.parametrize("ours, theirs", [
    ("security@curl.example", '"security@curl.example"  # the security team'),
    ("'security@curl.example'", "security@curl.example\t"),
    ("security@curl.example # adopted", "  security@curl.example"),
], ids=["quotes and a comment", "single quotes and a tab", "a comment and spaces"])
def test_the_contact_is_read_without_quotes_comments_or_spaces(tmp_path, ours, theirs):
    code, out, _ = branch(tmp_path, files=[adoption(contact=ours)],
                          others=adopter(files=[adoption(contact=theirs)]))
    assert code == 0, out
    assert RECORDED in out


def test_a_record_from_a_deleted_fork_is_from_a_fork(tmp_path):
    code, out, _ = branch(tmp_path, others=adopter(head_repository=None))
    assert code == 0, out
    assert RECORDED in out


@pytest.mark.parametrize("body", [
    "Carries the adoption of curl.\n" + TICKED,
    " Adoption: #9\n",
    "Adoption:#9\n",
    "Adoption: #9 and #10\n",
    "Adoption: https://github.com/someone/oss-verify/pull/9\n",
], ids=["no line, the box ticked", "a space before it", "no space after the colon", "text after it",
        "a pull request of another repository"])
def test_a_branch_that_adopts_a_seeded_project_with_no_record_fails(tmp_path, body):
    # Negative control: the adopter's pull request 9 would pass, but the description does not name it.
    code, out, calls = branch(tmp_path, body=body, others=adopter())
    assert code == 1, out
    assert NO_RECORD in out
    assert RECORDED not in out
    assert not [call for call in calls if "pulls/9" in call]


@pytest.mark.parametrize("body", [UNTICKED, "", "I accept the OSS Verify terms.\n"],
                         ids=["not ticked", "no description", "no box"])
def test_a_record_that_does_not_tick_the_box_fails(tmp_path, body):
    # Negative control: the description names pull request 9, which sets the same contact, but its box is not ticked.
    code, out, _ = branch(tmp_path, others=adopter(body=body))
    assert code == 1, out
    assert "::error::Pull request #9 does not tick 'I accept the OSS Verify terms'." in out
    assert RECORDED not in out


def test_a_record_from_a_branch_of_this_repository_fails(tmp_path):
    code, out, _ = branch(tmp_path, others=adopter(head_repository=REPOSITORY))
    assert code == 1, out
    assert "::error::Pull request #9 comes from a branch of this repository, not from a fork." in out
    assert RECORDED not in out


@pytest.mark.parametrize("files", [
    [adoption(contact="someone@else.example")],
    [adoption(name="sqlpage")],
    [adoption(contact="n/a")],
    [{"filename": "projects/curl/project.yaml", "status": "modified"}],
    ["projects/curl/build.sh"],
], ids=["another address", "another project", "n/a", "no patch", "no project.yaml"])
def test_a_record_that_sets_another_contact_or_none_fails(tmp_path, files):
    code, out, _ = branch(tmp_path, others=adopter(files=files))
    assert code == 1, out
    assert "::error::Pull request #9 sets another primary_contact for curl, or none." in out
    assert RECORDED not in out


@pytest.mark.parametrize("line", ["Adoption: #7", "Adoption: https://github.com/theorem-labs/oss-verify/pull/7"])
def test_a_record_that_is_this_pull_request_fails(tmp_path, line):
    code, out, _ = branch(tmp_path, body=line + "\n", others=adopter())
    assert code == 1, out
    assert "::error::The line Adoption: names this pull request itself." in out
    assert "the adoption is recorded" not in out


@pytest.mark.parametrize("author", ["dependabot[bot]", "someone[bot]"])
def test_a_record_opened_by_a_bot_fails(tmp_path, author):
    code, out, _ = branch(tmp_path, others=adopter(author=author))
    assert code == 1, out
    assert "::error::Pull request #9 was opened by a bot, not by the adopter." in out
    assert "the adoption is recorded" not in out


def test_a_record_that_cannot_be_read_fails(tmp_path):
    code, out, _ = branch(tmp_path, body="Adoption: #10\n", others=adopter())
    assert code == 1, out
    assert "::error::Pull request #10, which the line Adoption: names, could not be read." in out
    assert "the adoption is recorded" not in out


@pytest.mark.parametrize("files", [
    ["projects/curl/build.sh"],
    [{"filename": "projects/curl/project.yaml", "status": "modified", "patch":
      "@@ -4,3 +4,3 @@\n primary_contact: n/a\n-homepage: https://curl.haxx.se\n+homepage: https://curl.se\n"}],
    [{"filename": "projects/curl/project.yaml", "status": "modified", "patch":
      "@@ -4,1 +4,1 @@\n-primary_contact: n/a\n+primary_contact: \"n/a\"  # not adopted yet\n"}],
    [{"filename": "projects/curl/project.yaml", "status": "removed",
      "patch": "@@ -1,1 +0,0 @@\n-primary_contact: security@curl.example\n"}],
    [{"filename": "projects/curl/project.yaml", "status": "removed"}],
    [{"filename": "projects/curl/tools/project.yaml", "patch": "+primary_contact: security@curl.example\n"},
     {"filename": "seeds/curl/project.yaml", "patch": "+primary_contact: security@curl.example\n"},
     {"filename": "projects/curl/project.yaml", "patch": "+ primary_contact: security@curl.example\n"}],
    [{"filename": "projects/curl/project.yaml", "previous_filename": "seeds/curl/project.yaml", "status": "renamed",
      "changes": 0}],
], ids=["a build file", "project.yaml, primary_contact kept", "project.yaml, n/a set again", "project.yaml removed",
        "project.yaml removed, no patch", "no line primary_contact of a projects/<name>/project.yaml",
        "a seed port moved into projects/ with no change, no patch"])
def test_a_branch_that_changes_a_seeded_port_and_keeps_its_contact_needs_no_record(tmp_path, files):
    # A maintainer's own fix of a seeded port. With no contact to adopt, the step does not read the table.
    code, out, calls = branch(tmp_path, files=files, body="Fixes the build of curl.\n")
    assert code == 0, out
    assert NO_ADOPTION in out
    assert not [call for call in calls if "contents/" in call]


def test_a_branch_that_sets_the_contact_of_a_project_that_is_not_seeded_needs_no_record(tmp_path):
    code, out, calls = branch(tmp_path, files=[adoption(name="sqlpage"), adoption(name="demo")], body="Enrolls.\n")
    assert code == 0, out
    assert NO_ADOPTION in out
    assert [call for call in calls if "contents/docs/seeded-projects.tsv" in call]


@pytest.mark.parametrize("case", ["API error", "head moved before", "head moved after", "over the API's list",
                                  "no table"])
def test_a_branch_whose_files_or_table_cannot_be_read_fails(tmp_path, case):
    # Each one with the adopter's record, which would pass: the read alone fails the check.
    arguments = {"API error": {"fail": True},
                 "head moved before": {"api_head": "b" * 40},
                 "head moved after": {"after_head": "b" * 40},
                 "over the API's list": {"changed": 3001},
                 "no table": {"table": None}}[case]
    code, out, _ = branch(tmp_path, others=adopter(), **arguments)
    assert code == 1, out
    if case == "no table":
        assert "::error::docs/seeded-projects.tsv of the base branch could not be read." in out
    else:
        assert NOT_READ in out
    assert NO_ADOPTION not in out
    assert "the adoption is recorded" not in out


def test_a_project_yaml_with_no_patch_needs_a_record_that_cannot_match_it(tmp_path):
    # GitHub leaves out the patch of a large diff: the contact that the branch sets for curl is unknown.
    files = [{"filename": "projects/curl/project.yaml", "status": "modified"}]
    code, out, _ = branch(tmp_path, files=files, body="Carries a large change of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 1, out
    assert ("::error::GitHub lists projects/curl/project.yaml of this pull request with no patch: the primary_contact "
            "that it sets is unknown, and no pull request can record it.") in out
    assert "the adoption is recorded" not in out


def test_a_long_ticked_description_is_read_as_ticked(tmp_path):
    # As long as GitHub allows (65536 characters), the box first: grep -q stops reading at the box, and the step sets
    # no pipefail, so printf's broken pipe never reads as an unticked box.
    code, out, calls = terms(tmp_path, ["projects/demo/project.yaml"], body=TICKED + "x\n" * 32_700)
    assert code == 0, out
    assert calls == []


def test_a_long_ticked_record_is_read_as_ticked(tmp_path):
    code, out, _ = branch(tmp_path, others=adopter(body=TICKED + "x\n" * 32_700))
    assert code == 0, out
    assert RECORDED in out


def test_the_description_reaches_the_step_only_as_data(tmp_path):
    hostile = '$(touch pwned-a) `touch pwned-b` "; touch pwned-c; " \' ; touch pwned-d #'
    code, out, _ = terms(tmp_path, ["projects/demo/project.yaml"], body=hostile)
    assert code == 1, out
    assert sorted(tmp_path.glob("pwned-*")) == []


def test_a_branch_reads_descriptions_patches_file_names_and_logins_only_as_data(tmp_path):
    hostile = '$(touch pwned-a) `touch pwned-b` "; touch pwned-c; " \' ; touch pwned-d #'
    contact = '$(touch pwned-e) `touch pwned-f` "; touch pwned-g; " \' ; touch pwned-h'
    files = [adoption(contact=contact), {"filename": "projects/$(touch pwned-i)/project.yaml",
                                         "patch": "+primary_contact: `touch pwned-j`\n"}]
    login = "$(touch pwned-k)`touch pwned-l`"
    code, out, _ = branch(tmp_path, files=files, body=f"{hostile}\nAdoption: #9\n",
                          others=adopter(body=f"{hostile}\n{TICKED}", author=login, files=files))
    assert sorted(tmp_path.glob("pwned-*")) == []
    # The same text on both sides is the same contact, and the login is only printed.
    assert code == 0, out
    assert f"from a fork by {login}, accepts the OSS Verify terms" in out
