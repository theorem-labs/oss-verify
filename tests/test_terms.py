# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for terms.yaml's check terms-accepted, its step run with a made-up gh:  uv run pytest

The check needs the box that accepts the OSS Verify terms in an enrollment's description, and no box for a pull request
that changes no file under projects/, which enrolls nothing. A branch of this repository that adopts a seeded project
names the adopter's pull request from their fork, which ticks the box and names the project: their record that they
accept the terms. The step runs .github/scripts/terms-accepted, which reads the addresses that get findings as
oss-verify validate reads them: with load and finding_addresses of oss_verify.validate. The step runs in a temporary
directory, as in the checkout of the base, where .github/scripts and src are links to this repository's.
"""
import json
import os
import pathlib
import shutil
import subprocess
import time

import pytest
import yaml

from oss_verify import validate

from test_outside_screen import read_workflow

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = "theorem-labs/oss-verify"
HEAD = "a" * 40
BASE = "c" * 40
TICKED = "- [x] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).\n"
UNTICKED = "- [ ] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).\n"
# docs/seeded-projects.tsv of the base, in the form that src/oss_verify/seeded_projects.py writes: curl and abseil-cpp
# are seeded, and sqlpage is not.
TABLE = ("# Written by src/oss_verify/seeded_projects.py; do not edit.\t\n"
         "project\tseedable\tbuild\tbuild notes\treason or notes\n"
         "abseil-cpp\tyes\treproduces\tall binaries match the release's\t-\n"
         "curl\tyes\treproduces\tall binaries match the release's\t-\n"
         "sqlpage\tno\t-\t-\tthe release did not build it\n")
# The description of a branch that carries the adoption of curl, and names the adopter's pull request 9.
CARRIED = "Carries the adoption of curl from the adopter's pull request.\n\nAdoption: #9\n"
# The description of the adopter's pull request 9: the heading of the pull request template names the project, and
# the box is ticked.
NAMES_CURL = "## Enroll `projects/curl`\n\n" + TICKED
NO_ADOPTION = "Opened from this repository, and it adopts no seeded project: no terms box needed."
RECORDED = ("Pull request #9, from a fork by adopter, accepts the OSS Verify terms and names projects/curl, and no "
            "other project: the adoption is recorded.")
NO_RECORD = "::error::This branch adopts curl, which docs/seeded-projects.tsv marks seeded."
NOT_READ = "::error::The files of this pull request could not be read for certain."
REFUSED = "::error::oss-verify validate refuses projects/curl/project.yaml of this pull request"
# The text of the seed port of curl, of curl adopted, and of curl adopted by alice.
SEED = "repo: https://github.com/curl/curl\nprimary_contact: n/a\n"
ADOPTED = "repo: https://github.com/curl/curl\nprimary_contact: security@curl.example\n"
ALICE = "repo: https://github.com/curl/curl\nprimary_contact: alice@curl.example\n"
# The two comment lines of a seeded project.yaml.
SEEDED = ("# Seeded by Theorem from the oss-fuzz-theorems 2026.10 release, not enrolled by the project's\n"
          "# maintainers: provisional. To adopt it, set primary_contact and remove these lines "
          "(docs/project-yaml.md).\n")
# For the `head` or `base` of a file entry: the API gives an error other than a 404 for that text.
API_ERROR = object()
# A changed copy of .github/scripts/terms-accepted, in merge/: it passes every pull request.
PASSES = "print(\"the merge commit's copy of terms-accepted ran\")\n"

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="the made-up gh needs jq, as on GitHub's runners")

# gh api, answered by the path it is given from the files the test wrote: pull request <n> (pull.<n>.json, and
# pull.<n>.after.json for every read after the first, a push while the step reads), its files (files.<n>.json, with the
# program's --jq filter applied as gh applies it), docs/seeded-projects.tsv at the base (table.tsv), and the text of a
# file at a commit (contents/<commit>/<path>; errors/<commit>/<path> for an API error), each as text only for the raw
# media type, as the API gives it. A file that the test did not write is a 404. Each call is appended to `calls`. A file
# `fail` makes every call fail, as an API error.
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
  contents/*\?ref=*)
    file=${path#contents/}; ref=${file##*\?ref=}; file=${file%\?ref=*}
    [ -e "$STUB/errors/$ref/$file" ] && { echo "gh: Server Error (HTTP 502)" >&2; exit 1; }
    [ -f "$STUB/contents/$ref/$file" ] || missing
    if [ -n "$raw" ]; then cat "$STUB/contents/$ref/$file"
    else jq -n --rawfile text "$STUB/contents/$ref/$file" '{encoding: "base64", content: ($text | @base64)}'; fi ;;
  *) missing ;;
esac
"""


def entry(file):
    """The API's entry for a file: a path, a (new, old) pair for a rename, or the entry itself, without its `head` and
    `base`, which only `write_texts` reads."""
    if isinstance(file, str):
        return {"filename": file}
    if isinstance(file, tuple):
        return {"filename": file[0], "previous_filename": file[1]}
    return {key: value for key, value in file.items() if key not in ("head", "base")}


def texts(file):
    """The (head, base) texts of a file entry, None for no file. The entry's own `head` and `base` win. Else, for an
    entry that has only a patch (the tester's test of another YAML spelling, and its sibling): the context and added
    lines at the head, and the context and removed lines at the base. An added file has no base, a removed file no
    head, and an entry with neither texts nor a patch neither."""
    head = base = None
    if "patch" in file:
        lines = file["patch"].split("\n")
        if file.get("status") != "removed":
            head = "".join(line[1:] + "\n" for line in lines if line[:1] in (" ", "+"))
        if file.get("status") != "added":
            base = "".join(line[1:] + "\n" for line in lines if line[:1] in (" ", "-"))
    return file.get("head", head), file.get("base", base)


def write_texts(stub, files, head, base=None):
    """Make the made-up gh give the texts of `files` (each as `entry` takes it): the head text of each one at commit
    `head`, and its base text, under its old name for a rename, at commit `base` (None: no base). A text API_ERROR is
    an API error."""
    for file in files:
        if not isinstance(file, dict):
            continue
        head_text, base_text = texts(file)
        reads = [(head, file["filename"], head_text)]
        if base is not None:
            reads.append((base, file.get("previous_filename", file["filename"]), base_text))
        for commit, path, text in reads:
            if text is None:
                continue
            where = stub / ("errors" if text is API_ERROR else "contents") / commit / path
            where.parent.mkdir(parents=True, exist_ok=True)
            where.write_text("" if text is API_ERROR else text)


def terms(tmp_path, files, body=UNTICKED, head_repository="someone/oss-verify", association="NONE",
          author="someone", changed=None, api_head=HEAD, after_head=None, fail=False, table=TABLE, others=None,
          no_yaml=False, base_program=True, merge_program=None):
    """Run the check's step on pull request 7 from `head_repository` whose description is `body` and that changes
    `files` (each as `entry` takes it, with its texts as `texts` gives them; changed_files: `changed`, by default their
    number). The API gives `api_head` as its head, and `after_head` on every later read, docs/seeded-projects.tsv of the
    base as `table` (None: a 404), and each other pull request of `others`, {number: pull request}. The step runs in
    `tmp_path`, as in the checkout of the base: .github/scripts and src there are links to this repository's. With
    `no_yaml`, src there is a directory with a link to oss_verify and a yaml.py that raises ImportError, as on a runner
    without PyYAML. With `base_program` False, the base is older than .github/scripts/terms-accepted: its
    .github/scripts is an empty directory, and it has no src. With `merge_program`, merge/ is the checkout of the merge
    commit: its .github/scripts/terms-accepted has the text `merge_program`, and its src is a link to this
    repository's. Return (exit code, output, calls)."""
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
    write_texts(stub, files, HEAD, BASE)
    for number, other in (others or {}).items():
        (stub / f"pull.{number}.json").write_text(json.dumps(other))
    if table is not None:
        (stub / "table.tsv").write_text(table)
    if fail:
        (stub / "fail").write_text("")
    (stub / "calls").write_text("")
    scripts = tmp_path / ".github" / "scripts"
    scripts.parent.mkdir()
    if not base_program:
        scripts.mkdir()
    else:
        scripts.symlink_to(ROOT / ".github" / "scripts")
        if no_yaml:
            (tmp_path / "src").mkdir()
            (tmp_path / "src" / "oss_verify").symlink_to(ROOT / "src" / "oss_verify")
            (tmp_path / "src" / "yaml.py").write_text('raise ImportError("no PyYAML on this runner")\n')
        else:
            (tmp_path / "src").symlink_to(ROOT / "src")
    if merge_program is not None:
        (tmp_path / "merge" / ".github" / "scripts").mkdir(parents=True)
        (tmp_path / "merge" / ".github" / "scripts" / "terms-accepted").write_text(merge_program)
        (tmp_path / "merge" / "src").symlink_to(ROOT / "src")
    flow = read_workflow("terms.yaml")
    [step] = [step for step in flow["jobs"]["terms-accepted"]["steps"]
              if step.get("name") == "The description accepts the OSS Verify terms"]
    env = {**os.environ, "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}", "STUB": str(stub), "STUB_BASE": BASE,
           "BODY": body, "AUTHOR": author, "ASSOCIATION": association, "HEAD_REPOSITORY": head_repository,
           "REPOSITORY": REPOSITORY, "GH_TOKEN": "x", "PR": "7", "HEAD_SHA": HEAD, "BASE_SHA": BASE}
    # bash -e, as GitHub runs a step's run, and no longer than the job's timeout-minutes.
    run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True,
                         timeout=60 * flow["jobs"]["terms-accepted"]["timeout-minutes"])
    return run.returncode, run.stdout + run.stderr, (stub / "calls").read_text().splitlines()


def adoption(name="curl", contact="security@curl.example"):
    """The API's entry for projects/<name>/project.yaml of a branch that adopts the seeded port: the base has the two
    comment lines and primary_contact n/a, and the head has no comment lines and primary_contact `contact`."""
    repo, homepage = f"repo: https://github.com/{name}/{name}\n", f"homepage: https://{name}.example\n"
    return {"filename": f"projects/{name}/project.yaml", "status": "modified",
            "base": SEEDED + repo + "primary_contact: n/a\n" + homepage,
            "head": repo + f"primary_contact: {contact}\n" + homepage}


def adopter(body=NAMES_CURL, head_repository="adopter/oss-verify", author="adopter", number=9):
    """For `others`: pull request `number` from `head_repository` (None: a deleted fork), opened by `author`, whose
    description is `body`. Its head is the commit "d" * 40, but the check reads no file at that commit."""
    head = {"sha": "d" * 40, "repo": None if head_repository is None else {"full_name": head_repository}}
    return {number: {"number": number, "head": head, "user": {"login": author}, "body": body, "changed_files": 2}}


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


@pytest.mark.parametrize("files, reads", [
    (["projects/demo/build.sh"], []),
    (["projects/demo/project.yaml"], ["docs/seeded-projects.tsv"]),
    (["README.md"], []),
], ids=["a build file", "a project.yaml of a project that is not seeded", "no file under projects/"])
def test_a_branch_that_adopts_nothing_needs_no_box_after_it_reads_its_files(tmp_path, files, reads):
    code, out, calls = branch(tmp_path, files=files, body=UNTICKED)
    assert code == 0, out
    assert NO_ADOPTION in out
    assert f"api --paginate repos/{REPOSITORY}/pulls/7/files?per_page=100" in " ".join(calls)
    # The table only for a project.yaml, and the text of no file: no project of these is seeded.
    assert [call.split("/contents/")[1].split("?")[0] for call in calls if "/contents/" in call] == reads


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
    # The table, and projects/curl/project.yaml at the head and at the base: no file of the record.
    assert [call.split("/contents/")[1] for call in calls if "/contents/" in call] == [
        f"docs/seeded-projects.tsv?ref={BASE}", f"projects/curl/project.yaml?ref={HEAD}",
        f"projects/curl/project.yaml?ref={BASE}"]


def test_a_record_need_not_change_the_project(tmp_path):
    # The check reads the description of pull request 9, never its list of files or a file at its head: the record
    # does not have to change projects/curl/.
    code, out, calls = branch(tmp_path, others=adopter())
    assert code == 0, out
    assert RECORDED in out
    assert [call for call in calls if "pulls/9" in call] == [f"api repos/{REPOSITORY}/pulls/9"]
    assert not [call for call in calls if f"ref={'d' * 40}" in call]


@pytest.mark.parametrize("base, head", [
    ("security@curl.example", '"security@curl.example"  # the security team'),
    ("'security@curl.example'", "security@curl.example   "),
    ("security@curl.example # adopted", "  security@curl.example"),
], ids=["quotes and a comment", "single quotes and spaces after it", "a comment and spaces"])
def test_the_same_contact_in_another_spelling_adopts_nothing(tmp_path, base, head):
    # The check compares the values that YAML gives at the head and at the base, not the lines.
    files = [{"filename": "projects/curl/project.yaml", "status": "modified",
              "base": f"repo: https://github.com/curl/curl\nprimary_contact: {base}\n",
              "head": f"repo: https://github.com/curl/curl\nprimary_contact: {head}\n"}]
    code, out, _ = branch(tmp_path, files=files, body="Fixes the build of curl.\n")
    assert code == 0, out
    assert NO_ADOPTION in out


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
    # Negative control: the description names pull request 9, which names curl, but its box is not ticked.
    code, out, _ = branch(tmp_path, others=adopter(body="## Enroll `projects/curl`\n\n" + body))
    assert code == 1, out
    assert "::error::Pull request #9 does not tick 'I accept the OSS Verify terms'." in out
    assert RECORDED not in out


def test_a_record_from_a_branch_of_this_repository_fails(tmp_path):
    code, out, _ = branch(tmp_path, others=adopter(head_repository=REPOSITORY))
    assert code == 1, out
    assert "::error::Pull request #9 comes from a branch of this repository, not from a fork." in out
    assert RECORDED not in out


@pytest.mark.parametrize("body", [
    NAMES_CURL,
    "Adopts projects/curl/ for its maintainers.\n" + TICKED,
    "Adopts projects/curl for its maintainers.\n" + TICKED,
    "Adopts projects/curl\n" + TICKED,
    TICKED + "Adopts projects/curl",
    "Adopts projects/curl, with its build files.\n" + TICKED,
    "Adopts https://github.com/theorem-labs/oss-verify/tree/main/projects/curl\n" + TICKED,
    "I adopt projects/curl.\n" + TICKED,
], ids=["a backtick after it, in the template's heading", "a slash after it", "a space after it",
        "a line end after it", "the end of the description", "a comma after it", "in the path of a URL",
        "a final period after it"])
def test_a_record_that_names_the_project_passes(tmp_path, body):
    code, out, _ = branch(tmp_path, others=adopter(body=body))
    assert code == 0, out
    assert RECORDED in out


@pytest.mark.parametrize("body, errors", [
    (TICKED, ["::error::Pull request #9 does not name projects/curl in its description."]),
    ("## Enroll `projects/<name>`\n\n" + TICKED,
     ["::error::Pull request #9 does not name projects/curl in its description."]),
    ("## Enroll `projects/sqlpage`\n\n" + TICKED,
     ["::error::Pull request #9 does not name projects/curl in its description.",
      "::error::Pull request #9 also names projects/sqlpage. One record names each project that this branch adopts, "
      "and no other."]),
    ("## Enroll `projects/curl` and `projects/sqlpage`\n\n" + TICKED,
     ["::error::Pull request #9 also names projects/sqlpage. One record names each project that this branch adopts, "
      "and no other."]),
    ("## Enroll `projects/curlx`\n\n" + TICKED,
     ["::error::Pull request #9 does not name projects/curl in its description.",
      "::error::Pull request #9 also names projects/curlx."]),
    # A name ends before a final period only: projects/curl.. names curl., and projects/curl.x names curl.x.
    ("I adopt projects/curl..\n" + TICKED,
     ["::error::Pull request #9 does not name projects/curl in its description.",
      "::error::Pull request #9 also names projects/curl.. One record names each project"]),
    ("I adopt projects/curl.x\n" + TICKED,
     ["::error::Pull request #9 does not name projects/curl in its description.",
      "::error::Pull request #9 also names projects/curl.x. One record names each project"]),
], ids=["no project", "the template's heading as it is", "another project", "the project and another",
        "projects/curlx, which is not curl", "two periods after it", "a period and more after it"])
def test_a_record_that_does_not_name_the_project_alone_fails(tmp_path, body, errors):
    # One record cannot serve two projects: it names each project that the branch adopts, and no other.
    code, out, _ = branch(tmp_path, others=adopter(body=body))
    assert code == 1, out
    for error in errors:
        assert error in out
    assert "the adoption is recorded" not in out


def test_a_branch_that_adopts_several_projects_needs_one_record_that_names_each(tmp_path):
    files = [adoption(), adoption(name="abseil-cpp")]
    both = "## Enroll `projects/curl` and `projects/abseil-cpp`\n\n" + TICKED
    code, out, _ = branch(tmp_path, files=files, others=adopter(body=both))
    assert code == 0, out
    assert ("accepts the OSS Verify terms and names projects/abseil-cpp, projects/curl, and no other project: the "
            "adoption is recorded.") in out
    # Negative control: the record names curl alone.
    (tmp_path / "curl").mkdir()
    code, out, _ = branch(tmp_path / "curl", files=files, others=adopter())
    assert code == 1, out
    assert "::error::Pull request #9 does not name projects/abseil-cpp in its description." in out
    assert "the adoption is recorded" not in out


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
    [{"filename": "projects/curl/project.yaml", "status": "modified", "base": SEED + "homepage: https://curl.haxx.se\n",
      "head": SEED + "homepage: https://curl.se\n"}],
    [{"filename": "projects/curl/project.yaml", "status": "modified", "base": SEED,
      "head": "repo: https://github.com/curl/curl\nprimary_contact: \"n/a\"  # not adopted yet\n"}],
    [{"filename": "projects/curl/project.yaml", "status": "removed", "base": ADOPTED}],
    [{"filename": "projects/curl/project.yaml", "status": "removed"}],
    [{"filename": "projects/curl/tools/project.yaml", "status": "added", "head": ADOPTED},
     {"filename": "seeds/curl/project.yaml", "status": "modified", "base": SEED, "head": ADOPTED},
     {"filename": "projects/curl/project.yaml", "status": "modified", "base": SEED, "head": SEED + (
         "# primary_contact: security@curl.example\nnotes:\n  primary_contact: security@curl.example\n")}],
    [{"filename": "projects/curl/project.yaml", "previous_filename": "seeds/curl/project.yaml", "status": "renamed",
      "changes": 0, "head": SEED, "base": SEED}],
    [{"filename": "projects/curl/project.yaml", "status": "added", "head": SEED}],
    [{"filename": "projects/curl/project.yaml", "status": "modified",
      "base": "repo: https://github.com/curl/curl\nprimary_contact: old@curl.example\n", "head": SEED}],
    [{"filename": "projects/curl/project.yaml", "status": "modified",
      "base": ALICE + "auto_ccs: [bob@curl.example, mallory@evil.example]\n",
      "head": ALICE + "auto_ccs: [bob@curl.example]\n"}],
    [{"filename": "projects/curl/project.yaml", "status": "modified", "base": ALICE + "auto_ccs: [bob@curl.example]\n",
      "head": SEED}],
], ids=["a build file", "project.yaml, primary_contact kept", "project.yaml, n/a set again", "project.yaml removed",
        "project.yaml removed, no text",
        "a contact in a comment, under another key, or in another file than projects/<name>/project.yaml",
        "a seed port moved into projects/ with no change", "a seed port added to projects/ with n/a",
        "a contact set back to n/a", "an auto_ccs address removed", "a contact set back to n/a, and auto_ccs removed"])
def test_a_branch_that_changes_a_seeded_port_and_keeps_its_contact_needs_no_record(tmp_path, files):
    # A maintainer's own fix of a seeded port: the head has no project.yaml, or gives findings to no address that the
    # base does not give them to.
    code, out, _ = branch(tmp_path, files=files, body="Fixes the build of curl.\n")
    assert code == 0, out
    assert NO_ADOPTION in out


def test_a_branch_that_sets_the_contact_of_a_project_that_is_not_seeded_needs_no_record(tmp_path):
    code, out, calls = branch(tmp_path, files=[adoption(name="sqlpage"), adoption(name="demo")], body="Enrolls.\n")
    assert code == 0, out
    assert NO_ADOPTION in out
    assert [call for call in calls if "contents/docs/seeded-projects.tsv" in call]
    assert not [call for call in calls if "contents/projects/" in call]


@pytest.mark.parametrize("key", ['"primary_contact":', "'primary_contact':", "primary_contact :"],
                         ids=["double quotes", "single quotes", "a space before the colon"])
def test_a_seeded_contact_in_another_yaml_spelling_needs_the_record(tmp_path, key):
    # oss-verify validate reads project.yaml with yaml.safe_load, which reads each of these lines as primary_contact:
    # the branch adopts curl as surely as with primary_contact:. With no record, the step says that the record is
    # missing. With the adopter's record, which names curl, it passes.
    assert yaml.safe_load(f"{key} security@curl.example\n") == {"primary_contact": "security@curl.example"}
    files = [{"filename": "projects/curl/project.yaml", "status": "modified",
              "patch": f"@@ -4,1 +4,1 @@\n-primary_contact: n/a\n+{key} security@curl.example\n"}]
    code, out, _ = branch(tmp_path, files=files, body="Carries the adoption of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out


@pytest.mark.parametrize("head", [
    "{repo: https://github.com/curl/curl, primary_contact: security@curl.example}\n",
    "repo: https://github.com/curl/curl\nprimary_contact: >-\n  security@curl.example\n",
], ids=["a flow mapping", "a block scalar"])
def test_a_seeded_contact_in_another_yaml_form_is_an_adoption(tmp_path, head):
    files = [{"filename": "projects/curl/project.yaml", "status": "modified", "base": SEED, "head": head}]
    assert yaml.safe_load(head)["primary_contact"] == "security@curl.example"
    code, out, _ = branch(tmp_path, files=files, body="Carries the adoption of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out


@pytest.mark.parametrize("base, status", [
    ("repo: https://github.com/curl/curl\nprimary_contact: old@curl.example\n", "modified"),
    (None, "added"),
], ids=["another address than the base's", "a new file, which the base does not have: n/a"])
def test_a_branch_that_sets_a_contact_other_than_the_bases_adopts(tmp_path, base, status):
    # A change from one contact to another needs a record from the new contact.
    files = [{"filename": "projects/curl/project.yaml", "status": status, "base": base, "head": ADOPTED}]
    code, out, calls = branch(tmp_path, files=files, body="Carries the adoption of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    assert (f"api -H Accept: application/vnd.github.raw repos/{REPOSITORY}/contents/projects/curl/project.yaml"
            f"?ref={BASE}") in calls
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out


@pytest.mark.parametrize("base", [ALICE, SEED], ids=["an adopted project", "an n/a port"])
def test_an_added_auto_ccs_address_adopts_the_project(tmp_path, base):
    # Each address of auto_ccs gets each finding, as primary_contact does: an address added there needs a record of
    # its own, as a new contact does.
    files = [{"filename": "projects/curl/project.yaml", "status": "modified", "base": base,
              "head": base + "auto_ccs: [mallory@evil.example]\n"}]
    code, out, _ = branch(tmp_path, files=files, body="Carries a change of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out
    # Negative control: the same auto_ccs at the base and at the head adopts nothing.
    (tmp_path / "kept").mkdir()
    code, out, _ = branch(tmp_path / "kept", files=[{**files[0], "base": files[0]["head"]}],
                          body="Fixes the build of curl.\n")
    assert code == 0, out
    assert NO_ADOPTION in out


@pytest.mark.parametrize("ccs", ["mallory@evil.example", "[5]", "[null]", "[[mallory@evil.example]]",
                                 "{address: mallory@evil.example}"],
                         ids=["a string", "a number in the list", "null in the list", "a list in the list",
                              "a mapping"])
@pytest.mark.parametrize("contact", ["security@curl.example", "n/a"])
def test_an_auto_ccs_that_is_not_a_list_of_strings_at_the_head_fails(tmp_path, ccs, contact):
    # oss-verify validate refuses the file, so the addresses are unknown and the check fails, even with the adopter's
    # record, which would pass.
    head = f"repo: https://github.com/curl/curl\nprimary_contact: {contact}\nauto_ccs: {ccs}\n"
    assert "auto_ccs must be a list of addresses" in validate.check_addresses(yaml.safe_load(head))
    code, out, _ = branch(tmp_path, files=[{**adoption(), "head": head}], others=adopter())
    assert code == 1, out
    assert REFUSED in out
    assert "the adoption is recorded" not in out


def test_a_seed_port_moved_into_projects_with_a_contact_adopts_it(tmp_path):
    # The two steps of the review. Step A changes only seeds/abseil-cpp/project.yaml, to a contact: the check reads no
    # file of seeds/, and the test in tests/test_seeded_projects.py that each seed port has n/a fails step A. Step B,
    # this branch, moves seeds/abseil-cpp/ into projects/abseil-cpp/ with no change. Had step A merged, the seed port at
    # the base would have the contact too, but the check reads projects/abseil-cpp/project.yaml of the base, which is
    # not there: n/a. So step B adopts abseil-cpp, and with no record the step must not pass it.
    text = "repo: https://github.com/abseil/abseil-cpp\nprimary_contact: maintainer@abseil.example\n"
    rename = {"filename": "projects/abseil-cpp/project.yaml", "previous_filename": "seeds/abseil-cpp/project.yaml",
              "status": "renamed", "changes": 0, "head": text, "base": text}
    code, out, calls = branch(tmp_path, files=[rename], body="Moves abseil-cpp into projects/.\n")
    assert code == 1, out
    assert "::error::This branch adopts abseil-cpp, which docs/seeded-projects.tsv marks seeded." in out
    assert [call.split("/contents/")[1] for call in calls if "/contents/" in call] == [
        f"docs/seeded-projects.tsv?ref={BASE}", f"projects/abseil-cpp/project.yaml?ref={HEAD}",
        f"projects/abseil-cpp/project.yaml?ref={BASE}"]
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=[rename],
                          others=adopter(body="## Enroll `projects/abseil-cpp`\n\n" + TICKED))
    assert code == 0, out
    assert "names projects/abseil-cpp, and no other project: the adoption is recorded." in out


def test_a_rename_of_the_project_yaml_of_another_project_onto_a_seeded_project_adopts_it(tmp_path):
    # projects/sqlpage/project.yaml, which sets a contact, becomes projects/curl/project.yaml with no change. The
    # contact of sqlpage does not carry over to curl: the base of curl is projects/curl/project.yaml, which is not
    # there, so the branch gives curl a first contact, and with no record the step must not pass it.
    sqlpage = "repo: https://github.com/sqlpage/sqlpage\nprimary_contact: maintainer@sqlpage.example\n"
    files = [{"filename": "projects/curl/project.yaml", "previous_filename": "projects/sqlpage/project.yaml",
              "status": "renamed", "changes": 0, "head": sqlpage, "base": sqlpage}]
    code, out, calls = branch(tmp_path, files=files, body="Moves sqlpage onto curl.\n")
    assert code == 1, out
    assert NO_ADOPTION not in out
    assert NO_RECORD in out
    assert [call.split("/contents/")[1] for call in calls if "/contents/" in call] == [
        f"docs/seeded-projects.tsv?ref={BASE}", f"projects/curl/project.yaml?ref={HEAD}",
        f"projects/curl/project.yaml?ref={BASE}"]


@pytest.mark.parametrize("old", ["seeds/curl/project.yaml", "seeds/sqlpage/project.yaml", "projects/curl/project.yml",
                                 "seeds/../seeds/curl/project.yaml", "seeds/$(touch pwned-a)/project.yaml",
                                 "seeds/curl/project.yaml?ref=main", "seeds/curl project.yaml"],
                         ids=["the seed port of curl", "the seed port of another project", "another file of curl",
                              "a part ..", "a shell expansion", "a query", "a space"])
def test_a_rename_never_reads_the_old_name(tmp_path, old):
    # The old file sets the same contact, but the check never reads it. The base of curl is projects/curl/project.yaml,
    # which is not there, so the rename gives curl a first contact.
    files = [{"filename": "projects/curl/project.yaml", "previous_filename": old, "status": "renamed",
              "head": ADOPTED, "base": ADOPTED}]
    code, out, calls = branch(tmp_path, files=files, body="Moves curl into projects/.\n")
    assert sorted(tmp_path.glob("pwned-*")) == []
    assert code == 1, out
    assert NO_RECORD in out
    assert [call.split("/contents/")[1] for call in calls if "/contents/" in call] == [
        f"docs/seeded-projects.tsv?ref={BASE}", f"projects/curl/project.yaml?ref={HEAD}",
        f"projects/curl/project.yaml?ref={BASE}"]


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


@pytest.mark.parametrize("head", [API_ERROR, None], ids=["an API error", "no file at the head"])
def test_a_head_project_yaml_that_cannot_be_read_fails(tmp_path, head):
    # With the adopter's record, which would pass: the read alone fails the check.
    code, out, _ = branch(tmp_path, files=[{**adoption(), "head": head}], others=adopter())
    assert code == 1, out
    assert "::error::projects/curl/project.yaml of this pull request could not be read." in out
    assert NO_ADOPTION not in out
    assert "the adoption is recorded" not in out


# A graph of YAML aliases, 9 levels deep: it loads fast, with each list once, but its JSON is about 10 MB.
ALIASES = ("a: &a [x, x, x, x, x]\n"
           + "".join(f"{name}: &{name} [{', '.join(['*' + below] * 5)}]\n"
                     for below, name in zip("abcdefgh", "bcdefghi"))
           + "repo: https://github.com/curl/curl\nprimary_contact: *i\n")


@pytest.mark.parametrize("text", [
    "primary_contact: [security@curl.example\n",
    "primary_contact: 2026-11-18\n",
    "primary_contact: 2026-13-45\n",
    'primary_contact: !!python/object/apply:os.system ["touch pwned-a"]\n',
    "primary_contact: 5\n",
    "primary_contact: [security@curl.example]\n",
    "primary_contact: {address: security@curl.example}\n",
    "primary_contact:\n",
    "repo: https://github.com/curl/curl\n",
    "security@curl.example\n",
    ALIASES,
    ADOPTED + "#" * validate.MAX_CONFIG_BYTES,
], ids=["a flow sequence with no end", "a date", "a date that does not exist", "a tag that would run code",
        "a number", "a list", "a mapping", "null", "no primary_contact", "no mapping", "a graph of aliases",
        "larger than oss-verify validate reads"])
def test_a_head_contact_that_oss_verify_validate_refuses_fails(tmp_path, text):
    # The contact is unknown, and oss-verify validate refuses the file: the check fails, even with the adopter's
    # record, which would pass.
    start = time.monotonic()
    code, out, _ = branch(tmp_path, files=[{**adoption(), "head": text}], others=adopter())
    assert time.monotonic() - start < 30, "the step must not make JSON of what the text loads to"
    assert code == 1, out
    assert REFUSED in out
    assert NO_RECORD not in out
    assert "the adoption is recorded" not in out
    # yaml.safe_load makes no Python object of a tag: the text runs no code.
    assert sorted(tmp_path.rglob("pwned-*")) == []


@pytest.mark.parametrize("text", [
    "primary_contact: [security@curl.example\n",
    "primary_contact: 5\n",
    "repo: https://github.com/curl/curl\n",
    ADOPTED + "#" * validate.MAX_CONFIG_BYTES,
    ADOPTED + "auto_ccs: security@curl.example\n",
], ids=["a flow sequence with no end", "a number", "no primary_contact", "larger than oss-verify validate reads",
        "an auto_ccs that is not a list"])
def test_an_unknown_contact_at_the_base_differs_from_each_contact(tmp_path, text):
    # The addresses at the base are unknown, so each address at the head is new, even the same address: the branch
    # adopts curl.
    files = [{**adoption(), "base": text}]
    code, out, _ = branch(tmp_path, files=files, body="Carries a change of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out
    # A contact of n/a at the head adopts nothing, whatever the base has: the check does not read the base.
    (tmp_path / "n-a").mkdir()
    code, out, calls = branch(tmp_path / "n-a", files=[{**adoption(contact="n/a"), "base": text}],
                              body="Fixes the build of curl.\n")
    assert code == 0, out
    assert NO_ADOPTION in out
    assert not [call for call in calls if f"?ref={BASE}" in call and "contents/projects/" in call]


def test_a_base_project_yaml_that_cannot_be_read_fails(tmp_path):
    # With the adopter's record, which would pass: the read alone fails the check. Only a 404 says that the file is not
    # at the base.
    code, out, _ = branch(tmp_path, files=[{**adoption(), "base": API_ERROR}], others=adopter())
    assert code == 1, out
    assert "::error::projects/curl/project.yaml of the base branch could not be read." in out
    assert NO_ADOPTION not in out
    assert "the adoption is recorded" not in out


def test_a_runner_without_pyyaml_fails(tmp_path):
    code, out, calls = branch(tmp_path, others=adopter(), no_yaml=True)
    assert code == 1, out
    assert "::error::The runner image lacks PyYAML (python3-yaml)" in out
    assert "the adoption is recorded" not in out
    assert not [call for call in calls if "contents/projects/" in call]
    # Negative control: a branch that changes no project.yaml of a seeded project needs no PyYAML.
    (tmp_path / "build").mkdir()
    code, out, _ = branch(tmp_path / "build", files=["projects/curl/build.sh"], body=UNTICKED, no_yaml=True)
    assert code == 0, out
    assert NO_ADOPTION in out
    # Nor does a fork: its box, and the list of files of a pull request that is not an enrollment, need no YAML.
    (tmp_path / "ticked").mkdir()
    code, out, _ = terms(tmp_path / "ticked", ["projects/demo/project.yaml"], body=TICKED, no_yaml=True)
    assert code == 0, out
    assert "The OSS Verify terms are accepted in the description." in out
    (tmp_path / "docs").mkdir()
    code, out, _ = terms(tmp_path / "docs", ["README.md"], no_yaml=True)
    assert code == 0, out
    assert "Not an enrollment: this pull request changes no file under projects/" in out


def test_a_long_ticked_description_is_read_as_ticked(tmp_path):
    # As long as GitHub allows (65536 characters), the box first.
    code, out, calls = terms(tmp_path, ["projects/demo/project.yaml"], body=TICKED + "x\n" * 32_700)
    assert code == 0, out
    assert calls == []


def test_a_long_ticked_record_is_read_as_ticked(tmp_path):
    code, out, _ = branch(tmp_path, others=adopter(body=NAMES_CURL + "x\n" * 32_700))
    assert code == 0, out
    assert RECORDED in out


def test_the_description_reaches_the_step_only_as_data(tmp_path):
    hostile = '$(touch pwned-a) `touch pwned-b` "; touch pwned-c; " \' ; touch pwned-d #'
    code, out, _ = terms(tmp_path, ["projects/demo/project.yaml"], body=hostile)
    assert code == 1, out
    assert sorted(tmp_path.glob("pwned-*")) == []


def test_a_branch_reads_descriptions_texts_file_names_and_logins_only_as_data(tmp_path):
    hostile = '$(touch pwned-a) `touch pwned-b` "; touch pwned-c; " \' ; touch pwned-d #'
    contact = '$(touch pwned-e) `touch pwned-f` "; touch pwned-g; " \' ; touch pwned-h'
    files = [adoption(contact=contact), {"filename": "projects/$(touch pwned-i)/project.yaml", "status": "added",
                                         "head": "primary_contact: `touch pwned-j`\n"}]
    login = "$(touch pwned-k)`touch pwned-l`"
    code, out, _ = branch(tmp_path, files=files, body=f"{hostile}\nAdoption: #9\n",
                          others=adopter(body=f"{hostile}\n{NAMES_CURL}", author=login))
    assert sorted(tmp_path.glob("pwned-*")) == []
    # The contact is only compared, and the login is only printed.
    assert code == 0, out
    assert f"from a fork by {login}, accepts the OSS Verify terms" in out


def test_the_job_checks_out_the_merge_commit_into_merge_only_while_the_base_has_no_program():
    # The step's run: falls back to merge/, so the job checks the merge commit out there, and only then. hashFiles reads
    # the checkout at the top of the workspace, so the checkout into merge/ comes after the step with id: parent, which
    # checks out the first parent of the merge commit there.
    flow = read_workflow("terms.yaml")
    steps = flow["jobs"]["terms-accepted"]["steps"]
    checkouts = [n for n, step in enumerate(steps) if step.get("uses", "").startswith("actions/checkout@")]
    [merge] = [n for n in checkouts if steps[n].get("with", {}).get("path") == "merge"]
    [parent] = [n for n, step in enumerate(steps) if step.get("id") == "parent"]
    [program] = [n for n, step in enumerate(steps)
                 if step.get("name") == "The description accepts the OSS Verify terms"]
    assert checkouts[0] < parent < merge < program
    assert "if" not in steps[checkouts[0]]
    assert steps[merge]["uses"] == steps[checkouts[0]]["uses"]
    assert steps[merge]["if"] == "hashFiles('.github/scripts/terms-accepted') == ''"
    assert steps[merge]["with"] == {"path": "merge", "persist-credentials": False}
    assert "PYTHONPATH" not in steps[program]["env"]


def test_a_base_without_the_program_runs_the_merge_commits_copy(tmp_path):
    # The pull request that adds .github/scripts/terms-accepted, or one whose base is older than that. The base has
    # neither the program nor this src/, so only merge/'s copy, with merge/src, can decide as below.
    program = (ROOT / ".github" / "scripts" / "terms-accepted").read_text()
    code, out, _ = branch(tmp_path, body="Carries the adoption of curl.\n", base_program=False, merge_program=program)
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", others=adopter(), base_program=False, merge_program=program)
    assert code == 0, out
    assert RECORDED in out


def test_once_the_base_has_the_program_the_step_runs_the_bases_copy_not_the_merge_commits(tmp_path):
    # merge/ holds a changed copy that passes every pull request. The base's copy decides: a branch that adopts curl
    # with no record fails.
    code, out, _ = branch(tmp_path, body="Carries the adoption of curl.\n", merge_program=PASSES)
    assert code == 1, out
    assert NO_RECORD in out
    assert "the merge commit's copy of terms-accepted ran" not in out
    # Negative control: with no program in the base, merge/'s copy runs, and passes the same branch.
    (tmp_path / "older").mkdir()
    code, out, _ = branch(tmp_path / "older", body="Carries the adoption of curl.\n", base_program=False,
                          merge_program=PASSES)
    assert code == 0, out
    assert "the merge commit's copy of terms-accepted ran" in out
