# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for terms.yaml's check terms-accepted, its step run with a made-up gh:  uv run pytest

The check needs the box that accepts the OSS Verify terms in an enrollment's description, and no box for a pull request
that changes no file under projects/, which enrolls nothing. A branch of this repository that adopts a seeded project
names the adopter's pull request from their fork, which ticks the box: their record that they accept the terms. The
check reads primary_contact as oss-verify validate reads it, from the text of project.yaml with yaml.safe_load.
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
# The text of the seed port of curl, and of curl adopted with the contact that the adopter's pull request 9 sets.
SEED = "repo: https://github.com/curl/curl\nprimary_contact: n/a\n"
ADOPTED = "repo: https://github.com/curl/curl\nprimary_contact: security@curl.example\n"
# For the `head` or `base` of a file entry: the API gives an error other than a 404 for that text.
API_ERROR = object()

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="the check needs jq, as on GitHub's runners")

# gh api, answered by the path it is given from the files the test wrote: pull request <n> (pull.<n>.json, and
# pull.<n>.after.json for every read after the first, a push while the step reads), its files (files.<n>.json, with the
# step's --jq filter applied as gh applies it), docs/seeded-projects.tsv at the base (table.tsv), and the text of a file
# at a commit (contents/<commit>/<path>; errors/<commit>/<path> for an API error), each as text only for the raw media
# type, as the API gives it. A file that the test did not write is a 404. Each call is appended to `calls`. A file
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
    """The (head, base) texts of a file entry, None for no file. The entry's own `head` and `base` win. Else, from its
    patch: the context and added lines at the head, and the context and removed lines at the base. An added file has
    no base, a removed file no head, and an entry with no patch neither."""
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
          author="someone", changed=None, api_head=HEAD, after_head=None, fail=False, table=TABLE, others=None):
    """Run the check's step on pull request 7 from `head_repository` whose description is `body` and that changes
    `files` (each as `entry` takes it, with its texts as `texts` gives them; changed_files: `changed`, by default their
    number). The API gives `api_head` as its head, and `after_head` on every later read, docs/seeded-projects.tsv of the
    base as `table` (None: a 404), and each other pull request of `others`, {number: (pull request, files)}, with the
    head texts of its files at its head. Return (exit code, output, calls)."""
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
    for number, (other, other_files) in (others or {}).items():
        (stub / f"pull.{number}.json").write_text(json.dumps(other))
        (stub / f"files.{number}.json").write_text(json.dumps([entry(f) for f in other_files]))
        write_texts(stub, other_files, other["head"]["sha"])
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


def adopter(body=TICKED, head_repository="adopter/oss-verify", author="adopter", files=None, number=9, sha="d" * 40):
    """For `others`: pull request `number` from `head_repository` (None: a deleted fork), opened by `author`, whose
    description is `body` and whose head, commit `sha`, has the texts of `files`, by default the adoption of curl and
    its build.sh."""
    head = {"sha": sha, "repo": None if head_repository is None else {"full_name": head_repository}}
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
    assert (f"api -H Accept: application/vnd.github.raw repos/{REPOSITORY}/contents/docs/seeded-projects.tsv"
            f"?ref={BASE}") in calls
    # The record's project.yaml at its head, and not its list of files.
    assert (f"api -H Accept: application/vnd.github.raw repos/{REPOSITORY}/contents/projects/curl/project.yaml"
            f"?ref={'d' * 40}") in calls
    assert not [call for call in calls if "pulls/9/files" in call]


@pytest.mark.parametrize("ours, theirs", [
    ("security@curl.example", '"security@curl.example"  # the security team'),
    ("'security@curl.example'", "security@curl.example   "),
    ("security@curl.example # adopted", "  security@curl.example"),
], ids=["quotes and a comment", "single quotes and spaces after it", "a comment and spaces"])
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
    [{"filename": "projects/curl/project.yaml", "head": "notes:\n  primary_contact: security@curl.example\n"}],
    [{"filename": "projects/curl/project.yaml", "head": "primary_contact: [security@curl.example\n"}],
    ["projects/curl/build.sh"],
], ids=["another address", "another project", "n/a", "the contact only under another key", "a text that does not load",
        "no project.yaml"])
def test_a_record_that_sets_another_contact_or_none_fails(tmp_path, files):
    code, out, _ = branch(tmp_path, others=adopter(files=files))
    assert code == 1, out
    assert "::error::Pull request #9 sets another primary_contact for curl, or none." in out
    assert RECORDED not in out


@pytest.mark.parametrize("case", ["API error", "a head that is not a commit id"])
def test_a_record_whose_project_yaml_cannot_be_read_fails(tmp_path, case):
    # The texts of the record are at its head "main" too, but only a commit id goes into an API path.
    others = (adopter(files=[{**adoption(), "head": API_ERROR}]) if case == "API error" else adopter(sha="main"))
    code, out, calls = branch(tmp_path, others=others)
    assert code == 1, out
    assert "::error::projects/curl/project.yaml of pull request #9 could not be read." in out
    assert RECORDED not in out
    assert not [call for call in calls if "?ref=main" in call]


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
     {"filename": "projects/curl/project.yaml", "status": "modified", "base": SEED, "head": SEED + (
         "# primary_contact: security@curl.example\nnotes:\n  primary_contact: security@curl.example\n")}],
    [{"filename": "projects/curl/project.yaml", "previous_filename": "seeds/curl/project.yaml", "status": "renamed",
      "changes": 0, "head": SEED, "base": SEED}],
    [{"filename": "projects/curl/project.yaml", "status": "added",
      "patch": "@@ -0,0 +1,2 @@\n+repo: https://github.com/curl/curl\n+primary_contact: n/a\n"}],
], ids=["a build file", "project.yaml, primary_contact kept", "project.yaml, n/a set again", "project.yaml removed",
        "project.yaml removed, no patch",
        "a contact in a comment, under another key, or in another file than projects/<name>/project.yaml",
        "a seed port moved into projects/ with no change", "a seed port added to projects/ with n/a"])
def test_a_branch_that_changes_a_seeded_port_and_keeps_its_contact_needs_no_record(tmp_path, files):
    # A maintainer's own fix of a seeded port: the contact at the head is none, n/a, or the contact at the base.
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
def test_a_branch_that_sets_a_seeded_contact_in_another_yaml_spelling_is_an_adoption(tmp_path, key):
    # oss-verify validate reads project.yaml with yaml.safe_load, which reads each of these lines as primary_contact:
    # the branch adopts curl as surely as with primary_contact:, so with no record the step must not pass it.
    assert yaml.safe_load(f"{key} security@curl.example\n") == {"primary_contact": "security@curl.example"}
    files = [{"filename": "projects/curl/project.yaml", "status": "modified",
              "patch": f"@@ -4,1 +4,1 @@\n-primary_contact: n/a\n+{key} security@curl.example\n"}]
    code, out, _ = branch(tmp_path, files=files, body="Carries the adoption of curl.\n")
    assert code == 1, out
    assert NO_ADOPTION not in out


@pytest.mark.parametrize("patch", [
    "@@ -1,2 +1,1 @@\n-repo: https://github.com/curl/curl\n-primary_contact: n/a\n"
    "+{repo: https://github.com/curl/curl, primary_contact: security@curl.example}\n",
    "@@ -1,2 +1,3 @@\n repo: https://github.com/curl/curl\n-primary_contact: n/a\n"
    "+primary_contact: >-\n+  security@curl.example\n",
], ids=["a flow mapping", "a block scalar"])
def test_a_seeded_contact_in_another_yaml_form_is_an_adoption_that_a_plain_record_matches(tmp_path, patch):
    files = [{"filename": "projects/curl/project.yaml", "status": "modified", "patch": patch}]
    assert yaml.safe_load(texts(files[0])[0])["primary_contact"] == "security@curl.example"
    code, out, _ = branch(tmp_path, files=files, body="Carries the adoption of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    # The record compares contacts, not spellings: pull request 9 sets the same contact as "primary_contact: <value>".
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out


@pytest.mark.parametrize("patch, status", [
    ("@@ -2,1 +2,1 @@\n-primary_contact: old@curl.example\n+primary_contact: security@curl.example\n", "modified"),
    ("@@ -0,0 +1,2 @@\n+repo: https://github.com/curl/curl\n+primary_contact: security@curl.example\n", "added"),
], ids=["another address than the base's", "a new file"])
def test_a_branch_that_sets_a_contact_other_than_the_bases_adopts(tmp_path, patch, status):
    files = [{"filename": "projects/curl/project.yaml", "status": status, "patch": patch}]
    code, out, _ = branch(tmp_path, files=files, body="Carries the adoption of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter())
    assert code == 0, out
    assert RECORDED in out


def test_a_seed_port_moved_into_projects_compares_the_contact_with_its_old_file(tmp_path):
    rename = {"filename": "projects/curl/project.yaml", "previous_filename": "seeds/curl/project.yaml",
              "status": "renamed", "head": ADOPTED, "base": ADOPTED}
    code, out, calls = branch(tmp_path, files=[rename], body="Moves curl into projects/.\n")
    assert code == 0, out
    assert NO_ADOPTION in out
    assert (f"api -H Accept: application/vnd.github.raw repos/{REPOSITORY}/contents/seeds/curl/project.yaml"
            f"?ref={BASE}") in calls
    # Negative control: the old file says n/a, so the same rename sets a new contact.
    (tmp_path / "n-a").mkdir()
    code, out, _ = branch(tmp_path / "n-a", files=[{**rename, "base": SEED}], body="Moves curl into projects/.\n")
    assert code == 1, out
    assert NO_RECORD in out


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


@pytest.mark.parametrize("old", ["seeds/sqlpage/project.yaml", "projects/curl/project.yml",
                                 "seeds/../seeds/curl/project.yaml", "seeds/$(touch pwned-a)/project.yaml",
                                 "seeds/curl/project.yaml?ref=main", "seeds/curl project.yaml"],
                         ids=["the seed port of another project", "another file of curl", "a part ..",
                              "a shell expansion", "a query", "a space"])
def test_a_rename_from_another_file_than_the_seed_port_never_reads_that_file(tmp_path, old):
    # The old file sets the same contact, but only seeds/curl/project.yaml is read under its old name. The base of curl
    # is projects/curl/project.yaml, which is not there, so the rename gives curl a first contact.
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


@pytest.mark.parametrize("text", [
    "primary_contact: [security@curl.example\n",
    "primary_contact: 2026-11-18\n",
    'primary_contact: !!python/object/apply:os.system ["touch pwned-a"]\n',
], ids=["a flow sequence with no end", "a date, which has no JSON form", "a tag that would run code"])
def test_a_head_project_yaml_that_does_not_load_needs_a_record_that_cannot_match_it(tmp_path, text):
    # Its contact is unknown: the branch adopts curl, and no record matches it, not even one with the same text.
    files = [{**adoption(), "head": text}]
    code, out, _ = branch(tmp_path, files=files, body="Carries a change of curl.\n")
    assert code == 1, out
    assert NO_RECORD in out
    (tmp_path / "named").mkdir()
    code, out, _ = branch(tmp_path / "named", files=files, others=adopter(files=files))
    assert code == 1, out
    assert "::error::The primary_contact that projects/curl/project.yaml of this pull request sets is unknown" in out
    assert "the adoption is recorded" not in out
    # yaml.safe_load makes no Python object of a tag: the text runs no code.
    assert sorted(tmp_path.rglob("pwned-*")) == []


def test_a_base_project_yaml_that_cannot_be_read_fails(tmp_path):
    # With the adopter's record, which would pass: the read alone fails the check. Only a 404 says that the file is not
    # at the base.
    code, out, _ = branch(tmp_path, files=[{**adoption(), "base": API_ERROR}], others=adopter())
    assert code == 1, out
    assert "::error::projects/curl/project.yaml of the base branch could not be read." in out
    assert NO_ADOPTION not in out
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


def test_a_branch_reads_descriptions_texts_file_names_and_logins_only_as_data(tmp_path):
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
