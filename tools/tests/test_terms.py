# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for terms.yaml's check terms-accepted, its step run with a made-up gh:  python3 -m pytest tools/tests

The check needs the box that accepts the OSS Verify terms in an enrollment's description, and no box for a pull request
that changes no file under projects/, which enrolls nothing.
"""
import json
import os
import pathlib
import shutil
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEAD = "a" * 40
TICKED = "- [x] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).\n"
UNTICKED = "- [ ] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).\n"

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="the check needs jq, as on GitHub's runners")

# gh api, answered from the files the test wrote: the pull request (pull.json; pull.after.json for every read after
# the first, a push while the step reads), and its files, with the step's --jq filter applied as gh applies it. Each
# call is appended to `calls`. A file `fail` makes every call fail, as an API error.
STUB_GH = r"""#!/bin/bash
echo "$*" >> "$STUB/calls"
[ -e "$STUB/fail" ] && { echo "gh: Server Error (HTTP 502)" >&2; exit 1; }
filter=""; for a; do [ "$prev" = --jq ] && filter=$a; prev=$a; done
case " $*" in
  *"/files"*) jq -r "$filter" "$STUB/files.json" ;;
  *)
    pull=$STUB/pull.json
    if [ -e "$STUB/read" ] && [ -e "$STUB/pull.after.json" ]; then pull=$STUB/pull.after.json; fi
    : > "$STUB/read"
    if [ -n "$filter" ]; then jq -r "$filter" "$pull"; else cat "$pull"; fi ;;
esac
"""


def terms(tmp_path, files, body=UNTICKED, head_repository="someone/oss-verify", association="NONE",
          author="someone", changed=None, api_head=HEAD, after_head=None, fail=False):
    """Run the check's step on a pull request from `head_repository` whose description is `body` and that changes
    `files` (a path, or a (new, old) pair for a rename; changed_files: `changed`, by default their number). The API
    gives `api_head` as its head, and `after_head` on every later read. Return (exit code, output, calls)."""
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "gh").write_text(STUB_GH)
    (stub / "gh").chmod(0o755)

    def pull(head):
        return json.dumps({"head": {"sha": head}, "changed_files": len(files) if changed is None else changed})

    (stub / "pull.json").write_text(pull(api_head))
    if after_head:
        (stub / "pull.after.json").write_text(pull(after_head))
    (stub / "files.json").write_text(json.dumps(
        [{"filename": f} if isinstance(f, str) else {"filename": f[0], "previous_filename": f[1]} for f in files]))
    if fail:
        (stub / "fail").write_text("")
    (stub / "calls").write_text("")
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "terms.yaml").read_text())
    [step] = flow["jobs"]["terms-accepted"]["steps"]
    env = {**os.environ, "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}", "STUB": str(stub), "BODY": body,
           "AUTHOR": author, "ASSOCIATION": association, "HEAD_REPOSITORY": head_repository,
           "REPOSITORY": "theorem-labs/oss-verify", "GH_TOKEN": "x", "PR": "7", "HEAD_SHA": HEAD}
    # bash -e, as GitHub runs a step's run.
    run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True)
    return run.returncode, run.stdout + run.stderr, (stub / "calls").read_text().splitlines()


@pytest.mark.parametrize("files", [
    ["tools/check"],
    ["docs/build-contract.md", "tools/validate.py", "tools/tests/test_validate.py"],
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
    ["projects/demo/project.yaml", "tools/check"],
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
    code, out, _ = terms(tmp_path, ["tools/check"], **arguments)
    assert code == 1, out
    assert "Not an enrollment" not in out
    assert "::error::Tick 'I accept the OSS Verify terms' in the pull request description." in out


@pytest.mark.parametrize("arguments", [
    {"head_repository": "theorem-labs/oss-verify"},
    {"association": "MEMBER"},
    {"author": "dependabot[bot]"},
])
def test_a_branch_a_maintainer_or_a_bot_needs_no_box_and_no_api(tmp_path, arguments):
    code, out, calls = terms(tmp_path, ["projects/demo/project.yaml"], **arguments)
    assert code == 0, out
    assert calls == []


def test_a_long_ticked_description_is_read_as_ticked(tmp_path):
    # As long as GitHub allows (65536 characters), the box first: grep -q stops reading at the box, and the step sets
    # no pipefail, so printf's broken pipe never reads as an unticked box.
    code, out, calls = terms(tmp_path, ["projects/demo/project.yaml"], body=TICKED + "x\n" * 32_700)
    assert code == 0, out
    assert calls == []


def test_the_description_reaches_the_step_only_as_data(tmp_path):
    hostile = '$(touch pwned-a) `touch pwned-b` "; touch pwned-c; " \' ; touch pwned-d #'
    code, out, _ = terms(tmp_path, ["projects/demo/project.yaml"], body=hostile)
    assert code == 1, out
    assert sorted(tmp_path.glob("pwned-*")) == []
