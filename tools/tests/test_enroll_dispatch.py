# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/enroll-dispatch and the jobs around it, offline, with a fake GitHub API:
python3 -m pytest tools/tests/test_enroll_dispatch.py"""
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
LOADER = importlib.machinery.SourceFileLoader("enroll_dispatch", str(ROOT / ".github" / "scripts" / "enroll-dispatch"))
SPEC = importlib.util.spec_from_loader("enroll_dispatch", LOADER)
dispatch = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(dispatch)

REPO = "theorem-labs/oss-verify"
SHA = "7e8e28d95389c7261efeb48e4114cd1186bf8e7e"
OTHER = "0" * 40
PR = 32
ACTIONS = 15368
REQUIRED = ["enrollment", "project-builds", "terms-accepted", "tests"]
RUN = 40231238399


def zipped(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class FakeApi:
    """Answers from a table: get and raw by path, pages as a list of pages."""

    def __init__(self, table):
        self.table = table

    def get(self, path):
        return self.table[path]

    def pages(self, path):
        return self.table[path]

    def raw(self, path):
        return self.table[path]


def record(**change):
    out = {"schema": dispatch.RECORD_SCHEMA, "pr": PR, "project": "plugin-hostd", "sha": SHA,
           "text_bytes": {"fuzz_command": {"plain": 61_316, "ubsan": 63_860, "asan": 454_828, "asan-ubsan": 456_904},
                          "fuzz_config": {"plain": 58_316, "ubsan": 59_976, "asan": 2_447_656, "asan-ubsan": 448_852}}}
    out.update(change)
    return out


def table(files=None, checks=None, rec=None, artifacts=None, pulls=None, archive=None):
    files = [{"filename": "projects/plugin-hostd/project.yaml", "status": "added"},
             {"filename": "projects/plugin-hostd/build.sh", "status": "added"}] if files is None else files
    checks = {name: "success" for name in REQUIRED} if checks is None else checks
    runs = [{"id": 100 + i, "name": name, "app": {"id": ACTIONS}, "status": "completed", "conclusion": conclusion,
             "details_url": f"https://github.com/{REPO}/actions/runs/{RUN}/job/{500 + i}"}
            for i, (name, conclusion) in enumerate(checks.items())]
    pulls = [{"number": PR, "head": {"sha": SHA}}, {"number": 7, "head": {"sha": OTHER}}] if pulls is None else pulls
    artifacts = [{"id": 9, "name": dispatch.RECORD_ARTIFACT, "expired": False, "size_in_bytes": 300}] \
        if artifacts is None else artifacts
    rules = [{"type": "pull_request"},
             {"type": "required_status_checks", "parameters": {"required_status_checks": [
                 {"context": name, "integration_id": ACTIONS} for name in REQUIRED]}}]
    return FakeApi({
        f"repos/{REPO}/pulls?state=open&base=main&per_page=100": [pulls],
        f"repos/{REPO}/pulls/{PR}/files?per_page=100": [files],
        f"repos/{REPO}/rules/branches/main": rules,
        f"repos/{REPO}/commits/{SHA}/check-runs?filter=latest&per_page=100": [{"check_runs": runs}],
        f"repos/{REPO}/actions/runs/{RUN}/artifacts?name={dispatch.RECORD_ARTIFACT}&per_page=100":
            [{"artifacts": artifacts}],
        f"repos/{REPO}/actions/artifacts/9/zip":
            archive if archive is not None else zipped({"record.json": json.dumps(rec or record())}),
    })


def decide(api, event="pull_request_target", sha=SHA):
    return dispatch.decide(api, REPO, sha, event)


class SizeLine(unittest.TestCase):
    """The 1 MB line is on each plain binary's .text: at most 1,000,000 bytes passes, more or unknown goes to a person."""

    def text(self, plain):
        return record(text_bytes={"fuzz_command": {"plain": plain, "asan": 9_000_000},
                                  "fuzz_config": {"plain": 10, "asan": 20}})

    def test_every_plain_binary_at_most_the_line_is_dispatched(self):
        got = decide(table(rec=self.text(1_000_000)))
        self.assertEqual((got["decision"], got["pr"], got["project"], got["sha"]), ("dispatch", "32", "plugin-hostd", SHA))

    def test_a_plain_binary_one_byte_over_the_line_goes_to_size_review(self):
        got = decide(table(rec=self.text(1_000_001)))
        self.assertEqual((got["decision"], got["pr"], got["project"]), ("size-review", "32", "plugin-hostd"))
        self.assertIn("fuzz_command.plain (1,000,001 bytes of .text)", got["reason"])

    def test_a_plain_binary_whose_size_is_unknown_goes_to_size_review(self):
        got = decide(table(rec=self.text(None)))
        self.assertEqual(got["decision"], "size-review")
        self.assertIn(".text size unknown", got["reason"])

    def test_large_sanitizer_builds_do_not_count(self):
        self.assertEqual(decide(table())["decision"], "dispatch")


class WhatIsSent(unittest.TestCase):
    def test_only_a_pull_request_run_is_considered(self):
        for event in ("push", "workflow_dispatch", "schedule"):
            self.assertEqual(decide(table(), event=event)["decision"], "none", event)

    def test_a_check_not_passed_yet_sends_nothing(self):
        for conclusion in ("failure", "cancelled", None):
            checks = {name: "success" for name in REQUIRED}
            checks["terms-accepted"] = conclusion
            got = decide(table(checks=checks))
            self.assertEqual(got["decision"], "none", conclusion)
            self.assertIn("terms-accepted", got["reason"])

    def test_a_required_check_that_never_ran_sends_nothing(self):
        checks = {name: "success" for name in REQUIRED if name != "tests"}
        got = decide(table(checks=checks))
        self.assertEqual(got["decision"], "none")
        self.assertIn("tests (not run)", got["reason"])

    def test_a_check_of_another_app_with_the_same_name_does_not_count(self):
        api = table()
        runs = api.table[f"repos/{REPO}/commits/{SHA}/check-runs?filter=latest&per_page=100"][0]["check_runs"]
        for run in runs:
            if run["name"] == "tests":
                run["app"] = {"id": 1}
        self.assertEqual(decide(api)["decision"], "none")

    def test_no_open_pull_request_at_the_head_sends_nothing(self):
        self.assertEqual(decide(table(pulls=[{"number": 7, "head": {"sha": OTHER}}]))["decision"], "none")

    def test_a_file_outside_one_project_sends_nothing(self):
        for files in ([{"filename": "projects/plugin-hostd/build.sh", "status": "added"},
                       {"filename": "tools/check", "status": "modified"}],
                      [{"filename": "projects/plugin-hostd/build.sh", "status": "added"},
                       {"filename": "projects/libreac/build.sh", "status": "modified"}],
                      [{"filename": "projects/plugin-hostd/build.sh", "status": "renamed",
                        "previous_filename": ".github/workflows/build.yaml"}],
                      [{"filename": "projects/plugin-hostd", "status": "added"}]):
            self.assertEqual(decide(table(files=files))["decision"], "none", files)

    def test_removing_the_project_sends_nothing(self):
        files = [{"filename": "projects/plugin-hostd/build.sh", "status": "removed"}]
        self.assertEqual(decide(table(files=files))["decision"], "none")

    def test_a_record_of_another_head_project_or_pull_request_sends_nothing(self):
        for change in ({"sha": OTHER}, {"project": "libreac"}, {"pr": 31}, {"schema": "other"},
                       {"text_bytes": {}}, {"text_bytes": {"fuzz_command": {"asan": 1}}},
                       {"text_bytes": {"fuzz_command": {"plain": "1"}}}, {"text_bytes": {"fuzz_command": {"plain": -1}}},
                       {"text_bytes": {"fuzz_command": {"plain": True}}}):
            got = decide(table(rec=record(**change)))
            self.assertEqual(got["decision"], "none", change)

    def test_no_record_or_an_unreadable_one_sends_nothing(self):
        self.assertEqual(decide(table(artifacts=[]))["decision"], "none")
        self.assertEqual(decide(table(archive=b"not a zip"))["decision"], "none")
        self.assertEqual(decide(table(archive=zipped({"record.json": "{}", "x": ""})))["decision"], "none")
        big = [{"id": 9, "name": dispatch.RECORD_ARTIFACT, "expired": False, "size_in_bytes": 2 << 20}]
        self.assertEqual(decide(table(artifacts=big))["decision"], "none")

    def test_the_reason_is_one_line(self):
        files = [{"filename": "a\nb\n::error::x", "status": "added"}]
        got = decide(table(files=files))
        self.assertNotIn("\n", got["reason"])


class Jobs(unittest.TestCase):
    """Which jobs hold what: the lines of the workflows' headers, as tests."""

    def jobs(self, name):
        return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())["jobs"]

    def test_only_the_dispatch_job_reads_the_app_key(self):
        jobs = self.jobs("enroll-dispatch.yml")
        self.assertEqual({n for n, j in jobs.items() if (j.get("permissions") or {}).get("id-token") == "write"},
                         {"dispatch"})
        self.assertEqual({n: j.get("environment") for n, j in jobs.items() if "environment" in j},
                         {"dispatch": "comment"})
        steps = jobs["dispatch"]["steps"]
        checkouts = [s["with"] for s in steps if str(s.get("uses", "")).startswith("actions/checkout")]
        self.assertEqual(checkouts, [{"persist-credentials": False, "sparse-checkout": ".github/scripts"}])
        self.assertEqual([s["run"] for s in steps if "run" in s and ".github/scripts" in s["run"]],
                         [".github/scripts/app-token"])
        self.assertNotIn("write", (jobs["decide"].get("permissions") or {}).values())

    def test_the_workflow_names_no_other_theorem_labs_repository(self):
        # The event's target is named by its id alone, so that this public file and its log name no private
        # repository.
        text = (ROOT / ".github" / "workflows" / "enroll-dispatch.yml").read_text()
        named = set(re.findall(r"theorem-labs/([A-Za-z0-9._-]+)", text))
        self.assertLessEqual(named, {"oss-verify"}, named)
        self.assertIn('INTERNAL_ID: "1425069221"', text)

    def test_the_record_job_runs_no_code_of_the_pull_request_and_holds_nothing(self):
        job = self.jobs("build.yaml")["record"]
        self.assertEqual(job["permissions"], {})
        self.assertNotIn("environment", job)
        uses = [s["uses"].split("@")[0] for s in job["steps"] if "uses" in s]
        self.assertEqual(uses, ["actions/upload-artifact"])
        self.assertNotIn("secrets.", yaml.safe_dump(job))


class AppToken(unittest.TestCase):
    """.github/scripts/app-token, with a stand-in curl: the request it makes, and no secret in any argument."""

    def test_a_token_for_one_repository_by_id_with_one_permission(self):
        if not shutil.which("openssl") or not shutil.which("jq"):
            self.skipTest("openssl or jq is not installed")
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            key = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True, text=True).stdout
            bin = directory / "bin"
            bin.mkdir()
            (bin / "curl").write_text(
                "#!/bin/bash\n"
                f"printf '%s\\n' \"$@\" >> {directory}/curl-argv\n"
                f"for a in \"$@\"; do case $a in @/dev/fd/*|@/proc/*) cat \"${{a#@}}\" >> {directory}/curl-headers;; "
                "esac; done\n"
                "case \"${@: -1}\" in\n"
                f"  */installation) echo '{{\"id\": 174627013}}' ;;\n"
                f"  */access_tokens) cat > {directory}/body; echo '{{\"token\": \"ghs_stand-in\"}}' ;;\n"
                "esac\n")
            (bin / "curl").chmod(0o755)
            env = {"PATH": f"{bin}:{os.environ['PATH']}", "APP_KEY": key, "CLIENT_ID": "Iv23liAWPMahJZYsw3un",
                   "REPOSITORY_ID": "1425069221", "PERMISSION": "contents", "ACCESS": "write",
                   "GITHUB_OUTPUT": str(directory / "output"), "GITHUB_REPOSITORY": REPO}
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "app-token")], env=env, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual((directory / "output").read_text(), "token=ghs_stand-in\n")
            self.assertEqual(json.loads((directory / "body").read_text()),
                             {"repository_ids": [1425069221], "permissions": {"contents": "write"}})
            argv = (directory / "curl-argv").read_text()
            self.assertIn("https://api.github.com/app/installations/174627013/access_tokens", argv)
            self.assertNotIn("Bearer", argv)
            self.assertNotIn("PRIVATE KEY", argv)
            self.assertIn("Authorization: Bearer ey", (directory / "curl-headers").read_text())
            self.assertIn("::add-mask::ghs_stand-in", run.stdout)

    def test_a_repository_that_is_not_an_id_is_refused(self):
        env = {"PATH": os.environ["PATH"], "APP_KEY": "x", "CLIENT_ID": "x", "REPOSITORY_ID": "theorem-labs/x",
               "PERMISSION": "contents", "ACCESS": "write", "GITHUB_OUTPUT": os.devnull, "GITHUB_REPOSITORY": REPO}
        run = subprocess.run([str(ROOT / ".github" / "scripts" / "app-token")], env=env, capture_output=True)
        self.assertEqual(run.returncode, 2)


if __name__ == "__main__":
    unittest.main()
