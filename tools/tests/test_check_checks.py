# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check_checks.py, build.yaml's review steps and the review's helper scripts, that need no Docker:
python3 -m pytest tools/tests"""
import base64
import shlex
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_checks  # noqa: E402
import check_records  # noqa: E402
import validate  # noqa: E402
from workflow_expressions import as_text, evaluate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Shifts(unittest.TestCase):
    def test_a_patch_moves_the_lines_after_its_hunks(self):
        patch = (b"diff --git a/fuzz/f.c b/fuzz/f.c\n--- a/fuzz/f.c\n+++ b/fuzz/f.c\n"
                 b"@@ -10,3 +10,2 @@\n a\n-b\n c\n@@ -40 +39,3 @@\n-x\n+y\n+z\n+w\n")
        shifts = check_checks.hunk_shifts(patch, "/src/p")
        self.assertEqual(shifts, {"/src/p/fuzz/f.c": [(11, -1), (40, -1), (41, 1), (41, 1), (41, 1)]})

        def check(line):
            return check_records.Check(line, None, path="/src/p/fuzz/f.c")
        self.assertEqual(check_checks.moved(check(5), shifts), 5)
        self.assertEqual(check_checks.moved(check(20), shifts), 19)
        self.assertEqual(check_checks.moved(check(50), shifts), 51)
        # A check in the trailing context of a hunk moves too.
        near = check_checks.hunk_shifts(b"+++ b/fuzz/f.c\n@@ -10,7 +10,6 @@\n a\n b\n-c\n d\n e\n f\n g\n", "/src/p")
        self.assertEqual(check_checks.moved(check(15), near), 14)

    def test_two_files(self):
        patch = (b"--- a/fuzz/f.c\n+++ b/fuzz/f.c\n@@ -10,1 +10,1 @@\n-x\n+y\n"
                 b"--- a/src/lib.c\n+++ b/src/lib.c\n@@ -5 +5,2 @@\n-p\n+q\n+r\n")
        shifts = check_checks.hunk_shifts(patch, "/src/p")
        self.assertEqual(shifts["/src/p/fuzz/f.c"], [(10, -1), (11, 1)])
        self.assertEqual(check_checks.moved(check_records.Check(40, None, path="/src/p/fuzz/f.c"), shifts), 40)

    def test_record_patches_apply_on_the_last_lines(self):
        import subprocess, tempfile
        for ending in (b"\n", b""):
            data = b"a\nb\nc\nd\ne" + ending
            for line in range(1, 6):
                with tempfile.TemporaryDirectory() as directory:
                    directory = pathlib.Path(directory)
                    (directory / "f.c").write_bytes(data)
                    record = check_records.Record("f.c", line, "abcde"[line - 1], "X", "s")
                    changed, _ = check_records.mutate(data, record)
                    import difflib
                    diff = b"".join(difflib.diff_bytes(difflib.unified_diff, check_checks.diff_lines(data),
                                                       check_checks.diff_lines(changed), b"a/f.c", b"b/f.c"))
                    (directory / "p").write_bytes(b"diff --git a/f.c b/f.c\n" + diff)
                    subprocess.run(["git", "apply", "p"], cwd=directory, check=True, capture_output=True)
                    self.assertEqual((directory / "f.c").read_bytes(), changed, (line, ending))

    def test_record_patches_split_on_newlines_only(self):
        data = "int x;\n/* \u00c5 */\nif (a) abort();\n".encode()
        record = check_records.Record("fuzz/f.c", 3, "(a)", "(!a)", "s")
        changed, _ = check_records.mutate(data, record)
        import difflib
        before = [line + b"\n" for line in data.split(b"\n")]
        after = [line + b"\n" for line in changed.split(b"\n")]
        diff = b"".join(difflib.diff_bytes(difflib.unified_diff, before, after, b"a/f", b"b/f"))
        self.assertIn("\u00c5".encode(), diff)
        self.assertEqual(diff.count(b"\n-"), 1)


class Positions(unittest.TestCase):
    def test_the_reader_gives_columns_for_coverage(self):
        source = "int f(int a) {\n\tif (a > 4 &&\n\t    a < 9)\n\t\tabort();\n\treturn 0;\n}\n"
        (found,) = check_records.find_checks(source, "/src/x/f.c")
        self.assertEqual((found.path, found.line, found.column, found.guard_at), ("/src/x/f.c", 4, 3, (2, 2)))
        self.assertEqual(found.text, "if (a > 4 &&")


class Coverage(unittest.TestCase):
    def test_counts_add_up_across_targets(self):
        coverage = check_checks.Coverage()
        export = {"data": [{"files": [{"filename": "/src/f.c", "segments": [
            [1, 1, 5, True, True, False], [2, 3, 0, True, True, False], [2, 10, 5, True, False, False],
            [4, 1, 0, False, False, False]]}]}]}
        coverage.add(export)
        coverage.add(export)
        self.assertEqual(coverage.count("/src/f.c", 1, 7), 10)
        self.assertEqual(coverage.count("/src/f.c", 2, 3), 0)
        self.assertEqual(coverage.count("/src/f.c", 2, 12), 10)
        self.assertIsNone(coverage.count("/src/f.c", 5, 1))
        self.assertIsNone(coverage.count("/src/other.c", 1, 1))

    def test_fuzz_target_files(self):
        export = {"data": [{"functions": [{"name": "LLVMFuzzerTestOneInput", "filenames": ["/src/a/f.c", "/x.h"]},
                                          {"name": "helper", "filenames": ["/src/lib.c"]}]}]}
        self.assertEqual(check_checks.fuzz_target_files(export), {"/src/a/f.c"})


class Report(unittest.TestCase):
    def test_code_cannot_be_ended_by_its_text(self):
        self.assertEqual(check_checks.code("a`b"), "``a`b``")
        self.assertEqual(check_checks.code("x\x1b[31m"), "`x [31m`")
        self.assertEqual(check_checks.cell("a|b"), "`a\\|b`")
        self.assertTrue(check_checks.code("y" * 500, 10).endswith("…`"))

    def test_runs(self):
        self.assertTrue(check_checks.Run("t", "s", 2, "coverage").passed())
        self.assertTrue(check_checks.Run("t", "s", 134, "coverage").caught())
        # A run stopped at the time limit neither passes nor catches a breakage.
        self.assertFalse(check_checks.Run("t", "s", None, "coverage").passed())
        self.assertFalse(check_checks.Run("t", "s", None, "coverage").caught())
        self.assertIn("abort()", check_checks.describe(check_checks.Run("t", "s", 134, "asan")))

    def test_seeds_get_the_driver_header(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            with zipfile.ZipFile(directory / "demo_seed_corpus.zip", "w") as archive:
                archive.writestr("one", b"\x01")
                archive.writestr("two", b"\x02\x03")
            names = check_checks.write_seeds(directory, ["demo", "none"], directory / "inputs")
            self.assertEqual(names, {"demo": ["one", "two"]})
            self.assertEqual((directory / "inputs" / "demo" / "1").read_bytes(), b"\0" * 6 + b"\x02\x03")


class Mutants(unittest.TestCase):
    def test_validate(self):
        base = "repo: https://github.com/a/b\nprimary_contact: a@b.cd\nlanguage: c\n"
        for good in ("fuzz/sabotage", "mutants"):
            self.assertEqual(list(validate.check_types(validate.yaml.safe_load(base + f"mutants: {good}\n"))), [])
        for bad in ("../x", "/abs", "[a]"):
            problems = list(validate.check_types(validate.yaml.safe_load(base + f"mutants: {bad}\n")))
            self.assertTrue(problems, bad)


class WorkflowArguments(unittest.TestCase):
    """What build.yaml, triage.yaml and enroll-dispatch.yml do with the credentials they hold, as far as their text
    shows it: each named credential reaches a command through a pipe or a shell builtin and never as a process's
    argument, and only the jobs that run no code of the pull request can ask for a GitHub identity token. This reads
    the files; it does not run them, so it proves nothing about what a called script does with what it is given."""

    # The jobs of each workflow that read the App's key, in the GitHub Environment `comment`: build.yaml's hold job
    # sends held findings with the App's token.
    KEY_JOBS = {"build.yaml": ("comment", "hold"), "triage.yaml": ("comment",), "enroll-dispatch.yml": ("dispatch",)}

    def workflow(self, name):
        return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())

    def steps(self, workflow):
        return [step for job in self.workflow(workflow)["jobs"].values() for step in job["steps"] if "run" in step]

    def argument_problems(self, run, name):
        """Where `run` gives $name to a process as an argument, as far as this test can read: [] if nowhere.

        It removes the forms in which only the shell itself reads the value, each in the exact place it is safe, and
        refuses any use of the name that is left. Anything new must be added here on purpose."""
        variable = re.escape(f'"${name}"')
        blank = re.escape(f'"${{{name}//[[:space:]]/}}"')
        # Where a test or a printf statement starts a command: the builtin is read only there, never after a path
        # (/usr/bin/[) or a wrapper (env [), which would be a process with the value in its arguments.
        start = r"(?m)(^\s*|\bif\s+|\belif\s+|&&\s*|\|\|\s*|;\s*|\{\s*|\bthen\s+|\bdo\s+|!\s+)"
        rest = run
        for form in (
                # printf into a process substitution: curl reads a pipe, never the value.
                rf"<\((?:builtin )?printf '[^']*' {variable}\)",
                # The decoded key, assigned to a shell variable: the value goes through a pipe into base64.
                rf"(?m)^\s*\w+=\$\(builtin printf '[^']*' {variable} \| base64 -d\)\s*$",
                # A here-string into a `while read` loop, and a [[ ]] pattern, both the shell's own.
                rf"<<< {variable}", rf"== \*{variable}\*"):
            rest = re.sub(form, "", rest)
        for form in (rf"\[ -[zn] {variable} \]", rf"\[ -z {blank} \]",
                     rf"builtin printf '[^']*' {variable}(?=\s*(?:$|;|>>?|\||&&|\}}))"):
            rest = re.sub(start + form, r"\1", rest)
        problems = []
        if f"${name}" in rest:
            problems.append(f"${name} is an argument")
        # ${NAME…} in any other spelling is refused outright rather than matched: a step that starts using it must be
        # read again.
        if "${" + name in rest:
            problems.append("${" + name + "…} is not one of the forms this test reads")
        return problems

    def test_no_credential_is_an_argument(self):
        # The App's key and the base64 it is decoded from are shell variables of their step, so they are named here
        # by those names, beside the environment variables.
        for workflow, names in (("build.yaml", ("GCP_ACCESS_TOKEN", "key", "payload")),
                                ("triage.yaml", ("GCP_ACCESS_TOKEN", "key", "payload")),
                                ("enroll-dispatch.yml", ("GCP_ACCESS_TOKEN", "key", "payload"))):
            steps = self.steps(workflow)
            for name in names:
                used = 0
                for step in steps:
                    used += step["run"].count(f"${name}")
                    self.assertEqual(self.argument_problems(step["run"], name), [], f"{workflow} {step.get('name')}")
                self.assertGreater(used, 0, f"{workflow} {name}")

    def test_the_argument_forms_are_refused(self):
        for run in ('curl -H "$(builtin printf \'Authorization: Bearer %s\\n\' "$X")" https://x',
                    'curl -H "Authorization: Bearer ${X:-}" https://x', 'echo "$X"',
                    'curl -H "$(printf \'%s\' "$X")" https://x', 'f "$(builtin printf \'%s\' "$X")"',
                    'curl -H "$(builtin printf \'%s\' "$X" | cat)" https://x',
                    'curl -H "$(builtin printf \'%s\' "$X" | base64 -d)" https://x',
                    'if /usr/bin/[ -z "$X" ]; then :; fi', 'env [ -n "$X" ]',
                    'if /usr/bin/[ -z "${X//[[:space:]]/}" ]; then :; fi', 'echo *"$X"*',
                    'env builtin printf \'%s\' "$X"', 'k=$(builtin printf \'%s\' "$X" | base64 -d) other'):
            self.assertTrue(self.argument_problems(run, "X"), run)
        for run in ('curl -H @<(builtin printf \'Authorization: Bearer %s\\n\' "$X") https://x',
                    'builtin printf \'::add-mask::%s\\n\' "$X"', 'k=$(builtin printf \'%s\' "$X" | base64 -d)',
                    '{ echo a; builtin printf \'%s\\n\' "$X"; echo b; } >> out', 'if [ -n "$X" ]; then :; fi',
                    'done <<< "$X"', 'if [ -z "${X//[[:space:]]/}" ]; then', '[[ $s == *"$X"* ]]'):
            self.assertEqual(self.argument_problems(run, "X"), [], run)

    def test_only_the_jobs_that_run_no_pull_request_code_hold_an_identity_token(self):
        # A GitHub identity token names no job; the GitHub Environment a job declares is what holds each Google account
        # to its job, and these files must also keep id-token: write off every other job. project-builds builds the
        # pull request's code and triage's gather reads its text, so neither may ever ask for one. A job with no permissions of its own inherits the workflow's, so the effective
        # permission is what is read here: a workflow-level id-token: write would reach every job.
        for workflow, want in (("build.yaml", {"review", "comment", "hold"}), ("triage.yaml", {"comment"}),
                               ("enroll-dispatch.yml", {"dispatch"})):
            parsed = self.workflow(workflow)
            default = parsed.get("permissions") or {}
            got = set()
            for name, job in parsed["jobs"].items():
                permissions = job["permissions"] if "permissions" in job else default
                if (permissions or {}).get("id-token") == "write":
                    got.add(name)
            self.assertEqual(got, want, f"{workflow}: the jobs whose effective permissions hold id-token: write")

    def test_the_helpers_use_no_argv_form_for_the_github_token(self):
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        # env NAME=value puts the value in env's argument vector; -c http.extraheader= puts the header in git's.
        self.assertNotIn("env GITHUB_TOKEN=", gather)
        self.assertIn('GITHUB_TOKEN="${GH_TOKEN:-}" keep', gather)
        self.assertNotIn("-c http.extraheader=", take)
        self.assertIn("--config-env=http.extraheader=", take)

    def test_the_credential_steps_put_no_credential_in_any_argv(self):
        # The text test above reads the steps; this one runs them. Each step that holds a credential is run in its
        # own shell (bash -e, as the runner does) under strace, with stand-ins for curl and base64's input, and every
        # credential's value must be absent from every program's arguments.
        if not shutil.which("strace"):
            self.skipTest("strace is not installed (the tests workflow installs it)")
        gcp = "gcp-not-a-secret"
        key_lines = ["-----BEGIN RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4",
                     "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==", "-----END RSA PRIVATE KEY-----"]
        key = "\n".join(key_lines) + "\n"

        def steps(workflow, job, name):
            found = [s for s in self.workflow(workflow)["jobs"][job]["steps"] if s.get("name") == name]
            self.assertEqual(len(found), 1, f"{workflow} {job} {name}")
            return found[0]["run"]

        cases = [
            # Both steps upload through .github/scripts/held-bucket-put, which runs here too.
            ("build.yaml review held finding store", steps("build.yaml", "review", "Store the held finding for the hold job"),
             json.dumps({"generation": "1761500000000000"}),
             {"GCP_ACCESS_TOKEN": gcp, "RUN_ID": "7", "PR": "68", "NAME": "libreac", "HEAD_SHA": "1" * 40,
              "RUN_URL": "https://github.com/theorem-labs/oss-verify/actions/runs/7"}, [gcp]),
            ("build.yaml review issue draft store", steps("build.yaml", "review", "Store the issue draft for a person"),
             json.dumps({"generation": "1761500000000000"}),
             {"GCP_ACCESS_TOKEN": gcp, "REPO": "theorem-labs/oss-verify", "ISSUE": "45", "RUN_ID": "7",
              "RUN_ATTEMPT": "1", "RUN_URL": "https://github.com/theorem-labs/oss-verify/actions/runs/7"}, [gcp]),
            ("build.yaml hold listing", steps("build.yaml", "hold", "Look for stored held findings"),
             json.dumps({"items": [{"name": "held/7/" + "a" * 32}]}), {"GCP_ACCESS_TOKEN": gcp}, [gcp]),
            ("build.yaml hold repository", steps("build.yaml", "hold", "Where the held findings go"),
             json.dumps({"payload": {"data": base64.b64encode(b"private-repository").decode()}}),
             {"GCP_ACCESS_TOKEN": gcp}, [gcp]),
        ]
        for workflow, job in [(w, j) for w, js in self.KEY_JOBS.items() for j in js]:
            cases.append((f"{workflow} {job} key", steps(workflow, job, "Read the oss-verify App's key"),
                          json.dumps({"payload": {"data": base64.b64encode(key.encode()).decode()}}),
                          {"GCP_ACCESS_TOKEN": gcp}, [gcp, base64.b64encode(key.encode()).decode()] + key_lines[1:3]))
        for label, run, answer, environment, secrets in cases:
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                bin = directory / "bin"
                bin.mkdir()
                # curl answers on standard output, or into the file -o names.
                (bin / "curl").write_text("#!/bin/bash\nout=\"\"\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n"
                                          f"if [ -n \"$out\" ]; then printf '%s' {shlex.quote(answer)} > \"$out\"; "
                                          f"else printf '%s' {shlex.quote(answer)}; fi\n")
                (bin / "curl").chmod(0o755)
                (directory / "tmp").mkdir()
                (directory / "tmp" / "held-finding.md").write_text("<!-- held finding -->\ntitle: x\n")
                (directory / "tmp" / "issue-draft.md").write_text("The draft reply:\n\nSee docs/dsl.md.\n")
                # The steps run from the checkout's root, where .github/scripts is.
                (directory / ".github").symlink_to(ROOT / ".github")
                trace = directory / "trace"
                env = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "RUNNER_TEMP": str(directory / "tmp"),
                       "GITHUB_OUTPUT": str(directory / "output"), "GITHUB_ENV": str(directory / "env"),
                       "GITHUB_STEP_SUMMARY": str(directory / "summary"), **environment}
                result = subprocess.run(["strace", "-f", "-qq", "-s", "65536", "-e", "trace=execve", "-o", str(trace),
                                         "bash", "--noprofile", "--norc", "-e", "-c", run],
                                        cwd=directory, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f"{label}: {result.stderr}")
                text = trace.read_text()
                self.assertIn('"curl"', text, f"{label}: the stand-in curl was not started")
                for secret in secrets:
                    self.assertNotIn(secret, text, f"{label}: a credential is in a program's arguments")
                    self.assertNotIn(secret, result.stderr, f"{label}: a credential is on stderr")

    def test_the_helpers_production_definitions_keep_the_token_out_of_argv(self):
        # The production keep, the triage call and fetch_head, taken from the scripts and run under strace with a fake
        # python3 and git that record their arguments and environment: the token reaches the environment only.
        if not shutil.which("strace"):
            self.skipTest("strace is not installed (the tests workflow installs it)")
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        keep = re.search(r"^keep\(\) \{.*\}$", gather, re.M).group(0)
        call = re.search(r"^.*\bkeep triage-today\.md .*$", gather, re.M).group(0)
        fetch = re.search(r"^fetch_head\(\) \{\n.*?^\}$", take, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            (directory / "out").mkdir()
            for name in ("git", "python3"):
                (bin / name).write_text(f'#!/bin/bash\nprintf "%s\\n" "$@" >> {directory}/{name}-argv\n'
                                        f"env >> {directory}/{name}-env\n")
                (bin / name).chmod(0o755)
            secret = "ghs_" + "Q" * 36
            auth = base64.b64encode(f"x-access-token:{secret}".encode()).decode()
            script = "\n".join(["set -euo pipefail", f"out={directory}/out REPO=o/r PR=1 sha={'a' * 40} fetched=false",
                                keep, call, fetch, "fetch_head", "fetch_head"])
            run = subprocess.run(["strace", "-f", "-qq", "-s", "8192", "-e", "trace=execve", "-o",
                                  str(directory / "trace"), "bash", "-c", script], cwd=directory,
                                 env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": secret},
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            trace = (directory / "trace").read_text()
            self.assertIn("python3", trace)
            self.assertIn("--config-env=http.extraheader=", trace)
            for value in (secret, auth):
                self.assertNotIn(value, trace)
                self.assertNotIn(value, run.stdout + run.stderr)
            self.assertIn(f"GITHUB_TOKEN={secret}", (directory / "python3-env").read_text())
            self.assertIn(f"Authorization: Basic {auth}", (directory / "git-env").read_text())
            # fetch_head fetches once, however often it is called.
            self.assertEqual((directory / "git-argv").read_text().split("\n").count("fetch"), 1)
            # Nor in what keep gathered (python3-env and git-env are the fakes' deliberate captures of the environment).
            gathered = sorted((directory / "out").iterdir())
            self.assertTrue(gathered)
            for path in gathered:
                for value in (secret, auth):
                    self.assertNotIn(value, path.read_text(), path.name)

    APP_ACCOUNT = "ossv-app-comment@theorem-agent-infra.iam.gserviceaccount.com"

    def app_key_jobs_problems(self, jobs, key_jobs=("comment",)):
        """Why these jobs could let a job other than `key_jobs` read the App's key, or [] if they cannot.

        The account that reads the key can be acted as only by an oss-verify job whose identity token carries
        `environment: comment` (Theorem's infrastructure code). GitHub accepts an environment as a string,
        as an object with `name`, and through an expression, and compares names without regard to case. An expression
        can compute `comment` from text that does not contain it (format('com{0}', 'ment')), so another job's
        environment is refused if it holds an expression at all, or if its text names `comment` in any case; the
        review job's own, the plain name enroll-review, passes. The key jobs' must be the plain name `comment`, with
        nothing but `deployment: false` beside it."""
        problems = []
        for name, job in jobs.items():
            if name in key_jobs:
                if job.get("environment") not in ("comment", {"name": "comment", "deployment": False}):
                    problems.append(f"{name}: environment {job.get('environment')!r}, want the plain name 'comment'")
                if (job.get("env") or {}).get("GCP_SERVICE_ACCOUNT") != self.APP_ACCOUNT:
                    problems.append(f"{name}: does not sign in as {self.APP_ACCOUNT}")
            else:
                text = json.dumps(job.get("environment", ""))
                if "${{" in text:
                    problems.append(f"{name}: its environment ({job['environment']!r}) is an expression")
                if "comment" in text.lower():
                    problems.append(f"{name}: its environment ({job['environment']!r}) names comment; only "
                                    f"{', '.join(key_jobs)} may")
                if self.APP_ACCOUNT in json.dumps(job):
                    problems.append(f"{name}: names {self.APP_ACCOUNT}")
        return problems

    def test_only_the_key_jobs_can_read_the_app_key(self):
        for workflow, key_jobs in self.KEY_JOBS.items():
            jobs = self.workflow(workflow)["jobs"]
            for key_job in key_jobs:
                self.assertIn(key_job, jobs, workflow)
            self.assertEqual(self.app_key_jobs_problems(jobs, key_jobs), [], workflow)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("base64"), "the key step needs jq and base64")
    def test_the_app_key_is_masked_in_every_key_job(self):
        # The key-reading step is in each of these files, and the runner logs the private-key input of the next step:
        # these masks are what keep a key that does not expire out of a public log. Each copy is run with a stand-in
        # curl for Secret Manager, and every non-blank line of the key, and its base64 form, must be masked.
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" \
              "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----\n"
        payload = base64.b64encode(key.encode()).decode()
        for workflow, key_job in [(w, j) for w, js in self.KEY_JOBS.items() for j in js]:
            steps = [s for s in self.workflow(workflow)["jobs"][key_job]["steps"]
                     if s.get("name") == "Read the oss-verify App's key"]
            self.assertEqual(len(steps), 1, workflow)
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                bin = directory / "bin"
                bin.mkdir()
                (bin / "curl").write_text("#!/bin/bash\nprintf '%s' "
                                          + shlex.quote(json.dumps({"payload": {"data": payload}})) + "\n")
                (bin / "curl").chmod(0o755)
                run = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", steps[0]["run"]], cwd=directory,
                                     env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}",
                                          "GCP_ACCESS_TOKEN": "gcp-not-a-secret",
                                          "GITHUB_OUTPUT": str(directory / "output")},
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, f"{workflow}: {run.stderr}")
                masked = {line[len("::add-mask::"):] for line in run.stdout.splitlines()
                          if line.startswith("::add-mask::")}
                for line in [payload] + [line for line in key.splitlines() if line.strip()]:
                    self.assertIn(line, masked, f"{workflow}: {line[:20]}… is not masked")
                # Every line of the key, and the payload, appears only inside its own mask line.
                for line in [payload] + [line for line in key.splitlines() if line.strip()]:
                    outside = [o for o in run.stdout.splitlines() if line in o and o != f"::add-mask::{line}"]
                    self.assertEqual(outside, [], f"{workflow}: {line[:20]}… is printed outside its mask")
                    self.assertNotIn(line, run.stderr, f"{workflow}: {line[:20]}… is on stderr")
                self.assertIn(key.splitlines()[1], (directory / "output").read_text(), workflow)

    def test_another_job_in_the_comment_environment_is_refused_in_every_shape(self):
        # The shapes GitHub takes for `environment` (workflow syntax, jobs.<job_id>.environment), each put on the
        # review job of the real build.yaml: every one must be refused.
        for shape in ("comment", {"name": "comment"}, {"name": "comment", "url": "https://example.invalid"},
                      "${{ 'comment' }}", {"name": "${{ 'comment' }}"}, "Comment",
                      {"name": "${{ github.ref == 'x' && 'enroll-review' || 'COMMENT' }}", "deployment": False},
                      "${{ format('com{0}', 'ment') }}", {"name": "${{ format('com{0}', 'ment') }}"}):
            jobs = self.workflow("build.yaml")["jobs"]
            jobs["review"]["environment"] = shape
            self.assertTrue(self.app_key_jobs_problems(jobs, self.KEY_JOBS["build.yaml"]),
                            f"review with environment {shape!r} was not refused")
        for shape in ({"name": "comment"}, "${{ 'comment' }}", {"name": "comment", "url": "https://example.invalid"}):
            jobs = self.workflow("build.yaml")["jobs"]
            jobs["comment"]["environment"] = shape
            self.assertTrue(self.app_key_jobs_problems(jobs, self.KEY_JOBS["build.yaml"]),
                            f"comment with environment {shape!r} was not refused")


class PostingStep(unittest.TestCase):
    """build.yaml's own "Post the comment" step, run with a fake gh: what it sends GitHub. Its BODY is the review job's
    body.md, made here by .github/scripts/review-body from the review, the checks' report and the rules file, as the
    review job makes it, unless `text` gives it."""

    def post(self, review, existing=True, head="b" * 40, pr_head=None, checks="### new report\n", rules="review.md",
             pr="8", status=0, verdicts="", text=None):
        if text is None:
            # As the job output gives it: without the file's last line end.
            text = body(verdicts, head, review=review, checks=checks, rules=rules).removesuffix("\n")
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        name = "Post the comment, or update the one already there"
        matches = [s for s in workflow["jobs"]["comment"]["steps"] if s.get("name") == name]
        # Exactly one, so this cannot run a same-name copy instead of the step the job really uses.
        self.assertEqual(len(matches), 1, f"{len(matches)} steps named {name!r}")
        step = matches[0]
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            # Like the real gh: the pull request's head is pr_head, and the comment already there has id 4242.
            (bin / "gh").write_text(
                "#!/bin/bash\n"
                f'case "$*" in\n'
                f'  *"pulls/8 "*) echo {pr_head or head} ;;\n'
                f'  *"--method PATCH"*) echo "$*" > {directory}/patch.url; cat > {directory}/patch.json ;;\n'
                f'  *"--method POST"*) cat > {directory}/post.json ;;\n'
                f'  *"--paginate"*) {"echo 4242; echo 4343" if existing else "true"} ;;\n'
                '  *) echo "unexpected gh $*" >&2; exit 1 ;;\n'
                "esac\n")
            (bin / "gh").chmod(0o755)
            (directory / "temp").mkdir()
            environment = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                           "PR": pr, "BODY": text, "HEAD_SHA": head, "RUNNER_TEMP": str(directory / "temp")}
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=ROOT, env=environment, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, status, run.stderr)
            sent = [name for name in ("patch.json", "post.json") if (directory / name).exists()]
            self.assertLessEqual(len(sent), 1, sent)
            if sent:
                self.assertEqual(sent[0], "patch.json" if existing else "post.json")
            if existing and sent:
                self.assertIn("issues/comments/4242", (directory / "patch.url").read_text())
            return json.loads((directory / sent[0]).read_text())["body"] if sent else None

    def test_a_run_with_no_pull_request_posts_nothing(self):
        # An issue's run has no pull request: the step refuses, before any read or write, whatever the job's if: says.
        for pr in ("", "8; x"):
            with self.subTest(pr=pr):
                self.assertIsNone(self.post("The draft reply.\n", pr=pr, status=1))

    def test_the_triage_step_posts_or_updates_its_comment(self):
        # triage.yaml's own posting step, run with a fake gh: with no comment of ours it posts one; with one, it edits it.
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "triage.yaml").read_text())
        name = "Post the comment, or update the one already there"
        matches = [s for s in workflow["jobs"]["comment"]["steps"] if s.get("name") == name]
        self.assertEqual(len(matches), 1)
        for existing, sent in (("", "post.json"), ("4242", "patch.json")):
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                (directory / "bin").mkdir()
                (directory / "bin" / "gh").write_text(
                    f'#!/bin/bash\necho "$*" >> {directory}/calls\n'
                    f'case "$*" in *"--paginate"*) echo "{existing}" ;;\n'
                    f'  *"--method POST"*) cat > {directory}/post.json ;;\n'
                    f'  *"--method PATCH"*) cat > {directory}/patch.json ;; esac\n')
                (directory / "bin" / "gh").chmod(0o755)
                environment = {**os.environ, "PATH": f"{directory / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x",
                               "REPO": "o/r", "PR": "8", "COMMENT": "<!-- oss-verify-triage -->\n### Triage\n"}
                run = subprocess.run(["bash", "-e", "-c", matches[0]["run"]], env=environment, capture_output=True,
                                     text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(sorted(p.name for p in directory.glob("*.json")), [sent], existing)
                self.assertEqual(json.loads((directory / sent).read_text())["body"],
                                 "<!-- oss-verify-triage -->\n### Triage\n")

    def test_a_review_replaces_the_posted_one(self):
        body = self.post("Thanks again.\n\n2. Fix Y.\n")
        self.assertTrue(body.startswith("<!-- oss-verify-review -->\n<sub>Claude wrote this review of `bbbbbbb`"))
        self.assertIn("\n\nThanks again.\n\n2. Fix Y.\n", body)
        self.assertIn("<summary>What the checks of the fuzz targets and of the binaries measured</summary>\n\n### new report", body)

    def test_a_change_review_names_review_change_md(self):
        body = self.post("Thanks.\n", checks="", rules="review-change.md")
        self.assertTrue(body.startswith("<!-- oss-verify-review -->\n<sub>Claude wrote this review of `bbbbbbb` from "
                                        "`review-change.md`."))

    def test_without_a_posted_comment_it_posts_one(self):
        body = self.post("Thanks.\n", existing=False, checks="")
        self.assertTrue(body.startswith("<!-- oss-verify-review -->\n"))
        self.assertNotIn("<details>", body)

    def test_a_run_of_an_older_head_posts_nothing(self):
        # The pull request moved on while this run worked: its newer head's run posts, and this one does not replace
        # that review.
        self.assertIsNone(self.post("Thanks again.\n", pr_head="c" * 40))
        self.assertIsNone(self.post("Thanks again.\n", existing=False, pr_head="c" * 40))

    def test_the_comment_stays_under_githubs_limit(self):
        body = self.post("R" * 70_000, checks="C" * 20_000)
        self.assertLess(len(body), 65_536)
        self.assertIn("R" * 50_000, body)

    def test_the_draft_body_md_is_what_the_comment_job_posts(self):
        # The review job's step writes body.md with .github/scripts/review-body, and its job output `body`; the comment
        # job's post step, given that output, posts body.md as it is. Both steps are run here. Which values the job
        # gives the first step is the workflow's, proved on a run.
        jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]
        [write] = [s for s in jobs["review"]["steps"]
                   if s.get("name") == "Write the comment as the comment job posts it"]
        review = "Thanks.\n\n1. Fix X.\n"
        with tempfile.TemporaryDirectory() as directory:
            temp = pathlib.Path(directory)
            (temp / "draft").mkdir()
            # As the result step writes it (jq .verdicts): over several lines.
            (temp / "draft" / "verdicts.json").write_text(
                json.dumps({"F2": "fail", "F7": "pass", "C4": "person"}, indent=2) + "\n")
            run = subprocess.run(["bash", "-e", "-c", write["run"]], cwd=ROOT, capture_output=True, text=True,
                                 env={**os.environ, "RUNNER_TEMP": str(temp), "GITHUB_OUTPUT": str(temp / "output"),
                                      "HEAD_SHA": "b" * 40, "REVIEW": review, "CHECKS": "### new report\n",
                                      "RULES": "review.md"})
            self.assertEqual(run.returncode, 0, run.stderr)
            output = (temp / "output").read_text()
            draft = (temp / "draft" / "body.md").read_text()
        # GITHUB_OUTPUT's form for a value of several lines: body<<delimiter, the lines, the delimiter.
        first, rest = output.split("\n", 1)
        self.assertRegex(first, r"\Abody<<body_[0-9a-f]{32}\Z")
        delimiter = first.split("<<", 1)[1]
        self.assertTrue(rest.endswith(f"\n{delimiter}\n"))
        self.assertEqual(self.post(review, text=rest[:-len(delimiter) - 2]), draft)
        self.assertEqual(draft.split("\n")[1],
                         '<!-- oss-verify-verdict {"head":"%s","blocking":["F2"],"person":["C4"]} -->' % ("b" * 40))


HEAD40 = "0123456789abcdef0123456789abcdef01234567"


def body(verdicts, head, review="Thanks.\n", checks="", rules="review.md"):
    """The comment that .github/scripts/review-body prints from this environment, as both of build.yaml's jobs run it."""
    run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-body")], capture_output=True, text=True,
                         env={**os.environ, "HEAD_SHA": head, "REVIEW": review, "CHECKS": checks,
                              "VERDICTS": verdicts, "RULES": rules})
    assert run.returncode == 0, run.stderr
    return run.stdout


class VerdictLine(unittest.TestCase):
    """Line 2 of the review comment: the checks whose verdict is fail, and those left to a person, at the reviewed
    commit, for the inbound watcher (the stream's bin/ossv-pr-watch, verdict_line)."""

    def test_the_comment_has_the_verdict_line_second(self):
        lines = body(verdicts='{"A1":"pass","F2":"fail","C4":"person","F7":"pass"}', head=HEAD40).split("\n")
        self.assertEqual(lines[0], "<!-- oss-verify-review -->")
        self.assertEqual(lines[1], '<!-- oss-verify-verdict {"head":"%s","blocking":["F2"],"person":["C4"]} -->' % HEAD40)

    def test_no_verdicts_writes_no_verdict_line(self):
        for v in ("", "null", "{}", "[]"):
            self.assertNotIn("oss-verify-verdict", body(verdicts=v, head=HEAD40))

    def test_a_long_review_keeps_the_verdict_line_second(self):
        self.assertTrue(body(verdicts='{"F2":"pass","F7":"pass"}', head=HEAD40, review="x" * 60000)
                        .split("\n")[1].startswith("<!-- oss-verify-verdict "))

    def test_a_change_review_uses_its_own_ids(self):
        self.assertIn('"blocking":["2"],"person":["5"]',
                      body(verdicts='{"1":"pass","2":"fail","5":"person"}', head=HEAD40).split("\n")[1])

    def test_the_rest_of_the_body_is_unchanged(self):
        b = body(verdicts='{"F2":"pass","F7":"pass"}', head=HEAD40, review="r" * 50001, checks="c", rules="review.md")
        lines = b.split("\n")
        self.assertEqual(lines[2], "<sub>Claude wrote this review of `%s` from `review.md`. It can be wrong. "
                                   "Each push replaces it.</sub>" % HEAD40[:7])
        self.assertIn("r" * 50000 + "\n", b)
        self.assertNotIn("r" * 50001, b)
        self.assertIn("<details><summary>What the checks of the fuzz targets and of the binaries measured</summary>", b)


@unittest.skipUnless(shutil.which("jq"), "needs jq, which the gh stand-in runs the script's filters with")
class ReviewHeld(unittest.TestCase):
    """review-held opens one private issue for each held finding, keyed by what the finding is, through a fake gh,
    and prints none of it."""

    RUN = "https://github.com/theorem-labs/oss-verify/actions/runs/7"
    OBJECT = "held/7/" + "a" * 32
    HEADER = f"oss-verify held finding v1\npr: 68\nhead: {'1' * 40}\nproject: libreac\nrun: {RUN}\n---\n"

    @staticmethod
    def body(key, texthash="0" * 12):
        """An issue body as review-held writes it: its key on the fifth line, its text's hash on the sixth."""
        return (f"enrollment PR: x\nenrollment PR head: y\npublic PR comment: z\nreview run: r\n"
                f"held finding key: {key}\nheld finding text: {texthash}\n")

    @staticmethod
    def key_of(body):
        """The key of an issue body this script wrote."""
        return body.split("\n")[4].removeprefix("held finding key: ")

    # A stand-in for `gh api`: it answers each call with the JSON GitHub would (from state.json), applies the script's
    # own --jq filter to it with the real jq, and records each call and each body it is sent. So the tests check the
    # script's filters, not a copy of them.
    GH = r'''#!@@PYTHON@@
import json, os, pathlib, subprocess, sys
root = pathlib.Path(@@ROOT@@)
state = json.loads((root / "state.json").read_text())
a = sys.argv[2:]
with open(root / "calls", "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
with open(root / "tokens", "a") as f:
    f.write(os.environ.get("GH_TOKEN", "") + "\n")
path = next(x for x in a if x.startswith("repos/"))
fields = [x for i, x in enumerate(a) if i and a[i - 1] in ("-f", "-F")]
# The body as GitHub would store it: bytes that are not UTF-8 become U+FFFD.
body = next((open(x[6:], "rb").read().decode("utf-8", "replace") for x in fields if x.startswith("body=@")), None)
if body is not None:
    with open(root / "bodies", "a") as f:
        f.write(body + "\0")
repo = path.split("/")[1] + "/" + path.split("/")[2]
private = repo == state["variable"]
if path.endswith("/labels/held-finding"):
    sys.exit(0 if state["label"] else 1)
if path == "repos/" + state["variable"]:
    answer = {"visibility": state["visibility"]}
elif "/issues?" in path:
    if state["listing_fails"]:
        # gh writes the request it failed on, which holds the private repository's name.
        sys.stderr.write("gh: HTTP 500 on " + path + "\n")
        sys.exit(1)
    answer = [{"number": i, "body": b[0], "state": b[1], "title": b[2]} for i, b in enumerate(state["issues"], 1)]
    # As GitHub answers it: open issues only, unless the query asks for every state.
    if "state=all" not in path:
        answer = [i for i in answer if i["state"] == "open"]
    if "labels=held-finding" not in path:
        answer = []
elif path.endswith("/comments") and not fields:
    if state["comments_fail"] and private:
        sys.stderr.write("gh: the stand-in refuses the comments\n")
        sys.exit(1)
    answer = state["comments"] if private else state["public_comments"]
elif path.endswith("/comments"):
    answer = {"id": 7, "html_url": "https://example.test/comment"}
elif path.endswith("/issues"):
    answer = {"number": 42, "html_url": "https://example.test/issue"}
else:
    answer = {}
if "--jq" in a:
    out = subprocess.run(["jq", "-r", a[a.index("--jq") + 1]], input=json.dumps(answer), capture_output=True, text=True,
                         check=True).stdout
    sys.stdout.write(out)
else:
    print(json.dumps(answer))
'''
    # A held finding as the review writes it in the `held` field of its structured output.
    HELD = ("<!-- held finding -->\ntitle: [held] libreac/fuzz: heap-buffer-overflow in parse_SECRETBUG\n"
            "project: libreac\nharness: fuzz_one\nupstream repository: https://github.com/example/libreac\n"
            "upstream commit: " + "c" * 40 + "\nwhy held: memory safety: a read past the end\n\n"
            "src/parse.c:40-80, parse_SECRETBUG reads past the end.\n")

    @staticmethod
    def an_issue(given):
        """One issue of the label as GitHub gives it: a body, or a (body, state) or (body, state, title) tuple."""
        given = [given] if isinstance(given, str) else list(given)
        return [given[0], given[1] if len(given) > 1 else "open", given[2] if len(given) > 2 else ""]

    def run_held(self, held, bodies_on_github=(), label=True, variable="theorem-labs/private", visibility="private",
                 header=None, comments=(), public_comments=(), obj=None, listing_fails=False, comments_fail=False):
        """bodies_on_github: the issues of the label already there, each a body, a (body, state) pair or a
        (body, state, title) triple, numbered from 1. comments: the bodies of comments already on a private issue.
        public_comments: the pull request's comments, as (login, body, html_url). held follows the six lines the
        review job writes (header, by default HEADER).
        obj: the stored object's name, which is a new one for every run of a review."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "review").mkdir()
            (root / "review" / "object").write_text((self.HEADER if header is None else header) + held)
            (root / "state.json").write_text(json.dumps({
                "variable": variable, "visibility": visibility, "label": label,
                "issues": [self.an_issue(b) for b in bodies_on_github],
                "listing_fails": listing_fails, "comments_fail": comments_fail,
                "comments": [{"id": i, "body": c} for i, c in enumerate(comments)],
                "public_comments": [{"user": {"login": login}, "body": b, "html_url": u}
                                    for login, b, u in public_comments]}))
            gh = root / "bin" / "gh"
            gh.write_text(self.GH.replace("@@PYTHON@@", sys.executable).replace("@@ROOT@@", repr(str(root))))
            gh.chmod(0o755)
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-held"), str(root / "review")],
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "HELD_FINDINGS_REPO": variable, "REPO": "theorem-labs/oss-verify",
                                      "GH_TOKEN": "app-not-a-secret", "READ_TOKEN": "read-not-a-secret",
                                      "GITHUB_STEP_SUMMARY": str(root / "summary"),
                                      "HELD_OBJECT": obj or self.OBJECT},
                                 capture_output=True, text=True)
            # The token of each call, in the order of calls.
            run.tokens = (root / "tokens").read_text().splitlines() if (root / "tokens").exists() else []
            run.summary = (root / "summary").read_text() if (root / "summary").exists() else ""
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] \
                if (root / "calls").exists() else []
            bodies = (root / "bodies").read_text().split("\0")[:-1] if (root / "bodies").exists() else []
            return run, calls, bodies

    @staticmethod
    def opened(calls):
        """The issues opened in this run."""
        return [c for c in calls if c[1] == "repos/theorem-labs/private/issues"]

    def test_each_finding_is_one_labelled_issue_with_the_pull_request_and_nothing_is_printed(self):
        two = self.HELD + self.HELD.replace("parse_SECRETBUG", "other_SECRETBUG")
        run, calls, bodies = self.run_held(two, label=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("SECRETBUG", run.stdout + run.stderr + run.summary)
        self.assertIn(["api", "repos/theorem-labs/private/labels", "-f", "name=held-finding", "-f", "color=b60205",
                       "-f", "description=A finding held back from a public review, for the disclosure route"], calls)
        created = self.opened(calls)
        self.assertEqual([c[c.index("-f") + 1] for c in created],
                         ["title=[held] libreac/fuzz: heap-buffer-overflow in parse_SECRETBUG",
                          "title=[held] libreac/fuzz: heap-buffer-overflow in other_SECRETBUG"])
        self.assertTrue(all("labels[]=held-finding" in c for c in created))
        self.assertEqual(len(bodies), 2)
        self.assertTrue(bodies[0].startswith(f"enrollment PR: theorem-labs/oss-verify#68\nenrollment PR head: {'1' * 40}\n"
                                             "public PR comment: not posted yet: the review comment on "
                                             "theorem-labs/oss-verify#68\n"
                                             f"review run: {self.RUN}\nheld finding key: review/libreac/fuzz_one/"))
        self.assertNotEqual(self.key_of(bodies[0]), self.key_of(bodies[1]))
        self.assertRegex(bodies[0].split("\n")[5], r"^held finding text: [0-9a-f]{12}$")
        self.assertNotIn("theorem-labs/private", run.stdout + run.stderr + run.summary)
        self.assertIn("project: libreac\n", bodies[0])
        self.assertNotIn("title:", bodies[0])
        self.assertEqual(run.summary, "2 findings of libreac: 2 sent for private review, 0 already filed, 0 with a"
                                      " text added to the issue that holds it, 0 whose issue is closed.\n")
        # Nothing of any one finding is in the log or the summary, and that includes its key: every input of the
        # identity is public, so a reader who can hash a million candidates reads the file and the function out of
        # it (the CI/CD lead's reviewer did, in 1.5 s, from the public upstream tree).
        for key in (self.key_of(bodies[0]), self.key_of(bodies[1])):
            self.assertNotIn(key, run.stdout + run.stderr + run.summary)
            self.assertNotIn(key.rsplit("/", 1)[1], run.stdout + run.stderr + run.summary)

    def test_the_key_holds_nothing_of_the_run_that_found_the_finding(self):
        # The defect of oss-verify-proofs-internal#450: the key was the stored object's name, so each re-run of a
        # review filed the same finding again.
        run, _, bodies = self.run_held(self.HELD)
        self.assertEqual(run.returncode, 0, run.stderr)
        key = self.key_of(bodies[0])
        self.assertNotIn("a" * 32, key)
        self.assertNotIn(self.OBJECT, bodies[0])
        self.assertRegex(key, r"^review/libreac/fuzz_one/c{12}/[0-9a-f]{12}$")
        # `review/`, so that the statement work's reader, which takes an issue whose key starts `enroll/` as its
        # own and reads its sixth line as the project, never takes one of these (ossv-held-bridge, STATEMENT_KEY).

    def test_a_field_a_review_answers_in_a_sentence_stays_out_of_the_key(self):
        # A review answered `harness:` with a sentence (oss-verify-proofs-internal#372, closed). A sentence is
        # written afresh each run, so only a value that is one name is in the key, and a sentence is no harness.
        prose = ("harness: none: no enrolled fuzz target reaches it. The file is not built (CMakeLists.txt, the "
                 "option defaults to OFF), and the project's build.sh links the library only")
        held = self.HELD.replace("harness: fuzz_one", prose)
        run, _, bodies = self.run_held(held)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertRegex(self.key_of(bodies[0]), r"^review/libreac/none/c{12}/[0-9a-f]{12}$")
        for reworded in ("reaches it", "reaches this code"), ("the library only", "that one library"), \
                        (prose, "harness: none"):
            with self.subTest(reworded=reworded[1]):
                run, calls, _ = self.run_held(held.replace(*reworded), bodies_on_github=[bodies[0]],
                                               obj="held/9/" + "b" * 32,
                                               header=self.HEADER.replace("runs/7", "runs/9"))
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(self.opened(calls), [])

    def test_an_issue_filed_before_this_key_is_matched_by_its_own_text(self):
        # The issues already in the repository: five of the old key `held/<run id>/<32 hex digits> <n>` and one the
        # statement work filed, whose first line is its key. Each is read for the identity of the text it holds, so
        # the first run after this change files none of them again.
        # The body of such an issue is the finding without its title line, which is the issue's title.
        title, text = self.HELD.split("\n")[1][len("title: "):], self.HELD.split("\n", 2)[2]
        old = (f"enrollment PR: theorem-labs/oss-verify#68\nenrollment PR head: {'1' * 40}\n"
               f"public PR comment: not posted yet\nreview run: {self.RUN}\n"
               f"held finding key: held/40971300962/{'f' * 32} 1\n" + text)
        lane = f"held finding key: libreac-1 (lane record ossv-agent-open:/home/sami/libreac-1.md)\n{text}"
        for what, body in (("the old key", old), ("the statement work's", lane)):
            with self.subTest(what=what):
                run, calls, sent = self.run_held(self.HELD, bodies_on_github=[(body, "open", title)],
                                                  obj="held/9/" + "b" * 32,
                                                  header=self.HEADER.replace("runs/7", "runs/9"))
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual((self.opened(calls), sent), ([], []))
                self.assertIn("1 already filed", run.summary)
        # Another project's finding is not it.
        other = old.replace("project: libreac", "project: other")
        run, calls, _ = self.run_held(self.HELD, bodies_on_github=[(other, "open", title)],
                                       obj="held/9/" + "b" * 32, header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(len(self.opened(calls)), 1)

    def test_the_same_finding_of_another_run_of_the_review_is_not_filed_again(self):
        # Two runs of the same review: a new stored object, a new run id, and the model's own words around the
        # finding written afresh. The second run opens nothing and says so in the job summary.
        first, _, bodies = self.run_held(self.HELD)
        self.assertEqual(first.returncode, 0, first.stderr)
        again = self.HELD.replace("a read past the end", "it reads past the end of the buffer") \
                         .replace("src/parse.c:40-80, parse_SECRETBUG reads past the end.",
                                  "src/parse.c:40-80, parse_SECRETBUG. The call at line 51 is the one.")
        run, calls, sent = self.run_held(again, bodies_on_github=[bodies[0]], obj="held/9/" + "b" * 32,
                                         header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.opened(calls), [])
        self.assertIn("1 with a text added to the issue that holds it", run.stdout)
        self.assertIn("1 with a text added to the issue that holds it", run.summary)
        # The text changed, so it goes on the issue that is there, as a comment, and no new issue is opened.
        self.assertEqual([c[1] for c in calls if "-F" in c], ["repos/theorem-labs/private/issues/1/comments"])
        self.assertTrue(sent[0].startswith(f"held finding update: {self.key_of(bodies[0])} "), sent[0])
        self.assertIn("found again in run: https://github.com/theorem-labs/oss-verify/actions/runs/9\n", sent[0])
        self.assertIn("The call at line 51 is the one.", sent[0])
        self.assertNotIn("SECRETBUG", run.stdout + run.stderr + run.summary)

    def test_the_same_finding_with_the_same_text_sends_nothing_at_all(self):
        _, _, bodies = self.run_held(self.HELD)
        run, calls, sent = self.run_held(self.HELD, bodies_on_github=[bodies[0]], obj="held/9/" + "b" * 32,
                                         header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.opened(calls), sent), ([], []))
        self.assertIn("1 already filed", run.summary)

    def test_a_body_a_person_edited_with_windows_line_ends_is_still_the_key_that_is_there(self):
        _, _, bodies = self.run_held(self.HELD)
        run, calls, sent = self.run_held(self.HELD, bodies_on_github=[bodies[0].replace("\n", "\r\n")],
                                         obj="held/9/" + "b" * 32, header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.opened(calls), sent), ([], []))

    def test_another_finding_of_the_same_project_is_filed(self):
        _, _, bodies = self.run_held(self.HELD)
        other = self.HELD.replace("heap-buffer-overflow in parse_SECRETBUG", "crash in other_SECRETBUG") \
                         .replace("why held: memory safety: a read past the end", "why held: crash: it aborts") \
                         .replace("src/parse.c:40-80, parse_SECRETBUG reads past the end.", "src/other.c:3, it aborts.")
        run, calls, sent = self.run_held(other, bodies_on_github=[bodies[0]], obj="held/9/" + "b" * 32,
                                         header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(self.opened(calls)), 1)
        self.assertNotEqual(self.key_of(sent[0]), self.key_of(bodies[0]))

    def test_a_closed_issue_of_the_same_key_is_neither_reopened_nor_filed_again(self):
        # The disclosure route closed it (oss-verify-proofs-internal#450 was closed as a duplicate). A re-run of a
        # review is no new evidence: reopening would undo that decision, and a new issue is the duplicate the key
        # exists to stop.
        _, _, bodies = self.run_held(self.HELD)
        run, calls, sent = self.run_held(self.HELD, bodies_on_github=[(bodies[0], "closed")],
                                         obj="held/9/" + "b" * 32, header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.opened(calls), sent), ([], []))
        self.assertFalse([c for c in calls if any(x in ("-X", "PATCH", "state=open") for x in c)], calls)
        self.assertIn("1 whose issue is closed", run.stdout)
        self.assertIn("1 whose issue is closed", run.summary)

    def test_a_lookup_that_fails_files_nothing_and_fails_the_step(self):
        run, calls, sent = self.run_held(self.HELD, listing_fails=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual((self.opened(calls), sent), ([], []))
        self.assertIn("could not read the issues already filed", run.stderr)
        # gh's own words, which hold the private repository's name, reach neither the log nor the job summary.
        self.assertNotIn("private", run.stdout + run.stderr + run.summary)
        # And a lookup of the comments of the issue that is there, for the parts it already holds.
        _, _, bodies = self.run_held(self.HELD)
        run, calls, sent = self.run_held(self.HELD, bodies_on_github=[bodies[0]], comments_fail=True,
                                         obj="held/9/" + "b" * 32, header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual((self.opened(calls), sent), ([], []))

    def test_the_words_a_review_writes_differently_each_run_are_not_in_the_key(self):
        # Each of these is the same finding, written as a model writes it on another run. None of them files again.
        _, _, bodies = self.run_held(self.HELD)
        same = {
            "the function in code quotes": ("in parse_SECRETBUG", "in `parse_SECRETBUG`"),
            "the function with its brackets": ("in parse_SECRETBUG", "in parse_SECRETBUG()"),
            "the kind with a hyphen": ("why held: memory safety:", "why held: memory-safety:"),
            "the repository over ssh": ("https://github.com/example/libreac",
                                        "ssh://git@github.com/example/libreac.git"),
            "the commit in capitals": ("upstream commit: " + "c" * 40, "upstream commit: " + "C" * 40),
            "a line that moved": ("src/parse.c:40-80", "src/parse.c:41-81"),
        }
        for what, (before, after) in same.items():
            with self.subTest(what=what):
                run, calls, _ = self.run_held(self.HELD.replace(before, after), bodies_on_github=[bodies[0]],
                                               obj="held/9/" + "b" * 32,
                                               header=self.HEADER.replace("runs/7", "runs/9"))
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(self.opened(calls), [])

    def test_a_text_the_issue_already_holds_is_not_added_again_or_reported_as_added(self):
        _, _, bodies = self.run_held(self.HELD)
        again = self.HELD.replace("a read past the end", "it reads past the end of the buffer")
        run, _, update = self.run_held(again, bodies_on_github=[bodies[0]], obj="held/9/" + "b" * 32,
                                        header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(update), 1)
        run, calls, sent = self.run_held(again, bodies_on_github=[bodies[0]], comments=[update[0]],
                                          obj="held/11/" + "c" * 32,
                                          header=self.HEADER.replace("runs/7", "runs/11"))
        self.assertEqual((run.returncode, self.opened(calls), sent), (0, [], []))
        self.assertIn("1 already filed", run.summary)
        self.assertNotIn("1 with a text added", run.summary)

    def test_findings_of_an_issue_that_holds_several_are_never_filed_on_their_own(self):
        # Eleven findings go as one issue. The next run holds ten of them: each is already filed, in that issue.
        findings = [f"<!-- held finding -->\ntitle: t{i} in f{i}\nproject: libreac\nharness: fuzz_one\n"
                    f"why held: crash: SECRET{i}\n\nsrc/f{i}.c, it aborts.\n" for i in range(11)]
        run, _, bodies = self.run_held("".join(findings))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        self.assertEqual(len(bodies[0].split("\n")[6].removeprefix("held finding set: ").split()), 11)
        run, calls, sent = self.run_held("".join(findings[:10]), bodies_on_github=[bodies[0]],
                                          obj="held/9/" + "b" * 32,
                                          header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual((run.returncode, self.opened(calls), sent), (0, [], []))
        self.assertIn("10 already filed", run.summary)

    def test_an_issue_that_holds_several_takes_only_the_findings_that_are_not_filed_yet(self):
        # Ten findings file one issue each; a re-run that holds eleven files only the one that is new.
        findings = [f"<!-- held finding -->\ntitle: t{i} in f{i}\nproject: libreac\nharness: fuzz_one\n"
                    f"why held: crash: SECRET{i}\n\nsrc/f{i}.c, it aborts.\n" for i in range(11)]
        run, _, bodies = self.run_held("".join(findings[:10]))
        self.assertEqual((run.returncode, len(bodies)), (0, 10))
        run, calls, sent = self.run_held("".join(findings), bodies_on_github=list(bodies),
                                          obj="held/9/" + "b" * 32,
                                          header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(sent), 1)
        self.assertIn("SECRET10", sent[0])
        for i in range(10):
            self.assertNotIn(f"SECRET{i}\n", sent[0])

    def test_an_open_issue_of_the_key_is_the_one_a_closed_one_does_not_hide(self):
        _, _, bodies = self.run_held(self.HELD)
        run, calls, sent = self.run_held(self.HELD, obj="held/9/" + "b" * 32,
                                         header=self.HEADER.replace("runs/7", "runs/9"),
                                         bodies_on_github=[(bodies[0], "closed"), (bodies[0], "open")])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.opened(calls), [])
        self.assertIn("1 already filed", run.stdout)

    def test_a_re_run_sends_only_what_its_run_did_not_send_and_the_title_routes_nothing(self):
        # The first of two untitled findings was sent before the run failed; a closed issue counts too. Another
        # project's issue does not stop either.
        two = "<!-- held finding -->\nproject: libreac\n<!-- held finding -->\nproject: libreac\nsecond\n"
        run, calls, bodies = self.run_held(two)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 2)
        run, calls, sent = self.run_held(two, obj="held/9/" + "b" * 32,
                                         header=self.HEADER.replace("runs/7", "runs/9"),
                                         bodies_on_github=[(bodies[0], "closed"),
                                                           self.body(f"other/none/none/{'d' * 12}"),
                                                           # A key anywhere but the fifth line is no key.
                                                           f"held finding key: {self.key_of(bodies[1])}\n"])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(self.opened(calls)), 1)
        self.assertEqual(self.key_of(sent[0]), self.key_of(bodies[1]))
        self.assertIn("second", sent[0])

    def test_a_finding_with_only_a_title_is_sent(self):
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: [held] libreac/x: crash in f\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)

    def test_every_object_is_settled_the_first_time(self):
        # Empty markers are no findings; an object with none sends nothing and succeeds; more than 10 go as one issue.
        run, calls, bodies = self.run_held("<!-- held finding -->\n<!-- held finding -->\nproject: libreac\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        run, _, bodies = self.run_held("<!-- held finding -->\n")
        self.assertEqual((run.returncode, bodies), (0, []))
        eleven = "".join(f"<!-- held finding -->\ntitle: t{i}\nproject: libreac SECRET{i}\n" for i in range(11))
        run, calls, bodies = self.run_held(eleven)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        self.assertRegex(self.key_of(bodies[0]), r"^review/libreac/all/[0-9a-f]{12}$")
        self.assertIn("SECRET10", bodies[0])
        # The same eleven findings of another run of the review are the same set: one issue, not twelve.
        run, calls, sent = self.run_held(eleven, bodies_on_github=[bodies[0]], obj="held/9/" + "b" * 32,
                                         header=self.HEADER.replace("runs/7", "runs/9"))
        self.assertEqual((run.returncode, self.opened(calls), sent), (0, [], []))

    def test_a_long_finding_goes_whole_in_parts_and_a_re_run_posts_only_the_missing_ones(self):
        # 130,000 bytes in lines of 1,000: the issue and two comments, each at most 60,000 bytes, which hold it all.
        long = "".join(f"{i:05d}" + "x" * 994 + "\n" for i in range(130))
        held = "<!-- held finding -->\ntitle: big in f\n" + long + "END-OF-FINDING\n"
        run, calls, bodies = self.run_held(held)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 3)
        key = self.key_of(bodies[0])
        self.assertTrue(all(len(b.encode()) <= 60500 for b in bodies))
        self.assertIn("(Part 1 of 3: the rest follows in the comments.)", bodies[0])
        self.assertTrue(bodies[1].startswith(f"held finding part: {key} 2/3\n"))
        self.assertIn("END-OF-FINDING", bodies[2])
        joined = "".join(bodies)
        self.assertTrue(all(f"{i:05d}" in joined for i in range(130)))
        self.assertEqual([c[1] for c in calls if "-F" in c][1:], ["repos/theorem-labs/private/issues/42/comments"] * 2)
        # A run that stopped after part 2: the next posts only part 3, on the issue that is there.
        run, calls, sent = self.run_held(held, bodies_on_github=[bodies[0]],
                                         comments=[f"held finding part: {key} 2/3\n\n..."])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0].startswith(f"held finding part: {key} 3/3\n"))
        self.assertEqual([c[1] for c in calls if "-F" in c], ["repos/theorem-labs/private/issues/1/comments"])

    @staticmethod
    def finding_of(issue_body, comment_bodies):
        """The finding as the disclosure route reads it back: the issue after its six lines, without the part note,
        then each comment after its part line and the blank line."""
        text = issue_body.split("\n", 6)[6]
        text = re.sub(r"\n\n\(Part 1 of \d+: the rest follows in the comments\.\)\n$", "", text)
        return text + "".join(c.split("\n", 2)[2] for c in comment_bodies)

    def test_a_long_finding_comes_back_byte_for_byte_whatever_the_comment_address(self):
        # Run 1 finds no review comment yet (the long fallback text) and stops after part 2. Run 2 finds the comment
        # (a short address) and posts the rest. The parts must join to the finding exactly.
        # Short lines, so that a change of a few bytes in the lines the script adds would move where a part ends.
        lines = [f"{i:05d} " + "é" * (i % 7) + "y" * (30 + i % 13) + "\n" for i in range(2800)]
        finding = "".join(lines) + "END-OF-FINDING\n"
        held = "<!-- held finding -->\ntitle: big in f\n" + finding
        run, _, first = self.run_held(held)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertGreater(len(first), 2)
        self.assertEqual(self.finding_of(first[0], first[1:]), finding)
        issue = first[0].replace("public PR comment: not posted yet: the review comment on theorem-labs/oss-verify#68",
                                 "public PR comment: https://example.test/c")
        run, _, second = self.run_held(held, bodies_on_github=[issue], comments=first[1:2],
                                       public_comments=[("oss-verify[bot]", "<!-- oss-verify-review -->\nx",
                                                         "https://example.test/c")])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(second, first[2:])
        self.assertEqual(self.finding_of(first[0], first[1:2] + second), finding)

    def test_only_the_first_title_line_leaves_the_finding(self):
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: crash in f\nlog:\ntitle: from the input\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.finding_of(bodies[0], []), "log:\ntitle: from the input\n")

    def test_a_line_longer_than_a_part_is_cut_between_characters(self):
        # One long line of two-, three- or four-byte characters, after a prefix of 0 to 3 bytes, so that byte 60,000
        # falls at every place inside a character. The stand-in stores bytes that are not UTF-8 as U+FFFD, as GitHub.
        for char in ("é", "€", "😀"):
            for prefix in range(4):
                with self.subTest(char=char, prefix=prefix):
                    finding = "x" * prefix + char * (130000 // len(char.encode())) + "\n"
                    run, _, bodies = self.run_held("<!-- held finding -->\ntitle: big in f\n" + finding)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(len(bodies), 3)
                    self.assertNotIn("\ufffd", "".join(bodies))
                    self.assertEqual(self.finding_of(bodies[0], bodies[1:]), finding)

    def test_a_part_ends_at_a_line_end_when_the_line_fits(self):
        finding = "".join(f"{i:05d} " + "y" * 994 + "\n" for i in range(130))
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: big in f\n" + finding)
        self.assertEqual(run.returncode, 0, run.stderr)
        texts = [re.sub(r"\n\n\(Part 1 of \d+: the rest follows in the comments\.\)\n$", "",
                        bodies[0].split("\n", 6)[6])] + [b.split("\n", 2)[2] for b in bodies[1:]]
        self.assertTrue(all(t.endswith("\n") and t.split("\n")[0][:5].isdigit() for t in texts), texts[1][:20])

    def test_the_public_comment_is_the_bots_review_comment_of_the_pull_request(self):
        # Another user's comment with the marker, the bot's other comment, then the bot's review comment; and a comment
        # with the marker on the private repository's issue, which is not the pull request's.
        public = [("someone", "<!-- oss-verify-review -->\nfake", "https://example.test/other-user"),
                  ("oss-verify[bot]", "Thanks for the enrollment.", "https://example.test/other-bot-comment"),
                  ("oss-verify[bot]", "Quoted: <!-- oss-verify-review -->", "https://example.test/quoting-comment"),
                  ("oss-verify[bot]", "<!-- oss-verify-review -->\nreview", "https://example.test/review-comment"),
                  ("oss-verify[bot]", "<!-- oss-verify-review -->\nlater", "https://example.test/later-comment")]
        run, calls, bodies = self.run_held(self.HELD, public_comments=public,
                                           comments=["<!-- oss-verify-review -->\nprivate"])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(bodies[0].split("\n")[2], "public PR comment: https://example.test/review-comment")
        lookups = [c for c in calls if c[1].endswith("/comments") and "-F" not in c]
        self.assertEqual([c[1] for c in lookups], ["repos/theorem-labs/oss-verify/issues/68/comments"])
        # It reads the public comments with the token for this repository, not the App's token for the private one,
        # and every call to the private repository uses the App's token.
        tokens = dict(zip(map(json.dumps, calls), run.tokens))
        self.assertEqual(tokens[json.dumps(lookups[0])], "read-not-a-secret")
        self.assertEqual({t for c, t in zip(calls, run.tokens) if "theorem-labs/private" in c[1]}, {"app-not-a-secret"})

    def test_a_loose_marker_splits_findings_as_review_run_cuts_them(self):
        run, _, bodies = self.run_held("  - <!--Held Finding-->\nproject: a\n> <!-- held_finding -->\nproject: b\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 2)

    def test_without_a_private_repository_or_a_held_object_it_fails(self):
        run, calls, _ = self.run_held(self.HELD, variable="")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(calls, [])
        for visibility in ("public", "internal", ""):
            with self.subTest(visibility=visibility):
                run, calls, _ = self.run_held(self.HELD, visibility=visibility)
                self.assertEqual(run.returncode, 2)
                self.assertIn("names is not private, so nothing is sent", run.stderr)
                self.assertFalse([c for c in calls if "-F" in c or "-f" in c])
        run, calls, _ = self.run_held(self.HELD, obj="held/7/short")
        self.assertEqual((run.returncode, calls), (2, []))

    def test_an_object_that_does_not_start_with_the_workflows_lines_is_sent_whole_once(self):
        for header in ("", "oss-verify held finding v1\npr: 68\nhead: x\nproject: libreac\nrun: r\n---\n",
                       self.HEADER.replace("runs/7", "runs/8")):
            with self.subTest(header=header):
                run, calls, bodies = self.run_held(self.HELD, header=header)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(len(bodies), 1)
                self.assertRegex(self.key_of(bodies[0]), r"^review/raw/[0-9a-f]{12}$")
                self.assertIn("SECRETBUG", bodies[0])
                # The same broken object, stored again by another run, is the same key: one issue.
                run, calls, sent = self.run_held(self.HELD, header=header, bodies_on_github=[bodies[0]],
                                                 obj="held/9/" + "b" * 32)
                self.assertEqual((run.returncode, self.opened(calls), sent), (0, [], []))

    def test_the_review_jobs_own_step_puts_no_finding_in_the_output_the_log_or_the_summary(self):
        # The review job's step, run as the runner runs it, with a stand-in curl for the bucket: of the finding it
        # stores, the job's output, the log and the job summary of this public repository hold nothing but the
        # object's name, and that name is what the hold job reads the finding by.
        [script] = [s["run"] for s in
                    yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]["review"]
                    ["steps"] if s.get("name") == "Store the held finding for the hold job"]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "tmp").mkdir()
            (root / "tmp" / "held-finding.md").write_text(self.HELD)
            # curl answers as the bucket does, and keeps the bytes it was sent. The step runs from the checkout's
            # root, as the runner runs it, because it calls .github/scripts/held-bucket-put by a relative path.
            (root / "bin" / "curl").write_text(
                "#!/bin/bash\nfor a in \"$@\"; do case $a in --data-binary) ;; @*) cp \"${a#@}\" "
                f"{root}/uploaded ;; esac; done\n" + 'printf \'{"generation": "1761500000000000"}\'\n')
            (root / "bin" / "curl").chmod(0o755)
            run = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", script], cwd=ROOT, text=True,
                                 capture_output=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "RUNNER_TEMP": str(root / "tmp"), "GITHUB_OUTPUT": str(root / "output"),
                                      "GITHUB_STEP_SUMMARY": str(root / "summary"),
                                      "GCP_ACCESS_TOKEN": "gcp-not-a-secret", "RUN_ID": "7", "PR": "68",
                                      "NAME": "libreac", "HEAD_SHA": "1" * 40,
                                      "RUN_URL": "https://github.com/theorem-labs/oss-verify/actions/runs/7"})
            self.assertEqual(run.returncode, 0, run.stderr)
            output = (root / "output").read_text()
            summary = (root / "summary").read_text() if (root / "summary").exists() else ""
            uploaded = (root / "uploaded").read_text()
        # The output is the object's name and nothing else, and the finding went to the bucket, whole.
        self.assertRegex(output, r"^object=held/7/[0-9a-f]{32}\n$")
        self.assertTrue(uploaded.startswith(self.HEADER), uploaded[:100])
        self.assertIn("SECRETBUG", uploaded)
        for public in (output, summary, run.stdout, run.stderr):
            self.assertNotIn("SECRETBUG", public)
            self.assertNotIn("parse_SECRETBUG", public)
            self.assertNotIn("memory safety", public)


class ReviewHold(unittest.TestCase):
    """review-hold sends every stored finding in the bucket, its own run's and a cancelled run's, through a fake curl for
    the bucket and a stand-in review-held, and deletes each object once it is sent."""

    def sweep(self, objects, held_fails=(), delete_fails=False, current="", gone=(), sizes=None, cut=(), late=()):
        """objects: name -> stored bytes. held_fails: names whose review-held fails. current: this run's object. gone:
        names another hold job deleted (404). sizes: name -> the size the listing reports. cut: names whose download
        the connection cuts after the 200 line (half the bytes, curl exit 18). late: names whose download has every
        byte but curl still exits 18 (the connection fails at the end)."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy(ROOT / ".github" / "scripts" / "review-hold", scripts / "review-hold")
            (root / "store").mkdir()
            listing = {"items": [{"name": n, "generation": str(100 + i), "size": str((sizes or {}).get(n, len(b)))}
                                 for i, (n, b) in enumerate(objects.items())]}
            (root / "listing.json").write_text(json.dumps(listing))
            for name, data in objects.items():
                (root / "store" / name.replace("/", "%2F")).write_bytes(data)
            # review-held stand-in: records the object it was given, and fails for the names in held_fails.
            (scripts / "review-held").write_text(
                f"#!/bin/bash\necho \"$HELD_OBJECT $(head -c 20 \"$1/object\")\" >> {root}/sent\n"
                f"case \"$HELD_OBJECT\" in {'|'.join(held_fails) or 'none'}) exit 1 ;; esac\n")
            (scripts / "review-held").chmod(0o755)
            bin = root / "bin"
            bin.mkdir()
            (bin / "curl").write_text(
                f"#!{sys.executable}\nimport pathlib, sys, urllib.parse\nroot = pathlib.Path({str(root)!r})\n"
                "a = sys.argv[1:]\nurl = a[-1]\n"
                "with open(root / 'curl', 'a') as f: f.write(' '.join(a) + '\\n')\n"
                "if '-X' in a and a[a.index('-X') + 1] == 'DELETE':\n"
                f"    sys.exit(22 if {delete_fails} else 0)\n"
                "if '?prefix=' in url: print((root / 'listing.json').read_text()); sys.exit(0)\n"
                "name = url.split('/o/')[1].split('?')[0]\n"
                f"if urllib.parse.unquote(name) in {list(gone)!r}: print('404', end=''); sys.exit(0)\n"
                "data = (root / 'store' / name).read_bytes()\n"
                f"if urllib.parse.unquote(name) in {list(cut) + list(late)!r}:\n"
                f"    keep = data if urllib.parse.unquote(name) in {list(late)!r} else data[:len(data) // 2]\n"
                "    pathlib.Path(a[a.index('-o') + 1]).write_bytes(keep); print('200', end='')\n"
                "    sys.exit(18)\n"
                "pathlib.Path(a[a.index('-o') + 1]).write_bytes(data)\n"
                "print('200', end='')\n")
            (bin / "curl").chmod(0o755)
            run = subprocess.run([str(scripts / "review-hold"), str(root / "work")],
                                 env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}",
                                      "GCP_ACCESS_TOKEN": "gcp-not-a-secret", "CURRENT_OBJECT": current},
                                 capture_output=True, text=True)
            sent = (root / "sent").read_text().splitlines() if (root / "sent").exists() else []
            curl = (root / "curl").read_text()
            return run, sent, curl

    def test_a_cancelled_runs_finding_is_sent_by_the_next_run_and_both_are_deleted(self):
        mine, cancelled = "held/9/" + "a" * 32, "held/8/" + "b" * 32
        run, sent, curl = self.sweep({cancelled: b"oss-verify held finding v1\n", mine: b"oss-verify held finding v1\n"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sorted(s.split()[0] for s in sent), sorted([mine, cancelled]))
        self.assertEqual(curl.count("-X DELETE"), 2)
        self.assertIn(f"sent and deleted {cancelled}", run.stdout)
        self.assertNotIn("gcp-not-a-secret", curl)

    def test_only_this_runs_own_object_fails_the_job(self):
        mine, other = "held/9/" + "a" * 32, "held/8/" + "b" * 32
        # Another run's object that cannot be sent is a warning; this run's is a failure.
        run, sent, curl = self.sweep({other: b"x", mine: b"x"}, held_fails=(other,), current=mine)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(curl.count("-X DELETE"), 1)
        self.assertIn(f"::warning::review-hold: could not send {other}", run.stdout)
        run, sent, curl = self.sweep({other: b"x", mine: b"x"}, held_fails=(mine,), current=mine)
        self.assertEqual(run.returncode, 1)
        self.assertIn(f"could not send {mine}, this run's own finding", run.stderr)

    def test_this_runs_object_goes_first_and_the_cap_leaves_the_rest(self):
        mine = "held/99/" + "f" * 32
        objects = {f"held/{i}/" + "a" * 32: b"x" for i in range(25)}
        objects[mine] = b"x"
        run, sent, curl = self.sweep(objects, current=mine)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sent[0].split()[0], mine)
        self.assertEqual(len(sent), 20)
        self.assertIn("more than 20 stored findings", run.stdout)

    def test_an_object_another_hold_job_sent_is_gone_not_failed(self):
        mine = "held/9/" + "a" * 32
        run, sent, curl = self.sweep({mine: b"x"}, current=mine, gone=(mine,))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sent, [])
        self.assertIn(f"{mine} is no longer in the bucket", run.stdout)

    def test_a_cut_download_is_not_sent_or_deleted(self):
        # curl exit 18 after the 200 line, and a download shorter than the listing's size with exit 0.
        mine = "held/9/" + "a" * 32
        for kwargs in ({"cut": (mine,)}, {"late": (mine,)}, {"sizes": {mine: 40}}):
            with self.subTest(kwargs=kwargs):
                run, sent, curl = self.sweep({mine: b"oss-verify held finding v1\n" + b"y" * 20}, current=mine,
                                             **kwargs)
                self.assertEqual(run.returncode, 1)
                self.assertEqual(sent, [])
                self.assertNotIn("-X DELETE", curl)

    def test_a_sent_object_that_cannot_be_deleted_does_not_fail_the_job(self):
        run, sent, curl = self.sweep({"held/9/" + "a" * 32: b"x"}, delete_fails=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("could not delete it: the next run finds its issues and sends nothing twice", run.stdout)

    def test_an_object_that_is_not_a_held_finding_or_too_large_is_skipped(self):
        big = "held/9/" + "c" * 32
        run, sent, curl = self.sweep({"held/9/short": b"x", "other/9/" + "a" * 32: b"x", big: b"x"},
                                     sizes={big: 1100001})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sent, [])
        self.assertEqual(run.stdout.count("skipped an object that is not a held finding"), 3)

    def test_the_object_is_read_at_its_listed_generation(self):
        run, sent, curl = self.sweep({"held/9/" + "a" * 32: b"x"})
        self.assertIn("alt=media&generation=100", curl)
        self.assertIn("--max-filesize 1100000", curl)


class SinceLastReview(unittest.TestCase):
    """review-gather writes the diff since the last review's commit only when the head descends from it, and only
    then has the review resume that review's session."""

    SESSION = "09227178-7bbf-4e5f-86db-8736e530ef01"

    def gathered(self, status, last=None):
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        keep = re.search(r"^keep\(\) \{.*\}$", gather, re.M).group(0)
        block = gather[gather.index("last=$(sed"):gather.index('ls -la "$out"')]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for sub in ("bin", "out"):
                (root / sub).mkdir()
            (root / "last-review").write_text(f"session={self.SESSION} head={'2' * 40}\n" if last is None else last)
            # gh: the compare's status for --jq .status, else a diff of the project and of another file.
            gh = root / "bin" / "gh"
            gh.write_text("#!/bin/bash\n"
                          f'case "$*" in *"--jq .status"*) echo "{status}" ;;\n'
                          '  *) printf "diff --git a/projects/p/f b/projects/p/f\\n+x\\ndiff --git a/o b/o\\n+y\\n" ;;\n'
                          "esac\n")
            gh.chmod(0o755)
            run = subprocess.run(["bash", "-c", f"set -euo pipefail\nout={root / 'out'}\ndir=projects/p\n{keep}\n{block}"],
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "REPO": "o/r",
                                      "HEAD_SHA": "1" * 40, "LAST_REVIEW": str(root / "last-review"),
                                      "GITHUB_OUTPUT": str(root / "output")},
                                 capture_output=True, text=True)
            diff = root / "out" / "since-last-review.diff"
            output = (root / "output").read_text() if (root / "output").exists() else ""
            return run, diff.read_text() if diff.exists() else None, output

    def test_a_head_that_descends_gets_the_projects_diff_and_resumes(self):
        run, diff, output = self.gathered("ahead")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(diff, "diff --git a/projects/p/f b/projects/p/f\n+x\n(exit status 0)\n")
        self.assertEqual(output, f"session={self.SESSION}\nlast={'2' * 40}\n")
        self.assertIn(f"the review resumes the session {self.SESSION}", run.stdout)

    def test_a_force_push_or_the_same_head_gets_no_diff_and_a_fresh_review(self):
        # A three-dot compare after a force-push diffs from the merge base: it can show nothing that changed.
        for status in ("diverged", "behind", "identical", ""):
            with self.subTest(status=status):
                run, diff, output = self.gathered(status)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIsNone(diff)
                self.assertEqual(output, "")
                self.assertIn(f"no diff from {'2' * 40}", run.stdout)
                self.assertIn("the review is fresh", run.stdout)

    def test_no_kept_review_or_one_of_another_shape_is_a_fresh_review(self):
        for last in ("", f"session=x head={'2' * 40}\n", f"session={self.SESSION}\n",
                     f"session={self.SESSION} head={'2' * 40} extra\n"):
            with self.subTest(last=last):
                run, diff, output = self.gathered("ahead", last=last)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIsNone(diff)
                self.assertEqual((output, run.stdout), ("", ""))


class ReviewJob(unittest.TestCase):
    """build.yaml's review job: its own small steps, and the scripts it runs (review-gather, review-prompt), run with
    stand-ins."""

    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        self.jobs = self.workflow["jobs"]
        self.steps = {s.get("name"): s for s in self.jobs["review"]["steps"]}

    def gather(self, root, gh, **env):
        """review-gather, from this checkout, into root/out, with the stand-in gh script `gh` and `env`."""
        (root / "bin").mkdir(exist_ok=True)
        (root / "bin" / "gh").write_text("#!/bin/bash\n" + f'echo "$*" >> {root / "calls"}\n' + gh)
        (root / "bin" / "gh").chmod(0o755)
        environment = {**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                       "PR": "", "NAME": "", "ISSUE": "", "HEAD_SHA": "", **env}
        return subprocess.run([str(ROOT / ".github" / "scripts" / "review-gather"), str(root / "out")],
                              env=environment, cwd=ROOT, capture_output=True, text=True)

    def test_a_change_gathers_only_the_pull_request_and_its_changed_files_as_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            files = ["tools/a.py", "docs/CLAUDE.md", ".claude/skills/x/SKILL.md", "a/../b", "README.md", "big.bin",
                     "gone.txt"]
            run = self.gather(root, (
                f'case "$*" in\n'
                f'  "pr view"*) echo "{{}}" ;;\n'
                f'  *"/files"*) printf "%s\\n" {" ".join(shlex.quote(f) for f in files)} ;;\n'
                '  "pr diff"*) echo diff ;;\n'
                # A file over 1 MiB, which gh stops writing when head has its first MiB; a file the API cannot give.
                '  *contents/big.bin*) head -c 3000000 /dev/zero | tr "\\0" x ;;\n'
                '  *contents/gone.txt*) echo "{\\"message\\": \\"Not Found\\"}"; exit 1 ;;\n'
                '  *contents/*) echo "file at ${@: -1}" ;;\n'
                '  *) true ;;\n'
                "esac\n"), KIND="change", PR="8", HEAD_SHA="a" * 40)
            self.assertEqual(run.returncode, 0, run.stderr)
            head = sorted(str(p.relative_to(root / "out" / "head")) for p in (root / "out" / "head").rglob("*")
                          if p.is_file())
            self.assertEqual(head, ["README.md", "big.bin", "tools/a.py"])
            self.assertEqual((root / "out" / "head" / "big.bin").stat().st_size, 1048576)
            # Nothing of an enrollment's: no build results, no seeds, no validation.
            for name in ("build", "seeds", "validate.txt", "triage-today.md"):
                self.assertFalse((root / "out" / name).exists(), name)

    def test_an_issue_gathers_only_the_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            gh = 'case "$*" in "issue view 5 "*) echo \'{"title": "Q"}\' ;; *) exit 1 ;; esac\n'
            run = self.gather(root, gh, KIND="issue", ISSUE="5")
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(sorted(p.name for p in (root / "out").iterdir()), ["issue.json"])
            self.assertEqual((root / "out" / "issue.json").read_text(), '{"title": "Q"}\n(exit status 0)\n')
            self.assertEqual((root / "calls").read_text(),
                             "issue view 5 -R o/r --json number,title,author,createdAt,body,comments\n")

    def test_gather_refuses_a_kind_or_a_value_it_cannot_take_before_any_read(self):
        for env in ({"KIND": "issue", "ISSUE": "5; x"}, {"KIND": "enrollment", "PR": "8", "NAME": ""},
                    {"KIND": "enrollment", "PR": "8", "NAME": "../x"}, {"KIND": "change", "PR": "8x"},
                    {"KIND": "", "PR": "8"}, {"KIND": "build", "PR": "8"}):
            with self.subTest(env=env), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                run = self.gather(root, "exit 0\n", **env)
                self.assertEqual(run.returncode, 2, run.stderr)
                self.assertFalse((root / "calls").exists())

    def test_hostile_issue_text_is_only_data_in_the_gather_and_the_result_steps(self):
        # The issue's text reaches the scripts only from gh's answer (a file) and the model's output (a file): a title
        # or body that is shell text runs nothing.
        hostile = '$(touch pwned-a) `touch pwned-b` "; touch pwned-c; " \' ; touch pwned-d #'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            answer = shlex.quote(json.dumps({"title": hostile, "body": hostile}))
            run = self.gather(root, f'echo {answer}\n', KIND="issue", ISSUE="5")
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("touch pwned-a", (root / "out" / "issue.json").read_text())
        run, comment, _, _, _, _ = self.result({"comment": hostile, "decide": hostile}, kind="issue", issue="5")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.issue_draft.count(hostile), 2)
        for where in (ROOT, pathlib.Path.cwd()):
            self.assertEqual(sorted(where.glob("pwned-*")), [])
        self.assertEqual(sorted(self.ran_in.glob("pwned-*")), [])

    def test_an_issue_draft_stays_out_of_the_artifact_and_the_summary(self):
        # The artifact and the job summary are public: the draft and what a person decides go to a file that the
        # next step stores in the private bucket.
        run, comment, verdicts, held, output, _ = self.result(
            {"comment": "See docs/dsl.md.\n", "decide": "nothing"}, kind="issue", issue="5")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse((self.ran_in / "temp" / "draft").exists())
        self.assertEqual((comment, verdicts, held, output, self.summary), (None, None, None, {}, None))
        self.assertEqual(self.issue_draft, "The draft reply:\n\nSee docs/dsl.md.\n\n\n"
                                           "What a person at Theorem decides before it is posted:\n\nnothing\n")

    def test_an_issue_run_gives_the_job_no_comment_output(self):
        # The job's comment output is the result step's: for an issue, whose draft no one has approved, it has none,
        # so no expression and no debug log carries the draft. A change's and an enrollment's comment is there.
        _, _, _, _, output, _ = self.result({"comment": "The draft reply.\n", "decide": "nothing"}, kind="issue",
                                            issue="5")
        self.assertNotIn("comment", output)
        _, _, _, _, output, _ = self.result({"comment": "Thanks.\n", "verdicts": {}}, kind="change")
        self.assertEqual(output["comment"], "Thanks.\n")

    def test_a_change_without_a_held_field_holds_nothing(self):
        run, comment, verdicts, held, output, _ = self.result(
            {"comment": "Thanks.\n", "verdicts": {str(n): "pass" for n in range(1, 6)}}, kind="change")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(verdicts), {str(n): "pass" for n in range(1, 6)})
        self.assertEqual((output, held, self.summary, self.issue_draft),
                         ({"comment": "Thanks.\n"}, "<!-- held finding -->\n\n", None, None))

    @staticmethod
    def outputs(text):
        """GITHUB_OUTPUT's text as the runner reads it: name=value lines, and name<<delimiter blocks."""
        found, lines = {}, iter((text or "").splitlines())
        for line in lines:
            equals, heredoc = line.find("="), line.find("<<")
            if heredoc >= 0 and (equals < 0 or heredoc < equals):
                name, delimiter = line.split("<<", 1)
                value = []
                for inner in lines:
                    if inner == delimiter:
                        break
                    value.append(inner)
                found[name] = "\n".join(value)
            else:
                name, value = line.split("=", 1)
                found[name] = value
        return found

    def result(self, output, kind="enrollment", issue=""):
        """The result step, on an execution file whose result carries `output` as its structured output, for a review
        of `kind` (the issue `issue` for an issue). It returns the step's outputs as the runner reads them, and keeps
        the step summary in self.summary, an issue's draft file in self.issue_draft, and the directory it ran in in
        self.ran_in."""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        root = self.ran_in = pathlib.Path(directory)
        (root / "temp").mkdir()
        (root / "home").mkdir()
        execution = root / "execution.json"
        execution.write_text(json.dumps([{"type": "system", "subtype": "init"},
                                         {"type": "result", "subtype": "success", "structured_output": output}]))
        run = subprocess.run(["bash", "-e", "-c", self.steps["Keep the draft, and the held finding apart from it"]["run"]],
                             cwd=root, capture_output=True, text=True,
                             env={**os.environ, "HOME": str(root / "home"), "RUNNER_TEMP": str(root / "temp"),
                                  "GITHUB_OUTPUT": str(root / "output"), "RESULT": str(execution),
                                  "SESSION": "09227178-7bbf-4e5f-86db-8736e530ef01", "HEAD_SHA": "1" * 40,
                                  "KIND": kind, "ISSUE": issue, "GITHUB_STEP_SUMMARY": str(root / "summary")})
        read = lambda path: path.read_text() if path.exists() else None  # noqa: E731
        self.summary = read(root / "summary")
        self.issue_draft = read(root / "temp" / "issue-draft.md")
        return (run, read(root / "temp" / "draft" / "comment.md"), read(root / "temp" / "draft" / "verdicts.json"),
                read(root / "temp" / "held-finding.md"), self.outputs(read(root / "output")),
                read(root / "home" / ".claude" / "ossv-last-review"))

    def store(self, issue="5", attempt="2", repo="theorem-labs/oss-verify",
              answer='{"generation": "1730000000000000"}',
              draft="The draft reply:\n\nSee docs/dsl.md.\n"):
        """.github/scripts/store-issue-draft on a draft file, with a stand-in curl that keeps its arguments, the object
        it uploads, and answers `answer`. Return the exit status, the output, the summary, curl's arguments and the
        object."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "draft.md").write_text(draft, encoding="utf-8")
            (root / "bin" / "curl").write_text(
                "#!/bin/bash\n"
                f'printf "%s\\n" "$@" > {root}/argv\n'
                'prev=""; for a; do\n'
                f'  [ "$prev" = --data-binary ] && cp "${{a#@}}" {root}/object\n'
                f'  [ "$prev" = -H ] && [[ $a == @* ]] && cat "${{a#@}}" > {root}/header\n'
                '  prev=$a; done\n'
                f'echo {shlex.quote(answer)}\n')
            (root / "bin" / "curl").chmod(0o755)
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "store-issue-draft"), str(root / "draft.md")],
                                 capture_output=True, text=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "GCP_ACCESS_TOKEN": "gcp-token-not-a-secret", "REPO": repo, "ISSUE": issue,
                                      "RUN_ID": "77", "RUN_ATTEMPT": attempt,
                                      "RUN_URL": "https://github.com/o/r/actions/runs/77",
                                      "GITHUB_STEP_SUMMARY": str(root / "summary")})
            read = lambda path: path.read_text(encoding="utf-8") if path.exists() else ""  # noqa: E731
            return (run.returncode, run.stdout, read(root / "summary"), read(root / "argv"), read(root / "object"),
                    read(root / "header"))

    def test_an_issue_draft_is_stored_privately_once_and_the_summary_names_only_where(self):
        code, out, summary, argv, stored, header = self.store()
        self.assertEqual(code, 0, out)
        name = "issue-drafts%2Foss-verify%2F5%2F77-2"
        self.assertIn("/b/theorem-agent-infra-oss-verify-held-findings/o?uploadType=media&ifGenerationMatch=0"
                      f"&name={name}", argv)
        self.assertEqual(stored, "oss-verify issue draft v1\nissue: 5\nrun: https://github.com/o/r/actions/runs/77\n"
                                 "---\nThe draft reply:\n\nSee docs/dsl.md.\n")
        self.assertEqual(header, "Authorization: Bearer gcp-token-not-a-secret\n")
        self.assertNotIn("gcp-token-not-a-secret", argv)
        self.assertIn("gcloud storage cat gs://theorem-agent-infra-oss-verify-held-findings/issue-drafts/oss-verify/5/77-2", summary)
        self.assertNotIn("dsl.md", summary + out)

    def test_another_repository_draft_is_stored_under_its_own_name(self):
        for repo in ("theorem-labs/oss-verify-proofs", "theorem-labs/rocq-linux-process-semantics"):
            with self.subTest(repo=repo):
                code, out, summary, argv, _, _ = self.store(repo=repo)
                self.assertEqual(code, 0, out)
                name = f"issue-drafts%2F{repo.rsplit('/', 1)[1]}%2F5%2F77-2"
                self.assertIn(f"&name={name}", argv)
                self.assertIn(f"gs://theorem-agent-infra-oss-verify-held-findings/issue-drafts/"
                              f"{repo.rsplit('/', 1)[1]}/5/77-2", summary)

    def test_a_draft_that_cannot_be_stored_fails_the_step(self):
        for kwargs in ({"answer": '{"error": "403"}'}, {"issue": "5; x"}, {"attempt": ""}, {"repo": ""},
                       {"repo": "theorem-labs/oss-verify-proofs-internal"}, {"repo": "other/oss-verify"}):
            with self.subTest(kwargs=kwargs):
                code, _, summary, _, _, _ = self.store(**kwargs)
                self.assertNotEqual(code, 0)
                self.assertNotIn("gcloud storage cat", summary)

    def test_control_characters_are_taken_out_of_the_stored_draft(self):
        # A person reads the draft in a terminal: an escape sequence (SGR 8 hides text), a carriage return, a bell,
        # DEL and a C1 CSI (U+009B) in the model's text must not reach it. Tab, newline and other text stay.
        draft = "Fine \x1b[8mhidden\x1b[0m text\r\nnext\tcol\x07\x7f\u009b31m café — ok\n"
        code, out, _, _, stored, _ = self.store(draft=draft)
        self.assertEqual(code, 0, out)
        self.assertEqual(stored.split("---\n", 1)[1], "Fine [8mhidden[0m text\nnext\tcol31m café — ok\n")

    def test_bidirectional_text_controls_are_taken_out_of_the_stored_draft(self):
        # U+202A to U+202E and U+2066 to U+2069 can show the draft in an order that is not its own (Trojan Source).
        # Each one, alone, is taken out; the letters around it stay in their order.
        for code_point in [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]:
            with self.subTest(code_point=f"U+{code_point:04X}"):
                code, out, _, _, stored, _ = self.store(draft=f"ab{chr(code_point)}cd\n")
                self.assertEqual(code, 0, out)
                self.assertEqual(stored.split("---\n", 1)[1], "abcd\n")
        # Their neighbours in Unicode, which control nothing, stay.
        code, out, _, _, stored, _ = self.store(draft="a\u2029b\u202fc\u2065d\u206ae\n")
        self.assertEqual(stored.split("---\n", 1)[1], "a\u2029b\u202fc\u2065d\u206ae\n")

    def prompt(self, **env):
        """.github/scripts/review-prompt with `env`: its exit status and the outputs it wrote."""
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "output"
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-prompt")], capture_output=True, text=True,
                                 env={**os.environ, "GITHUB_OUTPUT": str(output), **env})
            lines = output.read_text().splitlines() if output.exists() else []
        return run.returncode, dict(line.split("=", 1) for line in lines)

    def schema(self, arguments):
        return json.loads(re.search(r"--json-schema '([^']*)'", arguments).group(1))

    def test_the_prompt_of_each_kind_names_its_rules_and_its_schema(self):
        code, out = self.prompt(KIND="change", PR="8", REPO="theorem-labs/oss-verify")
        self.assertEqual(code, 0)
        self.assertTrue(out["prompt"].startswith("Read review-change.md at the root of this checkout"))
        self.assertIn("pull request #8 of theorem-labs/oss-verify checks,", out["prompt"])
        schema = self.schema(out["arguments"])
        self.assertEqual(schema["required"], ["comment", "verdicts"])
        self.assertEqual(schema["properties"]["verdicts"]["required"], ["1", "2", "3", "4", "5"])
        self.assertNotIn("held", schema["properties"])
        self.assertNotIn("--resume", out["arguments"])
        code, out = self.prompt(KIND="issue", ISSUE="45", REPO="theorem-labs/oss-verify-proofs")
        self.assertEqual(code, 0)
        self.assertTrue(out["prompt"].startswith("Read review-issue.md at the root of this checkout"))
        self.assertIn("issue #45 of theorem-labs/oss-verify-proofs says,", out["prompt"])
        schema = self.schema(out["arguments"])
        self.assertEqual((schema["required"], sorted(schema["properties"])), (["comment", "decide"],
                                                                            ["comment", "decide"]))
        code, out = self.prompt(KIND="enrollment", PR="8", NAME="libreac")
        self.assertEqual(code, 0)
        self.assertIn("projects/libreac/", out["prompt"])
        self.assertIn(" Then review as the section", out["prompt"])
        schema = self.schema(out["arguments"])
        self.assertEqual((schema["required"], schema["properties"]["verdicts"]["required"]),
                         (["comment", "held", "verdicts"], ["F2", "F7"]))
        self.assertNotIn("--resume", out["arguments"])
        for code, out in (self.prompt(KIND="issue", ISSUE="45", REPO="o/r"),
                          self.prompt(KIND="change", PR="8", REPO="o/r")):
            self.assertTrue(out["prompt"].endswith(" Give the result as the structured output."))

    def test_an_enrollment_with_a_kept_session_resumes_it_for_the_diff_and_check_d3(self):
        session, last, head = "09227178-7bbf-4e5f-86db-8736e530ef01", "2" * 40, "3" * 40
        code, out = self.prompt(KIND="enrollment", PR="8", NAME="libreac", SESSION=session, LAST=last, HEAD_SHA=head)
        self.assertEqual(code, 0)
        self.assertTrue(out["arguments"].endswith(f"' --resume {session}"))
        self.assertIn(f"Earlier in this session you reviewed {last}.", out["prompt"])
        self.assertIn(f"the diff from {last} to {head}, with one exception: check D3 of review.md", out["prompt"])
        self.assertIn(f"each failing result of the report this build wrote for {head}, whatever the diff holds",
                      out["prompt"])

    def test_a_change_with_a_kept_session_resumes_it_and_judges_checks_4_and_5_on_the_whole_diff(self):
        session, last, head = "09227178-7bbf-4e5f-86db-8736e530ef01", "2" * 40, "3" * 40
        code, out = self.prompt(KIND="change", PR="34", REPO="theorem-labs/rocq-linux-process-semantics",
                                SESSION=session, LAST=last, HEAD_SHA=head)
        self.assertEqual(code, 0)
        self.assertTrue(out["arguments"].endswith(f"' --resume {session}"))
        self.assertIn("pull request #34 of theorem-labs/rocq-linux-process-semantics", out["prompt"])
        self.assertIn(f".review/since-last-review.diff, the diff from {last} to {head}, is an aid for checks 1 to 3"
                      " only. Judge checks 4 and 5 on the whole diff of the pull request against its base,"
                      " .review/pr.diff, as on a first review.", out["prompt"])
        # Without a session that review-gather kept, the review is fresh.
        code, out = self.prompt(KIND="change", PR="34", REPO="o/r", LAST=last, HEAD_SHA=head)
        self.assertEqual(code, 0)
        self.assertNotIn("since-last-review", out["prompt"])
        self.assertNotIn("--resume", out["arguments"])

    def test_the_prompt_refuses_what_it_cannot_check(self):
        for env in ({"KIND": "issue", "ISSUE": "45 extra", "REPO": "o/r"}, {"KIND": "change", "PR": "", "REPO": "o/r"},
                    {"KIND": "change", "PR": "8"}, {"KIND": "change", "PR": "8", "REPO": "o/r; x"},
                    {"KIND": "issue", "ISSUE": "45", "REPO": "$(touch pwned)"},
                    {"KIND": "enrollment", "PR": "8", "NAME": "$(touch pwned)"}, {"KIND": "", "PR": "8"},
                    {"KIND": "other", "PR": "8"}):
            with self.subTest(env=env):
                self.assertEqual(self.prompt(**env), (2, {}))

    def test_a_review_without_a_held_finding_keeps_its_session(self):
        run, comment, verdicts, held, output, last = self.result(
            {"comment": "Thanks.\n\n1. Fix X.\n", "held": "", "verdicts": {"F2": "pass", "F7": "fail"}})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(comment, "Thanks.\n\n1. Fix X.\n\n")
        self.assertEqual(json.loads(verdicts), {"F2": "pass", "F7": "fail"})
        self.assertEqual(output, {"comment": "Thanks.\n\n1. Fix X.\n"})
        self.assertEqual(last, f"session=09227178-7bbf-4e5f-86db-8736e530ef01 head={'1' * 40}\n")

    def test_a_held_finding_stays_out_of_the_draft_and_its_session_is_not_kept(self):
        run, comment, verdicts, held, output, last = self.result(
            {"comment": "Thanks.\n\nA finding was sent for private review.\n", "held": ReviewHeld.HELD,
             "verdicts": {"F2": "pass", "F7": "pass"}})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("SECRETBUG", comment + verdicts + run.stdout + run.stderr)
        self.assertEqual(held, "<!-- held finding -->\n" + ReviewHeld.HELD + "\n")
        self.assertEqual(output, {"comment": "Thanks.\n\nA finding was sent for private review.\n", "held": "yes"})
        self.assertIsNone(last)

    def test_a_result_without_a_structured_output_fails_the_step(self):
        run, comment, _, _, _, last = self.result(None)
        self.assertNotEqual(run.returncode, 0)
        self.assertIsNone(last)

    # bootstrap/'s stack outputs in agent-infra, read with `pulumi stack output --stack prod` after the apply of
    # 2026-10-31 that made the federated identity ossv-review-github and the Service svc:spend (INFRA-832 S1a):
    # ossvReviewTailnetClientId, and spendCollectorTailnetUrl, http:// and the Service's IPv4 address.
    CLIENT_ID = "TWbBfz7fqc11CNTRL-kwYSkwdwGN11CNTRL"
    COLLECTOR_URL = "http://100.116.58.240"

    def test_the_job_joins_the_tailnet_as_ossv_review(self):
        join = self.steps["Join Theorem's tailnet, to export this review's usage"]
        self.assertEqual(join["uses"],
                         "tailscale/github-action@99a8333667fff04fdd6cffb46dfd409f8329a7bf")
        self.assertEqual(join["id"], "tailnet")
        # The join never decides whether a review runs.
        self.assertIs(join["continue-on-error"], True)
        # Exactly these settings: another one, `args:` for example, would change how the node joins while the join
        # still passed. `version:` is forbidden here too, so the action keeps its own default, 1.104.2, which is
        # above the 1.94 a Linux device needs to reach a Tailscale Service's address.
        self.assertEqual(set(join["with"]),
                         {"oauth-client-id", "audience", "tags", "hostname", "use-cache", "log-mode"})
        self.assertEqual(join["with"]["oauth-client-id"], "${{ env.TAILNET_CLIENT_ID }}")
        self.assertEqual(join["with"]["audience"], "theorem.dev/tailnet/ossv-review")
        self.assertEqual(join["with"]["tags"], "tag:ossv-review")
        # One review job runs in a run attempt, so the run id and the attempt name the node.
        self.assertEqual(join["with"]["hostname"],
                         "ossv-review-${{ github.run_id }}-${{ github.run_attempt }}")
        # The Actions cache of this job holds the review's session alone, so the action keeps no binary in it.
        self.assertIs(join["with"]["use-cache"], False)
        # This public repository's log never shows the action's commands, even on a re-run with debug logging: with
        # another log-mode, the action prints the `tailscale up` command, which carries this job's GitHub identity
        # token, and the output of `tailscale status --json`, the tailnet's nodes.
        self.assertEqual(join["with"]["log-mode"], "quiet")
        self.assertEqual(join["timeout-minutes"], 3)
        # The node is ephemeral: the logout deletes it at once, whatever the review did and whatever the join's
        # outcome. Neither the join, the export nor the logout may stop the steps that keep the draft, the verdicts
        # and a held finding.
        self.assertIs(self.steps["Export the review's usage to the cost collector"]["continue-on-error"], True)
        leave = self.steps["Leave the tailnet"]
        self.assertEqual(leave["if"], "always()")
        self.assertIs(leave["continue-on-error"], True)
        self.assertEqual(leave["timeout-minutes"], 2)
        names = [s.get("name") for s in self.jobs["review"]["steps"]]
        self.assertLess(names.index("Review"), names.index("Leave the tailnet"))
        self.assertLess(names.index("Leave the tailnet"),
                        names.index("Keep the draft, and the held finding apart from it"))

    def test_the_review_job_outlives_the_caps_of_its_steps(self):
        # A job cancelled at its own cap keeps no draft and no verdicts, so the job's cap holds every step's.
        job = self.jobs["review"]
        steps = sum(step["timeout-minutes"] for step in job["steps"] if "timeout-minutes" in step)
        self.assertGreater(job["timeout-minutes"], steps)

    def test_the_tailnet_client_id_is_the_one_tailscale_gave(self):
        self.assertEqual(self.jobs["review"]["env"]["TAILNET_CLIENT_ID"], self.CLIENT_ID)

    def test_the_collector_url_is_the_collector_tailnet_address(self):
        # One URL for every sender, and it holds the address, because linux28-agents-1 joins the tailnet with
        # --accept-dns=false and resolves no MagicDNS name (INFRA-832).
        self.assertEqual(self.jobs["review"]["env"]["SPEND_COLLECTOR_URL"], self.COLLECTOR_URL)

    def leave(self, installed):
        """The logout step, with a stand-in sudo that records its arguments, and a stand-in tailscale or none."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            stand_ins = {"sudo": f"#!/bin/bash\nprintf '%s\\n' \"$*\" >> {shlex.quote(str(root / 'sudo'))}\n"}
            if installed:
                stand_ins["tailscale"] = "#!/bin/bash\nexit 0\n"
            for name, text in stand_ins.items():
                (root / "bin" / name).write_text(text)
                (root / "bin" / name).chmod(0o755)
            # PATH holds the stand-ins alone, so a tailscale of the machine that runs the tests is not found.
            run = subprocess.run([shutil.which("bash"), "-e", "-c", self.steps["Leave the tailnet"]["run"]], cwd=root,
                                 capture_output=True, text=True, env={"PATH": str(root / "bin")})
            return run, (root / "sudo").read_text() if (root / "sudo").exists() else ""

    def test_the_logout_passes_when_the_join_installed_no_tailscale(self):
        run, sudo = self.leave(installed=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sudo, "tailscale logout\n")
        run, sudo = self.leave(installed=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sudo, "")

    def test_no_step_reads_the_collector_token(self):
        text = (ROOT / ".github" / "workflows" / "build.yaml").read_text()
        self.assertNotIn("agent-spend-otel-token", text)
        self.assertNotIn("agent-otel-public", text)
        self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS", text)
        self.assertNotIn("Sign in to Google Cloud, for the cost collector's token", text)
        # One URL for every sender, the address in SPEND_COLLECTOR_URL: no step and no comment of the file names
        # the tailnet's MagicDNS domain, which linux28-agents-1, a sender that joins with --accept-dns=false,
        # cannot resolve.
        self.assertNotIn("ts.net", text)

    def export(self, outcome, name="libreac", kind="enrollment", answers=True):
        """The export step, with the job's own SPEND_COLLECTOR_URL as Actions gives it, and a stand-in curl that
        records its arguments and answers, or fails as a refused connection does (exit status 7)."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "bin" / "curl").write_text(f"#!/bin/bash\nprintf '%s\\n' \"$@\" >> {shlex.quote(str(root / 'curl'))}\n"
                                               f"exit {0 if answers else 7}\n")
            (root / "bin" / "curl").chmod(0o755)
            step = self.steps["Export the review's usage to the cost collector"]
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=root, capture_output=True, text=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "GITHUB_ENV": str(root / "env"), "TAILNET": outcome, "NAME": name, "KIND": kind,
                                      "SPEND_COLLECTOR_URL": self.jobs["review"]["env"]["SPEND_COLLECTOR_URL"]})
            env, curl = ((root / f).read_text() if (root / f).exists() else "" for f in ("env", "curl"))
            return run, env, curl

    def test_the_export_names_the_tailnet_endpoint_and_no_header(self):
        run, env, curl = self.export("success")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, "")
        # The probe: one GET of the collector's address, for at most 10 seconds.
        self.assertEqual(curl, f"-q\n-sS\n--max-time\n10\n-o\n/dev/null\n{self.COLLECTOR_URL}\n")
        self.assertEqual(env, "CLAUDE_CODE_ENABLE_TELEMETRY=1\nOTEL_LOGS_EXPORTER=otlp\nOTEL_METRICS_EXPORTER=none\n"
                         "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n"
                         "OTEL_EXPORTER_OTLP_ENDPOINT=http://100.116.58.240\n"
                         "OTEL_RESOURCE_ATTRIBUTES=theorem.project=oss-verify,theorem.subproject=libreac,"
                         "theorem.lane=enroll-review-ci,theorem.credential=oss-verify-ci\n")
        self.assertNotIn("Authorization", env)
        self.assertNotIn("SPEND_COLLECTOR_URL",
                         self.steps["Export the review's usage to the cost collector"]["env"])
        # A change and an issue keep their own subproject, as they did with the token.
        for kind in ("change", "issue"):
            with self.subTest(kind=kind):
                _, env, _ = self.export("success", name="", kind=kind)
                self.assertIn(f"theorem.subproject=_{kind},", env)

    def test_review_runs_when_the_tailnet_join_fails(self):
        for outcome in ("failure", "skipped", ""):
            with self.subTest(outcome=outcome):
                run, env, curl = self.export(outcome)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn("::warning::", run.stdout)
                self.assertIn("tailnet", run.stdout)
                self.assertEqual(env, "")
                self.assertEqual(curl, "")
        # The Review step comes after the export and has no condition of its own, so it runs either way.
        names = [s.get("name") for s in self.jobs["review"]["steps"]]
        self.assertLess(names.index("Export the review's usage to the cost collector"), names.index("Review"))
        self.assertNotIn("if", self.steps["Review"])

    def test_review_runs_when_the_collector_does_not_answer(self):
        run, env, curl = self.export("success", answers=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"::warning::The cost collector did not answer at '{self.COLLECTOR_URL}' on the tailnet",
                      run.stdout)
        self.assertEqual(env, "")
        self.assertTrue(curl.endswith(f"{self.COLLECTOR_URL}\n"))


@unittest.skipUnless(shutil.which("jq"), "needs jq, which the gh stand-in runs the script's filters with")
class IssueDraftCap(unittest.TestCase):
    """.github/scripts/issue-draft-cap, build.yaml's step "Hold the draft at the hourly cap", with a stand-in gh: it
    counts the other runs for one repository's issue drafts in the last hour whose review reached the model, and holds
    the draft at the cap or on a failed read with a ::error::HELD annotation and exit status 1."""

    def cap(self, runs, skipped=(), held=(), stopped=(), fail=None, run_id="99", source_repo="oss-verify"):
        """runs: ids, or (id, event, title) triples, that the runs API lists; skipped: the ids whose review job was
        skipped; held: the ids whose step "Hold the draft at the hourly cap" failed; stopped: the ids whose step
        "Stop before the model when the draft cannot be stored" failed (a refused sign-in); fail: "runs", or the id
        whose jobs cannot be read. Return the exit status, the output and gh's calls."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            records = [{"id": item, "event": "issues", "display_title": "Issue 5"}
                       if isinstance(item, int) else {"id": item[0], "event": item[1], "display_title": item[2]}
                       for item in runs]
            ids = [record["id"] for record in records]
            (root / "runs.json").write_text(json.dumps({"workflow_runs": records}))
            (root / "issue-runs.json").write_text(json.dumps(
                {"workflow_runs": [record for record in records if record["event"] == "issues"]}))
            for i in ids:
                gate = "skipped" if i in held else "failure" if i in stopped else "success"
                model = "skipped" if i in held or i in stopped else "success"
                review = {"name": "review",
                          "conclusion": "skipped" if i in skipped else "failure" if i in held or i in stopped else None,
                          "steps": [{"name": "Set up job", "conclusion": "success"},
                                    {"name": "Hold the draft at the hourly cap",
                                     "conclusion": "failure" if i in held else "success"},
                                    {"name": "Sign in to Google Cloud, to check that an issue's draft can be stored",
                                     "conclusion": "skipped" if i in held else "success"},
                                    {"name": "Stop before the model when the draft cannot be stored", "conclusion": gate},
                                    {"name": "Review", "conclusion": model}]}
                (root / f"jobs-{i}.json").write_text(json.dumps({"jobs": [
                    {"name": "route", "conclusion": "success", "steps": []}, review]}))
            listing = ('echo "gh: HTTP 502" >&2; exit 1' if fail == "runs"
                       else f'if [[ " $*" == *" event=issues "* ]]; then jq -r "$filter" {root}/issue-runs.json; '
                       f'else jq -r "$filter" {root}/runs.json; fi')
            (root / "bin" / "gh").write_text(
                "#!/bin/bash\n"
                'filter=""; path=""; for a; do [ "$prev" = --jq ] && filter=$a; [[ $a == repos/* ]] && path=$a; prev=$a; done\n'
                f'echo "$*" >> {root}/calls\n'
                'case "$path" in\n'
                f'  */workflows/build.yaml/runs) {listing} ;;\n'
                f'  */runs/{fail}/jobs*) echo "gh: HTTP 502" >&2; exit 1 ;;\n'
                f'  */runs/*/jobs*) id=${{path#*/runs/}}; id=${{id%%/*}}; jq -r "$filter" {root}/jobs-$id.json ;;\n'
                '  *) exit 1 ;;\n'
                "esac\n")
            (root / "bin" / "gh").chmod(0o755)
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "issue-draft-cap")], capture_output=True, text=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x",
                                      "RUNS_REPO": "theorem-labs/oss-verify", "RUN_ID": run_id, "CAP": "6",
                                      "SOURCE_REPO": source_repo})
            return run.returncode, run.stdout, (root / "calls").read_text()

    def test_under_the_cap_the_draft_is_made(self):
        # Five drafts ran; three runs of the hour skipped the review (route found the event ours), and one is this run.
        code, out, calls = self.cap([*range(1, 9), 99], skipped=(6, 7, 8))
        self.assertEqual(code, 0, out)
        self.assertIn("5 issue drafts ran the model in the last hour, under the cap of 6", out)
        self.assertNotIn("HELD", out)
        self.assertNotIn("event=issues", calls)
        self.assertIn("created=>=", calls)
        self.assertNotIn("runs/99/jobs", calls)

    def test_a_run_the_cap_held_is_not_counted(self):
        # Seven qualifying events in the hour: five drafted, one held at the cap, and this one. The held run called no
        # model, so this draft is made.
        code, out, _ = self.cap([*range(1, 7), 99], held=(6,))
        self.assertEqual(code, 0, out)
        self.assertIn("5 issue drafts ran the model in the last hour, under the cap of 6", out)
        # A person's re-run after six held runs is made too.
        code, out, _ = self.cap([*range(1, 7), 99], held=range(1, 7))
        self.assertEqual(code, 0, out)
        self.assertIn("0 issue drafts ran the model", out)

    def test_a_run_stopped_at_the_sign_in_is_not_counted(self):
        # A run whose Google sign-in was refused stopped before the model: it is not counted, so it leaves the count as
        # it was. Five drafted, six stopped, and this one: the draft is made.
        code, out, _ = self.cap([*range(1, 12), 99], stopped=range(6, 12))
        self.assertEqual(code, 0, out)
        self.assertIn("5 issue drafts ran the model in the last hour, under the cap of 6", out)

    def test_at_the_cap_the_draft_is_held_and_the_step_fails(self):
        code, out, _ = self.cap([*range(1, 8), 99], held=(7,))
        self.assertEqual(code, 1)
        self.assertIn("::error::HELD: 6 issue drafts ran the model in the last hour, at the cap of 6.", out)

    def test_each_source_repository_has_its_own_cap(self):
        # Six drafts of each of the three repositories in the hour: each repository counts only its own six.
        runs = [(n, "issues", f"Issue {n}") for n in range(1, 7)]
        runs += [(10 + n, "workflow_dispatch", f"Issue oss-verify-proofs#{n}") for n in range(1, 7)]
        runs += [(20 + n, "workflow_dispatch", f"Issue rocq-linux-process-semantics#{n}") for n in range(1, 7)]
        for repo in ("oss-verify", "oss-verify-proofs", "rocq-linux-process-semantics"):
            with self.subTest(repo=repo):
                code, out, _ = self.cap(runs, source_repo=repo)
                self.assertEqual(code, 1, out)
                self.assertIn("::error::HELD: 6 issue drafts ran the model in the last hour, at the cap of 6.", out)
                # Five of its own and the twelve of the other two repositories: under the cap.
                own = {"oss-verify": 6, "oss-verify-proofs": 16, "rocq-linux-process-semantics": 26}[repo]
                code, out, _ = self.cap([r for r in runs if r[0] != own], source_repo=repo)
                self.assertEqual(code, 0, out)
                self.assertIn("5 issue drafts ran the model in the last hour, under the cap of 6", out)

    def test_this_repositorys_cap_counts_issue_events_only(self):
        # As on main: a person's run for an issue of this repository, started by hand, is neither held nor counted.
        runs = [(n, "workflow_dispatch", f"Issue {n}") for n in range(1, 7)]
        code, out, _ = self.cap(runs)
        self.assertEqual(code, 0, out)
        self.assertIn("0 issue drafts ran the model in the last hour, under the cap of 6", out)

    def test_another_repository_issue_draft_hits_its_hourly_cap(self):
        for repo in ("oss-verify-proofs", "rocq-linux-process-semantics"):
            with self.subTest(repo=repo):
                runs = [(number, "workflow_dispatch", f"Issue {repo}#{number}") for number in range(1, 7)]
                code, out, calls = self.cap(runs, source_repo=repo)
                self.assertEqual(code, 1)
                self.assertIn("::error::HELD: 6 issue drafts ran the model in the last hour, at the cap of 6.", out)
                self.assertNotIn("event=issues", calls)

    def test_a_pull_request_titled_as_an_issue_is_not_counted(self):
        # A pull request's run carries the pull request's title, which its author chooses. Such titles never count
        # towards an issue draft cap, for this repository or for another one.
        for repo, title in (("oss-verify", "Issue 5"), ("oss-verify-proofs", "Issue oss-verify-proofs#5"),
                            ("rocq-linux-process-semantics", "Issue rocq-linux-process-semantics#5")):
            with self.subTest(repo=repo):
                runs = [(number, "pull_request_target", title) for number in range(1, 7)]
                code, out, _ = self.cap(runs, source_repo=repo)
                self.assertEqual(code, 0, out)
                self.assertIn("0 issue drafts ran the model in the last hour, under the cap of 6", out)

    def test_a_read_that_fails_holds_the_draft(self):
        for fail in ("runs", 3):
            with self.subTest(fail=fail):
                code, out, _ = self.cap(list(range(1, 5)), fail=fail)
                self.assertEqual(code, 1)
                self.assertIn("::error::HELD: ", out)


class StoreSignInGate(unittest.TestCase):
    """build.yaml's step "Stop before the model when the draft cannot be stored", run as it is: for an issue, a
    refused Google sign-in before the model fails the job there, red, with ::error:: and a summary naming the
    cause."""

    def gate(self, outcome, event="issues"):
        flow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        [step] = [s for s in flow["jobs"]["review"]["steps"]
                  if s.get("name") == "Stop before the model when the draft cannot be stored"]
        with tempfile.TemporaryDirectory() as directory:
            summary = pathlib.Path(directory) / "summary"
            run = subprocess.run(["bash", "-e", "-c", step["run"]], capture_output=True, text=True,
                                 env={**os.environ, "SIGN_IN": outcome, "EVENT": event,
                                      "GITHUB_STEP_SUMMARY": str(summary)})
            return run.returncode, run.stdout, summary.read_text() if summary.exists() else ""

    def test_a_refused_sign_in_fails_the_job_before_the_model_and_says_why(self):
        for outcome in ("failure", "cancelled", ""):
            with self.subTest(outcome=outcome):
                code, out, summary = self.gate(outcome)
                self.assertEqual(code, 1)
                self.assertTrue(out.startswith("::error::NOT STORED: Google Cloud refused this run's sign-in"), out)
                self.assertIn("does not admit runs that an issue's event starts yet", out)
                self.assertIn("does not admit runs that an issue's event starts yet", summary)
                self.assertNotIn("HELD", out + summary)

    def test_a_refused_sign_in_on_a_run_started_by_hand_names_another_cause(self):
        # gh workflow run build.yaml -f issue=<n>: the provider admits workflow_dispatch already, so the issues
        # setting is not the cause.
        code, out, summary = self.gate("failure", event="workflow_dispatch")
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("::error::NOT STORED: Google Cloud refused this run's sign-in"), out)
        self.assertNotIn("an issue's event", out + summary)
        self.assertIn("The provider admits a run started by hand, so the cause is elsewhere", out)
        self.assertIn("identity provider for this repository and its service account", summary)

    def test_an_admitted_sign_in_goes_on_to_the_model(self):
        for event in ("issues", "workflow_dispatch"):
            with self.subTest(event=event):
                self.assertEqual(self.gate("success", event), (0, "", ""))


@unittest.skipUnless(shutil.which("jq"), "needs jq, which the gh stand-in runs the script's filters with")
class ChangeReviewSession(unittest.TestCase):
    """A change review resumes its last session for context: review-gather takes the head that review reviewed from
    the runs API, and the session's id from the cache only when the cache names that head."""

    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        self.jobs = self.workflow["jobs"]
        self.steps = {s.get("name"): s for s in self.jobs["review"]["steps"]}

    # A change review of pull request 34 at HEAD, in Build run 900 of theorem-labs/oss-verify.
    HEAD, LAST, OLDER, FAILED, CACHED = "e" * 40, "b" * 40, "a" * 40, "f" * 40, "d" * 40
    SESSION = "09227178-7bbf-4e5f-86db-8736e530ef01"
    # A stand-in for gh: `gh pr view` and `gh pr diff`, and `gh api` answered from state.json by its path without the
    # query, with the script's own --jq filter applied by the real jq; a compare gives its status (ahead when the base
    # is in state["ahead"]), or with the diff media type the diff. It records every call.
    GATHER_GH = r'''#!@@PYTHON@@
import json, pathlib, subprocess, sys
root = pathlib.Path(@@ROOT@@)
a = sys.argv[1:]
with open(root / "calls", "a") as f:
    f.write(json.dumps(a) + "\n")
if a[:2] == ["pr", "view"]:
    sys.exit(print("{}"))
if a[:2] == ["pr", "diff"]:
    sys.exit(print("the whole diff against the base"))
state = json.loads((root / "state.json").read_text())
path = next(x for x in a if x.startswith("repos/")).split("?")[0]
if "/compare/" in path:
    base, head = path.split("/compare/")[1].split("...")
    if "Accept: application/vnd.github.diff" in a:
        sys.exit(print(f"diff from {base} to {head}"))
    answer = {"status": "ahead" if base in state["ahead"] else "diverged"}
else:
    # The pull request's files and review comments: none.
    answer = state.get(path, [])
if "--jq" in a:
    sys.stdout.flush()
    sys.stdout.buffer.write(subprocess.run(["jq", "-r", a[a.index("--jq") + 1]], input=json.dumps(answer).encode(),
                                           capture_output=True, check=True).stdout)
else:
    print(json.dumps(answer))
'''

    def gather_change(self, repo, runs, reviews, last_review, pull=None, ahead=()):
        """review-gather for the change review of pull request 34 of `repo`: `runs` the runs API's Build runs, newest
        first; `reviews` {run id: its review job's conclusion}; `last_review` the file of the cache (None: none);
        `pull` the pull request as the API gives it. Return the run, its output, since-last-review.diff, pr.diff and
        gh's calls."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            runs_path = "repos/theorem-labs/oss-verify/actions/workflows/build.yaml/runs"
            state = {"ahead": list(ahead), runs_path: {"workflow_runs": runs}}
            for run_id, conclusion in reviews.items():
                state[f"repos/theorem-labs/oss-verify/actions/runs/{run_id}/jobs"] = {"jobs": [
                    {"name": "route", "conclusion": "success"}, {"name": "review", "conclusion": conclusion}]}
            if pull is not None:
                state[f"repos/{repo}/pulls/34"] = pull
            (root / "state.json").write_text(json.dumps(state))
            (root / "bin" / "gh").write_text(
                self.GATHER_GH.replace("@@PYTHON@@", sys.executable).replace("@@ROOT@@", repr(str(root))))
            (root / "bin" / "gh").chmod(0o755)
            if last_review is not None:
                (root / "last-review").write_text(last_review)
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-gather"), str(root / "out")], cwd=ROOT,
                                 capture_output=True, text=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x",
                                      "KIND": "change", "REPO": repo, "PR": "34", "NAME": "", "HEAD_SHA": self.HEAD,
                                      "LAST_REVIEW": str(root / "last-review"), "RUNS_REPO": "theorem-labs/oss-verify",
                                      "RUN_ID": "900", "GITHUB_OUTPUT": str(root / "output")})
            read = lambda path: path.read_text() if path.exists() else None
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            return (run, read(root / "output") or "", read(root / "out" / "since-last-review.diff"),
                    read(root / "out" / "pr.diff"), calls)

    @staticmethod
    def dispatched(run_id, title, event="workflow_dispatch", branch="main"):
        """A Build run of theorem-labs/oss-verify as the runs API lists it."""
        return {"id": run_id, "event": event, "head_branch": branch, "path": ".github/workflows/build.yaml",
                "display_title": title, "head_sha": "9" * 40, "head_repository": {"full_name": "theorem-labs/oss-verify"}}

    def test_a_change_review_restores_its_session_by_repository_and_number(self):
        # The cache key, evaluated: one key for each repository and number, and none is the start of another, which
        # restore-keys would match.
        key = self.jobs["review"]["env"]["CHANGE_KEY"]
        keys = [evaluate(key, {"inputs": {"repo": repo, "pr": number}})
                for repo in ("oss-verify", "oss-verify-proofs", "rocq-linux-process-semantics") for number in (1, 10)]
        self.assertEqual(keys[2], "review-oss-verify-proofs-1-")
        self.assertFalse([(a, b) for a in keys for b in keys if a != b and a.startswith(b)])
        self.assertEqual(evaluate(key, {"github": {"event": {"pull_request": {"number": 7}}}}), "review-oss-verify-7-")

    def test_last_comes_from_the_runs_api_not_the_cache(self):
        name = "rocq-linux-process-semantics"
        cached = f"session={self.SESSION} head={self.LAST}\n"
        runs = [self.dispatched(950, f"Review {name}#34 at {'3' * 40}"),  # made after this run
                self.dispatched(900, f"Review {name}#34 at {self.HEAD}"),  # this run
                self.dispatched(890, f"Review {name}#34 at {self.FAILED}"),  # its review failed
                # A pull request of this repository can take any title; a run on another branch is not main's.
                self.dispatched(880, f"Review {name}#34 at {'0' * 40}", event="pull_request_target"),
                self.dispatched(875, f"Review {name}#34 at {'0' * 40}", branch="ci/x"),
                self.dispatched(870, f"Review {name}#340 at {'1' * 40}"),
                self.dispatched(865, f"Review oss-verify-proofs#34 at {'2' * 40}"),
                self.dispatched(860, f"Review {name}#34 at {self.LAST}"),
                self.dispatched(850, f"Review {name}#34 at {self.OLDER}")]
        reviews = {950: "success", 900: None, 890: "failure", 880: "success", 875: "success", 870: "success",
                   865: "success", 860: "success", 850: "success"}
        run, output, since, _, calls = self.gather_change(f"theorem-labs/{name}", runs, reviews, cached,
                                                          ahead=(self.LAST, self.OLDER, self.CACHED))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, f"session={self.SESSION}\nlast={self.LAST}\n")
        self.assertEqual(since, f"diff from {self.LAST} to {self.HEAD}\n(exit status 0)\n")
        # The session itself comes from the cache: with no cache entry, the review is fresh.
        self.assertEqual(self.gather_change(f"theorem-labs/{name}", runs, reviews, None, ahead=(self.LAST,))[1], "")
        # No earlier review that succeeded: fresh, whatever head the cache names.
        self.assertEqual(self.gather_change(f"theorem-labs/{name}", runs[2:3], {890: "failure"},
                                            f"session={self.SESSION} head={self.LAST}\n", ahead=(self.LAST,))[1], "")
        # A pull request of this repository: its own events' runs, of its head branch in its head repository.
        pull = {"head": {"ref": "fix-x", "repo": {"full_name": "someone/oss-verify"}}}
        own = lambda run_id, sha, fork="someone/oss-verify": {
            "id": run_id, "event": "pull_request_target", "head_branch": "fix-x", "display_title": "fix x",
            "path": ".github/workflows/build.yaml", "head_sha": sha, "head_repository": {"full_name": fork}}
        run, output, since, _, _ = self.gather_change(
            "theorem-labs/oss-verify",
            [own(900, self.HEAD), own(885, "2" * 40, fork="other/oss-verify"), own(880, self.LAST),
             own(870, self.OLDER), self.dispatched(860, "Pull request 34")],
            {885: "success", 880: "success", 870: "success", 860: "success"}, cached, pull=pull, ahead=(self.LAST,))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output, f"session={self.SESSION}\nlast={self.LAST}\n")

    def test_a_session_kept_for_another_head_is_not_resumed(self):
        # The runs API names the head the last review reviewed; the session in the cache was kept for another head (the
        # save of that review did not happen, or the cache holds an older run's session). It is not resumed, and the
        # head the cache names is never read.
        name = "rocq-linux-process-semantics"
        runs = [self.dispatched(860, f"Review {name}#34 at {self.LAST}")]
        run, output, since, _, calls = self.gather_change(
            f"theorem-labs/{name}", runs, {860: "success"}, f"session={self.SESSION} head={self.CACHED}\n",
            ahead=(self.LAST, self.CACHED))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((output, since), ("", None))
        self.assertIn(f"the session in the cache was kept for {self.CACHED}, not {self.LAST}: the review is fresh",
                      run.stdout)
        self.assertFalse([c for c in calls if self.CACHED in json.dumps(c) or "/compare/" in json.dumps(c)])

    def test_checks_4_and_5_read_the_whole_diff_against_main(self):
        env = {"KIND": "change", "PR": "34", "REPO": "theorem-labs/rocq-linux-process-semantics", "HEAD_SHA": self.HEAD}
        code, resumed = ReviewJob.prompt(self, **env, SESSION=self.SESSION, LAST=self.LAST)
        self.assertEqual(code, 0)
        self.assertIn("pull request #34 of theorem-labs/rocq-linux-process-semantics", resumed["prompt"])
        self.assertIn(f".review/since-last-review.diff, the diff from {self.LAST} to {self.HEAD}, is an aid for checks 1 "
                      "to 3 only. Judge checks 4 and 5 on the whole diff of the pull request against its base, "
                      ".review/pr.diff, as on a first review.", resumed["prompt"])
        self.assertNotIn("since-last-review", ReviewJob.prompt(self, **env)[1]["prompt"])
        # The gather writes that whole diff whether or not the review resumes.
        name = "rocq-linux-process-semantics"
        _, output, since, whole, _ = self.gather_change(
            f"theorem-labs/{name}", [self.dispatched(860, f"Review {name}#34 at {self.LAST}")], {860: "success"},
            f"session={self.SESSION} head={self.LAST}\n", ahead=(self.LAST,))
        self.assertTrue(output and since)
        self.assertEqual(whole, "the whole diff against the base\n")


class Owners(unittest.TestCase):

    def test_only_the_review_files_the_skill_and_codeowners_have_an_owner_and_are_the_last_patterns(self):
        lines = [line.split() for line in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        owned = [["/review.md", "@theorem-labs/engineering"],
                 ["/review-change.md", "@theorem-labs/engineering"],
                 ["/review-issue.md", "@theorem-labs/engineering"],
                 ["/.claude/skills/write-to-maintainer/", "@theorem-labs/engineering"],
                 ["/.github/CODEOWNERS", "@theorem-labs/engineering"]]
        self.assertEqual([line for line in lines if len(line) > 1], owned)
        self.assertEqual(lines[-5:], owned)
        self.assertTrue(all((ROOT / name).is_file() for name in ("review.md", "review-change.md", "review-issue.md")))


class Starters(unittest.TestCase):
    """The starter workflows of theorem-labs/oss-verify-proofs and theorem-labs/rocq-linux-process-semantics, whose copies
    are in .github/starters/: their steps' own scripts, run here with the env GitHub gives them on an event and with a
    stand-in gh. What only the workflow file holds (its triggers, environment and token inputs) is proved on a run."""

    NAMES = ("oss-verify-proofs", "rocq-linux-process-semantics")
    TOKEN = "ghs_stand-in-not-a-secret"

    @staticmethod
    def starter(name):
        return yaml.safe_load((ROOT / ".github" / "starters" / f"{name}.yml").read_text())

    def steps(self, name):
        [job] = self.starter(name)["jobs"].values()
        return {s["name"]: s for s in job["steps"]}

    def event(self, name, current="e" * 40, **values):
        """The starter's first step, with the env GitHub gives it on an event of `values` (pull_request, issue, sender,
        event_name), and a stand-in gh whose pull request 34 has the head `current`. Return its exit status, its
        outputs and gh's calls."""
        step = self.steps(name)["Read what to start from the event"]
        context = {"github": {"event_name": values.get("event_name", "pull_request_target"), "token": "x",
                              "event": {k: v for k, v in values.items() if k != "event_name"}}}
        env = {k: as_text(evaluate(v, context)) if "${{" in str(v) else str(v) for k, v in step["env"].items()}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "pull.json").write_text(json.dumps({"head": {"sha": current}}))
            (root / "bin" / "gh").write_text(
                '#!/bin/bash\n[ "$GH_TOKEN" = x ] || { echo "missing token" >&2; exit 1; }\n'
                'filter=""; for a; do [ "$prev" = --jq ] && filter=$a; prev=$a; done\n'
                f'echo "$*" >> {root}/calls\n'
                f'case "$*" in "api repos/theorem-labs/{name}/pulls/34 --jq .head.sha") jq -r "$filter" {root}/pull.json ;; '
                '*) exit 1 ;; esac\n')
            (root / "bin" / "gh").chmod(0o755)
            output = root / "output"
            run = subprocess.run(["bash", "-e", "-c", step["run"]], capture_output=True, text=True,
                                 env={**os.environ, **env, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "GITHUB_OUTPUT": str(output)})
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
            calls = (root / "calls").read_text() if (root / "calls").exists() else ""
        return run.returncode, outputs, calls

    def test_it_starts_only_values_of_their_shape_read_from_the_event_and_the_pull_request(self):
        # (4) The repository from the fixed list, the pull request's number from the event and its head as the API
        # gives it when the step runs, or the issue's number; each must have its shape, or nothing starts. The head is
        # read when the step runs, not taken from the event: a run that waited in the group behind an older event's
        # run starts the review of the newest head, so a later push is never left unreviewed.
        event_head, newest = "c" * 40, "e" * 40
        for name in self.NAMES:
            with self.subTest(name=name):
                code, outputs, calls = self.event(name, pull_request={"number": 34, "head": {"sha": event_head}})
                self.assertEqual((code, outputs), (0, {"repo": name, "pr": "34", "head": newest}))
                self.assertIn(f"repos/theorem-labs/{name}/pulls/34", calls)
                alice = {"login": "alice"}
                code, outputs, calls = self.event(name, event_name="issues", sender=alice,
                                                  issue={"number": 5, "user": alice, "author_association": "NONE"})
                self.assertEqual((code, outputs, calls), (0, {"repo": name, "issue": "5"}, ""))
                for pull, current in (({"number": "34; x", "head": {"sha": event_head}}, newest),
                                      ({"number": 34, "head": {"sha": event_head}}, newest[:7]),
                                      ({"number": 34, "head": {"sha": event_head}}, newest.upper()),
                                      ({"number": 34, "head": {"sha": event_head}}, "null")):
                    code, outputs, _ = self.event(name, current=current, pull_request=pull)
                    self.assertNotEqual(code, 0, (pull, current))
                    self.assertEqual(outputs, {}, (pull, current))
                code, outputs, _ = self.event(name, event_name="issues", sender=alice,
                                              issue={"number": "5x", "user": alice, "author_association": "NONE"})
                self.assertNotEqual(code, 0)
                self.assertEqual(outputs, {})
                # An issue's event that is ours starts nothing, and succeeds.
                for sender, author, association in (("carol", "carol", "MEMBER"), ("o", "o", "OWNER"),
                                                    ("oss-verify[bot]", "oss-verify[bot]", "NONE"),
                                                    ("carol", "alice", "NONE")):
                    self.assertEqual(self.event(name, event_name="issues", sender={"login": sender},
                                                issue={"number": 5, "user": {"login": author},
                                                       "author_association": association}), (0, {}, ""), sender)
        # A name outside the list is refused, so a copy that names another repository starts nothing.
        step = self.steps(self.NAMES[0])["Read what to start from the event"]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "bin" / "gh").write_text(
                f'#!/bin/bash\necho called > {root}/called\necho {"e" * 40}\n')
            (root / "bin" / "gh").chmod(0o755)
            output = root / "output"
            run = subprocess.run(["bash", "-e", "-c", step["run"]], capture_output=True, text=True,
                                 env={**os.environ, **{k: "" for k in step["env"]}, "NAME": "oss-verify-proofs-internal",
                                      "EVENT": "pull_request_target", "PR": "34", "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "GITHUB_OUTPUT": str(output)})
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse((root / "called").exists())

    def start(self, name, outputs):
        """The starter's start step, with the token and the first step's outputs, and a stand-in gh that records its
        arguments and whether it got the token in GH_TOKEN. Return the run, gh's arguments and every file left."""
        step = self.steps(name)["Start OSS Verify's review in theorem-labs/oss-verify"]
        context = {"steps": {"app": {"outputs": {"token": self.TOKEN}}, "event": {"outputs": outputs}}}
        env = {k: as_text(evaluate(v, context)) for k, v in step["env"].items()}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "bin" / "gh").write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$OUT/gh-argv"\n'
                                             f'[ "$GH_TOKEN" = {shlex.quote(self.TOKEN)} ] && : > "$OUT/gh-token"\n')
            (root / "bin" / "gh").chmod(0o755)
            (root / "out").mkdir()
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=root / "out", capture_output=True, text=True,
                                 env={**os.environ, **env, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "OUT": str(root / "out"), "GITHUB_STEP_SUMMARY": str(root / "out" / "summary")})
            files = {p.name: p.read_text() for p in (root / "out").iterdir()}
        return run, files.pop("gh-argv", "").splitlines(), files

    def test_the_token_reaches_gh_only_in_gh_token_of_the_start_step(self):
        # (5) One step gets the token, in GH_TOKEN, and it never prints it or writes it to a file.
        head = "c" * 40
        for name in self.NAMES:
            with self.subTest(name=name):
                steps = self.steps(name)
                for outputs, argv in (
                        ({"repo": name, "pr": "34", "head": head},
                         ["workflow", "run", "build.yaml", "-R", "theorem-labs/oss-verify", "--ref", "main",
                          "-f", f"repo={name}", "-f", "pr=34", "-f", f"head={head}"]),
                        ({"repo": name, "issue": "5"},
                         ["workflow", "run", "build.yaml", "-R", "theorem-labs/oss-verify", "--ref", "main",
                          "-f", f"repo={name}", "-f", "issue=5"])):
                    run, got, files = self.start(name, outputs)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(got, argv)
                    self.assertIn("gh-token", files)
                    for where in [run.stdout, run.stderr, *files.values(), *got]:
                        self.assertNotIn(self.TOKEN, where)
                # The token step and the start step run only when the first step found something to start.
                for step in (steps["Get the OSS Verify App's token, to start one run in theorem-labs/oss-verify"],
                             steps["Start OSS Verify's review in theorem-labs/oss-verify"]):
                    self.assertIs(evaluate(step["if"], {"steps": {"event": {"outputs": {}}}}), False)
                    self.assertIs(evaluate(step["if"], {"steps": {"event": {"outputs": {"repo": name}}}}), True)


@unittest.skipUnless(shutil.which("jq"), "needs jq, which the gh stand-in runs the step's filters with")
class ReviewRerun(unittest.TestCase):
    """review-rerun.yml, on each completed Build run: its one step, run with a stand-in gh, re-runs the failed jobs of
    a failed run of an enrollment pull request whose review job failed, up to the run's third attempt."""

    HEAD = "c" * 40
    ENROLLMENT = ["projects/zlib/project.yaml", "projects/zlib/build.sh"]

    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "review-rerun.yml").read_text())
        (self.job,) = self.workflow["jobs"].values()

    @staticmethod
    def jobs(review="failure", **others):
        """The jobs of one attempt of a Build run, by the names the API gives them: project-builds' job is "build", the
        required job is "project-builds" (build.yaml), and the review job has no name of its own."""
        jobs = {"route": "success", "build": "success", "review": review, "record": "success", "hold": "success",
                "comment": "skipped", "project-builds": "success" if review == "success" else "failure"}
        return {**jobs, **others}

    def rerun(self, attempt, jobs, pulls=None, run_id=40, fails=None, ok=True, lost=False):
        """Run the step for the completion of attempt `attempt` of Build run `run_id` at HEAD. jobs: {name: conclusion}
        of that attempt. pulls: {number: (head, paths)} or {number: (head, paths, draft)} of the open pull requests
        into main, the path "new<-old" for a rename (default: one enrollment at HEAD, ready for review). fails: {call:
        n}, the first n tries of that call ("jobs", "pulls", "files" or "rerun") fail, after printing a cut page. lost:
        GitHub takes the first re-run (the run moves to the next attempt) but its answer is lost. ok: whether the step
        must succeed. Return the re-runs GitHub took, the output and the summary; self.waits holds the waits it asked
        sleep for, and self.tries the tries of each call."""
        pulls = {5: (self.HEAD, self.ENROLLMENT)} if pulls is None else pulls
        pulls = {n: (p + (False,))[:3] for n, p in pulls.items()}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / f"jobs-{run_id}-{attempt}.json").write_text(json.dumps({"total_count": len(jobs), "jobs": [
                {"name": name, "status": "completed", "conclusion": conclusion, "run_attempt": attempt,
                 "head_branch": "$(touch pwned)"} for name, conclusion in jobs.items()]}))
            (root / "pulls.json").write_text(json.dumps(
                [{"number": n, "head": {"sha": head, "ref": "`touch pwned`"}, "base": {"ref": "main"}, "draft": draft}
                 for n, (head, paths, draft) in pulls.items()]))
            for number, (head, paths, draft) in pulls.items():
                (root / f"files-{number}.json").write_text(json.dumps(
                    [dict(zip(("filename", "previous_filename"), path.split("<-"))) for path in paths]))
            for call, n in (fails or {}).items():
                (root / f"fails-{call}").write_text(str(n))
            (root / "attempt-now").write_text(str(attempt))
            if lost:
                (root / "lose-first-rerun").write_text("")
            (root / "bin" / "gh").write_text(
                "#!/bin/bash\n"
                'filter=""; path=""; for a; do [ "$prev" = --jq ] && filter=$a\n'
                '  [[ $a == repos/* ]] && path=${path:-$a}; prev=$a; done\n'
                f'cd {root}\n'
                'echo "gh $*" >> calls\n'
                'case "$path" in\n'
                '  "") call=rerun ;;\n'
                '  repos/o/r/actions/runs/*/attempts/*/jobs\\?per_page=100) call=jobs ;;\n'
                '  repos/o/r/actions/runs/*) echo "{\\"run_attempt\\": $(cat attempt-now)}" | jq -r "$filter"\n'
                '    exit ;;\n'
                '  "repos/o/r/pulls?state=open&base=main&per_page=100") call=pulls ;;\n'
                '  repos/o/r/pulls/*/files\\?per_page=100) call=files ;;\n'
                '  *) echo "unexpected gh $*" >&2; exit 1 ;;\n'
                "esac\n"
                'try=$(( $(cat "tries-$call" 2>/dev/null || echo 0) + 1 )); echo "$try" > "tries-$call"\n'
                'if [ "$call" = rerun ] && [ -f lose-first-rerun ] && (( try == 1 )); then\n'
                '  echo "$*" >> reruns; echo $(( $(cat attempt-now) + 1 )) > attempt-now\n'
                '  echo "connection reset" >&2; exit 1\n'
                'fi\n'
                'if (( try <= $(cat "fails-$call" 2>/dev/null || echo 0) )); then\n'
                '  echo 99; echo "HTTP 502" >&2; exit 1\n'
                'fi\n'
                'case $call in\n'
                '  rerun) [ "$1 $2" = "run rerun" ] || { echo "unexpected gh $*" >&2; exit 1; }\n'
                '    echo "$*" >> reruns ;;\n'
                '  jobs) r=${path#repos/o/r/actions/runs/}; a=${r#*/attempts/}\n'
                '    jq -r "$filter" "jobs-${r%%/*}-${a%%/*}.json" ;;\n'
                '  pulls) jq -r "$filter" pulls.json ;;\n'
                '  files) n=${path#repos/o/r/pulls/}; jq -r "$filter" "files-${n%%/*}.json" ;;\n'
                "esac\n")
            (root / "bin" / "gh").chmod(0o755)
            (root / "bin" / "sleep").write_text(f'#!/bin/bash\necho "$1" >> {root}/waits\n')
            (root / "bin" / "sleep").chmod(0o755)
            (step,) = self.job["steps"]
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=root, capture_output=True, text=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x",
                                      "REPO": "o/r", "RUN_ID": str(run_id), "RUN_ATTEMPT": str(attempt),
                                      "HEAD_SHA": self.HEAD, "GITHUB_STEP_SUMMARY": str(root / "summary")})
            if ok:
                self.assertEqual(run.returncode, 0, run.stderr)
            else:
                self.assertNotEqual(run.returncode, 0, run.stdout)
            self.assertFalse((root / "pwned").exists())
            reruns = (root / "reruns").read_text().splitlines() if (root / "reruns").exists() else []
            summary = (root / "summary").read_text() if (root / "summary").exists() else ""
            self.waits = [int(w) for w in (root / "waits").read_text().split()] if (root / "waits").exists() else []
            self.tries = {p.name[len("tries-"):]: int(p.read_text()) for p in root.glob("tries-*")}
            return reruns, run.stdout, summary

    def test_a_failed_enrollment_review_is_re_run_at_attempt_1_and_2(self):
        # A review that fails for a short fault: a 401 of the model's API (2026-10-26), a 429 of its rate limit (pull
        # request 59, Build run 40523715526), or a job cancelled or out of time. A label from an earlier commit, or
        # none, changes nothing: the step reads none. A renamed file counts under both names.
        enrollment = self.ENROLLMENT + ["projects/zlib/fuzz.c<-projects/zlib/old_fuzz.c"]
        for attempt in (1, 2):
            for review in ("failure", "cancelled", "timed_out"):
                with self.subTest(attempt=attempt, review=review):
                    reruns, out, summary = self.rerun(attempt, self.jobs(review), {5: (self.HEAD, enrollment)})
                    self.assertEqual(reruns, ["run rerun 40 --failed -R o/r"])
                    self.assertEqual(summary.splitlines(), [
                        f"Pull request 5: the review job of Build run 40 ended {review} at attempt {attempt}; its "
                        "failed jobs run again."])

    def test_a_review_is_re_run_at_most_two_times_for_one_build_run(self):
        # Attempt 3 is the second re-run's; a fourth is a person's re-run by hand.
        for attempt in (3, 4):
            with self.subTest(attempt=attempt):
                reruns, out, summary = self.rerun(attempt, self.jobs())
                self.assertEqual(reruns, [])
                self.assertEqual(summary.splitlines(), [
                    f"Pull request 5: the review job of Build run 40 ended failure at attempt {attempt}. At most two "
                    "re-runs for one Build run: it is not run again."])

    def test_a_successful_run_re_runs_nothing(self):
        # The step re-runs nothing whose review passed, whatever its verdicts (`person` too: a person decides, not a
        # re-run).
        reruns, out, summary = self.rerun(1, self.jobs("success"))
        self.assertEqual((reruns, summary), ([], ""))

    def test_a_failure_of_another_job_alone_re_runs_nothing(self):
        # Another job failed and the review passed or did not run; or the build failed too, which is the project's or
        # the runner's, and a maintainer re-runs it (build.yaml): the step re-runs no build of up to six hours.
        for jobs in (self.jobs("success", build="failure"), self.jobs("success", record="failure"),
                     self.jobs("skipped", build="failure"), self.jobs("success", hold="failure"),
                     self.jobs("failure", build="failure"), self.jobs("failure", build="cancelled")):
            with self.subTest(jobs=jobs):
                reruns, out, summary = self.rerun(1, jobs)
                self.assertEqual((reruns, summary), ([], ""))

    def test_a_change_or_a_pull_request_that_moved_on_is_not_re_run(self):
        # Not one enrollment: a change, a project and another file, two projects, a file renamed into a project, a file
        # directly in projects/. Or no open pull request into main is at the run's head any more: a later push, a
        # close, a merge (its review decides nothing, and a re-run could cancel the newer head's Build run). Or the
        # pull request at the head is a draft: enroll-dispatch's decide refuses it, and marking it ready runs Build.
        cases = [{5: (self.HEAD, ["tools/check"])}, {5: (self.HEAD, ["projects/zlib/build.sh", "README.md"])},
                 {5: (self.HEAD, ["projects/zlib/build.sh", "projects/curl/build.sh"])},
                 {5: (self.HEAD, ["projects/zlib/build.sh<-tools/x"])}, {5: (self.HEAD, ["projects/zlib"])},
                 {5: ("d" * 40, self.ENROLLMENT)}, {}, {5: (self.HEAD, self.ENROLLMENT, True)},
                 # Two pull requests at the head: each must be one enrollment.
                 {5: (self.HEAD, self.ENROLLMENT), 6: (self.HEAD, ["tools/check"])}]
        for pulls in cases:
            with self.subTest(pulls=pulls):
                reruns, out, summary = self.rerun(1, self.jobs(), pulls)
                self.assertEqual((reruns, summary), ([], ""))

    def test_a_failed_call_is_tried_again_and_the_review_is_re_run(self):
        # A fault of GitHub's API on any call: the jobs, the pull requests, their files, the re-run. One or three
        # failed tries, 15, 30 and 60 s apart, then the call succeeds. A failed try's output (here a cut page that
        # names pull request 99) is never used.
        for call in ("jobs", "pulls", "files", "rerun"):
            for failed in (1, 3):
                with self.subTest(call=call, failed=failed):
                    reruns, out, summary = self.rerun(1, self.jobs(), fails={call: failed})
                    self.assertEqual(reruns, ["run rerun 40 --failed -R o/r"])
                    self.assertEqual(self.waits, [15, 30, 60][:failed])
                    self.assertEqual(self.tries[call], failed + 1)
                    self.assertEqual(summary.splitlines(), [
                        "Pull request 5: the review job of Build run 40 ended failure at attempt 1; its failed jobs "
                        "run again."])

    def test_four_failed_tries_fail_the_job_and_name_the_build_run(self):
        # Nothing runs on a schedule, so nothing else would try again: the job fails, and its summary says which Build
        # run is not re-run.
        for call, what in (("jobs", "read the jobs of attempt 1"), ("pulls", "list the open pull requests"),
                           ("files", "list the files of pull request 5"), ("rerun", "re-run its failed jobs")):
            with self.subTest(call=call):
                reruns, out, summary = self.rerun(1, self.jobs(), fails={call: 4}, ok=False)
                self.assertEqual(reruns, [])
                self.assertEqual(self.waits, [15, 30, 60])
                self.assertEqual(self.tries[call], 4)
                self.assertEqual(summary.splitlines(),
                                 [f"Build run 40: could not {what} after 4 tries, so it is not re-run."])
                self.assertIn(f"::error::Build run 40: could not {what} after 4 tries", out)

    def test_a_re_run_whose_answer_is_lost_is_not_asked_for_twice(self):
        # GitHub takes the first try of the re-run, but its answer is lost. Before the next try the run is already at
        # attempt 2, so the step asks for no second re-run, and it does not fail.
        reruns, out, summary = self.rerun(1, self.jobs(), lost=True)
        self.assertEqual(reruns, ["run rerun 40 --failed -R o/r"])
        self.assertEqual((self.tries["rerun"], self.waits), (1, [15]))
        self.assertIn("Build run 40 is at attempt 2: a try was taken, though its answer was lost.", out)
        self.assertEqual(summary.splitlines(), [
            "Pull request 5: the review job of Build run 40 ended failure at attempt 1; its failed jobs run again."])


if __name__ == "__main__":
    unittest.main()
