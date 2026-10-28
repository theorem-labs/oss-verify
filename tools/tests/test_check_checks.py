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
        for workflow, names in (("build.yaml", ("OTEL_COLLECTOR_TOKEN",
                                                "GCP_ACCESS_TOKEN", "key", "payload")),
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
        token, gcp = "collector-token-not-a-secret", "gcp-not-a-secret"
        key_lines = ["-----BEGIN RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4",
                     "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==", "-----END RSA PRIVATE KEY-----"]
        key = "\n".join(key_lines) + "\n"

        def steps(workflow, job, name):
            found = [s for s in self.workflow(workflow)["jobs"][job]["steps"] if s.get("name") == name]
            self.assertEqual(len(found), 1, f"{workflow} {job} {name}")
            return found[0]["run"]

        cases = [
            ("build.yaml review usage export", steps("build.yaml", "review", "Export the review's usage to the cost collector"),
             json.dumps({"payload": {"data": base64.b64encode(token.encode()).decode()}}),
             {"GCP_ACCESS_TOKEN": gcp}, [token, base64.b64encode(token.encode()).decode(), gcp]),
            ("build.yaml review held finding store", steps("build.yaml", "review", "Store the held finding for the hold job"),
             json.dumps({"generation": "1761500000000000"}),
             {"GCP_ACCESS_TOKEN": gcp, "RUN_ID": "7", "PR": "68", "NAME": "libreac", "HEAD_SHA": "1" * 40,
              "RUN_URL": "https://github.com/theorem-labs/oss-verify/actions/runs/7"}, [gcp]),
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

    def test_only_the_review_job_can_read_the_collector_token(self):
        # ossv-ci can be acted as only from oss-verify's GitHub Environment `enroll-review` (Theorem's
        # infrastructure code), which the review job declares; no other job of either file may name that account or
        # that environment, and the review job must keep it, or its sign-in stops working.
        account = "ossv-ci@theorem-agent-infra.iam.gserviceaccount.com"
        for workflow in self.KEY_JOBS:
            for name, job in self.workflow(workflow)["jobs"].items():
                review = workflow == "build.yaml" and name == "review"
                environment = json.dumps(job.get("environment", "")).lower()
                if review:
                    self.assertEqual(job.get("environment"), {"name": "enroll-review", "deployment": False})
                    self.assertEqual((job.get("env") or {}).get("GCP_SERVICE_ACCOUNT"), account)
                else:
                    self.assertNotIn(account, json.dumps(job), f"{workflow} {name} names {account}")
                    self.assertNotIn("enroll-review", environment, f"{workflow} {name} is in enroll-review")

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

    def test_every_google_sign_in_keeps_its_token_to_one_step(self):
        # Each auth step writes no credentials file, exports no variable, and mints a five-minute access token: its
        # output is all that holds it. Six steps: build.yaml's review job signs in before the review and again, for a
        # held finding, after it (the first token has expired by then); its hold and comment jobs, triage's comment job
        # and enroll-dispatch's dispatch job sign in once each.
        found = 0
        for workflow in self.KEY_JOBS:
            for name, job in self.workflow(workflow)["jobs"].items():
                for step in job["steps"]:
                    if step.get("uses", "").startswith("google-github-actions/auth@"):
                        found += 1
                        self.assertEqual({k: step["with"].get(k) for k in ("token_format", "access_token_lifetime",
                                          "create_credentials_file", "export_environment_variables")},
                                         {"token_format": "access_token", "access_token_lifetime": "300s",
                                          "create_credentials_file": False, "export_environment_variables": False},
                                         f"{workflow} {name}")
        self.assertEqual(found, 6)

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
    """build.yaml's own "Post the comment" step, run with a fake gh: what it sends GitHub."""

    def post(self, review, existing=True, head="b" * 40, pr_head=None, checks="### new report\n"):
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
                           "PR": "8", "REVIEW": review, "CHECKS": checks, "HEAD_SHA": head,
                           "RUNNER_TEMP": str(directory / "temp")}
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=ROOT, env=environment, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            sent = [name for name in ("patch.json", "post.json") if (directory / name).exists()]
            self.assertLessEqual(len(sent), 1, sent)
            if sent:
                self.assertEqual(sent[0], "patch.json" if existing else "post.json")
            if existing and sent:
                self.assertIn("issues/comments/4242", (directory / "patch.url").read_text())
            return json.loads((directory / sent[0]).read_text())["body"] if sent else None

    def test_nothing_is_posted_unless_posting_is_on(self):
        # The comment job, which alone holds the App's key, runs only while OSSV_POST_REVIEW is `post`, and the
        # required job asks for it on the same condition, so with the variable unset no job can post or edit a comment.
        jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]
        condition = jobs["comment"]["if"]
        self.assertIn("vars.OSSV_POST_REVIEW == 'post' && ", condition)
        asked = jobs["required"]["steps"][-1]["env"]["ASKED_COMMENT"]
        self.assertEqual(condition.replace("!cancelled() && ", ""), asked)
        # No other job of the file can write to the pull request: only the comment job's token is the App's.
        for name, job in jobs.items():
            if name != "comment":
                self.assertNotIn("write", json.dumps({k: v for k, v in (job.get("permissions") or {}).items()
                                                      if k != "id-token"}), name)

    def test_the_triage_comment_is_a_draft_without_its_variable(self):
        # triage.yaml's own posting step: with OSSV_POST_TRIAGE anything but post, it calls gh not at all and writes the
        # draft to the summary; with post, it posts.
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "triage.yaml").read_text())
        name = "Post the comment, or update the one already there"
        matches = [s for s in workflow["jobs"]["comment"]["steps"] if s.get("name") == name]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["env"]["POST_TO_PR"], "${{ vars.OSSV_POST_TRIAGE }}")
        for value, posts in (("", False), ("draft", False), ("Post", False), ("post", True)):
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                (directory / "bin").mkdir()
                (directory / "bin" / "gh").write_text(
                    f'#!/bin/bash\necho "$*" >> {directory}/calls\n'
                    f'case "$*" in *"--method POST"*) cat > {directory}/post.json ;; esac\n')
                (directory / "bin" / "gh").chmod(0o755)
                environment = {**os.environ, "PATH": f"{directory / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x",
                               "REPO": "o/r", "PR": "8", "COMMENT": "<!-- oss-verify-triage -->\n### Triage\n",
                               "POST_TO_PR": value, "GITHUB_STEP_SUMMARY": str(directory / "summary")}
                run = subprocess.run(["bash", "-e", "-c", matches[0]["run"]], env=environment, capture_output=True,
                                     text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual((directory / "post.json").exists(), posts, value)
                if not posts:
                    self.assertFalse((directory / "calls").exists(), value)
                    self.assertIn("\n    ### Triage\n", (directory / "summary").read_text())

    def test_a_review_replaces_the_posted_one(self):
        body = self.post("Thanks again.\n\n2. Fix Y.\n")
        self.assertTrue(body.startswith("<!-- oss-verify-review -->\n<sub>Claude wrote this review of `bbbbbbb`"))
        self.assertIn("\n\nThanks again.\n\n2. Fix Y.\n", body)
        self.assertIn("<summary>What the breakage and coverage checks measured</summary>\n\n### new report", body)

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


@unittest.skipUnless(shutil.which("jq"), "needs jq, which the gh stand-in runs the script's filters with")
class ReviewHeld(unittest.TestCase):
    """review-held opens one private issue for each held finding, through a fake gh, and prints none of it."""

    RUN = "https://github.com/theorem-labs/oss-verify/actions/runs/7"
    OBJECT = "held/7/" + "a" * 32
    HEADER = f"oss-verify held finding v1\npr: 68\nhead: {'1' * 40}\nproject: libreac\nrun: {RUN}\n---\n"

    @staticmethod
    def body(key):
        """An issue body as review-held writes it: its key on the fifth line."""
        return f"enrollment PR: x\nenrollment PR head: y\npublic PR comment: z\nreview run: r\n{key}\n"

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
    answer = [{"number": i, "body": b} for i, b in enumerate(state["issues"], 1)]
elif path.endswith("/comments") and not fields:
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
            "project: libreac\nwhy held: memory safety\n\nparse_SECRETBUG reads past the end.\n")

    def run_held(self, held, bodies_on_github=(), label=True, variable="theorem-labs/private", visibility="private",
                 header=None, comments=(), public_comments=()):
        """bodies_on_github: the bodies of the label's issues already there, open or closed, numbered from 1. comments:
        the bodies of comments already on a private issue. public_comments: the pull request's comments, as
        (login, body, html_url). held follows the six lines the review job writes (header, by default HEADER)."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "review").mkdir()
            (root / "review" / "object").write_text((self.HEADER if header is None else header) + held)
            (root / "state.json").write_text(json.dumps({
                "variable": variable, "visibility": visibility, "label": label, "issues": list(bodies_on_github),
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
                                      "HELD_OBJECT": self.OBJECT},
                                 capture_output=True, text=True)
            # The token of each call, in the order of calls.
            run.tokens = (root / "tokens").read_text().splitlines() if (root / "tokens").exists() else []
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] \
                if (root / "calls").exists() else []
            bodies = (root / "bodies").read_text().split("\0")[:-1] if (root / "bodies").exists() else []
            return run, calls, bodies

    def test_each_finding_is_one_labelled_issue_with_the_pull_request_and_nothing_is_printed(self):
        two = self.HELD + self.HELD.replace("parse_SECRETBUG", "other_SECRETBUG")
        run, calls, bodies = self.run_held(two, label=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("SECRETBUG", run.stdout + run.stderr)
        self.assertIn(["api", "repos/theorem-labs/private/labels", "-f", "name=held-finding", "-f", "color=b60205",
                       "-f", "description=A finding held back from a public review, for the disclosure route"], calls)
        created = [c for c in calls if c[1] == "repos/theorem-labs/private/issues"]
        self.assertEqual([c[c.index("-f") + 1] for c in created],
                         ["title=[held] libreac/fuzz: heap-buffer-overflow in parse_SECRETBUG",
                          "title=[held] libreac/fuzz: heap-buffer-overflow in other_SECRETBUG"])
        self.assertTrue(all("labels[]=held-finding" in c for c in created))
        self.assertEqual(len(bodies), 2)
        self.assertTrue(bodies[0].startswith(f"enrollment PR: theorem-labs/oss-verify#68\nenrollment PR head: {'1' * 40}\n"
                                             "public PR comment: not posted yet: the review comment on "
                                             "theorem-labs/oss-verify#68\n"
                                             f"review run: {self.RUN}\nheld finding key: {self.OBJECT} 1\n"))
        self.assertIn(f"held finding key: {self.OBJECT} 2\n", bodies[1])
        self.assertNotIn("theorem-labs/private", run.stdout + run.stderr)
        self.assertIn("project: libreac\nwhy held: memory safety\n", bodies[0])
        self.assertNotIn("title:", bodies[0])

    def test_a_re_run_sends_only_what_its_run_did_not_send_and_the_title_routes_nothing(self):
        # The first of two untitled findings was sent before the run failed; a closed issue counts too. Another run's
        # issue with the same title does not stop either.
        two = "<!-- held finding -->\nproject: libreac\n<!-- held finding -->\nproject: libreac\nsecond\n"
        run, calls, bodies = self.run_held(two, bodies_on_github=[
            self.body(f"held finding key: {self.OBJECT} 1"), self.body(f"held finding key: held/1/{'b' * 32} 2"),
            # A key anywhere but the fifth line is no key.
            f"held finding key: {self.OBJECT} 2\n"])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"1 of {self.OBJECT} was already sent", run.stdout)
        self.assertEqual(len(bodies), 1)
        self.assertIn(f"held finding key: {self.OBJECT} 2\n", bodies[0])
        self.assertIn("second", bodies[0])

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
        self.assertIn(f"held finding key: {self.OBJECT} all\n", bodies[0])
        self.assertIn("SECRET10", bodies[0])

    def test_a_long_finding_goes_whole_in_parts_and_a_re_run_posts_only_the_missing_ones(self):
        # 130,000 bytes in lines of 1,000: the issue and two comments, each at most 60,000 bytes, which hold it all.
        long = "".join(f"{i:05d}" + "x" * 994 + "\n" for i in range(130))
        run, calls, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + long + "END-OF-FINDING\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 3)
        self.assertTrue(all(len(b.encode()) <= 60500 for b in bodies))
        self.assertIn("(Part 1 of 3: the rest follows in the comments.)", bodies[0])
        self.assertTrue(bodies[1].startswith(f"held finding part: {self.OBJECT} 1 2/3\n"))
        self.assertIn("END-OF-FINDING", bodies[2])
        joined = "".join(bodies)
        self.assertTrue(all(f"{i:05d}" in joined for i in range(130)))
        self.assertEqual([c[1] for c in calls if "-F" in c][1:], ["repos/theorem-labs/private/issues/42/comments"] * 2)
        # A run that stopped after part 2: the next posts only part 3, on the issue that is there.
        run, calls, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + long + "END-OF-FINDING\n",
                                           bodies_on_github=[self.body(f"held finding key: {self.OBJECT} 1")],
                                           comments=[f"held finding part: {self.OBJECT} 1 2/3\n\n..."])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        self.assertTrue(bodies[0].startswith(f"held finding part: {self.OBJECT} 1 3/3\n"))
        self.assertEqual([c[1] for c in calls if "-F" in c], ["repos/theorem-labs/private/issues/1/comments"])

    @staticmethod
    def finding_of(issue_body, comment_bodies):
        """The finding as the disclosure route reads it back: the issue after its five lines, without the part note,
        then each comment after its part line and the blank line."""
        text = issue_body.split("\n", 5)[5]
        text = re.sub(r"\n\n\(Part 1 of \d+: the rest follows in the comments\.\)\n$", "", text)
        return text + "".join(c.split("\n", 2)[2] for c in comment_bodies)

    def test_a_long_finding_comes_back_byte_for_byte_whatever_the_comment_address(self):
        # Run 1 finds no review comment yet (the long fallback text) and stops after part 2. Run 2 finds the comment
        # (a short address) and posts the rest. The parts must join to the finding exactly.
        # Short lines, so that a change of a few bytes in the lines the script adds would move where a part ends.
        lines = [f"{i:05d} " + "é" * (i % 7) + "y" * (30 + i % 13) + "\n" for i in range(2800)]
        finding = "".join(lines) + "END-OF-FINDING\n"
        held = "<!-- held finding -->\ntitle: big\n" + finding
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
                    run, _, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + finding)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(len(bodies), 3)
                    self.assertNotIn("\ufffd", "".join(bodies))
                    self.assertEqual(self.finding_of(bodies[0], bodies[1:]), finding)

    def test_a_part_ends_at_a_line_end_when_the_line_fits(self):
        finding = "".join(f"{i:05d} " + "y" * 994 + "\n" for i in range(130))
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + finding)
        self.assertEqual(run.returncode, 0, run.stderr)
        texts = [re.sub(r"\n\n\(Part 1 of \d+: the rest follows in the comments\.\)\n$", "",
                        bodies[0].split("\n", 5)[5])] + [b.split("\n", 2)[2] for b in bodies[1:]]
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
        self.OBJECT = "held/7/short"
        run, calls, _ = self.run_held(self.HELD)
        self.assertEqual((run.returncode, calls), (2, []))

    def test_an_object_that_does_not_start_with_the_workflows_lines_is_sent_whole(self):
        for header in ("", "oss-verify held finding v1\npr: 68\nhead: x\nproject: libreac\nrun: r\n---\n",
                       self.HEADER.replace("runs/7", "runs/8")):
            with self.subTest(header=header):
                run, calls, bodies = self.run_held(self.HELD, header=header)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(len(bodies), 1)
                self.assertIn(f"held finding key: {self.OBJECT} raw\n", bodies[0])
                self.assertIn("SECRETBUG", bodies[0])

    def test_the_finding_reaches_the_hold_job_only_through_the_private_bucket(self):
        jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]
        text = (ROOT / ".github" / "workflows" / "build.yaml").read_text()
        # No job holds the App's key as a repository secret, and nothing reads a variable for the repository.
        self.assertNotIn("OSS_VERIFY_APP_PRIVATE_KEY", text)
        self.assertNotIn("HELD_FINDINGS_REPO }}", text)
        review = {s.get("name"): s for s in jobs["review"]["steps"]}
        store = review["Store the held finding for the hold job"]["run"]
        self.assertIn("ifGenerationMatch=0", store)
        self.assertIn('name="held/$RUN_ID/$(openssl rand -hex 16)"', store)
        self.assertIn("oss-verify held finding v1", store)
        self.assertEqual(jobs["review"]["outputs"]["held_object"], "${{ steps.held.outputs.object }}")
        # The review job passes names only: no output holds a file's text or the finding.
        self.assertNotIn("held-finding.md", json.dumps(jobs["review"]["outputs"]))
        # The finding is stored only when the review held one back, from the file the result step wrote, and the
        # session of that review is not kept.
        for name in ("Sign in to Google Cloud to store the held finding", "Store the held finding for the hold job"):
            self.assertEqual(review[name]["if"], "${{ steps.result.outputs.held == 'yes' }}")
        self.assertIn('"$RUNNER_TEMP/held-finding.md"', store)
        self.assertEqual(review["Keep this review's session for the next push's review"]["if"],
                         "${{ steps.result.outputs.held != 'yes' }}")
        hold = jobs["hold"]
        self.assertEqual(hold["environment"], {"name": "comment", "deployment": False})
        self.assertEqual(hold["needs"], ["project-builds", "review"])
        # Every run that reviewed anything sweeps the bucket, so a cancelled run's finding goes with the next run.
        self.assertEqual(hold["if"], "${{ !cancelled() && needs.review.result != 'skipped' }}")
        # One sweep at a time in the repository; every waiting one keeps its place, so none is cancelled by another.
        self.assertEqual(hold["concurrency"], {"group": "build-hold", "cancel-in-progress": False, "queue": "max"})
        steps = {s.get("name"): s for s in hold["steps"]}
        where = steps["Where the held findings go"]["run"]
        self.assertIn("secrets/oss-verify-held-findings-repo/versions/latest:access", where)
        self.assertLess(where.index("::add-mask::"), where.index('echo "name=$name"'))
        token = steps["Get the oss-verify App's token for the held findings' repository"]["with"]
        self.assertEqual((token["owner"], token["repositories"], token["permission-issues"]),
                         ("${{ github.repository_owner }}", "${{ steps.where.outputs.name }}", "write"))
        send = steps["Send every stored held finding to the disclosure route"]
        self.assertEqual(send["run"], '.github/scripts/review-hold "$RUNNER_TEMP/held"')
        self.assertEqual(send["env"]["CURRENT_OBJECT"], "${{ needs.review.outputs.held_object }}")
        # The comment job posts no review unless the review job succeeded and, if it held a finding, hold sent it.
        self.assertIn("hold", jobs["comment"]["needs"])
        self.assertIn("needs.review.result == 'success' && needs.review.outputs.comment != '' && "
                      "(needs.review.outputs.held_object == '' || needs.hold.result == 'success')",
                      jobs["comment"]["if"])


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
    """build.yaml's review job: one claude-code-action step with the settings the review needs, its session kept in
    the Actions cache by the job itself, and its own small steps run with stand-ins."""

    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        self.jobs = self.workflow["jobs"]
        self.steps = {s.get("name"): s for s in self.jobs["review"]["steps"]}
        self.review = self.steps["Review"]

    def test_the_action_runs_from_main_with_three_tools_and_resumes_only_with_a_diff(self):
        # pull_request_target: GitHub runs main's copy of this file, never the pull request's.
        self.assertIn("pull_request_target", self.workflow.get("on", self.workflow.get(True)))
        self.assertRegex(self.review["uses"], r"^anthropics/claude-code-action@[0-9a-f]{40}$")
        settings = self.review["with"]
        self.assertEqual((settings["allowed_non_write_users"], settings["github_token"]), ("*", "${{ github.token }}"))
        self.assertEqual(settings["anthropic_federation_rule_id"], "fdrl_019restxFx3PhpLhbziQoQKf")
        self.assertNotIn("anthropic_api_key", settings)
        args = settings["claude_args"]
        self.assertTrue(args.startswith("--tools Read,Glob,Grep --model claude-opus-5-5 --effort xhigh --max-turns 300 "))
        self.assertIn("${{ steps.gather.outputs.session && format('--resume {0}', steps.gather.outputs.session) || '' }}",
                      args)
        for word in ("Bash", "Write", "Edit", "WebFetch", "mcp", "allowedTools", "permission-mode"):
            self.assertNotIn(word, args)
        schema = json.loads(re.search(r"--json-schema '([^']*)'$", args).group(1))
        self.assertEqual(schema["required"], ["comment", "held", "verdicts"])
        self.assertEqual(schema["properties"]["verdicts"]["required"], ["F2", "F7"])
        self.assertEqual(schema["properties"]["verdicts"]["additionalProperties"], {"enum": ["pass", "fail", "person"]})
        prompt = settings["prompt"]
        self.assertIn("Read review.md at the root of this checkout", prompt)
        self.assertIn("read only review.md and .review/since-last-review.diff", prompt)

    def test_the_session_is_kept_by_the_review_job_and_not_when_it_holds_a_finding(self):
        self.assertEqual(self.workflow["cache-mode"], "none")
        self.assertEqual({name: job["cache-mode"] for name, job in self.jobs.items() if "cache-mode" in job},
                         {"review": "write"})
        restore = self.steps["Restore the last review's session and the head it reviewed"]
        save = self.steps["Keep this review's session for the next push's review"]
        self.assertTrue(restore["uses"].startswith("actions/cache/restore@"))
        self.assertTrue(save["uses"].startswith("actions/cache/save@"))
        paths = "~/.claude/projects\n~/.claude/ossv-last-review"
        key = "${{ env.SESSION_KEY }}${{ github.run_id }}-${{ github.run_attempt }}"
        self.assertEqual((restore["with"]["path"], restore["with"]["key"]), (paths, key))
        self.assertEqual((save["with"]["path"], save["with"]["key"]), (paths, key))
        self.assertEqual(restore["with"]["restore-keys"], "${{ env.SESSION_KEY }}")
        self.assertEqual(self.jobs["review"]["env"]["SESSION_KEY"],
                         "enroll-review/${{ github.event.pull_request.number || inputs.pr }}/"
                         "${{ needs.project-builds.outputs.name }}/")
        self.assertEqual(save["if"], "${{ steps.result.outputs.held != 'yes' }}")
        gather = self.steps["Gather what the review reads, and the diff since the last review"]["run"]
        self.assertIn("LAST_REVIEW=~/.claude/ossv-last-review .github/scripts/review-gather .review", gather)

    def result(self, output):
        """The result step, on an execution file whose result carries `output` as its structured output."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "temp").mkdir()
            (root / "home").mkdir()
            execution = root / "execution.json"
            execution.write_text(json.dumps([{"type": "system", "subtype": "init"},
                                             {"type": "result", "subtype": "success", "structured_output": output}]))
            run = subprocess.run(["bash", "-e", "-c", self.steps["Keep the draft, and the held finding apart from it"]["run"]],
                                 cwd=root, capture_output=True, text=True,
                                 env={**os.environ, "HOME": str(root / "home"), "RUNNER_TEMP": str(root / "temp"),
                                      "GITHUB_OUTPUT": str(root / "output"), "RESULT": str(execution),
                                      "SESSION": "09227178-7bbf-4e5f-86db-8736e530ef01", "HEAD_SHA": "1" * 40})
            read = lambda path: path.read_text() if path.exists() else None
            return (run, read(root / "temp" / "draft" / "comment.md"), read(root / "temp" / "draft" / "verdicts.json"),
                    read(root / "temp" / "held-finding.md"), read(root / "output") or "",
                    read(root / "home" / ".claude" / "ossv-last-review"))

    def test_a_review_without_a_held_finding_keeps_its_session(self):
        run, comment, verdicts, held, output, last = self.result(
            {"comment": "Thanks.\n\n1. Fix X.\n", "held": "", "verdicts": {"F2": "pass", "F7": "fail"}})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(comment, "Thanks.\n\n1. Fix X.\n\n")
        self.assertEqual(json.loads(verdicts), {"F2": "pass", "F7": "fail"})
        self.assertEqual(output, "")
        self.assertEqual(last, f"session=09227178-7bbf-4e5f-86db-8736e530ef01 head={'1' * 40}\n")

    def test_a_held_finding_stays_out_of_the_draft_and_its_session_is_not_kept(self):
        run, comment, verdicts, held, output, last = self.result(
            {"comment": "Thanks.\n\nA finding was sent for private review.\n", "held": ReviewHeld.HELD,
             "verdicts": {"F2": "pass", "F7": "pass"}})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("SECRETBUG", comment + verdicts + run.stdout + run.stderr)
        self.assertEqual(held, "<!-- held finding -->\n" + ReviewHeld.HELD + "\n")
        self.assertEqual(output, "held=yes\n")
        self.assertIsNone(last)

    def test_a_result_without_a_structured_output_fails_the_step(self):
        run, comment, _, _, _, last = self.result(None)
        self.assertNotEqual(run.returncode, 0)
        self.assertIsNone(last)

    def export(self, answer):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "bin" / "curl").write_text(f"#!/bin/bash\nprintf '%s' {shlex.quote(answer)}\n" if answer is not None
                                               else "#!/bin/bash\nexit 22\n")
            (root / "bin" / "curl").chmod(0o755)
            run = subprocess.run(["bash", "-e", "-c", self.steps["Export the review's usage to the cost collector"]["run"]],
                                 cwd=root, capture_output=True, text=True,
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "GCP_ACCESS_TOKEN": "gcp-not-a-secret", "GITHUB_ENV": str(root / "env"),
                                      "NAME": "libreac"})
            return run, (root / "env").read_text() if (root / "env").exists() else ""

    def test_the_collector_token_is_masked_and_reaches_the_action_by_the_environment(self):
        token = "collector-token-not-a-secret"
        run, env = self.export(json.dumps({"payload": {"data": base64.b64encode((token + "\n").encode()).decode()}}))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, f"::add-mask::{token}\n")
        self.assertEqual(env, "CLAUDE_CODE_ENABLE_TELEMETRY=1\nOTEL_LOGS_EXPORTER=otlp\nOTEL_METRICS_EXPORTER=none\n"
                         "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n"
                         "OTEL_EXPORTER_OTLP_ENDPOINT=https://agent-otel-public-6acxmql5za-uw.a.run.app\n"
                         "OTEL_RESOURCE_ATTRIBUTES=theorem.project=oss-verify,theorem.subproject=libreac,"
                         "theorem.lane=enroll-review-ci,theorem.credential=oss-verify-ci\n"
                         f"OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer {token}\n")

    def test_a_token_that_cannot_be_read_does_not_stop_the_review(self):
        for answer in (None, "{}", '{"payload": {"data": null}}', json.dumps({"payload": {"data": "IAoJ"}})):
            with self.subTest(answer=answer):
                run, env = self.export(answer)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn("::warning::No cost collector token", run.stdout)
                self.assertNotIn("::add-mask::", run.stdout)
                self.assertEqual(env, "")
        self.assertIs(self.steps["Sign in to Google Cloud, for the cost collector's token"]["continue-on-error"], True)


class Owners(unittest.TestCase):

    def test_only_review_md_the_skill_and_codeowners_have_an_owner_and_are_the_last_patterns(self):
        lines = [line.split() for line in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        owned = [["/review.md", "@theorem-labs/engineering"],
                 ["/.claude/skills/write-to-maintainer/", "@theorem-labs/engineering"],
                 ["/.github/CODEOWNERS", "@theorem-labs/engineering"]]
        self.assertEqual([line for line in lines if len(line) > 1], owned)
        self.assertEqual(lines[-3:], owned)
        self.assertTrue((ROOT / "review.md").is_file())


if __name__ == "__main__":
    unittest.main()
