# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of the move of this repository's workflows off pull_request_target, and of the approval of the held runs of a
first-time contributor after the screen (OSSV-679):

    python3 -P -m pytest -q -p no:cacheprovider -c pyproject.toml tests/test_trigger_move.py

With `-k held`, only the cases of the held runs run. With `-k 'not held'`, only the other cases run.

The move:
  (r)  No workflow starts on pull_request_target. A workflow that starts on pull_request reads no secret, and its jobs
       have no identity token, no environment and only read permissions.
  (s)  A Build run's artifact build-results that names another pull request or another head, or that holds a diff,
       changes nothing that review.yml reads or posts: route reads the pull request and its head from the API,
       .github/scripts/take-build-results gives its fixed line, the gather job reads the text and the diff from the
       API, and the comment job posts to that pull request at that head.
  (u)  The list of .github/scripts/steering.py is the list of patterns of .github/CODEOWNERS that give a file to
       @theorem-labs/engineering, at commit 62081ee and today.
  (w)  Enroll dispatch sends no enrollment that changes a steering file, and puts no label on it, until a person
       approved its head: for an open pull request and for a merge.
  (x)  No workflow with workflow_dispatch builds the code of a pull request (oss-verify check, docker).
  (z2) A run by hand on another branch than main holds no identity and posts nothing.
  (claude files) The gather job keeps no CLAUDE*.md, AGENTS*.md or .claude/ of the pull request, and the review job
       refuses one.
The held runs (each test name holds the word held):
  route finds the held runs of a head on a run by hand. The comment job approves them with a token of the oss-verify
  App that can write runs, only when the screen passed that head. A screen that cannot sign in fails with no verdict,
  before the mark of the daily cap. Held runs (.github/workflows/held-runs.yml) starts a run by hand of review.yml for
  each held head that no run screened, and re-runs the failed jobs of a run whose screen gave a verdict.
A review that passes: the paragraph of review.md that says what happens next, and the comment that says it.

Each case runs the steps and the scripts of the workflows with stand-ins: this file's gh, which gives the API's answers
from files and records each call with its GH_TOKEN, and for the screen the stand-in services of tests/test_screen.py.
A changed-code control (its name holds the word control) copies the scripts and the workflows into a temporary
directory. It runs its case on that copy, where the case passes. Then it changes a second copy, runs the case there,
and asserts that the case fails.

Of the test files, the cases (r), (s), (u), (w) and (x) import only tests/test_enroll_dispatch.py: (w) makes its
stand-in API with its World, and uses only what World has before the move too. In a tree of the commit before the move
(0666dceb750a), these cases fail on their own assertions.
"""
import datetime
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = "theorem-labs/oss-verify"
# The outside pull request of the cases: number 7, from mallory's fork, at HEAD. OTHER is another commit.
PR, HEAD, OTHER = "7", "a" * 40, "b" * 40
FORK, BRANCH = "mallory/oss-verify", "add-x"
REAL_GIT = shutil.which("git") or "git"
# The tokens, as the stand-in gh records them: the job's own token (github.token), and the oss-verify App's two tokens
# of the comment job (steps.app and steps.approve).
WORKFLOW_TOKEN, APP_TOKEN, APPROVE_TOKEN = "workflow-token", "app-token", "app-actions-token"

# The stand-in gh, as tests/test_outside_screen.py's FAKE_GH, with more of gh. `gh api <endpoint> [--paginate]
# [--slurp] [--jq <filter>] [--method M] [-f|-F k=v] [-H <header>] [--input -] [--]` answers from
# $FAKE_GH/<endpoint>.json through jq, and with --slurp as a list of that one page. In the file's name, the endpoint's
# slashes are underscores, and its query stays when a file is served for the endpoint with it. With an Accept header of
# a raw or a diff answer, it gives $FAKE_GH/<endpoint>.raw as it is. An endpoint with no file answers as GitHub's 404
# does. `gh pr view <n>` gives $FAKE_GH/pr-view-<n>.json, `gh pr diff <n>` gives $FAKE_GH/pr-<n>.diff, and
# `gh workflow run` does nothing. Each call goes to $FAKE_GH/calls: its GH_TOKEN, then its arguments, each ended by NUL,
# and the call by \1. What a call reads on its standard input (--input -) goes to $FAKE_GH/input.<n>, n counted from 1.
GH = r"""#!/usr/bin/env bash
printf '%s\0' "${GH_TOKEN:-}" "$@" >> "$FAKE_GH/calls"
printf '\1' >> "$FAKE_GH/calls"
n=$(tr -cd '\1' < "$FAKE_GH/calls" | wc -c)
case "${1:-} ${2:-}" in
  "workflow run") exit 0 ;;
  "pr view")
    case "$*" in *statusCheckRollup*) echo '{"statusCheckRollup": []}' ;; *) cat "$FAKE_GH/pr-view-$3.json" ;; esac
    exit ;;
  "pr diff") cat "$FAKE_GH/pr-$3.diff"; exit ;;
esac
[ "${1:-}" = api ] || { echo "gh: not served here: $*" >&2; exit 9; }
shift
filter=. endpoint="" input="" slurp="" raw=""
while [ $# -gt 0 ]; do
  case $1 in
    --paginate|--) shift ;;
    --slurp) slurp=1; shift ;;
    --jq) filter=$2; shift 2 ;;
    --input) input=$2; shift 2 ;;
    -H) case $2 in *vnd.github.raw*|*vnd.github.diff*) raw=1 ;; esac; shift 2 ;;
    --method|-X|-f|-F) shift 2 ;;
    *) endpoint=$1; shift ;;
  esac
done
[ "$input" != - ] || cat > "$FAKE_GH/input.$n"
queried=${endpoint//\//_}
bare=${endpoint%%\?*}
bare=${bare//\//_}
kind=json
[ -z "$raw" ] || kind=raw
for file in "$FAKE_GH/$queried.$kind" "$FAKE_GH/$bare.$kind"; do
  [ -f "$file" ] || continue
  if [ -n "$raw" ]; then exec cat "$file"; fi
  if [ -n "$slurp" ]; then exec jq -c -s . "$file"; fi
  exec jq -r "$filter" "$file"
done
echo "gh: Not Found (HTTP 404): $endpoint" >&2
exit 1
"""

# git, but no command reaches the network: ls-remote answers nothing, and a command that names an http or https
# address fails as a fetch that cannot reach it does.
GIT = r"""#!/usr/bin/env bash
for arg in "$@"; do
  case $arg in
    ls-remote) exit 0 ;;
    http://*|https://*) echo "fatal: $arg: no network in this test" >&2; exit 128 ;;
  esac
done
exec "$REAL_GIT" "$@"
"""

# The flags of gh api that take a value, as the stand-in gh reads them.
GH_FLAGS = {"--jq", "--input", "--method", "-X", "-f", "-F", "-H"}
# The check of review.yml's jobs that sign in, for a run by hand on another branch than main.
MAIN_CHECK = "(github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main')"
LOOKUP = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*")
# PyYAML's C parser when it is built, else its Python one: review.yml is long, and the C parser reads it many times
# faster.
YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def as_text(value):
    """A value as an env or an output gets it."""
    return "true" if value is True else "false" if value is False else "" if value is None else str(value)


def render(value, ctx, evaluate=None):
    """`value` as GitHub gives it to an env: each ${{ }} in it replaced by its value in ctx. With no `evaluate` (the
    expression evaluator of tests/test_outside_screen.py), an expression must be a context or several joined by ||."""
    def one(match):
        inner = match.group(1).strip()
        if evaluate is not None:
            return as_text(evaluate(inner, ctx))
        names = [name.strip() for name in inner.split("||")]
        if not all(LOOKUP.fullmatch(name) for name in names):
            raise KeyError(f"no value is given for the expression {inner!r}")
        return next((as_text(ctx[name]) for name in names if ctx.get(name) not in (None, "")), "")
    return re.sub(r"\$\{\{(.*?)\}\}", one, value if isinstance(value, str) else as_text(value), flags=re.S)


def env_of(workflow, job, step, ctx, given=None, evaluate=None):
    """The environment of `step` of `job`: the workflow's env, the job's and the step's, each rendered for ctx. A name
    of `given` gets its value from `given`."""
    given = given or {}
    env = {}
    for scope in (workflow.get("env") or {}, workflow["jobs"][job].get("env") or {}, step.get("env") or {}):
        for name, value in scope.items():
            env[name] = given[name] if name in given else render(value, ctx, evaluate)
    return env


def outputs(text):
    """The outputs a step wrote to GITHUB_OUTPUT: name=value lines, and name<<delimiter blocks."""
    got, lines, i = {}, text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        block = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*)<<(.+)", line)
        if block:
            end = lines.index(block.group(2), i)
            got[block.group(1)] = "\n".join(lines[i:end])
            i = end + 1
        elif "=" in line:
            name, value = line.split("=", 1)
            got[name] = value
    return got


def triggers(workflow):
    """The events of a workflow's on (PyYAML reads the key on as true), as a dict."""
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return dict(on or {})


def zipped(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def ago(minutes):
    """The time `minutes` before now, as GitHub writes it."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    return (now - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def members(path):
    with tarfile.open(path) as archive:
        return archive.getnames()


class Stand(unittest.TestCase):
    """A temporary directory with this file's stand-ins at the front of PATH (gh, git, python3 as this interpreter,
    dpkg that finds every package, and sudo that refuses), the API's answers that gh gives, a runner temporary
    directory, a home, and a GITHUB_OUTPUT."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="trigger-move-test-")
        self.dir = pathlib.Path(self._tmp.name)
        self.api, self.temp, self.home, self.bin = (self.dir / n for n in ("api", "temp", "home", "bin"))
        for directory in (self.api, self.temp, self.home, self.bin):
            directory.mkdir()
        for name, text in (("gh", GH), ("git", GIT), ("python3", f'#!/bin/sh\nexec "{sys.executable}" "$@"\n'),
                           ("dpkg", "#!/bin/sh\nexit 0\n"),
                           ("sudo", '#!/bin/sh\necho "sudo: not run in a test" >&2\nexit 1\n')):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        self.output = self.dir / "output"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GH_", "GITHUB_", "ACTIONS_", "RUNNER_"))}
        self.env.update(PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}", FAKE_GH=str(self.api),
                        REAL_GIT=REAL_GIT, RUNNER_TEMP=str(self.temp), GITHUB_OUTPUT=str(self.output),
                        GITHUB_STEP_SUMMARY=os.devnull, HOME=str(self.home),
                        GIT_CONFIG_GLOBAL=str(self.home / ".gitconfig"), GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
                        GIT_COMMITTER_EMAIL="t@example.invalid", PYTHONDONTWRITEBYTECODE="1")
        # The stand-in services are on 127.0.0.1: no proxy is between.
        bypass = ",".join(filter(None, ("127.0.0.1,localhost", os.environ.get("no_proxy"), os.environ.get("NO_PROXY"))))
        self.env.update(no_proxy=bypass, NO_PROXY=bypass)

    def tearDown(self):
        self._tmp.cleanup()

    def serve(self, endpoint, data):
        (self.api / (endpoint.replace("/", "_") + ".json")).write_text(json.dumps(data))

    def serve_raw(self, endpoint, data):
        data = data if isinstance(data, bytes) else data.encode()
        (self.api / (endpoint.replace("/", "_") + ".raw")).write_bytes(data)

    def clear(self):
        """No answer of the API, and no call recorded."""
        for path in self.api.iterdir():
            path.unlink()

    def calls(self):
        """Each call of gh: (its GH_TOKEN, its arguments)."""
        path = self.api / "calls"
        if not path.exists():
            return []
        found = []
        for call in path.read_bytes().split(b"\1")[:-1]:
            parts = call.decode().split("\0")[:-1]
            found.append((parts[0], parts[1:]))
        return found

    def requests(self, since=0):
        """Each `gh api` call from the call `since` on: its token, method, endpoint and the JSON it sent."""
        found = []
        for n, (token, args) in enumerate(self.calls()[since:], since + 1):
            if args[:1] != ["api"]:
                continue
            method, endpoint, i = "GET", None, 1
            while i < len(args):
                if args[i] in GH_FLAGS:
                    if args[i] in ("--method", "-X"):
                        method = args[i + 1]
                    i += 2
                    continue
                if not args[i].startswith("-"):
                    endpoint = args[i]
                i += 1
            sent = self.api / f"input.{n}"
            body = json.loads(sent.read_text()) if "--input" in args and sent.exists() else None
            found.append({"token": token, "method": method, "endpoint": endpoint, "body": body, "args": args})
        return found

    def run_script(self, script, cwd, **env):
        """A step's script, as GitHub runs one with bash: (its exit status, what it printed, its outputs)."""
        self.output.write_text("")
        path = self.dir / "step.sh"
        path.write_text(script)
        done = subprocess.run(["bash", "--noprofile", "--norc", "-e", str(path)], cwd=cwd, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=600)
        return done.returncode, done.stdout + done.stderr, outputs(self.output.read_text())

    def need(self, tree, *paths):
        for path in paths:
            self.assertTrue((tree / path).is_file(), f"{path} is absent")

    def workflow(self, tree, name):
        self.need(tree, f".github/workflows/{name}")
        return yaml.load((tree / ".github" / "workflows" / name).read_text(), Loader=YAML_LOADER)

    def step(self, workflow, job, name):
        found = [s for s in workflow["jobs"][job]["steps"] if s.get("name") == name]
        self.assertEqual(len(found), 1, f"the steps named {name!r} of the job {job}")
        return found[0]

    def run_step(self, workflow, job, name, ctx, cwd, given=None, evaluate=None):
        """The step `name` of `job`, with its env rendered for ctx (env_of), in cwd."""
        step = self.step(workflow, job, name)
        return self.run_script(step["run"], cwd, **env_of(workflow, job, step, ctx, given, evaluate))

    def copy_tree(self, name, changes=()):
        """A copy of what the cases run, .github/ and the rules files, with src/ as a link, with `changes`. A change is
        (path, old text, new text), where the old text is in the file once, or (path, a function of the file's text)."""
        tree = self.dir / name
        shutil.copytree(ROOT / ".github", tree / ".github", ignore=shutil.ignore_patterns("__pycache__"))
        for rules in ("review.md", "review-change.md", "review-issue.md"):
            shutil.copy2(ROOT / rules, tree / rules)
        (tree / "src").symlink_to(ROOT / "src")
        for path, *change in changes:
            file = tree / path
            text = file.read_text()
            if len(change) == 1:
                new = change[0](text)
            else:
                self.assertEqual(text.count(change[0]), 1, f"{path}: the text that the control changes")
                new = text.replace(change[0], change[1])
            self.assertNotEqual(new, text, path)
            file.write_text(new)
        return tree

    def main_checkout(self, where, tree=ROOT):
        """`where` as the checkout of main that the gather job makes: the scripts of `tree`, with a stand-in
        triage.py (it reads GitHub), the template of a pull request, src/ and projects/."""
        shutil.copytree(tree / ".github" / "scripts", where / ".github" / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        (where / ".github" / "scripts" / "triage.py").write_text('print("| OK | triage |")\n')
        shutil.copy2(tree / ".github" / "PULL_REQUEST_TEMPLATE.md", where / ".github" / "PULL_REQUEST_TEMPLATE.md")
        (where / "src").symlink_to((tree / "src").resolve())
        (where / "projects").mkdir(exist_ok=True)
        return where

    def git(self, *args, cwd):
        return subprocess.run([REAL_GIT, "-c", "commit.gpgsign=false", *args], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def repository(self, files):
        """A repository whose main holds one file, and whose branch pull holds the pull request's commit, which adds
        `files`. Return the checkout of main at depth 1, as actions/checkout makes it, and that commit."""
        origin = self.dir / "origin"
        self.git("init", "-q", "-b", "main", str(origin), cwd=self.dir)
        (origin / "README.md").write_text("main\n")
        self.git("add", "-A", cwd=origin)
        self.git("commit", "-q", "-m", "main", cwd=origin)
        self.git("checkout", "-q", "-b", "pull", cwd=origin)
        for path, text in files.items():
            (origin / path).parent.mkdir(parents=True, exist_ok=True)
            (origin / path).write_text(text)
        self.git("add", "-A", cwd=origin)
        self.git("commit", "-q", "-m", "pull request", cwd=origin)
        sha = self.git("rev-parse", "HEAD", cwd=origin)
        self.git("checkout", "-q", "main", cwd=origin)
        checkout = self.dir / "checkout"
        self.git("clone", "-q", "--single-branch", "--branch", "main", "--depth", "1", f"file://{origin}",
                 str(checkout), cwd=self.dir)
        return checkout, sha

    def pull_request(self, files, head=HEAD):
        """Pull request PR into main from mallory's fork at `head`, with `files`, and its text: what route,
        take-project, take-build-results and review-gather read of it."""
        pull = {"number": int(PR), "state": "open", "user": {"login": "mallory"}, "changed_files": len(files),
                "head": {"sha": head, "ref": BRANCH, "repo": {"full_name": FORK}},
                "base": {"ref": "main", "repo": {"full_name": REPO, "default_branch": "main"}}}
        self.serve(f"repos/{REPO}/pulls/{PR}", pull)
        self.serve(f"repos/{REPO}/pulls/{PR}/files", [{"filename": f, "status": "added"} for f in files])
        self.serve(f"repos/{REPO}/issues/{PR}", {"user": {"login": "mallory"}})
        (self.api / f"pr-view-{PR}.json").write_text(json.dumps({
            "number": int(PR), "title": "Add x", "author": {"login": "mallory"}, "isDraft": False,
            "createdAt": "2026-11-01T00:00:00Z", "body": "API-BODY", "headRefOid": head,
            "files": [{"path": f} for f in files], "comments": [], "reviews": [],
            "commits": [{"messageHeadline": "Add x", "messageBody": ""}]}) + "\n")
        (self.api / f"pr-{PR}.diff").write_text("".join(f"diff --git a/{f} b/{f}\n+API-DIFF\n" for f in files))
        self.serve(f"repos/{REPO}/pulls/{PR}/comments", [])
        self.serve(f"repos/{REPO}/issues/{PR}/comments", [])
        return pull

    def gather_job(self, review, route, checkout, evaluate):
        """The gather job of review.yml for route's outputs `route`, each of its run steps whose if holds, in order,
        in `checkout`: (the exit status of the first step that failed or 0, the log, the job's outputs)."""
        shutil.rmtree(self.temp / "review-data", ignore_errors=True)
        job = review["jobs"]["gather"]
        ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "github.run_id": "77",
               "github.run_attempt": "1", **{f"needs.route.outputs.{k}": v for k, v in route.items()}}
        ctx.update({f"env.{k}": render(v, ctx, evaluate) for k, v in (job.get("env") or {}).items()})
        log = ""
        for s in job["steps"]:
            if "run" not in s or ("if" in s and not evaluate(s["if"], ctx)):
                continue
            rc, out, got = self.run_script(s["run"], checkout, **env_of(review, "gather", s, ctx, evaluate=evaluate))
            log += out
            if rc:
                return rc, log, {}
            if "id" in s:
                ctx.update({f"steps.{s['id']}.outputs.{k}": v for k, v in got.items()})
        return 0, log, {k: render(v, ctx, evaluate) for k, v in job["outputs"].items()}


class PullRequestWorkflows(unittest.TestCase):
    """(r) and (x): the events of each workflow, and what the jobs hold and run."""

    def workflows(self):
        found = sorted(p for p in (ROOT / ".github" / "workflows").iterdir() if p.suffix in (".yml", ".yaml"))
        self.assertTrue(found)
        return found

    def test_r_no_pull_request_target_and_a_pull_request_job_holds_nothing(self):
        for path in self.workflows():
            text = path.read_text()
            workflow = yaml.load(text, Loader=YAML_LOADER)
            on = triggers(workflow)
            self.assertNotIn("pull_request_target", on, path.name)
            if "pull_request" not in on:
                continue
            self.assertNotIn("secrets.", text, path.name)
            holders = [("the workflow", workflow)] + [(f"the job {n}", job) for n, job in workflow["jobs"].items()]
            for where, holder in holders:
                if holder is not workflow:
                    self.assertNotIn("environment", holder, f"{path.name}, {where}")
                permissions = holder.get("permissions")
                if permissions is None:
                    # A job with no permissions of its own takes the workflow's.
                    self.assertIn("permissions", workflow, f"{path.name}, {where}: no permissions are given")
                    continue
                if isinstance(permissions, str):
                    self.assertEqual(permissions, "read-all", f"{path.name}, {where}")
                    continue
                self.assertNotIn("id-token", permissions, f"{path.name}, {where}")
                for scope, level in permissions.items():
                    self.assertIn(level, ("read", "none"), f"{path.name}, {where}: {scope}")

    # A command of a step that builds the code of a pull request: oss-verify check (but --print-toolchain, which only
    # names the toolchain), or docker.
    BUILDS = re.compile(r"-m oss_verify check\b(?!\s+--print-toolchain)"
                        r"|^\s*(?:uv run\s+)?oss-verify check\b(?!\s+--print-toolchain)|\bdocker\b")

    def test_x_no_workflow_with_workflow_dispatch_builds_the_code_of_a_pull_request(self):
        builds = []
        for path in self.workflows():
            workflow = yaml.load(path.read_text(), Loader=YAML_LOADER)
            on = triggers(workflow)
            for name, job in workflow["jobs"].items():
                for step in job.get("steps") or []:
                    # The script's commands, without its comment lines.
                    run = "\n".join(line for line in str(step.get("run", "")).splitlines()
                                    if not line.lstrip().startswith("#"))
                    if any(self.BUILDS.search(line) for line in run.splitlines()) \
                            or str(step.get("uses", "")).startswith(("docker://", "docker/")):
                        builds.append((path.name, name, step.get("name")))
                        self.assertNotIn("workflow_dispatch", on,
                                         f"{path.name}, job {name}, step {step.get('name')!r} builds code")
        self.assertIn("build.yaml", {found[0] for found in builds})


class FirstRunArtifact(Stand):
    """(s): Build run 900 of pull request 7 at HEAD completed, and review.yml runs on workflow_run. The run's artifact
    build-results names pull request 8, or the head OTHER, or holds a diff of its own."""

    RUN, ARTIFACT = "900", 9001
    VARIANTS = (("another number", {"pr": 8}), ("another head", {"sha": OTHER}),
                ("another diff", {"diff": "diff --git a/README.md b/README.md\n+ARTIFACT-DIFF\n"}))
    FILES = ("projects/x/project.yaml", "projects/x/build.sh")
    ROUTE = "An enrollment, a change or an issue"
    TAKE = "Take the results of the Build run"
    GATHER = "Gather what the review reads, and the diff since the last review"
    POST = "Post the comment and record the verdict"
    # Control (1): route takes the number and the head from the artifact, in place of the ones it read from the API.
    ROUTE_OUTPUTS = '          {\n            echo "pr=$PR"\n'
    FROM_ARTIFACT = (
        "          # The control's change: the number and the head that the Build run's artifact names.\n"
        "          artifact=$(gh api \"repos/$REPO/actions/runs/$RUN_ID/artifacts?name=build-results&per_page=100\""
        " --jq '.artifacts[0].id')\n"
        "          results=$(gh api -H 'Accept: application/vnd.github.raw'"
        " \"repos/$REPO/actions/artifacts/$artifact/zip\" | python3 -c 'import io, sys, zipfile;"
        " sys.stdout.write(zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())).read(\"results.json\").decode())')\n"
        "          PR=$(jq -r .pr <<< \"$results\") sha=$(jq -r .sha <<< \"$results\")\n")
    # Control (2): take-build-results compares nothing of the artifact with the pull request, the head and the project.
    COMPARISON = ('    if results["pr"] != pr:\n'
                  '        return f"{MEMBER} is of another pull request, not {pr}"\n'
                  '    if results["sha"] != head:\n'
                  '        return f"{MEMBER} is of another head, not {head}"\n'
                  '    if results["project"] != name:\n'
                  '        return f"{MEMBER} is of another project, not {name}"\n')

    def results(self, change):
        """The results of Build run 900 of pull request 7 at HEAD, with `change`."""
        return {"schema": "oss-verify build results v1", "pr": 7, "project": "x", "sha": HEAD, "commit": "", "code": 0,
                "result": "ARTIFACT-RESULT", "binaries": "ARTIFACT-BINARIES", "checks": "ARTIFACT-CHECKS", **change}

    def fixture(self, change, data=None):
        """The API: pull request 7 at HEAD, and Build run 900 whose artifact holds the results with `change`, or is the
        zip `data`."""
        self.clear()
        pull = self.pull_request(self.FILES)
        self.serve(f"repos/{REPO}/pulls?state=open&base=main&head=mallory:{BRANCH}&per_page=100", [pull])
        data = data or zipped({"results.json": json.dumps(self.results(change))})
        self.serve(f"repos/{REPO}/actions/runs/{self.RUN}/artifacts", {"artifacts": [
            {"id": self.ARTIFACT, "name": "build-results", "expired": False, "size_in_bytes": len(data)}]})
        self.serve_raw(f"repos/{REPO}/actions/artifacts/{self.ARTIFACT}/zip", data)
        self.serve(f"repos/{REPO}/check-runs", {"id": 1})

    def case(self, tree=ROOT):
        """Route, take-build-results, review-gather and the comment job's post, each as review.yml runs it, for each
        artifact of VARIANTS."""
        self.need(tree, ".github/workflows/review.yml", ".github/scripts/take-build-results",
                  ".github/scripts/steering.py")
        review = self.workflow(tree, "review.yml")
        no_result = re.search(r'^NO_RESULT = "(.*)"$', (tree / ".github/scripts/take-build-results").read_text(),
                              re.M).group(1)
        ids = json.loads(subprocess.run([str(tree / ".github/scripts/review-verdict"), "--ids"], env=self.env,
                                        check=True, capture_output=True, text=True).stdout)
        for label, change in self.VARIANTS:
            self.fixture(change)
            ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "github.actor": "mallory",
                   "github.event_name": "workflow_run", "github.ref": "refs/heads/main",
                   "github.server_url": "https://github.com", "github.run_id": "77",
                   "github.event.repository.default_branch": "main", "github.event.workflow_run.id": self.RUN,
                   "github.event.workflow_run.event": "pull_request",
                   "github.event.workflow_run.path": ".github/workflows/build.yaml",
                   "github.event.workflow_run.conclusion": "success", "github.event.workflow_run.head_sha": HEAD,
                   "github.event.workflow_run.head_repository.full_name": FORK,
                   "github.event.workflow_run.head_branch": BRANCH}
            rc, log, route = self.run_step(review, "route", self.ROUTE, ctx, tree)
            self.assertEqual(rc, 0, log)
            self.assertEqual({k: route.get(k) for k in ("pr", "sha", "kind", "build_run")},
                             {"pr": PR, "sha": HEAD, "kind": "enrollment", "build_run": self.RUN},
                             f"route's outputs ({label}): {log}")
            ctx.update({f"needs.route.outputs.{k}": v for k, v in route.items()})
            ctx.update({"needs.route.outputs.trust": "screen", "steps.project.outputs.kind": "enrollment",
                        "steps.project.outputs.name": "x"})
            rc, log, build = self.run_step(review, "gather", self.TAKE, ctx, tree)
            self.assertEqual(rc, 0, log)
            self.assertEqual(build, {"build": no_result, "binaries": "", "checks": "", "commit": ""},
                             f"take-build-results' outputs ({label}): {log}")
            ctx.update({f"steps.build.outputs.{k}": v for k, v in build.items()})
            checkout = self.dir / "checkout"
            shutil.rmtree(checkout, ignore_errors=True)
            self.main_checkout(checkout, tree)
            (checkout / "projects" / "x").mkdir()
            (checkout / "projects" / "x" / "project.yaml").write_text("repo: https://github.com/mallory/libx#v1\n")
            rc, log, _ = self.run_step(review, "gather", self.GATHER, ctx, checkout)
            self.assertEqual(rc, 0, log)
            gathered = checkout / ".review"
            pr = json.loads((gathered / "pr.json").read_text().rsplit("\n(exit status ", 1)[0])
            self.assertEqual(((pr["number"], pr["headRefOid"]), (gathered / "pr.diff").read_text(),
                              (gathered / "build" / "result.md").read_text(),
                              (gathered / "build" / "binaries.md").read_text(),
                              (gathered / "build" / "checks.md").read_text()),
                             ((7, HEAD), (self.api / "pr-7.diff").read_text(), no_result + "\n", "\n", "\n"),
                             f"the gathered files ({label})")
            marked = [str(p.relative_to(gathered)) for p in gathered.rglob("*")
                      if p.is_file() and "ARTIFACT-" in p.read_text(errors="replace")]
            self.assertEqual(marked, [], f"the gathered files ({label})")
            ctx.update({"needs.route.outputs.free": "", "needs.gather.result": "success",
                        "needs.gather.outputs.checks": build["checks"], "needs.gather.outputs.screen": "true",
                        "needs.gather.outputs.name": "x", "needs.screen.result": "success",
                        "needs.screen.outputs.verdict": "clean", "needs.screen.outputs.checks": "claude",
                        "needs.review.result": "success", "needs.review.outputs.comment": "Thanks.\n",
                        "needs.review.outputs.verdicts": json.dumps({check: "pass" for check in ids}),
                        "needs.review.outputs.reasons": "{}", "needs.review.outputs.held_object": "",
                        "needs.hold.result": "success", "steps.app.outputs.token": APP_TOKEN})
            since = len(self.calls())
            rc, log, _ = self.run_step(review, "comment", self.POST, ctx, tree, given={
                "SCREENED": "claude", "HELD": "false", "RECORD": "true", "APPROVE": "false", "HOLDING": "false"})
            self.assertEqual(rc, 0, log)
            sent = [r for r in self.requests(since) if r["method"] != "GET"]
            self.assertEqual([(r["token"], r["method"], r["endpoint"]) for r in sent],
                             [(APP_TOKEN, "POST", f"repos/{REPO}/issues/7/comments"),
                              (APP_TOKEN, "POST", f"repos/{REPO}/check-runs")], f"the comment job's post ({label})")
            self.assertTrue(sent[0]["body"]["body"].endswith(f"\n<!-- oss-verify-review-head {HEAD} -->\n"),
                            f"the comment job's post ({label})")
            self.assertEqual((sent[1]["body"]["head_sha"], sent[1]["body"]["external_id"]), (HEAD, PR),
                             f"the comment job's post ({label})")
            # No call of the run (gh api, gh pr view or gh pr diff) names the artifact's number or head.
            named = [args for _, args in self.calls()
                     if any(re.search(r"(^|/)8(/|$)", arg) for arg in args) or OTHER in " ".join(args)]
            self.assertEqual(named, [], f"the calls of the run ({label})")

    def test_s_an_artifact_of_another_number_head_or_diff_changes_nothing(self):
        self.case()

    def test_control_s_route_reads_the_artifact(self):
        self.case(self.copy_tree("unchanged"))
        changed = self.copy_tree("changed", [(".github/workflows/review.yml", self.ROUTE_OUTPUTS,
                                              self.FROM_ARTIFACT + self.ROUTE_OUTPUTS)])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("route's outputs (another number)", str(caught.exception))

    def test_control_s_take_build_results_compares_nothing(self):
        self.case(self.copy_tree("unchanged"))
        changed = self.copy_tree("changed", [(".github/scripts/take-build-results", self.COMPARISON, "")])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("take-build-results' outputs (another number)", str(caught.exception))

    def test_s_a_member_that_holds_more_than_its_header_says_gives_no_result(self):
        """The header of results.json says that it holds the results of this head alone; it holds them and more than
        1 MiB after them. take-build-results gives its no-result line."""
        import test_enroll_dispatch
        review = self.workflow(ROOT, "review.yml")
        no_result = re.search(r'^NO_RESULT = "(.*)"$', (ROOT / ".github/scripts/take-build-results").read_text(),
                              re.M).group(1)
        text = json.dumps(self.results({}))
        data = test_enroll_dispatch.understated("results.json", text + " " * (1 << 20), len(text))
        self.assertLess(len(data), 1 << 20)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.getinfo("results.json").file_size, len(text))
        self.fixture({}, data)
        ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "needs.route.outputs.pr": PR,
               "needs.route.outputs.sha": HEAD, "needs.route.outputs.build_run": self.RUN,
               "steps.project.outputs.name": "x"}
        rc, log, build = self.run_step(review, "gather", self.TAKE, ctx, ROOT)
        self.assertEqual(rc, 0, log)
        self.assertEqual(build, {"build": no_result, "binaries": "", "checks": "", "commit": ""}, log)


class SteeringFiles(unittest.TestCase):
    """(u): the list of steering files."""

    # The patterns of .github/CODEOWNERS at commit 62081ee (#194), the last commit that changed them, in their order.
    CODEOWNERS_62081EE = (
        "/.github/", "/src/", "/infra/", "/seeds/", ".claude/", "CLAUDE*.md", "AGENTS*.md", "/.mcp.json", "/*.py",
        "/pytest.ini", "/.pytest.ini", "/pyproject.toml", "/uv.lock", "/.python-version", "/setup.cfg", "/tox.ini",
        "/review.md", "/review-change.md", "/review-issue.md", "/.claude/skills/write-to-maintainer/",
        "/.github/CODEOWNERS")

    def test_u_the_steering_files_are_the_engineering_patterns_of_codeowners(self):
        path = ROOT / ".github" / "scripts" / "steering.py"
        self.assertTrue(path.is_file(), ".github/scripts/steering.py is absent")
        spec = importlib.util.spec_from_file_location("steering_of_this_test", path)
        steering = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(steering)
        self.assertEqual(list(steering.STEERING), list(self.CODEOWNERS_62081EE))
        for name in (".github/workflows/build.yaml", ".github/workflows/review.yml", "projects/x/AGENTS.md",
                     "projects/x/.claude/settings.json", "docs/CLAUDE.md"):
            self.assertTrue(steering.is_steering(name), name)
        for name in ("projects/x/build.sh", "docs/build-contract.md", "tests/test_x.py"):
            self.assertFalse(steering.is_steering(name), name)
        owned = [line.split()[0] for line in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
                 if line.strip() and not line.startswith("#") and "@theorem-labs/engineering" in line.split()[1:]]
        self.assertEqual(owned, list(steering.STEERING))


class SteeringGate(Stand):
    """(w): Enroll dispatch's steering-file gate, with the stand-in API of World of tests/test_enroll_dispatch.py. Its
    reviews and the permissions of the reviewers are answers that this class adds to World's table, and the
    enrollment's project is x."""

    AGENTS = ("projects/x/project.yaml", "projects/x/build.sh", "projects/x/AGENTS.md")
    SETTINGS = ("projects/x/project.yaml", "projects/x/build.sh", "projects/x/.claude/settings.json")
    # Control: decision() with no steering-file gate.
    GATE = ('    why, approval = steering_gate(api, repo, number, pull, files, sha)\n'
            '    if why:\n'
            '        return outcome("none", f"pull request {number}: {why}", number, project, sha)\n'
            '    where = f"pull request {number}: projects/{project}/ at {sha[:7]}{approval}"')
    NO_GATE = '    where = f"pull request {number}: projects/{project}/ at {sha[:7]}"'

    def setUp(self):
        super().setUp()
        import test_enroll_dispatch
        self.ed = test_enroll_dispatch

    def review(self, review_id, login, state="APPROVED", commit=None, kind="User", minutes=30):
        return {"id": review_id, "user": {"login": login, "type": kind}, "state": state,
                "commit_id": commit or self.ed.SHA, "submitted_at": ago(minutes)}

    def world_api(self, files, reviews=(), permissions=None, merged=False):
        """World's API for an enrollment of projects/x/ by mallory, an account without write access. Its files are
        `files`, the reviews of the pull request are `reviews`, and `permissions` gives the collaborator permission of
        their accounts. With `merged`, the run of Enrollment merged for its merge completed."""
        ed = self.ed
        world = ed.World()
        world.artifacts[101] = ed.record(project="x")
        world.files = [{"filename": f, "status": "added"} for f in files]
        pull = dict(ed.World.pull(), user={"login": "mallory"})
        if merged:
            world.run(ed.MERGED_RUN, ".github/workflows/enroll-merged.yml", "pull_request")
            world.runs[ed.MERGED_RUN].update(conclusion="success", display_title=f"merged #{ed.PR}")
            pull = dict(ed.World.pull(state="closed"), merged=True, merged_by={"login": "a-member"},
                        user={"login": "mallory"})
        world.pulls = [pull]
        api = world.api()
        api.table[f"repos/{REPO}/contents/projects/x/project.yaml?ref={ed.SHA}"] = world.project_yaml
        api.table[f"repos/{REPO}/pulls/{ed.PR}/reviews?per_page=100"] = [list(reviews)]
        for login, permission in {"mallory": "read", **(permissions or {})}.items():
            api.table[f"repos/{REPO}/collaborators/{login}/permission"] = {"permission": permission}
        return api

    def decide(self, dispatch, api, merged=False):
        """What Enroll dispatch decides after the run of tests.yaml at the head, or after Enrollment merged's run."""
        run = self.ed.MERGED_RUN if merged else 104
        return dispatch.decide(api, REPO, run, "pull_request", self.ed.SHA)

    def case_first(self, dispatch):
        """An enrollment whose files are all under projects/x/, one of them a steering file, whose every check passed
        and whose Enrollment review is success: no dispatch and no label, and review-passed does not go on."""
        for files in (self.AGENTS, self.SETTINGS):
            got = self.decide(dispatch, self.world_api(files))
            self.assertEqual((got["decision"], got["label"]), ("none", ""), f"the first case, {files[-1]}: {got}")
            self.assertNotEqual(got.get("review_passed"), "on", f"the first case, {files[-1]}")
            self.assertIn(f"changes the steering file {files[-1]}", got["reason"], f"the first case, {files[-1]}")

    def test_w_a_steering_file_waits_for_a_person_approval_of_the_head(self):
        ed = self.ed
        self.case_first(ed.dispatch)
        # A person approval of the head: an APPROVED review of it by a User who is not the author, with write or admin
        # permission.
        for login, permission in (("alice", "write"), ("boss", "admin")):
            got = self.decide(ed.dispatch, self.world_api(self.AGENTS, [self.review(1, login)], {login: permission}))
            self.assertEqual(got["decision"], "dispatch", got)
            self.assertIn(f"{login} approved {ed.SHA[:7]}, which changes the steering file projects/x/AGENTS.md",
                          got["reason"])
        # None of these is one.
        for why, reviews, permissions in (
                ("a User with read permission", [self.review(1, "reader")], {"reader": "read"}),
                ("the author", [self.review(1, "mallory")], {"mallory": "write"}),
                ("an older head", [self.review(1, "alice", commit=ed.NEWER)], {"alice": "write"}),
                ("a Bot", [self.review(1, "helper[bot]", kind="Bot")], {"helper[bot]": "write"}),
                ("an approval and then CHANGES_REQUESTED",
                 [self.review(1, "alice", minutes=20), self.review(2, "alice", "CHANGES_REQUESTED", minutes=10)],
                 {"alice": "write"})):
            got = self.decide(ed.dispatch, self.world_api(self.AGENTS, reviews, permissions))
            self.assertEqual((got["decision"], got["label"]), ("none", ""), (why, got))
            self.assertIn("changes the steering file projects/x/AGENTS.md", got["reason"], why)
        # The same gate for a merge.
        got = self.decide(ed.dispatch, self.world_api(self.AGENTS, merged=True), merged=True)
        self.assertEqual((got["decision"], got["label"], got.get("merged")), ("none", "", None), got)
        self.assertIn("changes the steering file projects/x/AGENTS.md", got["reason"])
        got = self.decide(ed.dispatch, self.world_api(self.AGENTS, [self.review(1, "alice")], {"alice": "write"},
                                                      merged=True), merged=True)
        self.assertEqual((got["decision"], got.get("merged")), ("dispatch", "true"), got)

    def load(self, tree):
        """The copy of enroll-dispatch in `tree`, with the stand-in maintainer check of test_enroll_dispatch.py."""
        path = tree / ".github" / "scripts" / "enroll-dispatch"
        saved = list(sys.path)
        try:
            loader = importlib.machinery.SourceFileLoader(f"enroll_dispatch_{tree.name}", str(path))
            dispatch = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
            loader.exec_module(dispatch)
        finally:
            sys.path[:] = saved
        dispatch.standing = lambda config, login: ""
        return dispatch

    def test_control_w_gate_taken_out_of_decision(self):
        self.case_first(self.load(self.copy_tree("unchanged")))
        changed = self.load(self.copy_tree("changed", [(".github/scripts/enroll-dispatch", self.GATE, self.NO_GATE)]))
        with self.assertRaises(AssertionError) as caught:
            self.case_first(changed)
        self.assertIn("the first case, projects/x/AGENTS.md", str(caught.exception))


class RunByHandOffMain(Stand):
    """(z2): a run by hand of review.yml on another branch than main."""

    SIGNING = {"screen", "review", "hold", "comment", "triage"}
    # route's outputs as for gh workflow run review.yml -f pr=7, for each path of a run by hand.
    ROUTES = ({"kind": "enrollment", "pr": PR, "sha": HEAD, "author": "mallory", "build_run": "900", "trust": "screen",
               "triage": "true"},
              {"kind": "change", "pr": PR, "sha": HEAD, "author": "mallory", "trust": "writer"},
              {"kind": "change", "pr": PR, "sha": HEAD, "author": "mallory", "held": "true", "trust": "screen"},
              {"kind": "enrollment", "pr": PR, "sha": HEAD, "author": "mallory", "held": "true", "trust": "screen"},
              {"kind": "change", "pr": PR, "sha": HEAD, "author": "mallory", "trust": "cap",
               "free": "2026-11-17T00:00:00Z"},
              {"pr": PR, "sha": HEAD, "author": "mallory", "replay": "true"})
    # What each job gives when it runs: the review held a finding back, kept a session, and the triage comment is
    # written.
    OUTPUTS = {"gather": {"digest": "d" * 64, "screen": "true", "name": "x"},
               "screen": {"verdict": "clean", "checks": "claude"},
               "review": {"comment": "Thanks.", "held_object": "held/77/x", "session": "1", "kind": "change"},
               "triage-gather": {"comment": "<!-- oss-verify-triage -->"}}

    def case(self, tree=ROOT):
        import test_outside_screen
        review = self.workflow(tree, "review.yml")
        signing = {n for n, j in review["jobs"].items()
                   if "environment" in j or "id-token" in (j.get("permissions") or {})}
        self.assertEqual(signing, self.SIGNING)
        for route in self.ROUTES:
            got, _ = test_outside_screen.run_graph(route, outputs=self.OUTPUTS, event="workflow_dispatch",
                                                   workflow=review, ref="refs/heads/other")
            self.assertEqual({n: got[n] for n in sorted(signing)}, {n: "skipped" for n in sorted(signing)},
                             f"the jobs that sign in, for {route}")
        self.pull_request(("README.md",))
        self.serve(f"repos/{REPO}/actions/runs", {"workflow_runs": [
            {"id": 11, "head_sha": HEAD, "head_repository": {"full_name": FORK}, "head_branch": BRANCH}]})
        ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "github.event_name": "workflow_dispatch",
               "github.ref": "refs/heads/other", "github.actor": "alice", "inputs.pr": PR}
        rc, log, got = self.run_step(review, "route", "An enrollment, a change or an issue", ctx, tree)
        self.assertEqual((rc, got, self.calls()), (0, {}, []), f"route's step: {log}")
        self.assertIn("Started by hand on refs/heads/other, not on main: nothing runs.", log)

    def test_z2_a_run_by_hand_off_main_holds_no_identity_and_posts_nothing(self):
        self.case()

    def test_control_z2_main_check_taken_out_of_each_jobs_if(self):
        self.case(self.copy_tree("unchanged"))

        def no_main_check(text):
            workflow = yaml.load(text, Loader=YAML_LOADER)
            changed = set()
            for name, job in workflow["jobs"].items():
                if MAIN_CHECK in str(job.get("if", "")):
                    job["if"] = job["if"].replace(MAIN_CHECK, "true")
                    changed.add(name)
            self.assertEqual(changed, self.SIGNING)
            return yaml.safe_dump(workflow, sort_keys=False, width=1 << 16)

        changed = self.copy_tree("changed", [(".github/workflows/review.yml", no_main_check)])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("the jobs that sign in", str(caught.exception))


class ClaudeFiles(Stand):
    """(claude files): what Claude Code would read as instructions, in the files of a pull request, reaches no review.
    The gather job of review.yml runs step by step against the stand-in gh. git runs as it is, but reaches no network."""

    CLAUDE = re.compile(r"(?i)(^|/)(claude[^/]*\.md|agents[^/]*\.md|\.claude)(/|$)")

    def setUp(self):
        super().setUp()
        import test_outside_screen
        self.tos = test_outside_screen
        self.review = self.workflow(ROOT, "review.yml")

    def test_claude_files_of_an_enrollment_are_not_kept(self):
        files = {"projects/x/project.yaml": "repo: https://github.com/mallory/libx#v1\nlanguage: c\n",
                 "projects/x/build.sh": "#!/bin/bash\n", "projects/x/AGENTS.md": "PULL-REQUEST-INSTRUCTIONS\n",
                 "projects/x/CLAUDE.md": "PULL-REQUEST-INSTRUCTIONS\n"}
        checkout, sha = self.repository(files)
        self.main_checkout(checkout)
        self.pull_request(tuple(files), head=sha)
        route = {"kind": "enrollment", "pr": PR, "sha": sha, "author": "mallory", "build_run": "900",
                 "trust": "screen"}
        rc, log, got = self.gather_job(self.review, route, checkout, self.tos.evaluate)
        self.assertEqual(rc, 0, log)
        self.assertEqual(got["name"], "x", log)
        kept = members(self.temp / "review-data" / "review.tar")
        self.assertIn("projects/x/project.yaml", kept)
        self.assertEqual([m for m in kept if self.CLAUDE.search(m)], [])
        self.assertEqual(self.take(got["digest"], "x"), 0)

    def test_claude_files_of_a_change_are_not_kept(self):
        files = {"docs/CLAUDE.md": "PULL-REQUEST-INSTRUCTIONS\n", ".claude/settings.json": '{"hooks": {}}\n',
                 "docs/build-contract.md": "A change of the build contract.\n"}
        self.pull_request(tuple(files))
        for path, text in files.items():
            self.serve_raw(f"repos/{REPO}/contents/{path}?ref={HEAD}", text)
        checkout = self.main_checkout(self.dir / "checkout")
        route = {"kind": "change", "pr": PR, "sha": HEAD, "author": "mallory", "trust": "screen"}
        rc, log, got = self.gather_job(self.review, route, checkout, self.tos.evaluate)
        self.assertEqual(rc, 0, log)
        kept = members(self.temp / "review-data" / "review.tar")
        self.assertIn(".review/head/docs/build-contract.md", kept)
        self.assertEqual([m for m in kept if self.CLAUDE.search(m)], [])
        read = [r["endpoint"] for r in self.requests() if "/contents/" in (r["endpoint"] or "")]
        self.assertEqual(read, [f"repos/{REPO}/contents/docs/build-contract.md?ref={HEAD}"])

    def take(self, digest, name):
        """The review job's step "Take what the gather job kept", in a checkout of its own: its exit status."""
        where = self.dir / "review-checkout"
        shutil.rmtree(where, ignore_errors=True)
        (where / ".github").mkdir(parents=True)
        (where / ".github" / "scripts").symlink_to(ROOT / ".github" / "scripts")
        ctx = {"needs.gather.outputs.digest": digest, "needs.gather.outputs.name": name}
        rc, self.took, _ = self.run_step(self.review, "review", "Take what the gather job kept", ctx, where,
                                         evaluate=self.tos.evaluate)
        return rc

    def test_claude_files_the_review_job_refuses_a_tar_that_holds_one(self):
        for member in ("projects/x/CLAUDE.md", "projects/x/AGENTS.md"):
            for held_in in (True, False):
                tar = self.temp / "review-data" / "review.tar"
                tar.parent.mkdir(exist_ok=True)
                with tarfile.open(tar, "w") as archive:
                    for path, text in ((".review/pr.json", "{}\n"), ("projects/x/project.yaml", "language: c\n"),
                                       *([(member, "PULL-REQUEST-INSTRUCTIONS\n")] if held_in else [])):
                        info = tarfile.TarInfo(path)
                        info.size = len(text)
                        archive.addfile(info, io.BytesIO(text.encode()))
                rc = self.take(hashlib.sha256(tar.read_bytes()).hexdigest(), "x")
                self.assertEqual(rc, 1 if held_in else 0, (member, held_in, self.took))
                if held_in:
                    self.assertIn("::error::take-review-data: review.tar holds a CLAUDE*.md or an AGENTS*.md under "
                                  "projects/x/", self.took)

    def test_claude_files_no_checkout_of_review_yml_takes_a_ref(self):
        checkouts = [(name, step) for name, job in self.review["jobs"].items() for step in job.get("steps") or []
                     if str(step.get("uses", "")).startswith("actions/checkout@")]
        self.assertTrue(checkouts)
        for name, step in checkouts:
            self.assertNotIn("ref", step.get("with") or {}, name)


class HeldApproval(Stand):
    """d7: a run by hand of review.yml for a pull request whose runs GitHub holds, and the comment job's approval of
    them; and a run by hand for a merged pull request whose run of enroll-merged.yml GitHub holds, and the comment job's
    replay of the merge. The screen's verdict is the screen job's output, given to run_graph of
    tests/test_outside_screen.py."""

    ROUTE = "An enrollment, a change or an issue"
    TRUST = "Whether the author and the account that started the run have write access"
    TOKEN = "Get the oss-verify App's token to approve the held runs"
    APPROVE = "Approve the held runs"
    REPLAY = "Replay the merge for Enroll dispatch"
    # The merge commit of pull request 7, once it is merged.
    MERGE = "c" * 40
    # The held runs that the API lists: (id, workflow file, head commit, head repository, head branch). 11 to 13 are
    # the pull request's, at HEAD. 21 is of another head, 22 of another repository, and 23 of another branch.
    HELD = ((11, ".github/workflows/build.yaml", HEAD, FORK, BRANCH),
            (12, ".github/workflows/terms.yaml", HEAD, FORK, BRANCH),
            (13, ".github/workflows/validate.yaml", HEAD, FORK, BRANCH),
            (21, ".github/workflows/build.yaml", OTHER, FORK, BRANCH),
            (22, ".github/workflows/build.yaml", HEAD, "eve/oss-verify", BRANCH),
            (23, ".github/workflows/build.yaml", HEAD, FORK, "other"))
    # Controls: the verdict condition taken out of the approval step's condition, or out of approve-held.
    APPROVE_IF = ("APPROVE: ${{ needs.route.outputs.held == 'true' && needs.screen.result == 'success'"
                  " && needs.screen.outputs.verdict == 'clean' }}")
    APPROVE_IF_ANY = "APPROVE: ${{ needs.route.outputs.held == 'true' && needs.screen.result == 'success' }}"
    REFUSAL = '[ "${SCREEN_VERDICT:-}" = clean ] || fail "the screen\'s verdict is not clean: no run is approved."\n'

    def setUp(self):
        super().setUp()
        import test_outside_screen
        self.tos = test_outside_screen
        self.review = self.workflow(ROOT, "review.yml")
        # What the trust step reads: the author mallory has no write access, and alice has it. The daily cap counts no
        # run.
        self.serve(f"repos/{REPO}/collaborators/mallory/permission", {"permission": "read"})
        self.serve(f"repos/{REPO}/collaborators/alice/permission", {"permission": "write"})
        self.serve("users/alice", {"type": "User"})
        self.serve(f"repos/{REPO}/actions/workflows/review.yml/runs", {"workflow_runs": []})
        self.serve(f"repos/{REPO}/actions/artifacts", {"artifacts": []})

    def held_runs(self, runs):
        self.serve(f"repos/{REPO}/actions/runs", {"workflow_runs": [
            {"id": i, "path": path, "event": "pull_request", "status": "action_required", "head_sha": sha,
             "head_repository": {"full_name": repository}, "head_branch": branch}
            for i, path, sha, repository, branch in runs]})
        for run in self.HELD:
            self.serve(f"repos/{REPO}/actions/runs/{run[0]}/approve", {})

    def route(self, actor):
        """route's two steps for gh workflow run review.yml -f pr=7 on main, started by `actor`: its outputs, and the
        log of its first step."""
        ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "github.event_name": "workflow_dispatch",
               "github.ref": "refs/heads/main", "github.actor": actor, "github.run_id": "1000", "inputs.pr": PR}
        rc, log, decided = self.run_step(self.review, "route", self.ROUTE, ctx, ROOT, evaluate=self.tos.evaluate)
        self.assertEqual(rc, 0, log)
        ctx.update({f"steps.decide.outputs.{k}": v for k, v in decided.items()})
        trust = self.step(self.review, "route", self.TRUST)
        if not self.tos.evaluate(trust["if"], ctx):
            return decided, log
        rc, more, trusted = self.run_script(trust["run"], ROOT, **env_of(self.review, "route", trust, ctx,
                                                                          evaluate=self.tos.evaluate))
        self.assertEqual(rc, 0, more)
        return {**decided, **trusted}, log

    def graph(self, route, verdict, gather=None, review=None):
        """run_graph of review.yml for a run by hand on main, with the screen's verdict."""
        gather = gather or {"digest": "d" * 64, "screen": "true", "name": ""}
        return self.tos.run_graph(route, outputs={"gather": gather, "screen": {"verdict": verdict, "checks": "claude"}},
                                  event="workflow_dispatch", workflow=review or self.review, ref="refs/heads/main")

    def comment_env(self, ctx, review=None):
        review = review or self.review
        return {k: render(v, ctx, self.tos.evaluate) for k, v in review["jobs"]["comment"]["env"].items()}

    def ran(self, name, env, review=None):
        """Whether the comment job's step `name` runs, for the job's env `env`."""
        step = self.step(review or self.review, "comment", name)
        return bool(self.tos.evaluate(step["if"], {f"env.{k}": v for k, v in env.items()}))

    def approve(self, tree, ctx):
        """The comment job's step "Approve the held runs", as review.yml in `tree` runs it: (its exit status, its log,
        its calls of the API)."""
        review = self.workflow(tree, "review.yml")
        ctx = dict(ctx, **{"github.token": WORKFLOW_TOKEN, "github.repository": REPO,
                           "steps.app.outputs.token": APP_TOKEN, "steps.approve.outputs.token": APPROVE_TOKEN})
        since = len(self.calls())
        rc, log, _ = self.run_step(review, "comment", self.APPROVE, ctx, tree, evaluate=self.tos.evaluate)
        return rc, log, self.requests(since)

    def test_held_a_run_by_hand_on_main_finds_the_held_runs_of_the_head(self):
        self.pull_request(("projects/x/project.yaml", "projects/x/build.sh"))
        self.held_runs(self.HELD)
        route, log = self.route("alice")
        self.assertEqual({k: route.get(k) for k in ("pr", "sha", "kind", "held", "build_run", "trust")},
                         {"pr": PR, "sha": HEAD, "kind": "enrollment", "held": "true", "build_run": None,
                          "trust": "screen"}, log)

    def test_held_a_screen_that_passes_approves_the_heads_held_runs_with_the_apps_token(self):
        self.pull_request(("README.md",))
        self.held_runs(self.HELD)
        route, log = self.route("github-actions[bot]")
        self.assertEqual({k: route.get(k) for k in ("pr", "sha", "kind", "held", "triage", "trust")},
                         {"pr": PR, "sha": HEAD, "kind": "change", "held": "true", "triage": None, "trust": "screen"},
                         log)
        got, ctx = self.graph(route, "clean")
        self.assertEqual({j: got[j] for j in ("gather", "screen", "review", "comment")},
                         {"gather": "success", "screen": "success", "review": "skipped", "comment": "success"})
        env = self.comment_env(ctx)
        self.assertEqual((env["APPROVE"], env["HOLDING"]), ("true", "false"))
        self.assertEqual({n: self.ran(n, env) for n in (self.TOKEN, self.APPROVE, "Label it review-held and say so",
                                                        "Post the comment and record the verdict")},
                         {self.TOKEN: True, self.APPROVE: True, "Label it review-held and say so": False,
                          "Post the comment and record the verdict": False})
        rc, log, sent = self.approve(ROOT, ctx)
        self.assertEqual(rc, 0, log)
        self.assertEqual([(r["token"], r["endpoint"]) for r in sent if r["method"] == "POST"],
                         [(APPROVE_TOKEN, f"repos/{REPO}/actions/runs/{n}/approve") for n in (11, 12, 13)], log)
        self.assertEqual({r["token"] for r in sent}, {APPROVE_TOKEN})

    def case_held_verdict(self, tree):
        """A screen that held a held head: the comment job records the hold, and its approval step does not run.
        approve-held, run alone with that verdict, refuses and calls nothing."""
        review = self.workflow(tree, "review.yml")
        self.pull_request(("README.md",))
        self.held_runs(self.HELD)
        route = {"kind": "change", "pr": PR, "sha": HEAD, "author": "mallory", "held": "true", "trust": "screen"}
        got, ctx = self.graph(route, "held", review=review)
        self.assertEqual(got["comment"], "success", "the comment job, which records the hold")
        env = self.comment_env(ctx, review)
        ran, sent = self.ran(self.APPROVE, env, review), []
        if ran:
            _, _, sent = self.approve(tree, ctx)
        approved = [r["endpoint"] for r in sent if (r["endpoint"] or "").endswith("/approve")]
        self.assertEqual((ran, approved), (False, []), "the approval of a head that the screen held")
        since = len(self.calls())
        alone = {"GH_TOKEN": APPROVE_TOKEN, "REPO": REPO, "PR": PR, "HEAD_SHA": HEAD, "SCREEN_VERDICT": "held"}
        rc, log, _ = self.run_script(".github/scripts/approve-held", tree, **alone)
        self.assertEqual((rc, self.calls()[since:]), (1, []), f"approve-held alone, for the verdict held: {log}")
        self.assertIn("::error::approve-held: the screen's verdict is not clean: no run is approved.", log)

    def test_held_a_screen_that_held_the_head_approves_nothing(self):
        self.case_held_verdict(ROOT)

    def test_held_control_verdict_condition_taken_out_of_the_approval_step(self):
        self.case_held_verdict(self.copy_tree("unchanged"))
        changed = self.copy_tree("changed", [(".github/workflows/review.yml", self.APPROVE_IF, self.APPROVE_IF_ANY)])
        with self.assertRaises(AssertionError) as caught:
            self.case_held_verdict(changed)
        self.assertIn("the approval of a head that the screen held", str(caught.exception))

    def test_held_control_verdict_refusal_taken_out_of_approve_held(self):
        self.case_held_verdict(self.copy_tree("unchanged"))
        changed = self.copy_tree("changed", [(".github/scripts/approve-held", self.REFUSAL, "")])
        with self.assertRaises(AssertionError) as caught:
            self.case_held_verdict(changed)
        self.assertIn("approve-held alone, for the verdict held", str(caught.exception))

    def test_held_a_head_whose_runs_are_not_held_gets_no_approval(self):
        self.pull_request(("README.md",))
        # Held runs of another head, repository or branch alone.
        self.held_runs([run for run in self.HELD if run[0] > 20])
        route, log = self.route("alice")
        self.assertEqual((route.get("kind"), route.get("held"), route.get("trust")), ("change", None, "screen"), log)
        got, ctx = self.graph(route, "clean")
        self.assertEqual((got["review"], got["comment"]), ("success", "success"))
        env = self.comment_env(ctx)
        self.assertEqual(env["APPROVE"], "false")
        self.assertEqual((self.ran(self.TOKEN, env), self.ran(self.APPROVE, env)), (False, False))

    def test_held_a_head_that_moved_after_the_screen_gets_no_approval(self):
        self.pull_request(("README.md",), head=OTHER)
        self.held_runs(self.HELD)
        route = {"kind": "change", "pr": PR, "sha": HEAD, "author": "mallory", "held": "true", "trust": "screen"}
        got, ctx = self.graph(route, "clean")
        self.assertEqual(got["comment"], "success")
        rc, log, sent = self.approve(ROOT, ctx)
        self.assertEqual(rc, 0, log)
        self.assertEqual([(r["method"], r["endpoint"]) for r in sent], [("GET", f"repos/{REPO}/pulls/{PR}")], log)
        self.assertIn(f"The head of pull request {PR} is now {OTHER}, not {HEAD}", log)

    def test_held_a_run_that_held_runs_started_for_a_head_no_longer_held_runs_nothing(self):
        self.pull_request(("README.md",))
        self.held_runs([])
        route, log = self.route("github-actions[bot]")
        self.assertEqual(route, {}, log)
        self.assertIn("Held runs started this run for a held head, and the head is no longer held.", log)
        got, _ = self.tos.run_graph({}, event="workflow_dispatch", workflow=self.review, ref="refs/heads/main")
        self.assertEqual({job for job, result in got.items() if result != "skipped"}, {"route", "collect"}, got)

    def test_held_an_enrollment_that_take_project_refuses_is_gathered_as_a_change_and_screened(self):
        files = {"README.md": "The fork's README.\n",
                 "projects/x/project.yaml": "repo: https://github.com/mallory/libx#v1\nlanguage: c\n"}
        self.pull_request(tuple(files))
        for path, text in files.items():
            self.serve_raw(f"repos/{REPO}/contents/{path}?ref={HEAD}", text)
        self.held_runs(self.HELD)
        route, log = self.route("github-actions[bot]")
        self.assertEqual((route.get("kind"), route.get("held"), route.get("trust")), ("enrollment", "true", "screen"),
                         log)
        checkout = self.main_checkout(self.dir / "checkout")
        rc, log, gathered = self.gather_job(self.review, route, checkout, self.tos.evaluate)
        self.assertEqual(rc, 0, log)
        self.assertIn("this held head is gathered as a change, and the screen reads each changed file", log)
        self.assertEqual((gathered["name"], gathered["screen"]), ("", "true"))
        kept = members(self.temp / "review-data" / "review.tar")
        self.assertTrue({".review/head/README.md", ".review/head/projects/x/project.yaml"} <= set(kept), kept)
        got, ctx = self.graph(route, "clean", gather=gathered)
        self.assertEqual((got["screen"], got["review"], got["comment"]), ("success", "skipped", "success"))
        env = self.comment_env(ctx)
        self.assertEqual((env["APPROVE"], env["RECORD"]), ("true", "false"))

    def merged(self, held, merged=True):
        """Pull request 7 of mallory's fork at HEAD, closed, and with `merged` merged into main at MERGE, and the runs of
        enroll-merged.yml that GitHub holds: `held`, each (id, head commit, head repository, head branch)."""
        pull = self.pull_request(("projects/x/project.yaml", "projects/x/build.sh"))
        pull.update(state="closed", merged=merged, merge_commit_sha=self.MERGE)
        self.serve(f"repos/{REPO}/pulls/{PR}", pull)
        self.serve(f"repos/{REPO}/actions/workflows/enroll-merged.yml/runs", {"workflow_runs": [
            {"id": i, "path": ".github/workflows/enroll-merged.yml", "event": "pull_request",
             "status": "action_required", "head_sha": sha, "head_repository": {"full_name": repository},
             "head_branch": branch} for i, sha, repository, branch in held]})

    def test_held_a_merged_pull_request_whose_merge_run_is_held_is_replayed_with_the_apps_token(self):
        for label, held, commits in (("at its head commit", [(31, HEAD, FORK, BRANCH)], [HEAD]),
                                     ("at its merge commit", [(32, self.MERGE, FORK, BRANCH)], [HEAD, self.MERGE])):
            with self.subTest(label):
                self.clear()
                self.merged(held)
                route, log = self.route("github-actions[bot]")
                self.assertEqual(route, {"pr": PR, "sha": HEAD, "author": "mallory", "replay": "true"}, log)
                self.assertIn(f"GitHub holds run {held[0][0]} of enroll-merged.yml at {held[0][1]}", log)
                # route reads the pull request and the held runs of enroll-merged.yml at each commit until it finds
                # one, and no file of the closed pull request, no other held run and no Build run.
                self.assertEqual([r["endpoint"] for r in self.requests()], [f"repos/{REPO}/pulls/{PR}"] + [
                    f"repos/{REPO}/actions/workflows/enroll-merged.yml/runs?event=pull_request&status=action_required"
                    f"&head_sha={commit}&per_page=100" for commit in commits], log)
                got, ctx = self.tos.run_graph(route, event="workflow_dispatch", workflow=self.review,
                                              ref="refs/heads/main")
                self.assertEqual({job for job, result in got.items() if result != "skipped"},
                                 {"route", "comment", "collect"}, got)
                # The check review jobs: the comment job asked for and passed, and every other job skipped, as asked.
                code, said = self.tos.required(ctx)
                self.assertEqual(code, 0, said)
                self.assertIn("the jobs the run asked for (comment)", said)
                env = self.comment_env(ctx)
                self.assertEqual({k: env[k] for k in ("KIND", "REPLAY", "APPROVE", "HOLDING", "RECORD")},
                                 {"KIND": "", "REPLAY": "true", "APPROVE": "false", "HOLDING": "false",
                                  "RECORD": "false"})
                # Of the comment job's steps, those with no condition (its checkout, its sign-in and the read of the
                # App's key, which every token needs) and, of the others, the token that can write runs and the replay.
                steps = self.review["jobs"]["comment"]["steps"]
                self.assertEqual([s.get("name") or s["uses"].split("@")[0] for s in steps if "if" not in s],
                                 ["actions/checkout", "Sign in to Google Cloud", "Read the oss-verify App's key"])
                self.assertEqual([s["name"] for s in steps if "if" in s and self.ran(s["name"], env)],
                                 [self.TOKEN, self.REPLAY])
                ctx = dict(ctx, **{"github.token": WORKFLOW_TOKEN, "github.repository": REPO,
                                   "steps.app.outputs.token": APP_TOKEN, "steps.approve.outputs.token": APPROVE_TOKEN})
                since = len(self.calls())
                rc, log, _ = self.run_step(self.review, "comment", self.REPLAY, ctx, ROOT, evaluate=self.tos.evaluate)
                self.assertEqual(rc, 0, log)
                self.assertEqual(self.calls()[since:], [(APPROVE_TOKEN, ["workflow", "run", "enroll-merged.yml", "-R",
                                                                         REPO, "--ref", "main", "-f", f"pr={PR}"])])
                self.assertIn(f"Started enroll-merged.yml on main for pull request {PR} with the oss-verify App's token",
                              log)

    def test_held_a_closed_pull_request_with_no_held_merge_run_runs_nothing(self):
        # A held run of enroll-merged.yml of another commit, repository or branch alone; none; and a pull request
        # closed with no merge, whose head has a held run.
        for label, held, merged, said in (
                ("another commit, repository or branch",
                 [(33, OTHER, FORK, BRANCH), (34, HEAD, "eve/oss-verify", BRANCH), (35, self.MERGE, FORK, "other")],
                 True, f"Pull request {PR} is merged, and GitHub holds no run of enroll-merged.yml"),
                ("no held run", [], True, f"Pull request {PR} is merged, and GitHub holds no run of enroll-merged.yml"),
                ("closed with no merge", [(31, HEAD, FORK, BRANCH)], False,
                 f"Pull request {PR} is closed, and not merged into the default branch: nothing runs.")):
            with self.subTest(label):
                self.clear()
                self.merged(held, merged)
                # Held runs of other workflows at the head: a closed pull request is still not screened.
                self.held_runs(self.HELD)
                for actor in ("github-actions[bot]", "alice"):
                    route, log = self.route(actor)
                    self.assertEqual(route, {}, log)
                    self.assertIn(said, log)
                got, _ = self.tos.run_graph({}, event="workflow_dispatch", workflow=self.review, ref="refs/heads/main")
                self.assertEqual({job for job, result in got.items() if result != "skipped"}, {"route", "collect"}, got)

    def test_held_the_comment_job_makes_a_token_of_its_own_for_the_approval(self):
        steps = self.review["jobs"]["comment"]["steps"]
        names = [s.get("name") for s in steps]
        app = self.step(self.review, "comment", "Get the oss-verify App's token")
        token = self.step(self.review, "comment", self.TOKEN)
        approve = self.step(self.review, "comment", self.APPROVE)

        def permissions(step):
            return {k: v for k, v in step["with"].items() if k.startswith("permission-")}

        for step in (app, token):
            self.assertTrue(step["uses"].startswith("actions/create-github-app-token@"), step)
        self.assertNotIn("permission-actions", permissions(app))
        self.assertEqual(permissions(token), {"permission-actions": "write"})
        self.assertEqual((token["id"], token["if"], approve["if"]),
                         ("approve", "env.APPROVE == 'true' || env.REPLAY == 'true'", "env.APPROVE == 'true'"))
        self.assertEqual(app["if"], "env.APPROVE != 'true' && env.REPLAY != 'true'")
        self.assertEqual(names.index(self.TOKEN) + 1, names.index(self.APPROVE))
        self.assertLess(names.index(self.TOKEN), names.index(self.REPLAY))
        replay = self.step(self.review, "comment", self.REPLAY)
        self.assertEqual(replay["if"], "env.REPLAY == 'true'")
        for step in (approve, replay):
            self.assertEqual(step["env"]["GH_TOKEN"], "${{ steps.approve.outputs.token }}")
        # No other step takes the token that can write runs.
        self.assertEqual([s.get("name") for s in steps if "steps.approve.outputs.token" in json.dumps(s)],
                         [self.APPROVE, self.REPLAY])
        # The token that can write runs is made only on an approval (route found held runs, and the screen succeeded
        # with the verdict clean) or on a merge's replay (route's replay). The approval runs only on an approval, the
        # replay only on a replay, and the other token only on neither.
        for replay in ("true", ""):
            for held in ("true", "false", ""):
                for result in ("success", "failure", "cancelled", "skipped"):
                    for verdict in ("clean", "held", ""):
                        ctx = {"needs.route.outputs.held": held, "needs.screen.result": result,
                               "needs.screen.outputs.verdict": verdict, "needs.route.outputs.replay": replay}
                        env = self.comment_env(ctx)
                        approval = (held, result, verdict) == ("true", "success", "clean")
                        replays = replay == "true"
                        self.assertEqual(tuple(self.ran(n, env) for n in (self.TOKEN, self.APPROVE, self.REPLAY,
                                                                          "Get the oss-verify App's token")),
                                         (approval or replays, approval, replays, not (approval or replays)), ctx)


class HeldScreen(Stand):
    """d7: the screen job of a held head, whose screen cannot sign in, with the stand-in services of
    tests/test_screen.py on 127.0.0.1 in place of Google's, Microsoft's and Anthropic's."""

    # Control: a sign-in that fails holds the item, as a check that cannot answer does.
    STOPS = ("        except SignInError as e:\n"
             "            if sign_in_stops:\n"
             "                raise\n")
    HOLDS = "        except SignInError as e:\n"

    def setUp(self):
        super().setUp()
        import test_outside_screen
        import test_screen
        self.tos, self.ts = test_outside_screen, test_screen

    def services(self, exchange):
        """The stand-in services: each answers as the real one does, and Anthropic's token exchange answers
        `exchange`."""
        services = self.ts.Services()
        self.addCleanup(services.close)
        answers = services.answers
        answers["/oidc"] = lambda _b: (200, {"value": "github-jwt"})
        answers["/oauth2/v2.0/token"] = (200, {"access_token": "azure-not-a-secret", "token_type": "Bearer"})
        answers["/v1/oauth/token"] = exchange
        answers[":sanitizeUserPrompt"] = lambda _b: self.ts.armor()
        answers["/contentsafety/text:shieldPrompt"] = lambda b: self.ts.shields(*[False] * len(b["documents"]))
        answers["/v1/messages"] = lambda _b: self.ts.message()
        return services

    def screen_env(self, review, step, services):
        """The env of the screen job's `step`, with the services' addresses in place of the real ones, and the identity
        token's request that the runner gives a job with id-token: write."""
        ctx = {"needs.route.outputs.trust": "screen", "needs.route.outputs.pr": PR, "needs.gather.outputs.name": "",
               "needs.gather.outputs.writers": "", "needs.gather.outputs.app_comments": "",
               "steps.google.outputs.access_token": "google-not-a-secret", "github.repository": REPO,
               "github.server_url": "https://github.com", "github.run_id": "77", "github.run_attempt": "1"}
        env = env_of(review, "screen", step, ctx, evaluate=self.tos.evaluate)
        url = services.url
        served = {"MODEL_ARMOR_URL": f"{url}/armor", "STORAGE_URL": f"{url}/storage", "AZURE_LOGIN_URL": f"{url}/entra",
                  "CONTENT_SAFETY_URL": f"{url}/safety", "ANTHROPIC_URL": f"{url}/anthropic",
                  "ACTIONS_ID_TOKEN_REQUEST_URL": f"{url}/oidc?api-version=2.0",
                  "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request"}
        # No real service is reached.
        self.assertEqual({k for k, v in review["jobs"]["screen"]["env"].items() if str(v).startswith("https://")},
                         {k for k in served if k.endswith("_URL")} - {"ACTIONS_ID_TOKEN_REQUEST_URL"})
        env.update(served)
        return env

    def screen_checkout(self, tree):
        """The screen job's checkout: screen.py of `tree`, and the .review/ of pull request 7 that it took."""
        where = self.dir / "screen-checkout"
        shutil.rmtree(where, ignore_errors=True)
        (where / ".github" / "scripts").mkdir(parents=True)
        shutil.copy2(tree / ".github" / "scripts" / "screen.py", where / ".github" / "scripts" / "screen.py")
        (where / ".review").mkdir()
        (where / ".review" / "pr.json").write_text(json.dumps({
            "number": 7, "title": "Fix a typo", "author": {"login": "mallory"}, "body": "A body of a few words.",
            "headRefOid": HEAD, "isDraft": False, "comments": [], "reviews": [], "files": [{"path": "README.md"}],
            "commits": [{"messageHeadline": "Fix a typo", "messageBody": ""}]}) + "\n(exit status 0)\n")
        (where / ".review" / "pr.diff").write_text("diff --git a/README.md b/README.md\n+A fixed line.\n")
        return where

    def case_no_token(self, tree):
        """The Screen step, where Anthropic's token exchange gives no token: the step fails, and gives no verdict."""
        review = self.workflow(tree, "review.yml")
        step = self.step(review, "screen", "Screen")
        services = self.services((200, {}))
        rc, log, _ = self.run_script(step["run"], self.screen_checkout(tree), **self.screen_env(review, step, services))
        self.assertNotEqual(rc, 0, f"the Screen step's exit status: {log}")
        self.assertNotRegex(self.output.read_text(), r"(?m)^verdict=", "the Screen step's outputs")
        self.assertIn("::error::The screen could not sign in, and gives no verdict (Anthropic's token exchange: an "
                      "answer with no token).", log)
        self.assertEqual((services.to("/v1/messages"), services.objects), ([], {}))

    def test_held_a_screen_that_gets_no_anthropic_token_fails_with_no_verdict(self):
        self.case_no_token(ROOT)

    def test_held_control_screen_sign_in_failure_turned_into_a_held_verdict(self):
        self.case_no_token(self.copy_tree("unchanged"))
        changed = self.copy_tree("changed", [(".github/scripts/screen.py", self.STOPS, self.HOLDS)])
        with self.assertRaises(AssertionError) as caught:
            self.case_no_token(changed)
        self.assertIn("the Screen step's exit status", str(caught.exception))

    def test_held_a_refused_sign_in_ends_the_screen_job_before_its_daily_cap_mark(self):
        review = self.workflow(ROOT, "review.yml")
        steps = review["jobs"]["screen"]["steps"]
        names = [s.get("name") or s["uses"].split("@")[0] for s in steps]
        signs_in = names.index("Sign in to the screen's services")
        step = steps[signs_in]
        self.assertNotIn("continue-on-error", step)
        # It runs for a screen: a measurement alone skips it (tests/test_outside_screen.py, DailyCap).
        self.assertTrue(self.tos.evaluate(step.get("if", "true"), {"needs.route.outputs.trust": "screen"}))
        for refused, said in (("/oauth2/v2.0/token", "Microsoft Entra's access token: no answer, HTTP 401"),
                              ("/v1/oauth/token", "Anthropic's token exchange: no answer, HTTP 401")):
            services = self.services((200, {"access_token": "anthropic-not-a-secret", "token_type": "Bearer"}))
            services.answers[refused] = (401, {"error": "refused"})
            rc, log, got = self.run_script(step["run"], self.screen_checkout(ROOT),
                                           **self.screen_env(review, step, services))
            self.assertEqual((rc, got), (1, {}), log)
            self.assertIn(f"::error::The screen could not sign in, and gives no verdict ({said}).", log)
            self.assertEqual(services.to("/v1/messages"), [])
        # After a step that failed, GitHub runs only a step whose if calls always(), failure() or cancelled(): the mark
        # and its upload, after the sign-ins, do not run.
        mark = names.index("Mark this run's screen for the daily cap")
        upload = [i for i, s in enumerate(steps) if (s.get("with") or {}).get("name") == "daily-cap-screen"]
        self.assertEqual(upload, [mark + 1])
        self.assertGreater(mark, signs_in)
        ran = [names[i] for i in range(signs_in + 1, len(steps))
               if re.search(r"\b(always|failure|cancelled)\(\)", str(steps[i].get("if", "")))]
        self.assertNotIn(names[mark], ran)
        self.assertNotIn(names[mark + 1], ran)
        # The daily cap counts no completed run that route marked (daily-cap-route) and whose screen job did not mark
        # (daily-cap-screen): run 50. Run 51, whose screen job marked, counts.
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.serve(f"repos/{REPO}/issues/7", {"user": {"login": "mallory"}})
        self.serve(f"repos/{REPO}/collaborators/mallory/permission", {"permission": "read"})
        for runs, counted in (((50,), "0"), ((50, 51), "1")):
            self.serve(f"repos/{REPO}/actions/workflows/review.yml/runs", {"workflow_runs": [
                {"id": n, "created_at": ago(n), "status": "completed", "event": "workflow_dispatch",
                 "actor": {"login": "github-actions[bot]"}, "display_title": "Pull request 7"} for n in runs]})
            for name, marked in (("daily-cap-route", runs), ("daily-cap-screen", [n for n in runs if n != 50])):
                self.serve(f"repos/{REPO}/actions/artifacts?name={name}&per_page=100", {"artifacts": [
                    {"id": n * 10, "name": name, "expired": False, "workflow_run": {"id": n}} for n in marked]})
            rc, log, _ = self.run_script(".github/scripts/screened-review-cap", ROOT, REPO=REPO, RUN_ID="1000",
                                         ACCOUNT="mallory", NOW=now,
                                         **{k: str(review["env"][k]) for k in ("ALLOWED_BOTS", "REVIEW_CAP",
                                                                                "REVIEW_CAP_AUTHOR")})
            self.assertEqual(rc, 0, log)
            self.assertEqual(dict(re.findall(r"^(count|account_count)=(.*)$", log, re.M)),
                             {"count": counted, "account_count": counted}, (runs, log))


class HeldRuns(Stand):
    """d7: the step of .github/workflows/held-runs.yml (Held runs), against the stand-in gh. Its fixtures' times are
    before now."""

    STEP = "Start a screen for each held head"

    def setUp(self):
        super().setUp()
        self.need(ROOT, ".github/workflows/held-runs.yml")
        self.workflow_text = (ROOT / ".github" / "workflows" / "held-runs.yml").read_text()
        self.held, self.pulls, self.reviews, self.replays, self.jobs, self.comment = [], [], [], [], {}, {}

    @staticmethod
    def held_run(run_id, sha, repository, branch, minutes, path=".github/workflows/build.yaml"):
        return {"id": run_id, "path": path, "event": "pull_request", "status": "action_required", "head_sha": sha,
                "head_repository": {"full_name": repository}, "head_branch": branch, "created_at": ago(minutes)}

    @staticmethod
    def pull(number, repository, branch, sha, state="open", merged=False, merge=None):
        return {"number": number, "state": state, "merged_at": ago(5) if merged else None,
                "base": {"ref": "main", "repo": {"full_name": REPO}},
                "head": {"ref": branch, "sha": sha, "repo": {"full_name": repository}},
                "merge_commit_sha": merge or "e" * 40}

    @staticmethod
    def by_hand(run_id, title, minutes, status="completed", conclusion="success", event="workflow_dispatch",
                started=None):
        """A run by hand created `minutes` ago, whose latest attempt started `started` minutes ago (at its creation
        when None)."""
        return {"id": run_id, "display_title": title, "status": status, "event": event,
                "conclusion": conclusion if status == "completed" else None, "created_at": ago(minutes),
                "run_started_at": ago(minutes if started is None else started)}

    def go(self, refused=()):
        """One run of the step: the runs it started, as the arguments of gh, then the runs whose failed jobs it re-ran
        (reruns). `refused`: the runs whose re-run GitHub refuses. The stand-in serves no answer for those, so gh fails
        on them as on GitHub's refusal, and the step's exit status is not checked."""
        for path in self.api.glob("*.json"):
            path.unlink()
        self.serve(f"repos/{REPO}", {"default_branch": "main"})
        self.serve(f"repos/{REPO}/actions/runs", {"workflow_runs": self.held})
        self.serve(f"repos/{REPO}/pulls", self.pulls)
        self.serve(f"repos/{REPO}/actions/workflows/review.yml/runs", {"workflow_runs": self.reviews})
        self.serve(f"repos/{REPO}/actions/workflows/enroll-merged.yml/runs", {"workflow_runs": self.replays})
        for run_id, screen in self.jobs.items():
            jobs = [{"id": run_id * 10 + 1, "name": "route", "conclusion": "success"}]
            if screen is not None:
                jobs.append({"id": run_id * 10 + 2, "name": "screen", "conclusion": screen})
            if run_id in self.comment:
                # The comment job, and its step that failed.
                jobs.append({"id": run_id * 10 + 3, "name": "comment", "conclusion": "failure",
                             "steps": [{"name": self.comment[run_id], "conclusion": "failure"}]})
            self.serve(f"repos/{REPO}/actions/runs/{run_id}/jobs", {"total_count": len(jobs), "jobs": jobs})
        # GitHub's answer to a re-run of the failed jobs of a run: 201, with an empty object.
        for run in self.reviews:
            if run["id"] not in refused:
                self.serve(f"repos/{REPO}/actions/runs/{run['id']}/rerun-failed-jobs", {})
        since = len(self.calls())
        workflow = yaml.safe_load(self.workflow_text)
        rc, log, _ = self.run_step(workflow, "held-runs", self.STEP,
                                   {"github.token": WORKFLOW_TOKEN, "github.repository": REPO}, self.temp)
        if not refused:
            self.assertEqual(rc, 0, log)
        calls = self.calls()[since:]
        # It only reads, but for the runs it starts and the runs whose failed jobs it re-runs, each with the job's own
        # token.
        reran = []
        for r in self.requests(since):
            if r["method"] == "GET" and "--input" not in r["args"]:
                continue
            rerun = re.fullmatch(f"repos/{REPO}/actions/runs/([0-9]+)/rerun-failed-jobs", r["endpoint"] or "")
            self.assertTrue(rerun and r["method"] == "POST" and "--input" not in r["args"], r)
            self.assertEqual(r["token"], WORKFLOW_TOKEN, r)
            reran.append(self.reruns(int(rerun.group(1))))
        # Each read of the runs by hand asks GitHub only for the runs created from a time. No run that the case serves
        # is before that time, so GitHub's answer is the stand-in's, which ignores the filter.
        for r in self.requests(since):
            if "/runs?event=workflow_dispatch" in (r["endpoint"] or ""):
                bounds = [a.removeprefix("created=>=") for a in r["args"] if a.startswith("created=>=")]
                self.assertEqual(len(bounds), 1, r["args"])
                self.assertRegex(bounds[0], r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
                runs = self.reviews if "/review.yml/" in r["endpoint"] else self.replays
                self.assertEqual([run for run in runs if run["created_at"] < bounds[0]], [], bounds[0])
        started = [(token, " ".join(args)) for token, args in calls if args[:2] == ["workflow", "run"]]
        self.assertEqual({token for token, _ in started} - {WORKFLOW_TOKEN}, set())
        self.log = log
        return [run for _, run in started] + reran

    @staticmethod
    def starts(file, number):
        return f"workflow run {file} -R {REPO} --ref main -f pr={number}"

    @staticmethod
    def reruns(run_id):
        return f"POST repos/{REPO}/actions/runs/{run_id}/rerun-failed-jobs"

    def test_held_runs_starts_a_screen_of_the_head_that_no_run_screened_and_then_nothing(self):
        a, b = "1" * 40, "2" * 40
        self.pulls = [self.pull(11, "alice/oss-verify", "feature/a", a), self.pull(12, "bob/oss-verify", "fix-b", b)]
        self.held = [self.held_run(1102, b, "bob/oss-verify", "fix-b", 100),
                     self.held_run(1101, a, "alice/oss-verify", "feature/a", 120),
                     self.held_run(1100, a, "alice/oss-verify", "feature/a", 125, ".github/workflows/terms.yaml")]
        self.reviews = [self.by_hand(901, "Pull request 11", 90)]
        self.jobs = {901: "success"}
        self.assertEqual(self.go(), [self.starts("review.yml", 12)], self.log)
        # A second run with nothing new: the run it started is queued, and then it screened the head.
        self.reviews.insert(0, self.by_hand(902, "Pull request 12", 0, status="queued"))
        self.jobs[902] = None
        self.assertEqual(self.go(), [], self.log)
        self.reviews[0] = self.by_hand(902, "Pull request 12", 0)
        self.jobs[902] = "success"
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_held_event_after_a_screen_that_passed_gets_one_more_screen(self):
        sha = "3" * 40
        self.pulls = [self.pull(21, "carol/oss-verify", "c", sha)]
        self.reviews = [self.by_hand(911, "Pull request 21", 180)]
        self.jobs = {911: "success"}
        # Terms, on an edit of the description after that screen.
        self.held = [self.held_run(2101, sha, "carol/oss-verify", "c", 120, ".github/workflows/terms.yaml")]
        self.assertEqual(self.go(), [self.starts("review.yml", 21)], self.log)

    def test_held_runs_a_workflow_run_review_does_not_count_as_a_screen(self):
        sha = "4" * 40
        self.pulls = [self.pull(31, "dan/oss-verify", "d", sha)]
        self.held = [self.held_run(3101, sha, "dan/oss-verify", "d", 120)]
        self.reviews = [self.by_hand(921, "Review of run 5555", 60, event="workflow_run")]
        self.jobs = {921: "success"}
        self.assertEqual(self.go(), [self.starts("review.yml", 31)], self.log)

    def test_held_runs_a_head_the_screen_held_is_not_screened_again(self):
        sha = "5" * 40
        self.pulls = [self.pull(41, "erin/oss-verify", "f", sha)]
        self.held = [self.held_run(4102, sha, "erin/oss-verify", "f", 120),
                     self.held_run(4101, sha, "erin/oss-verify", "f", 180)]
        # screen.py exits 0 with the verdict held too: the run and its job screen ended success.
        self.reviews = [self.by_hand(931, "Pull request 41", 60)]
        self.jobs = {931: "success"}
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_run_with_no_verdict_starts_the_head_again_at_most_once_an_hour(self):
        sha = "6" * 40
        for label, minutes, screen, held_at, again in (
                ("screen failed, run 90 minutes old", 90, "failure", 180, True),
                ("screen failed, run 30 minutes old", 30, "failure", 180, False),
                ("no job screen, run 90 minutes old", 90, None, 180, True),
                ("no job screen, run 30 minutes old", 30, None, 180, False),
                ("screen failed, run 40 minutes old, a held event 10 minutes ago", 40, "failure", 10, False),
                ("screen failed, run 90 minutes old, a held event 10 minutes ago", 90, "failure", 10, True)):
            self.pulls = [self.pull(51, "fay/oss-verify", "g", sha)]
            self.held = [self.held_run(5101, sha, "fay/oss-verify", "g", held_at)]
            self.reviews = [self.by_hand(941, "Pull request 51", minutes, conclusion="failure")]
            self.jobs = {941: screen}
            self.assertEqual(self.go(), [self.starts("review.yml", 51)] if again else [], (label, self.log))
        # The next schedule, 15 minutes after a start: the run it started ended before a verdict too.
        self.reviews = [self.by_hand(942, "Pull request 51", 15, conclusion="failure"),
                        self.by_hand(941, "Pull request 51", 105, conclusion="failure")]
        self.jobs = {941: "failure", 942: "failure"}
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_run_that_failed_after_a_screen_that_passed_reruns_its_failed_jobs_at_most_once_an_hour(self):
        sha = "7" * 40
        # Its job screen succeeded, and then its comment job failed: it could not sign in, or GitHub refused the
        # approval (the App's installation has not accepted actions: write).
        for failed in ("Sign in to Google Cloud", "Get the oss-verify App's token to approve the held runs"):
            for label, minutes, started, again in (
                    ("run 90 minutes old", 90, None, True),
                    ("run 30 minutes old", 30, None, False),
                    ("run 150 minutes old, its latest attempt 30 minutes ago", 150, 30, False),
                    ("run 150 minutes old, its latest attempt 70 minutes ago", 150, 70, True)):
                self.pulls = [self.pull(121, "pat/oss-verify", "s", sha)]
                self.held = [self.held_run(12101, sha, "pat/oss-verify", "s", 180)]
                self.reviews = [self.by_hand(971, "Pull request 121", minutes, conclusion="failure", started=started)]
                self.jobs, self.comment = {971: "success"}, {971: failed}
                self.assertEqual(self.go(), [self.reruns(971)] if again else [], (failed, label, self.log))
                if again:
                    self.assertIn("re-ran the failed jobs of run 971 of review.yml", self.log)
                    self.assertIn("The verdict stands, and nothing screens the head again.", self.log)
        # The next schedule, while the re-run runs: nothing. Then the re-run failed too, 15 minutes after its start:
        # nothing in that hour.
        self.reviews = [self.by_hand(971, "Pull request 121", 150, status="in_progress", started=0)]
        self.assertEqual(self.go(), [], self.log)
        self.reviews = [self.by_hand(971, "Pull request 121", 150, conclusion="failure", started=15)]
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_run_that_ended_success_with_its_screen_counts_as_a_screen(self):
        sha = "8" * 40
        for minutes in (10, 120):
            self.pulls = [self.pull(131, "quinn/oss-verify", "t", sha)]
            self.held = [self.held_run(13101, sha, "quinn/oss-verify", "t", 180)]
            self.reviews = [self.by_hand(981, "Pull request 131", minutes)]
            self.jobs = {981: "success"}
            self.assertEqual(self.go(), [], (minutes, self.log))

    def test_held_runs_a_run_in_progress_starts_nothing(self):
        sha = "9" * 40
        for minutes, held_at in ((5, 120), (90, 10)):
            self.pulls = [self.pull(61, "gus/oss-verify", "h", sha)]
            self.held = [self.held_run(6101, sha, "gus/oss-verify", "h", held_at)]
            self.reviews = [self.by_hand(951, "Pull request 61", minutes, status="in_progress")]
            self.jobs = {951: None}
            self.assertEqual(self.go(), [], (minutes, self.log))

    def test_held_runs_a_held_merge_run_is_replayed_once(self):
        merged = ".github/workflows/enroll-merged.yml"
        h71, m71, h72, m72 = "c" * 40, "d" * 40, "e" * 40, "f" * 40
        self.pulls = [self.pull(71, "hal/oss-verify", "p71", h71, state="closed", merged=True, merge=m71),
                      self.pull(72, "ivy/oss-verify", "p72", h72, state="closed", merged=True, merge=m72)]
        # 71 is held at its head commit, 72 at its merge commit.
        self.held = [self.held_run(7101, h71, "hal/oss-verify", "p71", 60, merged),
                     self.held_run(7201, m72, "ivy/oss-verify", "p72", 50, merged)]
        self.replays = [self.by_hand(7998, "merged #72", 600)]
        self.assertEqual(self.go(), [self.starts("enroll-merged.yml", 71), self.starts("enroll-merged.yml", 72)],
                         self.log)
        # The next run, with the replays there: nothing new.
        self.replays = [self.by_hand(8002, "merged #72", 0, status="queued"),
                        self.by_hand(8001, "merged #71", 0, status="queued")] + self.replays
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_held_run_at_a_head_the_pull_request_no_longer_has_gets_nothing(self):
        self.pulls = [self.pull(91, "max/oss-verify", "q", "0" * 40)]
        self.held = [self.held_run(9101, "1" * 40, "max/oss-verify", "q", 30)]
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_held_run_of_the_apps_own_label_gets_no_screen(self):
        # The screen held head 5555555 of pull request 41 an hour ago (run 931 counts). The comment job then put the
        # label review-held on the pull request with the oss-verify App's token. That label starts a run of Maintainer
        # confirmed, which GitHub holds as it holds a person's label (the top of held-runs.yml). The App's own label is
        # no new event at the head, so the head that the screen held is not screened again (R2, dispatch://OSSV-202's
        # rule). A person's label after the hold still gets one more screen.
        sha = "5" * 40
        for who, kind, again in (("oss-verify[bot]", "Bot", False), ("sjawhar", "User", True)):
            pull = self.pull(41, "erin/oss-verify", "f", sha)
            pull["user"] = {"login": "erin", "type": "User"}
            self.pulls = [pull]
            label = self.held_run(4103, sha, "erin/oss-verify", "f", 58, ".github/workflows/maintainer-confirmed.yml")
            label["actor"] = label["triggering_actor"] = {"login": who, "type": kind}
            pushed = self.held_run(4101, sha, "erin/oss-verify", "f", 180)
            pushed["actor"] = pushed["triggering_actor"] = {"login": "erin", "type": "User"}
            self.held = [label, pushed]
            self.reviews = [self.by_hand(931, "Pull request 41", 60)]
            self.jobs = {931: "success"}
            self.assertEqual(self.go(), [self.starts("review.yml", 41)] if again else [], (who, self.log))

    def test_held_runs_a_rerun_that_github_refuses_leaves_the_other_heads_their_screen(self):
        # GitHub refuses a re-run of a run that was re-run 50 times, or that started more than 30 days ago
        # (https://github.blog/changelog/2026-04-10-actions-workflows-are-limited-to-50-reruns/). Pull request 301 is
        # due a re-run of run 971 (its screen gave a verdict, its comment job failed, its latest attempt started 70
        # minutes ago), and GitHub refuses it. Pull request 302, held before 301, was never screened. The refusal of
        # one head's re-run does not keep the other head from its screen.
        p, q = "7" * 40, "2" * 40
        self.pulls = [self.pull(301, "pat/oss-verify", "s", p), self.pull(302, "rob/oss-verify", "u", q)]
        self.held = [self.held_run(30101, p, "pat/oss-verify", "s", 200),
                     self.held_run(30201, q, "rob/oss-verify", "u", 300)]
        self.reviews = [self.by_hand(971, "Pull request 301", 190, conclusion="failure", started=70)]
        self.jobs, self.comment = {971: "success"}, {971: "Sign in to Google Cloud"}
        self.assertIn(self.starts("review.yml", 302), self.go(refused={971}), self.log)

    def test_held_runs_workflow_holds_no_identity_and_starts_on_its_schedule_alone(self):
        workflow = yaml.safe_load(self.workflow_text)
        self.assertEqual(workflow["name"], "Held runs")
        self.assertEqual(triggers(workflow), {"schedule": [{"cron": "*/15 * * * *"}]})
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(list(workflow["jobs"]), ["held-runs"])
        job = workflow["jobs"]["held-runs"]
        self.assertNotIn("environment", job)
        self.assertEqual(job["permissions"], {"actions": "write", "pull-requests": "read"})
        self.assertNotIn("secrets.", self.workflow_text)
        self.assertNotIn("id-token", self.workflow_text)
        self.assertEqual([s for s in job["steps"] if "uses" in s], [])


class ReviewThatPasses(Stand):
    """d10: the comment of an enrollment whose review passes says what happens next, as review.md's paragraph
    says."""

    # The paragraph's three statements.
    STATEMENTS = ("Theorem writes the theorem statements of the project, and publishes them as its `publish` field "
                  "allows", "We do not promise to merge the pull request or to start work on the proofs.",
                  "The maintainer needs to do nothing more.")
    # The stand-in model's comment, which says them to the maintainer.
    SAID = ("Theorem writes the theorem statements of the project, and publishes them as its `publish` field allows",
            "We do not promise to merge the pull request or to start work on the proofs.",
            "You need to do nothing more.")
    COMMENT = ("Every check of review.md passes for projects/libreac/. The check `Enrollment review` of this commit "
               "has the conclusion `success`. " + SAID[0] + " (`docs/project-yaml.md`, \"publish\"). " + SAID[1]
               + " " + SAID[2] + "\n")
    SESSION = "09227178-7bbf-4e5f-86db-8736e530ef01"

    def paragraph(self):
        """The bullet of review.md's section "Write the comment" that holds the first statement."""
        text = (ROOT / "review.md").read_text()
        section = text.split("\n## Write the comment\n", 1)[1].split("\n## ", 1)[0]
        found = [bullet for bullet in re.split(r"(?m)^- ", section) if self.STATEMENTS[0] in bullet]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_passes_review_md_says_what_happens_after_a_review_that_passes(self):
        paragraph = self.paragraph()
        for statement in self.STATEMENTS:
            self.assertIn(statement, paragraph)
        self.assertIn("conclusion `success`", paragraph)

    def test_passes_review_md_says_nothing_the_comment_of_a_pass_must_not_say(self):
        said = re.compile(r"theorem decides|decides the next step|maintainer will (look|review)|held bug", re.I)
        lines = (ROOT / "review.md").read_text().splitlines()
        self.assertEqual([(n, line) for n, line in enumerate(lines, 1) if said.search(line)], [])

    def test_passes_the_comment_of_an_enrollment_that_passes_says_what_happens_next(self):
        import test_check_checks
        import test_outside_screen
        evaluate = test_outside_screen.evaluate
        review = self.workflow(ROOT, "review.yml")
        posting = test_check_checks.PostingStep
        # The prompt that the review job builds has the model read review.md, which holds the paragraph.
        self.paragraph()
        ctx = {"needs.route.outputs.kind": "enrollment", "needs.route.outputs.pr": "8",
               "needs.route.outputs.sha": posting.HEAD, "needs.gather.outputs.name": "libreac",
               "needs.gather.outputs.session": "", "needs.gather.outputs.last": ""}
        rc, log, prompt = self.run_step(review, "review", "What the review reads and gives", ctx, ROOT,
                                        evaluate=evaluate)
        self.assertEqual(rc, 0, log)
        self.assertTrue(prompt["prompt"].startswith("Read review.md at the root of this checkout"), prompt)
        self.assertEqual(self.step(review, "review", "Review")["with"]["prompt"], "${{ steps.prompt.outputs.prompt }}")
        # The stand-in model: its structured output, every verdict pass.
        ids = json.loads(subprocess.run([str(ROOT / ".github/scripts/review-verdict"), "--ids"], env=self.env,
                                        check=True, capture_output=True, text=True).stdout)
        result = self.dir / "execution.json"
        result.write_text(json.dumps([
            {"type": "system", "subtype": "init", "session_id": self.SESSION},
            {"type": "result", "subtype": "success", "session_id": self.SESSION, "structured_output": {
                "comment": self.COMMENT, "held": "", "verdicts": {check: "pass" for check in ids}, "reasons": {}}}]))
        ctx.update({"steps.review.outputs.execution_file": str(result),
                    "steps.review.outputs.session_id": self.SESSION})
        rc, log, kept = self.run_step(review, "review", "Keep the draft, and the held finding apart from it", ctx,
                                      self.temp, evaluate=evaluate)
        self.assertEqual(rc, 0, log)
        # The comment job's step "Post the comment and record the verdict", as PostingStep runs it.
        step = posting()
        step.setUp()
        try:
            _, requests = step.post(verdicts=json.loads(kept["verdicts"]), reasons=json.loads(kept["reasons"]),
                                    review=kept["comment"])
            sentence = subprocess.run([str(ROOT / ".github/scripts/review-verdict"), "--sentence", "success"],
                                      env=self.env, check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(step.first_sentence(requests), sentence)
            [(_, _, body)] = step.comments(requests)
            for said in self.SAID:
                self.assertIn(said, body)
            self.assertEqual(step.record(requests)["conclusion"], "success")
        finally:
            step.tearDown()


if __name__ == "__main__":
    unittest.main()
