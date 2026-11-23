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
  (u)  The list of .github/scripts/steering.py is the list of the last patterns of .github/CODEOWNERS, which give a file
       to @theorem-labs/engineering and @theorem-labs/research, at commit 62081ee and today.
  (w)  Enroll dispatch sends no enrollment that changes a steering file, and puts no label on it, until a person
       approved its head: for an open pull request and for a merge.
  (x)  No workflow with workflow_dispatch builds the code of a pull request (oss-verify check, docker).
  (z2) A run by hand on another branch than main holds no identity and posts nothing.
  (claude files) The gather job keeps no CLAUDE*.md, AGENTS*.md or .claude/ of the pull request, and the review job
       refuses one.
  (publish) toolchain-images-publish.yaml, the one workflow with packages: write for the frame-pointer images, runs on
       workflow_run, so GitHub runs main's copy of it. It acts only on a push run of toolchain-images.yaml on main
       of this repository that passed. It runs no docker, and no script of it reads GITHUB_SHA or holds an
       expression. Each value that it holds and toolchain-images.yaml holds too is equal in both files. make's steps
       and then its push step, run on the same infra/toolchains.tsv, pass or refuse the same frame-pointer rows:
       publish checks out that file at the commit that make built, not at main's newest commit. The push step reads
       each digest where make's upload of it lands. publish downloads that upload from the run of
       toolchain-images.yaml that started it, not from its own run, which holds none of make's artifacts. The push
       step copies the image of each base row to the one package of the frame-pointer images,
       ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain, under a tag that names the language of the row. Its job's
       token can read contents for the checkout, read actions for the download, and write packages for the copy.
       publish installs crane only from the archive with the SHA-256 of its pin, and no step of it writes
       GITHUB_PATH or GITHUB_ENV. Its push step stops at an unset variable before it copies, and at a base row
       outside the toolchain packages before any command of crane. It logs out of ghcr.io after its push.
  (artifacts) Each script of .github/scripts that reads a file of a Build run's artifact (read_member) reads an
       artifact and a file that build.yaml uploads, with if-no-files-found: error. The step that writes the file, run
       in (s) and in tests/test_enroll_dispatch.py, writes it at the path of the upload.
  (workflow_run) Each name that a workflow_run trigger listens to is the name of exactly one workflow file of
       .github/workflows.
The held runs (each test name holds the word held):
  route finds the held runs of a head on a run by hand. It counts the held runs that Held runs counts: neither counts a
  run of the oss-verify App's own label. The comment job approves them with a token of the oss-verify App that can
  write runs, only when the screen passed that head. Its hold of a held head replaces no verdict of the review that the
  App recorded at that head, but it replaces an earlier hold: the newest check run Enrollment review of the App decides.
  A screen that cannot sign in fails with no verdict, before the mark of the daily cap. Held runs
  (.github/workflows/held-runs.yml) starts a run by hand of review.yml for each held head that no run screened, and
  re-runs the failed jobs of a run whose screen gave a verdict.
A review that passes: the review job hands the comment that the model wrote on to the comment job as it is.

Each case runs the steps and the scripts of the workflows with stand-ins: this file's gh, which gives the API's answers
from files and records each call with its GH_TOKEN, and for the screen the stand-in services of tests/test_screen.py.
A changed-code control (its name holds the word control) copies the scripts and the workflows into a temporary
directory. It runs its case on that copy, where the case passes. The copy is the same for each control of a case, so
only the first of them in a process runs it, and the others read its pass (Stand.passes_unchanged). Then it changes a
second copy, runs the case there, and asserts that the case fails.

Of the test files, the cases (r), (s), (u), (w) and (x) import only tests/test_enroll_dispatch.py: (w) makes its
stand-in API with its World, and uses only what World has before the move too. In a tree of the commit before the move
(0666dceb750a), these cases fail on their own assertions.
"""
import ast
import contextlib
import copy
import datetime
import fnmatch
import functools
import hashlib
import importlib.machinery
import importlib.util
import io
import itertools
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
from unittest import mock

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
# An endpoint with a file $FAKE_GH/<endpoint>.error fails: gh prints the text of that file. A list of runs (an answer
# with workflow_runs) is as GitHub gives it. With -f or -F created=<from>..<to> or created=>=<from>, it holds only the
# runs created in that range. With a filter (actor, branch, check_suite_id, created, event, head_sha or status, in the
# query or in a field), it holds at most the first 1,000 runs.
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
filter=. endpoint="" input="" slurp="" raw="" created="" cut=""
while [ $# -gt 0 ]; do
  case $1 in
    --paginate|--) shift ;;
    --slurp) slurp=1; shift ;;
    --jq) filter=$2; shift 2 ;;
    --input) input=$2; shift 2 ;;
    -H) case $2 in *vnd.github.raw*|*vnd.github.diff*) raw=1 ;; esac; shift 2 ;;
    -f|-F)
      case $2 in created=*) created=${2#created=} ;; esac
      case ${2%%=*} in actor|branch|check_suite_id|created|event|head_sha|status) cut=1 ;; esac
      shift 2 ;;
    --method|-X) shift 2 ;;
    *) endpoint=$1; shift ;;
  esac
done
case "&${endpoint#*\?}" in
  *"&actor="*|*"&branch="*|*"&check_suite_id="*|*"&created="*|*"&event="*|*"&head_sha="*|*"&status="*) cut=1 ;;
esac
[ "$input" != - ] || cat > "$FAKE_GH/input.$n"
queried=${endpoint//\//_}
bare=${endpoint%%\?*}
bare=${bare//\//_}
for file in "$FAKE_GH/$queried.error" "$FAKE_GH/$bare.error"; do
  if [ -f "$file" ]; then cat "$file" >&2; exit 1; fi
done
runs='if type == "object" and (.workflow_runs | type) == "array" then .workflow_runs |= (map(select(
    if $created == "" then true
    elif ($created | startswith(">=")) then .created_at >= $created[2:]
    elif ($created | test("^[^.]+[.][.][^.]+$")) then
      ($created | split("..")) as [$from, $to] | .created_at >= $from and .created_at <= $to
    else error("the stand-in gh reads no created=" + $created) end)) | if $cut == "" then . else .[:1000] end)
  else . end'
kind=json
[ -z "$raw" ] || kind=raw
for file in "$FAKE_GH/$queried.$kind" "$FAKE_GH/$bare.$kind"; do
  [ -f "$file" ] || continue
  if [ -n "$raw" ]; then exec cat "$file"; fi
  if [ -n "$slurp" ]; then exec jq -c -s . "$file"; fi
  exec jq -r --arg created "$created" --arg cut "$cut" "$runs | $filter" "$file"
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


@functools.cache
def parsed(text):
    return yaml.load(text, Loader=YAML_LOADER)


def parse(text):
    """The YAML `text`, parsed once in this process for each text: the tests read the same workflows many times. Each
    call gets a copy of its own, so that a test that changes what it got changes no other test's."""
    return copy.deepcopy(parsed(text))


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


def action_of(step):
    """The action that a step uses, without its pin: the part of its uses before @."""
    return str(step.get("uses", "")).partition("@")[0]


def zipped(files, method=zipfile.ZIP_STORED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
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


# The cases that passed on an unchanged copy of the tree in this process (Stand.passes_unchanged), each as (its class,
# its name, its arguments).
UNCHANGED_PASSES = set()


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

    def serve_error(self, endpoint, printed):
        """A call of `endpoint` fails, and gh prints `printed`."""
        (self.api / (endpoint.replace("/", "_") + ".error")).write_text(printed)

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
        return parse((tree / ".github" / "workflows" / name).read_text())

    def step(self, workflow, job, name):
        found = [s for s in workflow["jobs"][job]["steps"] if s.get("name") == name]
        self.assertEqual(len(found), 1, f"the steps named {name!r} of the job {job}")
        return found[0]

    def run_step(self, workflow, job, name, ctx, cwd, given=None, evaluate=None):
        """The step `name` of `job`, with its env rendered for ctx (env_of), in cwd."""
        step = self.step(workflow, job, name)
        return self.run_script(step["run"], cwd, **env_of(workflow, job, step, ctx, given, evaluate))

    def check_ids(self, tree=ROOT):
        """Each check id of review.md, in its order, with the verdicts it takes: what `tree`'s
        .github/scripts/review-verdict --ids prints."""
        return json.loads(subprocess.run([str(tree / ".github/scripts/review-verdict"), "--ids"], env=self.env,
                                         check=True, capture_output=True, text=True).stdout)

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

    def passes_unchanged(self, case, *args, **kwargs):
        """case(<an unchanged copy of the tree>, *args, **kwargs) passes. A control runs this before it runs its case
        on its changed copy, so that only its change can make the case fail there. An unchanged copy is the tree
        itself, byte for byte, so each control of a case would run the same case on the same files: the first control
        of a case and its arguments in this process runs it, and the others read its pass from UNCHANGED_PASSES. A
        failure is not kept, so each control runs the case again and fails."""
        key = (type(self), case.__name__, args, tuple(sorted(kwargs.items())))
        if key not in UNCHANGED_PASSES:
            case(self.copy_tree("unchanged"), *args, **kwargs)
            UNCHANGED_PASSES.add(key)

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

    def workflows(self, directory=ROOT / ".github" / "workflows"):
        found = sorted(p for p in directory.iterdir() if p.suffix in (".yml", ".yaml"))
        self.assertTrue(found)
        return found

    def test_r_no_pull_request_target_and_a_pull_request_job_holds_nothing(self):
        self.r_case()

    def test_control_r_a_calling_job_with_secrets_inherit(self):
        # toolchain-images.yaml's docker-tests calls frame-pointer-tests.yaml; with secrets: inherit it would pass that
        # workflow every secret, and the file would hold no text "secrets.".
        copies = {}
        for name in ("unchanged", "changed"):
            copies[name] = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "workflows"
            shutil.copytree(ROOT / ".github" / "workflows", copies[name])
        calling = copies["changed"] / "toolchain-images.yaml"
        line = "    uses: ./.github/workflows/frame-pointer-tests.yaml\n"
        self.assertEqual(calling.read_text().count(line), 1, "the line of docker-tests that the control follows")
        calling.write_text(calling.read_text().replace(line, line + "    secrets: inherit\n"))
        self.r_case(copies["unchanged"])
        with self.assertRaises(AssertionError) as caught:
            self.r_case(copies["changed"])
        self.assertIn("toolchain-images.yaml, the job docker-tests", str(caught.exception))

    def r_case(self, directory=ROOT / ".github" / "workflows"):
        """(r) on the workflow files of `directory`."""
        for path in self.workflows(directory):
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
                    # A job that calls a workflow passes it a secret by its key secrets (secrets: inherit passes all),
                    # with no text "secrets." in the file.
                    self.assertNotIn("secrets", holder, f"{path.name}, {where}")
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
            workflow = parse(path.read_text())
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


class ToolchainPublish(Stand):
    """(publish): toolchain-images-publish.yaml (Toolchain images: publish) starts when a run of toolchain-images.yaml
    (Toolchain images) on main completes. Its one job, publish, has packages: write, and acts only when that run was
    of toolchain-images.yaml, for a push to main of this repository, and passed. It copies the three images to one
    package, each under a tag that names the language of its base row (OSSV-276)."""

    PUBLISH, IMAGES = "toolchain-images-publish.yaml", "toolchain-images.yaml"
    # The run of Toolchain images that completed: its event, its conclusion, its head branch, its head repository and
    # its workflow file. A pull request from a fork, or from this repository, can have a head branch named main.
    # workflow_run finds the workflow by its name, so a file of another path with the name Toolchain images starts
    # publish too.
    EVENTS = ("push", "pull_request", "workflow_dispatch", "schedule", "merge_group")
    CONCLUSIONS = ("success", "failure", "cancelled", "skipped")
    BRANCHES = ("main", BRANCH)
    HEADS = (REPO, FORK)
    PATHS = (f".github/workflows/{IMAGES}", ".github/workflows/other.yaml")
    # The condition of the publish job's if on the event, and what follows it there.
    EVENT_CHECK = "github.event.workflow_run.event == 'push' && "
    # The condition of the publish job's if on the workflow file of the run, and the line end before it there.
    PATH_CHECK = f"\n      && github.event.workflow_run.path == '.github/workflows/{IMAGES}'"
    # The one package of the three frame-pointer images, and the tag of the image of each base row for the commit HEAD,
    # which names the row's language.
    PACKAGE = "ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain"
    TAGS = {"oss-fuzz-theorems-2026.10": f"frame-pointers-{HEAD}",
            "oss-fuzz-theorems-2026.10-rust": f"frame-pointers-rust-{HEAD}",
            "oss-fuzz-theorems-2026.10-python": f"frame-pointers-python-{HEAD}"}
    # The start of the name of publish's step that pushes.
    PUSH = "unless ghcr.io holds it"
    # The stand-in crane of the push step: a registry in $FAKE_CRANE/registry.json. Its images map a reference by
    # digest (repository@digest) to a manifest and a configuration, and its tags map repository:tag to a digest. made
    # maps a base image to the image that crane mutate --env OFT_FRAME_POINTERS=1 makes of it, with that image's
    # digest. `manifest`, `config` and `digest` of a reference answer from the registry, and fail as crane does for a
    # reference that it does not hold. `mutate <base> --env OFT_FRAME_POINTERS=1 -t <repository>:<tag>` puts the image
    # made of the base there, and prints repository@digest, as crane does. `copy <from> <to>` puts the image of <from>
    # at <to>. A command that writes to ghcr.io fails unless `auth login ghcr.io` read a password, with no logout after
    # it: the login is the file $FAKE_CRANE/login. With FAKE_CRANE_NO_PACKAGES_WRITE=1, which run_push sets for a job
    # whose token cannot write packages, such a command also fails, as ghcr.io refuses that token (DENIED). Each call
    # goes to $FAKE_CRANE/calls: its arguments, as a JSON list on one line. The stand-in runs no other command.
    CRANE = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

home = pathlib.Path(os.environ["FAKE_CRANE"])
args = sys.argv[1:]
with open(home / "calls", "a") as calls:
    calls.write(json.dumps(args) + "\n")
registry = json.loads((home / "registry.json").read_text())


def held(ref):
    # (the digest, the image) of a reference by digest or by tag
    repository, digest = ref.split("@", 1) if "@" in ref else (ref.rpartition(":")[0], registry["tags"].get(ref))
    image = registry["images"].get(f"{repository}@{digest}")
    if image is None:
        sys.exit(f"Error: fetching manifest {ref}: MANIFEST_UNKNOWN: manifest unknown")
    return digest, image


def put(to, digest, image):
    # the image at the reference by tag `to`; its repository
    repository, _, tag = to.rpartition(":")
    if not repository or "/" in tag:
        sys.exit(f"the stand-in crane takes a reference by tag here, not {to}")
    if to.startswith("ghcr.io/") and not (home / "login").exists():
        sys.exit(f"Error: PUT {to}: UNAUTHORIZED: authentication required")
    if to.startswith("ghcr.io/") and os.environ.get("FAKE_CRANE_NO_PACKAGES_WRITE") == "1":
        sys.exit(f"Error: PUT {to}: DENIED: permission_denied: write_package")
    registry["images"][f"{repository}@{digest}"] = image
    registry["tags"][to] = digest
    return repository


match args:
    case ["auth", "login", "ghcr.io", "--username", _, "--password-stdin"]:
        if not sys.stdin.read().strip():
            sys.exit("Error: no password on the standard input")
        (home / "login").touch()
    case ["auth", "logout", "ghcr.io"]:
        (home / "login").unlink(missing_ok=True)
    case ["manifest" | "config" as part, ref]:
        print(json.dumps(held(ref)[1][part]))
    case ["digest", ref]:
        print(held(ref)[0])
    case ["mutate", base, "--env", "OFT_FRAME_POINTERS=1", "-t", to] if base in registry["made"]:
        held(base)
        made = registry["made"][base]
        print(put(to, made["digest"], made["image"]) + "@" + made["digest"])
    case ["copy", source, to]:
        put(to, *held(source))
    case _:
        sys.exit(f"the stand-in crane does not run: crane {' '.join(args)}")
(home / "registry.json").write_text(json.dumps(registry))
"""

    def case(self, tree=ROOT):
        import test_outside_screen
        job = self.workflow(tree, self.PUBLISH)["jobs"]["publish"]
        acts = set()
        for run in itertools.product(self.EVENTS, self.CONCLUSIONS, self.BRANCHES, self.HEADS, self.PATHS):
            event, conclusion, branch, head, path = run
            ctx = {"github.repository": REPO, "github.event.workflow_run.event": event,
                   "github.event.workflow_run.conclusion": conclusion,
                   "github.event.workflow_run.head_branch": branch,
                   "github.event.workflow_run.head_repository.full_name": head,
                   "github.event.workflow_run.path": path}
            if test_outside_screen.evaluate(job.get("if", "true"), ctx):
                acts.add(run)
        self.assertEqual(acts, {("push", "success", "main", REPO, self.PATHS[0])}, "the runs that publish acts on")

    def test_publish_acts_only_on_a_push_run_on_main_of_this_repository_that_passed(self):
        self.case()

    def test_control_publish_event_check_taken_out_of_the_jobs_if(self):
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(f".github/workflows/{self.PUBLISH}", self.EVENT_CHECK, "")])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("the runs that publish acts on", str(caught.exception))

    def test_control_publish_path_check_taken_out_of_the_jobs_if(self):
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(f".github/workflows/{self.PUBLISH}", self.PATH_CHECK, "")])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("the runs that publish acts on", str(caught.exception))

    @staticmethod
    def digest_of(value):
        return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def lands(down, artifact, file, temp):
        """Where actions/download-artifact, with the inputs `down`, puts the file `file` of the artifact `artifact`, in
        a job whose runner.temp is `temp`: None if it does not download that artifact. An upload of one file holds it
        under its own name. A download by name, or a download with merge-multiple, puts each file in its path. Else
        each artifact gets a directory of its own name there. This takes the artifact to be in the run that the
        download reads. make_then_publish gives make's files only to a download of make's run (reads_run)."""
        into = pathlib.PurePosixPath(render(down.get("path", ""), {"runner.temp": temp}))
        file = pathlib.PurePosixPath(file).name
        if "name" in down:
            return into / file if artifact == down["name"] else None
        if not fnmatch.fnmatchcase(artifact, down.get("pattern", "*")):
            return None
        return into / file if down.get("merge-multiple") is True else into / artifact / file

    @staticmethod
    def grants(workflow, job, scope):
        """The level, none, read or write, that the token of the job `job` of `workflow` has for the scope `scope`. The
        token takes the job's permissions, or the workflow's when the job has none. A permissions block gives none to
        each scope that it does not name, so {} gives none. read-all and write-all give each scope read or write. With
        permissions in neither, the token has the repository's default, which this file does not see: it counts as
        none. publish's checkout needs contents read (checks_out), its download of make's run actions read
        (reads_run), and its push packages write (run_push)."""
        permissions = workflow["jobs"][job].get("permissions", workflow.get("permissions"))
        if isinstance(permissions, str):
            return {"read-all": "read", "write-all": "write"}.get(permissions, "none")
        return (permissions or {}).get(scope, "none")

    # The id of the run of Toolchain images that started publish, in which make uploaded its files. publish's own run
    # has another id, and holds none of make's artifacts.
    MAKE_RUN = "4242"

    @staticmethod
    def reads_run(down, workflow, job):
        """The run whose artifacts actions/download-artifact, with the inputs `down`, reads in the job `job` of
        `workflow`. It reads another run only when its run-id names that run, it has a github-token, and the job's
        token can read actions (grants: read or write). With no run-id, or with no token, it reads the artifacts of
        its own job's run: publish's own run. A token that cannot read actions reads no run: the API refuses it. This
        renders the inputs in publish's context, where github.event.workflow_run.id is MAKE_RUN and github.token is the
        job's token. It matches no text of them. So a download reads make's run only when its run-id gives MAKE_RUN,
        its github-token is not empty, and the job's token can read actions."""
        if "run-id" not in down or not render(down.get("github-token", ""), {"github.token": WORKFLOW_TOKEN}):
            return "publish's own run"
        if ToolchainPublish.grants(workflow, job, "actions") not in ("read", "write"):
            return "no run: the token cannot read actions"
        return render(down["run-id"], {"github.event.workflow_run.id": ToolchainPublish.MAKE_RUN})

    # main's newest commit: github.sha of publish's run, a later commit than HEAD, the commit that make built.
    MAIN_SHA = "f" * 40

    @staticmethod
    def checks_out(step, workflow, job):
        """The commit whose infra/toolchains.tsv actions/checkout, as the step `step` of the job `job` of `workflow`,
        checks out. None when it gives no infra/toolchains.tsv: when the job's token cannot read contents (grants: read
        or write), the checkout fails, and when its sparse checkout leaves that file out (sparse_takes), it gives other
        files only. This renders its ref in publish's context, where github.event.workflow_run.head_sha is HEAD, the
        commit that make built, and github.sha is MAIN_SHA, main's newest commit. It matches no text of the ref. With
        no ref, or with one that renders empty, actions/checkout takes the commit of the event: for workflow_run,
        github.sha."""
        given = step.get("with") or {}
        if ToolchainPublish.grants(workflow, job, "contents") not in ("read", "write"):
            return None
        if not ToolchainPublish.sparse_takes(given, "infra/toolchains.tsv"):
            return None
        ctx = {"github.event.workflow_run.head_sha": HEAD, "github.sha": ToolchainPublish.MAIN_SHA}
        return render(given.get("ref", ""), ctx) or ToolchainPublish.MAIN_SHA

    @staticmethod
    def sparse_takes(given, path):
        """Whether actions/checkout, with the inputs `given`, checks out the file `path` of the tree. With no
        sparse-checkout, or with one of no line, it checks out every file. Else it takes the lines of sparse-checkout,
        each trimmed, and sparse-checkout-cone-mode, which is true unless it is false (the default of the pin's
        action.yml). This renders the inputs, and reads each line as git does.
          - Cone mode: actions/checkout runs git sparse-checkout set with the lines. Each line names a directory. git
            checks out the files at the top of the tree, each file under a named directory, and each file directly in
            a leading directory of a named one. So the line infra/toolchains.tsv, or infra/other.tsv, gives each file
            directly in infra. git refuses a line that starts with / or !, or that holds one of *?[], and the checkout
            then fails.
          - Non-cone mode: actions/checkout writes the lines to .git/info/sparse-checkout, where each line is a pattern
            of gitignore. git decides on the file first, then on each directory above it, the nearest first. At each,
            the last line that matches decides, and a line that starts with ! leaves the file out. When no line
            matches any of them, the file stays out. A line that starts with # is a comment. A line that ends in /
            matches a directory only. A line with no other / matches the name at any depth. Else it matches the path
            from the top, without a leading /, one segment at a time (fnmatch, so * does not cross a /), and a segment
            ** matches any number of segments."""
        sparse = given.get("sparse-checkout")
        text = "\n".join(render(p, {}) for p in sparse) if isinstance(sparse, list) else render(sparse or "", {})
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        if not lines:
            return True
        names = path.split("/")
        if (render(given.get("sparse-checkout-cone-mode", ""), {}) or "true").upper() == "TRUE":
            if any(line[0] in "/!" or any(c in line for c in "*?[]") for line in lines):
                return False
            parent = "/".join(names[:-1])
            return not parent or any(path.startswith(f"{named}/") or f"{named}/".startswith(f"{parent}/")
                                     for named in (line.rstrip("/") for line in lines))

        def segments(have, want):
            if not want:
                return not have
            if want[0] == "**":
                return any(segments(have[n:], want[1:]) for n in range(len(have) + 1))
            return bool(have) and fnmatch.fnmatchcase(have[0], want[0]) and segments(have[1:], want[1:])

        def matches(pattern, at, directory):
            if pattern.endswith("/") and not directory:
                return False
            pattern = pattern.rstrip("/")
            if "/" not in pattern:
                return fnmatch.fnmatchcase(at[-1], pattern)
            return segments(at, pattern.removeprefix("/").split("/"))

        for depth in range(len(names), 0, -1):
            decided = [not line.startswith("!") for line in lines if not line.startswith("#")
                       and matches(line.removeprefix("!"), names[:depth], depth < len(names))]
            if decided:
                return decided[-1]
        return False

    def base_rows(self, rows):
        """Each of the base rows `rows` as this repository's infra/toolchains.tsv has it: (its line, its image)."""
        bases = {}
        for line in (ROOT / "infra" / "toolchains.tsv").read_text().splitlines():
            fields = line.split("\t")
            if fields[0] in rows:
                bases[fields[0]] = (line, fields[1])
        self.assertEqual(sorted(bases), sorted(rows), "the base rows of infra/toolchains.tsv")
        return bases

    def checkout_of(self, bases, more=""):
        """A new directory with infra/toolchains.tsv, as the checkouts of make and publish give it: the lines of
        `bases`, and then `more`."""
        where = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        (where / "infra").mkdir()
        (where / "infra" / "toolchains.tsv").write_text("".join(line + "\n" for line, _ in bases.values()) + more)
        return where

    def registry_of(self, bases):
        """The stand-in registry with the base image of each row of `bases`, and what crane mutate makes of it: the
        base image's configuration with OFT_FRAME_POINTERS=1 added, and a manifest that names it and the base image's
        layers. Return the registry, and for each row the digest and the image that crane mutate makes."""
        registry, made, fp = {"images": {}, "tags": {}, "made": {}}, {}, {}
        for row, (_, base) in bases.items():
            config = {"architecture": "amd64", "os": "linux", "config": {"Env": ["PATH=/usr/local/bin:/usr/bin:/bin"]}}
            manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 1,
                                   "digest": self.digest_of(config)},
                        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": n + 1,
                                    "digest": self.digest_of([row, n])} for n in range(3)]}
            fp_config = {**config, "config": {"Env": [*config["config"]["Env"], "OFT_FRAME_POINTERS=1"]}}
            fp_manifest = {**manifest, "config": {**manifest["config"], "digest": self.digest_of(fp_config)}}
            made[row], fp[row] = self.digest_of(fp_manifest), {"manifest": fp_manifest, "config": fp_config}
            registry["images"][base] = {"manifest": manifest, "config": config}
            registry["made"][base] = {"digest": made[row], "image": fp[row]}
        return registry, made, fp

    def crane_home(self, registry):
        """A new home of the stand-in crane ($FAKE_CRANE), whose registry is `registry`."""
        home = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        (home / "registry.json").write_text(json.dumps(registry))
        (home / "calls").write_text("")
        return home

    def put_crane(self, directory):
        """The stand-in crane in `directory`, as the step install crane puts crane in $RUNNER_TEMP/bin."""
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "crane").write_text(self.CRANE)
        (directory / "crane").chmod(0o755)

    def push_step(self, publish):
        """publish's push step: the one step whose name starts with PUSH."""
        steps = [s for s in publish["jobs"]["publish"]["steps"] if str(s.get("name", "")).startswith(self.PUSH)]
        self.assertEqual(len(steps), 1, f"the steps of publish whose name starts with {self.PUSH!r}")
        return steps[0]

    @staticmethod
    def file_commands(temp):
        """GITHUB_PATH and GITHUB_ENV of a job whose runner.temp is `temp`, as {name: path}, where GitHub's runner keeps
        them. A step that writes to one changes the PATH or the env of the job's later steps. A file that is not there
        yet starts empty."""
        files = {"GITHUB_PATH": temp / "_runner_file_commands" / "add_path",
                 "GITHUB_ENV": temp / "_runner_file_commands" / "set_env"}
        for path in files.values():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        return files

    def run_push(self, publish, row, where, home, temp):
        """publish's push step for the base row `row`, in `where`, with the stand-in registry of `home`. Its
        $RUNNER_TEMP is `temp`, which holds crane in bin/ and the job's GITHUB_PATH and GITHUB_ENV (file_commands).
        Each row is a job of its own, on a runner of its own: no login of a job before. When the job's token cannot
        write packages (grants), the stand-in crane refuses each write to ghcr.io, as ghcr.io does. Return (its exit
        status, its log, its calls of crane, each a list of arguments)."""
        step = self.push_step(publish)
        (home / "login").unlink(missing_ok=True)
        (home / "calls").write_text("")
        ctx = {"github.token": WORKFLOW_TOKEN, "github.event.workflow_run.head_sha": HEAD, "matrix.base": row}
        denied = {} if self.grants(publish, "publish", "packages") == "write" else {"FAKE_CRANE_NO_PACKAGES_WRITE": "1"}
        files = {name: str(path) for name, path in self.file_commands(temp).items()}
        rc, log, _ = self.run_script(step["run"], where, RUNNER_TEMP=str(temp), FAKE_CRANE=str(home),
                                     GITHUB_ACTOR="github-actions[bot]", **denied, **files,
                                     **env_of(publish, "publish", step, ctx))
        return rc, log, [json.loads(line) for line in (home / "calls").read_text().splitlines()]

    def push_temp(self, row, digest):
        """A new runner temp of publish's push step for the base row `row`: crane in bin/ (put_crane), and `digest`, the
        digest that make made, at fp-digest/<row>.digest, where publish's download puts it."""
        temp = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        self.put_crane(temp / "bin")
        (temp / "fp-digest").mkdir()
        (temp / "fp-digest" / f"{row}.digest").write_text(digest + "\n")
        return temp

    # The step of make that compares a frame-pointer row of infra/toolchains.tsv with the image that make made.
    ROW_CHECK = "the frame-pointer row of infra/toolchains.tsv, if there is one, names this image, and ghcr.io holds it"

    # The parts of handover_case, as its messages name them.
    EQUAL, RUN = "the values that both files hold", "make, then publish, on one table"
    # The run steps of make that part 2 of handover_case runs, in their order: the base image, the new image, the row
    # check and the digest. make's other run steps install crane, check the new image and probe it. They give publish
    # nothing.
    MAKE_STEPS = ("the base image, from infra/toolchains.tsv", "make the image in the runner's registry", ROW_CHECK,
                  "the digest, for compare-digests and publish")

    def handover_case(self, tree=ROOT, upto=RUN):
        """What toolchain-images.yaml hands over to publish (toolchain-images-publish.yaml): values, the digest
        artifacts, and the image that make makes. A value that one file copies from the other with no test fails only
        on main, after the merge. So this case reads both files, and finds each value there, not in a list of its own.
        It has two parts, and each message names its part:
          1. EQUAL (shared_values): each value that both files hold is equal.
          2. RUN (make_then_publish): make's steps and then publish's push step, run on the same tables, pass or refuse
             the same frame-pointer rows, and publish copies the image that make made. publish reads each digest where
             its download puts the file of make's upload.
        The case runs the parts in this order, and stops after the part `upto`. Return what each part that ran
        found."""
        publish, images = self.workflow(tree, self.PUBLISH), self.workflow(tree, self.IMAGES)
        parts = {self.EQUAL: lambda publish, images: self.shared_values(publish, images, tree),
                 self.RUN: self.make_then_publish}
        self.assertIn(upto, parts, "the part of handover_case to stop after")
        found = []
        for part, run in parts.items():
            found.append(run(publish, images))
            if part == upto:
                return tuple(found)

    def shared_values(self, publish, images, tree):
        """Part 1 of handover_case: the values that both files hold, each as (publish's, toolchain-images.yaml's):
          - each name of the workflow's env that both files define,
          - each pin in toolchain-images.yaml of an action that publish uses, and publish's pin of it,
          - the image and the ports of each service of publish, in each job of toolchain-images.yaml with that service,
          - each key of publish's matrix (make's), and each name of publish's job env that make's job env has too.
        A job of toolchain-images.yaml that calls a workflow of `tree` (uses: ./<path>) has no steps, services or env
        there: the called workflow holds them, and a caller's env does not reach it. So the jobs and the env of that
        workflow count as toolchain-images.yaml's here, and their values name its path.
        Each kind has at least one value, and each pair is equal. The message names each value that differs. Other
        tests hold the trigger: test_publish_acts_only_on_a_push_run_on_main_of_this_repository_that_passed runs
        publish's if over each run (case) and holds that publish acts only on a push run on main of this repository
        that passed, and test_publish_starts_on_the_runs_of_toolchain_images_by_its_name_alone holds the name of the
        workflow that publish listens to."""
        job, make = publish["jobs"]["publish"], images["jobs"]["make"]
        kinds = {"the env": {}, "the actions": {}, "the services": {}, "the matrix": {}, "the job env": {}}
        # Each job, by the words that name it in a value ("make's"), and each env, by the words after its names.
        jobs, envs = {}, {"": images.get("env") or {}}
        for name, held in images["jobs"].items():
            called = str(held.get("uses", ""))
            if not called:
                jobs[f"{name}'s"] = held
                continue
            self.assertTrue(called.startswith("./"), f"{self.EQUAL}: the job {name} calls {called}, outside the tree")
            self.need(tree, called[2:])
            workflow = yaml.load((tree / called[2:]).read_text(), Loader=YAML_LOADER)
            envs[f" of {called[2:]}"] = workflow.get("env") or {}
            jobs.update({f"{called[2:]} {inner}'s": job_of for inner, job_of in workflow["jobs"].items()})
        for where, theirs in envs.items():
            for name, value in (publish.get("env") or {}).items():
                if name in theirs:
                    kinds["the env"][f"the env {name}{where}"] = (value, theirs[name])
        pins = {}
        for step in job["steps"]:
            if action_of(step):
                pins.setdefault(action_of(step), set()).add(step["uses"].partition("@")[2])
        for who, held in jobs.items():
            for n, step in enumerate(held.get("steps") or [], 1):
                if action_of(step) in pins:
                    kinds["the actions"][f"the pin of {action_of(step)} ({who} step {n})"] = (
                        " ".join(sorted(pins[action_of(step)])), step["uses"].partition("@")[2])
        for service, given in (job.get("services") or {}).items():
            for who, held in jobs.items():
                if service in (held.get("services") or {}):
                    for key in ("image", "ports"):
                        kinds["the services"][f"the {key} of the service {service} ({who})"] = (
                            given.get(key), held["services"][service].get(key))
        for key, value in job["strategy"]["matrix"].items():
            kinds["the matrix"][f"the matrix {key} (make's)"] = (value, make["strategy"]["matrix"].get(key))
        for name, value in (job.get("env") or {}).items():
            if name in (make.get("env") or {}):
                kinds["the job env"][f"the job env {name} (make's)"] = (value, make["env"][name])
        for kind, found in kinds.items():
            self.assertTrue(found, f"{self.EQUAL}: {kind}: no value that both files hold")
        values = {what: pair for found in kinds.values() for what, pair in found.items()}
        differ = {what: pair for what, pair in values.items() if pair[0] != pair[1]}
        self.assertEqual(differ, {}, f"{self.EQUAL}: the values of {self.PUBLISH} that differ from {self.IMAGES}'s, "
                                     f"each as (publish's, {self.IMAGES}'s): {'; '.join(differ)}")
        return values

    @staticmethod
    def outcome(rc, log, row):
        """The outcome of a step for the base row `row`: passes, refuses the row (its error names the frame-pointer row
        of `row`), or fails."""
        if rc == 0:
            return "passes"
        refusal = f"::error::infra/toolchains.tsv's row {row}-frame-pointers names "
        return "refuses the row" if refusal in log else "fails"

    def run_make(self, images, row, where, home):
        """make's MAKE_STEPS for the base row `row`, in their order, in `where`, with the stand-in crane and the
        registry of `home`. $RUNNER_TEMP is a directory of this test, and $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY are
        files of it. Each step gets the outputs that the steps before it wrote. GitHub stops a job at its first step
        that fails. Here the steps after a refusal of the row check run too, so that publish gets the digest on each
        table. Then each upload of make takes the file of its path. Return make's outcome, its log, and each file that
        an upload gives, as (the artifact, the file)."""
        job = images["jobs"]["make"]
        steps = [self.step(images, "make", name) for name in self.MAKE_STEPS]
        order = [job["steps"].index(step) for step in steps]
        self.assertEqual(order, sorted(order), f"{self.RUN}: the order of make's steps {self.MAKE_STEPS}")
        temp = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        self.put_crane(temp / "bin")
        given = {"RUNNER_TEMP": str(temp), "FAKE_CRANE": str(home),
                 "PATH": f"{temp / 'bin'}{os.pathsep}{self.env['PATH']}",
                 "GITHUB_STEP_SUMMARY": str(pathlib.Path(tempfile.mkdtemp(dir=self.dir)) / "summary")}
        ctx = {"matrix.base": row, "runner.temp": str(temp)}
        outcome, log = "passes", ""
        for step in steps:
            rc, out, got = self.run_script(step["run"], where, **{**given, **env_of(images, "make", step, ctx)})
            log += f"{step['name']}:\n{out}"
            if "id" in step:
                ctx.update({f"steps.{step['id']}.outputs.{k}": v for k, v in got.items()})
            if self.outcome(rc, out, row) == "fails":
                return f"fails at {step['name']!r}", log, []
            if outcome == "passes":
                outcome = self.outcome(rc, out, row)
        handed = []
        for step in job["steps"]:
            if action_of(step) == "actions/upload-artifact":
                up = step.get("with") or {}
                file = pathlib.Path(render(up.get("path", ""), ctx))
                if file.is_file():
                    handed.append((render(up.get("name", "artifact"), ctx), file))
                elif up.get("if-no-files-found") == "error" and outcome == "passes":
                    return f"fails at its upload of {file}", log, []
        return outcome, log, handed

    def make_then_publish(self, publish, images):
        """Part 2 of handover_case: make's steps (run_make), and then publish's push step (run_push), for each base row
        of make's matrix, on four tables of infra/toolchains.tsv. Each table holds the base rows of this repository's
        file, and for the row one of these:
          - none: no frame-pointer row,
          - made: a row that names the image that make makes, in PACKAGE,
          - base package: a row that names the same digest in the package of the base image (the rows of #155 did),
          - other digest: a row that names another digest in PACKAGE.
        ghcr.io holds the image that the row names, so only the comparison with the made image refuses a row. Each file
        that make uploads goes where publish's downloads of make's run put it (reads_run, lands). A download of
        publish's own run gets none of them. publish then runs on the same registry, and on the table of the commit
        that its checkout gives (checks_out). At HEAD, the commit that make built, the table is make's. At any other
        commit, it is the table of main's newest commit, a later one that moved the row's base line to another base
        image: the registry holds that image, and crane mutate makes another image of it. A checkout that gives no
        infra/toolchains.tsv gives no table: its sparse checkout leaves the file out (sparse_takes), or its token
        cannot read contents. publish's token has the permissions of its job (grants). Without actions read, a
        download reads no run. Without packages write, ghcr.io refuses each write of the push step (run_push).
        publish's registry service is its own, and holds no image of make's. The checks:
          - make's row check and publish's step agree on each table: both pass, or both refuse the row,
          - make passes only the tables with no row or with the made image in PACKAGE,
          - where both pass and ghcr.io does not hold the image, publish copies the digest that make made to PACKAGE,
            under the tag of the row's language (TAGS),
          - where ghcr.io holds it, publish pushes nothing, and its checks of the manifest and the configuration pass.
          - on no table does publish's push step write GITHUB_PATH or GITHUB_ENV (file_commands).
        Return the outcome on each table, as (make's, publish's, the copies of publish)."""
        rows = images["jobs"]["make"]["strategy"]["matrix"]["base"]
        inputs = [s.get("with") or {} for s in publish["jobs"]["publish"]["steps"]
                  if action_of(s) == "actions/download-artifact"]
        downloads = [down for down in inputs if self.reads_run(down, publish, "publish") == self.MAKE_RUN]
        checkouts = [s for s in publish["jobs"]["publish"]["steps"] if action_of(s) == "actions/checkout"]
        self.assertEqual(len(checkouts), 1, f"{self.RUN}: the checkouts of publish")
        commit = self.checks_out(checkouts[0], publish, "publish")
        bases = self.base_rows(rows)
        registry, made, fp = self.registry_of(bases)
        # main's newest commit moves the base line of a row to another base image, in the same package. registry_of
        # takes the layers of an image from the name of its row, so under another name it gives that image other
        # layers, and crane mutate makes another image of it.
        moved = {}
        for row, (line, base) in bases.items():
            image = f"{base.partition('@')[0]}@{self.digest_of([row, self.MAIN_SHA])}"
            moved[row] = (line.replace(base, image), image)
        later, _, _ = self.registry_of({f"{row} at {self.MAIN_SHA}": value for row, value in moved.items()})
        for part in ("images", "made"):
            registry[part].update(later[part])
        other = "sha256:" + "e" * 64
        named, held, results, logs, written = {}, set(), {}, {}, {}
        for row in rows:
            package = bases[row][1].partition("@")[0]
            for table, ref in (("none", None), ("made", f"{self.PACKAGE}@{made[row]}"),
                               ("base package", f"{package}@{made[row]}"), ("other digest", f"{self.PACKAGE}@{other}")):
                key = (row, table)
                named[key] = ref
                more = f"{row}-frame-pointers\t{ref}\n" if ref else ""
                where = self.checkout_of(bases, more)
                ghcr = json.loads(json.dumps(registry))
                if ref:
                    ghcr["images"][ref] = fp[row]
                if f"{self.PACKAGE}@{made[row]}" in ghcr["images"]:
                    held.add(key)
                home = self.crane_home(ghcr)
                make, make_log, handed = self.run_make(images, row, where, home)
                # publish's job has a registry service of its own: it holds no image of make's.
                state = json.loads((home / "registry.json").read_text())
                for part in ("images", "tags"):
                    state[part] = {at: v for at, v in state[part].items() if not at.startswith("localhost:")}
                (home / "registry.json").write_text(json.dumps(state))
                temp = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
                self.put_crane(temp / "bin")
                for artifact, file in handed:
                    for down in downloads:
                        to = self.lands(down, artifact, str(file), str(temp))
                        if to is not None:
                            pathlib.Path(to).parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(file, to)
                # publish's checkout: no table when it gives no infra/toolchains.tsv (checks_out), make's table at
                # HEAD, else the table of main's newest commit
                if commit is None:
                    there = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
                elif commit == HEAD:
                    there = where
                else:
                    there = self.checkout_of({**bases, row: moved[row]}, more)
                rc, log, calls = self.run_push(publish, row, there, home, temp)
                copies = [(call[2], call[1].rpartition("@")[2]) for call in calls if call[0] == "copy"]
                results[key] = (make, self.outcome(rc, log, row), copies)
                logs[key] = (make_log, log)
                written[key] = {name: path.read_text() for name, path in self.file_commands(temp).items()
                                if path.read_text()}

        def shown(keys):
            return "".join(f"\n{key}, make:\n{logs[key][0]}{key}, publish:\n{logs[key][1]}" for key in keys)

        differ = {key: result[:2] for key, result in results.items() if result[0] != result[1]}
        self.assertEqual(differ, {}, f"{self.RUN}: the tables on which make's row check and publish's step disagree:"
                         + "".join(f"\n  {row}, {table}: make {by_make}, publish {by_publish}"
                                   for (row, table), (by_make, by_publish) in differ.items())
                         + "\nTheir logs:" + shown(differ))
        want = {key: "passes" if ref in (None, f"{self.PACKAGE}@{made[key[0]]}") else "refuses the row"
                for key, ref in named.items()}
        self.assertEqual({key: result[0] for key, result in results.items()}, want,
                         f"{self.RUN}: make's outcome on each table. The logs where it differs:"
                         + shown(key for key in want if results[key][0] != want[key]))
        both = [key for key, result in results.items() if result[:2] == ("passes", "passes")]
        self.assertEqual({key: results[key][2] for key in both},
                         {key: [] if key in held else [(f"{self.PACKAGE}:{self.TAGS.get(key[0])}", made[key[0]])]
                          for key in both},
                         f"{self.RUN}: the targets of crane copy, each with the digest that it copies, on each table "
                         f"that make and publish pass:" + shown(both))
        for key in both:
            how = "already on ghcr.io, nothing pushed" if key in held else f"pushed under the tag {self.TAGS[key[0]]}"
            self.assertIn(f"`{self.PACKAGE}@{made[key[0]]}` ({how})", logs[key][1], f"{self.RUN}: {key}")
        self.assertEqual({key: files for key, files in written.items() if files}, {},
                         f"{self.RUN}: the tables on which publish's push step wrote GITHUB_PATH or GITHUB_ENV, which "
                         "change the PATH or the env of the job's later steps")
        return results

    def test_publish_takes_what_toolchain_images_hands_over(self):
        self.handover_case()

    def handover_fails(self, part, *changes):
        """handover_case passes on an unchanged copy of the tree, and fails on a copy with `changes` (copy_tree). Its
        message names the part `part`. On each copy, the case stops after `part`, so the parts after it do not run.
        Return the message."""
        self.passes_unchanged(self.handover_case, upto=part)
        changed = self.copy_tree("changed", changes)
        with self.assertRaises(AssertionError) as caught:
            self.handover_case(changed, upto=part)
        self.assertIn(f" : {part}: ", str(caught.exception))
        return str(caught.exception)

    def test_control_crane_version_changed_in_toolchain_images_alone(self):
        def other_crane(text):
            return re.sub(r"(?m)^  CRANE_VERSION: .+$", r"\g<0>-other", text)

        caught = self.handover_fails(self.EQUAL, (f".github/workflows/{self.IMAGES}", other_crane))
        self.assertTrue(caught.endswith(f"{self.IMAGES}'s): the env CRANE_VERSION"), caught)

    def test_control_crane_version_changed_in_frame_pointer_tests_alone(self):
        # frame-pointer-tests.yaml, which toolchain-images.yaml's docker-tests calls, holds its own copy of the env.
        def other_crane(text):
            return re.sub(r"(?m)^  CRANE_VERSION: .+$", r"\g<0>-other", text)

        caught = self.handover_fails(self.EQUAL, (f".github/workflows/{self.FP_TESTS}", other_crane))
        self.assertTrue(caught.endswith(f"the env CRANE_VERSION of .github/workflows/{self.FP_TESTS}"), caught)

    # frame-pointer-tests.yaml and its step FP_MAKE: it makes the two images that FramePointersC and FramePointersRust
    # build on, from FP_ROWS, and writes the digest of each for an upload of its job. toolchain-images.yaml calls the
    # file, which has no trigger of its own, as its job docker-tests, beside make; the step COMPARE of its job
    # compare-digests fails unless each of those digests is make's.
    FP_TESTS = "frame-pointer-tests.yaml"
    FP_ROWS = ("oss-fuzz-theorems-2026.10", "oss-fuzz-theorems-2026.10-rust")
    FP_MAKE = "make the C and C++ image and the Rust image"
    COMPARE = "each image that docker-tests tested has the digest that make made"
    # A stand-in docker: `docker pull --quiet <image>` passes, and each call goes to $FAKE_DOCKER_CALLS. It runs no other
    # command.
    DOCKER = ('#!/bin/sh\necho "$*" >> "$FAKE_DOCKER_CALLS"\n[ "$1 $2" = "pull --quiet" ] && [ $# -eq 3 ] && exit 0\n'
              'echo "the stand-in docker does not run: docker $*" >&2\nexit 1\n')

    def fp_make(self, tree=ROOT):
        """frame-pointer-tests.yaml's step FP_MAKE of `tree`, with the stand-in crane and docker, on a table of the base
        rows of make's matrix, and then each upload of its job docker-tests: an upload of a directory holds each file
        in it, under its name. Return its exit status, its log, its outputs, the digests that crane mutate makes, the
        images that docker pulled, and each file that an upload gives, as (the artifact, the file)."""
        tests = self.workflow(tree, self.FP_TESTS)
        step = self.step(tests, "docker-tests", self.FP_MAKE)
        bases = self.base_rows(self.workflow(tree, self.IMAGES)["jobs"]["make"]["strategy"]["matrix"]["base"])
        registry, made, _ = self.registry_of(bases)
        home, temp = self.crane_home(registry), pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        self.put_crane(temp / "bin")
        (temp / "bin" / "docker").write_text(self.DOCKER)
        (temp / "bin" / "docker").chmod(0o755)
        calls = temp / "docker-calls"
        calls.write_text("")
        rc, log, got = self.run_script(step["run"], self.checkout_of(bases), RUNNER_TEMP=str(temp),
                                       FAKE_CRANE=str(home), FAKE_DOCKER_CALLS=str(calls),
                                       PATH=f"{temp / 'bin'}{os.pathsep}{self.env['PATH']}",
                                       **env_of(tests, "docker-tests", step, {}))
        pulled = [line.removeprefix("pull --quiet ") for line in calls.read_text().splitlines()]
        handed = []
        for up in (s.get("with") or {} for s in tests["jobs"]["docker-tests"]["steps"]
                   if action_of(s) == "actions/upload-artifact"):
            path = pathlib.Path(render(up.get("path", ""), {"runner.temp": str(temp)}))
            files = sorted(path.iterdir()) if path.is_dir() else [path] if path.is_file() else []
            handed += [(render(up.get("name", "artifact"), {}), file) for file in files]
        return rc, log, got, made, pulled, handed

    def fp_images(self, made):
        """The images that FP_MAKE gives FramePointers, as its outputs c and rust: each made in the runner's registry,
        by the digest that crane mutate makes. And the images that it pulls, row by row in FP_ROWS' order: the base
        image, then the image made."""
        bases = self.base_rows(self.FP_ROWS)
        refs = {row: f"localhost:5000/{bases[row][1].partition('@')[0].removeprefix('ghcr.io/')}@{made[row]}"
                for row in self.FP_ROWS}
        pulled = [image for row in self.FP_ROWS for image in (bases[row][1], refs[row])]
        return {"c": refs[self.FP_ROWS[0]], "rust": refs[self.FP_ROWS[1]]}, pulled

    def test_frame_pointer_tests_hands_over_the_digests_of_the_images_that_it_tests(self):
        # FramePointers gets each image by its digest, and an upload holds that digest, in <row>.digest, for each row.
        rc, log, got, made, pulled, handed = self.fp_make()
        self.assertEqual((rc, (got, pulled)), (0, self.fp_images(made)), log)
        self.assertEqual({file.name: file.read_text() for _, file in handed},
                         {f"{row}.digest": made[row] + "\n" for row in self.FP_ROWS}, log)

    def test_frame_pointer_tests_starts_only_when_toolchain_images_calls_it(self):
        # tests.yaml's job docker runs FramePointersC and FramePointersRust for every other change.
        self.assertEqual(list(triggers(self.workflow(ROOT, self.FP_TESTS))), ["workflow_call"])

    def compare_case(self, tree=ROOT, tested=None):
        """make's steps (run_make) for each base row of its matrix, and frame-pointer-tests.yaml's step FP_MAKE and its
        uploads (fp_make), on one table with no frame-pointer row. Then the step COMPARE of compare-digests, with each
        file of those uploads where the downloads of compare-digests put it (lands). `tested`, a function of the files
        of docker-tests ({(the artifact, the file's name): its text}), gives the files that docker-tests hands over in
        their place. compare-digests must wait for each job whose upload a download of it reads (needs): else it can
        start before the file is there. Return COMPARE's exit status, its log, the digests that make made, and the
        rows of the files of docker-tests."""
        images = self.workflow(tree, self.IMAGES)
        job = images["jobs"]["compare-digests"]
        rows = images["jobs"]["make"]["strategy"]["matrix"]["base"]
        bases = self.base_rows(rows)
        registry, made, _ = self.registry_of(bases)
        handed = {}
        for row in rows:
            outcome, log, files = self.run_make(images, row, self.checkout_of(bases), self.crane_home(registry))
            self.assertEqual(outcome, "passes", log)
            handed.update({("make", artifact, file.name): file.read_text() for artifact, file in files})
        rc, log, _, _, _, files = self.fp_make(tree)
        self.assertEqual(rc, 0, log)
        theirs = {(artifact, file.name): file.read_text() for artifact, file in files}
        theirs = tested(theirs) if tested else theirs
        handed.update({("docker-tests", *key): text for key, text in theirs.items()})
        temp = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        downloads = [s.get("with") or {} for s in job["steps"] if action_of(s) == "actions/download-artifact"]
        read = set()
        for (by, artifact, name), text in handed.items():
            for down in downloads:
                to = self.lands(down, artifact, name, str(temp))
                if to is not None:
                    read.add(by)
                    pathlib.Path(to).parent.mkdir(parents=True, exist_ok=True)
                    pathlib.Path(to).write_text(text)
        needs = job.get("needs") or []
        self.assertEqual(read - set([needs] if isinstance(needs, str) else needs), set(),
                         "the jobs whose uploads compare-digests reads, and does not wait for")
        step = self.step(images, "compare-digests", self.COMPARE)
        rc, log, _ = self.run_script(step["run"], temp, RUNNER_TEMP=str(temp), GITHUB_STEP_SUMMARY=str(temp / "summary"),
                                     **env_of(images, "compare-digests", step, {"runner.temp": str(temp)}))
        return rc, log, made, [name.removesuffix(".digest") for _, name in theirs]

    def compare_passes(self, tree=ROOT):
        """compare_case passes, and names the digest of each row of FP_ROWS."""
        rc, log, made, _ = self.compare_case(tree)
        self.assertEqual(rc, 0, log)
        for row in self.FP_ROWS:
            self.assertIn(f"{row}: docker-tests tested `{made[row]}`, the image that make made", log)

    def test_compare_digests_passes_on_the_images_that_make_made(self):
        self.compare_passes()

    def test_control_docker_tests_uploads_its_digests_under_another_name(self):
        # compare-digests' download then gets no file of docker-tests.
        self.passes_unchanged(self.compare_passes)
        changed = self.copy_tree("changed", [(f".github/workflows/{self.FP_TESTS}", "name: fp-tested-digest\n",
                                              "name: fp-tested-digests\n")])
        with self.assertRaises(AssertionError) as caught:
            self.compare_passes(changed)
        self.assertIn("::error::docker-tests gave no digest for oss-fuzz-theorems-2026.10: ''", str(caught.exception))

    def test_control_compare_digests_does_not_wait_for_docker_tests(self):
        images = f".github/workflows/{self.IMAGES}"
        self.passes_unchanged(self.compare_passes)
        changed = self.copy_tree("changed", [(images, "    needs: [make, docker-tests]\n", "    needs: make\n")])
        with self.assertRaises(AssertionError) as caught:
            self.compare_passes(changed)
        self.assertIn("the jobs whose uploads compare-digests reads, and does not wait for", str(caught.exception))

    def tested_rows_case(self, tree=ROOT):
        """docker-tests hands over a digest of FP_ROWS alone, and compare-digests requires each of them: it passes with
        these files, and fails when the file of any one of them is missing. So the rows that compare-digests requires
        are the rows of which docker-tests keeps a digest."""
        rc, log, _, rows = self.compare_case(tree)
        self.assertEqual((rc, sorted(rows)), (0, sorted(self.FP_ROWS)), log)
        for row in rows:
            rc, log, _, _ = self.compare_case(
                tree, lambda files, row=row: {k: v for k, v in files.items() if k[1] != f"{row}.digest"})
            self.assertNotEqual(rc, 0, f"compare-digests passes without docker-tests' digest of {row}: {log}")
            self.assertIn(f"::error::docker-tests gave no digest for {row}: ''", log)

    def test_compare_digests_requires_each_row_that_docker_tests_tests(self):
        self.tested_rows_case()

    def test_control_compare_digests_requires_the_c_row_alone(self):
        # Without the Rust row in TESTED_ROWS, compare-digests passes when docker-tests gives no digest of it.
        self.passes_unchanged(self.tested_rows_case)
        rows = "      TESTED_ROWS: oss-fuzz-theorems-2026.10 oss-fuzz-theorems-2026.10-rust\n"
        changed = self.copy_tree("changed", [(f".github/workflows/{self.IMAGES}", rows,
                                              "      TESTED_ROWS: oss-fuzz-theorems-2026.10\n")])
        with self.assertRaises(AssertionError) as caught:
            self.tested_rows_case(changed)
        self.assertIn("compare-digests passes without docker-tests' digest of oss-fuzz-theorems-2026.10-rust",
                      str(caught.exception))

    def other_digest_case(self, tree=ROOT):
        """docker-tests hands over another digest of the C and C++ row than make made: compare-digests fails, and names
        both digests."""
        c, other = self.FP_ROWS[0], "sha256:" + "0" * 64
        rc, log, made, _ = self.compare_case(
            tree, lambda files: {k: other + "\n" if k[1] == f"{c}.digest" else v for k, v in files.items()})
        self.assertNotEqual(rc, 0, log)
        self.assertIn(f"::error::docker-tests tested the image {other} of {c}, but make made {made[c]}", log)

    def test_compare_digests_fails_when_docker_tests_tested_another_image(self):
        self.other_digest_case()

    def test_control_compare_digests_without_its_comparison(self):
        self.passes_unchanged(self.other_digest_case)
        changed = self.copy_tree("changed", [(f".github/workflows/{self.IMAGES}",
                                              '            elif [ "$tested" != "$made" ]; then\n',
                                              "            elif false; then\n")])
        with self.assertRaises(AssertionError):
            self.other_digest_case(changed)

    def test_control_fp_package_changed_in_publish_alone(self):
        line = f"  FP_PACKAGE: {self.PACKAGE}\n"
        caught = self.handover_fails(self.EQUAL, (f".github/workflows/{self.PUBLISH}", line,
                                                  line.replace(self.PACKAGE, f"{self.PACKAGE}-rust")))
        self.assertTrue(caught.endswith(f"{self.IMAGES}'s): the env FP_PACKAGE"), caught)

    def test_control_registry_image_changed_in_publish_alone(self):
        caught = self.handover_fails(self.EQUAL, (f".github/workflows/{self.PUBLISH}", "image: registry:2@",
                                                  "image: registry:3@"))
        self.assertIn("the image of the service registry (make's)", caught)

    def test_control_digest_artifact_renamed_in_make_alone(self):
        # make uploads the digest under another name, which publish's pattern fp-digest-* does not match. make stays
        # whole, but publish downloads no digest.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.IMAGES}",
                                                "name: fp-digest-${{ matrix.base }}",
                                                "name: fp-made-${{ matrix.base }}"))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn("make gave no digest for oss-fuzz-theorems-2026.10: '': nothing pushed", caught)

    def test_control_digest_file_renamed_in_make_alone(self):
        # make writes the digest to <row>.made and uploads that file. make stays whole, but publish reads <row>.digest.
        images = f".github/workflows/{self.IMAGES}"
        caught = self.handover_fails(
            self.RUN, (images, "/${{ matrix.base }}.digest", "/${{ matrix.base }}.made"),
            (images, 'echo "${MADE#*@}" > "$RUNNER_TEMP/fp-digest/$BASE_ROW.digest"',
             'echo "${MADE#*@}" > "$RUNNER_TEMP/fp-digest/$BASE_ROW.made"'))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn("make gave no digest for oss-fuzz-theorems-2026.10: '': nothing pushed", caught)

    def test_control_publish_download_from_its_own_run(self):
        # Without run-id and github-token, publish's download reads the artifacts of publish's own run, which holds
        # none of make's. make stays whole, but publish downloads no digest.
        publish = f".github/workflows/{self.PUBLISH}"
        caught = self.handover_fails(
            self.RUN, (publish, "          run-id: ${{ github.event.workflow_run.id }}\n", ""),
            (publish, "          github-token: ${{ github.token }}\n", ""))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn("make gave no digest for oss-fuzz-theorems-2026.10: '': nothing pushed", caught)

    def test_control_publish_without_actions_read(self):
        # publish's job-level permissions then give actions none, so its token cannot read the artifacts of make's
        # run. make stays whole, but publish downloads no digest.
        line = "      actions: read   # to download the artifacts fp-digest-<base row> of the run of Toolchain images\n"
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.PUBLISH}", line, ""))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn("make gave no digest for oss-fuzz-theorems-2026.10: '': nothing pushed", caught)

    def test_control_publish_checks_out_main_not_the_built_commit(self):
        # With no ref, publish checks out main's newest commit, whose infra/toolchains.tsv names another base image of
        # the row. publish then makes another image than make made, and pushes nothing.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.PUBLISH}",
                                                "          ref: ${{ github.event.workflow_run.head_sha }}\n", ""))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn("::error::the image made here from oss-fuzz-theorems-2026.10 is ", caught)
        self.assertIn(", but make made sha256:", caught)

    def test_control_publish_without_packages_write(self):
        # publish's job-level permissions then give packages none, so ghcr.io refuses its copy of the image that it
        # made. On a table where ghcr.io does not hold that image, make stays whole, but publish fails.
        line = "      packages: write # to push the image, when ghcr.io does not hold it yet\n"
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.PUBLISH}", line, ""))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn(f"Error: PUT {self.PACKAGE}:{self.TAGS['oss-fuzz-theorems-2026.10']}: DENIED: "
                      "permission_denied: write_package", caught)

    def test_control_publish_without_contents_read(self):
        # publish's job-level permissions then give contents none, so its checkout fails and gives no
        # infra/toolchains.tsv. make stays whole, but publish fails.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.PUBLISH}", "      contents: read\n", ""))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertRegex(caught, r"awk: .*infra/toolchains\.tsv.*No such file or directory")

    def test_control_publish_sparse_checkout_of_another_file(self):
        # With cone mode off, the sparse checkout then takes infra/other.tsv alone, and leaves infra/toolchains.tsv out
        # (sparse_takes). make stays whole, but publish fails.
        publish = f".github/workflows/{self.PUBLISH}"
        caught = self.handover_fails(self.RUN, (publish, "sparse-checkout: infra/toolchains.tsv",
                                                "sparse-checkout: infra/other.tsv"))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertRegex(caught, r"awk: .*infra/toolchains\.tsv.*No such file or directory")

    def test_control_publish_push_step_writes_github_env(self):
        # The push step then changes the env of the job's later steps, in a job with packages: write.
        line = '          PATH="$RUNNER_TEMP/bin:$PATH"\n'
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.PUBLISH}", line,
                                                line + '          echo "X=1" >> "$GITHUB_ENV"\n'))
        self.assertIn("wrote GITHUB_PATH or GITHUB_ENV", caught)

    def test_control_publish_tag_in_the_package_of_the_base_image(self):
        # publish tags each image in the package of its base image. The Rust and the Python images then go to their
        # own packages, and publish's check of the image in FP_PACKAGE fails.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.PUBLISH}",
                                                'tag="$FP_PACKAGE:frame-pointers$language-$HEAD_SHA"',
                                                'tag="$name:frame-pointers-$HEAD_SHA"'))
        self.assertIn("oss-fuzz-theorems-2026.10-rust, none: make passes, publish fails", caught)
        self.assertRegex(caught, rf"::error::{re.escape(self.PACKAGE)}@sha256:[0-9a-f]{{64}} does not name exactly the "
                                 r"base image's layers")

    def test_control_make_row_check_without_its_comparison(self):
        # make's row check passes each row that ghcr.io holds, whatever image it names. publish refuses a row that
        # does not name the image that make made.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.IMAGES}",
                                                '          [ "$named" = "$want" ] ||\n', '          true ||\n'))
        self.assertIn("oss-fuzz-theorems-2026.10, other digest: make passes, publish refuses the row", caught)
        self.assertIn("oss-fuzz-theorems-2026.10-rust, base package: make passes, publish refuses the row", caught)

    def test_control_make_row_check_on_the_package_of_the_base_image(self):
        # make's row check as it was before FP_PACKAGE: it wants the made digest in the package of the base image.
        # That line read NAME, which the step's env no longer gives, so this line takes the package from the made
        # image: localhost:5000/<the path of the base package>@<digest>. make then passes the row of the base package,
        # and publish refuses it.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.IMAGES}", 'want="$FP_PACKAGE@${MADE#*@}"',
                                                'want="ghcr.io/${MADE#localhost:5000/}"'))
        self.assertIn("oss-fuzz-theorems-2026.10-rust, base package: make passes, publish refuses the row", caught)
        self.assertIn("oss-fuzz-theorems-2026.10-rust, made: make refuses the row, publish passes", caught)

    def test_control_make_writes_the_whole_reference_as_the_digest(self):
        # Part 1 sees no change. publish reads localhost:5000/...@sha256:..., which is no digest.
        caught = self.handover_fails(self.RUN, (f".github/workflows/{self.IMAGES}",
                                                'echo "${MADE#*@}" > "$RUNNER_TEMP/fp-digest/$BASE_ROW.digest"',
                                                'echo "$MADE" > "$RUNNER_TEMP/fp-digest/$BASE_ROW.digest"'))
        self.assertIn("oss-fuzz-theorems-2026.10, none: make passes, publish fails", caught)
        self.assertIn("make gave no digest for oss-fuzz-theorems-2026.10: 'localhost:5000/", caught)

    # make's line that writes the digest of its row, which compare-digests and publish read.
    DIGEST_WRITE = '          echo "${MADE#*@}" > "$RUNNER_TEMP/fp-digest/$BASE_ROW.digest"\n'

    def no_digest_case(self, name, *changes):
        """make's steps (run_make) for each base row of its matrix, on a table with no frame-pointer row, in a copy of
        the repository whose line DIGEST_WRITE writes no file, with `changes` too. make must then fail at its upload of
        the digest (if-no-files-found: error), so the run of Toolchain images on the pull request and on main fails
        there, and not later, in publish on main, on 'make gave no digest'."""
        tree = self.copy_tree(name, [(f".github/workflows/{self.IMAGES}", self.DIGEST_WRITE, "          true\n"),
                                     *changes])
        images = self.workflow(tree, self.IMAGES)
        rows = images["jobs"]["make"]["strategy"]["matrix"]["base"]
        bases = self.base_rows(rows)
        registry, _, _ = self.registry_of(bases)
        outcomes = {row: self.run_make(images, row, self.checkout_of(bases), self.crane_home(registry))[0]
                    for row in rows}
        self.assertEqual({row: outcome.startswith("fails at its upload of ") for row, outcome in outcomes.items()},
                         dict.fromkeys(rows, True),
                         f"make's outcome for each base row when no file is at the path of its upload: {outcomes}")

    def test_make_fails_at_its_upload_when_no_digest_is_written(self):
        self.no_digest_case("no digest")

    def test_control_make_upload_without_if_no_files_found_error(self):
        with self.assertRaises(AssertionError) as caught:
            self.no_digest_case("no digest, no error", (f".github/workflows/{self.IMAGES}",
                                                        "          if-no-files-found: error\n", ""))
        self.assertIn("when no file is at the path of its upload", str(caught.exception))

    def guard_fails(self, case, old, new=""):
        """`case` passes on an unchanged copy of the tree, and fails on a copy whose publish file has `new` for `old`
        (copy_tree). Return its message."""
        self.passes_unchanged(case)
        changed = self.copy_tree("changed", [(f".github/workflows/{self.PUBLISH}", old, new)])
        with self.assertRaises(AssertionError) as caught:
            case(changed)
        return str(caught.exception)

    def packages_case(self, tree=ROOT):
        """publish's push step for each base row of its matrix (pushes), with the digest that make made, on a table
        with no frame-pointer row: ghcr.io holds no frame-pointer image, so the step makes each image, logs in and
        copies it. After the grant, this job's token can write to every package that the grant covers, so each
        command of crane names a reference of ghcr.io only in PACKAGE or as the row's base image, which the step reads,
        and writes (the target of crane copy, the tag of crane mutate) only to its own registry (localhost:5000) or
        PACKAGE."""
        publish = self.workflow(tree, self.PUBLISH)
        rows = publish["jobs"]["publish"]["strategy"]["matrix"]["base"]
        bases = self.base_rows(rows)
        found = {}
        for row, (rc, log, calls, _) in self.pushes(publish).items():
            self.assertEqual(rc, 0, f"{row}: {log}")
            found[row] = []
            for call in calls:
                writes = call[2:3] if call[0] == "copy" else call[call.index("-t") + 1:][:1] if "-t" in call else []
                found[row] += [f"crane {' '.join(call)} names {arg}" for arg in call
                               if arg.partition("/")[:2] == ("ghcr.io", "/") and arg != bases[row][1]
                               and arg.partition("@")[0].partition(":")[0] != self.PACKAGE]
                found[row] += [f"crane {' '.join(call)} writes to {to}" for to in writes
                               if not to.startswith(("localhost:5000/", f"{self.PACKAGE}:", f"{self.PACKAGE}@"))]
        self.assertEqual(found, dict.fromkeys(rows, []),
                         "the commands of publish's crane that name a package of ghcr.io other than PACKAGE and the "
                         "row's base image, or write outside PACKAGE and its own registry")

    def test_publish_names_no_package_of_ghcr_io_but_the_one_and_the_base_image(self):
        self.packages_case()

    def test_control_publish_writes_to_a_second_package(self):
        login = '            echo "$GH_TOKEN" | crane auth login ghcr.io --username "$GITHUB_ACTOR" --password-stdin\n'
        mirror = ('            crane mutate "$base" --env OFT_FRAME_POINTERS=1'
                  ' -t "${name}-mirror:frame-pointers-$HEAD_SHA" > /dev/null\n')
        self.maxDiff = None  # the message then names each command that it found
        caught = self.guard_fails(self.packages_case, login, login + mirror)
        self.assertIn("-mirror:frame-pointers-", caught)

    # The faults of ghcr.io that publish's push step checks for after its push, or on an image that ghcr.io holds.
    FAULTS = ("none", "another digest for the tag", "other layers", "another configuration")

    def ghcr_case(self, tree=ROOT):
        """publish's push step (run_push) for each base row of its matrix, with the digest that make made, on a ghcr.io
        that is honest (none) and on three faults: it gives another digest for the tag that the step pushed; it holds
        the image at PACKAGE@<digest> with layers other than the base image's; it holds it with a configuration other
        than the base image's plus OFT_FRAME_POINTERS=1. The step must pass only on the honest one: else a run on main
        ends green with an image that the rows of infra/toolchains.tsv would then name."""
        publish = self.workflow(tree, self.PUBLISH)
        rows = publish["jobs"]["publish"]["strategy"]["matrix"]["base"]
        bases = self.base_rows(rows)
        where = self.checkout_of(bases)
        results = {}
        for row in rows:
            for fault in self.FAULTS:
                registry, made, fp = self.registry_of(bases)
                ref = f"{self.PACKAGE}@{made[row]}"
                if fault == "other layers":
                    layers = fp[row]["manifest"]["layers"][:-1]
                    registry["images"][ref] = {**fp[row], "manifest": {**fp[row]["manifest"], "layers": layers}}
                elif fault == "another configuration":
                    registry["images"][ref] = {**fp[row], "config": registry["images"][bases[row][1]]["config"]}
                temp = self.push_temp(row, made[row])
                if fault == "another digest for the tag":
                    # crane digest of a tag of PACKAGE gives another digest; every other command is the stand-in's.
                    self.put_crane(temp / "real")
                    real = temp / "real" / "crane"
                    (temp / "bin" / "crane").write_text(
                        "#!/usr/bin/env python3\nimport os\nimport sys\n"
                        f"if sys.argv[1:2] == ['digest'] and sys.argv[2].startswith({self.PACKAGE + ':'!r}):\n"
                        "    print('sha256:' + 'd' * 64)\nelse:\n"
                        f"    os.execv({str(real)!r}, [{str(real)!r}, *sys.argv[1:]])\n")
                rc, log, _ = self.run_push(publish, row, where, self.crane_home(registry), temp)
                results[(row, fault)] = (rc, log)
        self.assertEqual({key: rc == 0 for key, (rc, _) in results.items()},
                         {(row, fault): fault == "none" for row in rows for fault in self.FAULTS},
                         f"publish's push step passes only on an honest ghcr.io: {results}")

    def test_publish_checks_the_image_on_ghcr_io(self):
        self.ghcr_case()

    def test_control_publish_without_its_check_of_the_pushed_digest(self):
        caught = self.guard_fails(self.ghcr_case, '            [ "$pushed" = "$want" ] ||\n', "            true ||\n")
        self.assertIn("publish's push step passes only on an honest ghcr.io", caught)

    def test_control_publish_without_its_check_of_the_layers(self):
        caught = self.guard_fails(self.ghcr_case, "'$b.layers == $n.layers and $b.mediaType == $n.mediaType'",
                                  "'true'")
        self.assertIn("publish's push step passes only on an honest ghcr.io", caught)

    def test_control_publish_without_its_check_of_the_configuration(self):
        caught = self.guard_fails(self.ghcr_case, """'($b | .config.Env += ["OFT_FRAME_POINTERS=1"]) == $n'""",
                                  "'true'")
        self.assertIn("publish's push step passes only on an honest ghcr.io", caught)

    # A stand-in curl: it writes the file $FAKE_CURL/archive at the path of its -o, and adds each address that it is
    # asked for to $FAKE_CURL/urls, one a line.
    CURL = r"""#!/usr/bin/env python3
import os
import pathlib
import shutil
import sys

home = pathlib.Path(os.environ["FAKE_CURL"])
args = sys.argv[1:]
with open(home / "urls", "a") as urls:
    urls.writelines(arg + "\n" for arg in args if arg.startswith(("http://", "https://")))
shutil.copyfile(home / "archive", args[args.index("-o") + 1])
"""

    def install_case(self, tree=ROOT):
        """publish's step install crane, with the stand-in CURL first on PATH, which gives a tar.gz of one file, crane.
        The step must fetch CRANE_ARCHIVE of the release CRANE_VERSION of go-containerregistry. The workflow's pin
        CRANE_SHA256 is not the SHA-256 of this archive, so the step must fail and put no crane in $RUNNER_TEMP/bin.
        With CRANE_SHA256 set to the archive's own SHA-256, it must put the archive's crane there. After each run,
        GITHUB_PATH and GITHUB_ENV (file_commands) are still empty: a step that writes them changes the PATH or the env
        of the push step, in a job with packages: write."""
        publish = self.workflow(tree, self.PUBLISH)
        step = self.step(publish, "publish", "install crane")
        fake = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        (fake / "bin").mkdir()
        (fake / "bin" / "curl").write_text(self.CURL)
        (fake / "bin" / "curl").chmod(0o755)
        crane = b"#!/bin/sh\necho the crane of the archive\n"
        with tarfile.open(fake / "archive", "w:gz") as archive:
            member = tarfile.TarInfo("crane")
            member.size, member.mode = len(crane), 0o755
            archive.addfile(member, io.BytesIO(crane))
        own = hashlib.sha256((fake / "archive").read_bytes()).hexdigest()
        pin = env_of(publish, "publish", step, {})
        self.assertNotEqual(own, pin["CRANE_SHA256"])
        url = ("https://github.com/google/go-containerregistry/releases/download/"
               f"{pin['CRANE_VERSION']}/{pin['CRANE_ARCHIVE']}")
        for what, given in (("an archive whose SHA-256 is not CRANE_SHA256", {}),
                            ("CRANE_SHA256 set to the archive's SHA-256", {"CRANE_SHA256": own})):
            temp = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
            files = self.file_commands(temp)
            (fake / "urls").write_text("")
            rc, log, _ = self.run_script(step["run"], self.dir, RUNNER_TEMP=str(temp), FAKE_CURL=str(fake),
                                         PATH=f"{fake / 'bin'}{os.pathsep}{self.env['PATH']}",
                                         **{name: str(path) for name, path in files.items()},
                                         **env_of(publish, "publish", step, {}, given))
            self.assertEqual((fake / "urls").read_text().splitlines(), [url],
                             f"install crane, with {what}: the addresses that curl fetched")
            installed = temp / "bin" / "crane"
            self.assertEqual((rc == 0, installed.is_file() and installed.read_bytes() == crane), (bool(given),) * 2,
                             f"install crane, with {what}: (it passes, crane is in $RUNNER_TEMP/bin). Its log:\n{log}")
            self.assertEqual({name: path.read_text() for name, path in files.items()}, dict.fromkeys(files, ""),
                             f"install crane, with {what}: GITHUB_PATH and GITHUB_ENV after the step")

    def test_publish_installs_crane_only_from_the_archive_of_its_pin(self):
        self.install_case()

    def test_control_publish_install_without_its_check_of_the_archive(self):
        caught = self.guard_fails(self.install_case,
                                  '          echo "$CRANE_SHA256  $RUNNER_TEMP/$CRANE_ARCHIVE" | sha256sum -c -\n')
        self.assertIn("install crane, with an archive whose SHA-256 is not CRANE_SHA256: (it passes, crane is in "
                      "$RUNNER_TEMP/bin)", caught)

    def test_control_publish_install_writes_github_path(self):
        tar = '          tar -xzf "$RUNNER_TEMP/$CRANE_ARCHIVE" -C "$RUNNER_TEMP/bin" crane\n'
        caught = self.guard_fails(self.install_case, tar, tar + '          echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"\n')
        self.assertIn("install crane, with CRANE_SHA256 set to the archive's SHA-256: GITHUB_PATH and GITHUB_ENV",
                      caught)

    def pushes(self, publish, base=None):
        """publish's push step (run_push) of the workflow `publish` for each base row of its matrix, with the digest
        that make made (push_temp), on a table with no frame-pointer row, where ghcr.io holds no frame-pointer image:
        the step makes the image, logs in and copies it. With `base`, the row's base line names the image `base`
        instead. Return for each row (its exit status, its log, its calls of crane, whether a login of crane is left
        at its end)."""
        rows = publish["jobs"]["publish"]["strategy"]["matrix"]["base"]
        bases = self.base_rows(rows)
        found = {}
        for row in rows:
            table = {**bases, row: (bases[row][0].replace(bases[row][1], base), base)} if base else bases
            # registry_of takes the layers of an image from the name of its row, so the stand-in registry holds `base`,
            # and crane mutate makes of it the image that make made of the row's own base image.
            registry, made, _ = self.registry_of(table)
            home = self.crane_home(registry)
            rc, log, calls = self.run_push(publish, row, self.checkout_of(table), home, self.push_temp(row, made[row]))
            found[row] = (rc, log, calls, (home / "login").exists())
        return found

    @staticmethod
    def logs_of(found):
        """The log of each row of `found` (pushes), for a message."""
        return "".join(f"\n{row}:\n{log}" for row, (_, log, _, _) in found.items())

    def unset_case(self, tree=ROOT):
        """publish's push step (pushes) with HEAD_SHA taken out of its env. GitHub runs a step that names no shell with
        bash -e {0}, as run_script does, so only the step's own set -u stops it at the unset variable. Without it, the
        step pushes the image under the tag frame-pointers-, with no commit, and passes. It must fail with
        'HEAD_SHA: unbound variable' before its crane copy."""
        publish = self.workflow(tree, self.PUBLISH)
        del self.push_step(publish)["env"]["HEAD_SHA"]
        found = self.pushes(publish)
        got = {row: (rc != 0, "HEAD_SHA: unbound variable" in log, [call for call in calls if call[0] == "copy"])
               for row, (rc, log, calls, _) in found.items()}
        self.assertEqual(got, dict.fromkeys(found, (True, True, [])),
                         "publish's push step with no HEAD_SHA in its env, on each row: (it fails, it says 'HEAD_SHA: "
                         "unbound variable', its crane copies). Its logs:" + self.logs_of(found))

    def test_publish_push_step_stops_at_an_unset_variable(self):
        self.unset_case()

    def test_control_publish_push_step_without_set_euo_pipefail(self):
        caught = self.guard_fails(self.unset_case,
                                  '          set -euo pipefail\n          PATH="$RUNNER_TEMP/bin:$PATH"\n',
                                  '          PATH="$RUNNER_TEMP/bin:$PATH"\n')
        self.assertIn("publish's push step with no HEAD_SHA in its env, on each row: (it fails, it says", caught)

    # An image outside the toolchain packages of ghcr.io, which a base row of infra/toolchains.tsv must not name.
    FOREIGN = "docker.io/library/debian@sha256:" + "d" * 64

    def foreign_case(self, tree=ROOT):
        """publish's push step (pushes) on a table whose base row names FOREIGN, an image outside the toolchain
        packages. The stand-in registry holds it, and crane mutate makes of it the image with the digest that make
        made, so no comparison of the step refuses it. The step must fail with its error on the base row, and run no
        command of crane. Without that check, the step stops at ${BASH_REMATCH[1]}, which set -u refuses after a match
        that failed, and says nothing of the row."""
        found = self.pushes(self.workflow(tree, self.PUBLISH), base=self.FOREIGN)
        error = "::error::infra/toolchains.tsv has no row {} with a toolchain digest: '{}'"
        got = {row: (rc != 0, error.format(row, self.FOREIGN) in log, calls)
               for row, (rc, log, calls, _) in found.items()}
        self.assertEqual(got, dict.fromkeys(found, (True, True, [])),
                         f"publish's push step on a base row that names {self.FOREIGN}, on each row: (it fails, it "
                         "says that infra/toolchains.tsv has no such row with a toolchain digest, its commands of "
                         "crane). Its logs:" + self.logs_of(found))

    def test_publish_refuses_a_base_row_outside_the_toolchain_packages(self):
        self.foreign_case()

    def test_control_publish_without_its_check_of_the_base_row(self):
        caught = self.guard_fails(self.foreign_case, "            { echo \"::error::infra/toolchains.tsv has no row "
                                  "$BASE_ROW with a toolchain digest: '$base'\"; exit 1; }\n", "            true\n")
        self.assertIn(f"publish's push step on a base row that names {self.FOREIGN}, on each row: (it fails, it says",
                      caught)

    def logout_case(self, tree=ROOT):
        """publish's push step (pushes) on each row where ghcr.io does not hold the image: it logs in to copy the image.
        It must log out of ghcr.io after its copy and after its check of the digest of the pushed tag, and leave no
        login of crane (the stand-in's file $FAKE_CRANE/login) at its end."""
        found = self.pushes(self.workflow(tree, self.PUBLISH))
        got = {}
        for row, (rc, _, calls, login) in found.items():
            pushed = [n for n, call in enumerate(calls)
                      if call[0] == "copy" or call == ["digest", f"{self.PACKAGE}:{self.TAGS[row]}"]]
            got[row] = (rc, len(pushed) == 2 and ["auth", "logout", "ghcr.io"] in calls[max(pushed) + 1:], login)
        self.assertEqual(got, dict.fromkeys(found, (0, True, False)),
                         "publish's push step on each row: (its exit status, a logout of ghcr.io after its copy and "
                         "its check of the pushed tag, a login of crane left at its end). Its logs:"
                         + self.logs_of(found))

    def test_publish_logs_out_of_ghcr_io_after_its_push(self):
        self.logout_case()

    def test_control_publish_without_its_logout(self):
        caught = self.guard_fails(self.logout_case, "            crane auth logout ghcr.io\n")
        self.assertIn("publish's push step on each row: (its exit status, a logout of ghcr.io after its copy", caught)

    def test_publish_starts_on_the_runs_of_toolchain_images_by_its_name_alone(self):
        # workflow_run names a workflow by its name: a rename of toolchain-images.yaml, or of the name publish listens
        # to, would stop publishing with no error. No other workflow has that name.
        publish, images = self.workflow(ROOT, self.PUBLISH), self.workflow(ROOT, self.IMAGES)
        self.assertEqual(triggers(publish)["workflow_run"]["workflows"], [images["name"]])
        names = [parse(p.read_text()).get("name")
                 for p in sorted((ROOT / ".github" / "workflows").iterdir()) if p.suffix in (".yml", ".yaml")]
        self.assertEqual(names.count(images["name"]), 1, names)

    def test_publish_runs_no_docker_and_no_script_of_it_reads_github_sha_or_holds_an_expression(self):
        steps = self.workflow(ROOT, self.PUBLISH)["jobs"]["publish"]["steps"]
        # crane alone: no step runs docker.
        for step in steps:
            run = "\n".join(line for line in str(step.get("run", "")).splitlines()
                            if not line.lstrip().startswith("#"))
            self.assertNotRegex(run, r"\bdocker\b", step.get("name"))
        # In a workflow_run run, GITHUB_SHA is main's newest commit, not the commit that the run of Toolchain images
        # built. No script holds an expression.
        self.assertFalse([s.get("name") for s in steps if "GITHUB_SHA" in str(s.get("run", ""))
                          or "${{" in str(s.get("run", ""))])


class FirstRunArtifact(Stand):
    """(s): Build run 900 of pull request 7 at HEAD completed, and review.yml runs on workflow_run. The run's artifact
    build-results names pull request 8, or the head OTHER, or holds a diff of its own. And the sizes of the artifact,
    which build.yaml's results job writes: take-build-results gives them as its output sizes, bound in size, and only
    them when they have another shape; it reads an artifact from before sizes with none."""

    RUN, ARTIFACT = "900", 9001
    VARIANTS = (("another number", {"pr": 8}), ("another head", {"sha": OTHER}),
                ("another diff", {"diff": "diff --git a/README.md b/README.md\n+ARTIFACT-DIFF\n"}))
    FILES = ("projects/x/project.yaml", "projects/x/build.sh")
    ROUTE = "An enrollment, a change or an issue"
    TAKE = "Take the results of the Build run"
    GATHER = "Gather what the review reads, and the diff since the last review"
    POST = "Post the comment and record the verdict"
    # The four outputs of take-build-results for the results of Build run 900 (results()).
    HONEST = {"build": "The Build check success: ARTIFACT-RESULT.", "binaries": "ARTIFACT-BINARIES",
              "checks": "ARTIFACT-CHECKS", "commit": ""}
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
                "result": "ARTIFACT-RESULT", "binaries": "ARTIFACT-BINARIES", "checks": "ARTIFACT-CHECKS",
                "sizes": None, **change}

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
                  ".github/scripts/steering.py", ".github/scripts/artifact.py")
        review = self.workflow(tree, "review.yml")
        no_result = re.search(r'^NO_RESULT = "(.*)"$', (tree / ".github/scripts/take-build-results").read_text(),
                              re.M).group(1)
        ids = self.check_ids(tree)
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
            self.assertEqual(build, {"build": no_result, "binaries": "", "checks": "", "commit": "", "sizes": ""},
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
                        "needs.gather.outputs.checks": build["checks"], "needs.gather.outputs.sizes": build["sizes"],
                        "needs.gather.outputs.screen": "true",
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
            # The check run keeps the record of the review in its output.text, an HTML comment.
            text = sent[1]["body"]["output"]["text"]
            self.assertEqual((text[:5], text[-4:], json.loads(text[5:-4])["head"]), ("<!-- ", " -->", HEAD),
                             f"the comment job's post ({label})")
            # No call of the run (gh api, gh pr view or gh pr diff) names the artifact's number or head.
            named = [args for _, args in self.calls()
                     if any(re.search(r"(^|/)8(/|$)", arg) for arg in args) or OTHER in " ".join(args)]
            self.assertEqual(named, [], f"the calls of the run ({label})")

    def test_s_an_artifact_of_another_number_head_or_diff_changes_nothing(self):
        self.case()

    def test_control_s_route_reads_the_artifact(self):
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(".github/workflows/review.yml", self.ROUTE_OUTPUTS,
                                              self.FROM_ARTIFACT + self.ROUTE_OUTPUTS)])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("route's outputs (another number)", str(caught.exception))

    def test_control_s_take_build_results_compares_nothing(self):
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(".github/scripts/take-build-results", self.COMPARISON, "")])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("take-build-results' outputs (another number)", str(caught.exception))

    @staticmethod
    def understated(name, text, method):
        """A zip of one member `name`, compressed with `method`, that holds the text `text` and then 64 MiB of spaces.
        Its local file header and its central directory entry say that it holds `text` alone. The uncompressed size is
        22 bytes into the local file header (at the start of the zip) and 24 bytes into the entry. The end of central
        directory record (the last 22 bytes) gives the offset of the entry 16 bytes into it."""
        import struct
        data, spaces = text.encode(), b" " * (1 << 20)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", method) as archive, archive.open(name, "w") as member:
            member.write(data)
            for _ in range(64):
                member.write(spaces)
        out = bytearray(buffer.getvalue())
        struct.pack_into("<I", out, 22, len(data))
        struct.pack_into("<I", out, struct.unpack_from("<I", out, len(out) - 22 + 16)[0] + 24, len(data))
        return bytes(out)

    def take_module(self):
        """.github/scripts/take-build-results as a module of this process, so that a test runs its main here."""
        self.need(ROOT, ".github/scripts/take-build-results", ".github/scripts/steering.py",
                  ".github/scripts/artifact.py")
        saved = list(sys.path)
        try:
            loader = importlib.machinery.SourceFileLoader("take_build_results_of_this_test",
                                                          str(ROOT / ".github" / "scripts" / "take-build-results"))
            take = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
            loader.exec_module(take)
        finally:
            sys.path[:] = saved
        return take

    def take_env(self):
        """The environment of take-build-results in the gather job, for Build run 900 of pull request 7 at HEAD."""
        return {**self.env, "GH_TOKEN": WORKFLOW_TOKEN, "REPO": REPO, "BUILD_RUN": self.RUN, "PR": PR,
                "HEAD_SHA": HEAD, "NAME": "x"}

    def taken(self, take, results):
        """The main of `take` (take_module), run in this process for Build run 900 whose artifact holds `results` as
        results.json: (its exit status, its outputs, what it printed)."""
        data = zipped({"results.json": json.dumps(results)})
        self.assertLess(len(data), take.MAX_ARTIFACT_BYTES)
        self.fixture({}, data)
        self.output.write_text("")
        printed = io.StringIO()
        with mock.patch.dict(os.environ, self.take_env(), clear=True), contextlib.redirect_stdout(printed):
            code = take.main()
        return code, outputs(self.output.read_text()), printed.getvalue()

    @staticmethod
    def compact(value):
        """`value` as one line of compact JSON."""
        return json.dumps(value, separators=(",", ":"))

    def test_s_a_member_that_holds_more_than_its_header_says_gives_no_result_in_little_memory(self):
        """The header of results.json says that it holds the results of this head alone. It holds them and 64 MiB of
        spaces after them, deflated or in bzip2. take-build-results gives its no-result line, and takes less than
        16 MiB of memory: a read of the whole member takes about 128 MiB. Its main runs in this process, so that
        tracemalloc sees its memory. A deflated results.json that holds what its header says gives its results."""
        import tracemalloc
        take = self.take_module()
        env = self.take_env()
        text = json.dumps(self.results({}))
        no_result = {"build": take.NO_RESULT, "binaries": "", "checks": "", "commit": "", "sizes": ""}
        for label, data, want, said in (
                ("deflated", self.understated("results.json", text, zipfile.ZIP_DEFLATED), no_result,
                 "the read failed (BadZipFile)"),
                ("bzip2", self.understated("results.json", text, zipfile.ZIP_BZIP2), no_result,
                 f"Build run {self.RUN}'s results.json has the compression method 12, not stored or deflated."),
                ("honest and deflated", zipped({"results.json": text}, zipfile.ZIP_DEFLATED),
                 {**self.HONEST, "sizes": ""}, f"read the results of Build run {self.RUN}")):
            self.assertLess(len(data), 1 << 20, label)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.assertEqual(archive.getinfo("results.json").file_size, len(text), label)
            self.fixture({}, data)
            self.output.write_text("")
            printed = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(printed):
                tracemalloc.start()
                try:
                    baseline = tracemalloc.get_traced_memory()[0]
                    code = take.main()
                    peak = tracemalloc.get_traced_memory()[1] - baseline
                finally:
                    tracemalloc.stop()
            self.assertLess(peak, 16 << 20, f"the peak of the memory ({label})")
            self.assertEqual(code, 0, printed.getvalue())
            self.assertEqual(outputs(self.output.read_text()), want, f"take-build-results' outputs ({label})")
            self.assertIn(f"take-build-results: {said}", printed.getvalue(), label)

    def test_s_the_sizes_of_the_results_are_the_output_sizes_in_one_line_of_compact_json(self):
        """The sizes of results.json, as .github/scripts/binary-sizes gives them, are the fifth output of
        take-build-results. Null sizes give it empty."""
        take = self.take_module()
        sizes = {"parse": {"plain": {"text": 1000, "exec": 1200}, "asan": {"text": 3000, "exec": None}},
                 "dump all": {"plain": {"text": 0, "exec": 950}}, "none built": {}}
        code, got, printed = self.taken(take, self.results({"sizes": sizes}))
        self.assertEqual((code, got), (0, {**self.HONEST, "sizes": (
            '{"parse":{"plain":{"text":1000,"exec":1200},"asan":{"text":3000,"exec":null}},'
            '"dump all":{"plain":{"text":0,"exec":950}},"none built":{}}')}), printed)
        code, got, printed = self.taken(take, self.results({"sizes": None}))
        self.assertEqual((code, got), (0, {**self.HONEST, "sizes": ""}), printed)

    def test_s_results_from_before_sizes_give_every_other_output(self):
        """A Build run keeps its artifact 30 days, so a review by hand of a head can read a results.json
        that build.yaml wrote before it wrote sizes: the four other outputs are its results, and sizes is empty."""
        take = self.take_module()
        old = self.results({})
        del old["sizes"]
        code, got, printed = self.taken(take, old)
        self.assertEqual((code, got), (0, {**self.HONEST, "sizes": ""}), printed)
        self.assertIn(f"take-build-results: read the results of Build run {self.RUN}", printed)

    def test_s_a_member_with_another_key_is_still_refused(self):
        take = self.take_module()
        old = self.results({})
        del old["sizes"]
        missing = self.results({})
        del missing["checks"]
        for label, results in (("an unknown key", self.results({"extra": 1})),
                               ("an unknown key and no sizes", dict(old, extra=1)), ("no checks", missing)):
            with self.subTest(label):
                code, got, printed = self.taken(take, results)
                self.assertEqual((code, got), (0, {"build": take.NO_RESULT, "binaries": "", "checks": "",
                                                   "commit": "", "sizes": ""}), printed)
                self.assertIn("take-build-results: results.json does not have the shape of 'oss-verify build results"
                              " v1'.", printed)

    def test_s_sizes_of_another_shape_give_no_sizes_and_keep_the_other_outputs(self):
        """Sizes that are not those of binary-sizes give the output sizes empty, and only it. One line of
        the log says why, and it names no text of the artifact."""
        take = self.take_module()
        plain = {"text": 1000, "exec": 1200}
        for label, sizes in (("a list", [plain]), ("a text", "ARTIFACT-SIZES"), ("a number", 1), ("a boolean", True),
                             ("a target that is not an object", {"ARTIFACT-TARGET": [plain]}),
                             ("a build that is not an object", {"ARTIFACT-TARGET": {"plain": 1000}}),
                             ("a build with an extra key",
                              {"ARTIFACT-TARGET": {"plain": {**plain, "ARTIFACT-KEY": 1}}}),
                             ("a build without exec", {"ARTIFACT-TARGET": {"plain": {"text": 1000}}}),
                             ("a negative size", {"ARTIFACT-TARGET": {"plain": {"text": -1, "exec": 1200}}}),
                             ("a float", {"ARTIFACT-TARGET": {"plain": {"text": 1000.0, "exec": 1200}}}),
                             ("a boolean size", {"ARTIFACT-TARGET": {"plain": {"text": True, "exec": 1200}}}),
                             ("a text size", {"ARTIFACT-TARGET": {"plain": {"text": "1000", "exec": 1200}}}),
                             ("a NUL in a target name", {"ARTIFACT-\0TARGET": {"plain": plain}}),
                             ("a NUL in a build name", {"ARTIFACT-TARGET": {"pl\0ain": plain}}),
                             ("an empty target name", {"": {"plain": plain}}),
                             ("an empty build name", {"ARTIFACT-TARGET": {"": plain}})):
            with self.subTest(label):
                code, got, printed = self.taken(take, self.results({"sizes": sizes}))
                self.assertEqual((code, got), (0, {**self.HONEST, "sizes": ""}), printed)
                said = [line for line in printed.splitlines() if "sizes" in line]
                self.assertEqual(len(said), 1, printed)
                self.assertNotIn("ARTIFACT-", printed)

    def test_s_sizes_over_the_bound_keep_only_the_plain_build_of_each_target(self):
        """The comment job's step gets the output sizes in one environment variable, and Linux starts no
        process with one over 131,072 bytes. Sizes of 100,001 bytes of compact JSON, 4 builds of each target, keep
        only the plain build of each target ({} for a target with none), and one line of the log says so. Sizes of
        100,000 bytes keep every build."""
        take = self.take_module()
        builds = {build: {"text": 123456, "exec": 234567} for build in ("plain", "asan", "ubsan", "msan")}
        sizes = {f"fuzz_{n:04d}": builds for n in range(100_000 // len(self.compact({"fuzz_0000": builds})))}
        sizes["no_plain_build"] = {"asan": {"text": 1, "exec": 2}}
        # The first target's name takes what is left, so that the JSON has exactly 100,000 bytes.
        first = "fuzz_0000" + "_" * (100_000 - len(self.compact(sizes)))
        sizes = {first if target == "fuzz_0000" else target: value for target, value in sizes.items()}
        self.assertEqual(len(self.compact(sizes).encode()), 100_000)
        code, got, printed = self.taken(take, self.results({"sizes": sizes}))
        self.assertEqual((code, got), (0, {**self.HONEST, "sizes": self.compact(sizes)}), printed)
        self.assertNotIn("sizes", printed)
        # One byte more.
        sizes = {target + "_" if target == first else target: value for target, value in sizes.items()}
        self.assertEqual(len(self.compact(sizes).encode()), 100_001)
        code, got, printed = self.taken(take, self.results({"sizes": sizes}))
        plain = {target: {"plain": value["plain"]} if "plain" in value else {} for target, value in sizes.items()}
        self.assertEqual(plain["no_plain_build"], {})
        self.assertEqual((code, got), (0, {**self.HONEST, "sizes": self.compact(plain)}), printed)
        self.assertLessEqual(len(got["sizes"].encode()), 100_000)
        said = [line for line in printed.splitlines() if "sizes" in line]
        self.assertEqual(len(said), 1, printed)

    def test_s_sizes_still_over_the_bound_with_the_plain_builds_alone_give_no_sizes(self):
        take = self.take_module()
        sizes = {f"fuzz_{n:04d}_" + "x" * 80: {"plain": {"text": 123456, "exec": 234567}} for n in range(1000)}
        self.assertGreater(len(self.compact(sizes).encode()), 100_000)
        code, got, printed = self.taken(take, self.results({"sizes": sizes}))
        self.assertEqual((code, got), (0, {**self.HONEST, "sizes": ""}), printed)
        said = [line for line in printed.splitlines() if "sizes" in line]
        self.assertEqual(len(said), 2, printed)

    def test_s_the_results_job_writes_the_sizes_of_the_build_step_and_take_build_results_gives_them(self):
        """build.yaml's results job, run here, writes the build step's output results_sizes (the sizes, cut at 100,000
        bytes) as JSON, null when the output is empty. It writes them into the file that its upload of build-results
        takes: the path of that upload, with this test's RUNNER_TEMP. take-build-results gives them back as its output
        sizes."""
        build = self.workflow(ROOT, "build.yaml")
        take = self.take_module()
        uploads = [step.get("with") or {} for step in build["jobs"]["results"]["steps"]
                   if action_of(step) == "actions/upload-artifact"]
        paths = [render(up.get("path", ""), {"runner.temp": str(self.temp)}) for up in uploads
                 if up.get("name") == "build-results"]
        self.assertEqual(len(paths), 1, f"the results job's uploads of build-results: {uploads}")
        uploaded = pathlib.Path(paths[0])
        line = '{"parse":{"asan":{"exec":3300,"text":3000},"plain":{"exec":1200,"text":1000}}}'
        for given in (line, ""):
            with self.subTest(sizes=given):
                shutil.rmtree(self.temp / "results", ignore_errors=True)
                built = {"name": "x", "sha": HEAD, "commit": "", "code": "0", "result": "ARTIFACT-RESULT",
                         "binaries": "ARTIFACT-BINARIES", "checks": "ARTIFACT-CHECKS", "results_sizes": given}
                ctx = {"github.event.pull_request.number": PR,
                       **{f"needs.project-builds.outputs.{k}": v for k, v in built.items()}}
                rc, log, _ = self.run_step(build, "results", "Write the results", ctx, self.dir)
                self.assertEqual(rc, 0, log)
                self.assertTrue(uploaded.is_file(), f"the results job wrote no {uploaded}, the path of its upload")
                results = json.loads(uploaded.read_text())
                self.assertEqual(results, self.results({"sizes": json.loads(given) if given else None}))
                code, got, printed = self.taken(take, results)
                self.assertEqual((code, got), (0, {**self.HONEST, "sizes": given}), printed)


class BuildArtifacts(Stand):
    """(artifacts): each script of .github/scripts that reads a file of an artifact of a Build run (read_member of
    artifact.py) reads an artifact and a file that build.yaml uploads. The upload fails when the file is absent
    (if-no-files-found: error). A rename on one side alone shows only when a later run reads the artifact: no run of
    the pull request that makes the rename reads it. FirstRunArtifact and tests/test_enroll_dispatch.py's TheRecord
    run the steps that write the two files, and read each file at the path of its upload."""

    BUILD = ".github/workflows/build.yaml"
    # The readers at the head, each as (the script, the artifact, the file): review.yml's gather job runs
    # take-build-results, and enroll-dispatch.yml runs enroll-dispatch.
    READERS = {("take-build-results", "build-results", "results.json"),
               ("enroll-dispatch", "enrollment-record", "record.json")}

    @staticmethod
    def string(node, constants):
        """The string that the argument `node` gives: a string, or a name of `constants`. Else None."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return constants.get(node.id) if isinstance(node, ast.Name) else None

    def readers(self, tree):
        """Each call of read_member in a Python script of `tree`'s .github/scripts, as (the script, its line, the
        artifact, the file). An argument that is a name gives the string that the top level of the script assigns to
        that name. An argument that this cannot read gives None."""
        scripts, found = tree / ".github" / "scripts", []
        for path in sorted(scripts.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            first = path.read_bytes().split(b"\n", 1)[0]
            if path.suffix != ".py" and not (first.startswith(b"#!") and b"python" in first):
                continue
            module = ast.parse(path.read_text(encoding="utf-8"), str(path))
            constants = {node.targets[0].id: node.value.value for node in module.body
                         if isinstance(node, ast.Assign) and len(node.targets) == 1
                         and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
                         and isinstance(node.value.value, str)}
            for node in ast.walk(module):
                func = node.func if isinstance(node, ast.Call) else None
                if getattr(func, "id", getattr(func, "attr", None)) != "read_member":
                    continue
                # artifact.py's read_member(api, repo, run, name, member, limit)
                given = dict(zip(("api", "repo", "run", "name", "member", "limit"), node.args))
                given.update((keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg)
                found.append((path.relative_to(scripts).as_posix(), node.lineno,
                              *(self.string(given.get(argument), constants) for argument in ("name", "member"))))
        return found

    def case(self, tree=ROOT):
        """Each reader (readers) reads an artifact that an upload of build.yaml (actions/upload-artifact) gives. The
        upload has the artifact's name, its path ends in /<the file>, and it has if-no-files-found: error. The message
        names each reader that no upload gives its file. Return the readers and the uploads."""
        build = self.workflow(tree, "build.yaml")
        readers = self.readers(tree)
        self.assertLessEqual(self.READERS, {(script, artifact, member) for script, _, artifact, member in readers},
                             f"the calls of read_member in .github/scripts: {readers}")
        uploads = []
        for job, held in build["jobs"].items():
            for step in held.get("steps") or []:
                if action_of(step) != "actions/upload-artifact":
                    continue
                up = step.get("with") or {}
                path = render(up.get("path", ""), {"runner.temp": "$RUNNER_TEMP"})
                uploads.append((job, up.get("name"), path, up.get("if-no-files-found")))
        missing = [f"{script} (line {line}) reads {member} of the artifact {artifact}"
                   for script, line, artifact, member in readers
                   if not any(artifact and member and name == artifact and path.endswith(f"/{member}")
                              and flag == "error" for _, name, path, flag in uploads)]
        self.assertEqual(missing, [], f"the readers of a Build run's artifact whose artifact or file {self.BUILD} does "
                                      f"not upload. Its uploads, each as (the job, the artifact, the path, "
                                      f"if-no-files-found): {uploads}")
        return readers, uploads

    def test_artifacts_each_reader_reads_a_file_that_build_yaml_uploads(self):
        self.case()

    def test_control_artifacts_build_results_renamed_in_build_yaml_alone(self):
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(self.BUILD, "name: build-results\n", "name: build-output\n")])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("take-build-results (line ", str(caught.exception))
        self.assertNotIn("enroll-dispatch (line ", str(caught.exception))

    def test_control_artifacts_results_json_renamed_in_build_yaml_alone(self):
        # The results job writes build.json and uploads it. build.yaml stays whole, but take-build-results reads
        # results.json.
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [
            (self.BUILD, "path: ${{ runner.temp }}/results/results.json",
             "path: ${{ runner.temp }}/results/build.json"),
            (self.BUILD, '> "$RUNNER_TEMP/results/results.json"', '> "$RUNNER_TEMP/results/build.json"')])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        self.assertIn("take-build-results (line ", str(caught.exception))
        self.assertNotIn("enroll-dispatch (line ", str(caught.exception))


class WorkflowRunNames(Stand):
    """(workflow_run): a workflow_run trigger names the workflows that it listens to by their name:, not by their file.
    A rename of one of them stops the trigger, and a second file with the same name starts it for the runs of that
    file too. No run fails either way. So each name in the workflows of a workflow_run trigger is the name of exactly
    one workflow file of .github/workflows."""

    # The files that listen to a workflow_run at the head.
    LISTENERS = {"enroll-dispatch.yml", "held-runs.yml", "review.yml", "toolchain-images-publish.yaml"}

    def case(self, tree=ROOT):
        """Each workflow file of `tree` with a workflow_run trigger, and each name in its workflows: exactly one
        workflow file there has that name. GitHub gives a file with no name: the name of its path. The message names
        each (listening file, name) that no file or more than one file has. Return the names that each listening file
        listens to, and the files of each name."""
        directory = tree / ".github" / "workflows"
        workflows = {path.name: parse(path.read_text())
                     for path in sorted(directory.iterdir()) if path.suffix in (".yml", ".yaml")}
        held = {}
        for file, workflow in workflows.items():
            held.setdefault(workflow.get("name") or f".github/workflows/{file}", []).append(file)
        listens = {file: list((triggers(workflow)["workflow_run"] or {}).get("workflows") or [])
                   for file, workflow in workflows.items() if "workflow_run" in triggers(workflow)}
        self.assertLessEqual(self.LISTENERS, set(listens),
                             f"the files of .github/workflows with workflow_run: {listens}")
        wrong = [f"{file} names no workflow in workflow_run" for file, names in listens.items() if not names]
        for file, names in listens.items():
            for name in names:
                files = held.get(name, [])
                if len(files) != 1:
                    wrong.append(f"{file} listens to {name!r}, the name of "
                                 + (f"{len(files)} files: {', '.join(files)}" if files else "no workflow file"))
        self.assertEqual(wrong, [], "the names of the workflow_run triggers that are not the name of exactly one "
                                    "workflow file:" + "".join(f"\n  {line}" for line in wrong)
                                    + f"\nThe files of each name: {held}")
        return listens, held

    def test_workflow_run_each_name_is_the_name_of_one_workflow_file(self):
        self.case()

    def test_control_workflow_run_tests_renamed_in_tests_yaml_alone(self):
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(".github/workflows/tests.yaml", 'name: "Tests"\n',
                                              'name: "Unit tests"\n')])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        for file in ("enroll-dispatch.yml", "held-runs.yml"):
            self.assertIn(f"{file} listens to 'Tests', the name of no workflow file", str(caught.exception))

    def test_control_workflow_run_a_second_file_named_build(self):
        # No file listens to Enroll dispatch, so only the name Build breaks: two files hold it.
        self.passes_unchanged(self.case)
        changed = self.copy_tree("changed", [(".github/workflows/enroll-dispatch.yml", "name: Enroll dispatch\n",
                                              "name: Build\n")])
        with self.assertRaises(AssertionError) as caught:
            self.case(changed)
        for file in ("held-runs.yml", "review.yml"):
            self.assertIn(f"{file} listens to 'Build', the name of 2 files: build.yaml, enroll-dispatch.yml",
                          str(caught.exception))
        self.assertNotIn("listens to 'Triage'", str(caught.exception))


class SteeringFiles(unittest.TestCase):
    """(u): the list of steering files."""

    # The patterns of .github/CODEOWNERS at commit 62081ee (#194), the last commit that changed them, in their order.
    CODEOWNERS_62081EE = (
        "/.github/", "/src/", "/infra/", "/seeds/", ".claude/", "CLAUDE*.md", "AGENTS*.md", "/.mcp.json", "/*.py",
        "/pytest.ini", "/.pytest.ini", "/pyproject.toml", "/uv.lock", "/.python-version", "/setup.cfg", "/tox.ini",
        "/review.md", "/review-change.md", "/review-issue.md", "/.claude/skills/write-to-maintainer/",
        "/.github/CODEOWNERS")

    def test_u_the_steering_files_are_the_last_owned_patterns_of_codeowners(self):
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
        # A line counts when either team owns it; each line of CODEOWNERS that names a team names both. The lines
        # with no team, which take the owner off some modules of src/, are not counted: they give no steering file.
        teams = {"@theorem-labs/engineering", "@theorem-labs/research"}
        owned = [line.split()[0] for line in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
                 if line.strip() and not line.startswith("#") and teams & set(line.split()[1:])]
        # The four patterns at the top give agent instructions and skills at any depth the same owners, and add no
        # steering file: AGENTS*.md and CLAUDE*.md already match each AGENTS.md and CLAUDE.md, and a skill that Claude
        # Code loads in the review job is under .claude/.
        self.assertEqual(owned, ["**/AGENTS.md", "**/CLAUDE.md", "**/SKILL.md", "skills/", *steering.STEERING])


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

    def case_first_in(self, tree):
        """case_first for the copy of enroll-dispatch in `tree` (load)."""
        self.case_first(self.load(tree))

    def test_control_w_gate_taken_out_of_decision(self):
        self.passes_unchanged(self.case_first_in)
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
        self.assertTrue(signing, "no job of review.yml signs in")
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
        self.passes_unchanged(self.case)

        def no_main_check(text):
            workflow = parse(text)
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


class HeldApproval(Stand):
    """d7: a run by hand of review.yml for a pull request whose runs GitHub holds, and the comment job's approval of
    them or its record of the hold; and a run by hand for a merged pull request whose run of enroll-merged.yml GitHub
    holds, and the comment job's replay of the merge. The screen's verdict is the screen job's output, given to
    run_graph of tests/test_outside_screen.py."""

    ROUTE = "An enrollment, a change or an issue"
    TRUST = "Whether the author and the account that started the run have write access"
    TOKEN = "Get the oss-verify App's token to approve the held runs or replay a merge"
    APPROVE = "Approve the held runs"
    REPLAY = "Replay the merge for Enroll dispatch"
    # The merge commit of pull request 7, once it is merged.
    MERGE = "c" * 40
    # The held runs that the API lists: (id, workflow file, head commit, head repository, head branch). 11 to 13 are
    # the pull request's, at HEAD. 21 is of another head, 22 of another repository, and 23 of another branch. GitHub
    # lists a held run with the status completed and the conclusion action_required, and the stand-ins do too.
    HELD = ((11, ".github/workflows/build.yaml", HEAD, FORK, BRANCH),
            (12, ".github/workflows/terms.yaml", HEAD, FORK, BRANCH),
            (13, ".github/workflows/validate.yaml", HEAD, FORK, BRANCH),
            (21, ".github/workflows/build.yaml", OTHER, FORK, BRANCH),
            (22, ".github/workflows/build.yaml", HEAD, "eve/oss-verify", BRANCH),
            (23, ".github/workflows/build.yaml", HEAD, FORK, "other"))
    # Controls: the verdict condition taken out of the approval step's condition, or out of approve-held. And route's
    # check of a run of enroll-merged.yml by its status alone, as before: GitHub never gives the status action_required.
    APPROVE_IF = ("APPROVE: ${{ needs.route.outputs.held == 'true' && needs.screen.result == 'success'"
                  " && needs.screen.outputs.verdict == 'clean' }}")
    APPROVE_IF_ANY = "APPROVE: ${{ needs.route.outputs.held == 'true' && needs.screen.result == 'success' }}"
    REFUSAL = '[ "${SCREEN_VERDICT:-}" = clean ] || fail "the screen\'s verdict is not clean: no run is approved."\n'
    HELD_MERGE = "&& $status == completed && $conclusion == action_required &&"
    STATUS_ALONE = "&& $status == action_required &&"
    POST = "Post the comment and record the verdict"
    # The holds of a held enrollment whose project the gather job took: (label, route's trust, the result of the screen
    # job, or None when it does not run, its verdict, and the title of the check run that records the hold).
    HOLDS = (("the screen held it", "screen", "success", "held", "The automated screen held this pull request."),
             ("the daily cap", "cap", None, None, "The daily cap of automated reviews held this pull request."),
             ("the screen failed", "screen", "failure", None, "The screen job failed."))

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
        # The oss-verify App's id: REVIEW_APP of .github/scripts/enroll-dispatch, which the comment job's step POST
        # writes as a number too. not_app_runs, check runs Enrollment review at HEAD: one of another App for pull
        # request 7, and one of the oss-verify App for pull request 8 at the same commit. enroll-dispatch counts neither
        # of them.
        app = self.review_app = int(re.search(r"^REVIEW_APP = ([0-9]+)$",
                                              (ROOT / ".github/scripts/enroll-dispatch").read_text(), re.M).group(1))
        self.not_app_runs = ({"id": 602, "name": "Enrollment review", "app": {"id": 1, "slug": "another-app"},
                              "external_id": PR, "status": "completed", "conclusion": "success"},
                             {"id": 603, "name": "Enrollment review", "app": {"id": app, "slug": "oss-verify"},
                              "external_id": "8", "status": "completed", "conclusion": "success"})

    def as_listed(self, record, run_id):
        """The check run `record`, as the API lists it: with the id `run_id`, by the oss-verify App."""
        return dict(record, id=run_id, app={"id": self.review_app, "slug": "oss-verify"})

    def verdict_run(self, run_id, **changed):
        """The oss-verify App's check run Enrollment review of pull request 7 at HEAD for a review that gave each check
        the verdict pass, but those of `changed`: what .github/scripts/review-verdict prints for those verdicts."""
        verdicts = json.dumps(dict(dict.fromkeys(self.check_ids(), "pass"), **changed))
        made = json.loads(subprocess.run([str(ROOT / ".github/scripts/review-verdict")],
                                         env={**self.env, "VERDICTS": verdicts, "REASONS": "{}", "HEAD_SHA": HEAD},
                                         check=True, capture_output=True, text=True).stdout)
        return self.as_listed({"name": "Enrollment review", "head_sha": HEAD, "external_id": PR, "status": "completed",
                               "conclusion": made["conclusion"],
                               "output": {"title": made["title"], "summary": made["summary"], "text": made["text"]}},
                              run_id)

    def held_runs(self, runs):
        self.serve(f"repos/{REPO}/actions/runs", {"workflow_runs": [
            {"id": i, "path": path, "event": "pull_request", "status": "completed", "conclusion": "action_required",
             "head_sha": sha, "head_repository": {"full_name": repository}, "head_branch": branch}
            for i, path, sha, repository, branch in runs]})
        for run in self.HELD:
            self.serve(f"repos/{REPO}/actions/runs/{run[0]}/approve", {})

    def route(self, actor, tree=ROOT):
        """route's two steps for gh workflow run review.yml -f pr=7 on main, started by `actor`, as review.yml in `tree`
        runs them: its outputs, and the log of its first step."""
        review = self.review if tree == ROOT else self.workflow(tree, "review.yml")
        ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "github.event_name": "workflow_dispatch",
               "github.ref": "refs/heads/main", "github.actor": actor, "github.run_id": "1000", "inputs.pr": PR}
        rc, log, decided = self.run_step(review, "route", self.ROUTE, ctx, tree, evaluate=self.tos.evaluate)
        self.assertEqual(rc, 0, log)
        ctx.update({f"steps.decide.outputs.{k}": v for k, v in decided.items()})
        trust = self.step(review, "route", self.TRUST)
        if not self.tos.evaluate(trust["if"], ctx):
            return decided, log
        rc, more, trusted = self.run_script(trust["run"], tree, **env_of(review, "route", trust, ctx,
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
                                                        self.POST)},
                         {self.TOKEN: True, self.APPROVE: True, "Label it review-held and say so": False,
                          self.POST: False})
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
        self.passes_unchanged(self.case_held_verdict)
        changed = self.copy_tree("changed", [(".github/workflows/review.yml", self.APPROVE_IF, self.APPROVE_IF_ANY)])
        with self.assertRaises(AssertionError) as caught:
            self.case_held_verdict(changed)
        self.assertIn("the approval of a head that the screen held", str(caught.exception))

    def test_held_control_verdict_refusal_taken_out_of_approve_held(self):
        self.passes_unchanged(self.case_held_verdict)
        changed = self.copy_tree("changed", [(".github/scripts/approve-held", self.REFUSAL, "")])
        with self.assertRaises(AssertionError) as caught:
            self.case_held_verdict(changed)
        self.assertIn("approve-held alone, for the verdict held", str(caught.exception))

    def hold_of_held_head(self, trust, screen, verdict, check_runs):
        """The comment job's step "Post the comment and record the verdict" on a run by hand for held enrollment 7 at
        HEAD, whose project x the gather job took: for route's `trust`, the screen job's result `screen` (None when it
        does not run) and its `verdict`. The check runs Enrollment review at HEAD are `check_runs`, or a read of them
        fails when it is None. Return the step's exit status, its log, its outputs, and the requests it sent that are
        not reads."""
        self.clear()
        self.pull_request(("projects/x/project.yaml", "projects/x/build.sh"))
        checks = f"repos/{REPO}/commits/{HEAD}/check-runs"
        if check_runs is None:
            self.serve_error(checks, "gh: Server Error (HTTP 500)")
        else:
            self.serve(checks, {"total_count": len(check_runs), "check_runs": list(check_runs)})
        self.serve(f"repos/{REPO}/check-runs", {"id": 1})
        route = {"kind": "enrollment", "pr": PR, "sha": HEAD, "author": "mallory", "held": "true", "trust": trust,
                 "free": "2026-11-20T00:00:00Z" if trust == "cap" else ""}
        outputs = {"gather": {"digest": "d" * 64, "screen": "true", "name": "x"}}
        if verdict is not None:
            outputs["screen"] = {"verdict": verdict, "checks": "claude"}
        got, ctx = self.tos.run_graph(route, results={"screen": screen} if screen else {}, outputs=outputs,
                                      event="workflow_dispatch", workflow=self.review, ref="refs/heads/main")
        self.assertEqual((got["screen"], got["review"], got["comment"]), (screen or "skipped", "skipped", "success"))
        env = self.comment_env(ctx)
        self.assertEqual((env["RECORD"], env["HOLDING"], env["APPROVE"]), ("true", "true", "false"))
        self.assertTrue(self.ran(self.POST, env))
        ctx = dict(ctx, **{"github.token": WORKFLOW_TOKEN, "github.repository": REPO,
                           "github.server_url": "https://github.com", "github.run_id": "1000",
                           "steps.app.outputs.token": APP_TOKEN})
        since = len(self.calls())
        rc, log, out = self.run_step(self.review, "comment", self.POST, ctx, ROOT, evaluate=self.tos.evaluate)
        requests = self.requests(since)
        self.assertEqual({r["token"] for r in requests}, {APP_TOKEN}, log)
        return rc, log, out, [r for r in requests if r["method"] != "GET"]

    def recorded(self, trust, screen, verdict):
        """The check run that the step records for that hold when the oss-verify App has no check run Enrollment
        review of pull request 7 at HEAD: the body of its request."""
        rc, log, out, sent = self.hold_of_held_head(trust, screen, verdict, self.not_app_runs)
        self.assertEqual((rc, out, [(r["method"], r["endpoint"]) for r in sent]),
                         (0, {"recorded": "true"}, [("POST", f"repos/{REPO}/check-runs")]), log)
        return sent[0]["body"]

    def test_held_a_hold_of_a_held_head_replaces_no_verdict_of_the_review_at_that_head(self):
        """On a run by hand for a held head, the screen decides only whether the comment job approves the held runs: it
        does not change the review's verdict. The oss-verify App's newest check run Enrollment review of pull request
        7 at HEAD records a verdict of the review: of a review that passed, or of one that left a check to a person,
        whose conclusion action_required a hold has too. Then a hold of the held path (the screen held it, the daily
        cap, or a screen that failed) records nothing and posts nothing, so Enroll dispatch still reads that verdict.
        With no check run of the App for the pull request, the hold is recorded as off the held path."""
        verdicts = {"passed": self.verdict_run(601), "a person's check": self.verdict_run(601, A1="person")}
        self.assertEqual({k: run["conclusion"] for k, run in verdicts.items()},
                         {"passed": "success", "a person's check": "action_required"})
        for label, trust, screen, verdict, title in self.HOLDS:
            for kind, run in verdicts.items():
                with self.subTest(label, verdict=kind):
                    rc, log, out, sent = self.hold_of_held_head(trust, screen, verdict, (*self.not_app_runs, run))
                    self.assertEqual((rc, out, sent), (0, {}, []), f"the hold replaces the App's verdict: {log}")
            with self.subTest(label):
                body = self.recorded(trust, screen, verdict)
                self.assertEqual((body["name"], body["head_sha"], body["external_id"], body["conclusion"],
                                  body["output"]["title"]), ("Enrollment review", HEAD, PR, "action_required", title))
        # A read of the check runs that fails fails the step, which records nothing and posts nothing.
        rc, log, out, sent = self.hold_of_held_head("screen", "success", "held", None)
        self.assertEqual((rc != 0, out, sent), (True, {}, []), log)

    def test_held_a_hold_of_a_held_head_replaces_an_earlier_hold_at_that_head(self):
        """The oss-verify App's newest check run Enrollment review of pull request 7 at HEAD records an earlier hold, as
        the step recorded it: of the screen, of the daily cap, or of a job that failed (the screen job). A hold gives
        no verdict of the review. Then a hold of the screen records the check run that it records when the App has no
        check run of the pull request, with the title of the screen's hold. After a hold of the screen, it records the
        same check run again."""
        screen_hold = self.HOLDS[0][1:4]
        alone = self.recorded(*screen_hold)
        for label, trust, screen, verdict, title in self.HOLDS:
            with self.subTest(label):
                hold = (trust, screen, verdict)
                earlier = self.as_listed(alone if hold == screen_hold else self.recorded(*hold), 604)
                self.assertEqual(earlier["output"]["title"], title)
                rc, log, out, sent = self.hold_of_held_head(*screen_hold, (*self.not_app_runs, earlier))
                self.assertEqual((rc, out), (0, {"recorded": "true"}), f"the earlier hold stands: {log}")
                self.assertEqual([(r["method"], r["endpoint"], r["body"]) for r in sent],
                                 [("POST", f"repos/{REPO}/check-runs", alone)], log)

    def test_held_the_newest_check_run_of_the_app_at_a_held_head_decides(self):
        """The oss-verify App recorded two check runs Enrollment review of pull request 7 at HEAD: the verdict of a
        review that passed, and a hold of the daily cap. The newest, the one with the larger id, decides, in whatever
        order the API lists them. When the hold is newer, a hold of the screen replaces it. When the verdict is newer,
        the verdict stands."""
        cap = self.recorded(*self.HOLDS[1][1:4])
        for label, verdict_id, hold_id, replaced in (("the hold is newer", 601, 604, True),
                                                     ("the verdict is newer", 605, 604, False)):
            with self.subTest(label):
                runs = (self.verdict_run(verdict_id), self.as_listed(cap, hold_id), *self.not_app_runs)
                rc, log, out, sent = self.hold_of_held_head(*self.HOLDS[0][1:4], runs)
                if replaced:
                    self.assertEqual((rc, out), (0, {"recorded": "true"}), f"the newer hold stands: {log}")
                    self.assertEqual([(r["method"], r["endpoint"], r["body"]) for r in sent],
                                     [("POST", f"repos/{REPO}/check-runs", self.recorded(*self.HOLDS[0][1:4]))], log)
                else:
                    self.assertEqual((rc, out, sent), (0, {}, []), f"the hold replaces the newer verdict: {log}")

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

    def test_held_a_persons_run_by_hand_at_a_head_held_only_by_the_apps_label_reviews_with_its_build_run(self):
        """The oss-verify App put one of its labels on enrollment 7, and that label started a run of Maintainer
        confirmed at head HEAD, with the App as its actor. GitHub holds that run, but it is no new event at the head,
        and Held runs does not count it. alice starts the review again by hand (gh workflow run review.yml -f pr=7).
        route finds no held head, and gives the enrollment the newest completed Build run of the head that wrote
        results, so the review runs with those results."""
        self.pull_request(("projects/x/project.yaml", "projects/x/build.sh"))
        self.serve(f"repos/{REPO}/actions/runs", {"workflow_runs": [
            {"id": 14, "path": ".github/workflows/maintainer-confirmed.yml", "event": "pull_request",
             "status": "completed", "conclusion": "action_required", "head_sha": HEAD,
             "head_repository": {"full_name": FORK}, "head_branch": BRANCH, "actor": {"login": "oss-verify[bot]"}}]})
        # The completed Build runs of the head: 43 wrote no results, and 42 and 41 wrote results.
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [
            {"id": i, "path": ".github/workflows/build.yaml", "event": "pull_request", "status": "completed",
             "head_sha": HEAD, "head_repository": {"full_name": FORK}, "head_branch": BRANCH} for i in (41, 43, 42)]})
        for i, wrote in ((41, True), (42, True), (43, False)):
            self.serve(f"repos/{REPO}/actions/runs/{i}/artifacts", {"artifacts": [
                {"id": i * 10, "name": "build-results", "expired": False}] if wrote else []})
        route, log = self.route("alice")
        self.assertEqual({k: route.get(k) for k in ("kind", "held", "build_run", "trust")},
                         {"kind": "enrollment", "held": None, "build_run": "42", "trust": "screen"}, log)
        self.assertIn("The review reads the results of Build run 42.", log)
        got, ctx = self.graph(route, "clean", gather={"digest": "d" * 64, "screen": "true", "name": "x"})
        self.assertEqual((got["gather"], got["screen"], got["review"]), ("success", "success", "success"))
        # The gather job takes the results of Build run 42, which the review reads.
        take = self.step(self.review, "gather", "Take the results of the Build run")
        ctx.update({f"needs.route.outputs.{k}": v for k, v in route.items()})
        ctx.update({"steps.project.outputs.kind": "enrollment", "steps.project.outputs.name": "x"})
        self.assertTrue(self.tos.evaluate(take["if"], ctx))
        self.assertEqual(env_of(self.review, "gather", take, ctx, evaluate=self.tos.evaluate)["BUILD_RUN"], "42")

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

    @staticmethod
    def merge_run(run_id, sha, repository=FORK, branch=BRANCH, conclusion="action_required"):
        """A run of enroll-merged.yml on pull_request at `sha`, as GitHub lists it: completed, with `conclusion`. GitHub
        holds the run when its conclusion is action_required."""
        return {"id": run_id, "path": ".github/workflows/enroll-merged.yml", "event": "pull_request",
                "status": "completed", "conclusion": conclusion, "head_sha": sha,
                "head_repository": {"full_name": repository}, "head_branch": branch}

    def merged(self, held, merged=True):
        """Pull request 7 of mallory's fork at HEAD, closed, and with `merged` merged into main at MERGE, and the runs of
        enroll-merged.yml that GitHub holds: `held`, each (id, head commit, head repository, head branch)."""
        pull = self.pull_request(("projects/x/project.yaml", "projects/x/build.sh"))
        pull.update(state="closed", merged=merged, merge_commit_sha=self.MERGE)
        self.serve(f"repos/{REPO}/pulls/{PR}", pull)
        self.serve(f"repos/{REPO}/actions/workflows/enroll-merged.yml/runs",
                   {"workflow_runs": [self.merge_run(*run) for run in held]})

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

    def case_merge_run_as_github_lists_it(self, tree):
        """Merged pull request 7 and its runs of enroll-merged.yml, as GitHub lists them: run 36 at HEAD completed with
        the conclusion success (GitHub did not hold it), and run 37 at MERGE completed with the conclusion
        action_required (GitHub holds it). The stand-in gh lists both runs, whatever the filter status=action_required.
        route of review.yml in `tree` replays the merge for run 37."""
        self.clear()
        self.merged([])
        self.serve(f"repos/{REPO}/actions/workflows/enroll-merged.yml/runs", {"workflow_runs": [
            self.merge_run(36, HEAD, conclusion="success"), self.merge_run(37, self.MERGE)]})
        route, log = self.route("github-actions[bot]", tree)
        self.assertEqual(route, {"pr": PR, "sha": HEAD, "author": "mallory", "replay": "true"},
                         f"route's replay of a merge whose run GitHub holds: {log}")
        self.assertIn(f"GitHub holds run 37 of enroll-merged.yml at {self.MERGE}", log)

    def test_held_a_merge_run_completed_with_the_conclusion_action_required_is_replayed(self):
        self.case_merge_run_as_github_lists_it(ROOT)

    def test_held_control_route_checks_a_merge_run_by_its_status_alone(self):
        self.passes_unchanged(self.case_merge_run_as_github_lists_it)
        changed = self.copy_tree("changed", [(".github/workflows/review.yml", self.HELD_MERGE, self.STATUS_ALONE)])
        with self.assertRaises(AssertionError) as caught:
            self.case_merge_run_as_github_lists_it(changed)
        self.assertIn("route's replay of a merge whose run GitHub holds", str(caught.exception))

    def test_held_the_comment_job_makes_a_token_of_its_own_for_the_approval(self):
        steps = self.review["jobs"]["comment"]["steps"]
        app = self.step(self.review, "comment", "Get the oss-verify App's token")
        token = self.step(self.review, "comment", self.TOKEN)

        def permissions(step):
            return {k: v for k, v in step["with"].items() if k.startswith("permission-")}

        for step in (app, token):
            self.assertTrue(step["uses"].startswith("actions/create-github-app-token@"), step)
        self.assertNotIn("permission-actions", permissions(app))
        self.assertEqual(permissions(token), {"permission-actions": "write"})
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
        self.passes_unchanged(self.case_no_token)
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
        """A held run, as GitHub lists it: completed, with the conclusion action_required."""
        return {"id": run_id, "path": path, "event": "pull_request", "status": "completed",
                "conclusion": "action_required", "head_sha": sha, "head_repository": {"full_name": repository},
                "head_branch": branch, "created_at": ago(minutes)}

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

    def go(self, refused=(), status=0, broken=None):
        """One run of the step: the runs it started, as the arguments of gh, then the runs whose failed jobs it re-ran
        or tried to re-run (reruns). `refused`: the runs whose re-run GitHub refuses. The stand-in serves no answer for
        those, so gh prints gh: Not Found (HTTP 404), as on GitHub's refusal. `broken`: for each run in it, what gh
        prints when GitHub answers the re-run of the run with HTTP 5xx, or gives no answer. `status`: the step's exit
        status. self.reads gets the filter created of each read of a list (None when the read has none): of the held
        runs (held), and of the runs by hand of each file. self.bounds gets the bound of the reads of each file."""
        broken = broken or {}
        for path in [*self.api.glob("*.json"), *self.api.glob("*.error")]:
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
            if run["id"] not in refused and run["id"] not in broken:
                self.serve(f"repos/{REPO}/actions/runs/{run['id']}/rerun-failed-jobs", {})
        for run_id, printed in broken.items():
            self.serve_error(f"repos/{REPO}/actions/runs/{run_id}/rerun-failed-jobs", printed)
        since = len(self.calls())
        workflow = parse(self.workflow_text)
        before = datetime.datetime.now(datetime.timezone.utc)
        rc, log, _ = self.run_step(workflow, "held-runs", self.STEP,
                                   {"github.token": WORKFLOW_TOKEN, "github.repository": REPO}, self.temp)
        after = datetime.datetime.now(datetime.timezone.utc)
        self.assertEqual(rc, status, log)
        stamp = "%Y-%m-%dT%H:%M:%SZ"
        low, high = ((moment - datetime.timedelta(hours=3)).strftime(stamp) for moment in (before, after))
        month = [(moment - datetime.timedelta(days=30)).strftime(stamp) for moment in (before, after)]
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
        # The reads of the lists. The first read of the held runs has no filter created. The first read of the runs by
        # hand of a file asks for the runs created from the bound of the pass: three hours before now, or the newest
        # held run of a head (of a merged head, its newest held run of enroll-merged.yml) when that is earlier. The
        # stand-in cuts a read at 1,000 runs, as GitHub does. After a cut read, the next read of the list asks for the
        # runs created from its bound (for the held runs, 30 days before now) to the oldest run that the cut read gave.
        # The last read of each list gives fewer than 1,000 runs, so the step loses no run of the list.
        held = {run["created_at"] for run in self.held}
        self.reads, self.bounds = {}, {}
        for r in self.requests(since):
            endpoint = r["endpoint"] or ""
            if endpoint.startswith(f"repos/{REPO}/actions/runs?"):
                name = "held"
            elif "/runs?event=workflow_dispatch" in endpoint:
                name = re.search(r"/workflows/([^/]+)/runs", endpoint).group(1)
            else:
                continue
            created = [a.removeprefix("created=") for a in r["args"] if a.startswith("created=")]
            self.assertLessEqual(len(created), 1, r["args"])
            self.reads.setdefault(name, []).append(created[0] if created else None)
        for name, reads in self.reads.items():
            runs = {"held": self.held, "review.yml": self.reviews, "enroll-merged.yml": self.replays}[name]
            if name == "held":
                self.assertIsNone(reads[0], reads)
            else:
                self.assertTrue((reads[0] or "").startswith(">="), reads)
                bound = self.bounds[name] = reads[0][2:]
                self.assertRegex(bound, r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
                self.assertTrue(low <= bound <= high or (bound in held and bound < low), (bound, low, high))
            gave = self.given(runs, reads[0])
            for created in reads[1:]:
                self.assertEqual(len(gave), 1000, (name, reads))
                start, _, end = (created or "").partition("..")
                if name == "held":
                    self.assertTrue(month[0] <= start <= month[1], (created, month))
                else:
                    self.assertEqual(start, bound, reads)
                self.assertEqual(end, min(run["created_at"] for run in gave), reads)
                gave = self.given(runs, created)
            self.assertLess(len(gave), 1000, (name, reads))
        started = [(token, " ".join(args)) for token, args in calls if args[:2] == ["workflow", "run"]]
        self.assertEqual({token for token, _ in started} - {WORKFLOW_TOKEN}, set())
        self.log = log
        return [run for _, run in started] + reran

    @staticmethod
    def given(runs, created):
        """The runs of a list that a read with the filter created gives (None: no filter), as the stand-in gives them:
        the runs created in its range, at most the first 1,000."""
        if created is None:
            kept = runs
        elif created.startswith(">="):
            kept = [run for run in runs if run["created_at"] >= created[2:]]
        else:
            low, high = created.split("..")
            kept = [run for run in runs if low <= run["created_at"] <= high]
        return kept[:1000]

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
        # The next event, 15 minutes after a start: the run it started ended before a verdict too.
        self.reviews = [self.by_hand(942, "Pull request 51", 15, conclusion="failure"),
                        self.by_hand(941, "Pull request 51", 105, conclusion="failure")]
        self.jobs = {941: "failure", 942: "failure"}
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_a_run_that_failed_after_a_screen_that_passed_reruns_its_failed_jobs_at_most_once_an_hour(self):
        sha = "7" * 40
        # Its job screen succeeded, and then its comment job failed: it could not sign in, or GitHub refused the
        # approval (the App's installation has not accepted actions: write).
        for failed in ("Sign in to Google Cloud",
                       "Get the oss-verify App's token to approve the held runs or replay a merge"):
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
        # The next event, while the re-run runs: nothing. Then the re-run failed too, 15 minutes after its start:
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

    def test_held_runs_a_held_merge_run_starts_review_yml_at_most_once_an_hour_until_the_replay(self):
        # review.yml replays the merge with the oss-verify App's token: a run that the job's own token starts starts no
        # workflow_run when it completes, so the step starts review.yml, never enroll-merged.yml.
        merged = ".github/workflows/enroll-merged.yml"
        h71, m71, h72, m72 = "c" * 40, "d" * 40, "e" * 40, "f" * 40
        self.pulls = [self.pull(71, "hal/oss-verify", "p71", h71, state="closed", merged=True, merge=m71),
                      self.pull(72, "ivy/oss-verify", "p72", h72, state="closed", merged=True, merge=m72)]
        def held(minutes):
            """71 held at its head commit `minutes` ago, and 72 at its merge commit 10 minutes later."""
            self.held = [self.held_run(7101, h71, "hal/oss-verify", "p71", minutes, merged),
                         self.held_run(7201, m72, "ivy/oss-verify", "p72", minutes - 10, merged)]
        held(120)
        # The replay of 72 before its held run is not its replay.
        self.replays = [self.by_hand(7998, "merged #72", 600)]
        both = [self.starts("review.yml", 71), self.starts("review.yml", 72)]
        self.assertEqual(self.go(), both, self.log)
        # The next events, while the runs it started are queued, then in progress: nothing.
        for status in ("queued", "in_progress"):
            self.reviews = [self.by_hand(8102, "Pull request 72", 0, status=status),
                            self.by_hand(8101, "Pull request 71", 0, status=status)]
            self.assertEqual(self.go(), [], (status, self.log))
        # They ended with no replay (their comment job failed, say): nothing in the hour after each run, then a start.
        for minutes, again in ((40, False), (70, True)):
            self.reviews = [self.by_hand(8102, "Pull request 72", minutes, conclusion="failure"),
                            self.by_hand(8101, "Pull request 71", minutes, conclusion="failure")]
            self.assertEqual(self.go(), both if again else [], (minutes, self.log))
        # A run less than an hour old that came before the held run does not make the head wait.
        held(30)
        self.reviews = [self.by_hand(8102, "Pull request 72", 25), self.by_hand(8101, "Pull request 71", 35)]
        self.assertEqual(self.go(), both, self.log)
        # A replay of each after its held run: nothing, whatever the runs of review.yml did.
        held(120)
        self.reviews = [self.by_hand(8102, "Pull request 72", 20, conclusion="failure")]
        self.replays = [self.by_hand(8002, "merged #72", 0, status="queued"),
                        self.by_hand(8001, "merged #71", 30)] + self.replays
        self.assertEqual(self.go(), [], self.log)
        self.assertIn("Run 8001 of enroll-merged.yml replayed the merge after the held run.", self.log)
        # A merge held at its head commit and at its merge commit: one start for the pull request.
        self.pulls, self.reviews, self.replays = [self.pulls[0]], [], []
        self.held = [self.held_run(7102, m71, "hal/oss-verify", "p71", 40, merged), self.held[0]]
        self.assertEqual(self.go(), [self.starts("review.yml", 71)], self.log)
        self.assertIn("This run started review.yml for the pull request already.", self.log)

    def test_held_runs_a_held_run_at_a_head_the_pull_request_no_longer_has_gets_nothing(self):
        self.pulls = [self.pull(91, "max/oss-verify", "q", "0" * 40)]
        self.held = [self.held_run(9101, "1" * 40, "max/oss-verify", "q", 30)]
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_and_route_count_the_same_held_runs(self):
        # Neither route (review.yml) nor Held runs counts a held run of Maintainer confirmed whose actor is the
        # oss-verify App: the App's own label started it. Each set of held runs of head HEAD of pull request 7 goes to
        # both. Held runs starts the screen of the head exactly when route finds the head held on that run by hand.
        confirmed = ".github/workflows/maintainer-confirmed.yml"
        runs = {"the App's label": (4201, confirmed, "oss-verify[bot]"),
                "a person's label": (4202, confirmed, "sjawhar"),
                "a run of another workflow": (4203, ".github/workflows/build.yaml", "mallory")}
        review = self.workflow(ROOT, "review.yml")
        ctx = {"github.token": WORKFLOW_TOKEN, "github.repository": REPO, "github.event_name": "workflow_dispatch",
               "github.ref": "refs/heads/main", "github.actor": "github-actions[bot]", "github.run_id": "1000",
               "inputs.pr": PR}
        for chosen in (c for n in range(1, len(runs) + 1) for c in itertools.combinations(runs, n)):
            self.pulls, self.held = [self.pull(int(PR), FORK, BRANCH, HEAD)], []
            for name in chosen:
                run_id, path, actor = runs[name]
                self.held.append(dict(self.held_run(run_id, HEAD, FORK, BRANCH, 30, path), actor={"login": actor}))
            started = self.go()
            self.assertIn(started, ([], [self.starts("review.yml", PR)]), (chosen, self.log))
            # route reads the held runs that go() served, and the pull request.
            self.pull_request(("README.md",))
            rc, log, decided = self.run_step(review, "route", "An enrollment, a change or an issue", ctx, ROOT)
            self.assertEqual(rc, 0, log)
            counted = chosen != ("the App's label",)
            self.assertEqual((decided.get("held") == "true", started != []), (counted, counted),
                             f"route's held, and whether Held runs started the head ({chosen}): {log}{self.log}")

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
        # GitHub refuses (HTTP 4xx) a re-run of a run that started more than 30 days ago. A 51st re-run gets no
        # refusal but a failed check suite, so Held runs reads that limit from run_attempt (the test of a run at the
        # limit, below):
        # https://github.blog/changelog/2026-04-10-actions-workflows-are-limited-to-50-reruns/
        # Pull request 301 is due a re-run of run 971 (its screen gave a verdict, its comment job failed, its latest
        # attempt started 70 minutes ago), and GitHub refuses it. Pull request 302, held before 301, was never
        # screened. The refusal of one head's re-run does not keep the other head from its screen.
        p, q = "7" * 40, "2" * 40
        self.pulls = [self.pull(301, "pat/oss-verify", "s", p), self.pull(302, "rob/oss-verify", "u", q)]
        self.held = [self.held_run(30101, p, "pat/oss-verify", "s", 200),
                     self.held_run(30201, q, "rob/oss-verify", "u", 300)]
        self.reviews = [self.by_hand(971, "Pull request 301", 190, conclusion="failure", started=70)]
        self.jobs, self.comment = {971: "success"}, {971: "Sign in to Google Cloud"}
        self.assertIn(self.starts("review.yml", 302), self.go(refused={971}), self.log)

    def test_held_runs_a_rerun_that_github_refuses_starts_a_new_run_of_that_head(self):
        # The refusal is no failure of the step: a new run screens the head again, and the next event waits for it.
        sha = "7" * 40
        self.pulls = [self.pull(121, "pat/oss-verify", "s", sha)]
        self.held = [self.held_run(12101, sha, "pat/oss-verify", "s", 180)]
        self.reviews = [self.by_hand(971, "Pull request 121", 150, conclusion="failure", started=70)]
        self.jobs, self.comment = {971: "success"}, {971: "Sign in to Google Cloud"}
        self.assertEqual(self.go(refused={971}), [self.starts("review.yml", 121), self.reruns(971)], self.log)
        self.assertIn("GitHub refused the re-run of the failed jobs of run 971 of review.yml", self.log)
        self.assertIn("so a new run screens the head again.", self.log)
        self.reviews.insert(0, self.by_hand(972, "Pull request 121", 0, status="queued"))
        self.assertEqual(self.go(refused={971}), [], self.log)
        # An answer of HTTP 4xx with no message: gh prints gh: HTTP <status>. It is a refusal too.
        self.reviews = [self.by_hand(971, "Pull request 121", 150, conclusion="failure", started=70)]
        self.assertEqual(self.go(broken={971: "gh: HTTP 403"}), [self.starts("review.yml", 121), self.reruns(971)],
                         self.log)
        self.assertIn("so a new run screens the head again.", self.log)

    def test_held_runs_a_run_at_githubs_limit_of_50_reruns_gets_a_new_run_and_no_rerun(self):
        # GitHub runs no 51st re-run of a run: "if you attempt to rerun a given workflow more than 50 times, you will
        # get a failed check suite with an annotation indicating you have hit the limit"
        # (https://github.blog/changelog/2026-04-10-actions-workflows-are-limited-to-50-reruns/). That is no answer of
        # HTTP 4xx to rerun-failed-jobs: the stand-in answers it with 201, as for any re-run. A run at attempt 51 has had
        # its 50 re-runs, so the head gets a new run, which screens it again (R2), and no re-run that cannot run. A run
        # at attempt 50 still gets its re-run.
        sha = "7" * 40
        for attempt, again in ((50, [self.reruns(971)]), (51, [self.starts("review.yml", 121)])):
            self.pulls = [self.pull(121, "pat/oss-verify", "s", sha)]
            self.held = [self.held_run(12101, sha, "pat/oss-verify", "s", 180)]
            run = self.by_hand(971, "Pull request 121", 150, conclusion="failure", started=70)
            run["run_attempt"] = attempt
            self.reviews = [run]
            self.jobs, self.comment = {971: "success"}, {971: "Sign in to Google Cloud"}
            self.assertEqual(self.go(), again, (attempt, self.log))

    def test_held_runs_a_rerun_that_github_does_not_answer_starts_no_run_and_fails_the_step(self):
        # Only an answer of HTTP 4xx is GitHub's refusal of a re-run. Pull request 301 is due a re-run of run 971, and
        # GitHub answers it with HTTP 500, or gives no answer. The step starts no new run of 301, which would screen it
        # again. The line of that head says that GitHub gave no answer, pull request 302 still gets its screen, and the
        # step fails at its end. The next event re-runs the failed jobs of run 971.
        p, q = "7" * 40, "2" * 40
        for label, printed in (("HTTP 500", "gh: Server Error (HTTP 500)"),
                               ("no answer", "error connecting to api.github.com\n"
                                             "check your internet connection or https://githubstatus.com")):
            self.pulls = [self.pull(301, "pat/oss-verify", "s", p), self.pull(302, "rob/oss-verify", "u", q)]
            self.held = [self.held_run(30101, p, "pat/oss-verify", "s", 200),
                         self.held_run(30201, q, "rob/oss-verify", "u", 300)]
            self.reviews = [self.by_hand(971, "Pull request 301", 190, conclusion="failure", started=70)]
            self.jobs, self.comment = {971: "success"}, {971: "Sign in to Google Cloud"}
            self.assertEqual(self.go(status=1, broken={971: printed}),
                             [self.starts("review.yml", 302), self.reruns(971)], (label, self.log))
            self.assertIn("Head 7777777 of pat/oss-verify:s, pull request 301: failed. GitHub gave no answer to the "
                          "re-run of the failed jobs of run 971 of review.yml. The step goes on to the next head, and "
                          "fails at its end.", self.log)
            # The next event, when GitHub answers: the run that the step started for 302 is queued.
            self.reviews.insert(0, self.by_hand(3021, "Pull request 302", 0, status="queued"))
            self.assertEqual(self.go(), [self.reruns(971)], (label, self.log))

    def test_held_runs_a_read_that_fails_for_one_head_leaves_the_other_heads_their_screen(self):
        # GitHub gives no jobs of run 991, so the step cannot tell whether it screened pull request 151. The line of
        # that head says so, pull request 152, held before 151, still gets its screen, and the step fails at its end:
        # the run is red, and the next event reads that head again.
        a, b = "1" * 40, "2" * 40
        self.pulls = [self.pull(151, "uma/oss-verify", "v", a), self.pull(152, "val/oss-verify", "w", b)]
        self.held = [self.held_run(15101, a, "uma/oss-verify", "v", 100),
                     self.held_run(15201, b, "val/oss-verify", "w", 120)]
        self.reviews = [self.by_hand(991, "Pull request 151", 60)]
        self.assertEqual(self.go(status=1), [self.starts("review.yml", 152)], self.log)
        self.assertIn("Head 1111111 of uma/oss-verify:v, pull request 151: failed. GitHub gave no jobs of run 991 of "
                      "review.yml. The step goes on to the next head, and fails at its end.", self.log)
        # The next event, when GitHub gives them: run 991 counts, the run that the step started is queued, and the
        # step ends with no failure.
        self.jobs = {991: "success"}
        self.reviews.insert(0, self.by_hand(992, "Pull request 152", 0, status="queued"))
        self.assertEqual(self.go(), [], self.log)

    def test_held_runs_reads_each_file_once_and_each_head_decides_from_its_own_bound(self):
        # The step reads the runs by hand of each file once, from the earliest bound of a head: the held run of
        # enroll-merged.yml of merged pull request 144 five days ago, not its newer held run of Terms. The bound of a
        # head is the earlier of its newest held run and three hours before now, and the head decides only from the
        # runs created at or after it. Pull request 141, held two days ago, finds the run that screened it. Run 9142 of
        # pull request 142, held 20 minutes ago, is queued, and came before three hours before now: it does not make
        # 142 wait.
        merged = ".github/workflows/enroll-merged.yml"
        a, b, c, h, m = "3" * 40, "4" * 40, "5" * 40, "6" * 40, "7" * 40
        self.pulls = [self.pull(141, "wes/oss-verify", "x", a), self.pull(142, "xia/oss-verify", "y", b),
                      self.pull(143, "yan/oss-verify", "z", c),
                      self.pull(144, "zed/oss-verify", "m", h, state="closed", merged=True, merge=m)]
        self.held = [self.held_run(14201, b, "xia/oss-verify", "y", 20),
                     self.held_run(14301, c, "yan/oss-verify", "z", 30),
                     self.held_run(14402, h, "zed/oss-verify", "m", 60, ".github/workflows/terms.yaml"),
                     self.held_run(14101, a, "wes/oss-verify", "x", 2880),
                     self.held_run(14401, h, "zed/oss-verify", "m", 7200, merged)]
        self.reviews = [self.by_hand(9143, "Pull request 143", 25),
                        self.by_hand(9142, "Pull request 142", 200, status="queued"),
                        self.by_hand(9141, "Pull request 141", 2870)]
        self.jobs = {9141: "success", 9143: "success"}
        self.assertEqual(self.go(), [self.starts("review.yml", 142), self.starts("review.yml", 144)], self.log)
        held = {run["id"]: run["created_at"] for run in self.held}
        self.assertEqual(self.bounds, {"review.yml": held[14401], "enroll-merged.yml": held[14401]})
        self.assertEqual(self.reads["review.yml"], [f">={held[14401]}"])

    def test_held_runs_reads_the_runs_by_hand_past_githubs_cut_at_1000_runs(self):
        # Run 9161 screened pull request 161 after its held run two days ago, and 1,050 runs by hand of other pull
        # requests came after it. The first read of review.yml gives the newest 1,000 runs: the stand-in cuts as GitHub
        # does. The step reads the older runs too, finds run 9161, and leaves the head.
        sha = "6" * 40
        self.pulls = [self.pull(161, "ann/oss-verify", "k", sha)]
        self.held = [self.held_run(16101, sha, "ann/oss-verify", "k", 2880)]
        self.reviews = [self.by_hand(20000 + n, f"Pull request {1000 + n}", n) for n in range(1, 1051)]
        self.reviews.append(self.by_hand(9161, "Pull request 161", 2870))
        self.jobs = {9161: "success"}
        self.assertEqual(self.go(), [], self.log)
        self.assertIn("Run 9161 of review.yml screened the head after its newest held run, and ended success.", self.log)
        self.assertEqual(len(self.reads["review.yml"]), 2, self.reads)

    def test_held_runs_reads_the_held_runs_past_githubs_cut_at_1000_runs(self):
        # 1,050 held runs of the head of pull request 171 came after the one held run of pull request 172, which no run
        # screened. The first read of the held runs gives the newest 1,000: the stand-in cuts as GitHub does. The step
        # reads the older held runs too, from 30 days before now, and starts the screen of each head.
        a, b = "1" * 40, "2" * 40
        self.pulls = [self.pull(171, "bea/oss-verify", "n", a), self.pull(172, "cy/oss-verify", "o", b)]
        self.held = [self.held_run(170000 + n, a, "bea/oss-verify", "n", n) for n in range(1, 1051)]
        self.held.append(self.held_run(17201, b, "cy/oss-verify", "o", 1100))
        self.assertEqual(self.go(), [self.starts("review.yml", 171), self.starts("review.yml", 172)], self.log)
        self.assertEqual(len(self.reads["held"]), 2, self.reads)

    def test_held_runs_workflow_holds_no_identity_and_runs_by_hand_on_main_alone(self):
        # It holds no secret and no identity, and its token can do no more than the step needs: start and re-run runs
        # (actions: write) and read pull requests (pull-requests: read). Its job runs on each event of its triggers,
        # and on a run by hand only on main.
        import test_outside_screen
        workflow = parse(self.workflow_text)
        jobs = workflow["jobs"]
        allowed = {("actions", "write"), ("actions", "read"), ("pull-requests", "read")}
        for name, held in jobs.items():
            self.assertNotIn("environment", held, name)
            # A job's token has the job's permissions, else the workflow's, else the repository's default, which can
            # write every scope. read-all and write-all give each scope.
            granted = held.get("permissions", workflow.get("permissions", "write-all"))
            if isinstance(granted, str):
                granted = {"each scope": granted.removesuffix("-all")}
            self.assertEqual({scope: level for scope, level in granted.items()
                              if level != "none" and (scope, level) not in allowed}, {}, f"job {name}: {granted}")
        job = jobs["held-runs"]
        self.assertNotIn("secrets.", self.workflow_text)
        self.assertNotIn("id-token", self.workflow_text)
        for event, ref, runs in (("workflow_run", "refs/heads/main", True), ("push", "refs/heads/main", True),
                                 ("issues", "refs/heads/main", True), ("workflow_dispatch", "refs/heads/main", True),
                                 ("workflow_dispatch", "refs/heads/other", False)):
            self.assertEqual(bool(test_outside_screen.evaluate(job["if"], {"github.event_name": event,
                                                                           "github.ref": ref})), runs, (event, ref))


class ReviewThatPasses(Stand):
    """d10: the review job of an enrollment whose review passes has the model read review.md, and hands the comment
    and the verdicts that the model gave on to the comment job as they are. PostingStep of tests/test_check_checks.py
    runs the comment job's step that posts them."""

    # The stand-in model's comment.
    COMMENT = ("Every check of review.md passes for projects/libreac/.\n\nYou need to do nothing more, unless the pull "
               "request later gets the label `checks-failing`.\n")
    SESSION = "09227178-7bbf-4e5f-86db-8736e530ef01"

    def test_passes_the_review_job_hands_on_the_comment_and_the_verdicts_of_the_model(self):
        """The model reads the prompt the review job builds, and a stand-in model gives COMMENT and the verdict pass
        for each check. It does not check what a real model writes."""
        import test_outside_screen
        evaluate = test_outside_screen.evaluate
        review = self.workflow(ROOT, "review.yml")
        ctx = {"needs.route.outputs.kind": "enrollment", "needs.route.outputs.pr": "8",
               "needs.route.outputs.sha": OTHER, "needs.gather.outputs.name": "libreac",
               "needs.gather.outputs.session": "", "needs.gather.outputs.last": ""}
        rc, log, prompt = self.run_step(review, "review", "What the review reads and gives", ctx, ROOT,
                                        evaluate=evaluate)
        self.assertEqual(rc, 0, log)
        self.assertTrue(prompt["prompt"].startswith("Read review.md at the root of this checkout"), prompt)
        # The Review step gives the model the prompt that step built, by the step's own id.
        built = f"steps.{self.step(review, 'review', 'What the review reads and gives')['id']}.outputs.prompt"
        self.assertEqual(test_outside_screen.interpolated(self.step(review, "review", "Review")["with"]["prompt"],
                                                          {built: prompt["prompt"]}), prompt["prompt"])
        # The stand-in model: its structured output, every verdict pass.
        ids = self.check_ids()
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
        self.assertEqual((kept["comment"], json.loads(kept["verdicts"]), json.loads(kept["reasons"])),
                         (self.COMMENT, {check: "pass" for check in ids}, {}), log)


if __name__ == "__main__":
    unittest.main()
