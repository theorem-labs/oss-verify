# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests that four pull_request jobs take the base branch's tools from the first parent of GitHub's merge commit
(OSSV-902):

    python3 -P -m pytest -q -p no:cacheprovider -c pyproject.toml -rs tests/test_base_tools.py

On pull_request, GitHub reads each workflow file from the merge commit github.sha. The first parent of that commit is
the commit of the base branch on which GitHub built the merge. The event's pull_request.base.sha is the base that GitHub
recorded for the pull request, and it does not move when the base branch moves. So these jobs take their scripts from
the first parent: project-builds of build.yaml, validate of validate.yaml, terms-accepted of terms.yaml, and, for a
pull request from a fork, required of tests.yaml. A test of one job has the id <file>:<job>.

Some tests read the workflow files:
  - No workflow names pull_request.base.sha in an expression.
  - No checkout of a workflow that starts on pull_request names a ref.
  - In each job, the first checkout has fetch-depth: 2. The next step has id: parent. Its if: is none in project-builds
    and terms-accepted, pull_request only in validate, and a fork only in required of tests.yaml.
  - terms.yaml gives the program BASE_SHA from the output of that step.

Other tests run the steps of each job in a scratch repository over file://. GitHub built the merge M on P1, a commit
newer than the recorded base B, and then main moved on to N:

    B --- P1 --- N        main is at N.
    |     |
    P2 -- M               M, at refs/pull/7/merge, merges P2 into P1.

Each commit holds a trap at each path that the jobs run. A trap logs its commit and its path to $TRAP_LOG. The test
makes each checkout from that checkout's own with: inputs, as actions/checkout v7.0.1 does. It runs each run: as GitHub
runs a step with no shell:. A stand-in gh answers the compare API with the status of the case. These tests check:
  - The step with id: parent checks out P1, detached. It gives P1 as its output sha, logs it, and runs no file of the
    checkout.
  - The step refuses a merge that is behind the base branch or diverged from it, a compare that fails, and a merge
    commit with one parent or three.
  - The step does not run on a run by hand of validate.yaml, or on a pull request from a branch in tests.yaml.
  - Each job runs its scripts, and src/oss_verify/, from P1.

The last test runs the build step of build.yaml with a stand-in oss-verify check and binary-sizes. When oss-verify
check passes and a run of binary-sizes fails, the step writes a warning and a summary sentence with the exit status.
It writes no output of binary-sizes, and its exit status does not change.

Each test reads the workflow files from one directory: the repository's .github/workflows, or the directory that a
caller gives. So a control can run a test on a changed copy of the workflows.
"""
import collections
import hashlib
import os
import pathlib
import re
import secrets
import shlex
import subprocess
import tempfile

import pytest
import yaml

from test_outside_screen import evaluate
from test_take_project import git, isolated_git_env
from test_trigger_move import YAML_LOADER, action_of, as_text, env_of, outputs, render, triggers

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REPO = "theorem-labs/oss-verify"
# The head repository of each pull request here but one: tests.yaml takes the first parent only for a fork.
FORK = "someone/oss-verify"
# The four jobs, as <file>:<job>, and the if: of the step with id: parent in each. None: the step has no if:.
JOBS = {
    "build.yaml:project-builds": None,
    "validate.yaml:validate": "github.event_name == 'pull_request'",
    "terms.yaml:terms-accepted": None,
    "tests.yaml:required": "env.FORK == 'true'",
}
# The files of the checkout that each job runs. The first one is the file of the first step after the step with
# id: parent.
TOOLS = {
    "build.yaml:project-builds": (".github/scripts/take-project",),
    "validate.yaml:validate": (".github/scripts/take-project", "src/oss_verify/__main__.py"),
    "terms.yaml:terms-accepted": (".github/scripts/terms-accepted",),
    "tests.yaml:required": (".github/scripts/collect",),
}
# validate's step after take-project. It runs src/oss_verify/ of the checkout.
VALIDATE_STEP = "Check projects/<name>/ with oss-verify validate"
# The paths of the traps in each commit. python3 -m oss_verify needs src/oss_verify/__init__.py too: without it, an
# installed oss_verify would come before the checkout's.
TRAPS = (".github/scripts/take-project", ".github/scripts/collect", ".github/scripts/terms-accepted",
         ".github/scripts/binary-sizes", "src/oss_verify/__init__.py", "src/oss_verify/__main__.py")
# The commits of the scratch repository, each with its parents. P3 is the third parent of M3, an octopus merge. M1 is
# a merge commit with one parent. refs/pull/7/merge names M, M1 or M3.
COMMITS = (("B", ()), ("P1", ("B",)), ("P2", ("B",)), ("P3", ("B",)), ("N", ("P1",)), ("M", ("P1", "P2")),
           ("M1", ("P1",)), ("M3", ("P1", "P2", "P3")))
MESSAGES = {"M": "Merge P2 into P1", "M1": "Merge P2 into P1, with one parent",
            "M3": "Merge P2 and P3 into P1"}
SIGNATURE = "Test <test@example.org> 1767225600 +0000"
# The with: inputs that the checkout model reads. It refuses a checkout with any other input.
CHECKOUT_INPUTS = {"ref", "fetch-depth", "persist-credentials", "sparse-checkout", "path"}
# The cases of test_the_step_refuses: the commit at refs/pull/7/merge, and the stand-in gh's answer to the compare
# ("error": gh fails as on an error of the API).
REFUSALS = {
    "behind": ("M", "behind"),
    "diverged": ("M", "diverged"),
    "compare fails": ("M", "error"),
    "one parent": ("M1", "ahead"),
    "three parents": ("M3", "ahead"),
}
# The cases of test_the_step_skips_where_r1_says: the run, and the words that name it.
SKIPS = {
    "validate.yaml:validate": ({"event": "workflow_dispatch"}, "a run by hand"),
    "tests.yaml:required": ({"fork": False}, "a pull request from a branch of this repository"),
}
# The sizes that the stand-in binary-sizes prints: one line of JSON, as the real one prints it.
SIZES = '{"demo_fuzzer":{"plain":{"exec":4096,"text":1024}}}'
# The line that the build step writes when binary-sizes --cut exits 0 and prints nothing.
NO_CUT_SIZES = "binary-sizes --cut gave no sizes: those of the plain builds are over 100,000 bytes of JSON."
# A case of test_binary_sizes. check: the exit status of oss-verify check. plain and cut: what the plain run and the
# --cut run of binary-sizes do, each (what it prints: sizes, nothing or marker; its exit status), or None for a run
# that does not happen. Then what the build step does: code, its exit status; warned, the exit status that its warning
# and its summary sentence give, or None for no warning; sizes and results_sizes, whether those outputs are set;
# no_cut_line, whether it logs NO_CUT_SIZES.
Sizes = collections.namedtuple("Sizes", "check plain cut code warned sizes results_sizes no_cut_line")
BINARY_SIZES = {
    "no run fails": Sizes(0, ("sizes", 0), ("sizes", 0), 0, None, True, True, False),
    "the plain run fails": Sizes(0, ("marker", 1), None, 0, 1, False, False, False),
    "the plain run exits 3": Sizes(0, ("marker", 3), None, 0, 3, False, False, False),
    "the cut run fails": Sizes(0, ("sizes", 0), ("marker", 1), 0, 1, True, False, False),
    "the cut run prints nothing": Sizes(0, ("sizes", 0), ("nothing", 0), 0, None, True, False, True),
    "oss-verify check fails": Sizes(1, ("marker", 1), None, 1, None, False, False, False),
}
# An expression that names the event's base.sha, in any case of letters (GitHub reads names without case), with
# github.event.pull_request['base']['sha'] read as github.event.pull_request.base.sha.
BASE_SHA = re.compile(r"pull_request\s*\.\s*base\s*\.\s*sha\b", re.I)

# The stand-in gh. It logs each call: each argument ended by NUL, and the call by \1. It serves only the compare API's
# status, `gh api repos/<owner>/<repo>/compare/<a>...<b> --jq .status`, with @STATUS@. With the status error, it fails
# as gh fails on an error of the API.
GH = r"""#!/usr/bin/env bash
{ printf '%s\0' "$@"; printf '\1'; } >> @LOG@
if [ $# = 4 ] && [ "$1" = api ] && [[ $2 =~ ^repos/[^/]+/[^/]+/compare/[^/]+\.\.\.[^/]+$ ]] && [ "$3" = --jq ] \
    && [ "$4" = .status ]; then
  [ @STATUS@ != error ] || { echo "gh: Server Error (HTTP 502)" >&2; exit 1; }
  echo @STATUS@
  exit 0
fi
echo "gh: not served here: $*" >&2
exit 9
"""
# dpkg finds every package, so no step installs one. sudo refuses.
DPKG = "#!/bin/sh\nexit 0\n"
SUDO = '#!/bin/sh\necho "sudo: not run in a test" >&2\nexit 1\n'

Ran = collections.namedtuple("Ran", "code log output summary skipped", defaults=(None, "", "", "", False))


def load(workflows, name):
    return yaml.load((pathlib.Path(workflows) / name).read_text(), Loader=YAML_LOADER)


def describe(step):
    """A step's name, or else its action or the start of its run:."""
    return repr(step.get("name") or step.get("uses") or str(step.get("run", "")).strip()[:60] or "none")


def inner(expression):
    """The text of an expression, without ${{ }} and with each run of spaces as one space; None for None."""
    if expression is None:
        return None
    text = str(expression).strip()
    found = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.S)
    return " ".join((found.group(1) if found else text).split())


def from_checkout(label, steps):
    """The steps of a job from its first actions/checkout."""
    first = next((i for i, step in enumerate(steps) if action_of(step) == "actions/checkout"), None)
    assert first is not None, f"{label}: the job has no actions/checkout"
    return steps[first:]


def commands(log):
    """The workflow commands that the runner reads in a step's log: each line that starts with ::, but none between
    ::stop-commands::<token> and ::<token>::."""
    found, stopped = [], None
    for line in log.splitlines():
        if stopped is not None:
            if line == f"::{stopped}::":
                stopped = None
        elif line.startswith("::stop-commands::"):
            stopped = line[len("::stop-commands::"):]
        elif line.startswith("::"):
            found.append(line)
    return found


def trap(commit, path):
    """The trap at `path` in the commit `commit`. It logs `<commit> <path>` to $TRAP_LOG and exits 0. The trap of
    terms-accepted also logs BASE_SHA=<its BASE_SHA>. The trap of take-project also writes the outputs name=demo and
    sha=<HEAD_SHA>, which is P2, so that the steps after it run."""
    text = ("#!/usr/bin/env python3\n"
            f"# A trap of tests/test_base_tools.py: {path} of the commit {commit}.\n"
            "import os\n"
            'with open(os.environ["TRAP_LOG"], "a", encoding="utf-8") as log:\n'
            f'    log.write("{commit} {path}\\n")\n')
    if path == ".github/scripts/terms-accepted":
        text += '    log.write("BASE_SHA=" + os.environ.get("BASE_SHA", "") + "\\n")\n'
    if path == ".github/scripts/take-project":
        text += ('with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:\n'
                 '    out.write("name=demo\\nsha=" + os.environ.get("HEAD_SHA", "") + "\\n")\n')
    return text


def data(text):
    """`text` as a data command of git fast-import."""
    raw = text.encode()
    return b"data %d\n" % len(raw) + raw + b"\n"


class Scratch:
    """The scratch repository of one test: a bare repository under tmp_path, read over file://. It has
    uploadpack.allowFilter, for the filter of a sparse checkout, and uploadpack.allowAnySHA1InWant, for a fetch of a
    commit by its SHA. main is at N, refs/pull/7/head at P2, and refs/pull/7/merge at `merge` (M, M1 or M3)."""

    def __init__(self, tmp_path, merge="M"):
        self.env = isolated_git_env(tmp_path)
        self.origin = tmp_path / "origin.git"
        git("init", "-q", "--bare", "-b", "main", str(self.origin), env=self.env)
        git("config", "uploadpack.allowFilter", "true", cwd=self.origin, env=self.env)
        git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=self.origin, env=self.env)
        marks = {name: n for n, (name, _) in enumerate(COMMITS, 1)}
        stream = []
        for name, parents in COMMITS:
            stream.append(f"commit refs/scratch/{name}\nmark :{marks[name]}\n"
                          f"author {SIGNATURE}\ncommitter {SIGNATURE}\n".encode())
            stream.append(data(MESSAGES.get(name, name)))
            for n, parent in enumerate(parents):
                stream.append(f"{'merge' if n else 'from'} :{marks[parent]}\n".encode())
            stream.append(b"deleteall\n")
            for path in TRAPS:
                stream.append(f"M 100755 inline {path}\n".encode() + data(trap(name, path)))
            stream.append(b"\n")
        for ref, name in (("refs/heads/main", "N"), ("refs/pull/7/head", "P2"), ("refs/pull/7/merge", merge)):
            stream.append(f"reset {ref}\nfrom :{marks[name]}\n\n".encode())
        exported = tmp_path / "marks"
        subprocess.run(["git", "fast-import", "--quiet", f"--export-marks={exported}"], cwd=self.origin,
                       input=b"".join(stream), env=self.env, check=True, capture_output=True)
        by_mark = dict(line.split() for line in exported.read_text().splitlines())
        self.commits = {name: by_mark[f":{n}"] for name, n in marks.items()}
        self.merge = self.commits[merge]

    def name(self, sha):
        """The name of a commit of this repository, or the text itself."""
        return next((name for name, commit in self.commits.items() if commit == sha), sha)

    def named(self, text):
        """`text` with each commit of this repository as its name."""
        for name, commit in self.commits.items():
            text = text.replace(commit, name)
        return text


class Host:
    """The runner's side of one run, in `directory`: its temporary directory, $TRAP_LOG, and the stand-ins gh, dpkg
    and sudo at the front of PATH. gh answers the compare with `status`. `env` is the environment of git with no
    configuration of this machine, with its HOME. Each step gets its own GITHUB_OUTPUT and GITHUB_STEP_SUMMARY, as on
    GitHub."""

    def __init__(self, directory, env, status="ahead"):
        self.dir = directory
        self.temp = directory / "runner-temp"
        self.temp.mkdir(parents=True)
        self.trap_log = directory / "trap.log"
        self.trap_log.write_text("")
        self.gh_log = directory / "gh.log"
        self.gh_log.write_text("")
        stubs = directory / "stubs"
        stubs.mkdir()
        gh = GH.replace("@LOG@", shlex.quote(str(self.gh_log))).replace("@STATUS@", shlex.quote(status))
        for name, text in (("gh", gh), ("dpkg", DPKG), ("sudo", SUDO)):
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)
        self.env = {**env, "PATH": f"{stubs}{os.pathsep}{env['PATH']}", "RUNNER_TEMP": str(self.temp),
                    "TRAP_LOG": str(self.trap_log)}
        self.steps = 0

    def run(self, step, env, cwd):
        """Run the run: of `step` as GitHub runs a step with no shell: the script in a file, `bash -e <file>`, in
        `cwd`, with `env` and the runner's variables. Return its Ran."""
        assert "shell" not in step and "working-directory" not in step, f"the model runs no {describe(step)}"
        self.steps += 1
        script, output, summary = (self.dir / f"{kind}.{self.steps}" for kind in ("step.sh", "output", "summary"))
        # A run: that YAML reads as another type than text, such as true, is that text, as GitHub reads it.
        script.write_text(as_text(step["run"]))
        output.write_text("")
        summary.write_text("")
        done = subprocess.run(["bash", "-e", str(script)], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=120, check=False,
                              env={**env, **self.env, "GITHUB_OUTPUT": str(output),
                                   "GITHUB_STEP_SUMMARY": str(summary)})
        return Ran(done.returncode, done.stdout, output.read_text(), summary.read_text())

    def calls(self):
        """Each call of gh, as its arguments."""
        return [call.split("\0")[:-1] for call in self.gh_log.read_text().split("\1")[:-1]]

    def trapped(self):
        """The lines of $TRAP_LOG: each trap that ran."""
        return self.trap_log.read_text().splitlines()


class JobRun:
    """One run of the job `label` in the scratch repository, as GitHub runs it. It runs the steps from the job's first
    actions/checkout: each checkout by the checkout model, and each run: step under bash -e. `status` is the stand-in
    gh's answer to the compare. The run is of pull request 7 (from FORK, or from this repository when `fork` is false),
    or a run by hand on main."""

    def __init__(self, tmp_path, scratch, workflows, label, status="ahead", event="pull_request", fork=True):
        self.label, self.scratch = label, scratch
        name, self.job = label.split(":")
        self.workflow = load(workflows, name)
        self.steps = from_checkout(label, self.workflow["jobs"][self.job]["steps"])
        directory = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=tmp_path))
        self.workspace = directory / "workspace"
        self.workspace.mkdir()
        self.host = Host(directory, scratch.env, status)
        commits = scratch.commits
        ctx = {"github.event_name": event, "github.repository": REPO, "github.token": "stand-in-token",
               "github.workspace": str(self.workspace), "github.event.repository.default_branch": "main"}
        if event == "pull_request":
            ctx.update({"github.sha": scratch.merge, "github.ref": "refs/pull/7/merge",
                        "github.event.pull_request.number": 7,
                        "github.event.pull_request.base.ref": "main",
                        "github.event.pull_request.base.sha": commits["B"],
                        "github.event.pull_request.base.repo.default_branch": "main",
                        "github.event.pull_request.head.sha": commits["P2"],
                        "github.event.pull_request.head.repo.full_name": FORK if fork else REPO})
        else:
            # A run by hand on main: its commit is main's.
            assert event == "workflow_dispatch", event
            ctx.update({"github.sha": commits["N"], "github.ref": "refs/heads/main", "inputs.pr": 7})
        for scope in (self.workflow.get("env") or {}, self.workflow["jobs"][self.job].get("env") or {}):
            for key, value in scope.items():
                ctx[f"env.{key}"] = render(value, ctx, evaluate)
        self.ctx = ctx
        self.results = []

    def parent(self):
        """The job's step with id: parent, or None."""
        found = [step for step in self.steps if step.get("id") == "parent"]
        assert len(found) <= 1, f"{self.label}: {len(found)} steps have id: parent"
        return found[0] if found else None

    def run_to(self, last):
        """Run the steps from the first checkout through `last`. Between them, only a checkout or the step with
        id: parent may run: another step there fails the run, naming the job. A step that fails ends the run, as on
        GitHub. Return the Ran of the last step that ran."""
        end = next(n for n, step in enumerate(self.steps) if step is last)
        for step in self.steps[:end + 1]:
            if step is not last and action_of(step) != "actions/checkout" and step.get("id") != "parent":
                raise AssertionError(f"{self.label}: the step {describe(step)} lies between the checkout and the step "
                                     f"{describe(last)}")
            ran = self.run_step(step)
            if ran.code:
                break
        return ran

    def run_step(self, step):
        """Run one step whose if: holds: a checkout by the model, or a run: step with its env rendered for the run.
        A run: step's outputs go into the context as steps.<id>.outputs.<name>."""
        if not self.condition(step.get("if")):
            ran = Ran(skipped=True)
        elif action_of(step) == "actions/checkout":
            self.checkout(step)
            ran = Ran(0)
        else:
            assert "run" in step and "uses" not in step, f"{self.label}: the model runs no step {describe(step)}"
            env = env_of(self.workflow, self.job, step, self.ctx, evaluate=evaluate)
            ran = self.host.run(step, env, self.workspace)
            if step.get("id"):
                for key, value in outputs(ran.output).items():
                    self.ctx[f"steps.{step['id']}.outputs.{key}"] = value
        self.results.append((step, ran))
        return ran

    def condition(self, expression):
        """An if:, evaluated with evaluate for this run. Each hashFiles(...) in it is the hash of the files of the root
        checkout as they are now, or '' when no file matches, as GitHub gives it."""
        if expression is None or isinstance(expression, bool):
            return expression is not False

        def hashed(match):
            patterns = [p.replace("''", "'") for p in re.findall(r"'((?:[^']|'')*)'", match.group(1))]
            files = sorted({path for p in patterns for path in self.workspace.glob(p) if path.is_file()})
            if not files:
                return "''"
            return "'" + hashlib.sha256(b"".join(path.read_bytes() for path in files)).hexdigest() + "'"

        value = evaluate(re.sub(r"hashFiles\(([^)]*)\)", hashed, str(expression)), self.ctx)
        return value not in (None, False, "", 0)

    def checkout(self, step):
        """Check out as actions/checkout v7.0.1 does, from the step's own with: inputs. ref, rendered for the run,
        names what it fetches: none or an empty one gives github.sha at github.ref (+<M>:refs/remotes/pull/7/merge on
        pull_request), 40 hex digits give that commit, and any other text gives that branch. fetch-depth is the depth
        of the fetch (1 by default). A sparse-checkout also fetches with --filter=blob:none, and checks out only its
        lines. path is the directory of the checkout, under the workspace."""
        inputs = step.get("with") or {}
        unknown = sorted(set(inputs) - CHECKOUT_INPUTS)
        assert not unknown, f"{self.label}: the checkout model reads no with: {', '.join(unknown)}"
        ref = render(inputs.get("ref", ""), self.ctx, evaluate).strip()
        depth = int(inputs.get("fetch-depth", 1))
        sparse = str(inputs.get("sparse-checkout") or "").split()
        where = self.workspace / inputs["path"] if inputs.get("path") else self.workspace
        if not ref:
            sha, at = self.ctx["github.sha"], self.ctx["github.ref"]
            if at.startswith("refs/pull/"):
                target = "refs/remotes/pull/" + at[len("refs/pull/"):]
            else:
                assert at.startswith("refs/heads/"), at
                target = "refs/remotes/origin/" + at[len("refs/heads/"):]
            refspec = f"+{sha}:{target}"
        elif re.fullmatch(r"[0-9a-f]{40}", ref):
            refspec = target = ref
        else:
            assert not ref.startswith("refs/"), f"{self.label}: the checkout model reads no ref: {ref}"
            target = f"refs/remotes/origin/{ref}"
            refspec = f"+refs/heads/{ref}:{target}"
        env = self.scratch.env
        git("init", "-q", str(where), env=env)
        git("remote", "add", "origin", f"file://{self.scratch.origin}", cwd=where, env=env)
        fetch = ["fetch", "-q", "--no-tags"]
        if sparse:
            git("config", "remote.origin.promisor", "true", cwd=where, env=env)
            git("config", "remote.origin.partialclonefilter", "blob:none", cwd=where, env=env)
            git("sparse-checkout", "set", *sparse, cwd=where, env=env)
            fetch.append("--filter=blob:none")
        if depth > 0:
            fetch.append(f"--depth={depth}")
        git(*fetch, "origin", refspec, cwd=where, env=env)
        git("checkout", "-q", "--detach", target, cwd=where, env=env)
        if sparse:
            objects = git("rev-list", "--objects", "--missing=print", "--all", cwd=where, env=env)
            assert any(line.startswith("?") for line in objects.splitlines()), \
                f"{self.label}: the sparse checkout lacks no blob, so its filter did nothing"

    def head(self):
        """The commit of HEAD in the workspace."""
        return git("rev-parse", "HEAD", cwd=self.workspace, env=self.scratch.env)

    def detached(self):
        return subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=self.workspace, env=self.scratch.env,
                              capture_output=True, check=False).returncode == 1


def strings(node, where=""):
    """Each string of a parsed YAML node, keys included, with the path to it."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from strings(key, where)
            yield from strings(value, f"{where}.{key}" if where else str(key))
    elif isinstance(node, list):
        for n, value in enumerate(node):
            yield from strings(value, f"{where}[{n}]")
    elif isinstance(node, str):
        yield where, node


def expressions(where, text):
    """The expressions of a string at `where`: each ${{ }} in it, and an if: as a whole, which GitHub reads as an
    expression with or without ${{ }}."""
    found = re.findall(r"\$\{\{(.*?)\}\}", text, re.S)
    if where.rsplit(".", 1)[-1] == "if" and "${{" not in text:
        found.append(text)
    return found


# --- the workflow files ---


def no_workflow_names_the_events_base_sha(workflows=WORKFLOWS):
    named = []
    for path in sorted(pathlib.Path(workflows).glob("*.y*ml")):
        for where, text in strings(load(workflows, path.name)):
            for expression in expressions(where, text):
                if BASE_SHA.search(re.sub(r"\[\s*'([^']*)'\s*\]", r".\1", expression)):
                    named.append(f"{path.name}: {where}: {' '.join(expression.split())}")
    assert not named, "These expressions name the event's pull_request.base.sha:\n" + "\n".join(named)


def no_pull_request_checkout_names_a_ref(workflows=WORKFLOWS):
    named = []
    for path in sorted(pathlib.Path(workflows).glob("*.y*ml")):
        workflow = load(workflows, path.name)
        if "pull_request" not in triggers(workflow):
            continue
        for job_id, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if action_of(step) == "actions/checkout" and "ref" in (step.get("with") or {}):
                    named.append(f"{path.name}:{job_id}: ref: {step['with']['ref']}")
    assert not named, "These checkouts of a workflow that starts on pull_request name a ref:\n" + "\n".join(named)


def the_step_follows_the_checkout(label, workflows=WORKFLOWS):
    name, job = label.split(":")
    steps = from_checkout(label, load(workflows, name)["jobs"][job]["steps"])
    inputs = steps[0].get("with") or {}
    wrong = []
    if str(inputs.get("fetch-depth")) != "2":
        wrong.append(f"the checkout has fetch-depth: {inputs['fetch-depth']}" if "fetch-depth" in inputs
                     else "the checkout has no fetch-depth")
    if "ref" in inputs:
        wrong.append(f"the checkout names ref: {inputs['ref']}")
    if label == "tests.yaml:required" and str(inputs.get("sparse-checkout", "")).split() != [".github/scripts"]:
        wrong.append("the checkout lost sparse-checkout: .github/scripts")
    step = steps[1] if len(steps) > 1 else {}
    if step.get("id") != "parent" or "run" not in step or "uses" in step:
        wrong.append(f"the next step, {describe(step)}, is not a run: step with id: parent")
    elif inner(step.get("if")) != JOBS[label]:
        wrong.append(f"the step with id: parent has if: {step.get('if')}, not {JOBS[label] or 'none'}")
    assert not wrong, f"{label}: " + "; ".join(wrong) + " (R1: fetch-depth: 2, no ref, then the step with id: parent)"


def terms_gives_base_sha_the_first_parent(workflows=WORKFLOWS):
    steps = load(workflows, "terms.yaml")["jobs"]["terms-accepted"]["steps"]
    found = [step for step in steps if ".github/scripts/terms-accepted" in str(step.get("run", ""))]
    assert len(found) == 1, f"terms.yaml:terms-accepted: {len(found)} steps run .github/scripts/terms-accepted"
    value = (found[0].get("env") or {}).get("BASE_SHA")
    assert inner(value) == "steps.parent.outputs.sha", \
        f"terms.yaml:terms-accepted: BASE_SHA is {value}, not ${{{{ steps.parent.outputs.sha }}}}"


# --- the step with id: parent, run in the scratch repository ---


def the_step_checks_out_the_first_parent(tmp_path, label, workflows=WORKFLOWS):
    scratch = Scratch(tmp_path)
    p1, m, n = (scratch.commits[name] for name in ("P1", "M", "N"))
    for status in ("ahead", "identical"):
        run = JobRun(tmp_path, scratch, workflows, label, status=status)
        step = run.parent()
        if step is None:
            run.run_to(run.steps[0])
            raise AssertionError(f"{label}: no step has id: parent, and the checkout holds "
                                 f"{scratch.name(run.head())}, not P1")
        ran = run.run_to(step)
        where = f"{label} (compare: {status})"
        assert not ran.skipped, f"{where}: the step with id: parent did not run: its if: is false"
        assert ran.code == 0, f"{where}: the step exited {ran.code}:\n{scratch.named(ran.log)}"
        head = run.head()
        assert head == p1 and run.detached(), \
            f"{where}: HEAD is {scratch.name(head)}{'' if run.detached() else ' on a branch'}, not P1, detached"
        assert ran.output.splitlines().count(f"sha={p1}") == 1 and outputs(ran.output).get("sha") == p1, \
            f"{where}: $GITHUB_OUTPUT does not hold sha=P1 once:\n{scratch.named(ran.output)}"
        assert f"Checked out {p1}, the first parent of the merge commit {m}:" in ran.log, \
            f"{where}: the log does not say that the step checked out P1 of M:\n{scratch.named(ran.log)}"
        assert run.host.trapped() == [], \
            f"{where}: the step ran files of the checkout:\n" + scratch.named("\n".join(run.host.trapped()))
        assert run.host.calls() == [["api", f"repos/{REPO}/compare/{p1}...{n}", "--jq", ".status"]], \
            f"{where}: gh was not called once, for the compare of P1 with N: {scratch.named(str(run.host.calls()))}"


def the_step_refuses(tmp_path, label, case, workflows=WORKFLOWS):
    merge, status = REFUSALS[case]
    scratch = Scratch(tmp_path, merge=merge)
    run = JobRun(tmp_path, scratch, workflows, label, status=status)
    step = run.parent()
    where = f"{label} ({case})"
    assert step is not None, f"{where}: no step has id: parent, so nothing refuses the run"
    ran = run.run_to(step)
    assert not ran.skipped, f"{where}: the step with id: parent did not run: its if: is false"
    assert ran.code != 0, f"{where}: the step exited 0:\n{scratch.named(ran.log)}"
    errors = [line for line in commands(ran.log) if line.startswith("::error::")]
    assert errors, f"{where}: the step wrote no ::error:: line:\n{scratch.named(ran.log)}"
    if case in ("behind", "diverged"):
        assert any("push a commit" in line.lower() for line in errors), \
            f"{where}: the ::error:: line does not say to push a commit:\n{scratch.named(ran.log)}"
    assert "sha" not in outputs(ran.output), f"{where}: the step gave the output sha:\n{scratch.named(ran.output)}"
    assert run.host.trapped() == [], \
        f"{where}: the step ran files of the checkout:\n" + scratch.named("\n".join(run.host.trapped()))


def the_step_skips_where_r1_says(tmp_path, label, workflows=WORKFLOWS):
    given, why = SKIPS[label]
    scratch = Scratch(tmp_path)
    run = JobRun(tmp_path, scratch, workflows, label, **given)
    after = run.steps[1] if len(run.steps) > 1 else {}
    assert after.get("id") == "parent", f"{label}: the step after the checkout, {describe(after)}, has no id: parent"
    ran = run.run_to(after)
    where = f"{label} ({why})"
    assert ran.skipped, f"{where}: the step with id: parent ran:\n{scratch.named(ran.log)}"
    head, commit = run.head(), run.ctx["github.sha"]
    assert head == commit, f"{where}: HEAD is {scratch.name(head)}, not the run's commit {scratch.name(commit)}"
    assert run.host.calls() == [] and run.host.trapped() == [], f"{where}: the run called gh or ran a trap"


def the_job_runs_the_first_parents_tools(tmp_path, label, workflows=WORKFLOWS):
    scratch = Scratch(tmp_path)
    p1 = scratch.commits["P1"]
    run = JobRun(tmp_path, scratch, workflows, label)
    tools = TOOLS[label]
    found = [step for step in run.steps if tools[0] in str(step.get("run", ""))]
    assert found, f"{label}: no step runs {tools[0]}"
    ran = run.run_to(found[0])
    if label == "validate.yaml:validate" and ran.code == 0:
        named = [step for step in run.steps if step.get("name") == VALIDATE_STEP]
        assert len(named) == 1, f"{label}: {len(named)} steps are named {VALIDATE_STEP!r}"
        ran = run.run_step(named[0])
    assert not ran.skipped and ran.code == 0, \
        f"{label}: the step {describe(run.results[-1][0])} did not pass:\n{scratch.named(ran.log)}"
    trapped = run.host.trapped()
    commits = sorted({line.split(" ", 1)[0] for line in trapped if not line.startswith("BASE_SHA=")})
    assert commits == ["P1"], (f"{label}: $TRAP_LOG names {', '.join(commits) or 'no commit'}, not P1 alone:\n"
                               + scratch.named("\n".join(trapped)))
    for path in tools:
        assert f"P1 {path}" in trapped, f"{label}: {path} of P1 did not run:\n" + scratch.named("\n".join(trapped))
    if label == "terms.yaml:terms-accepted":
        assert f"BASE_SHA={p1}" in trapped, \
            f"{label}: terms-accepted got another BASE_SHA than P1:\n" + scratch.named("\n".join(trapped))
        assert not (run.workspace / "merge").exists(), f"{label}: P1 has terms-accepted, but merge/ was checked out"


# --- the build step and binary-sizes ---


def binary_sizes(tmp_path, case, workflows=WORKFLOWS):
    want = BINARY_SIZES[case]
    marker = f"MARKER-{secrets.token_hex(8)}"
    workflow = load(workflows, "build.yaml")
    found = [step for step in workflow["jobs"]["project-builds"]["steps"] if step.get("id") == "build"]
    assert len(found) == 1, f"build.yaml:project-builds: {len(found)} steps have id: build"
    workspace = tmp_path / "workspace"
    package = workspace / "src" / "oss_verify"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    # oss-verify check exits as the case says.
    (package / "__main__.py").write_text(f"import sys\nsys.exit({want.check} if sys.argv[1:2] == ['check'] else 99)\n")
    runs = tmp_path / "binary-sizes-runs"
    # What each run prints, and its exit status. A run that the case does not expect prints the sizes.
    answers = {"plain": want.plain, "--cut": want.cut or ("sizes", 0)}
    script = workspace / ".github" / "scripts" / "binary-sizes"
    script.parent.mkdir(parents=True)
    script.write_text(
        "#!/usr/bin/env python3\n"
        "# The stand-in binary-sizes of tests/test_base_tools.py: it logs each run, prints what its case says, and\n"
        "# exits with the status of its case.\n"
        "import sys\n"
        "run = '--cut' if sys.argv[1:2] == ['--cut'] else 'plain'\n"
        f"with open({str(runs)!r}, 'a', encoding='utf-8') as log:\n"
        "    log.write(run + '\\n')\n"
        f"what, status = {answers!r}[run]\n"
        "if what == 'sizes':\n"
        f"    print({SIZES!r})\n"
        "elif what == 'marker':\n"
        f"    print({marker!r})\n"
        f"    print({marker!r}, file=sys.stderr)\n"
        "sys.exit(status)\n")
    script.chmod(0o755)
    ctx = {"github.workspace": str(workspace), "steps.project.outputs.name": "demo",
           "steps.project.outputs.sha": "a" * 40}
    env = env_of(workflow, "project-builds", found[0], ctx, evaluate=evaluate)
    ran = Host(tmp_path / "runner", isolated_git_env(tmp_path)).run(found[0], env, workspace)
    where = f"build.yaml:project-builds ({case})"
    assert ran.code == want.code, f"{where}: the build step exited {ran.code}, not {want.code}:\n{ran.log}"
    warnings = [line for line in commands(ran.log) if line.startswith("::warning::")]
    sentence = f"binary-sizes exited {want.warned}: the sizes are missing."
    if want.warned is None:
        assert warnings == [], f"{where}: the build step wrote a warning: {warnings}"
        assert "binary-sizes exited" not in ran.summary, f"{where}: the summary says:\n{ran.summary}"
    else:
        assert warnings == [f"::warning::{sentence}"], \
            f"{where}: the build step's warnings are {warnings}, not ::warning::{sentence}"
        assert sentence in ran.summary, f"{where}: the summary does not say {sentence!r}:\n{ran.summary}"
    values = outputs(ran.output)
    for key, given in (("sizes", want.sizes), ("results_sizes", want.results_sizes)):
        assert values.get(key, "") == (SIZES if given else ""), \
            f"{where}: the output {key} is {values.get(key)!r}, not {'the sizes' if given else 'empty'}"
    if want.no_cut_line:
        assert NO_CUT_SIZES in ran.log.splitlines(), f"{where}: the log does not say {NO_CUT_SIZES!r}:\n{ran.log}"
    asked = ["plain"] + (["--cut"] if want.cut else [])
    got = runs.read_text().splitlines() if runs.exists() else []
    assert got == asked, f"{where}: binary-sizes ran {got}, not {asked}"
    for kind, text in (("log", ran.log), ("summary", ran.summary), ("outputs", ran.output)):
        assert marker not in text, f"{where}: the step's {kind} holds the output of binary-sizes:\n{text}"


# --- the tests ---


def test_no_workflow_names_the_events_base_sha():
    no_workflow_names_the_events_base_sha()


def test_no_pull_request_checkout_names_a_ref():
    no_pull_request_checkout_names_a_ref()


@pytest.mark.parametrize("label", list(JOBS))
def test_the_step_follows_the_checkout(label):
    the_step_follows_the_checkout(label)


def test_terms_gives_base_sha_the_first_parent():
    terms_gives_base_sha_the_first_parent()


@pytest.mark.parametrize("label", list(JOBS))
def test_the_step_checks_out_the_first_parent(tmp_path, label):
    the_step_checks_out_the_first_parent(tmp_path, label)


@pytest.mark.parametrize("label, case", [pytest.param(label, case, id=f"{label}-{case}")
                                         for label in JOBS for case in REFUSALS])
def test_the_step_refuses(tmp_path, label, case):
    the_step_refuses(tmp_path, label, case)


@pytest.mark.parametrize("label", list(SKIPS))
def test_the_step_skips_where_r1_says(tmp_path, label):
    the_step_skips_where_r1_says(tmp_path, label)


@pytest.mark.parametrize("label", list(JOBS))
def test_the_job_runs_the_first_parents_tools(tmp_path, label):
    the_job_runs_the_first_parents_tools(tmp_path, label)


@pytest.mark.parametrize("case", list(BINARY_SIZES))
def test_binary_sizes(tmp_path, case):
    binary_sizes(tmp_path, case)
