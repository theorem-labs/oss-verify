# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""No job of .github/workflows/ that holds a token, or whose outputs such a job reads, loads code from src/:
uv run pytest tests/test_token_jobs.py

src/ has no code owner (.github/CODEOWNERS, dispatch://OSSV-276/ask/6c92b099-08f4-4177-aa5a-6a3fc6292878), so a change
to it merges with its checks alone. A job holds a token when it names a secret (secrets.<name>, or secrets: of a call
of a reusable workflow), has an environment, or has a write permission, id-token: write among them: in its own
permissions:, else in the workflow's, else in the repository's default, which can write. The test checks each such
job, each job of a reusable workflow that one of them calls, and each job that one of them needs, directly or through
another (whose outputs and result it reads). None of them may:
  - name src in PYTHONPATH: in an env: of the workflow, of the job or of a step, or in a run: line;
  - check src out for itself: a sparse-checkout line, or the path:, of actions/checkout, that names it;
  - import oss_verify, run python3 -m oss_verify, or run the package another way (uv run, uv sync, uv pip, pip install,
    pytest, which reads pyproject.toml's pythonpath src, or the command oss-verify);
  - run a file of .github/scripts that does one of these, or that runs or imports one that does: each file that a run:
    or a script names by its path under .github/scripts, or that a script names by a path to its name beside it
    ("$(dirname "$0")/<name>", here / "<name>", with_name("<name>")), and each module of .github/scripts that a Python
    file imports (validate_rules and its own modules among them) or that a shell script runs or imports, to the end of
    the chain.
Only code is read: comment lines, and the docstrings of a Python file, are left out.

A checkout of the whole tree holds src/ as files; none of the above puts it on sys.path, and -P, or a program's own
directory first on sys.path, keeps the top of the checkout off it. Not followed: a run of another workflow whose
result, check run or artifact a job reads through the API. enroll-dispatch.yml reads the check runs of build.yaml,
validate.yaml, terms.yaml and tests.yaml, and review.yml reads the Build run's artifact; the YAML names no such link.
Those runs run the code of the merge commit or of the base by design: project-builds builds with src/'s oss-verify
check, validate runs src/'s oss-verify validate, and tests runs the pull request's tests. terms.yaml's terms-accepted,
whose token has no permission, takes the rules of oss-verify validate from .github/scripts/validate_rules/ too
(tests/test_terms.py)."""
import ast
import copy
import fnmatch
import json
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCRIPTS = ROOT / ".github" / "scripts"
# Code that runs the package oss_verify: its import, python3 -m, and, at the start of a command, the ways to install it
# or run its command or its tests.
RUNS_PACKAGE = re.compile(r"\b(?:from|import)\s+oss_verify\b|-m\s+(?:oss_verify|pytest)\b"
                          r"|(?:^|[;&|(]|\$\()\s*(?:uv\s+(?:run|sync|pip)|pip3?\s+install|pytest|oss-verify)\b", re.M)
# src on the module search path.
SRC_PATH = re.compile(r"\b(?:PYTHONPATH|sys\.path)\b.*\bsrc\b")
# A file of .github/scripts, by its path; a module, by python3 -m or an import in a shell script's here-document.
SCRIPT = re.compile(r"\.github/scripts/([A-Za-z0-9._/-]+)")
MODULE = re.compile(r"-m\s+([A-Za-z_][\w.]*)|^\s*from\s+([A-Za-z_][\w.]*)\s+import\b|^\s*import\s+([A-Za-z_][\w.]*)",
                    re.M)
# The jobs that hold a token today, and the jobs they need: the test checks at least these. publish-prebuilt, which
# holds packages: write, needs remake-prebuilt, which runs .github/scripts/python-runtime/make, which builds the runtime
# with docker: publish-prebuilt pushes the image of remake-prebuilt's artifact.
HOLDERS = {("enroll-dispatch.yml", "dispatch"), ("held-runs.yml", "held-runs"), ("review.yml", "screen"),
           ("review.yml", "review"), ("review.yml", "hold"), ("review.yml", "comment"), ("review.yml", "triage"),
           ("toolchain-images-publish.yaml", "publish"), ("toolchain-images-publish.yaml", "publish-prebuilt")}
FEEDERS = {("enroll-dispatch.yml", "decide"), ("review.yml", "route"), ("review.yml", "gather"),
           ("review.yml", "triage-gather"), ("toolchain-images-publish.yaml", "remake-prebuilt")}
# publish-prebuilt and remake-prebuilt, each by its file and its name.
PUBLISH_PREBUILT = ("toolchain-images-publish.yaml", "publish-prebuilt")
REMAKE_PREBUILT = ("toolchain-images-publish.yaml", "remake-prebuilt")
# A step that runs make, as remake-prebuilt's make step runs it.
MAKE_STEP = {"name": "make", "run": '.github/scripts/python-runtime/make "$START" "localhost:5000/x:$ROW"'}


def read_file(path):
    """The text of the file at `path`, or None when there is none."""
    return path.read_text(encoding="utf-8") if path.is_file() else None


def read_workflows():
    """{file name: workflow} of each workflow of .github/workflows/."""
    return {path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
            for path in sorted(WORKFLOWS.iterdir()) if path.suffix in (".yml", ".yaml")}


def token(workflow, job):
    """Why `job` of `workflow` holds a token: a list of reasons, empty when it holds none."""
    reasons = ["an environment"] if "environment" in job else []
    permissions = job["permissions"] if "permissions" in job else workflow.get("permissions")
    if permissions is None:
        reasons.append("the repository's default permissions")
    elif isinstance(permissions, str):
        if permissions != "read-all":
            reasons.append(f"permissions: {permissions}")
    else:
        reasons += [f"{scope}: {level}" for scope, level in permissions.items() if level == "write"]
    if "secrets" in job or "secrets." in json.dumps([workflow.get("env"), job]):
        reasons.append("a secret")
    return reasons


def checked(workflows):
    """{(file, job): why the test checks it} for every job that holds a token, every job of a reusable workflow that
    one calls, and every job that one of them needs."""
    todo = [((file, name), "holds a token: " + ", ".join(reasons))
            for file, workflow in workflows.items() for name, job in (workflow.get("jobs") or {}).items()
            if (reasons := token(workflow, job))]
    found = {}
    while todo:
        (file, name), why = todo.pop()
        if (file, name) in found:
            continue
        found[(file, name)] = why
        job = workflows[file]["jobs"][name]
        needs = job.get("needs") or []
        todo += [((file, need), f"{name} needs it") for need in ([needs] if isinstance(needs, str) else needs)]
        called = str(job.get("uses", ""))
        if called.startswith("./.github/workflows/"):
            callee = called.removeprefix("./.github/workflows/").split("@")[0]
            todo += [((callee, other), f"{file}'s {name} calls it") for other in workflows[callee].get("jobs") or {}]
    return found


def docstrings(tree):
    """The line numbers of the docstrings of a parsed Python file."""
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                lines |= set(range(first.lineno, first.end_lineno + 1))
    return lines


def code(text, skipped=()):
    """The lines of `text` but its comment lines and the lines `skipped`, as one text."""
    return "\n".join(line for number, line in enumerate(text.splitlines(), 1)
                     if number not in skipped and not line.lstrip().startswith("#"))


class Audit:
    """What the jobs that the test checks load. `read` gives the text of a file by its path, or None."""

    def __init__(self, workflows, read=read_file):
        self.workflows, self.read = workflows, read
        self.problems, self.files = [], {}

    def run(self):
        """Fill `problems`, each one line, and `files`, {(file, job): the files of .github/scripts it runs}."""
        for (file, name), why in sorted(checked(self.workflows).items()):
            workflow = self.workflows[file]
            job = workflow["jobs"][name]
            files = self.files[(file, name)] = set()

            def problem(where, what):
                self.problems.append(f"{file}: {name} ({why}): {where}: {what}")

            steps = job.get("steps") or []
            labels = [str(step.get("name") or step.get("id") or step.get("uses") or n) for n, step in enumerate(steps)]
            for where, env in [("the workflow's env", workflow.get("env")), ("the job's env", job.get("env")),
                               *((f"step {label}'s env", step.get("env")) for label, step in zip(labels, steps))]:
                value = (env or {}).get("PYTHONPATH") if isinstance(env, dict) else None
                if value is not None and re.search(r"\bsrc\b", str(value)):
                    problem(where, f"PYTHONPATH {value}")
            for label, step in zip(labels, steps):
                given = step.get("with") or {}
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    for line in str(given.get("sparse-checkout") or "").splitlines():
                        line = line.strip()
                        first = line.lstrip("/").split("/")[0]
                        if first and not line.startswith(("!", "#")) and fnmatch.fnmatchcase("src", first):
                            problem(f"step {label}", f"sparse-checkout {line}")
                    if str(given.get("path") or "").strip("/").split("/")[0] == "src":
                        problem(f"step {label}", f"checks out into {given['path']}")
                for text in (step.get("run"), given.get("script")):
                    if isinstance(text, str):
                        self.text(code(text), f"step {label}", problem, files, shell=True)

    def text(self, text, where, problem, files, shell):
        """Check the code `text`, and follow each file of .github/scripts it names, and in a shell script, each module
        of .github/scripts it runs or imports."""
        for match in RUNS_PACKAGE.finditer(text):
            problem(where, f"runs the package: {match.group(0).strip()}")
        for line in text.splitlines():
            if SRC_PATH.search(line):
                problem(where, f"puts src on the module search path: {line.strip()}")
        for name in SCRIPT.findall(text):
            self.file(SCRIPTS / name.rstrip("/"), where, problem, files)
        if shell:
            for match in MODULE.finditer(text):
                module = next(group for group in match.groups() if group)
                for path in self.module(module, SCRIPTS):
                    self.file(path, where, problem, files)

    def module(self, module, base, names=()):
        """The files of .github/scripts that importing `module` (with `names` from it) under `base` runs."""
        paths, here = [], base
        for part in module.split(".") if module else []:
            if self.read(here / part / "__init__.py") is not None:
                here = here / part
                paths.append(here / "__init__.py")
            elif self.read(here / f"{part}.py") is not None:
                paths.append(here / f"{part}.py")
                return paths
            else:
                return paths
        return paths + [here / f"{name}.py" for name in names if self.read(here / f"{name}.py") is not None]

    def file(self, path, where, problem, files):
        """Check the file at `path`, once for each job, and each file it runs or imports: by its path under
        .github/scripts, by a path to its name in the same directory ("$(dirname "$0")/<name>", here / "<name>",
        with_name("<name>")), or as a module."""
        if path in files:
            return
        text = self.read(path)
        if text is None:
            return
        files.add(path)
        where = f"{where} > {path.relative_to(SCRIPTS)}"
        python = path.suffix == ".py" or "python" in text.split("\n", 1)[0]
        tree = ast.parse(text) if python else None
        skipped = docstrings(tree) if python else set()
        body = code(text, skipped)
        self.text(body, where, problem, files, shell=not python)
        for sibling in sorted(other.name for other in path.parent.iterdir() if other.is_file() and other != path):
            name = re.escape(sibling)
            if re.search(rf"/\s*[\"']?{name}(?=[\"'\s)]|$)|with_name\(\s*[\"']{name}[\"']", body, re.M):
                self.file(path.parent / sibling, where, problem, files)
        if not python:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.lineno not in skipped \
                    and (node.value == "oss_verify" or node.value.startswith("oss_verify.")):
                problem(where, f"names the module {node.value}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    for imported in self.module(alias.name, SCRIPTS):
                        self.file(imported, where, problem, files)
            elif isinstance(node, ast.ImportFrom):
                base = SCRIPTS
                if node.level:
                    base = path.parent
                    for _ in range(node.level - 1):
                        base = base.parent
                names = [alias.name for alias in node.names]
                for imported in self.module(node.module or "", base, names):
                    self.file(imported, where, problem, files)


def audit(workflows=None, read=read_file):
    """The Audit of `workflows` (by default those of .github/workflows/), run."""
    done = Audit(read_workflows() if workflows is None else workflows, read)
    done.run()
    return done


def test_no_job_that_holds_a_token_or_feeds_one_loads_code_from_src():
    assert audit().problems == []


def files_run(workflows=None):
    """{(file, job): the files of .github/scripts that the job runs, by their paths under it} of each job that the
    audit checks."""
    return {key: {str(path.relative_to(SCRIPTS)) for path in paths} for key, paths in audit(workflows).files.items()}


def test_it_checks_the_jobs_that_hold_a_token_and_those_they_need_and_the_files_they_run():
    done = audit()
    assert HOLDERS | FEEDERS <= set(done.files)
    # No token: validate.yaml's validate runs src/'s oss-verify validate, the check enrollment, as a user does.
    assert ("validate.yaml", "validate") not in done.files
    relative = files_run()
    rules = {"validate_rules/__init__.py", "validate_rules/validate.py", "validate_rules/check_build.py"}
    assert {"review-gather", "triage.py"} | rules <= relative[("review.yml", "gather")]
    assert {"triage.py"} | rules <= relative[("review.yml", "triage-gather")]
    assert {"enroll-dispatch", "triage.py", "steering.py", "artifact.py"} | rules \
        <= relative[("enroll-dispatch.yml", "decide")]
    # By a path to a name beside the script: review-hold runs "$(dirname "$0")/review-held", which runs
    # review-neutralize so; review-verdict loads it by with_name("review-neutralize").
    assert {"review-hold", "review-held", "review-neutralize"} <= relative[("review.yml", "hold")]
    assert {"review-verdict", "review-neutralize"} <= relative[("review.yml", "comment")]
    # remake-prebuilt runs .github/scripts/python-runtime/make, which runs layer.py beside it. publish-prebuilt, which
    # holds packages: write, runs no file of .github/scripts.
    assert {"python-runtime/make", "python-runtime/layer.py"} <= relative[REMAKE_PREBUILT]
    assert relative[PUBLISH_PREBUILT] == set()


def test_control_make_back_in_publish_prebuilt():
    # A step of publish-prebuilt that runs make, as before remake-prebuilt: the audit follows make and layer.py from it,
    # so the assertion that publish-prebuilt runs no file of .github/scripts fails.
    workflows = read_workflows()
    workflows[PUBLISH_PREBUILT[0]]["jobs"][PUBLISH_PREBUILT[1]]["steps"].append(dict(MAKE_STEP))
    assert {"python-runtime/make", "python-runtime/layer.py"} <= files_run(workflows)[PUBLISH_PREBUILT]


def test_control_a_make_that_runs_the_package_fails_remake_prebuilt():
    # make as a script that runs oss-verify check of src/. remake-prebuilt runs it, and publish-prebuilt, which holds a
    # token, needs it; prebuilt of toolchain-images.yaml runs it too, but holds no token and feeds none.
    make = SCRIPTS / "python-runtime" / "make"

    def read(path):
        return "#!/usr/bin/env bash\nuv run oss-verify check projects/x\n" if path == make else read_file(path)
    problems = audit(read=read).problems
    assert {problem.split(" (")[0] for problem in problems} == {"toolchain-images-publish.yaml: remake-prebuilt"}, \
        problems
    assert all(problem.startswith("toolchain-images-publish.yaml: remake-prebuilt (publish-prebuilt needs it): ")
               and problem.endswith("python-runtime/make: runs the package: uv run") for problem in problems), problems


def test_control_a_make_that_runs_the_package_fails_publish_prebuilt_when_it_runs_make():
    # The same make, with make back in publish-prebuilt: the audit names publish-prebuilt, for its own token, too.
    make = SCRIPTS / "python-runtime" / "make"

    def read(path):
        return "#!/usr/bin/env bash\nuv run oss-verify check projects/x\n" if path == make else read_file(path)
    workflows = read_workflows()
    workflows[PUBLISH_PREBUILT[0]]["jobs"][PUBLISH_PREBUILT[1]]["steps"].append(dict(MAKE_STEP))
    problems = audit(workflows, read=read).problems
    assert {problem.split(" (")[0] for problem in problems} == {"toolchain-images-publish.yaml: remake-prebuilt",
                                                                 "toolchain-images-publish.yaml: publish-prebuilt"}, \
        problems
    assert ("toolchain-images-publish.yaml: publish-prebuilt (holds a token: packages: write): step make >"
            " python-runtime/make: runs the package: uv run") in problems, problems


def test_control_a_layer_py_that_imports_oss_verify_fails_remake_prebuilt():
    # make runs "$here/layer.py", the file beside it: the audit follows it from make.
    layer = SCRIPTS / "python-runtime" / "layer.py"

    def read(path):
        text = read_file(path)
        return text + "\nimport oss_verify\n" if path == layer else text
    problems = audit(read=read).problems
    assert {problem.split(" (")[0] for problem in problems} == {"toolchain-images-publish.yaml: remake-prebuilt"}, \
        problems
    assert all(problem.endswith("make > python-runtime/layer.py: runs the package: import oss_verify")
               for problem in problems), problems


def test_control_main_decide_job_with_src_fails():
    # main's enroll-dispatch.yml before this test: decide checked src/ out and named it in PYTHONPATH, so that
    # triage.py imported oss_verify.validate from it, and dispatch, which holds the App's key, acts on its outputs.
    workflows = read_workflows()
    decide = workflows["enroll-dispatch.yml"]["jobs"]["decide"]
    decide["steps"][0]["with"]["sparse-checkout"] += "src\n"
    [step] = [step for step in decide["steps"] if step.get("id") == "decide"]
    step["env"]["PYTHONPATH"] = "${{ github.workspace }}/src"
    assert sorted(audit(workflows).problems) == [
        "enroll-dispatch.yml: decide (dispatch needs it): step Decide's env: PYTHONPATH ${{ github.workspace }}/src",
        "enroll-dispatch.yml: decide (dispatch needs it): step"
        " actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1: sparse-checkout src"]


def test_control_a_script_that_imports_oss_verify_fails_every_job_that_runs_it():
    # triage.py as before: it imported oss_verify.validate. decide imports it through enroll-dispatch, gather runs it
    # through review-gather, and triage-gather runs it.
    def read(path):
        text = read_file(path)
        if path == SCRIPTS / "triage.py":
            text = text.replace("from validate_rules import validate", "from oss_verify import validate")
        return text
    problems = audit(read=read).problems
    jobs = {problem.split(" (")[0] for problem in problems}
    assert jobs == {"enroll-dispatch.yml: decide", "review.yml: gather", "review.yml: triage-gather"}, problems
    assert all(problem.endswith("triage.py: runs the package: from oss_verify") for problem in problems), problems


def test_control_the_copy_of_the_rules_is_followed_into_its_own_modules():
    # validate_rules/check_build.py, which validate.py imports as `from . import check_build`, importing from src/.
    def read(path):
        text = read_file(path)
        if path == SCRIPTS / "validate_rules" / "check_build.py":
            text += "\nfrom oss_verify.check_build import ROOT\n"
        return text
    jobs = {problem.split(" (")[0] for problem in audit(read=read).problems}
    assert jobs == {"enroll-dispatch.yml: decide", "review.yml: gather", "review.yml: triage-gather"}


def test_control_review_gather_with_src_on_its_path_fails_gather():
    def read(path):
        text = read_file(path)
        if path == SCRIPTS / "review-gather":
            text = text.replace('export PYTHONPATH="$PWD/.github/scripts"', 'export PYTHONPATH="$PWD/src"')
            text = text.replace("-m validate_rules.validate", "-m oss_verify validate")
        return text
    problems = audit(read=read).problems
    assert sorted(problem.split(": ", 3)[3] for problem in problems) == [
        "puts src on the module search path: export PYTHONPATH=\"$PWD/src\"",
        "runs the package: -m oss_verify"], problems
    assert {problem.split(" (")[0] for problem in problems} == {"review.yml: gather"}


def test_control_which_jobs_hold_a_token():
    # write: the workflow's permissions, which a job without its own takes; none: a job whose permissions are none,
    # unless a job that holds a token needs it; default: a workflow and a job that set none, so the repository's
    # default permissions, which can write; and an environment, a secret, and id-token: write.
    run = {"runs-on": "ubuntu-latest", "steps": [{"run": "python3 -P -m oss_verify validate"}]}
    workflows = {
        "write.yml": {"permissions": {"contents": "write"}, "jobs": {"inherits": run}},
        "none.yml": {"permissions": {}, "jobs": {
            "alone": run, "needed": run, "far": run,
            "deploys": {**run, "needs": "between", "environment": "x"},
            "between": {"runs-on": "ubuntu-latest", "needs": ["needed", "far"], "steps": [{"run": "true"}]},
            "secret": {**run, "env": {"KEY": "${{ secrets.KEY }}"}},
            "identity": {**run, "permissions": {"id-token": "write"}},
            "reads": {**run, "permissions": "read-all"},
            "calls": {"uses": "./.github/workflows/called.yml", "secrets": "inherit"}}},
        "default.yml": {"jobs": {"default": run}},
        "called.yml": {"permissions": {}, "jobs": {"inside": run}},
    }
    problems = audit(copy.deepcopy(workflows)).problems
    flagged = {tuple(problem.split(" (")[0].split(": ")) for problem in problems}
    assert flagged == {("write.yml", "inherits"), ("none.yml", "needed"), ("none.yml", "far"), ("none.yml", "deploys"),
                       ("none.yml", "secret"), ("none.yml", "identity"), ("default.yml", "default"),
                       ("called.yml", "inside")}, problems
