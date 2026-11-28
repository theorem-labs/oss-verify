# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of review.yml's screen of pull requests and issues from accounts without write access:  python3 -m pytest
tests

route's trust step (who is screened, and the daily cap of .github/scripts/screened-review-cap), which jobs run for each
route and each answer of the screen (the jobs' conditions, evaluated as GitHub does), what the check review jobs
(review.yml's collector, collect) reports, the run's concurrency, what each job holds, how the screen
and the review take the gathered data (.github/scripts/take-review-data), the gather job's checks that the head did not
move, the gather job run step by step for an outside account's enrollment (the project's source, the failed fetch, the
session the review resumes, and the criticality score and OSS-Fuzz of the triage and the Build run's sizes as the job's
outputs), the comment job's hold, and the review comment's line on the checks that ran. Of
build.yaml (Build), whose completed run starts review.yml: its events and its concurrency, that its jobs hold none of
the review's identities and touch no cache, and that the daily cap holds none of them. .github/scripts/screen.py itself
is tested in test_screen.py."""
import copy
import datetime
import functools
import hashlib
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
from unittest import mock

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".github" / "scripts"
WORKFLOWS = ROOT / ".github" / "workflows"


@functools.cache
def parsed_workflow(name):
    # PyYAML's C parser when it is built, else its Python one: review.yml is long, and the C parser reads it many times
    # faster. Each file is parsed once per process, however many tests read it.
    return yaml.load((WORKFLOWS / name).read_text(), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))


def read_workflow(name):
    """The workflow file `name` of .github/workflows, parsed. Each call gives its own copy, so a test that changes
    what it got changes no other test's workflow."""
    return copy.deepcopy(parsed_workflow(name))


# Build builds a pull request on pull_request. Review, main's copy, reviews the pull request when the Build run
# completes (workflow_run), and an issue on its own events, and runs by hand.
BUILD = read_workflow("build.yaml")
BUILD_JOBS = BUILD["jobs"]
REVIEW = read_workflow("review.yml")
REVIEW_JOBS = REVIEW["jobs"]
REPO = "theorem-labs/oss-verify"

# gh api <endpoint> [--paginate] [--jq <filter>] [--method M] [-f|-F k=v] [--input -], answered from
# $FAKE_GH/<endpoint>.json (the endpoint's slashes as underscores; its query kept when a file is served for the endpoint
# with it, else dropped) through jq, as gh applies --jq; an endpoint with no file answers as GitHub's 404 does. Each
# call's arguments go to $FAKE_GH/args, and what it read on its standard input (--input -) to $FAKE_GH/input.<n>.
FAKE_GH = r"""#!/usr/bin/env bash
[ "$1" = api ] || { echo "gh: only api is served here: $*" >&2; exit 9; }
shift
all=("$@")
filter=. endpoint= input=
while [ $# -gt 0 ]; do
  case $1 in
    --paginate) shift ;;
    --jq) filter=$2; shift 2 ;;
    --input) input=$2; shift 2 ;;
    --method|-f|-F|-H) shift 2 ;;
    *) endpoint=$1; shift ;;
  esac
done
queried="$FAKE_GH/${endpoint//\//_}.json"
endpoint=${endpoint%%\?*}
printf '%s\0' "${all[@]}" >> "$FAKE_GH/args"; printf '\1' >> "$FAKE_GH/args"
n=$(tr -cd '\1' < "$FAKE_GH/args" | wc -c)
[ "$input" != - ] || cat > "$FAKE_GH/input.$n"
file="$FAKE_GH/${endpoint//\//_}.json"
[ ! -f "$queried" ] || file=$queried
[ -f "$file" ] || { echo "gh: Not Found (HTTP 404): $endpoint" >&2; exit 1; }
jq -r "$filter" "$file"
"""


def truthy(value):
    """An expression's value as a condition: null, false, '' and 0 are false."""
    return value not in (None, False, "", 0)


def equal(a, b):
    """== of two values: null is '', and strings compare without case."""
    a = "" if a is None else a
    b = "" if b is None else b
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b


@functools.cache
def compiled(expression):
    """The expression `expression`, parsed once into a function that evaluates it on a context. The tests evaluate the
    same few expressions on many contexts (one test about 98,000 times), so each is read once."""
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    tokens = re.findall(r"\s*('(?:[^']|'')*'|&&|\|\||==|!=|!|\(|\)|,|[0-9]+(?![A-Za-z_])|[A-Za-z_][A-Za-z0-9_.\-]*)", text)
    assert "".join(tokens).replace(" ", "") == re.sub(r"\s+", "", text), text
    toks = [t.strip() for t in tokens]
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take(want=None):
        t = toks[pos[0]]
        assert want is None or t == want, (t, want, text)
        pos[0] += 1
        return t

    def constant(value):
        return lambda ctx: value

    def primary():
        t = take()
        if t == "(":
            run = disjunction()
            take(")")
            return run
        if t == "!":
            operand = primary()
            return lambda ctx: not truthy(operand(ctx))
        if t.startswith("'"):
            return constant(t[1:-1].replace("''", "'"))
        if t.isdigit():
            return constant(int(t))
        if t in ("true", "false"):
            return constant(t == "true")
        if t == "null":
            return constant(None)
        if peek() == "(":
            take("(")
            args = []
            while peek() != ")":
                args.append(disjunction())
                if peek() == ",":
                    take(",")
            take(")")
            if t == "format":
                def formatted(ctx):
                    values = [arg(ctx) for arg in args]
                    return re.sub(r"\{(\d+)\}", lambda m: as_text(values[1 + int(m.group(1))]), values[0])
                return formatted
            assert t in ("cancelled", "always") and not args, "no such function here: " + t
            return constant(t == "always")
        return lambda ctx: ctx.get(t)

    # Each chain of one operator is a list of its operands, evaluated in a loop: a function nested for each operator
    # would make a long chain deeper than Python's recursion limit.
    def comparison():
        first, rest = primary(), []
        while peek() in ("==", "!="):
            rest.append((take(), primary()))
        if not rest:
            return first

        def run(ctx):
            v = first(ctx)
            for op, operand in rest:
                w = operand(ctx)
                v = equal(v, w) if op == "==" else not equal(v, w)
            return v
        return run

    def conjunction():
        operands = [comparison()]
        while peek() == "&&":
            take()
            operands.append(comparison())
        if len(operands) == 1:
            return operands[0]

        def run(ctx):
            v = operands[0](ctx)
            for operand in operands[1:]:
                w = operand(ctx)
                v = w if truthy(v) else v
            return v
        return run

    def disjunction():
        operands = [conjunction()]
        while peek() == "||":
            take()
            operands.append(conjunction())
        if len(operands) == 1:
            return operands[0]

        def run(ctx):
            v = operands[0](ctx)
            for operand in operands[1:]:
                w = operand(ctx)
                v = v if truthy(v) else w
            return v
        return run

    run = disjunction()
    assert pos[0] == len(toks), (toks[pos[0]:], text)
    return run


def evaluate(expression, ctx):
    """A GitHub Actions expression, with or without ${{ }}, as GitHub evaluates it for what these tests need: string,
    whole number, boolean and null literals, contexts looked up whole in ctx (a missing one is null), == and !=
    (strings compared without case), !, && and || (which give an operand, not a boolean), parentheses, and the
    functions format, cancelled and always. cancelled() is false: these tests run no cancelled run."""
    return compiled(str(expression))(ctx)


def as_text(v):
    """A value as an env or output gets it."""
    return "true" if v is True else "false" if v is False else "" if v is None else str(v)


STATUS_FUNCTIONS = re.compile(r"\b(cancelled|always|success|failure)\(\)")
# Each workflow's jobs, by the workflow's name, each after every job it needs. The last is the workflow's collector.
ORDERS = {"Review": ["route", "gather", "screen", "review", "session", "hold", "comment", "triage-gather", "triage",
                     "collect"],
          "Build": ["route", "project-builds", "record", "results", "required"]}
# review.yml route's outputs for each kind of item: pull request 7 at its head (an enrollment with the Build run whose
# results the gather job reads), and issue 9.
ITEMS = {"enrollment": {"kind": "enrollment", "pr": "7", "sha": "a" * 40, "build_run": "900"},
         "change": {"kind": "change", "pr": "7", "sha": "a" * 40},
         "issue": {"kind": "issue", "issue": "9"}}


def run_graph(route, results=None, outputs=None, event="workflow_run", workflow=REVIEW, ref=None):
    """The result of each job of `workflow`, as GitHub decides it: a job runs when its if is true, and an if with no
    status function also needs every job it needs to have succeeded (GitHub's implicit success()). route is route's
    outputs; results and outputs give a job that runs another result than success, and its outputs. A job that did not
    succeed has no outputs unless they are given. ref is the run's github.ref, when a test gives it (a run by hand runs
    on the branch it was started on). A job's condition sees only the jobs in its direct needs. Return (results, the
    context of all jobs)."""
    results, outputs = dict(results or {}), dict(outputs or {})
    jobs, order = workflow["jobs"], ORDERS[workflow["name"]]
    assert set(order) == set(jobs), set(jobs)
    ctx = {"github.event_name": event}
    if ref is not None:
        ctx["github.ref"] = ref
    got = {}
    defaults = {"project-builds": {"name": "libx", "sha": "a" * 40},
                "gather": {"digest": "d" * 64, "screen": "true" if route.get("trust") == "screen" else "false",
                           "name": "libx" if route.get("kind") == "enrollment" else ""},
                "review": {"comment": "Thanks.", "held_object": "", "session": "", "kind": route.get("kind", "")}}
    for name in order:
        job = jobs[name]
        if name == "route":
            ran = True
        else:
            needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
            condition = job.get("if")
            visible = {key: value for key, value in ctx.items()
                       if not key.startswith("needs.") or key.split(".", 2)[1] in needs}
            ran = condition is None or bool(evaluate(condition, visible))
            if condition is None or not STATUS_FUNCTIONS.search(str(condition)):
                ran = ran and all(got[n] == "success" for n in needs)
        got[name] = results.get(name, "success") if ran else "skipped"
        out = (route if name == "route" else outputs.get(name, defaults.get(name, {}))
               if ran and (got[name] == "success" or name in outputs) else {})
        ctx[f"needs.{name}.result"] = got[name]
        for key, value in out.items():
            ctx[f"needs.{name}.outputs.{key}"] = value
    return got, ctx


COLLECT = "Every job route asked for passed, and no other ran"


def required(ctx, workflow=REVIEW):
    """What the collector's step answers for this run, review.yml's collect (the check review jobs) or build.yaml's
    required (the required check project-builds): (exit status, output)."""
    collector = step(ORDERS[workflow["name"]][-1], COLLECT, workflow)
    env = {k: as_text(evaluate(v, ctx)) for k, v in collector["env"].items()}
    # Each "job:$RESULT:$ASKED" argument, with its values.
    args = []
    for word in re.findall(r'"([^"]+)"', collector["run"]):
        args.append(re.sub(r"\$([A-Z_]+)", lambda m: env[m.group(1)], word))
    run = subprocess.run([str(SCRIPTS / "collect"), *args], capture_output=True, text=True,
                         env={**os.environ, "GITHUB_STEP_SUMMARY": os.devnull})
    return run.returncode, run.stdout


def step(job, name, workflow=REVIEW):
    found = [s for s in workflow["jobs"][job]["steps"] if s.get("name") == name]
    assert len(found) == 1, f"{len(found)} steps named {name!r} in {job}"
    return found[0]


def comment_job_env(ctx):
    """The comment job's own env (KIND, APPROVE, HOLDING, RECORD), as its expressions give it for the run of ctx."""
    return {k: as_text(evaluate(v, ctx)) for k, v in REVIEW_JOBS["comment"]["env"].items() if "${{" in str(v)}


def interpolated(value, ctx):
    """A value with ${{ }} expressions in its text, as the runner gives it for ctx."""
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: as_text(evaluate(m.group(1), ctx)), value)


def step_env(job, s, **given):
    """The env review.yml's step s of the job `job` runs with: the workflow's, the job's and the step's own, each over
    the one before, with `given` in place of the workflow's."""
    return {**REVIEW["env"], **given, **REVIEW_JOBS[job].get("env", {}), **s.get("env", {})}


def screen_script():
    """.github/scripts/screen.py, loaded as a module as test_screen.py loads it."""
    spec = importlib.util.spec_from_file_location("screen", SCRIPTS / "screen.py")
    screen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(screen)
    return screen


def outputs_of(path):
    """The name=value pairs a step wrote to GITHUB_OUTPUT."""
    got = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            got[name] = value
    return got


class Runner(unittest.TestCase):
    """A temporary directory with a stand-in gh at the front of PATH, the API answers it serves, a runner temporary
    directory and a GITHUB_OUTPUT."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="screen-workflow-test-")
        self.dir = pathlib.Path(self._tmp.name)
        self.api, self.temp, self.work, bin_dir = (self.dir / n for n in ("api", "temp", "work", "bin"))
        for d in (self.api, self.temp, self.work, bin_dir):
            d.mkdir()
        (bin_dir / "gh").write_text(FAKE_GH)
        (bin_dir / "gh").chmod(0o755)
        self.output = self.dir / "output"
        self.env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        self.env.update(PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", FAKE_GH=str(self.api), REPO=REPO,
                        GH_TOKEN="stand-in", RUNNER_TEMP=str(self.temp), GITHUB_OUTPUT=str(self.output),
                        GITHUB_STEP_SUMMARY=os.devnull,
                        **{k: str(v) for k, v in REVIEW["env"].items()})

    def tearDown(self):
        self._tmp.cleanup()

    def serve(self, endpoint, data):
        (self.api / (endpoint.replace("/", "_") + ".json")).write_text(json.dumps(data))

    def permissions(self, **logins):
        """Serve GitHub's collaborator permission answer for each login; a login not given is a 404."""
        for login, permission in logins.items():
            self.serve(f"repos/{REPO}/collaborators/{login}/permission", {"permission": permission})

    def calls(self):
        path = self.api / "args"
        if not path.exists():
            return []
        return [c.split("\0")[:-1] for c in path.read_text().split("\1")[:-1]]

    def run_script(self, script, cwd=None, **env):
        self.output.write_text("")
        path = self.dir / "step.sh"
        path.write_text(script)
        r = subprocess.run(["bash", "--noprofile", "--norc", "-e", str(path)], cwd=cwd or self.work,
                           env=dict(self.env, **env), capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr, outputs_of(self.output)


class Trust(Runner):
    """route's trust step: whose pull request or issue is reviewed as it comes, and whose is screened first."""

    STEP = "Whether the author and the account that started the run have write access"

    def trust(self, event, author="", actor="", measure="", number=""):
        """Run the trust step for an event's run, or a run by hand (workflow_dispatch) of item `number`, whose author
        the API gives as `author`. The daily cap reads the runs and the artifacts a test serves, or none."""
        runs = f"repos/{REPO}/actions/workflows/review.yml/runs"
        if not (self.api / (runs.replace("/", "_") + ".json")).exists():
            self.serve(runs, {"workflow_runs": []})
            self.serve(f"repos/{REPO}/actions/artifacts", {"artifacts": []})
        if event == "workflow_dispatch" and number:
            self.serve(f"repos/{REPO}/issues/{number}", {"number": int(number), "user": {"login": author}})
            author = ""
        return self.run_script(step("route", self.STEP)["run"], cwd=ROOT, EVENT=event, AUTHOR=author, ACTOR=actor,
                               RUN_ID="1000", MEASURE=measure, NUMBER=number)

    def assertTrust(self, want, *args, **kwargs):
        rc, out, got = self.trust(*args, **kwargs)
        self.assertEqual((rc, got.get("trust")), (0, want), out)
        # When it decided, which the comment job compares with the time of a hold.
        self.assertRegex(got.get("started", ""), r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
        return out

    def test_writers_are_reviewed_as_they_come(self):
        self.permissions(alice="write", root="admin")
        for event in ("workflow_run", "issues"):
            self.assertTrust("writer", event, "alice", "root")

    def test_an_account_without_write_access_is_screened_with_no_maintainer(self):
        self.permissions(alice="write", mallory="read", tess="triage", nobody="none")
        for author, actor in (("mallory", "mallory"), ("nobody", "nobody"), ("tess", "tess"),
                              ("alice", "mallory"), ("mallory", "alice")):
            with self.subTest(author=author, actor=actor):
                self.assertTrust("screen", "workflow_run", author, actor)
        self.assertTrust("screen", "issues", "mallory", "mallory")

    def test_the_organisations_apps_count_and_others_are_screened(self):
        self.assertTrust("writer", "workflow_run", "sjawhar-agent[bot]", "sjawhar-agent[bot]")
        self.assertTrust("writer", "workflow_run", "oss-verify[bot]", "oss-verify[bot]")
        self.assertTrust("screen", "workflow_run", "dependabot[bot]", "dependabot[bot]")

    def test_a_run_by_hand_of_a_writers_item_is_a_writers(self):
        self.permissions(alice="write", root="admin")
        self.assertTrust("writer", "workflow_dispatch", "alice", "root", number="7")
        # The daily cap reads nothing for a writer's item.
        self.assertEqual([c for c in self.calls() if "actions/workflows/review.yml/runs" in " ".join(c)], [])

    def test_a_run_by_hand_of_an_outsiders_item_is_screened(self):
        """c1 (e3): an account with write access starts the review of an outside account's pull request by hand. The
        item's author decides, as on an event: the run is screened, the daily cap counts it, and the screen job runs
        before the review."""
        self.permissions(alice="write", mallory="read")
        out = self.assertTrust("screen", "workflow_dispatch", "mallory", "alice", number="7")
        self.assertIn([f"repos/{REPO}/issues/7", "--jq", '.user.login // ""'], self.calls())
        self.assertTrue([c for c in self.calls() if f"repos/{REPO}/actions/workflows/review.yml/runs" in c], out)
        self.assertIn("charged to mallory", out)
        got, _ctx = run_graph(dict(ITEMS["enrollment"], trust="screen"),
                              outputs={"screen": {"verdict": "clean", "checks": "model_armor"}},
                              event="workflow_dispatch", ref="refs/heads/main")
        self.assertEqual((got["gather"], got["screen"], got["review"]), ("success", "success", "success"))

    def test_a_run_by_hand_whose_item_github_does_not_give_stops_the_run(self):
        rc, out, got = self.run_script(step("route", self.STEP)["run"], cwd=ROOT, EVENT="workflow_dispatch",
                                       AUTHOR="", ACTOR="alice", RUN_ID="1000", MEASURE="", NUMBER="7")
        self.assertEqual((rc, got.get("trust")), (1, None), out)
        self.assertIn("GitHub did not say who wrote 7. Re-run this run.", out)

    def test_a_writer_can_measure_the_screen(self):
        self.assertTrust("measure", "workflow_dispatch", "", "alice", measure="true")
        self.assertTrust("measure", "workflow_dispatch", "", "sjawhar-agent[bot]", measure="true")
        rc, out, got = self.trust("workflow_dispatch", "", "dependabot[bot]", measure="true")
        self.assertEqual((rc, got.get("trust")), (0, None), out)
        # only by hand: an event has no measure input
        self.permissions(mallory="read")
        self.assertTrust("screen", "issues", "mallory", "mallory", measure="true")

    def test_route_asks_for_a_measurement_alone(self):
        decide = step("route", "An enrollment, a change or an issue")
        for pr, issue, want in (("", "", (0, "true")), ("7", "", (1, None)), ("", "5", (1, None))):
            with self.subTest(pr=pr, issue=issue):
                rc, out, got = self.run_script(decide["run"], EVENT="workflow_dispatch", REF="refs/heads/main",
                                               MEASURE="true", PR=pr, ISSUE=issue, ACTOR="alice", SENDER="alice",
                                               AUTHOR="", ASSOCIATION="")
                self.assertEqual((rc, got.get("measure")), want, out)
                self.assertNotIn("kind", got)
        # A measurement passes the trust step, and so does every item of a kind; a run with neither does not.
        for outputs, want in (({"measure": "true"}, True), ({"kind": "enrollment"}, True), ({}, False)):
            ctx = {f"steps.decide.outputs.{k}": v for k, v in outputs.items()}
            self.assertEqual(bool(evaluate(step("route", self.STEP)["if"], ctx)), want, outputs)

    def test_a_permission_github_does_not_give_stops_the_run(self):
        rc, out, got = self.trust("workflow_run", "alice", "alice")
        self.assertEqual((rc, got.get("trust")), (1, None), out)
        self.assertIn("did not say whether alice has write access", out)

    def test_a_login_that_is_not_one_is_never_a_writer(self):
        self.permissions(**{"a": "admin"})
        self.assertTrust("screen", "issues", "a/../b", "a/../b")
        self.assertTrust("screen", "issues", "x[bot][bot]", "a")


class DailyCap(Runner):
    """The daily cap: .github/scripts/screened-review-cap with a stand-in runs and artifacts API, and route's trust
    step, which calls it for every item whose trust is screen (c3 (c)-(f))."""

    STEP = Trust.STEP
    NOW = "2026-11-09T12:00:00Z"
    CAP, AUTHOR_CAP = int(REVIEW["env"]["REVIEW_CAP"]), int(REVIEW["env"]["REVIEW_CAP_AUTHOR"])
    # A run's state, as (its status, its artifact daily-cap-route, its artifact daily-cap-screen): each artifact True,
    # False (none) or "expired".
    SCREENED = ("completed", True, True)  # route gave it trust screen, and its screen job signed in
    GATHERING = ("in_progress", True, False)  # route gave it trust screen, and its screen job has not signed in yet
    UNSTARTED = ("completed", True, False)  # it ended before its screen job signed in: cancelled, or refused
    UNMARKED = ("completed", False, False)  # route gave it no trust screen: capped, a writer's trust
    MEASURED = ("completed", False, True)  # a screen job with no trust screen: a measurement

    def setUp(self):
        super().setUp()
        self.env["NOW"] = self.NOW
        self.permissions(alice="write", mallory="read", eve="read", zed="read", **{f"o{i}": "read" for i in range(120)})

    @classmethod
    def at(cls, hours):
        """The time `hours` before NOW, as GitHub writes it."""
        now = datetime.datetime.strptime(cls.NOW, "%Y-%m-%dT%H:%M:%SZ")
        return (now - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def freed(self, hours):
        """The time a run made `hours` before NOW leaves the 24 hours."""
        return self.at(hours - 24)

    def runs(self, *runs):
        """Serve review.yml's runs and the artifacts that mark them for the daily cap. Each run is (id, hours before
        NOW it was made, event, actor, its state (above)[, its name])."""
        self.serve(f"repos/{REPO}/actions/workflows/review.yml/runs", {"workflow_runs": [
            {"id": r[0], "created_at": self.at(r[1]), "status": r[4][0], "event": r[2], "actor": {"login": r[3]},
             "display_title": r[5] if len(r) > 5 else "Review of run 900"} for r in runs]})
        for i, name in ((1, "daily-cap-route"), (2, "daily-cap-screen")):
            self.serve(f"repos/{REPO}/actions/artifacts?name={name}&per_page=100", {"artifacts": [
                {"id": r[0] * 10 + i, "name": name, "expired": r[4][i] == "expired", "workflow_run": {"id": r[0]}}
                for r in runs if r[4][i]]})

    @classmethod
    def screened(cls, n, first=10, account=None, hours=0.5, start=0.0, event="workflow_run", state=None):
        """n runs that ran the screen, each `hours` before the one after it, the newest `start` + `hours` before NOW:
        each by an outside account of its own (o<i>), or all by `account`."""
        return [(first + i, start + hours * (i + 1), event, account or f"o{i}", state or cls.SCREENED)
                for i in range(n)]

    def cap(self, account):
        """screened-review-cap for a run charged to `account`: its exit status, its log and what it printed."""
        rc, out, _ = self.run_script(str(SCRIPTS / "screened-review-cap"), RUN_ID="1000", ACCOUNT=account)
        return rc, out, dict(re.findall(r"^(count|account_count|capped|free)=(.*)$", out, re.M))

    def route(self, event, author, actor, number=""):
        """route's trust step: its trust and free outputs."""
        rc, out, got = Trust.trust(self, event, author, actor, number=number)
        self.assertEqual(rc, 0, out)
        return got.get("trust"), got.get("free")

    def read(self, suffix):
        """The endpoints of the stand-in gh's calls that end with `suffix`."""
        return [a for c in self.calls() for a in c if a.endswith(suffix)]

    def assertNoJobsRead(self):
        self.assertEqual([a for c in self.calls() for a in c if "/jobs" in a], [])

    def test_the_25th_over_all_authors_is_capped_until_the_oldest_leaves(self):
        """c3 (c): 24 counted runs of 24 outside accounts in 24 hours. A 25th, by a new account, gets trust cap: no
        gather, no screen and no review; the comment job holds it. Its free time is when the oldest counted run is 24
        hours old. The 24th was allowed."""
        self.runs(*self.screened(self.CAP))
        rc, out, got = self.cap("zed")
        self.assertEqual((rc, got), (0, {"count": "24", "account_count": "0", "capped": "true",
                                         "free": self.freed(12)}), out)
        self.assertEqual(self.route("workflow_run", "zed", "zed"), ("cap", self.freed(12)))
        got, ctx = run_graph(dict(ITEMS["enrollment"], trust="cap", free=self.freed(12)))
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "collect"}, {"comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        self.runs(*self.screened(self.CAP - 1))
        self.assertEqual(self.route("workflow_run", "zed", "zed"), ("screen", ""))

    def test_the_13th_of_one_author_is_capped(self):
        """c3 (d): one outside account's 12 earlier counted runs are the 12 of the 24 hours. Its 13th gets trust cap,
        free when its oldest counted run is 24 hours old; another account's run is screened."""
        self.runs(*self.screened(self.AUTHOR_CAP, account="mallory"))
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (0, {"count": "12", "account_count": "12", "capped": "true",
                                         "free": self.freed(6)}), out)
        self.assertEqual(self.route("workflow_run", "mallory", "mallory"), ("cap", self.freed(6)))
        self.assertEqual(self.cap("eve")[2], {"count": "12", "account_count": "0", "capped": "false", "free": ""})
        self.assertEqual(self.route("workflow_run", "eve", "eve"), ("screen", ""))

    def test_the_12th_of_one_author_is_reviewed(self):
        """c3 (e): with 11 earlier counted runs of one account, its 12th is screened, and a clean screen reviews it."""
        self.runs(*self.screened(self.AUTHOR_CAP - 1, account="mallory"))
        self.assertEqual(self.cap("mallory")[2], {"count": "11", "account_count": "11", "capped": "false", "free": ""})
        self.assertEqual(self.route("workflow_run", "mallory", "mallory"), ("screen", ""))
        got, _ = run_graph(dict(ITEMS["enrollment"], trust="screen"),
                           outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertEqual((got["screen"], got["review"], got["comment"]), ("success", "success", "success"))

    def test_an_outsiders_issue_that_is_the_25th_is_capped(self):
        """c3 (f): pull requests and issues share the cap. The 25th, an issue's own event, gets trust cap: no screen and
        no model; the comment job alone runs and holds the issue
        (Routes.test_at_the_daily_cap_it_is_held_without_a_screen for the jobs, Hold, below, for its words)."""
        self.runs(*self.screened(12), *self.screened(12, first=40, start=6, event="issues"))
        self.assertEqual(self.route("issues", "zed", "zed"), ("cap", self.freed(12)))

    def test_the_time_it_frees_is_the_later_of_the_two(self):
        # The account's 12 are the newest of 24: its oldest leaves after the oldest of all.
        self.runs(*self.screened(12, account="mallory"), *self.screened(12, first=40, start=12))
        self.assertEqual(self.cap("mallory")[2], {"count": "24", "account_count": "12", "capped": "true",
                                                  "free": self.freed(6)})
        # The account's 12 are the oldest of 30: the total needs 7 to leave, the account 1.
        self.runs(*self.screened(12, account="mallory", start=12), *self.screened(18, first=40))
        self.assertEqual(self.cap("mallory")[2], {"count": "30", "account_count": "12", "capped": "true",
                                                  "free": self.freed(15)})

    def test_only_earlier_screened_runs_of_outside_accounts_in_24_hours_count(self):
        self.runs((10, 25, "workflow_run", "o0", self.SCREENED),  # over 24 hours old
                  (11, 1, "workflow_run", "o1", self.UNMARKED),  # no trust screen: capped, or a writer's trust
                  (12, 1, "workflow_run", "alice", self.SCREENED),  # a writer's push to an outsider's item
                  (13, 1, "issues", "sjawhar-agent[bot]", self.SCREENED),  # an App of ALLOWED_BOTS
                  (14, 1, "workflow_dispatch", "alice", self.MEASURED, "Measure the screen"),  # a measurement
                  (1000, 1, "workflow_run", "o2", self.SCREENED),  # this run
                  (1001, 1, "workflow_run", "o3", self.SCREENED),  # a later run
                  (18, 1, "workflow_run", "o4", ("completed", True, "expired")),  # its mark expired
                  (19, 1, "workflow_run", "o5", ("completed", "expired", True)),
                  (15, 2, "workflow_run", "mallory", self.SCREENED),
                  (16, 3, "issues", "mallory", self.GATHERING),  # its screen has not started yet
                  (17, 4, "workflow_run", "mallory", self.SCREENED))
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (0, {"count": "3", "account_count": "3", "capped": "false", "free": ""}), out)
        # Each artifact list is read once, no run's jobs, and one permission read for each account a marked run is
        # charged to.
        self.assertEqual(self.read("&per_page=100"), [f"repos/{REPO}/actions/artifacts?name=daily-cap-{n}&per_page=100"
                                                      for n in ("route", "screen")])
        self.assertNoJobsRead()
        self.assertEqual(sorted(self.read("/permission")), sorted(f"repos/{REPO}/collaborators/{a}/permission"
                                                              for a in ("alice", "mallory")))

    def test_a_run_counts_from_routes_mark_until_it_ends_without_a_screen(self):
        """A run counts once route gave it trust screen (daily-cap-route), while it has not completed, and once it
        has, only when its screen job signed in (daily-cap-screen): a run whose gather job kept nothing (the head
        moved), a run that was cancelled, and a refused sign-in each end it before its screen. A run that route gave no
        trust screen never counts, whatever ran."""
        self.runs((20, 1, "workflow_run", "mallory", self.UNSTARTED),
                  (21, 2, "workflow_run", "mallory", self.SCREENED),
                  (22, 3, "workflow_run", "mallory", self.GATHERING),
                  (23, 4, "issues", "mallory", ("queued", True, False)),
                  (24, 5, "workflow_run", "mallory", self.UNMARKED),
                  (25, 6, "workflow_run", "mallory", self.MEASURED),
                  (26, 7, "workflow_run", "mallory", ("in_progress", False, False)))
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (0, {"count": "3", "account_count": "3", "capped": "false", "free": ""}), out)
        # A burst: 24 items whose runs have not screened yet cap the 25th.
        self.runs(*self.screened(self.CAP, hours=0.01, state=self.GATHERING))
        self.assertEqual(self.route("workflow_run", "zed", "zed"), ("cap", self.freed(0.01 * self.CAP)))
        self.assertNoJobsRead()

    def test_a_run_by_hand_is_charged_to_the_items_author(self):
        """A person's re-runs use up the author's share, never the starter's."""
        self.serve(f"repos/{REPO}/issues/9", {"user": {"login": "eve"}})
        self.serve(f"repos/{REPO}/issues/7", {"user": {"login": "mallory"}})
        self.runs(*[(20 + i, 0.5 * (i + 1), "workflow_dispatch", "alice", self.SCREENED, "Pull request 7")
                    for i in range(11)], (40, 7, "workflow_dispatch", "sjawhar-agent[bot]", self.SCREENED, "Issue 9"))
        self.assertEqual(self.cap("mallory")[2], {"count": "12", "account_count": "11", "capped": "false", "free": ""})
        self.assertEqual(self.cap("alice")[2]["account_count"], "0")
        self.assertEqual(self.read(f"repos/{REPO}/issues/7"), [f"repos/{REPO}/issues/7"] * 2)  # once per count
        # The 12th run of #7, by hand: charged to mallory, who reached the 12.
        self.runs(*[(20 + i, 0.5 * (i + 1), "workflow_dispatch", "alice", self.SCREENED, "Pull request 7")
                    for i in range(12)])
        self.assertEqual(self.route("workflow_dispatch", "mallory", "alice", number="7"), ("cap", self.freed(6)))

    def test_an_events_run_is_charged_to_the_account_that_started_it(self):
        """A writer's push to an outside account's pull request is screened, charged to the writer: the author's 12
        do not hold it, the total of 24 does."""
        self.runs(*self.screened(12, account="mallory"))
        self.assertEqual(self.route("workflow_run", "mallory", "alice"), ("screen", ""))
        self.runs(*self.screened(24))
        self.assertEqual(self.route("workflow_run", "mallory", "alice"), ("cap", self.freed(12)))

    def test_a_count_it_cannot_finish_fails_route(self):
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (1, {}), out)
        self.assertIn("::error::GitHub did not give this workflow's runs of the last 24 hours. Re-run this run.", out)
        artifacts = f"repos_{REPO.replace('/', '_')}_actions_artifacts?name=daily-cap-%s&per_page=100.json"
        for run, said in (((15, 1, "workflow_run", "o200", self.SCREENED),
                           "GitHub did not say whether o200 has write access. Re-run this run."),
                          ((15, 1, "workflow_dispatch", "alice", self.SCREENED, "Pull request 8"),
                           "GitHub did not say who wrote 8. Re-run this run."),
                          ((15, 1, "workflow_run", "o1", self.SCREENED),
                           "GitHub did not give the artifacts daily-cap-route. Re-run this run."),
                          ((15, 1, "workflow_run", "o1", self.SCREENED),
                           "GitHub did not give the artifacts daily-cap-screen. Re-run this run.")):
            with self.subTest(said=said):
                self.runs(run)
                for name in ("route", "screen"):
                    if f"daily-cap-{name}." in said:
                        self.api.joinpath(artifacts % name).unlink()
                rc, out, got = self.cap("mallory")
                self.assertEqual((rc, got), (1, {}), out)
                self.assertIn(f"::error::{said}", out)
                # route fails with it: no trust, so no screen and no review.
                rc, out, got = Trust.trust(self, "workflow_run", "mallory", "mallory")
                self.assertEqual((rc, got.get("trust")), (1, None), out)
                self.assertIn(f"::error::{said}", out)

    def test_150_runs_of_one_account_are_counted_with_no_jobs_read(self):
        """However many runs one account makes, the count reads no run's jobs and has no ceiling that fails route:
        it caps."""
        self.runs(*self.screened(150, account="mallory", hours=0.1))
        rc, out, got = self.cap("zed")
        self.assertEqual((rc, got), (0, {"count": "150", "account_count": "0", "capped": "true",
                                         "free": self.freed(0.1 * 24)}), out)
        self.assertEqual(self.route("workflow_run", "zed", "zed"), ("cap", self.freed(0.1 * 24)))
        self.assertEqual(self.route("workflow_run", "mallory", "mallory"), ("cap", self.freed(0.1 * 12)))
        self.assertNoJobsRead()

    # What the sign-ins of screen.py --sign-in read, besides GitHub's identity token request, which the runner gives
    # every step of a job with id-token: write.
    SIGN_IN_SETTINGS = ("SCREEN_CHECKS", "AZURE_LOGIN_URL", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "ANTHROPIC_URL",
                        "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID",
                        "ANTHROPIC_WORKSPACE_ID")

    def test_route_marks_a_screened_run_and_the_screen_job_marks_itself_after_its_sign_ins(self):
        """The marks the count reads: route keeps daily-cap-route for trust screen alone, from the file its trust step
        writes then, and the screen job keeps daily-cap-screen in the two steps right after "Sign in to the screen's
        services", which comes right after "Sign in to Google Cloud", whatever the job does next (OSSV-679's plan,
        decision 12). A sign-in to Google, Microsoft Entra or Anthropic that is refused fails the job before them: such
        a run ended before its screen, and the count does not count it. The sign-ins of the second step are the Screen
        step's, with the same settings. A measurement does not run that step: the Measure step records a sign-in that
        is refused as the error of that check (screen.py, measure)."""
        mark = step("route", "Mark this run for the daily cap")
        for trust in ("screen", "writer", "cap", "measure", ""):
            self.assertEqual(evaluate(mark["if"], {"steps.trust.outputs.trust": trust}), trust == "screen", trust)
        self.assertEqual((mark["with"]["name"], mark["with"]["path"]),
                         ("daily-cap-route", "${{ runner.temp }}/daily-cap"))
        for author, trust in (("mallory", "screen"), ("alice", "writer")):
            self.temp.joinpath("daily-cap").unlink(missing_ok=True)
            self.assertEqual(Trust.trust(self, "workflow_run", author, author)[2]["trust"], trust)
            self.assertEqual(self.temp.joinpath("daily-cap").exists(), trust == "screen", author)
        steps = REVIEW_JOBS["screen"]["steps"]
        names = [s.get("name") or s["uses"].split("@")[0] for s in steps]
        google = names.index("Sign in to Google Cloud")
        sign_in = names.index("Sign in to the screen's services")
        self.assertNotIn("if", steps[google])
        for trust in ("screen", "writer", "measure"):
            self.assertEqual(bool(evaluate(steps[sign_in]["if"], {"needs.route.outputs.trust": trust})),
                             trust != "measure", trust)
        for name in ("Sign in to Google Cloud", "Sign in to the screen's services"):
            self.assertNotIn("continue-on-error", steps[names.index(name)], name)
        # The settings come from the job's env, which the Screen and Measure steps read too: neither those steps nor
        # this one sets one of its own.
        self.assertNotIn("env", steps[sign_in])
        for setting in self.SIGN_IN_SETTINGS:
            self.assertIn(setting, REVIEW_JOBS["screen"]["env"])
            for name in ("Screen", "Measure"):
                self.assertNotIn(setting, step("screen", name).get("env", {}), name)
        write, upload = steps[sign_in + 1:sign_in + 3]
        self.assertLess(sign_in + 2, min(names.index("Screen"), names.index("Measure")))
        self.assertNotIn("if", write)
        self.assertNotIn("if", upload)
        self.assertEqual((upload["uses"].split("@")[0], upload["with"]["name"], upload["with"]["path"]),
                         ("actions/upload-artifact", "daily-cap-screen", "${{ runner.temp }}/daily-cap"))
        subprocess.run(["bash", "-e", "-c", write["run"]], check=True,
                       env={**os.environ, "GITHUB_RUN_ID": "1000", "RUNNER_TEMP": str(self.dir)})
        self.assertEqual(self.dir.joinpath("daily-cap").read_text(), "1000\n")


class Routes(unittest.TestCase):
    """Which jobs run, for each trust and each answer of the screen, and what the check review jobs reports."""

    def ran(self, route, results=None, outputs=None, **run):
        got, ctx = run_graph(route, results, outputs, **run)
        return {n for n, r in got.items() if r != "skipped"} - {"route", "collect"}, ctx

    ENROLLMENT = ITEMS["enrollment"]

    def test_a_writers_item_is_reviewed_without_a_screen(self):
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="writer"))
        self.assertEqual(jobs, {"gather", "review", "hold", "comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        self.assertEqual(evaluate(REVIEW_JOBS["comment"]["env"]["HOLDING"], ctx), False)

    def test_an_outsiders_clean_item_is_reviewed_with_no_maintainer(self):
        for kind in ("enrollment", "change", "issue"):
            with self.subTest(kind=kind):
                jobs, ctx = self.ran(dict(ITEMS[kind], trust="screen"),
                                     outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
                self.assertTrue({"gather", "screen", "review"} <= jobs, jobs)
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_an_outsiders_held_item_gets_no_review_and_is_held(self):
        for verdict in ("held", "", "suspicious", "CLEAN?"):
            with self.subTest(verdict=verdict):
                jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), outputs={"screen": {"verdict": verdict}})
                self.assertEqual(jobs, {"gather", "screen", "comment"})
                self.assertEqual(evaluate(REVIEW_JOBS["comment"]["env"]["HOLDING"], ctx), True)
                code, out = required(ctx)
                self.assertEqual(code, 0, out)

    def test_at_the_daily_cap_it_is_held_without_a_screen(self):
        """Every kind: the comment job alone. The cap holds the review, never the build: the Build run of an
        enrollment, whose route gives no trust, builds it, records it and keeps its results whatever the cap."""
        for kind in ("enrollment", "change", "issue"):
            with self.subTest(kind=kind):
                jobs, ctx = self.ran(dict(ITEMS[kind], trust="cap"))
                self.assertEqual(jobs, {"comment"})
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        got, ctx = run_graph({"build": "true"}, event="pull_request", workflow=BUILD)
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"},
                         {"project-builds", "record", "results"})
        self.assertEqual(required(ctx, BUILD)[0], 0, required(ctx, BUILD)[1])

    def test_at_the_daily_cap_gather_screen_and_review_run_nothing(self):
        """gather, screen and review each name the daily cap themselves, whatever the gather and the screen gave, and
        the job collect asks for each on its own job's condition."""
        collect = step("collect", COLLECT)["env"]
        ctx = {"needs.route.result": "success", "needs.route.outputs.kind": "enrollment",
               "needs.route.outputs.build_run": "900", "needs.gather.outputs.name": "libx",
               "needs.gather.result": "success", "needs.gather.outputs.digest": "d" * 64,
               "needs.gather.outputs.screen": "true", "needs.screen.result": "success",
               "needs.screen.outputs.verdict": "clean", "needs.route.outputs.trust": "cap",
               "github.event_name": "workflow_run"}
        for job, asked in (("gather", "ASKED_GATHER"), ("screen", "ASKED_SCREEN"), ("review", "ASKED_REVIEW")):
            self.assertFalse(evaluate(REVIEW_JOBS[job]["if"], ctx), job)
            self.assertFalse(evaluate(collect[asked], ctx), asked)
        # The same condition in each pair, over every route and gather the jobs can see: the item's kind, its Build
        # run or its held head, and a run by hand on main or on another branch.
        for route, trust, (kind, build_run, held), gathered, screen, (event, ref) in itertools.product(
                ("success", "failure"), ("", "writer", "screen", "cap", "measure"),
                (("enrollment", "900", ""), ("enrollment", "", "true"), ("enrollment", "", ""), ("change", "", ""),
                 ("change", "", "true"), ("issue", "", ""), ("", "", "")),
                ("success", "failure", "skipped"), ("true", "false"),
                (("workflow_run", "refs/heads/main"), ("workflow_dispatch", "refs/heads/main"),
                 ("workflow_dispatch", "refs/heads/other"))):
            ctx = {"needs.route.result": route, "needs.route.outputs.trust": trust,
                   "needs.route.outputs.kind": kind, "needs.route.outputs.build_run": build_run,
                   "needs.route.outputs.held": held, "needs.gather.result": gathered,
                   "needs.gather.outputs.digest": "d" * 64 if gathered == "success" else "",
                   "needs.gather.outputs.screen": screen, "github.event_name": event, "github.ref": ref}
            for job, asked in (("gather", "ASKED_GATHER"), ("screen", "ASKED_SCREEN")):
                self.assertEqual(bool(evaluate(REVIEW_JOBS[job]["if"], ctx)), bool(evaluate(collect[asked], ctx)),
                                 (job, ctx))

    def test_a_route_that_failed_after_it_gave_trust_screen_gathers_screens_and_reviews_nothing(self):
        """route's trust step gives trust screen and then the step that keeps the daily cap's mark fails: route fails,
        and a failed job keeps the outputs its steps wrote. No kind of item is then gathered, screened or reviewed, so
        no review escapes the cap's count, and the check review jobs fails."""
        for kind in ("enrollment", "change", "issue"):
            with self.subTest(kind=kind):
                route = dict(ITEMS[kind], trust="screen", started="2026-11-09T12:00:00Z")
                got, ctx = run_graph(route, results={"route": "failure"}, outputs={"route": route},
                                     event="issues" if kind == "issue" else "workflow_run")
                self.assertEqual({n for n, r in got.items() if r != "skipped"}, {"route", "collect"}, got)
                self.assertEqual(required(ctx)[0], 1)
                # The same route, when it succeeded, gathers, screens and reviews.
                got, _ = run_graph(route, outputs={"screen": {"verdict": "clean", "checks": "claude"}},
                                   event="issues" if kind == "issue" else "workflow_run")
                self.assertTrue({"gather", "screen", "review"} <= {n for n, r in got.items() if r == "success"}, got)

    def test_the_review_and_the_comment_are_asked_for_on_their_own_conditions(self):
        """Every condition change of the review and comment jobs is mirrored in the job collect's ASKED_REVIEW and
        ASKED_COMMENT: the same answer over every route, gather, screen and review those jobs can see, a held head, a
        merge's replay (no kind) and a run by hand on another branch than main included."""
        collect = step("collect", COLLECT)["env"]
        for trust, kind, name, gathered, screened, review, comment, held, replay, (event, ref) in itertools.product(
                ("", "writer", "screen", "cap"), ("enrollment", "change", "issue", ""),
                ("libx", ""), ("success", "failure", "kept nothing"), ("false", "clean", "held", "failure"),
                ("success", "failure", "cancelled", "skipped"), ("Thanks.", ""), ("", "true"), ("", "true"),
                (("workflow_run", "refs/heads/main"), ("workflow_dispatch", "refs/heads/other"))):
            ctx = {"needs.route.outputs.trust": trust, "needs.route.outputs.kind": kind,
                   "needs.route.outputs.held": held, "needs.route.outputs.replay": replay,
                   "needs.gather.outputs.name": name,
                   "needs.gather.result": "success" if gathered == "kept nothing" else gathered,
                   "needs.gather.outputs.digest": "d" * 64 if gathered == "success" else "",
                   "needs.gather.outputs.screen": "false" if screened == "false" else "true",
                   "needs.screen.result": {"false": "skipped", "failure": "failure"}.get(screened, "success"),
                   "needs.screen.outputs.verdict": screened if screened in ("clean", "held") else "",
                   "needs.review.result": review, "needs.review.outputs.comment": comment,
                   "github.event_name": event, "github.ref": ref}
            for job, asked in (("review", "ASKED_REVIEW"), ("comment", "ASKED_COMMENT")):
                self.assertEqual(bool(evaluate(REVIEW_JOBS[job]["if"], ctx)), bool(evaluate(collect[asked], ctx)),
                                 (job, ctx))

    def test_the_required_check_for_each_outcome_of_an_enrollment(self):
        """Decision 3: the comment job runs for every outcome of an enrollment whose gather job took the project, and
        the check review jobs passes for a screen's hold and the daily cap, and fails for a failed gather, screen,
        review (after its second attempt), hold or comment job. Each outcome runs the jobs it should, and the comment
        job holds the enrollment (HOLDING) whenever no review passed, whoever wrote it: a screen that failed reviews
        nothing, even one that said clean. The gather job's step that takes the project gives its name at once, so a
        gather job that fails after it still names the project. A change's review that fails is held only when it was
        screened."""
        screened = {"screen": {"verdict": "clean", "checks": "model_armor"}}
        failed_gather = {"gather": {"name": "libx"}}
        # The jobs that run besides route and collect.
        reviewed = {"gather", "review", "hold", "comment"}
        screen_reviewed = reviewed | {"screen"}
        screen_held = {"gather", "screen", "comment"}
        gather_held = {"gather", "comment"}
        for name, route, results, outputs, jobs, holding, want in (
                ("reviewed", {"trust": "writer"}, {}, {}, reviewed, False, 0),
                ("screened and reviewed", {"trust": "screen"}, {}, screened, screen_reviewed, False, 0),
                ("screen hold", {"trust": "screen"}, {}, {"screen": {"verdict": "held"}}, screen_held, True, 0),
                ("daily cap", {"trust": "cap", "free": "2026-11-10T00:00:00Z"}, {}, {}, {"comment"}, True, 0),
                ("gather failed", {"trust": "screen"}, {"gather": "failure"}, failed_gather, gather_held, True, 1),
                ("a writer's gather failed", {"trust": "writer"}, {"gather": "failure"}, failed_gather,
                 gather_held, True, 1),
                ("screen failed", {"trust": "screen"}, {"screen": "failure"}, {"screen": {"verdict": "clean"}},
                 screen_held, True, 1),
                ("review failed", {"trust": "screen"}, {"review": "failure"}, screened, screen_reviewed, True, 1),
                ("a writer's review failed", {"trust": "writer"}, {"review": "failure"}, {}, reviewed, True, 1),
                ("hold failed", {"trust": "writer"}, {"hold": "failure"},
                 {"review": {"comment": "Thanks.", "held_object": "held/1/x", "session": "", "kind": "enrollment"}},
                 reviewed, False, 1),
                ("comment failed", {"trust": "writer"}, {"comment": "failure"}, {}, reviewed, False, 1)):
            with self.subTest(name=name):
                ran, ctx = self.ran(dict(self.ENROLLMENT, **route), results, outputs)
                self.assertEqual(ran, jobs)
                self.assertEqual(evaluate(REVIEW_JOBS["comment"]["env"]["HOLDING"], ctx), holding)
                code, out = required(ctx)
                self.assertEqual(code, want, out)
        jobs, _ = self.ran(dict(ITEMS["change"], trust="writer"), results={"review": "failure"})
        self.assertNotIn("comment", jobs)

    def test_a_measurement_runs_the_screen_job_alone(self):
        """The screen job measures, and the check review jobs asks for it and nothing else. A measurement is a run by
        hand, on main."""
        by_hand = {"event": "workflow_dispatch", "ref": "refs/heads/main"}
        jobs, ctx = self.ran({"kind": "", "trust": "measure"}, outputs={"gather": {}}, **by_hand)
        self.assertEqual(jobs, {"screen"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        jobs, ctx = self.ran({"kind": "", "trust": "measure"}, results={"screen": "failure"}, outputs={"gather": {}},
                             **by_hand)
        self.assertEqual(jobs, {"screen"})
        self.assertEqual(required(ctx)[0], 1)
        # The Measure step runs for a measurement alone, and the steps that take and screen what the gather job kept
        # for every other trust.
        for trust in ("measure", "screen", "writer"):
            ctx = {"needs.route.outputs.trust": trust}
            ran = {s.get("name") or s["uses"].split("@")[0] for s in REVIEW_JOBS["screen"]["steps"]
                   if "if" not in s or evaluate(s["if"], ctx)}
            for name in ("Screen", "Take what the gather job kept", "actions/download-artifact"):
                self.assertEqual(name in ran, trust != "measure", (name, trust))
            self.assertEqual("Measure" in ran, trust == "measure", trust)
        # A measurement outlasts the screen's 10-minute token: its sign-in asks for an hour, a screen's for 10 minutes.
        lifetime = step("screen", "Sign in to Google Cloud")["with"]["access_token_lifetime"]
        self.assertEqual(evaluate(lifetime, {"needs.route.outputs.trust": "measure"}), "3600s")
        for trust in ("screen", "writer"):
            self.assertEqual(evaluate(lifetime, {"needs.route.outputs.trust": trust}), "600s")

    def test_the_measure_step_takes_only_a_labelled_set_and_one_to_five_repeats(self):
        run = step("screen", "Measure")["run"].replace("python3 .github/scripts/screen.py --measure", "echo ran")
        for measure_set, repeats, ok in (("measure/set-v1.json", "3", True), ("measure/set-v12.json", "5", True),
                                         ("measure/runs/x.json", "3", False), ("reasons/a.json", "3", False),
                                         ("measure/set-v1.json\nx", "3", False), ("measure/set-v1.json", "0", False),
                                         ("measure/set-v1.json", "6", False), ("measure/set-v1.json", "1;x", False)):
            with self.subTest(measure_set=measure_set, repeats=repeats):
                r = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", run], capture_output=True, text=True,
                                   env={**os.environ, "MEASURE_SET": measure_set, "MEASURE_REPEATS": repeats})
                self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)

    def test_nothing_reviewable_holds_nothing(self):
        """An enrollment pull request whose gather job kept nothing, neither a project nor a kind (the head moved after
        route read it, say), is not reviewed, so nothing is held either; nor is an enrollment with neither a Build run's
        results nor a held head. A gather job that took no project gives the kind change instead
        (tests/test_review_check.py)."""
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                jobs, ctx = self.ran(dict(self.ENROLLMENT, trust=trust), outputs={"gather": {"digest": "", "name": ""}})
                self.assertEqual(jobs, {"gather"})
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        jobs, _ = self.ran(dict(self.ENROLLMENT, trust="writer", build_run=""))
        self.assertEqual(jobs, set())
        jobs, _ = self.ran({"kind": "", "trust": ""})
        self.assertEqual(jobs, set())

    def test_a_writers_item_with_an_outsiders_comment_is_screened(self):
        """The gather job's output screen is true for it: the screen runs, and only a clean verdict reviews it."""
        route = dict(self.ENROLLMENT, trust="writer")
        gather = {"digest": "d" * 64, "screen": "true", "name": "libx"}
        jobs, ctx = self.ran(route, outputs={"gather": gather, "screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertTrue({"screen", "review"} <= jobs, jobs)
        jobs, ctx = self.ran(route, outputs={"gather": gather, "screen": {"verdict": "held"}})
        self.assertEqual(jobs, {"gather", "screen", "comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_a_gather_job_with_no_screen_output_screens(self):
        """Fail closed: only the word false skips the screen."""
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="writer"), outputs={"gather": {"digest": "d" * 64}},
                             results={"screen": "failure"})
        self.assertNotIn("review", jobs)
        self.assertIn("screen", jobs)

    def test_a_moved_head_runs_nothing_after_the_gather(self):
        """The gather job kept nothing (digest empty): no screen, review or hold, and the check review jobs passes.
        When the head moved while the gather job read it, the job had taken the project: the comment job runs for the
        enrollment, and its step records nothing at the head that moved (PostingStep). When the head had moved before
        the gather job started (HeadDidNotMove), the job took no project, and no comment job runs: the run of the new
        head records the verdict."""
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                # Even with a screen output: no digest, nothing to take.
                for gather in ({"digest": ""}, {"digest": "", "screen": "false"}, {"digest": "", "screen": "true"}):
                    for name, want in (("libx", {"gather", "comment"}), ("", {"gather"})):
                        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust=trust),
                                             outputs={"gather": dict(gather, name=name)})
                        self.assertEqual(jobs, want, (gather, name))
                        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_a_cancelled_or_timed_out_screen_reviews_nothing_and_fails_the_required_check(self):
        """A failed screen is the row "screen failed" of test_the_required_check_for_each_outcome_of_an_enrollment."""
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), results={"screen": "cancelled"},
                             outputs={"screen": {"verdict": "clean"}})
        self.assertNotIn("review", jobs)
        self.assertEqual(required(ctx)[0], 1)

    def test_a_screen_that_runs_out_of_time_fails_and_so_is_held(self):
        """A job that runs out of its own time ends as cancelled, and is neither reviewed nor held. Each step of the
        screen job has a time of its own, and those of the steps that run add up to less than the job's, so a slow
        step fails the job instead, and the comment job holds the item (the row "screen failed" of
        test_the_required_check_for_each_outcome_of_an_enrollment). The Screen step outlasts screen.py's own deadline,
        which holds the item first."""
        job = REVIEW_JOBS["screen"]
        for step_ in job["steps"]:
            self.assertIsInstance(step_.get("timeout-minutes"), int, step_.get("name") or step_.get("uses"))
        for trust in ("screen", "writer", "measure"):
            with self.subTest(trust=trust):
                ctx = {"needs.route.outputs.trust": trust}
                ran = [s for s in job["steps"] if "if" not in s or evaluate(s["if"], ctx)]
                self.assertLess(sum(s["timeout-minutes"] for s in ran), int(evaluate(job["timeout-minutes"], ctx)))
        self.assertGreater(step("screen", "Screen")["timeout-minutes"] * 60, screen_script().DEADLINE_SECONDS)

    def test_the_review_reads_what_the_screen_passed(self):
        """The screen and the review take the gathered file with take-review-data, by the gather job's digest, after
        the gather job, and only the gather job gathers: it alone uploads review-data, and the review job runs neither
        review-gather nor take-project, and restores no cache."""
        # Each of the gather job's outputs, the head that route read and the run's commit, a SHA-256 of its own: each
        # step takes the file by the gather job's digest, and by no other of them.
        ctx = {name: hashlib.sha256(name.encode()).hexdigest() for name in (
            *(f"needs.gather.outputs.{output}" for output in REVIEW_JOBS["gather"]["outputs"]),
            "needs.route.outputs.sha", "github.sha")}
        for job in ("screen", "review"):
            take = step(job, "Take what the gather job kept")
            self.assertEqual(interpolated(take["env"]["DIGEST"], ctx), ctx["needs.gather.outputs.digest"], job)
            self.assertIn(".github/scripts/take-review-data", take["run"])
            self.assertIn("gather", REVIEW_JOBS[job]["needs"])
        uploads = [(n, s) for n, j in REVIEW_JOBS.items() for s in j["steps"]
                   if "upload-artifact" in s.get("uses", "") and (s.get("with") or {}).get("name") == "review-data"]
        self.assertEqual([n for n, _ in uploads], ["gather"])
        review = json.dumps(REVIEW_JOBS["review"])
        for name in ("review-gather", "take-project", "actions/cache"):
            self.assertNotIn(name, review)
        self.assertNotIn("cache-mode", REVIEW_JOBS["review"])

    def test_the_triage_comment_is_asked_for_on_its_own(self):
        """route's output triage (after a Triage run, or on a person's run by hand): triage-gather writes the comment
        and triage posts it, and the check review jobs asks for each. After a Triage run route gives no kind, so no
        review job runs. A triage-gather job that writes no comment posts nothing, and one that fails fails the check.
        A person's run by hand of an enrollment has both the review and the triage comment."""
        triage = {"pr": "7", "sha": "a" * 40, "triage": "true"}
        comment = {"triage-gather": {"comment": "<!-- oss-verify-triage -->\nThe triage."}}
        for outputs, results, jobs, want in ((comment, {}, {"triage-gather", "triage"}, 0),
                                             ({"triage-gather": {"comment": ""}}, {}, {"triage-gather"}, 0),
                                             ({}, {"triage-gather": "failure"}, {"triage-gather"}, 1)):
            with self.subTest(outputs=outputs, results=results):
                got, ctx = self.ran(triage, results, outputs)
                self.assertEqual(got, jobs)
                self.assertEqual(required(ctx)[0], want, required(ctx)[1])
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="writer", triage="true"), outputs=comment,
                             event="workflow_dispatch", ref="refs/heads/main")
        self.assertEqual(jobs, {"gather", "review", "hold", "comment", "triage-gather", "triage"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])


class Holdings(unittest.TestCase):
    """What each job holds: the screen job no write token, no secret and none of the review's identities, and the
    jobs of build.yaml none of the review's."""

    SCREEN_IDENTITIES = ("review-screen@", "workloadIdentityPools/review-screen/")
    OTHER_IDENTITIES = ("ossv-ci@", "ossv-app-comment@", "svac_01WdHTLcJPEfiPttcuLK1hGT", "fdrl_019restxFx3PhpLhbziQoQKf",
                        "TAILNET_CLIENT_ID", "oss-verify-github-app-key")

    def test_no_job_reads_a_secret(self):
        for workflow in ("build.yaml", "review.yml"):
            self.assertNotRegex((WORKFLOWS / workflow).read_text(), r"\$\{\{[^}]*\bsecrets\b", workflow)

    def test_the_screen_job_holds_no_write_token_and_none_of_the_reviews_identities(self):
        job = REVIEW_JOBS["screen"]
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(job["environment"], {"name": "review-screen", "deployment": False})
        text = json.dumps(job)
        for name in self.OTHER_IDENTITIES:
            self.assertNotIn(name, text)

    def test_only_the_screen_job_reaches_the_screens_identities(self):
        for workflow in (REVIEW, BUILD):
            for name, job in workflow["jobs"].items():
                text = json.dumps(job)
                environment = json.dumps(job.get("environment", ""))
                with self.subTest(workflow=workflow["name"], job=name):
                    if workflow is REVIEW and name == "screen":
                        continue
                    self.assertNotIn("review-screen", environment)
                    self.assertNotIn("${{", environment)
                    for identity in self.SCREEN_IDENTITIES:
                        self.assertNotIn(identity, text)

    def test_the_screen_jobs_outputs_are_its_verdict_and_the_checks_that_ran(self):
        """The reason reaches no output: screen.py writes only the verdict and the checks that ran (test_screen.py),
        and the job passes on only these, each the Screen step's output of its name; no other job reads anything of
        the screen but these and its result."""
        outputs = REVIEW_JOBS["screen"]["outputs"]
        self.assertEqual(sorted(outputs), ["checks", "verdict"])
        screen = step("screen", "Screen")["id"]
        ctx = {f"steps.{screen}.outputs.{name}": f"the Screen step's {name}" for name in outputs}
        for name, value in outputs.items():
            self.assertEqual(interpolated(str(value), ctx), ctx[f"steps.{screen}.outputs.{name}"], name)
        for name, job in REVIEW_JOBS.items():
            for ref in re.findall(r"needs\.screen\.([a-z]+(?:\.[a-z]+)?)", json.dumps(job)):
                self.assertIn(ref, ("result", "outputs.verdict", "outputs.checks"), name)

    def test_the_comment_job_reads_main_s_scripts_and_writes_with_the_apps_tokens(self):
        """Its own token reads the checkout of .github/scripts and nothing else. The App's first token writes the
        check run, the review comment and the hold of a change pull request or an issue. The job makes it on every
        path but the approval of the held runs (APPROVE) and the replay of a merge (REPLAY), where no step writes
        these. tests/test_trigger_move.py (d7) evaluates the if of the two token steps on each path, and checks the
        second token, of the approval and the replay."""
        job = REVIEW_JOBS["comment"]
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
        checkout = job["steps"][0]
        self.assertTrue(checkout["uses"].startswith("actions/checkout@"))
        self.assertEqual(checkout["with"], {"persist-credentials": False, "sparse-checkout": ".github/scripts"})
        tokens = {s["id"]: s for s in job["steps"] if "create-github-app-token" in s.get("uses", "")}
        self.assertEqual(sorted(tokens), ["app", "approve"])
        self.assertEqual({k: v for k, v in tokens["app"]["with"].items() if k.startswith("permission-")},
                         {"permission-checks": "write", "permission-pull-requests": "write",
                          "permission-issues": "write"})
        for s in job["steps"]:
            if "GH_TOKEN" in s.get("env", {}) and s["name"] not in ("Approve the held runs",
                                                                    "Replay the merge for Enroll dispatch"):
                self.assertEqual(s["env"]["GH_TOKEN"], "${{ steps.app.outputs.token }}", s["name"])

    def test_the_gather_job_holds_no_model_and_writes_nothing(self):
        job = REVIEW_JOBS["gather"]
        self.assertEqual(job["permissions"], {"contents": "read", "pull-requests": "read", "issues": "read",
                                              "checks": "read", "statuses": "read", "actions": "read"})
        self.assertNotIn("environment", job)
        self.assertEqual(job["cache-mode"], "read")
        text = json.dumps(job)
        for name in ("claude-code-action", "google-github-actions", "id-token"):
            self.assertNotIn(name, text)

    def test_each_check_the_screen_lists_has_its_settings_and_its_anthropic_identity_is_its_own(self):
        e = REVIEW_JOBS["screen"]["env"]
        # an identity not set up yet is empty, and its check does not run; one that is set up is well formed
        self.assertRegex(e["AZURE_CLIENT_ID"], r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$")
        self.assertRegex(e["ANTHROPIC_SERVICE_ACCOUNT_ID"], r"^(svac_[0-9A-Za-z]+)?$")
        self.assertRegex(e["ANTHROPIC_FEDERATION_RULE_ID"], r"^(fdrl_[0-9A-Za-z]+)?$")
        self.assertEqual(bool(e["ANTHROPIC_SERVICE_ACCOUNT_ID"]), bool(e["ANTHROPIC_FEDERATION_RULE_ID"]))
        # Each listed check has every setting it reads: a listed check with one missing would hold every item.
        settings = {"model_armor": ("MODEL_ARMOR_URL", "MODEL_ARMOR_TEMPLATE"),
                    "prompt_shields": ("AZURE_LOGIN_URL", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "CONTENT_SAFETY_URL"),
                    "claude": ("ANTHROPIC_URL", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_WORKSPACE_ID",
                               "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_FEDERATION_RULE_ID", "SCREEN_MODEL")}
        listed = e["SCREEN_CHECKS"].split(",")
        self.assertIn("model_armor", listed)
        self.assertEqual(len(set(listed)), len(listed))
        for check in listed:
            for name in settings[check]:
                self.assertTrue(e[name], f"{check} is listed, and {name} is empty")
        # The screen's Anthropic identity is its own: the review reaches Claude through the model gateway, and holds
        # no Anthropic service account or federation rule at all.
        review = json.dumps(REVIEW_JOBS["review"])
        self.assertNotIn(e["ANTHROPIC_SERVICE_ACCOUNT_ID"], review)
        self.assertNotIn(e["ANTHROPIC_FEDERATION_RULE_ID"], review)
        self.assertNotRegex(review, r"svac_|fdrl_")

    def test_the_screen_holds_what_the_model_or_both_detectors_call_suspicious(self):
        """The policy the measurement chose (.github/scripts/screen.py, RULES): the model's word suspicious holds an
        item, and so do Model Armor's and Prompt Shields' together. screen.py, with the checks and the rule the Screen
        step runs with, holds every outcome of the three checks' words that the policy holds: so the screen runs each
        of the three, under no weaker rule (one detector, the detectors alone, the model alone, two of the three)."""
        e = step_env("screen", step("screen", "Screen"))
        screen = screen_script()
        with mock.patch.dict(os.environ, {"SCREEN_CHECKS": e["SCREEN_CHECKS"], "SCREEN_RULE": e["SCREEN_RULE"]}):
            ran = screen.listed()
            rule = screen.rule(ran)
        checks = ("model_armor", "prompt_shields", "claude")
        self.assertLessEqual(set(checks), set(ran))
        for words in itertools.product(("clean", "suspicious"), repeat=len(checks)):
            said = dict(zip(checks, words))
            if said["claude"] == "suspicious" or said["model_armor"] == said["prompt_shields"] == "suspicious":
                with self.subTest(**said):
                    self.assertEqual(screen.combine({c: said.get(c, "clean") for c in ran}, rule), "held")

    # The model that the rule in use was measured with (.github/scripts/screen.py, the measurement beside RULES). In
    # that measurement the detectors, either one, held none of the 220 ordinary items and 39 of the 125 injections (the
    # rule detectors), so the model's word made all 6 false holds of claude_or_both_detectors and at least 80 of the
    # 119 injections it held. Another model needs a new measurement (screen.py --measure) before it screens, and this
    # name changes with it.
    MEASURED_MODEL = "claude-haiku-5-5"

    def test_the_screen_asks_the_model_its_rule_was_measured_with(self):
        """Each step of the screen job that runs screen.py runs it with that model: the screen, its sign-in, and a
        measurement, which would otherwise measure another model than the one that screens."""
        ran = []
        for s in REVIEW_JOBS["screen"]["steps"]:
            if "screen.py" in str(s.get("run", "")):
                ran.append(s["name"])
                with self.subTest(step=s["name"]):
                    self.assertEqual(step_env("screen", s)["SCREEN_MODEL"], self.MEASURED_MODEL)
        self.assertLessEqual({"Screen", "Measure"}, set(ran))

    def test_each_attempt_of_each_run_stores_its_screen_record_under_a_name_of_its_own(self):
        """screen.py stores the reason of a screen (the Screen step's REASON_OBJECT) and the record of a measurement
        (the Measure step's MEASURE_OBJECT) as a new object, never over one (ifGenerationMatch=0, test_screen.py). A
        name that a re-run, or another run, gives again would lose that run's record. Each name differs for two
        attempts of one run, and for two runs."""
        for name, variable in (("Screen", "REASON_OBJECT"), ("Measure", "MEASURE_OBJECT")):
            value = step_env("screen", step("screen", name))[variable]
            names = {interpolated(value, {"github.repository": REPO, "github.run_id": run,
                                          "github.run_attempt": attempt})
                     for run in ("9001", "9002") for attempt in ("1", "2")}
            with self.subTest(step=name):
                self.assertEqual(len(names), 4, names)


class TakeReviewData(Runner):
    """.github/scripts/take-review-data: only the gather job's file, by its SHA-256, and only what the review reads."""

    def tar(self, members, links=()):
        path = self.dir / "review.tar"
        with tarfile.open(path, "w") as t:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
            for name, target in links:
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                t.addfile(info)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def take(self, path, digest, name="", home=None):
        (self.dir / "home").mkdir(exist_ok=True)
        args = f' "{self.dir / "home"}"' if home else ""
        return self.run_script(f'{SCRIPTS / "take-review-data"} "{path}"{args}', DIGEST=digest, NAME=name)

    GOOD = {".review/pr.json": b"{}", "projects/libx/build.sh": b"make\n",
            ".claude/ossv-last-review": b"session=x head=y\n", ".claude/projects/a/s.jsonl": b"{}"}

    def test_a_hard_link_is_refused(self):
        path = self.dir / "review.tar"
        with tarfile.open(path, "w") as t:
            info = tarfile.TarInfo(".review/a")
            t.addfile(info, io.BytesIO(b""))
            link = tarfile.TarInfo(".review/b")
            link.type, link.linkname = tarfile.LNKTYPE, ".review/a"
            t.addfile(link)
        rc, out, _ = self.take(path, hashlib.sha256(path.read_bytes()).hexdigest(), "libx")
        self.assertNotEqual(rc, 0, out)

    def test_what_the_gather_jobs_keep_step_makes_is_taken(self):
        """The gather job's own step, with GNU tar, and take-review-data on its file by the digest it gave. A screened
        item keeps its session as a writer's does: the review takes it, and the screen, given no home, does not."""
        gather = self.dir / "gather"
        (gather / ".review").mkdir(parents=True)
        (gather / ".review" / "pr.json").write_text("{}\n")
        (gather / "projects" / "libx").mkdir(parents=True)
        (gather / "projects" / "libx" / "build.sh").write_text("make\n")
        home = self.dir / "gather-home"
        (home / ".claude" / "projects").mkdir(parents=True)
        (home / ".claude" / "ossv-last-review").write_text("session=x head=y\n")
        for screened in ("true", "false"):
            with self.subTest(screened=screened):
                shutil.rmtree(self.temp / "review-data", ignore_errors=True)
                shutil.rmtree(self.work / ".review", ignore_errors=True)
                shutil.rmtree(self.dir / "home", ignore_errors=True)
                rc, out, got = self.run_script(step("gather", "Keep it for the screen and the review")["run"],
                                               cwd=gather, NAME="libx", HOME=str(home), SCREEN=screened)
                self.assertEqual(rc, 0, out)
                with tarfile.open(self.temp / "review-data" / "review.tar") as t:
                    self.assertIn(".claude/ossv-last-review", t.getnames())
                # The review's take: the session goes into its home.
                rc, out, _ = self.take(self.temp / "review-data" / "review.tar", got["digest"], "libx", home=True)
                self.assertEqual(rc, 0, out)
                self.assertTrue((self.work / "projects" / "libx" / "build.sh").is_file())
                self.assertEqual((self.dir / "home" / ".claude" / "ossv-last-review").read_text(), "session=x head=y\n")
                # The screen's take, with no home: no session anywhere it reads.
                shutil.rmtree(self.work / ".review")
                shutil.rmtree(self.dir / "home")
                rc, out, _ = self.take(self.temp / "review-data" / "review.tar", got["digest"], "libx")
                self.assertEqual(rc, 0, out)
                self.assertFalse((self.dir / "home" / ".claude").exists())
                self.assertFalse((self.work / ".claude").exists())
                # The job's outputs session and last are review-gather's, whatever the outside step said.
                ctx = {"steps.outside.outputs.screen": screened, "steps.gather.outputs.session": "x",
                       "steps.gather.outputs.last": "y"}
                self.assertEqual({k: evaluate(REVIEW_JOBS["gather"]["outputs"][k], ctx) for k in ("session", "last")},
                                 {"session": "x", "last": "y"})

    def test_it_takes_the_review_the_project_and_for_the_review_the_session(self):
        (self.work / "projects" / "libx").mkdir(parents=True)
        (self.work / "projects" / "libx" / "old").write_text("main's\n")
        path, digest = self.tar(self.GOOD)
        rc, out, _ = self.take(path, digest, "libx", home=True)
        self.assertEqual(rc, 0, out)
        self.assertTrue((self.work / ".review" / "pr.json").is_file())
        self.assertEqual(sorted(os.listdir(self.work / "projects" / "libx")), ["build.sh"])
        self.assertTrue((self.dir / "home" / ".claude" / "ossv-last-review").is_file())
        self.assertFalse((self.work / ".claude").exists())

    def test_the_screen_takes_no_session(self):
        path, digest = self.tar(self.GOOD)
        rc, out, _ = self.take(path, digest, "libx")
        self.assertEqual(rc, 0, out)
        self.assertFalse((self.dir / "home" / ".claude").exists())

    def test_another_file_is_refused(self):
        path, digest = self.tar(self.GOOD)
        rc, out, _ = self.take(path, "0" * 64, "libx")
        self.assertNotEqual(rc, 0, out)
        self.assertFalse((self.work / ".review").exists())

    def test_anything_outside_what_the_review_reads_is_refused(self):
        for members, links in (({".review/a": b"", ".github/review.md": b""}, ()),
                               ({".review/a": b"", "projects/other/x": b""}, ()),
                               ({".review/a": b"", ".review/../x": b""}, ()),
                               ({".review/a": b""}, ((".review/link", "/proc/self/environ"),)),
                               ({".review/a": b"", ".claude/settings.json": b""}, ())):
            with self.subTest(members=list(members), links=links):
                path, digest = self.tar(members, links)
                rc, out, _ = self.take(path, digest, "libx", home=True)
                self.assertNotEqual(rc, 0, out)
                self.assertFalse((self.work / ".review").exists())


class HeadDidNotMove(Runner):
    """The gather job's checks that the pull request is at the head that route read: at the job's start, and after the
    reads, that pr.json and the pull request now name the head that was gathered."""

    STEP = "The pull request's head did not move while it was read"

    def check(self, read, now, trust):
        (self.work / ".review").mkdir(exist_ok=True)
        (self.work / ".review" / "pr.json").write_text(json.dumps({"headRefOid": read}) + "\n(exit status 0)\n")
        if now:
            self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": now}})
        rc, _out, got = self.run_script(step("gather", self.STEP)["run"], PR="7", HEAD_SHA="a" * 40, TRUST=trust)
        return rc, got.get("moved")

    def test_the_same_head_passes(self):
        self.assertEqual(self.check("a" * 40, "a" * 40, "screen"), (0, None))

    def test_a_head_that_moved_keeps_nothing(self):
        """The job passes and says moved: its later steps keep nothing, and no screen, review or hold runs."""
        for read, now in (("b" * 40, "a" * 40), ("a" * 40, "b" * 40)):
            for trust in ("screen", "writer"):
                with self.subTest(read=read[0], now=now[0], trust=trust):
                    self.assertEqual(self.check(read, now, trust), (0, "true"))
        # Its later steps run only on a head that did not move.
        for name in ("Whether the review reads text of an account without write access",
                     "Keep it for the screen and the review"):
            for moved in ("true", ""):
                ctx = {"steps.head.outputs.moved": moved, "steps.project.outputs.kind": "enrollment"}
                self.assertEqual(bool(evaluate(step("gather", name)["if"], ctx)), moved != "true", (name, moved))

    def test_a_head_that_cannot_be_read_fails_only_a_screened_one(self):
        self.assertEqual(self.check("a" * 40, None, "screen")[0], 1)
        self.assertEqual(self.check("a" * 40, None, "writer"), (0, None))

    def test_a_push_after_the_run_that_route_read_keeps_nothing(self):
        """The job's first step: a pull request whose head is no longer route's has a run of its own for the push. The
        job then takes no project and keeps nothing, so no screen, review or comment runs (Routes). A read that fails
        decides nothing there: the step above reads the pull request again after the gather."""
        start = step("gather", "The pull request is still at the head that route read")
        pull = self.api / f"repos_{REPO.replace('/', '_')}_pulls_7.json"
        for now, moved in (("b" * 40, "true"), ("a" * 40, None), (None, None)):
            with self.subTest(now=now):
                pull.unlink(missing_ok=True)
                if now:
                    self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": now}})
                rc, out, got = self.run_script(start["run"], PR="7", HEAD_SHA="a" * 40)
                self.assertEqual((rc, got.get("moved")), (0, moved), out)
        # Every later step of the job then runs nothing: the project step does not run, so no step has a kind.
        steps = REVIEW_JOBS["gather"]["steps"]
        self.assertIs(steps[0], start)
        ctx = {"steps.start.outputs.moved": "true", "env.KIND": "enrollment", "needs.route.outputs.build_run": "900"}
        self.assertEqual([s.get("name") or s["uses"] for s in steps[1:] if "if" not in s or evaluate(s["if"], ctx)], [])


class Hold(Runner):
    """The comment job's hold of a change pull request or an issue (pull request 7 is a change here): the label, and
    one comment in fixed words that says nothing of why. An enrollment pull request whose check run Enrollment review
    records the hold is never held so (PostingStep in test_check_checks.py)."""

    STEP = "Label it review-held and say so"

    @staticmethod
    def comment_env(ctx):
        """The comment job's env that its steps' ifs read (env.<name>), for the run of ctx."""
        return {f"env.{k}": v for k, v in comment_job_env(ctx).items()}

    def hold(self, trust, pr="7", number="7", comments=(), head="a" * 40, review="skipped", free=""):
        """free: route's output free, the time the daily cap frees, for trust cap. Returns the calls, the body of each
        comment the step sent, and its output. A pull request's hold also posts the check run review
        (tests/test_review_check.py checks it)."""
        self.serve(f"repos/{REPO}/issues/{number}/comments", list(comments))
        self.serve(f"repos/{REPO}/issues/{number}/labels", [{"name": "review-held"}])
        self.serve(f"repos/{REPO}/labels/review-held", {"name": "review-held"})
        self.serve(f"repos/{REPO}/issues/comments/5", {})
        self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": head}})
        self.serve(f"repos/{REPO}/check-runs", {"id": 1})
        rc, out, _ = self.run_script(step("comment", self.STEP)["run"], cwd=ROOT, PR=pr, NUMBER=number, TRUST=trust,
                                     HEAD_SHA="a" * 40, REVIEW=review, RUN_ID="100", FREE=free, KIND="change",
                                     RUN_URL=f"https://github.com/{REPO}/actions/runs/100")
        self.assertEqual(rc, 0, out)
        calls = self.calls()
        bodies = [json.loads((self.api / f"input.{i + 1}").read_text())["body"]
                  for i, c in enumerate(calls) if "--input" in c and any("/comments" in a for a in c)]
        return calls, bodies, out

    def test_a_held_item_is_labelled_and_told_in_fixed_words(self):
        calls, bodies, _ = self.hold("screen")
        self.assertIn(["--method", "POST", f"repos/{REPO}/issues/7/labels", "-f", "labels[]=review-held",
                       "--jq", ".[].name"], calls)
        self.assertEqual(len(bodies), 1)
        self.assertTrue(bodies[0].startswith("<!-- oss-verify-held -->\n**Automated review held.**\n"))
        self.assertTrue(bodies[0].endswith("\n\n<!-- oss-verify-held-run 100 -->\n"), bodies[0])
        self.assertIn("the screen did not pass it", bodies[0])
        self.assertIn(f"gh workflow run review.yml -R {REPO} -f pr=7", bodies[0])
        # A person's approval of the head passes the check run review of a pull request
        # (dispatch://INFRA-5359/ask/605104e3-b85c-4c22-9a54-b254ba0e3c10).
        self.assertIn("can also approve this head on GitHub: the check review then passes with no review.", bodies[0])
        # nothing that notifies anyone or links an issue
        self.assertNotIn("@", bodies[0])
        self.assertNotRegex(bodies[0], r"#[0-9]|(?i:gh-)[0-9]")

    def test_an_issue_is_told_how_to_start_its_review(self):
        _calls, bodies, _ = self.hold("screen", pr="", number="9")
        self.assertIn(f"-f issue=9", bodies[0])
        self.assertNotIn("approve this head", bodies[0])

    def test_a_capped_item_is_told_the_cap_and_when_it_frees(self):
        """c3 (f), and an issue or a change pull request held at the daily cap: the cap and the time it frees, and
        that a push (for an issue, an edit of it) or a run by hand reviews it from then. No marker that anything tries
        it again."""
        approve = (" A person with write access who is not its author can also approve this head on GitHub: the "
                   "check review then passes with no review.")
        for pr, number, start, change, more in (("", "9", "-f issue=9", "an edit of the issue", ""),
                                                ("7", "7", "-f pr=7", "a push", approve)):
            with self.subTest(number=number):
                self.api.joinpath("args").unlink(missing_ok=True)
                _calls, bodies, _ = self.hold("cap", pr=pr, number=number, free="2026-11-10T00:00:00Z")
                self.assertEqual(bodies, [
                    "<!-- oss-verify-held -->\n**Automated review held.**\n\nIt comes from an account without write "
                    f"access to this repository, and the automated reviews of such accounts reached their cap of "
                    f"{REVIEW['env']['REVIEW_CAP']} in 24 hours, {REVIEW['env']['REVIEW_CAP_AUTHOR']} for one author. "
                    f"From 2026-11-10 00:00 UTC, {change} or `gh workflow run review.yml -R {REPO} {start}` reviews "
                    f"it.{more}\n\n"
                    "<!-- oss-verify-held-run 100 -->\n"])
        # A cap with no time it frees holds nothing.
        rc, out, _ = self.run_script(step("comment", self.STEP)["run"], PR="", NUMBER="9", TRUST="cap", HEAD_SHA="a" * 40,
                                     REVIEW="skipped", RUN_ID="100", FREE="")
        self.assertEqual(rc, 1, out)

    def test_no_hold_names_a_try_or_a_rescreen(self):
        for trust, review in (("screen", "skipped"), ("screen", "failure"), ("screen", "cancelled"),
                              ("writer", "failure")):
            with self.subTest(trust=trust, review=review):
                self.api.joinpath("args").unlink(missing_ok=True)
                _calls, bodies, _ = self.hold(trust, review=review)
                self.assertNotRegex(bodies[0], r"oss-verify-held-(limit|cap|transient)|screened again|tried|times")
                self.assertEqual(bodies[0].count("<!--"), 2, bodies[0])

    def test_a_review_that_did_not_finish_is_not_a_screen_hold(self):
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                self.api.joinpath("args").unlink(missing_ok=True)
                _calls, bodies, _ = self.hold(trust, review="failure")
                self.assertNotIn("the screen did not pass it", bodies[0])

    def test_a_later_hold_replaces_its_own_comment_only(self):
        calls, _bodies, _ = self.hold("screen", comments=[
            {"id": 4, "user": {"login": "mallory"}, "body": "<!-- oss-verify-held --> forged"},
            {"id": 5, "user": {"login": "oss-verify[bot]"}, "body": "<!-- oss-verify-held -->\nold"}])
        self.assertIn(["--method", "PATCH", f"repos/{REPO}/issues/comments/5", "--input", "-"], calls)

    def test_an_older_heads_run_holds_nothing(self):
        calls, bodies, out = self.hold("screen", head="b" * 40)
        self.assertEqual(bodies, [])
        self.assertIn("the run of", out)

    def test_the_step_gets_nothing_of_the_screen_but_its_route(self):
        e = step("comment", self.STEP)["env"]
        self.assertNotIn("needs.screen", json.dumps(e))
        self.assertNotIn("needs.gather", json.dumps(e))

    def test_only_a_change_or_an_issue_is_held_so(self):
        """Every held outcome of an enrollment (the screen, the cap, a failed job) runs the comment job, and none of
        them runs this step; the same outcomes of a change and an issue do."""
        for kind in ("enrollment", "change", "issue"):
            for route, results, outputs in (({"trust": "screen"}, {}, {"screen": {"verdict": "held"}}),
                                            ({"trust": "cap"}, {}, {}),
                                            ({"trust": "screen"}, {"gather": "failure"}, {}),
                                            ({"trust": "screen"}, {"review": "failure"},
                                             {"screen": {"verdict": "clean"}})):
                with self.subTest(kind=kind, route=route, results=results):
                    # A gather job that fails after its project step still names the project.
                    gather = {"gather": {"name": "libx" if kind == "enrollment" else ""}} if "gather" in results else {}
                    got, ctx = run_graph(dict(ITEMS[kind], **route), results, dict(outputs, **gather))
                    self.assertNotEqual(got["comment"], "skipped")
                    env = self.comment_env(ctx)
                    self.assertEqual(bool(evaluate(step("comment", self.STEP)["if"], dict(ctx, **env))),
                                     kind != "enrollment")

    def test_a_held_head_that_the_screen_did_not_pass_is_held_by_the_same_rule(self):
        """OSSV-679's plan, decision 16: a run by hand for a head whose runs GitHub holds (route's held) has no
        review. A screen that held it or failed, a gather job that failed, or the daily cap: the comment job records
        the hold, and approves nothing. An enrollment at the cap, or one whose project the gather job took, gets the
        check run Enrollment review; any other item the label and the hold comment (this step), an enrollment whose
        project the gather job did not take too. The check review jobs reports as for any held item."""
        for kind, name in (("enrollment", "libx"), ("enrollment", ""), ("change", "")):
            for route, results, outputs, want in (
                    ({"trust": "screen"}, {}, {"screen": {"verdict": "held"}}, 0),
                    ({"trust": "screen"}, {"screen": "failure"}, {}, 1),
                    ({"trust": "screen"}, {"gather": "failure"}, {}, 1),
                    ({"trust": "cap", "free": "2026-11-10T00:00:00Z"}, {}, {}, 0)):
                with self.subTest(kind=kind, name=name, route=route, results=results):
                    gather = {"name": name} if "gather" in results else {"digest": "d" * 64, "screen": "true",
                                                                          "name": name}
                    got, ctx = run_graph(dict(route, kind=kind, pr="7", sha="a" * 40, held="true"), results,
                                         dict(outputs, gather=gather), event="workflow_dispatch", ref="refs/heads/main")
                    self.assertEqual(got["review"], "skipped")
                    self.assertNotEqual(got["comment"], "skipped")
                    env = self.comment_env(ctx)
                    record = kind == "enrollment" and (name != "" or route["trust"] == "cap")
                    self.assertEqual((env["env.APPROVE"], env["env.HOLDING"], env["env.RECORD"]),
                                     ("false", "true", as_text(record)))
                    self.assertEqual(bool(evaluate(step("comment", self.STEP)["if"], dict(ctx, **env))), not record)
                    self.assertEqual(required(ctx)[0], want, required(ctx)[1])

    def test_a_review_of_this_head_already_posted_is_not_replaced_by_a_hold(self):
        """Only review-body's own last line, with the whole commit, counts: a short commit id that collides, or the
        commit quoted in the review's text, does not."""
        footer = "<!-- oss-verify-review -->\n<sub>Claude wrote this review of `aaaaaaa` from `review.md`.</sub>\n"
        calls, bodies, out = self.hold("screen", comments=[
            {"id": 3, "user": {"login": "oss-verify[bot]"},
             "body": footer + "\n<!-- oss-verify-review-head " + "a" * 40 + " -->\n"}])
        self.assertEqual(bodies, [])
        self.assertIn("is posted: no hold", out)
        for body in (footer, footer + '"head":"' + "a" * 40 + '"\n',
                     footer + "\n<!-- oss-verify-review-head " + "a" * 7 + "b" * 33 + " -->\n",
                     footer + "x <!-- oss-verify-review-head " + "a" * 40 + " -->\n"):
            with self.subTest(body=body[-60:]):
                self.api.joinpath("args").unlink(missing_ok=True)
                _calls, bodies, _ = self.hold("screen", comments=[
                    {"id": 3, "user": {"login": "oss-verify[bot]"}, "body": body}])
                self.assertEqual(len(bodies), 1)

    def test_review_body_writes_the_head_line_and_the_review_cannot(self):
        run = subprocess.run([str(SCRIPTS / "review-body")], capture_output=True, text=True, env={
            **os.environ, "HEAD_SHA": "a" * 40, "CONCLUSION": "success", "RULES": "review.md", "CHECKS": "",
            "REVIEW": "<!-- oss-verify-review-head " + "b" * 40 + " -->\nThanks."})
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = run.stdout.splitlines()
        self.assertEqual(lines[-1], "<!-- oss-verify-review-head " + "a" * 40 + " -->")
        self.assertEqual([x for x in lines if "oss-verify-review-head" in x], [lines[-1]])

    def test_the_comment_jobs_never_cancel_each_other(self):
        self.assertEqual(REVIEW_JOBS["comment"]["concurrency"]["queue"], "max")
        self.assertIs(REVIEW_JOBS["comment"]["concurrency"]["cancel-in-progress"], False)

    STARTED = "2026-11-03T10:00:00Z"

    def take_off(self, number, comments, label=True, kind="change", started=STARTED):
        s = step("comment", "Take the label review-held off")
        if label:
            self.serve(f"repos/{REPO}/issues/{number}/labels/review-held", [])
        self.serve(f"repos/{REPO}/issues/{number}/comments", comments)
        self.serve(f"repos/{REPO}/issues/comments/5", {})
        rc, out, _ = self.run_script(s["run"], NUMBER=number, STARTED=started, RUN_ID="100", KIND=kind)
        self.assertEqual(rc, 0, out)
        return self.calls(), out

    HELD = [{"id": 4, "user": {"login": "mallory"}, "body": "<!-- oss-verify-held --> forged",
             "updated_at": "2026-11-03T09:00:00Z"},
            {"id": 5, "user": {"login": "oss-verify[bot]"}, "body": "<!-- oss-verify-held -->\nheld",
             "updated_at": "2026-11-03T09:00:00Z"}]

    def test_a_posted_review_takes_the_label_and_the_hold_comment_off(self):
        for number in ("7", "9"):
            with self.subTest(number=number):
                self.api.joinpath("args").unlink(missing_ok=True)
                calls, _ = self.take_off(number, self.HELD)
                self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/{number}/labels/review-held"], calls)
                self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/comments/5"], calls)
                self.assertNotIn(["--method", "DELETE", f"repos/{REPO}/issues/comments/4"], calls)
        # no label and no hold comment is no error
        self.take_off("8", [], label=False)
        # nor is a hold comment already gone (comment 6 answers 404), for every kind
        for kind in ("change", "issue", "enrollment"):
            with self.subTest(kind=kind):
                self.api.joinpath("args").unlink(missing_ok=True)
                calls, _ = self.take_off("7", [dict(self.HELD[1], id=6)], kind=kind)
                self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/comments/6"], calls)

    def test_an_enrollments_record_takes_every_hold_off(self):
        """An enrollment gets no new hold comment: every hold comment of the App and the label come off, whatever their
        time."""
        calls, _ = self.take_off("7", [dict(self.HELD[1], updated_at="2026-11-03T10:30:00Z")], kind="enrollment")
        self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/7/labels/review-held"], calls)
        self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/comments/5"], calls)

    def test_a_hold_after_this_run_started_stays(self):
        """A newer event of the item, held in a run of its own while this run's review ran, keeps its hold."""
        for when in (self.STARTED, "2026-11-03T10:30:00Z"):
            with self.subTest(when=when):
                self.api.joinpath("args").unlink(missing_ok=True)
                calls, out = self.take_off("9", [dict(self.HELD[1], updated_at=when)])
                self.assertEqual([c for c in calls if "DELETE" in c], [])
                self.assertIn("the label and the hold comment stay", out)
                # another run's hold, named in its comment, stays too
                self.api.joinpath("args").unlink(missing_ok=True)
                calls, out = self.take_off("9", [dict(self.HELD[1], updated_at=when,
                                                      body="<!-- oss-verify-held -->\nheld\n\n"
                                                           "<!-- oss-verify-held-run 99 -->\n")])
                self.assertEqual([c for c in calls if "DELETE" in c], [])

    def test_this_runs_own_hold_comes_off_after_a_re_run_of_its_failed_jobs(self):
        """A re-run of the failed jobs runs no route, so the start time is the first attempt's, and the hold that
        attempt made is newer than it. Its comment names this run, so the re-run's review takes it off."""
        own = dict(self.HELD[1], updated_at="2026-11-03T10:30:00Z",
                   body="<!-- oss-verify-held -->\nheld\n\n<!-- oss-verify-held-run 100 -->\n")
        calls, _ = self.take_off("7", [own])
        self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/7/labels/review-held"], calls)
        self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/comments/5"], calls)
        # a forged marker in the text before it does not count
        self.api.joinpath("args").unlink(missing_ok=True)
        forged = dict(own, body="<!-- oss-verify-held -->\n<!-- oss-verify-held-run 100 -->\nx\n")
        calls, _ = self.take_off("7", [forged])
        self.assertEqual([c for c in calls if "DELETE" in c], [])

    def test_an_issue_whose_review_made_its_draft_loses_its_hold(self):
        """An issue held once (at the daily cap, say), whose later screen passes and whose review makes its
        draft: the comment job runs, holds nothing and posts nothing, and takes the label and the hold comment off
        with the App's token, which can write issues
        (Holdings.test_the_comment_job_reads_main_s_scripts_and_writes_with_the_apps_tokens)."""
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                got, ctx = run_graph(dict(ITEMS["issue"], trust=trust, started=self.STARTED),
                                     outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
                self.assertEqual(got["comment"], "success")
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
                env = self.comment_env(ctx)
                ran = {s.get("name") for s in REVIEW_JOBS["comment"]["steps"]
                       if "if" not in s or evaluate(s["if"], dict(ctx, **env))}
                self.assertIn("Get the oss-verify App's token", ran)
                self.assertNotIn("Label it review-held and say so", ran)
                self.assertNotIn("Post the comment and record the verdict", ran)
                self.assertIn("Take the label review-held off", ran)
        # an issue whose review failed is held, and keeps its hold
        got, ctx = run_graph(dict(ITEMS["issue"], trust="screen"), results={"review": "failure"},
                             outputs={"screen": {"verdict": "clean"}})
        self.assertEqual(evaluate(REVIEW_JOBS["comment"]["env"]["HOLDING"], ctx), True)


class OutsideText(Runner):
    """The gather job's step that has the screen read a writer's item that holds text of an account without write
    access."""

    STEP = "Whether the review reads text of an account without write access"

    def screen(self, trust="writer", comments=(), reviews=(), review_authors=(), status=0, event="workflow_run"):
        """comments: each an author ({"login": ...} or None), or an (author, comment id) pair for its url."""
        review = self.work / ".review"
        review.mkdir(exist_ok=True)
        pairs = [c if isinstance(c, tuple) else (c, 100 + i) for i, c in enumerate(comments)]
        item = {"author": {"login": "alice"},
                "comments": [{"author": a, "body": "x",
                              "url": f"https://github.com/{REPO}/pull/7#issuecomment-{n}"} for a, n in pairs],
                "reviews": [{"author": a, "body": "x"} for a in reviews]}
        (review / "pr.json").write_text(json.dumps(item) + f"\n(exit status {status})\n")
        (review / "review-comment-authors.txt").unlink(missing_ok=True)
        if review_authors is not None:
            (review / "review-comment-authors.txt").write_text("".join(f"{a}\n" for a in review_authors)
                                                             + "(exit status 0)\n")
        rc, out, got = self.run_script(step("gather", self.STEP)["run"], TRUST=trust, EVENT=event)
        self.assertEqual(rc, 0, out)
        self.last = got
        return got["screen"]

    def setUp(self):
        super().setUp()
        self.permissions(alice="write", root="admin", mallory="read")
        # Comment 900 is the App's, by the REST API; comment 901 a user's that took the App's name.
        self.serve(f"repos/{REPO}/issues/comments/900", {"user": {"login": "sjawhar-agent[bot]", "type": "Bot"}})
        self.serve(f"repos/{REPO}/issues/comments/901", {"user": {"login": "sjawhar-agent", "type": "User"}})

    def test_writers_and_our_apps_alone_need_no_screen(self):
        self.assertEqual(self.screen(comments=[{"login": "alice"}, ({"login": "sjawhar-agent"}, 900)],
                                     reviews=[{"login": "root"}], review_authors=["alice", "oss-verify[bot]"]), "false")

    def test_an_outsiders_comment_review_or_review_comment_screens_it(self):
        for kwargs in ({"comments": [{"login": "mallory"}]}, {"reviews": [{"login": "mallory"}]},
                       {"review_authors": ["alice", "mallory"]}, {"comments": [None]}, {"comments": [{"login": ""}]},
                       {"review_authors": ["-"]}, {"review_authors": ["alice", ""]},
                       {"reviews": [{"login": "sjawhar-agent"}]}):
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                self.assertEqual(self.screen(**kwargs), "true")

    def test_a_user_named_as_one_of_our_apps_is_not_that_app(self):
        """By the REST API the comment is a User's, or it cannot be read: not the App's."""
        self.assertEqual(self.screen(comments=[({"login": "sjawhar-agent"}, 901)]), "true")
        self.assertEqual(self.screen(comments=[({"login": "sjawhar-agent"}, 902)]), "true")

    def test_a_read_that_failed_or_a_missing_author_list_screens_it(self):
        (self.work / ".review").mkdir()
        (self.work / ".review" / "pr.json").write_text("gh: Server Error (HTTP 502)\n(exit status 1)\n")
        self.assertEqual(self.run_script(step("gather", self.STEP)["run"], TRUST="writer",
                                         EVENT="workflow_run")[2]["screen"], "true")
        self.assertEqual(self.screen(comments=[{"login": "alice"}], review_authors=None), "true")

    def test_review_gather_writes_the_authors_the_step_reads(self):
        """review-gather's own file, from one read: an App as name[bot], a deleted account as -, a failed read as -."""
        for answer, want in (([{"user": {"login": "oss-verify[bot]"}, "path": "a", "line": 1, "body": "x\nmallory a:1"},
                               {"user": None, "path": "b", "line": 2, "body": "y"}], ["oss-verify[bot]", "-"]),
                             (None, ["-"])):
            with self.subTest(answer=answer):
                f = self.api / f"repos_{REPO.replace('/', '_')}_pulls_7_comments.json"
                if answer is None:
                    f.unlink(missing_ok=True)
                else:
                    f.write_text(json.dumps(answer))
                script = (ROOT / ".github" / "scripts" / "review-gather").read_text()
                part = script[script.index("# One read gives both files"):script.index('rm -f "$out/review-comments.json"')]
                out = self.dir / "out"
                out.mkdir(exist_ok=True)
                # review-gather runs without -e, as its own set -uo pipefail says.
                rc, log, _ = self.run_script(f"set +e\nout={out}\n{part}", PR="7")
                self.assertEqual(rc, 0, log)
                lines = (out / "review-comment-authors.txt").read_text().splitlines()
                self.assertEqual(lines[:-1], want)
                self.assertRegex(lines[-1], r"^\(exit status \d+\)$")

    def test_a_run_started_by_hand_is_screened_as_an_events_run(self):
        """c1 (e3): a run started by hand (workflow_dispatch) is screened as an event's run is. An outside account's
        item (route's trust screen, Trust.test_a_run_by_hand_of_an_outsiders_item_is_screened) is screened whole;
        a writer's item is screened for the text of any other account it holds, and only for that (SCREEN_SCOPE
        comments), and one that holds only writers' text is not screened."""
        self.assertEqual(self.screen(trust="screen", event="workflow_dispatch"), "true")
        self.assertEqual(self.screen(comments=[{"login": "mallory"}], event="workflow_dispatch"), "true")
        self.assertEqual(self.screen(comments=[{"login": "alice"}], review_authors=["root"], event="workflow_dispatch"),
                         "false")
        scope = step("screen", "Screen")["env"]["SCREEN_SCOPE"]
        self.assertEqual([evaluate(scope, {"needs.route.outputs.trust": t}) for t in ("screen", "writer")],
                         ["all", "comments"])

    def test_an_outsiders_item_is_screened_whatever_it_holds(self):
        self.assertEqual(self.screen(trust="screen"), "true")

    def test_the_accounts_with_write_access_are_named_for_the_screen(self):
        """The screen reads none of their text, whatever the trust (.github/scripts/screen.py, SCREEN_WRITERS):
        it is this project's own. An account the API cannot place, and one without write access, are not named."""
        self.screen(trust="screen", comments=[{"login": "alice"}, {"login": "mallory"}, None],
                    reviews=[{"login": "root"}], review_authors=["alice", "oss-verify[bot]", "-"])
        self.assertEqual(self.last["writers"], "alice,oss-verify[bot],root")
        self.screen(trust="screen", comments=[{"login": "mallory"}], review_authors=[])
        self.assertEqual(self.last["writers"], "")

    def test_an_apps_own_comment_is_named_by_its_id_and_not_by_a_login(self):
        """gh names an App without its [bot], and a user can take that name: the step confirms the App comment
        by comment, by the account type the REST API gives, and names the comment, not the account. A login the
        REST API gives with its [bot] cannot be another account's, so that one is a writer."""
        self.screen(trust="screen", comments=[({"login": "sjawhar-agent"}, 900), ({"login": "sjawhar-agent"}, 901)],
                    review_authors=["oss-verify[bot]"])
        self.assertEqual(self.last["app_comments"], "900")
        self.assertEqual(self.last["writers"], "oss-verify[bot]")

    def test_a_read_that_failed_names_no_writer(self):
        """Then the screen reads every comment, as it did before any of them was told apart."""
        (self.work / ".review").mkdir()
        (self.work / ".review" / "pr.json").write_text("gh: Server Error (HTTP 502)\n(exit status 1)\n")
        got = self.run_script(step("gather", self.STEP)["run"], TRUST="screen", EVENT="workflow_run")[2]
        self.assertEqual((got["screen"], got["writers"]), ("true", ""))


# git for the gather job's run: `fetch` takes the commit from the local repository $UPSTREAM in place of the project's
# https URL, or fails as a fetch that cannot reach it does when $FETCH_FAILS is set; `ls-remote` answers nothing; every
# other command is git's own ($REAL_GIT).
FAKE_GIT = r"""#!/usr/bin/env bash
args=("$@")
for ((i = 0; i < $#; i++)); do
  case ${args[i]} in
    -C|-c) i=$((i + 1)) ;;
    fetch)
      [ -z "${FETCH_FAILS:-}" ] || { echo "fatal: unable to access the project's repository" >&2; exit 128; }
      exec "$REAL_GIT" -C "$2" fetch -q "$UPSTREAM" "${args[$# - 1]}" ;;
    ls-remote) exit 0 ;;
    *) break ;;
  esac
done
exec "$REAL_GIT" "$@"
"""

# gh for the gather job's run: the pull request (gh pr view, gh pr diff) and the compare of this repository (its
# status, and the diff) from files under $FAKE_GH; every other `gh api` from the stand-in FAKE_GH, here gh-api.
GATHER_GH = r"""#!/usr/bin/env bash
case "$1 $2" in
  "pr view") case "$*" in *statusCheckRollup*) echo '{"statusCheckRollup": []}' ;; *) cat "$FAKE_GH/pr-view.json" ;; esac ;;
  "pr diff") cat "$FAKE_GH/pr.diff" ;;
  "pr list") exit 1 ;;
  *) case "$*" in
       *"/oss-verify/compare/"*"--jq .status"*) cat "$FAKE_GH/compare-status" ;;
       *"/oss-verify/compare/"*) cat "$FAKE_GH/compare.diff" ;;
       *) exec "$(dirname "$0")/gh-api" "$@" ;;
     esac ;;
esac
"""


class GatherJob(Runner):
    """The gather job of an enrollment of mallory, an account without write access, run step by step from its step
    "Gather what the review reads, and the diff since the last review", in a checkout of main with the real
    review-gather and take-review-data, against a project repository that is a local git repository (FAKE_GIT); then
    what the review job and the screen job each take of what it kept, and what the screen reads of it. The steps
    before it gave what take-project took (the project libx) and the Build run's results (BUILD, COMMIT, BINARIES,
    CHECKS, and the step build's output sizes when a test gives it)."""

    GATHER = "Gather what the review reads, and the diff since the last review"
    SESSION = "09227178-7bbf-4e5f-86db-8736e530ef01"
    HEAD = "c" * 40
    REVIEWED = "b" * 40

    def setUp(self):
        super().setUp()
        git = shutil.which("git")
        if not git:
            self.skipTest("needs git")
        bin_dir = self.dir / "bin"
        (bin_dir / "gh-api").write_text(FAKE_GH)
        for name, text in (("gh", GATHER_GH), ("git", FAKE_GIT), ("dpkg", "#!/bin/sh\nexit 0\n")):
            (bin_dir / name).write_text(text)
        for path in bin_dir.iterdir():
            path.chmod(0o755)
        # The project's repository, at the commit the build resolved: a fuzz target, files Claude Code would read as
        # instructions, and a symbolic link out of it.
        upstream = self.dir / "upstream"
        (upstream / "lib").mkdir(parents=True)
        (upstream / "fuzz.c").write_text("int LLVMFuzzerTestOneInput() { return 0; } /* UPSTREAM-SOURCE */\n")
        (upstream / "CLAUDE.md").write_text("UPSTREAM-INSTRUCTIONS\n")
        (upstream / "lib" / "AGENTS.md").write_text("UPSTREAM-INSTRUCTIONS\n")
        (upstream / "link").symlink_to("/etc/passwd")
        quiet = {"capture_output": True, "check": True, "cwd": upstream,
                 "env": dict(os.environ, GIT_AUTHOR_NAME="u", GIT_AUTHOR_EMAIL="u@example.com",
                             GIT_COMMITTER_NAME="u", GIT_COMMITTER_EMAIL="u@example.com")}
        subprocess.run([git, "init", "-q"], **quiet)
        subprocess.run([git, "add", "-A"], **quiet)
        subprocess.run([git, "-c", "commit.gpgsign=false", "commit", "-qm", "x"], **quiet)
        self.commit = subprocess.run([git, "rev-parse", "HEAD"], text=True, **quiet).stdout.strip()
        # The checkout of main: review-gather, take-review-data and the rules of oss-verify validate (validate_rules)
        # are this repository's own, triage.py a stand-in (it reads GitHub), and projects/libx/ the pull request's, as
        # take-project leaves it. It has no src/: the gather job loads no code from it.
        self.checkout = self.dir / "checkout"
        scripts = self.checkout / ".github" / "scripts"
        scripts.mkdir(parents=True)
        for name in ("review-gather", "take-review-data", "validate_rules"):
            (scripts / name).symlink_to(SCRIPTS / name)
        (scripts / "triage.py").write_text('print("| OK | triage |")\n')
        (self.checkout / ".github" / "PULL_REQUEST_TEMPLATE.md").symlink_to(ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md")
        (self.checkout / "projects" / "libx").mkdir(parents=True)
        (self.checkout / "projects" / "libx" / "project.yaml").write_text("repo: https://github.com/mallory/libx#v1\n")
        self.home = self.dir / "gather-home"
        self.home.mkdir()
        (self.api / "pr-view.json").write_text(json.dumps({
            "number": 7, "title": "Add libx", "author": {"login": "mallory"}, "isDraft": False,
            "createdAt": "2026-11-01T00:00:00Z", "body": "MALLORY-BODY", "headRefOid": self.HEAD,
            "files": [{"path": "projects/libx/project.yaml"}], "comments": [], "reviews": [],
            "commits": [{"messageHeadline": "MALLORY-COMMIT", "messageBody": ""}]}) + "\n")
        (self.api / "pr.diff").write_text("diff --git a/projects/libx/project.yaml b/projects/libx/project.yaml\n"
                                          "+repo: https://github.com/mallory/libx#v1\n")
        self.serve(f"repos/{REPO}/pulls/7/comments", [])
        self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": self.HEAD}})
        self.permissions(alice="write")
        self.env.update(REAL_GIT=git, UPSTREAM=str(upstream), KIND="enrollment", PR="7", ISSUE="", NAME="libx",
                        HEAD_SHA=self.HEAD, BUILD="The Build check success: passed.", BINARIES="",
                        CHECKS="", HOME=str(self.home))

    def keep_session(self, last):
        """What the gather job's step "Restore the last review's session and the head it reviewed" restores."""
        (self.home / ".claude" / "projects" / "p").mkdir(parents=True)
        (self.home / ".claude" / "projects" / "p" / f"{self.SESSION}.jsonl").write_text("{}\n")
        (self.home / ".claude" / "ossv-last-review").write_text(last)

    def gather_job(self, trust="screen", commit=None, fetch_fails=False, compare_status=None, compare_diff="",
                   sizes=None):
        """The gather job's steps from GATHER on, each whose if holds, in a checkout with nothing gathered yet: (the
        first failing step's exit status or 0, the log, the job's outputs). GitHub gives the outputs of a job that
        failed too, from the steps that ran. `sizes` is the output sizes of the step build, which runs before GATHER
        (none when it is None)."""
        shutil.rmtree(self.checkout / ".review", ignore_errors=True)
        shutil.rmtree(self.temp / "review-data", ignore_errors=True)
        (self.api / "compare-status").write_text(f"{compare_status}\n" if compare_status else "")
        (self.api / "compare.diff").write_text(compare_diff)
        env = {"TRUST": trust, "COMMIT": self.commit if commit is None else commit,
               "FETCH_FAILS": "1" if fetch_fails else ""}
        ctx = {"env.KIND": "enrollment", "env.TRUST": trust, "steps.project.outputs.kind": "enrollment",
               "steps.project.outputs.name": "libx"}
        if sizes is not None:
            ctx["steps.build.outputs.sizes"] = sizes
        steps = REVIEW_JOBS["gather"]["steps"]
        start = [s.get("name") for s in steps].index(self.GATHER)
        log, rc = "", 0
        for s in steps[start:]:
            if "run" not in s or ("if" in s and not evaluate(s["if"], ctx)):
                continue
            rc, out, got = self.run_script(s["run"], cwd=self.checkout, **env)
            log += out
            if "id" in s:
                ctx.update({f"steps.{s['id']}.outputs.{k}": v for k, v in got.items()})
            if rc:
                break
        return rc, log, {k: as_text(evaluate(v, ctx)) for k, v in REVIEW_JOBS["gather"]["outputs"].items()}

    def take(self, job, digest):
        """take-review-data in a fresh checkout for `job`: the review job gives its home, the screen job none.
        Return the checkout and the home."""
        where, home = self.dir / f"{job}-checkout", self.dir / f"{job}-home"
        for path in (where, home):
            shutil.rmtree(path, ignore_errors=True)
            path.mkdir()
        args = f' "{home}"' if job == "review" else ""
        rc, out, _ = self.run_script(f'{SCRIPTS / "take-review-data"} "{self.temp / "review-data" / "review.tar"}"{args}',
                                     cwd=where, DIGEST=digest)
        self.assertEqual(rc, 0, out)
        return where, home

    def screen_reads(self, where):
        """What .github/scripts/screen.py sends to its checks of the screen job's checkout, as its Screen step runs it
        for an outside account's item (SCREEN_SCOPE all): {source: text}, and what it cannot screen."""
        code = ("import importlib.util, json, sys; "
                "spec = importlib.util.spec_from_file_location('screen', sys.argv[1]); "
                "screen = importlib.util.module_from_spec(spec); spec.loader.exec_module(screen); "
                "found, unscreenable = screen.parts(sys.argv[2], sys.argv[3]); "
                "print(json.dumps({'found': found, 'unscreenable': unscreenable}))")
        run = subprocess.run([sys.executable, "-c", code, str(SCRIPTS / "screen.py"), str(where / ".review"),
                              str(where / "projects" / "libx")], capture_output=True, text=True,
                             env=dict(os.environ, SCREEN_SCOPE="all", SCREEN_WRITERS="", SCREEN_APP_COMMENTS=""))
        self.assertEqual(run.returncode, 0, run.stderr)
        got = json.loads(run.stdout)
        return dict(got["found"]), got["unscreenable"]


class OutsidersEnrollment(GatherJob):
    """c1 (e), (e2): the project's source at the built commit for every enrollment, an outside account's included,
    which the review reads once the screen passes and the screen does not read."""

    def test_e_the_review_gets_the_source_and_the_screen_reads_only_the_pull_requests_text(self):
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                rc, log, outputs = self.gather_job(trust=trust)
                self.assertEqual(rc, 0, log)
                self.assertEqual(outputs["screen"], "true" if trust == "screen" else "false")
                self.assertRegex(outputs["digest"], r"^[0-9a-f]{64}$")
                # The review's input: the repository at the built commit, as data: no CLAUDE.md, AGENTS.md or
                # symbolic link, no .git, and no source.txt in its place.
                review, _ = self.take("review", outputs["digest"])
                source = review / ".review" / "source"
                self.assertIn("UPSTREAM-SOURCE", (source / "fuzz.c").read_text())
                self.assertEqual(sorted(str(p.relative_to(source)) for p in source.rglob("*")), ["fuzz.c", "lib"])
                self.assertFalse((review / ".review" / "source.txt").exists())
        # The outside account's item: the screen job's checkout holds the same file, and screen.py sends none of
        # source/ to its checks, and the pull request's own text.
        rc, log, outputs = self.gather_job(trust="screen")
        self.assertEqual(rc, 0, log)
        screen, _ = self.take("screen", outputs["digest"])
        self.assertTrue((screen / ".review" / "source" / "fuzz.c").is_file())
        sent, unscreenable = self.screen_reads(screen)
        self.assertEqual(unscreenable, [])
        self.assertFalse([s for s in sent if s.startswith("source")], sorted(sent))
        text = "\n".join(sent.values())
        self.assertNotIn("UPSTREAM-SOURCE", text)
        for word in ("MALLORY-BODY", "MALLORY-COMMIT", "Add libx", "https://github.com/mallory/libx#v1"):
            self.assertIn(word, text)
        # The screen job runs before the review, which runs only on its clean verdict.
        route = dict(ITEMS["enrollment"], trust="screen")
        for verdict, reviewed in (("clean", "success"), ("held", "skipped")):
            got, _ = run_graph(route, outputs={"gather": outputs, "screen": {"verdict": verdict, "checks": "claude"}})
            self.assertEqual((got["screen"], got["review"]), ("success", reviewed))

    def test_e2_a_failed_fetch_of_the_built_commit_fails_the_gather_job(self):
        """Departure 2: the gather job fails, so a re-run of the failed jobs fetches again; nothing is kept, no screen
        or review runs, and the check review jobs fails, for any trust."""
        rc, log, outputs = self.gather_job(trust="screen", fetch_fails=True)
        self.assertNotEqual(rc, 0, log)
        self.assertIn(f"review-gather: could not fetch {self.commit} from https://github.com/mallory/libx", log)
        self.assertIn("::error::review-gather failed (its log above)", log)
        self.assertFalse((self.temp / "review-data").exists())
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                got, ctx = run_graph(dict(ITEMS["enrollment"], trust=trust), results={"gather": "failure"})
                self.assertEqual((got["gather"], got["screen"], got["review"]), ("failure", "skipped", "skipped"))
                self.assertEqual(required(ctx)[0], 1, required(ctx)[1])

    def test_with_no_built_commit_the_review_runs_without_source(self):
        """Decision 10: a build that failed before it resolved a commit leaves nothing to fetch; the job passes, and
        source.txt says that the review has no source to read."""
        rc, log, outputs = self.gather_job(trust="screen", commit="")
        self.assertEqual(rc, 0, log)
        review, _ = self.take("review", outputs["digest"])
        self.assertFalse((review / ".review" / "source").exists())
        said = (review / ".review" / "source.txt").read_text()
        self.assertTrue(said.startswith("Not gathered: "), said)
        self.assertIn("there is no source to read", said)


class OutsidersResume(GatherJob):
    """c6: on a later push the review of an outside account's enrollment resumes the session of its last review, for
    the diff since the commit that review reviewed; the screen still reads the new text first and never the session.
    Which jobs restore and save the session in the Actions cache, and its paths and keys, are SessionCache's in
    test_check_checks.py."""

    DIFF = ("diff --git a/projects/libx/build.sh b/projects/libx/build.sh\n+SINCE-DIFF-MARK\n"
            "diff --git a/README.md b/README.md\n+OTHER-FILE\n")

    def prompt(self, outputs):
        """review-prompt as the review job runs it, after a clean screen, with the session the gather job gave."""
        got, ctx = run_graph(dict(ITEMS["enrollment"], sha=self.HEAD, trust="screen"),
                             outputs={"gather": outputs, "screen": {"verdict": "clean", "checks": "claude"}})
        self.assertEqual((got["screen"], got["review"]), ("success", "success"))
        env = {k: as_text(evaluate(v, ctx)) for k, v in step("review", "What the review reads and gives")["env"].items()}
        rc, out, got = self.run_script(f"{SCRIPTS / 'review-prompt'}", cwd=ROOT, **env)
        self.assertEqual(rc, 0, out)
        return got

    def test_a_a_push_that_descends_from_the_reviewed_commit_resumes_the_session_for_the_diff_since(self):
        self.keep_session(f"session={self.SESSION} head={self.REVIEWED}\n")
        rc, log, outputs = self.gather_job(compare_status="ahead", compare_diff=self.DIFF)
        self.assertEqual(rc, 0, log)
        self.assertIn(f"the review resumes the session {self.SESSION}, for the diff from {self.REVIEWED}", log)
        self.assertEqual((outputs["screen"], outputs["session"], outputs["last"]), ("true", self.SESSION, self.REVIEWED))
        review, home = self.take("review", outputs["digest"])
        self.assertEqual((review / ".review" / "since-last-review.diff").read_text(),
                         "diff --git a/projects/libx/build.sh b/projects/libx/build.sh\n+SINCE-DIFF-MARK\n"
                         "(exit status 0)\n")
        self.assertTrue((home / ".claude" / "projects" / "p" / f"{self.SESSION}.jsonl").is_file())
        self.assertEqual((home / ".claude" / "ossv-last-review").read_text(),
                         f"session={self.SESSION} head={self.REVIEWED}\n")
        got = self.prompt(outputs)
        self.assertTrue(got["arguments"].endswith(f" --resume {self.SESSION}"), got["arguments"])
        # The screen reads the new diff, and no session reaches it.
        screen, screen_home = self.take("screen", outputs["digest"])
        self.assertEqual(list(screen_home.iterdir()), [])
        self.assertFalse((screen / ".claude").exists())
        sent, _ = self.screen_reads(screen)
        self.assertIn("SINCE-DIFF-MARK", sent["since-last-review.diff"])

    def test_b_a_force_push_gets_a_fresh_review(self):
        self.keep_session(f"session={self.SESSION} head={self.REVIEWED}\n")
        rc, log, outputs = self.gather_job(compare_status="diverged", compare_diff=self.DIFF)
        self.assertEqual(rc, 0, log)
        self.assertIn(f"no diff from {self.REVIEWED}", log)
        self.assertIn("the review is fresh", log)
        self.assertEqual((outputs["session"], outputs["last"]), ("", ""))
        review, _ = self.take("review", outputs["digest"])
        self.assertFalse((review / ".review" / "since-last-review.diff").exists())
        self.assertNotIn("--resume", self.prompt(outputs)["arguments"])

    def test_c_a_first_review_is_fresh(self):
        rc, log, outputs = self.gather_job(compare_status="ahead", compare_diff=self.DIFF)
        self.assertEqual(rc, 0, log)
        self.assertNotIn("resumes the session", log)
        self.assertEqual((outputs["session"], outputs["last"]), ("", ""))
        review, home = self.take("review", outputs["digest"])
        self.assertFalse((review / ".review" / "since-last-review.diff").exists())
        self.assertEqual(list(home.iterdir()), [])
        self.assertNotIn("--resume", self.prompt(outputs)["arguments"])

    def test_an_enrollment_of_either_trust_restores_its_session_and_build_yaml_touches_no_cache(self):
        """What the tests above put in the gather job's home is what its restore step gives an enrollment, whatever
        the trust, and the session job saves what a screened review kept. build.yaml, whose runs are a pull request's,
        neither reads nor writes the cache."""
        self.assertEqual({BUILD["cache-mode"], *(j.get("cache-mode", "none") for j in BUILD_JOBS.values())}, {"none"})
        restore = step("gather", "Restore the last review's session and the head it reviewed")
        for trust in ("screen", "writer"):
            self.assertTrue(evaluate(restore["if"], {"steps.project.outputs.kind": "enrollment", "env.TRUST": trust}))
        got, _ = run_graph(dict(ITEMS["enrollment"], sha=self.HEAD, trust="screen"),
                           outputs={"screen": {"verdict": "clean", "checks": "claude"},
                                    "review": {"comment": "x", "held_object": "", "session": "41", "kind": "enrollment"}})
        self.assertEqual((got["screen"], got["review"], got["session"]), ("success", "success", "success"))


class TriageFacts(GatherJob):
    """The criticality score and OSS-Fuzz that .github/scripts/triage.py --facts writes in the same run as --full: the
    step gather gives them, and the job gives them as its outputs criticality_score and oss_fuzz, for the comment
    job's record, each as its JSON type or null. They go in no file that the gather job keeps."""

    TABLE = "| OK | Criticality score | 0.07 |"
    # The file of the stand-in triage.py's arguments, in the test's directory.
    ARGV = "triage-argv.json"

    def triage(self, facts):
        """The stand-in triage.py: its arguments in the file ARGV of the test's directory, the full table on standard
        output only for --full, and the text `facts` in the file after --facts."""
        (self.checkout / ".github" / "scripts" / "triage.py").write_text(
            "import json, sys\n"
            f"json.dump(sys.argv[1:], open({str(self.dir / self.ARGV)!r}, 'w'))\n"
            f"print({self.TABLE!r} if '--full' in sys.argv else 'THE-COMMENT')\n"
            "if '--facts' in sys.argv:\n"
            f"    open(sys.argv[sys.argv.index('--facts') + 1], 'w').write({facts!r})\n")

    @staticmethod
    def facts(outputs):
        """The job's outputs criticality_score and oss_fuzz."""
        return outputs["criticality_score"], outputs["oss_fuzz"]

    def test_the_job_gives_the_score_and_oss_fuzz_and_the_review_the_full_table(self):
        self.triage('{"criticality_score": 0.07123, "oss_fuzz": false}\n')
        rc, log, outputs = self.gather_job()
        self.assertEqual(rc, 0, log)
        self.assertEqual(self.facts(outputs), ("0.07123", "false"))
        # review-gather runs it with exactly these arguments: --full, and --facts with a file outside .review.
        argv = json.loads((self.dir / self.ARGV).read_text())
        self.assertEqual(argv[:-1], ["--repo", REPO, "--pr", "7", "--full", "--facts"])
        facts = pathlib.Path(os.path.normpath(self.checkout / argv[-1]))
        self.assertNotIn(self.checkout / ".review", [facts, *facts.parents])
        review, _ = self.take("review", outputs["digest"])
        self.assertEqual((review / ".review" / "triage-today.md").read_text(), f"{self.TABLE}\n(exit status 0)\n")
        # The file of the facts is in no member of what the screen and the review take, and gone from the checkout.
        with tarfile.open(self.temp / "review-data" / "review.tar") as tar:
            names = tar.getnames()
        self.assertIn(".review/triage-today.md", names)
        self.assertEqual([n for n in names if "facts" in n], [])
        self.assertEqual(list(self.checkout.rglob("*facts*")), [])
        # The step writes them before it fetches the project's repository: a fetch that fails does not lose them.
        rc, log, outputs = self.gather_job(fetch_fails=True)
        self.assertNotEqual(rc, 0, log)
        self.assertEqual(self.facts(outputs), ("0.07123", "false"))
        self.assertEqual(list(self.checkout.rglob("*facts*")), [])

    def test_a_value_of_another_type_or_a_file_that_is_not_one_object_gives_null(self):
        with self.subTest(facts="no file: the stand-in of setUp"):
            rc, log, outputs = self.gather_job()
            self.assertEqual(rc, 0, log)
            self.assertEqual(self.facts(outputs), ("null", "null"))
        for facts, want in (('{"criticality_score": "x", "oss_fuzz": true}', ("null", "true")),
                            ('{"criticality_score": true, "oss_fuzz": false}', ("null", "false")),
                            ('{"criticality_score": 0.5, "oss_fuzz": "yes"}', ("0.5", "null")),
                            ('{"criticality_score": 0.5, "oss_fuzz": tru', ("null", "null")),
                            ("not JSON\n", ("null", "null")),
                            ('[{"criticality_score": 0.5, "oss_fuzz": true}]', ("null", "null"))):
            with self.subTest(facts=facts):
                self.triage(facts)
                rc, log, outputs = self.gather_job()
                self.assertEqual(rc, 0, log)
                self.assertEqual(self.facts(outputs), want)
                self.assertEqual(list(self.checkout.rglob("*facts*")), [])


class BuildSizes(GatherJob):
    """The binaries' sizes of the Build run's results, which the step build (.github/scripts/take-build-results) gives
    before the step gather: the job gives them as its output sizes, for the comment job's record, and empty when the
    step gave none."""

    SIZES = '{"parse":{"plain":{"text":1000,"exec":1200},"asan":{"text":3000,"exec":null}}}'

    def test_the_job_gives_the_sizes_of_the_step_build(self):
        rc, log, outputs = self.gather_job(sizes=self.SIZES)
        self.assertEqual(rc, 0, log)
        self.assertEqual(outputs["sizes"], self.SIZES)

    def test_with_no_sizes_of_the_step_build_the_output_is_empty(self):
        rc, log, outputs = self.gather_job()
        self.assertEqual(rc, 0, log)
        self.assertEqual(outputs["sizes"], "")


class TrustWiring(unittest.TestCase):
    def test_the_trust_step_reads_the_author_and_the_account_that_started_the_run(self):
        """The author of a pull request as the decide step read it from the API, never from the event (a workflow_run
        run's event is the Build run's), or the issue's author from the issue's own event; the account that started the
        run (github.actor, not the account of a re-run); and the event."""
        e = step("route", Trust.STEP)["env"]
        pull = {"steps.decide.outputs.author": "mallory", "github.event.issue.user.login": "eve",
                "github.actor": "alice", "github.triggering_actor": "bob", "github.event_name": "workflow_run"}
        issue = {"steps.decide.outputs.author": "", "github.event.issue.user.login": "eve", "github.actor": "eve",
                 "github.event_name": "issues"}
        for ctx, want in ((pull, ("mallory", "alice", "workflow_run")), (issue, ("eve", "eve", "issues"))):
            self.assertEqual(tuple(interpolated(e[k], ctx) for k in ("AUTHOR", "ACTOR", "EVENT")), want, ctx)


class ScreenedFooter(unittest.TestCase):
    """The review comment names the checks of the screen that ran, so a clean verdict from fewer checks does not read
    as one from all three."""

    def body(self, screened):
        return subprocess.run([str(SCRIPTS / "review-body")], capture_output=True, text=True, env={
            **os.environ, "HEAD_SHA": "a" * 40, "REVIEW": "Thanks.", "CHECKS": "", "CONCLUSION": "success",
            "RULES": "review.md", "SCREENED": screened})

    def test_a_screened_review_names_the_checks_that_ran(self):
        for screened, names in (("model_armor", "Google Cloud Model Armor"),
                                ("model_armor,prompt_shields",
                                 "Google Cloud Model Armor, Azure AI Content Safety Prompt Shields"),
                                ("model_armor,prompt_shields,claude", "Google Cloud Model Armor, Azure AI Content "
                                 "Safety Prompt Shields, a Claude model with no tools")):
            with self.subTest(screened=screened):
                run = self.body(screened)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn(f"An automated screen passed it first; the checks that ran: {names}.", run.stdout)
        self.assertNotIn("screen", self.body("").stdout)
        # The comment job gives the checks of the screen that ran, and none when the gather job found nothing to
        # screen, whatever the screen job's outputs say.
        screened = step("comment", "Post the comment and record the verdict")["env"]["SCREENED"]
        for gathered, checks, want in (("true", "model_armor,claude", "model_armor,claude"),
                                       ("false", "model_armor", ""), ("true", "", "")):
            ctx = {"needs.gather.outputs.screen": gathered, "needs.screen.outputs.checks": checks}
            self.assertEqual(interpolated(screened, ctx), want, ctx)

    def test_anything_else_is_refused(self):
        for screened in ("x; rm -rf /", "model_armor,", "@octocat", "model_armor,other"):
            with self.subTest(screened=screened):
                self.assertNotEqual(self.body(screened).returncode, 0)


class RunWiring(unittest.TestCase):
    """The events build.yaml and review.yml start on and their concurrency, a screened review that ran out of time, and
    the Apps the review admits."""

    @staticmethod
    def group(ctx, workflow=REVIEW):
        return interpolated(workflow["concurrency"]["group"], ctx)

    @staticmethod
    def cancels(ctx, workflow=REVIEW):
        cancel = workflow["concurrency"]["cancel-in-progress"]
        return cancel if isinstance(cancel, bool) else evaluate(cancel, ctx)

    def test_it_starts_on_no_label_event_and_a_push_cancels_the_run_going(self):
        """No label event of a pull request (labeled, unlabeled) starts Build, and a push cancels the run of its older
        head. Review starts when a run of Build or Triage completes (by their names), on an issue's events, and by hand.
        A run after a Build run has a group of its own, by that run's id: no run of another Build run cancels it, so a
        second pull request from the same head repository and branch never cancels the review of the first, and a
        re-run of the same run cancels the run of its earlier attempt. A run after a
        Triage run that ended success has one group for the head repository and branch of that run. route triages only
        the pull request into the default branch, so a second pull request from the same branch into another base gets
        no triage, and the shared group cancels no triage of it. Of two Triage runs of one pull request, the run after
        the newer cancels the run after the older, so the triage comment is of the newest description. A run after a
        Triage run that ended skipped, cancelled or failure writes no triage comment (route stops it). It has a group of
        its own, by that run's id, so that it cancels no run that writes one. A run by hand cancels the run already
        going in its group; an issue's event waits for it."""
        on = BUILD.get("on", BUILD.get(True))
        self.assertFalse({"labeled", "unlabeled"} & set(on["pull_request"]["types"]), on)
        pr = {"github.event_name": "pull_request", "github.event.pull_request.number": 7}
        for action in ("opened", "reopened", "synchronize", "ready_for_review"):
            with self.subTest(action=action):
                ctx = dict(pr, **{"github.event.action": action})
                self.assertEqual((self.group(ctx, BUILD), self.cancels(ctx, BUILD)), ("build-pull_request-7", True))
        on = REVIEW.get("on", REVIEW.get(True))
        triage = read_workflow("triage.yaml")
        # And after a Review approvals run, which only refreshes the check run review (the refresh job).
        self.assertEqual(on["workflow_run"]["workflows"],
                         [BUILD["name"], triage["name"], read_workflow("review-approvals.yml")["name"]])
        # Runs 900 and 901 of Build are of two pull requests from mallory/libx's branch main, one into main and one into
        # another base. The review of each run has a group of its own. Runs 902 and 903 of Triage are of the first,
        # after two edits of its description. Their runs share one group, and the newer run cancels the older. Runs 904,
        # 905 and 906 of Triage are of the first too, and ended skipped (an edit of the title alone), cancelled and
        # failure. The run after each has a group of its own, so it cancels no run after 902 or 903.
        run = {"github.event_name": "workflow_run", "github.event.workflow_run.head_branch": "main",
               "github.event.workflow_run.head_repository.full_name": "mallory/libx"}
        shared = "review-workflow_run-Triage-mallory/libx:main"
        for name, run_id, conclusion, group in (("Build", 900, "success", "review-workflow_run-900"),
                                                ("Build", 901, "success", "review-workflow_run-901"),
                                                ("Triage", 902, "success", shared), ("Triage", 903, "success", shared),
                                                ("Triage", 904, "skipped", "review-workflow_run-904"),
                                                ("Triage", 905, "cancelled", "review-workflow_run-905"),
                                                ("Triage", 906, "failure", "review-workflow_run-906"),
                                                ("Review approvals", 907, "success", "review-workflow_run-907")):
            with self.subTest(workflow_run=name, run_id=run_id, conclusion=conclusion):
                ctx = dict(run, **{"github.event.workflow_run.name": name, "github.event.workflow_run.id": run_id,
                                   "github.event.workflow_run.conclusion": conclusion})
                self.assertEqual((self.group(ctx), self.cancels(ctx)), (group, True))
        by_hand = {"github.event_name": "workflow_dispatch", "inputs.pr": 7}
        self.assertEqual((self.group(by_hand), self.cancels(by_hand)), ("review-workflow_dispatch-7", True))
        issue = {"github.event_name": "issues", "github.event.action": "edited", "github.event.issue.number": 9,
                 "github.event.sender.login": "eve", "github.event.issue.user.login": "eve"}
        self.assertEqual((self.group(issue), self.cancels(issue)), ("review-issues-9", False))

    def test_a_screened_review_that_ran_out_of_time_is_held(self):
        """A review job that runs out of its own time ends cancelled, and the run goes on (when the whole run is
        cancelled, no job after it runs): the comment job holds the item."""
        got, ctx = run_graph(dict(ITEMS["change"], trust="screen"), results={"review": "cancelled"},
                             outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "collect"},
                         {"gather", "screen", "review", "comment"})
        self.assertEqual(evaluate(REVIEW_JOBS["comment"]["env"]["HOLDING"], ctx), True)
        self.assertNotEqual(required(ctx)[0], 0)

    def test_the_review_admits_the_apps_of_allowed_bots_alone(self):
        """Each attempt of the review gives the action, as its allowed_bots, the one list of Apps whose runs it admits:
        the workflow's ALLOWED_BOTS, which route reads through .github/scripts/actor-kind, whatever the list holds."""
        listed = "an-app[bot],another-app[bot]"
        attempts = [(job, s) for job, j in REVIEW_JOBS.items() for s in j["steps"]
                    if "claude-code-action@" in s.get("uses", "")]
        self.assertTrue(attempts, "no step runs claude-code-action")
        for job, s in attempts:
            ctx = {f"env.{k}": v for k, v in step_env(job, s, ALLOWED_BOTS=listed).items()}
            self.assertEqual(interpolated(s["with"]["allowed_bots"], ctx), listed, s["name"])
