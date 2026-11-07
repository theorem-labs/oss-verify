# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of build.yaml's screen of pull requests and issues from accounts without write access:  python3 -m pytest
tools/tests

route's trust step (who is screened, the hourly limit), which jobs run for each route and each answer of the screen
(the jobs' conditions, evaluated as GitHub does), what the required check reports, what each job holds, how the screen
and the review take the gathered data (.github/scripts/take-review-data), the gather job's check that the head did not
move, the comment job's hold, the review comment's line on the checks that ran, and how an item held at the hourly
limit is screened again (review-rescreen.yml, .github/scripts/review-rescreen and limit-hold, and route's check of a
rescreen). .github/scripts/screen.py itself is tested in test_screen.py."""
import datetime
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
WF = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
JOBS = WF["jobs"]
REPO = "theorem-labs/oss-verify"

# gh api <endpoint> [--paginate] [--jq <filter>] [--method M] [-f|-F k=v] [--input -], answered from
# $FAKE_GH/<endpoint>.json (the endpoint's slashes as underscores, its query dropped) through jq, as gh applies --jq;
# an endpoint with no file answers as GitHub's 404 does. Each call's arguments go to $FAKE_GH/args, and what it read
# on its standard input (--input -) to $FAKE_GH/input.<n>.
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
endpoint=${endpoint%%\?*}
printf '%s\0' "${all[@]}" >> "$FAKE_GH/args"; printf '\1' >> "$FAKE_GH/args"
n=$(tr -cd '\1' < "$FAKE_GH/args" | wc -c)
[ "$input" != - ] || cat > "$FAKE_GH/input.$n"
file="$FAKE_GH/${endpoint//\//_}.json"
[ -f "$file" ] || { echo "gh: Not Found (HTTP 404): $endpoint" >&2; exit 1; }
jq -r "$filter" "$file"
"""


def evaluate(expression, ctx):
    """A GitHub Actions expression, with or without ${{ }}, as GitHub evaluates it for what these tests need: string,
    whole number, boolean and null literals, contexts looked up whole in ctx (a missing one is null), == and !=
    (strings compared without case), !, && and || (which give an operand, not a boolean), parentheses, and the
    functions format, cancelled and always. cancelled() is false: these tests run no cancelled run."""
    text = str(expression).strip()
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

    def truthy(v):
        return v not in (None, False, "", 0)

    def eq(a, b):
        a = "" if a is None else a
        b = "" if b is None else b
        if isinstance(a, str) and isinstance(b, str):
            return a.lower() == b.lower()
        return a == b

    def primary():
        t = take()
        if t == "(":
            v = disjunction()
            take(")")
            return v
        if t == "!":
            return not truthy(primary())
        if t.startswith("'"):
            return t[1:-1].replace("''", "'")
        if t.isdigit():
            return int(t)
        if t in ("true", "false"):
            return t == "true"
        if t == "null":
            return None
        if peek() == "(":
            take("(")
            args = []
            while peek() != ")":
                args.append(disjunction())
                if peek() == ",":
                    take(",")
            take(")")
            if t == "format":
                return re.sub(r"\{(\d+)\}", lambda m: as_text(args[1 + int(m.group(1))]), args[0])
            assert t in ("cancelled", "always") and not args, "no such function here: " + t
            return t == "always"
        return ctx.get(t)

    def comparison():
        v = primary()
        while peek() in ("==", "!="):
            op = take()
            w = primary()
            v = eq(v, w) if op == "==" else not eq(v, w)
        return v

    def conjunction():
        v = comparison()
        while peek() == "&&":
            take()
            w = comparison()
            v = w if truthy(v) else v
        return v

    def disjunction():
        v = conjunction()
        while peek() == "||":
            take()
            w = conjunction()
            v = v if truthy(v) else w
        return v

    v = disjunction()
    assert pos[0] == len(toks), (toks[pos[0]:], text)
    return v


def as_text(v):
    """A value as an env or output gets it."""
    return "true" if v is True else "false" if v is False else "" if v is None else str(v)


STATUS_FUNCTIONS = re.compile(r"\b(cancelled|always|success|failure)\(\)")
ORDER = ["route", "project-builds", "record", "gather", "screen", "review", "session", "hold", "comment", "required"]


def run_graph(route, results=None, outputs=None, event="pull_request_target"):
    """The result of each job, as GitHub decides it: a job runs when its if is true, and an if with no status function
    also needs every job it needs to have succeeded (GitHub's implicit success()). route is route's outputs; results
    and outputs give a job that runs another result than success, and its outputs. A job that did not succeed has no
    outputs unless they are given. Return (results, the context)."""
    results, outputs = dict(results or {}), dict(outputs or {})
    assert set(ORDER) == set(JOBS), set(JOBS)
    ctx = {"github.event_name": event, "github.event.pull_request.number": "7"}
    got = {}
    defaults = {"project-builds": {"name": "libx", "sha": "a" * 40},
                "gather": {"digest": "d" * 64, "screen": "true" if route.get("trust") == "screen" else "false"},
                "review": {"comment": "Thanks.", "held_object": "", "session": "", "kind": route.get("kind", "")}}
    for name in ORDER:
        job = JOBS[name]
        if name == "route":
            ran = True
        else:
            needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
            condition = job.get("if")
            ran = condition is None or bool(evaluate(condition, ctx))
            if condition is None or not STATUS_FUNCTIONS.search(str(condition)):
                ran = ran and all(got[n] == "success" for n in needs)
        got[name] = results.get(name, "success") if ran else "skipped"
        out = (route if name == "route" else outputs.get(name, defaults.get(name, {}))
               if ran and (got[name] == "success" or name in outputs) else {})
        ctx[f"needs.{name}.result"] = got[name]
        for key, value in out.items():
            ctx[f"needs.{name}.outputs.{key}"] = value
    return got, ctx


def required(ctx):
    """What the required check's collect step answers for this run: (exit status, output)."""
    step = JOBS["required"]["steps"][-1]
    env = {k: as_text(evaluate(v, ctx)) for k, v in step["env"].items()}
    # Each "job:$RESULT:$ASKED" argument, with its values.
    args = []
    for word in re.findall(r'"([^"]+)"', step["run"]):
        args.append(re.sub(r"\$([A-Z_]+)", lambda m: env[m.group(1)], word))
    run = subprocess.run([str(SCRIPTS / "collect"), *args], capture_output=True, text=True,
                         env={**os.environ, "GITHUB_STEP_SUMMARY": os.devnull})
    return run.returncode, run.stdout


def step(job, name):
    found = [s for s in JOBS[job]["steps"] if s.get("name") == name]
    assert len(found) == 1, f"{len(found)} steps named {name!r} in {job}"
    return found[0]


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
                        **{k: str(v) for k, v in WF["env"].items()})

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

    def trust(self, event, author="", actor="", runs=(), measure=""):
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [
            {"id": i, "actor": {"login": who}, "triggering_actor": {"login": "someone-else"}, "event": e}
            for i, who, e in runs]})
        return self.run_script(step("route", self.STEP)["run"], EVENT=event, AUTHOR=author, ACTOR=actor,
                               RUN_ID="100", MEASURE=measure, RESCREEN="", ACCOUNT="", NUMBER="")

    def assertTrust(self, want, *args, **kwargs):
        rc, out, got = self.trust(*args, **kwargs)
        self.assertEqual((rc, got.get("trust")), (0, want), out)
        # When it decided, which the comment job compares with the time of a hold.
        self.assertRegex(got.get("started", ""), r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
        return out

    def test_writers_are_reviewed_as_they_come(self):
        self.permissions(alice="write", root="admin")
        for event in ("pull_request_target", "issues"):
            self.assertTrust("writer", event, "alice", "root")

    def test_an_account_without_write_access_is_screened_with_no_maintainer(self):
        self.permissions(alice="write", mallory="read", tess="triage", nobody="none")
        for author, actor in (("mallory", "mallory"), ("nobody", "nobody"), ("tess", "tess"),
                              ("alice", "mallory"), ("mallory", "alice")):
            with self.subTest(author=author, actor=actor):
                self.assertTrust("screen", "pull_request_target", author, actor)
        self.assertTrust("screen", "issues", "mallory", "mallory")

    def test_the_organisations_apps_count_and_others_are_screened(self):
        self.assertTrust("writer", "pull_request_target", "sjawhar-agent[bot]", "sjawhar-agent[bot]")
        self.assertTrust("writer", "pull_request_target", "oss-verify[bot]", "oss-verify[bot]")
        self.assertTrust("screen", "pull_request_target", "dependabot[bot]", "dependabot[bot]")

    def test_a_run_by_hand_is_a_writers(self):
        self.assertTrust("writer", "workflow_dispatch", "", "alice")
        self.assertEqual(self.calls(), [])

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
        self.assertEqual(decide["env"]["MEASURE"], "${{ inputs.measure }}")
        for pr, issue, want in (("", "", (0, "true")), ("7", "", (1, None)), ("", "5", (1, None))):
            with self.subTest(pr=pr, issue=issue):
                rc, out, got = self.run_script(decide["run"], EVENT="workflow_dispatch", MEASURE="true", PR=pr,
                                               ISSUE=issue, HEAD_SHA="", ACTOR="alice", SENDER="alice", AUTHOR="",
                                               ASSOCIATION="")
                self.assertEqual((rc, got.get("measure")), want, out)
                self.assertNotIn("kind", got)
        self.assertEqual(step("route", self.STEP)["if"],
                         "steps.decide.outputs.kind != '' || steps.decide.outputs.measure == 'true'")

    def test_a_permission_github_does_not_give_stops_the_run(self):
        rc, out, got = self.trust("pull_request_target", "alice", "alice")
        self.assertEqual((rc, got.get("trust")), (1, None), out)
        self.assertIn("did not say whether alice has write access", out)

    def test_a_login_that_is_not_one_is_never_a_writer(self):
        self.permissions(**{"a": "admin"})
        self.assertTrust("screen", "issues", "a/../b", "a/../b")
        self.assertTrust("screen", "issues", "x[bot][bot]", "a")


class HourlyLimit(Runner):
    """OUTSIDE_HOURLY_LIMIT: the runs one account without write access starts by its events in an hour."""

    LIMIT = int(WF["env"]["OUTSIDE_HOURLY_LIMIT"])
    STEP = Trust.STEP

    def setUp(self):
        super().setUp()
        self.permissions(alice="write", mallory="read", eve="read")

    def route(self, author, actor, runs, event="issues"):
        rc, out, got = Trust.trust(self, event, author, actor, runs)
        self.assertEqual(rc, 0, out)
        return got.get("trust")

    def test_the_limit_holds(self):
        self.assertGreater(self.LIMIT, 1)
        below = [(10 + i, "mallory", "issues") for i in range(self.LIMIT - 1)]
        self.assertEqual(self.route("mallory", "mallory", below), "screen")
        at = below + [(50, "mallory", "pull_request_target")]
        self.assertEqual(self.route("mallory", "mallory", at), "limit")

    def test_only_that_accounts_earlier_event_runs_count(self):
        others = [(10, "eve", "issues"), (11, "alice", "issues"), (12, "mallory", "workflow_dispatch")]
        later = [(200 + i, "mallory", "issues") for i in range(self.LIMIT)]
        self.assertEqual(self.route("mallory", "mallory", others * self.LIMIT + later), "screen")

    def test_it_reads_the_last_hour_of_this_workflow(self):
        run = step("route", Trust.STEP)["run"]
        self.assertIn("date -u -d '-1 hour'", run)
        self.assertIn('-f created=">=$from"', run)
        self.assertIn("repos/$REPO/actions/workflows/build.yaml/runs", run)

    def test_a_writers_action_on_an_outsiders_item_has_no_limit(self):
        runs = [(10 + i, "mallory", "issues") for i in range(self.LIMIT)]
        self.assertEqual(self.route("mallory", "alice", runs, event="pull_request_target"), "screen")

    def test_runs_that_cannot_be_read_stop_the_run(self):
        rc, out, got = self.run_script(step("route", Trust.STEP)["run"], EVENT="issues", AUTHOR="mallory",
                                       ACTOR="mallory", RUN_ID="100")
        self.assertEqual((rc, got.get("trust")), (1, None), out)
        self.assertIn("could not be read", out)


class Routes(unittest.TestCase):
    """Which jobs run, for each trust and each answer of the screen, and what the required check reports."""

    def ran(self, route, results=None, outputs=None):
        got, ctx = run_graph(route, results, outputs)
        return {n for n, r in got.items() if r != "skipped"} - {"route", "required"}, ctx

    ENROLLMENT = {"kind": "enrollment", "sha": "a" * 40}
    BUILT = {"project-builds", "record"}

    def test_a_writers_item_is_reviewed_without_a_screen(self):
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="writer"))
        self.assertEqual(jobs, self.BUILT | {"gather", "review", "hold", "comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), False)

    def test_an_outsiders_clean_item_is_reviewed_with_no_maintainer(self):
        for kind in ("enrollment", "change", "issue"):
            with self.subTest(kind=kind):
                jobs, ctx = self.ran({"kind": kind, "sha": "a" * 40, "trust": "screen"},
                                     outputs={"screen": {"verdict": "clean", "checks": "model_armor"},
                                              "project-builds": {"name": "libx" if kind == "enrollment" else ""}})
                self.assertTrue({"gather", "screen", "review"} <= jobs, jobs)
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_an_outsiders_held_item_gets_no_review_and_is_held(self):
        for verdict in ("held", "", "suspicious", "CLEAN?"):
            with self.subTest(verdict=verdict):
                jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), outputs={"screen": {"verdict": verdict}})
                self.assertEqual(jobs, self.BUILT | {"gather", "screen", "comment"})
                self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)
                code, out = required(ctx)
                self.assertEqual(code, 0, out)

    def test_a_screen_that_fails_holds_it_and_fails_the_required_check(self):
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), results={"screen": "failure"})
        self.assertEqual(jobs, self.BUILT | {"gather", "screen", "comment"})
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)
        self.assertEqual(required(ctx)[0], 1)

    def test_an_outsiders_item_that_cannot_be_gathered_is_held(self):
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), results={"gather": "failure"})
        self.assertEqual(jobs, self.BUILT | {"gather", "comment"})
        jobs, _ = self.ran(dict(self.ENROLLMENT, trust="writer"), results={"gather": "failure"})
        self.assertEqual(jobs, self.BUILT | {"gather"})

    def test_at_the_limit_it_is_held_without_a_screen(self):
        for kind in ("change", "issue"):
            with self.subTest(kind=kind):
                jobs, ctx = self.ran({"kind": kind, "sha": "a" * 40, "trust": "limit"})
                self.assertEqual(jobs, {"comment"})
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_a_measurement_runs_the_screen_job_alone(self):
        """The screen job measures, and the required check asks for it and nothing else."""
        jobs, ctx = self.ran({"kind": "", "trust": "measure"}, outputs={"gather": {}})
        self.assertEqual(jobs, {"screen"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        jobs, ctx = self.ran({"kind": "", "trust": "measure"}, results={"screen": "failure"}, outputs={"gather": {}})
        self.assertEqual(jobs, {"screen"})
        self.assertEqual(required(ctx)[0], 1)
        steps = {x.get("name") or x.get("uses", "").split("@")[0]: x.get("if") for x in JOBS["screen"]["steps"]}
        self.assertEqual(steps["Screen"], "needs.route.outputs.trust != 'measure'")
        self.assertEqual(steps["Measure"], "needs.route.outputs.trust == 'measure'")
        self.assertEqual(steps["Take what the gather job kept"], "needs.route.outputs.trust != 'measure'")
        self.assertEqual(steps["actions/download-artifact"], "needs.route.outputs.trust != 'measure'")
        m = step("screen", "Measure")
        self.assertTrue(m["run"].endswith("python3 .github/scripts/screen.py --measure\n"), m["run"])
        self.assertEqual(m["env"]["MEASURE_SET"], "${{ inputs.measure_set }}")
        self.assertEqual(m["env"]["MEASURE_REPEATS"], "${{ inputs.measure_repeats }}")
        self.assertEqual(m["env"]["MEASURE_OBJECT"],
                         "measure/runs/${{ github.repository }}/${{ github.run_id }}-${{ github.run_attempt }}.json")
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
        """An enrollment pull request whose build took no project is not reviewed, so nothing is held either."""
        jobs, _ = self.ran(dict(self.ENROLLMENT, trust="limit"), outputs={"project-builds": {"name": ""}})
        self.assertEqual(jobs, {"project-builds"})
        jobs, _ = self.ran({"kind": "", "trust": ""})
        self.assertEqual(jobs, set())

    def test_a_writers_item_with_an_outsiders_comment_is_screened(self):
        """The gather job's output screen is true for it: the screen runs, and only a clean verdict reviews it."""
        route = dict(self.ENROLLMENT, trust="writer")
        gather = {"digest": "d" * 64, "screen": "true"}
        jobs, ctx = self.ran(route, outputs={"gather": gather, "screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertTrue({"screen", "review"} <= jobs, jobs)
        jobs, ctx = self.ran(route, outputs={"gather": gather, "screen": {"verdict": "held"}})
        self.assertEqual(jobs, self.BUILT | {"gather", "screen", "comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_a_gather_job_with_no_screen_output_screens(self):
        """Fail closed: only the word false skips the screen."""
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="writer"), outputs={"gather": {"digest": "d" * 64}},
                             results={"screen": "failure"})
        self.assertNotIn("review", jobs)
        self.assertIn("screen", jobs)

    def test_a_screened_review_that_fails_is_held(self):
        """At SCREENED_HOURLY_CAP, or any failure of the review a clean screen let run: the comment job holds it."""
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), results={"review": "failure"},
                             outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertEqual(jobs, self.BUILT | {"gather", "screen", "review", "hold", "comment"})
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)
        self.assertEqual(required(ctx)[0], 1)
        # a writer's review that fails is not held
        jobs, _ = self.ran(dict(self.ENROLLMENT, trust="writer"), results={"review": "failure"})
        self.assertNotIn("comment", jobs)

    def test_a_moved_head_runs_nothing_after_the_gather(self):
        """The gather job kept nothing (digest empty): no screen, review or hold, and the required check passes."""
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                # Even with a screen output: no digest, nothing to take.
                for gather in ({"digest": ""}, {"digest": "", "screen": "false"}, {"digest": "", "screen": "true"}):
                    jobs, ctx = self.ran(dict(self.ENROLLMENT, trust=trust), outputs={"gather": gather})
                    self.assertEqual(jobs, self.BUILT | {"gather"}, gather)
                    self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    def test_a_cancelled_or_timed_out_screen_reviews_nothing_and_fails_the_required_check(self):
        for result in ("cancelled", "failure"):
            with self.subTest(result=result):
                jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), results={"screen": result},
                                     outputs={"screen": {"verdict": "clean"}})
                self.assertNotIn("review", jobs)
                self.assertEqual(required(ctx)[0], 1)

    def test_a_screen_that_runs_out_of_time_fails_and_so_is_held(self):
        """A job that runs out of its own time ends as cancelled, and is neither reviewed nor held. Each step of the
        screen job has a time of its own, and those of the steps that run add up to less than the job's, so a slow
        step fails the job instead, and the comment job holds the item. The Screen step outlasts screen.py's own
        deadline, which holds the item first."""
        job = JOBS["screen"]
        for step_ in job["steps"]:
            self.assertIsInstance(step_.get("timeout-minutes"), int, step_.get("name") or step_.get("uses"))
        for trust in ("screen", "writer", "measure"):
            with self.subTest(trust=trust):
                ctx = {"needs.route.outputs.trust": trust}
                ran = [s for s in job["steps"] if "if" not in s or evaluate(s["if"], ctx)]
                self.assertLess(sum(s["timeout-minutes"] for s in ran), int(evaluate(job["timeout-minutes"], ctx)))
        deadline = int(re.search(r"^DEADLINE_SECONDS = ([0-9]+)$", (SCRIPTS / "screen.py").read_text(), re.M).group(1))
        self.assertGreater(step("screen", "Screen")["timeout-minutes"] * 60, deadline)
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="screen"), results={"screen": "failure"})
        self.assertIn("comment", jobs)
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)

    def test_the_review_reads_what_the_screen_passed(self):
        """The screen and the review take the gathered file by the gather job's digest, and only the gather job
        gathers: the review job runs neither review-gather nor take-project, and restores no cache."""
        for job in ("screen", "review"):
            take = step(job, "Take what the gather job kept")
            self.assertEqual(take["env"], {"DIGEST": "${{ needs.gather.outputs.digest }}"})
            self.assertIn(".github/scripts/take-review-data", take["run"])
            self.assertIn("gather", JOBS[job]["needs"])
        uploads = [(n, s) for n, j in JOBS.items() for s in j["steps"]
                   if "upload-artifact" in s.get("uses", "") and (s.get("with") or {}).get("name") == "review-data"]
        self.assertEqual([n for n, _ in uploads], ["gather"])
        review = json.dumps(JOBS["review"])
        for name in ("review-gather", "take-project", "actions/cache"):
            self.assertNotIn(name, review)
        self.assertNotIn("cache-mode", JOBS["review"])


class Holdings(unittest.TestCase):
    """What each job holds: the screen job no write token, no secret and none of the review's identities."""

    SCREEN_IDENTITIES = ("review-screen@", "workloadIdentityPools/review-screen/")
    OTHER_IDENTITIES = ("ossv-ci@", "ossv-app-comment@", "svac_01WdHTLcJPEfiPttcuLK1hGT", "fdrl_019restxFx3PhpLhbziQoQKf",
                        "TAILNET_CLIENT_ID", "oss-verify-github-app-key")

    def test_no_job_reads_a_secret(self):
        self.assertNotRegex((ROOT / ".github" / "workflows" / "build.yaml").read_text(), r"\$\{\{[^}]*\bsecrets\b")

    def test_the_screen_job_holds_no_write_token_and_none_of_the_reviews_identities(self):
        job = JOBS["screen"]
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(job["environment"], {"name": "review-screen", "deployment": False})
        text = json.dumps(job)
        for name in self.OTHER_IDENTITIES:
            self.assertNotIn(name, text)
        uses = [s["uses"].split("@")[0] for s in job["steps"] if "uses" in s]
        self.assertEqual(uses, ["actions/checkout", "actions/download-artifact", "google-github-actions/auth"])
        runs = [s["run"] for s in job["steps"] if "run" in s]
        self.assertEqual(runs[:2], ['.github/scripts/take-review-data "$RUNNER_TEMP/review-data/review.tar"',
                                    'python3 .github/scripts/screen.py .review ${NAME:+"projects/$NAME"}'])
        self.assertEqual(len(runs), 3)
        self.assertTrue(runs[2].endswith("python3 .github/scripts/screen.py --measure\n"))

    def test_only_the_screen_job_reaches_the_screens_identities(self):
        for name, job in JOBS.items():
            text = json.dumps(job)
            environment = json.dumps(job.get("environment", ""))
            with self.subTest(job=name):
                if name == "screen":
                    continue
                self.assertNotIn("review-screen", environment)
                self.assertNotIn("${{", environment)
                for identity in self.SCREEN_IDENTITIES:
                    self.assertNotIn(identity, text)

    def test_the_screen_jobs_outputs_are_its_verdict_and_the_checks_that_ran(self):
        """The reason reaches no output: screen.py writes only these two (test_screen.py), and the job passes on only
        them; no other job reads anything of the screen but these and its result."""
        self.assertEqual(JOBS["screen"]["outputs"], {"verdict": "${{ steps.screen.outputs.verdict }}",
                                                     "checks": "${{ steps.screen.outputs.checks }}"})
        for name, job in JOBS.items():
            for ref in re.findall(r"needs\.screen\.([a-z]+(?:\.[a-z]+)?)", json.dumps(job)):
                self.assertIn(ref, ("result", "outputs.verdict", "outputs.checks"), name)

    def test_the_gather_job_holds_no_model_and_writes_nothing(self):
        job = JOBS["gather"]
        self.assertEqual(job["permissions"], {"contents": "read", "pull-requests": "read", "issues": "read",
                                              "checks": "read", "statuses": "read", "actions": "read"})
        self.assertNotIn("environment", job)
        self.assertEqual(job["cache-mode"], "read")
        text = json.dumps(job)
        for name in ("claude-code-action", "google-github-actions", "id-token"):
            self.assertNotIn(name, text)

    def test_the_screen_job_talks_to_the_real_services(self):
        e = JOBS["screen"]["env"]
        self.assertEqual(e["GCP_WORKLOAD_IDENTITY_PROVIDER"],
                         "projects/805240912354/locations/global/workloadIdentityPools/review-screen/providers/github")
        self.assertEqual(e["GCP_SERVICE_ACCOUNT"], "review-screen@theorem-agent-infra.iam.gserviceaccount.com")
        self.assertEqual(e["MODEL_ARMOR_URL"], "https://modelarmor.us.rep.googleapis.com")
        self.assertEqual(e["MODEL_ARMOR_TEMPLATE"], "projects/theorem-agent-infra/locations/us/templates/review-screen")
        self.assertEqual(e["REASON_BUCKET"], "theorem-agent-infra-review-screen-reasons")
        self.assertEqual(e["CONTENT_SAFETY_URL"], "https://theorem-review-screen.cognitiveservices.azure.com")
        self.assertEqual(e["AZURE_TENANT_ID"], "aaa6ad34-51af-41e7-891f-f16f5c53c396")
        self.assertEqual(e["SCREEN_MODEL"], "claude-haiku-5-5")
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
        # All three checks run, each under the screen's own identity.
        self.assertEqual(listed, ["model_armor", "prompt_shields", "claude"])
        # the rule chosen by measurement (.github/scripts/screen.py, RULES)
        self.assertEqual(e["SCREEN_RULE"], "claude_or_both_detectors")
        self.assertEqual((e["AZURE_CLIENT_ID"], e["ANTHROPIC_SERVICE_ACCOUNT_ID"], e["ANTHROPIC_FEDERATION_RULE_ID"]),
                         ("878cb696-144f-4c60-b04c-3974fad24e96", "svac_01JFhEhPizCyTiK2i22mRJ8a",
                          "fdrl_01PJtZrFW7ECzfBk5UVFjhw9"))
        for check in listed:
            for name in settings[check]:
                self.assertTrue(e[name], f"{check} is listed, and {name} is empty")
        # The screen's Anthropic identity is its own: the review reaches Claude through the model gateway, and holds
        # no Anthropic service account or federation rule at all.
        review = json.dumps(JOBS["review"])
        self.assertNotIn(e["ANTHROPIC_SERVICE_ACCOUNT_ID"], review)
        self.assertNotIn(e["ANTHROPIC_FEDERATION_RULE_ID"], review)
        self.assertNotRegex(review, r"svac_|fdrl_")
        self.assertEqual(JOBS["review"]["environment"], {"name": "enroll-review", "deployment": False})
        self.assertEqual(step("screen", "Screen")["env"]["REASON_OBJECT"],
                         "${{ github.repository }}/${{ github.run_id }}-${{ github.run_attempt }}.json")


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
        """The gather job's own step, with GNU tar, and take-review-data on its file by the digest it gave."""
        gather = self.dir / "gather"
        (gather / ".review").mkdir(parents=True)
        (gather / ".review" / "pr.json").write_text("{}\n")
        (gather / "projects" / "libx").mkdir(parents=True)
        (gather / "projects" / "libx" / "build.sh").write_text("make\n")
        home = self.dir / "gather-home"
        (home / ".claude" / "projects").mkdir(parents=True)
        (home / ".claude" / "ossv-last-review").write_text("session=x head=y\n")
        rc, out, got = self.run_script(step("gather", "Keep it for the screen and the review")["run"], cwd=gather,
                                       NAME="libx", HOME=str(home), SCREEN="false")
        self.assertEqual(rc, 0, out)
        rc, out, _ = self.take(self.temp / "review-data" / "review.tar", got["digest"], "libx", home=True)
        self.assertEqual(rc, 0, out)
        self.assertTrue((self.work / "projects" / "libx" / "build.sh").is_file())
        self.assertTrue((self.dir / "home" / ".claude" / "ossv-last-review").is_file())
        # A screened item: no session in the file.
        shutil.rmtree(self.temp / "review-data")
        rc, out, got = self.run_script(step("gather", "Keep it for the screen and the review")["run"], cwd=gather,
                                       NAME="libx", HOME=str(home), SCREEN="true")
        self.assertEqual(rc, 0, out)
        with tarfile.open(self.temp / "review-data" / "review.tar") as t:
            self.assertFalse([n for n in t.getnames() if n.startswith(".claude")])
        for output in ("session", "last"):
            self.assertEqual(JOBS["gather"]["outputs"][output],
                             f"${{{{ steps.outside.outputs.screen == 'false' && steps.gather.outputs.{output} || '' }}}}")

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


class ScreenedReviewCap(Runner):
    """.github/scripts/screened-review-cap, which counts, and the review job's three steps: the count, its check that
    the count is a number, and the hold that fails at the cap alone."""

    COUNT = "Count the screened reviews of the last hour"
    CHECK = "Check the count of screened reviews"
    HOLD = "Hold a screened review at the hourly cap"

    def runs(self, *jobs_of_runs):
        """Each run's jobs: a list of (job name, conclusion, [(step name, conclusion)]). Returns the count step's exit
        status, its log and its outputs."""
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs",
                   {"workflow_runs": [{"id": 10 + i} for i in range(len(jobs_of_runs))] + [{"id": 100}]})
        for i, jobs in enumerate(jobs_of_runs):
            self.serve(f"repos/{REPO}/actions/runs/{10 + i}/jobs", {"jobs": [
                {"name": n, "conclusion": c, "steps": [{"name": s, "conclusion": sc} for s, sc in steps]}
                for n, c, steps in jobs]})
        return self.run_script(str(SCRIPTS / "screened-review-cap"), RUN_ID="100", CAP="2")

    def held(self, count, cap="2"):
        return self.run_script(step("review", self.HOLD)["run"], COUNT=count, CAP=cap)[:2]

    def checked(self, count, cap="2"):
        return self.run_script(step("review", self.CHECK)["run"], COUNT=count, CAP=cap)[:2]

    SCREENED = [("screen", "success", []), ("review", "success", [("Review", "success")])]

    def test_it_counts_up_to_the_cap_and_passes(self):
        rc, out, got = self.runs(self.SCREENED)
        self.assertEqual((rc, got), (0, {"count": "1"}), out)
        rc, out, got = self.runs(self.SCREENED, self.SCREENED, self.SCREENED)
        self.assertEqual((rc, got), (0, {"count": "2"}), out)
        self.assertNotIn("::error::", out)

    def test_the_hold_step_fails_at_the_cap_alone(self):
        self.assertEqual(self.held("1")[0], 0)
        rc, out = self.held("2")
        self.assertEqual(rc, 1)
        self.assertIn("::error::HELD: 2 screened reviews ran in the last hour, at the cap of 2.", out)
        self.assertEqual(self.held("3")[0], 1)

    def test_only_screened_reviews_that_ran_count(self):
        writer = [("screen", "skipped", []), ("review", "success", [])]
        capped = [("screen", "success", []), ("review", "failure", [(self.COUNT, "success"), (self.HOLD, "failure")])]
        unread = [("screen", "success", []), ("review", "failure", [(self.COUNT, "failure"), (self.HOLD, "skipped")])]
        unchecked = [("screen", "success", []),
                     ("review", "failure", [(self.COUNT, "success"), (self.CHECK, "failure"), (self.HOLD, "skipped")])]
        held = [("screen", "success", []), ("review", "skipped", [])]
        running = [("screen", "success", []), ("review", None, [])]
        self.assertEqual(self.runs(writer, capped, unread, unchecked, held, writer)[2], {"count": "0"})
        self.assertEqual(self.runs(running, self.SCREENED)[2], {"count": "2"})

    def test_a_read_that_fails_fails_the_count_and_is_no_hold_at_the_cap(self):
        """The count step fails, so the hold step is skipped: the comment job holds the item as a review that did not
        finish, which is tried again under REVIEW_TRIES (Hold, below)."""
        rc, out, got = self.run_script(str(SCRIPTS / "screened-review-cap"), RUN_ID="100", CAP="2")
        self.assertEqual((rc, got), (1, {}))
        self.assertIn("could not be read", out)
        self.assertNotIn("HELD", out)
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [{"id": 10}]})
        rc, out, got = self.run_script(str(SCRIPTS / "screened-review-cap"), RUN_ID="100", CAP="2")
        self.assertEqual((rc, got), (1, {}), out)
        self.assertIn("the jobs of run 10 could not be read", out)
        self.assertEqual(self.run_script(str(SCRIPTS / "screened-review-cap"), RUN_ID="100", CAP="x")[0], 1)

    def test_a_count_that_cannot_be_written_fails_the_count(self):
        """An unwritten count would reach the hold step empty, read as 0, and let the review run past the cap."""
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [{"id": 100}]})
        unwritable = self.dir / "not-a-file"
        unwritable.mkdir()
        for output, said in ((str(unwritable), "the count could not be written"), ("", "GITHUB_OUTPUT is not set")):
            with self.subTest(output=output):
                rc, out, _ = self.run_script(str(SCRIPTS / "screened-review-cap"), RUN_ID="100", CAP="2",
                                             GITHUB_OUTPUT=output)
                self.assertEqual(rc, 1, out)
                self.assertIn(f"::error::{said}", out)

    def test_the_check_step_fails_on_a_count_that_is_not_a_number_and_says_no_cap(self):
        """Its failure skips the hold step, so the comment job holds the item as a review that did not finish (tried
        again under REVIEW_TRIES), not as one held at the cap."""
        for count, cap in (("0", "2"), ("5", "2")):
            with self.subTest(count=count, cap=cap):
                self.assertEqual(self.checked(count, cap)[0], 0)
        for count, cap in (("", "2"), ("x", "2"), ("-1", "2"), ("1", ""), ("1", "0")):
            with self.subTest(count=count, cap=cap):
                rc, out = self.checked(count, cap)
                self.assertEqual(rc, 1, out)
                self.assertIn("::error::the count of the last hour's screened reviews", out)
                self.assertNotIn("HELD", out)

    def test_the_review_job_runs_all_three_before_the_model_for_a_screened_item(self):
        count, check, hold = step("review", self.COUNT), step("review", self.CHECK), step("review", self.HOLD)
        for s in (count, check, hold):
            self.assertEqual(s["if"], "needs.gather.outputs.screen != 'false'")
            self.assertEqual(s["env"]["CAP"], "${{ env.SCREENED_HOURLY_CAP }}")
        self.assertEqual(count["run"], ".github/scripts/screened-review-cap")
        for s in (check, hold):
            self.assertEqual(s["env"]["COUNT"], f"${{{{ steps.{count['id']}.outputs.count }}}}")
        self.assertRegex(WF["env"]["SCREENED_HOURLY_CAP"], r"^[1-9][0-9]*$")
        names = [x.get("name") for x in JOBS["review"]["steps"]]
        self.assertEqual([names.index(self.CHECK), names.index(self.HOLD)],
                         [names.index(self.COUNT) + 1, names.index(self.COUNT) + 2])
        self.assertLess(names.index(self.HOLD), names.index("Review"))


class HeadDidNotMove(Runner):
    """The gather job's check that pr.json and the pull request now name the head that was gathered."""

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
        for name in ("Whether the review reads text of an account without write access",
                     "Keep it for the screen and the review"):
            self.assertTrue(step("gather", name)["if"].startswith("steps.head.outputs.moved != 'true'"))

    def test_a_head_that_cannot_be_read_fails_only_a_screened_one(self):
        self.assertEqual(self.check("a" * 40, None, "screen")[0], 1)
        self.assertEqual(self.check("a" * 40, None, "writer"), (0, None))


class Hold(Runner):
    """The comment job's hold: the label, and one comment in fixed words that says nothing of why."""

    STEP = "Label it review-held and say so"

    def hold(self, trust, pr="7", number="7", comments=(), head="a" * 40, review="skipped", origin="", tries="",
             capped=False):
        """capped: this run's screened review stopped at SCREENED_HOURLY_CAP (its step of that name failed)."""
        self.serve(f"repos/{REPO}/issues/{number}/comments", list(comments))
        self.serve(f"repos/{REPO}/issues/{number}/labels", [{"name": "review-held"}])
        self.serve(f"repos/{REPO}/labels/review-held", {"name": "review-held"})
        self.serve(f"repos/{REPO}/issues/comments/5", {})
        self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": head}})
        self.serve(f"repos/{REPO}/actions/runs/100/attempts/1/jobs", {"jobs": [
            {"name": "route", "steps": [{"name": "An enrollment, a change or an issue", "conclusion": "success"}]},
            {"name": "review", "steps": [
                {"name": "Hold a screened review at the hourly cap", "conclusion": "failure" if capped else "success"},
                {"name": "Review", "conclusion": "skipped" if capped else "failure"}]}]})
        rc, out, _ = self.run_script(step("comment", self.STEP)["run"], PR=pr, NUMBER=number, TRUST=trust,
                                     HEAD_SHA="a" * 40, REVIEW=review, RUN_ID="100", RUN_ATTEMPT="1",
                                     RUN_TOKEN="stand-in", TRIES=tries,
                                     ORIGIN=origin or ("50" if trust in ("limit", "screen") else ""))
        self.assertEqual(rc, 0, out)
        calls = self.calls()
        bodies = [json.loads((self.api / f"input.{i + 1}").read_text())["body"]
                  for i, c in enumerate(calls) if "--input" in c]
        return calls, bodies, out

    def test_a_held_item_is_labelled_and_told_in_fixed_words(self):
        calls, bodies, _ = self.hold("screen")
        self.assertIn(["--method", "POST", f"repos/{REPO}/issues/7/labels", "-f", "labels[]=review-held",
                       "--jq", ".[].name"], calls)
        self.assertEqual(len(bodies), 1)
        self.assertTrue(bodies[0].startswith("<!-- oss-verify-held -->\n**Automated review held.**\n"))
        self.assertTrue(bodies[0].endswith("\n\n<!-- oss-verify-held-run 100 -->\n"), bodies[0])
        self.assertIn("the screen did not pass it", bodies[0])
        self.assertIn(f"gh workflow run build.yaml -R {REPO} -f pr=7", bodies[0])
        # nothing that notifies anyone or links an issue
        self.assertNotIn("@", bodies[0])
        self.assertNotRegex(bodies[0], r"#[0-9]|(?i:gh-)[0-9]")

    def test_an_issue_is_told_how_to_start_its_review(self):
        _calls, bodies, _ = self.hold("screen", pr="", number="9")
        self.assertIn(f"-f issue=9", bodies[0])

    def test_at_the_limit_it_says_so(self):
        """And that it is screened again with no person, from when, and the run review-rescreen.yml finds it by,
        before the run marker the comment job reads last. A hold of the screen has no such marker."""
        _calls, bodies, _ = self.hold("limit")
        self.assertIn(f"the limit of {WF['env']['OUTSIDE_HOURLY_LIMIT']} an hour", bodies[0])
        self.assertRegex(bodies[0], r"It is screened again automatically, with no maintainer, from "
                                    r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC, by a check that runs every 15 "
                                    r"minutes")
        self.assertTrue(bodies[0].endswith("\n\n<!-- oss-verify-held-limit 50 0 -->\n<!-- oss-verify-held-run 100 -->\n"),
                        bodies[0])
        self.assertNotRegex(bodies[0], r"#[0-9]|@")

    def test_a_hold_of_the_screen_names_no_run_of_the_limit(self):
        _calls, bodies, _ = self.hold("screen")
        self.assertNotRegex(bodies[0], r"oss-verify-held-(limit|cap|transient)")

    def test_a_hold_tried_again_needs_its_run(self):
        for trust, review, capped in (("limit", "skipped", False), ("screen", "failure", False),
                                      ("screen", "failure", True)):
            for origin in ("", "5 0", "-1"):
                with self.subTest(trust=trust, capped=capped, origin=origin):
                    self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": "a" * 40}})
                    self.serve(f"repos/{REPO}/issues/7/comments", [])
                    self.serve(f"repos/{REPO}/actions/runs/100/attempts/1/jobs", {"jobs": [{"name": "review", "steps": [
                        {"name": "Hold a screened review at the hourly cap",
                         "conclusion": "failure" if capped else "success"}]}]})
                    rc, out, _ = self.run_script(step("comment", self.STEP)["run"], PR="7", NUMBER="7", TRUST=trust,
                                                 HEAD_SHA="a" * 40, REVIEW=review, RUN_ID="100", RUN_ATTEMPT="1",
                                                 RUN_TOKEN="stand-in", TRIES="", ORIGIN=origin)
                    self.assertEqual(rc, 1, out)

    AGAIN = (r"It is screened again automatically, with no maintainer, from [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} "
             r"UTC, by a check that runs every 15 minutes\. If that account is still at the limit then, the check tries "
             r"again later, and if the item is held again, this comment gives the new time\.")

    def test_an_outsiders_review_stopped_at_the_cap_is_tried_again_and_counts_no_try(self):
        _calls, bodies, _ = self.hold("screen", review="failure", tries="1", capped=True)
        self.assertIn(f"had reached their limit of {WF['env']['SCREENED_HOURLY_CAP']} an hour", bodies[0])
        self.assertRegex(bodies[0], self.AGAIN)
        self.assertTrue(bodies[0].endswith("\n\n<!-- oss-verify-held-cap 50 1 -->\n<!-- oss-verify-held-run 100 -->\n"),
                        bodies[0])

    def test_an_outsiders_review_that_did_not_finish_is_tried_again_up_to_review_tries(self):
        tries = int(WF["env"]["REVIEW_TRIES"])
        self.assertGreater(tries, 1)
        for review in ("failure", "cancelled"):
            for before in range(tries):
                with self.subTest(review=review, before=before):
                    self.tearDown()
                    self.setUp()
                    _calls, bodies, _ = self.hold("screen", review=review, tries=str(before))
                    if before + 1 < tries:
                        self.assertIn(f"did not finish ({before + 1} of the {tries} times it is tried)", bodies[0])
                        self.assertRegex(bodies[0], self.AGAIN)
                        self.assertIn(f"\n\n<!-- oss-verify-held-transient 50 {before + 1} -->\n", bodies[0])
                    else:
                        self.assertIn(f"did not finish, {tries} times. A maintainer will look at it.", bodies[0])
                        self.assertNotRegex(bodies[0], r"oss-verify-held-(limit|cap|transient)")

    def test_a_count_of_the_cap_that_failed_or_was_no_number_is_a_review_that_did_not_finish(self):
        """Its count step or its check failed and its hold step was skipped: tried again under REVIEW_TRIES, not as one
        held at the cap. Only the review job's hold step says the cap."""
        for count, check in (("failure", "skipped"), ("success", "failure")):
            with self.subTest(count=count, check=check):
                self.tearDown()
                self.setUp()
                self.serve(f"repos/{REPO}/issues/7/comments", [])
                self.serve(f"repos/{REPO}/issues/7/labels", [{"name": "review-held"}])
                self.serve(f"repos/{REPO}/labels/review-held", {"name": "review-held"})
                self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": "a" * 40}})
                self.serve(f"repos/{REPO}/actions/runs/100/attempts/1/jobs", {"jobs": [
                    {"name": "other", "steps": [{"name": ScreenedReviewCap.HOLD, "conclusion": "failure"}]},
                    {"name": "review", "steps": [
                        {"name": ScreenedReviewCap.COUNT, "conclusion": count},
                        {"name": ScreenedReviewCap.CHECK, "conclusion": check},
                        {"name": ScreenedReviewCap.HOLD, "conclusion": "skipped"},
                        {"name": "Review", "conclusion": "skipped"}]}]})
                rc, out, _ = self.run_script(step("comment", self.STEP)["run"], PR="7", NUMBER="7", TRUST="screen",
                                             HEAD_SHA="a" * 40, REVIEW="failure", RUN_ID="100", RUN_ATTEMPT="1",
                                             RUN_TOKEN="stand-in", TRIES="0", ORIGIN="50")
                self.assertEqual(rc, 0, out)
                body = json.loads((self.api / f"input.{len(self.calls())}").read_text())["body"]
                self.assertIn(f"did not finish (1 of the {WF['env']['REVIEW_TRIES']} times it is tried)", body)
                self.assertIn("\n\n<!-- oss-verify-held-transient 50 1 -->\n", body)
                self.assertNotIn("had reached their limit", body)

    def test_a_writers_item_whose_review_did_not_finish_is_its_writers(self):
        """Its screen read the text of others; no account without write access waits on it."""
        for capped in (False, True):
            with self.subTest(capped=capped):
                self.tearDown()
                self.setUp()
                _calls, bodies, _ = self.hold("writer", review="failure", capped=capped)
                self.assertIn("A maintainer will look at it.", bodies[0])
                self.assertNotRegex(bodies[0], r"oss-verify-held-(limit|cap|transient)")

    def test_a_screened_review_that_did_not_finish_says_so(self):
        _calls, bodies, _ = self.hold("screen", review="failure")
        self.assertIn("The automated screen passed it, but the automated review did not finish", bodies[0])
        self.assertNotIn("the screen did not pass it", bodies[0])
        _calls, bodies, _ = self.hold("screen", review="failure", capped=True)
        self.assertIn(f"their limit of {WF['env']['SCREENED_HOURLY_CAP']} an hour", bodies[-1])

    def test_one_account_cannot_fill_the_screened_reviews_of_an_hour(self):
        self.assertLess(int(WF["env"]["OUTSIDE_HOURLY_LIMIT"]), int(WF["env"]["SCREENED_HOURLY_CAP"]))

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
        self.assertEqual(set(e), {"GH_TOKEN", "REPO", "PR", "NUMBER", "TRUST", "REVIEW", "HEAD_SHA", "RUN_ID", "ORIGIN",
                                  "TRIES", "RUN_ATTEMPT", "RUN_TOKEN"})
        self.assertEqual(e["RUN_TOKEN"], "${{ github.token }}")
        self.assertNotIn("needs.screen", json.dumps(e))
        self.assertNotIn("needs.gather", json.dumps(e))

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
            **os.environ, "HEAD_SHA": "a" * 40, "VERDICTS": "{}", "RULES": "review.md", "CHECKS": "",
            "REVIEW": "<!-- oss-verify-review-head " + "b" * 40 + " -->\nThanks."})
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = run.stdout.splitlines()
        self.assertEqual(lines[-1], "<!-- oss-verify-review-head " + "a" * 40 + " -->")
        self.assertEqual([x for x in lines if "oss-verify-review-head" in x], [lines[-1]])

    def test_the_comment_jobs_never_cancel_each_other(self):
        self.assertEqual(JOBS["comment"]["concurrency"]["queue"], "max")
        self.assertIs(JOBS["comment"]["concurrency"]["cancel-in-progress"], False)

    STARTED = "2026-11-03T10:00:00Z"

    def take_off(self, number, comments, label=True):
        s = step("comment", "Take the label review-held off")
        if label:
            self.serve(f"repos/{REPO}/issues/{number}/labels/review-held", [])
        self.serve(f"repos/{REPO}/issues/{number}/comments", comments)
        self.serve(f"repos/{REPO}/issues/comments/5", {})
        rc, out, _ = self.run_script(s["run"], NUMBER=number, STARTED=self.STARTED, RUN_ID="100")
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
        """An issue held once (at the hourly limit, say), whose later screen passes and whose review makes its
        draft: the comment job runs, holds nothing and posts nothing, and takes the label and the hold comment off
        with a token that can write issues."""
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                got, ctx = run_graph({"kind": "issue", "sha": "", "trust": trust, "started": self.STARTED},
                                     outputs={"screen": {"verdict": "clean", "checks": "model_armor"},
                                              "project-builds": {"name": ""}})
                self.assertEqual(got["comment"], "success")
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
                env = {f"env.{k}": as_text(evaluate(JOBS["comment"]["env"][k], ctx)) for k in ("HOLDING", "KIND")}
                ran = {s.get("name") for s in JOBS["comment"]["steps"]
                       if "if" not in s or evaluate(s["if"], dict(ctx, **env))}
                self.assertIn("Get the oss-verify App's token for a hold or an issue", ran)
                self.assertNotIn("Get the oss-verify App's token", ran)
                self.assertNotIn("Label it review-held and say so", ran)
                self.assertNotIn("Post the comment, or update the one already there", ran)
                self.assertIn("Take the label review-held off", ran)
        token = step("comment", "Get the oss-verify App's token for a hold or an issue")["with"]
        self.assertEqual(token["permission-issues"], "write")
        e = step("comment", "Take the label review-held off")["env"]
        self.assertEqual(e["STARTED"], "${{ needs.route.outputs.started }}")
        self.assertEqual(e["GH_TOKEN"], "${{ steps.app.outputs.token || steps.app-hold.outputs.token }}")
        # an issue whose review failed is held, and keeps its hold
        got, ctx = run_graph({"kind": "issue", "sha": "", "trust": "screen"}, results={"review": "failure"},
                             outputs={"screen": {"verdict": "clean"}, "project-builds": {"name": ""}})
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)


class OutsideText(Runner):
    """The gather job's step that has the screen read a writer's item that holds text of an account without write
    access."""

    STEP = "Whether the review reads text of an account without write access"

    def screen(self, trust="writer", comments=(), reviews=(), review_authors=(), status=0, event="pull_request_target",
               rescreen=""):
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
        rc, out, got = self.run_script(step("gather", self.STEP)["run"], TRUST=trust, EVENT=event, RESCREEN=rescreen)
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
                                         EVENT="pull_request_target")[2]["screen"], "true")
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

    def test_a_run_started_by_hand_is_not_screened(self):
        self.assertEqual(self.screen(comments=[{"login": "mallory"}], event="workflow_dispatch"), "false")
        self.assertEqual(self.screen(trust="screen", event="workflow_dispatch"), "true")

    def test_a_rescreen_is_not_a_run_by_hand(self):
        """A writer's item that a rescreen reviews still has the text of others screened first."""
        self.assertEqual(self.screen(comments=[{"login": "mallory"}], event="workflow_dispatch", rescreen="true"),
                         "true")
        self.assertEqual(self.screen(comments=[{"login": "alice"}], event="workflow_dispatch", rescreen="true"),
                         "false")

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

    def test_a_read_that_failed_names_no_writer(self):
        """Then the screen reads every comment, as it did before any of them was told apart."""
        (self.work / ".review").mkdir()
        (self.work / ".review" / "pr.json").write_text("gh: Server Error (HTTP 502)\n(exit status 1)\n")
        got = self.run_script(step("gather", self.STEP)["run"], TRUST="screen", EVENT="pull_request_target")[2]
        self.assertEqual((got["screen"], got["writers"]), ("true", ""))

    def test_both_copies_of_trusted_are_the_same(self):
        def trusted(text):
            found = re.findall(r"# trusted\n(.*?)# end of trusted\n", text, re.S)
            self.assertEqual(len(found), 1)
            return found[0]
        self.assertEqual(trusted(step("route", Trust.STEP)["run"]), trusted(step("gather", self.STEP)["run"]))


class OutsidersEnrollment(Runner):
    """An enrollment of an account without write access: its review gets none of the project's repository, which no
    screen reads."""

    STEP = "A screened enrollment's review reads none of the project's repository"

    def test_the_source_goes_and_source_txt_says_why(self):
        s = step("gather", self.STEP)
        self.assertEqual(s["if"], "steps.head.outputs.moved != 'true' && env.KIND == 'enrollment' && env.TRUST == 'screen'")
        (self.work / ".review" / "source").mkdir(parents=True)
        (self.work / ".review" / "source" / "README").write_text("upstream\n")
        rc, out, _ = self.run_script(s["run"], PR="7")
        self.assertEqual(rc, 0, out)
        self.assertFalse((self.work / ".review" / "source").exists())
        self.assertIn("gh workflow run build.yaml -f pr=7", (self.work / ".review" / "source.txt").read_text())
        names = [x.get("name") for x in JOBS["gather"]["steps"]]
        self.assertLess(names.index(self.STEP), names.index("Keep it for the screen and the review"))


class TrustWiring(unittest.TestCase):
    def test_the_trust_step_reads_the_author_and_the_account_that_started_the_run(self):
        e = step("route", Trust.STEP)["env"]
        self.assertEqual(e["AUTHOR"], "${{ github.event.pull_request.user.login || github.event.issue.user.login }}")
        self.assertEqual(e["ACTOR"], "${{ github.actor }}")
        self.assertEqual(e["EVENT"], "${{ github.event_name }}")


class ScreenedFooter(unittest.TestCase):
    """The review comment names the checks of the screen that ran, so a clean verdict from fewer checks does not read
    as one from all three."""

    def body(self, screened):
        return subprocess.run([str(SCRIPTS / "review-body")], capture_output=True, text=True, env={
            **os.environ, "HEAD_SHA": "a" * 40, "REVIEW": "Thanks.", "CHECKS": "", "VERDICTS": "{}",
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
        self.assertEqual(step("review", "Write the comment as the comment job posts it")["env"]["SCREENED"],
                         "${{ needs.gather.outputs.screen != 'false' && needs.screen.outputs.checks || '' }}")

    def test_anything_else_is_refused(self):
        for screened in ("x; rm -rf /", "model_armor,", "@octocat", "model_armor,other"):
            with self.subTest(screened=screened):
                self.assertNotEqual(self.body(screened).returncode, 0)


OLD, NEW = "2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"   # a hold over an hour old, and one under it
APP = "oss-verify[bot]"
RESCREEN_WF = yaml.safe_load((ROOT / ".github" / "workflows" / "review-rescreen.yml").read_text())


def limit_hold(run, at=OLD, user=APP, kind="limit", tries=None):
    """A hold comment that review-rescreen.yml tries again, as the comment job writes it: kind limit, cap or transient,
    and the tries so far (none: a marker without them, read as 0)."""
    count = "" if tries is None else f" {tries}"
    return {"id": run, "user": {"login": user}, "updated_at": at,
            "body": f"<!-- oss-verify-held -->\n**Automated review held.**\n\nHeld.\n\n"
                    f"<!-- oss-verify-held-{kind} {run}{count} -->\n<!-- oss-verify-held-run {run + 1000} -->\n"}


def screen_hold(at=OLD, user=APP):
    return {"id": 1, "user": {"login": user}, "updated_at": at,
            "body": "<!-- oss-verify-held -->\n**Automated review held.**\n\nThe screen did not pass it.\n\n"
                    "<!-- oss-verify-held-run 900 -->\n"}


class Held(Runner):
    """Stand-in answers for held items: build.yaml's id, the runs that holds name, and the rescreens of the hour."""

    WORKFLOW_ID = 99
    LIMIT = int(WF["env"]["OUTSIDE_HOURLY_LIMIT"])

    def setUp(self):
        super().setUp()
        self.permissions(alice="write", bob="write", mallory="read", eve="read")
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml", {"id": self.WORKFLOW_ID})

    def origin(self, run, login, event="issues", workflow=None):
        self.serve(f"repos/{REPO}/actions/runs/{run}",
                   {"workflow_id": workflow or self.WORKFLOW_ID, "event": event, "actor": {"login": login}})

    def held(self, number, *comments):
        self.serve(f"repos/{REPO}/issues/{number}/comments", list(comments))

    def runs(self, *runs):
        """build.yaml's runs of the last hours: (id, actor, event, name), and the run's status and how many minutes ago
        it was made when they are not completed and 10."""
        now = datetime.datetime.now(datetime.timezone.utc)
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [
            {"id": r[0], "actor": {"login": r[1]}, "event": r[2], "display_title": r[3],
             "status": r[4] if len(r) > 4 else "completed",
             "created_at": (now - datetime.timedelta(minutes=r[5] if len(r) > 5 else 10))
             .strftime("%Y-%m-%dT%H:%M:%SZ")}
            for r in runs]})
        # Each run's jobs: one that did its work (route finished, and the gather job ran).
        for r in runs:
            self.serve(f"repos/{REPO}/actions/runs/{r[0]}/jobs", {"jobs": [
                {"name": "route", "status": "completed", "conclusion": "success"},
                {"name": "gather", "status": "completed", "conclusion": "success"},
                {"name": "comment", "status": "completed", "conclusion": "skipped"}]})

    @staticmethod
    def rescreened(account, n, first=10):
        return [(first + i, "github-actions[bot]", "workflow_dispatch", f"Rescreen {20 + i} of {account}")
                for i in range(n)]


class LimitHold(Held):
    """.github/scripts/limit-hold: the newest hold, and when it is one at the limit, its run and account."""

    def hold(self):
        run = subprocess.run([str(SCRIPTS / "limit-hold"), "7"], capture_output=True, text=True, env=self.env)
        return run.returncode, run.stdout.strip()

    def test_a_hold_at_the_limit_names_its_run_and_account(self):
        self.held(7, screen_hold(at="2000-01-01T00:00:00Z"), limit_hold(50, at="2000-02-01T00:00:00Z"))
        self.origin(50, "mallory")
        self.assertEqual(self.hold(), (0, "2000-02-01T00:00:00Z 50 mallory 0 limit"))
        for kind, tries in (("cap", 1), ("transient", 2)):
            with self.subTest(kind=kind):
                self.held(7, limit_hold(50, kind=kind, tries=tries))
                self.assertEqual(self.hold(), (0, f"{OLD} 50 mallory {tries} {kind}"))
        self.held(7, limit_hold(50, kind="screen"))
        self.assertRegex(self.hold()[1], r"^\S+ -$")

    def test_any_other_newest_hold_is_not_one_at_the_limit(self):
        cases = (
            ("the screen's is newer", [limit_hold(50, at="2000-01-01T00:00:00Z"), screen_hold(at="2000-02-01T00:00:00Z")],
             {}),
            ("only an outsider's comment has the marker", [screen_hold(), limit_hold(50, at=NEW, user="mallory")], {}),
            ("the run is another workflow's", [limit_hold(50)], {"workflow": 98}),
            ("the run is not an event's", [limit_hold(50)], {"event": "workflow_dispatch"}),
        )
        for case, comments, run in cases:
            with self.subTest(case=case):
                self.held(7, *comments)
                self.origin(50, "mallory", **run)
                rc, out = self.hold()
                self.assertEqual(rc, 0, out)
                self.assertRegex(out, r"^\S+ -$")

    def test_a_run_github_no_longer_has_is_not_one_at_the_limit(self):
        """A deleted or expired run: the item is left to a person, and the rescreen job does not fail on it each time."""
        self.held(7, limit_hold(50))
        rc, out = self.hold()
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"^\S+ -$")

    def test_no_hold_comment_prints_nothing_and_a_failed_read_fails(self):
        self.held(7)
        self.assertEqual(self.hold(), (0, ""))
        (self.api / f"repos_{REPO.replace('/', '_')}_issues_7_comments.json").unlink()
        self.assertEqual(self.hold()[0], 1)


class RescreenTrust(Held):
    """route's trust step on a rescreen's run (workflow_dispatch, rescreen=true): decided again from the API."""

    def setUp(self):
        super().setUp()
        self.item()
        self.held(7, limit_hold(50))
        self.origin(50, "mallory")
        self.runs()

    def item(self, author="mallory", state="open", labels=("review-held",)):
        self.serve(f"repos/{REPO}/issues/7",
                   {"number": 7, "state": state, "user": {"login": author}, "labels": [{"name": n} for n in labels]})

    def rescreen(self, actor="github-actions[bot]", account="mallory", event="workflow_dispatch", author="",
                 rescreen="true"):
        return self.run_script(step("route", Trust.STEP)["run"], cwd=ROOT, EVENT=event, AUTHOR=author, ACTOR=actor,
                               RUN_ID="100", MEASURE="", RESCREEN=rescreen, ACCOUNT=account, NUMBER="7")

    def route(self, **kwargs):
        rc, out, got = self.rescreen(**kwargs)
        self.assertEqual(rc, 0, out)
        return got

    def test_a_rescreen_takes_the_outsiders_path(self):
        """Started by review-rescreen.yml (github-actions[bot]), a person with write access or one of our Apps: it is
        screened, never taken as a run by hand, which would skip the screen."""
        for actor in ("github-actions[bot]", "alice", "sjawhar-agent[bot]"):
            with self.subTest(actor=actor):
                got = self.route(actor=actor)
                self.assertEqual((got.get("trust"), got.get("rescreen"), got.get("origin")), ("screen", "true", "50"))

    def test_a_writers_item_still_skips_the_screen(self):
        self.item(author="alice")
        self.origin(50, "bob")
        self.assertEqual(self.route(account="bob").get("trust"), "writer")
        self.origin(50, "mallory")
        self.assertEqual(self.route(account="mallory").get("trust"), "screen")
        self.item(author="mallory")
        self.origin(50, "bob")
        self.assertEqual(self.route(account="bob").get("trust"), "screen")

    def test_holds_at_the_cap_and_of_a_review_that_did_not_finish_take_the_outsiders_path_and_keep_their_tries(self):
        for kind, tries, want in (("cap", 1, "1"), ("transient", 2, "2"), ("limit", None, "0")):
            with self.subTest(kind=kind):
                self.held(7, limit_hold(50, kind=kind, tries=tries))
                got = self.route()
                self.assertEqual((got.get("trust"), got.get("origin"), got.get("tries")), ("screen", "50", want))

    def test_a_rescreen_its_trust_step_refused_does_not_count(self):
        """The item closed or lost its label in between: route finished, and neither the gather job nor the comment job
        ran. A rescreen held again at the limit, or not finished, counts."""
        rescreens = self.rescreened("mallory", self.LIMIT)
        self.runs(*rescreens)
        refused = [{"name": "route", "status": "completed", "conclusion": "success"},
                   {"name": "gather", "status": "completed", "conclusion": "skipped"},
                   {"name": "comment", "status": "completed", "conclusion": "skipped"}]
        self.serve(f"repos/{REPO}/actions/runs/{rescreens[0][0]}/jobs", {"jobs": refused})
        self.assertEqual(self.route().get("trust"), "screen")
        held_again = [dict(j, conclusion="success") if j["name"] == "comment" else j for j in refused]
        self.serve(f"repos/{REPO}/actions/runs/{rescreens[0][0]}/jobs", {"jobs": held_again})
        self.assertEqual(self.route().get("trust"), "limit")
        running = [{"name": "route", "status": "in_progress", "conclusion": None}]
        self.serve(f"repos/{REPO}/actions/runs/{rescreens[0][0]}/jobs", {"jobs": running})
        self.assertEqual(self.route().get("trust"), "limit")

    def test_the_cap(self):
        """The account's rescreens and events of the last hour, together, against OUTSIDE_HOURLY_LIMIT."""
        self.runs(*self.rescreened("mallory", self.LIMIT - 1))
        self.assertEqual(self.route().get("trust"), "screen")
        self.runs(*self.rescreened("mallory", self.LIMIT))
        got = self.route()
        self.assertEqual((got.get("trust"), got.get("origin")), ("limit", "50"))
        self.runs(*self.rescreened("mallory", self.LIMIT - 1), (30, "mallory", "issues", "Issue 8"))
        self.assertEqual(self.route().get("trust"), "limit")
        # Another account's rescreens, an outsider's pull request titled as a rescreen, and a name that only ends so.
        self.runs(*self.rescreened("mallory", self.LIMIT - 1), *self.rescreened("eve", self.LIMIT, first=40),
                  (50, "eve", "pull_request_target", "Rescreen 9 of mallory"),
                  (51, "alice", "workflow_dispatch", "Rescreen 9 of xmallory"))
        self.assertEqual(self.route().get("trust"), "screen")

    def test_an_outsider_cannot_start_a_rescreen_or_skip_the_screen_with_one(self):
        """Each case gets no trust, so no job after route runs but the build an enrollment asks for."""
        cases = {
            "an App outside ALLOWED_BOTS started it": lambda: {"actor": "dependabot[bot]"},
            "the inputs name another account": lambda: {"account": "eve"},
            "the inputs name no account": lambda: {"account": ""},
            "the screen held it last": lambda: self.held(7, limit_hold(50, at="2026-01-01T00:00:00Z"),
                                                         screen_hold(at="2026-02-01T00:00:00Z")),
            "only the outsider's own comment has the marker": lambda: self.held(
                7, screen_hold(), limit_hold(50, at="2026-02-01T00:00:00Z", user="mallory")),
            "it has no hold comment": lambda: self.held(7),
            "the run is another workflow's": lambda: self.origin(50, "mallory", workflow=98),
            "the run is not an event's": lambda: self.origin(50, "mallory", event="workflow_dispatch"),
            "it is closed": lambda: self.item(state="closed"),
            "it is not labelled": lambda: self.item(labels=()),
        }
        for case, arrange in cases.items():
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                kwargs = arrange() or {}
                self.assertEqual(self.route(**kwargs).get("trust"), None, case)

    def test_an_event_never_takes_the_rescreen_path(self):
        got = self.route(event="pull_request_target", author="mallory", actor="mallory", account="bob")
        self.assertEqual((got.get("trust"), got.get("rescreen")), ("screen", "false"))
        got = self.route(event="issues", author="alice", actor="alice")
        self.assertEqual((got.get("trust"), got.get("rescreen")), ("writer", "false"))
        self.assertFalse(any(f"repos/{REPO}/issues/7" in " ".join(c) for c in self.calls()))

    def test_a_read_that_fails_stops_the_run(self):
        (self.api / f"repos_{REPO.replace('/', '_')}_issues_7.json").unlink()
        rc, out, got = self.rescreen()
        self.assertEqual((rc, got.get("trust")), (1, None), out)


class ReviewRescreen(Held):
    """.github/scripts/review-rescreen: which held items it starts build.yaml for, and how many for one account."""

    def setUp(self):
        super().setUp()
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/dispatches", {})
        self.runs()

    def items(self, *items):
        """The open items labelled review-held, as GitHub lists them: (number, state, is a pull request)."""
        self.serve(f"repos/{REPO}/issues", [{"number": n, "state": s, **({"pull_request": {}} if pr else {})}
                                            for n, s, pr in items])

    def started(self):
        rc, out, _ = self.run_script(str(SCRIPTS / "review-rescreen"),
                                     OUTSIDE_HOURLY_LIMIT=RESCREEN_WF["env"]["OUTSIDE_HOURLY_LIMIT"],
                                     REVIEW_TRIES=RESCREEN_WF["env"]["REVIEW_TRIES"],
                                     HELD_LABEL=RESCREEN_WF["env"]["HELD_LABEL"])
        runs = []
        for call in self.calls():
            if call[:3] == ["--method", "POST", f"repos/{REPO}/actions/workflows/build.yaml/dispatches"]:
                f = dict(a.split("=", 1) for a in call[3:] if a != "-f")
                self.assertEqual(f.pop("ref"), "main")
                runs.append(f)
        return rc, out, runs

    @staticmethod
    def want(number, account, input="pr"):
        return {f"inputs[{input}]": str(number), "inputs[rescreen]": "true", "inputs[account]": account}

    def test_the_selection(self):
        """A hold at the limit over an hour old is picked; a fresh one, a hold of the screen, a closed item, an
        outsider's comment that copies the marker, and an item with no hold comment are not."""
        self.items((7, "open", True), (8, "open", True), (9, "open", False), (10, "closed", True), (11, "open", True),
                   (12, "open", False), (13, "open", False))
        self.held(7, limit_hold(50))
        self.held(8, limit_hold(51, at=NEW))
        self.held(9, screen_hold())
        self.held(10, limit_hold(52))
        self.held(11, screen_hold(), limit_hold(53, at="2001-01-01T00:00:00Z", user="mallory"))
        self.held(12)
        self.held(13, limit_hold(54, at="2000-06-01T00:00:00Z"))
        for run in (50, 51, 52, 53, 54):
            self.origin(run, "mallory")
        rc, out, runs = self.started()
        self.assertEqual(rc, 0, out)
        self.assertEqual(runs, [self.want(7, "mallory"), self.want(13, "mallory", "issue")])

    def test_holds_at_the_cap_and_of_a_review_that_did_not_finish_are_picked_too(self):
        """Neither is the item's own doing; a hold whose marker is another word is not one."""
        self.items((7, "open", True), (8, "open", False), (9, "open", True), (10, "open", True))
        self.held(7, limit_hold(50, kind="cap", tries=1))
        self.held(8, limit_hold(51, kind="transient", tries=2))
        self.held(9, limit_hold(52, kind="screen"))
        self.held(10, limit_hold(53, kind="transient", tries=1, at=NEW))
        for run, who in ((50, "mallory"), (51, "eve"), (52, "mallory"), (53, "eve")):
            self.origin(run, who)
        rc, out, runs = self.started()
        self.assertEqual((rc, runs), (0, [self.want(7, "mallory"), self.want(8, "eve", "issue")]), out)

    def test_the_cap_per_account_oldest_first(self):
        self.items(*[(n, "open", True) for n in (7, 8, 9, 10, 11)])
        for n, day in ((7, "04"), (8, "02"), (9, "01"), (10, "03")):
            self.held(n, limit_hold(40 + n, at=f"2000-01-{day}T00:00:00Z"))
            self.origin(40 + n, "mallory")
        self.held(11, limit_hold(51, at="2000-01-05T00:00:00Z"))
        self.origin(51, "eve")
        self.runs(*self.rescreened("mallory", 1))
        rc, out, runs = self.started()
        self.assertEqual(rc, 0, out)
        self.assertEqual(runs, [self.want(n, "mallory") for n in (9, 8)][:self.LIMIT - 1] + [self.want(11, "eve")])
        self.assertIn("10 waits: mallory had", out)

    def test_an_item_whose_rescreen_has_not_finished_is_not_started_again(self):
        """Its screen and review can outlast the 15 minutes between runs: a second run would cancel them."""
        for status in ("in_progress", "queued", "waiting"):
            with self.subTest(status=status):
                self.tearDown()
                self.setUp()
                self.items((7, "open", True), (8, "open", True))
                self.held(7, limit_hold(50))
                self.held(8, limit_hold(51))
                self.origin(50, "mallory")
                self.origin(51, "eve")
                # Made 4 hours ago (an enrollment's build alone may take 6): it no longer counts toward the hour, but it
                # still runs.
                self.runs((10, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", status, 240))
                rc, out, runs = self.started()
                self.assertEqual((rc, runs), (0, [self.want(8, "eve")]), out)
                self.assertIn("7: its rescreen has not finished", out)
                # The stand-in gh ignores query fields, so the lookup's own arguments show that it has no time window:
                # each read by an unfinished status sets no created, and every unfinished status is read. (The read of
                # an item's finished rescreens since its hold, status=completed, is another lookup.)
                by_status = [c for c in self.calls()
                             if any(a.startswith("status=") and a != "status=completed" for a in c)]
                self.assertEqual({a for c in by_status for a in c if a.startswith("status=")},
                                 {f"status={s}" for s in ("requested", "queued", "pending", "waiting", "in_progress")})
                self.assertFalse(any(a.startswith("created=") for c in by_status for a in c), by_status)

    def test_a_finished_rescreen_over_an_hour_ago_does_not_count(self):
        self.items((7, "open", True))
        self.held(7, limit_hold(50))
        self.origin(50, "mallory")
        self.runs(*[(10 + i, "github-actions[bot]", "workflow_dispatch", f"Rescreen {20 + i} of mallory", "completed", 90)
                    for i in range(self.LIMIT)])
        self.assertEqual(self.started()[2], [self.want(7, "mallory")])

    def test_an_apps_account_is_capped_too(self):
        self.items((7, "open", True))
        self.held(7, limit_hold(50))
        self.origin(50, "dependabot[bot]")
        self.runs(*self.rescreened("dependabot[bot]", self.LIMIT))
        rc, out, runs = self.started()
        self.assertEqual((rc, runs), (0, []), out)
        self.runs(*self.rescreened("dependabot[bot]", self.LIMIT - 1))
        self.assertEqual(self.started()[2], [self.want(7, "dependabot[bot]")])

    def test_a_read_that_fails_fails_the_job_and_starts_the_others(self):
        self.items((7, "open", True), (8, "open", True))
        self.held(8, limit_hold(51))
        self.origin(51, "mallory")
        rc, out, runs = self.started()
        self.assertEqual((rc, runs), (1, [self.want(8, "mallory")]), out)
        self.assertIn("the hold of 7 could not be read", out)

    TRIES = int(RESCREEN_WF["env"]["REVIEW_TRIES"])

    @staticmethod
    def ago(minutes):
        now = datetime.datetime.now(datetime.timezone.utc)
        return (now - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def patches(self):
        """The hold comments rewritten: (comment id, body)."""
        return [(c[2].rsplit("/", 1)[1], json.loads((self.api / f"input.{i + 1}").read_text())["body"])
                for i, c in enumerate(self.calls()) if c[:2] == ["--method", "PATCH"]]

    def test_rescreens_that_settle_nothing_start_it_again_below_review_tries(self):
        """Only finished rescreens of this item made since its hold count: not those before it, however many, nor
        another item's (70 is not 7), nor one of another workflow's event."""
        self.items((7, "open", True))
        self.held(7, limit_hold(50, at=self.ago(180)))
        self.origin(50, "mallory")
        before = [(10 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 240)
                  for i in range(self.TRIES)]
        other = [(20 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 70 of mallory", "completed", 100)
                 for i in range(self.TRIES)]
        event = [(30, "mallory", "issues", "Rescreen 7 of mallory", "completed", 100)]
        since = [(40 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 120 - i)
                 for i in range(self.TRIES - 1)]
        self.runs(*before, *other, *event, *since)
        rc, out, runs = self.started()
        self.assertEqual((rc, runs), (0, [self.want(7, "mallory")]), out)
        self.assertIn(f"7: {self.TRIES - 1} rescreens since its hold at", out)
        self.assertEqual(self.patches(), [])

    def test_a_rescreen_that_settled_nothing_is_tried_again_only_once_it_is_an_hour_old(self):
        """A rescreen that settles nothing leaves the hold's time where it was, so without a wait one problem of
        GitHub's would use all REVIEW_TRIES within 45 minutes."""
        self.items((7, "open", True))
        self.held(7, limit_hold(50, at=self.ago(180)))
        self.origin(50, "mallory")
        self.runs((40, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 120),
                  (41, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 30))
        rc, out, runs = self.started()
        self.assertEqual((rc, runs, self.patches()), (0, [], []), out)
        self.assertIn("settled nothing; it is tried again once that is an hour old", out)
        self.runs((40, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 120),
                  (41, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 61))
        (self.api / "args").unlink()
        self.assertEqual(self.started()[2], [self.want(7, "mallory")])

    def test_at_review_tries_its_hold_comment_says_a_person_decides_and_the_job_fails_once(self):
        self.items((7, "open", True), (9, "open", False))
        self.held(7, screen_hold(at="1999-01-01T00:00:00Z"), limit_hold(50, at=self.ago(180), kind="transient", tries=1))
        self.held(9, limit_hold(51, at=self.ago(180)))
        self.origin(50, "mallory")
        self.origin(51, "eve")
        self.serve(f"repos/{REPO}/issues/comments/50", {})
        self.runs(*[(40 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 120 - i)
                    for i in range(self.TRIES)])
        rc, out, runs = self.started()
        # The other item is still started; this one is not, and the run fails.
        self.assertEqual((rc, runs), (1, [self.want(9, "eve", "issue")]), out)
        self.assertIn(f"::error::7: screened again {self.TRIES} times since its hold", out)
        (patched, body), = self.patches()
        self.assertEqual(patched, "50")
        self.assertEqual(body,
                         "<!-- oss-verify-held -->\n**Automated review held.**\n\n"
                         f"It was screened again automatically {self.TRIES} times since it was held, and none of those "
                         "runs settled it, so it is not screened again automatically. A person with write access will "
                         "look at it. A person with write access can start the review with "
                         f"`gh workflow run build.yaml -R {REPO} -f pr=7`.\n\n<!-- oss-verify-held-run 1050 -->\n")
        self.assertNotRegex(body, r"oss-verify-held-(limit|cap|transient)|#[0-9]|@")
        # The next run: the rewritten comment is a hold a person decides on, so nothing starts it and the run passes.
        self.held(7, screen_hold(at="1999-01-01T00:00:00Z"),
                  {"id": 50, "user": {"login": APP}, "updated_at": self.ago(1), "body": body})
        self.held(9, limit_hold(51, at=self.ago(1)))
        (self.api / "args").unlink()
        rc, out, runs = self.started()
        self.assertEqual((rc, runs, self.patches()), (0, [], []), out)
        self.assertIn("7: no hold that is tried again", out)
        # And build.yaml's route no longer takes it as a hold that is tried again.
        self.assertEqual(subprocess.run([str(SCRIPTS / "limit-hold"), "7"], capture_output=True, text=True,
                                        env=self.env).stdout.split()[1:], ["-"])

    def test_a_hold_made_again_while_it_ran_is_not_rewritten(self):
        """The comment job may hold the item again between this script's read of the hold and its rewrite: the rewrite
        happens only while the newest hold comment's time is still the one the count started from. A stand-in
        limit-hold gives the time of the first read; the comment, read again at the bound, has the time given here."""
        counted = self.ago(180)
        for now, rewritten in ((counted, True), (self.ago(5), False)):
            with self.subTest(rewritten=rewritten):
                self.tearDown()
                self.setUp()
                scripts = self.dir / "scripts"
                scripts.mkdir()
                shutil.copy(SCRIPTS / "review-rescreen", scripts / "review-rescreen")
                (scripts / "limit-hold").write_text(f"#!/usr/bin/env bash\necho '{counted} 50 mallory 0 limit'\n")
                (scripts / "limit-hold").chmod(0o755)
                self.items((7, "open", True))
                self.held(7, limit_hold(50, at=now))
                self.serve(f"repos/{REPO}/issues/comments/50", {})
                self.runs(*[(40 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed",
                             120 - i) for i in range(self.TRIES)])
                rc, out, _ = self.run_script(str(scripts / "review-rescreen"),
                                             OUTSIDE_HOURLY_LIMIT=RESCREEN_WF["env"]["OUTSIDE_HOURLY_LIMIT"],
                                             REVIEW_TRIES=RESCREEN_WF["env"]["REVIEW_TRIES"],
                                             HELD_LABEL=RESCREEN_WF["env"]["HELD_LABEL"])
                started = [c for c in self.calls() if f"repos/{REPO}/actions/workflows/build.yaml/dispatches" in c]
                self.assertEqual(started, [], out)
                if rewritten:
                    self.assertEqual((rc, [p[0] for p in self.patches()]), (1, ["50"]), out)
                else:
                    self.assertEqual((rc, self.patches()), (0, []), out)
                    self.assertIn(f"7: held again after {counted}, while this run read it: the newer hold stands", out)
                    self.assertNotIn("::error::", out)

    def test_an_issue_at_review_tries_is_told_its_own_command(self):
        self.items((9, "open", False))
        self.held(9, limit_hold(51, at=self.ago(180)))
        self.origin(51, "eve")
        self.serve(f"repos/{REPO}/issues/comments/51", {})
        self.runs(*[(40 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 9 of eve", "completed", 120 - i)
                    for i in range(self.TRIES + 1)])
        rc, out, runs = self.started()
        self.assertEqual((rc, runs), (1, []), out)
        (_, body), = self.patches()
        self.assertIn(f"screened again automatically {self.TRIES + 1} times", body)
        self.assertIn(f"`gh workflow run build.yaml -R {REPO} -f issue=9`", body)

    def test_a_rewrite_that_fails_fails_the_job_and_leaves_the_item(self):
        self.items((7, "open", True))
        self.held(7, limit_hold(50, at=self.ago(180)))
        self.origin(50, "mallory")
        self.runs(*[(40 + i, "github-actions[bot]", "workflow_dispatch", "Rescreen 7 of mallory", "completed", 120 - i)
                    for i in range(self.TRIES)])
        rc, out, runs = self.started()   # no answer for the comment's PATCH: GitHub's 404
        self.assertEqual((rc, runs), (1, []), out)
        self.assertIn("its hold comment could not be rewritten", out)


class RescreenWiring(unittest.TestCase):
    """Where the rescreen runs, what it holds, and how build.yaml admits its runs."""

    def test_it_runs_on_the_schedule_alone_in_this_repository(self):
        on = RESCREEN_WF.get("on", RESCREEN_WF.get(True))
        self.assertEqual(on, {"schedule": [{"cron": "7,22,37,52 * * * *"}]})
        job = RESCREEN_WF["jobs"]["rescreen"]
        self.assertEqual(job["if"], "github.repository == 'theorem-labs/oss-verify'")
        self.assertEqual(evaluate(job["if"], {"github.repository": "theorem-labs/oss-verify"}), True)
        self.assertFalse(evaluate(job["if"], {"github.repository": "someone/oss-verify"}))

    def test_only_its_job_holds_actions_write_and_starts_build_yaml(self):
        self.assertEqual(RESCREEN_WF["permissions"], {})
        self.assertEqual(RESCREEN_WF["jobs"]["rescreen"]["permissions"],
                         {"actions": "write", "contents": "read", "issues": "write", "pull-requests": "write"})
        self.assertEqual(list(RESCREEN_WF["jobs"]), ["rescreen"])
        for name, job in JOBS.items():
            with self.subTest(job=name):
                self.assertNotEqual((job.get("permissions") or {}).get("actions"), "write")
                self.assertNotIn("/dispatches", json.dumps(job))
        self.assertEqual(WF["permissions"], {})
        self.assertNotIn("dispatches", "".join(p.read_text() for p in SCRIPTS.iterdir()
                                                if p.is_file() and p.name != "review-rescreen"))

    def test_it_keeps_build_yamls_limit_tries_and_label(self):
        for name in ("OUTSIDE_HOURLY_LIMIT", "REVIEW_TRIES", "HELD_LABEL"):
            self.assertEqual(RESCREEN_WF["env"][name], WF["env"][name])

    def test_build_yaml_takes_the_inputs_and_only_route_reads_them(self):
        inputs = WF.get("on", WF.get(True))["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["rescreen"]["type"], "boolean")
        self.assertEqual(inputs["account"]["type"], "string")
        for name, job in JOBS.items():
            with self.subTest(job=name):
                text = json.dumps(job)
                self.assertEqual("inputs.rescreen" in text or "inputs.account" in text, name == "route")

    def test_the_review_admits_github_actions_only_for_an_accepted_rescreen(self):
        bots = WF["env"]["ALLOWED_BOTS"]
        allowed = step("review", "Review")["with"]["allowed_bots"]
        for rescreen, want in (("true", bots + ",github-actions[bot]"), ("false", bots), ("", bots)):
            with self.subTest(rescreen=rescreen):
                self.assertEqual(evaluate(allowed, {"needs.route.outputs.rescreen": rescreen, "env.ALLOWED_BOTS": bots}),
                                 want)

    def test_a_rescreen_takes_the_outsiders_path(self):
        """screen, then review, then the comment; or held again at the limit."""
        for kind in ("change", "issue"):
            with self.subTest(kind=kind):
                route = {"kind": kind, "sha": "a" * 40, "trust": "screen", "rescreen": "true", "origin": "50"}
                got, ctx = run_graph(route, outputs={"screen": {"verdict": "clean", "checks": "model_armor"}},
                                     event="workflow_dispatch")
                self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"},
                                 {"gather", "screen", "review", "comment"})
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
                got, _ = run_graph(dict(route, trust="limit"), event="workflow_dispatch")
                self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"}, {"comment"})

    def test_a_screened_review_that_ran_out_of_time_is_held(self):
        """A review job that runs out of its own time ends cancelled, and the run goes on (a newer push cancels the
        whole run, and then no job after it runs): the comment job holds the item, to be tried again."""
        route = {"kind": "change", "sha": "a" * 40, "trust": "screen", "origin": "100"}
        got, ctx = run_graph(route, results={"review": "cancelled"},
                             outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"},
                         {"gather", "screen", "review", "comment"})
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)
        self.assertNotEqual(required(ctx)[0], 0)

    def test_the_comment_job_reads_this_runs_jobs_with_its_own_token(self):
        self.assertEqual(JOBS["comment"]["permissions"], {"id-token": "write", "actions": "read"})

    def test_names_the_counts_read_are_the_rescreens_own(self):
        ctx = {"inputs.rescreen": True, "inputs.pr": 7, "inputs.account": "mallory"}
        self.assertEqual(evaluate(WF["run-name"], ctx), "Rescreen 7 of mallory")
        self.assertEqual(evaluate(WF["run-name"], {"inputs.rescreen": True, "inputs.issue": 9, "inputs.account": "eve"}),
                         "Rescreen 9 of eve")
        self.assertEqual(evaluate(WF["run-name"], dict(ctx, **{"inputs.rescreen": False})), "Pull request 7")
        self.assertIn("title_re='^Rescreen ([0-9]+) of ([A-Za-z0-9-]+(\\[bot\\])?)$'",
                      (SCRIPTS / "review-rescreen").read_text())
        self.assertIn('test("^Rescreen [0-9]+ of [A-Za-z0-9-]+(\\\\[bot\\\\])?$")', step("route", Trust.STEP)["run"])

    def test_a_rescreen_never_cancels_a_run_by_hand(self):
        def group(ctx):
            return re.sub(r"\$\{\{(.*?)\}\}", lambda m: as_text(evaluate(m.group(1), ctx)), WF["concurrency"]["group"])
        by_hand = {"github.event_name": "workflow_dispatch", "inputs.pr": 7}
        self.assertEqual(group(by_hand), "build-workflow_dispatch-7")
        self.assertEqual(group(dict(by_hand, **{"inputs.rescreen": True})), "build-workflow_dispatch-rescreen-7")
