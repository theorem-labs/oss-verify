# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of build.yaml's screen of pull requests and issues from accounts without write access:  python3 -m pytest
tools/tests

route's trust step (who is screened, and the daily cap of .github/scripts/screened-review-cap), which jobs run for each
route and each answer of the screen (the jobs' conditions, evaluated as GitHub does), what the required check reports,
a label run's copy of the head's standing project-builds, the run's concurrency, what each job holds, how the screen
and the review take the gathered data (.github/scripts/take-review-data), the gather job's check that the head did not
move, the comment job's hold, and the review comment's line on the checks that ran. .github/scripts/screen.py itself
is tested in test_screen.py."""
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


def required_steps(ctx):
    """The names of the job required's steps that run on this run."""
    return {s["name"] for s in JOBS["required"]["steps"] if "name" in s and ("if" not in s or evaluate(s["if"], ctx))}


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

    def trust(self, event, author="", actor="", measure="", number=""):
        """Run the trust step for an event's run, or a run by hand (workflow_dispatch) of item `number`, whose author
        the API gives as `author`. The daily cap reads the runs a test serves, or none."""
        runs = f"repos/{REPO}/actions/workflows/build.yaml/runs"
        if not (self.api / (runs.replace("/", "_") + ".json")).exists():
            self.serve(runs, {"workflow_runs": []})
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

    def test_a_run_by_hand_of_a_writers_item_is_a_writers(self):
        self.permissions(alice="write", root="admin")
        self.assertTrust("writer", "workflow_dispatch", "alice", "root", number="7")
        # The daily cap reads nothing for a writer's item.
        self.assertEqual([c for c in self.calls() if "actions/workflows/build.yaml/runs" in " ".join(c)], [])

    def test_a_run_by_hand_of_an_outsiders_item_is_screened(self):
        """c1 (e3): an account with write access starts the review of an outside account's pull request by hand. The
        item's author decides, as on an event: the run is screened, the daily cap counts it, and the screen job runs
        before the review."""
        self.permissions(alice="write", mallory="read")
        out = self.assertTrust("screen", "workflow_dispatch", "mallory", "alice", number="7")
        self.assertIn([f"repos/{REPO}/issues/7", "--jq", '.user.login // ""'], self.calls())
        self.assertTrue([c for c in self.calls() if f"repos/{REPO}/actions/workflows/build.yaml/runs" in c], out)
        self.assertIn("charged to mallory", out)
        got, _ctx = run_graph({"kind": "enrollment", "sha": "a" * 40, "trust": "screen"},
                              outputs={"screen": {"verdict": "clean", "checks": "model_armor"}},
                              event="workflow_dispatch")
        self.assertEqual((got["gather"], got["screen"], got["review"]), ("success", "success", "success"))
        self.assertLess(ORDER.index("screen"), ORDER.index("review"))
        self.assertIn("screen", JOBS["review"]["needs"])

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
        self.assertEqual(decide["env"]["MEASURE"], "${{ inputs.measure }}")
        for pr, issue, want in (("", "", (0, "true")), ("7", "", (1, None)), ("", "5", (1, None))):
            with self.subTest(pr=pr, issue=issue):
                rc, out, got = self.run_script(decide["run"], EVENT="workflow_dispatch", MEASURE="true", PR=pr,
                                               ISSUE=issue, HEAD_SHA="", ACTOR="alice", SENDER="alice", AUTHOR="",
                                               ASSOCIATION="")
                self.assertEqual((rc, got.get("measure")), want, out)
                self.assertNotIn("kind", got)
        self.assertEqual(step("route", self.STEP)["if"],
                         "steps.decide.outputs.measure == 'true' || (steps.decide.outputs.kind != '' && "
                         "steps.decide.outputs.label_run != 'true' && steps.decide.outputs.parked != 'true')")
        # A measurement passes the trust step; a label run and a pull request that parked holds do not.
        for outputs, want in (({"measure": "true"}, True), ({"kind": "enrollment"}, True),
                              ({"kind": "enrollment", "label_run": "true"}, False),
                              ({"kind": "enrollment", "parked": "true"}, False), ({}, False)):
            ctx = {f"steps.decide.outputs.{k}": v for k, v in outputs.items()}
            self.assertEqual(bool(evaluate(step("route", self.STEP)["if"], ctx)), want, outputs)

    def test_a_permission_github_does_not_give_stops_the_run(self):
        rc, out, got = self.trust("pull_request_target", "alice", "alice")
        self.assertEqual((rc, got.get("trust")), (1, None), out)
        self.assertIn("did not say whether alice has write access", out)

    def test_a_login_that_is_not_one_is_never_a_writer(self):
        self.permissions(**{"a": "admin"})
        self.assertTrust("screen", "issues", "a/../b", "a/../b")
        self.assertTrust("screen", "issues", "x[bot][bot]", "a")


class DailyCap(Runner):
    """The daily cap: .github/scripts/screened-review-cap with a stand-in runs and jobs API, and route's trust step,
    which calls it for every item whose trust is screen (c3 (c)-(f))."""

    STEP = Trust.STEP
    NOW = "2026-11-09T12:00:00Z"
    CAP, AUTHOR_CAP = int(WF["env"]["REVIEW_CAP"]), int(WF["env"]["REVIEW_CAP_AUTHOR"])

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
        """Serve build.yaml's runs and their jobs. Each run is (id, hours before NOW it was made, event, actor, the
        conclusion of its screen job[, its name])."""
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [
            {"id": r[0], "created_at": self.at(r[1]), "event": r[2], "actor": {"login": r[3]},
             "display_title": r[5] if len(r) > 5 else "projects/libx: enroll libx"} for r in runs]})
        for r in runs:
            self.serve(f"repos/{REPO}/actions/runs/{r[0]}/jobs", {"jobs": [
                {"name": "route", "conclusion": "success"}, {"name": "screen", "conclusion": r[4]},
                {"name": "required", "conclusion": None}]})

    @staticmethod
    def screened(n, first=10, account=None, hours=0.5, start=0.0, event="pull_request_target"):
        """n runs that ran the screen, each `hours` before the one after it, the newest `start` + `hours` before NOW:
        each by an outside account of its own (o<i>), or all by `account`."""
        return [(first + i, start + hours * (i + 1), event, account or f"o{i}", "success") for i in range(n)]

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

    def jobs_read(self):
        return {a.split("/")[-2] for a in self.read("/jobs?per_page=100")}

    def test_the_25th_over_all_authors_is_capped_until_the_oldest_leaves(self):
        """c3 (c): 24 counted runs of 24 outside accounts in 24 hours. A 25th, by a new account, gets trust cap: no
        gather, no screen and no review; the comment job holds it. Its free time is when the oldest counted run is 24
        hours old. The 24th was allowed."""
        self.runs(*self.screened(self.CAP))
        rc, out, got = self.cap("zed")
        self.assertEqual((rc, got), (0, {"count": "24", "account_count": "0", "capped": "true",
                                         "free": self.freed(12)}), out)
        self.assertEqual(self.route("pull_request_target", "zed", "zed"), ("cap", self.freed(12)))
        got, ctx = run_graph({"kind": "enrollment", "sha": "a" * 40, "trust": "cap", "free": self.freed(12)})
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"},
                         {"project-builds", "record", "comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        self.runs(*self.screened(self.CAP - 1))
        self.assertEqual(self.route("pull_request_target", "zed", "zed"), ("screen", ""))

    def test_the_13th_of_one_author_is_capped(self):
        """c3 (d): one outside account's 12 earlier counted runs are the 12 of the 24 hours. Its 13th gets trust cap,
        free when its oldest counted run is 24 hours old; another account's run is screened."""
        self.runs(*self.screened(self.AUTHOR_CAP, account="mallory"))
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (0, {"count": "12", "account_count": "12", "capped": "true",
                                         "free": self.freed(6)}), out)
        self.assertEqual(self.route("pull_request_target", "mallory", "mallory"), ("cap", self.freed(6)))
        self.assertEqual(self.cap("eve")[2], {"count": "12", "account_count": "0", "capped": "false", "free": ""})
        self.assertEqual(self.route("pull_request_target", "eve", "eve"), ("screen", ""))

    def test_the_12th_of_one_author_is_reviewed(self):
        """c3 (e): with 11 earlier counted runs of one account, its 12th is screened, and a clean screen reviews it."""
        self.runs(*self.screened(self.AUTHOR_CAP - 1, account="mallory"))
        self.assertEqual(self.cap("mallory")[2], {"count": "11", "account_count": "11", "capped": "false", "free": ""})
        self.assertEqual(self.route("pull_request_target", "mallory", "mallory"), ("screen", ""))
        got, _ = run_graph({"kind": "enrollment", "sha": "a" * 40, "trust": "screen"},
                           outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertEqual((got["screen"], got["review"], got["comment"]), ("success", "success", "success"))

    def test_an_outsiders_issue_that_is_the_25th_is_capped(self):
        """c3 (f): pull requests and issues share the cap. The 25th, an issue's own event, gets trust cap: no screen and
        no model; the comment job holds the issue (Hold, below, for its words)."""
        self.runs(*self.screened(12), *self.screened(12, first=40, start=6, event="issues"))
        self.assertEqual(self.route("issues", "zed", "zed"), ("cap", self.freed(12)))
        got, ctx = run_graph({"kind": "issue", "sha": "", "trust": "cap", "free": self.freed(12)},
                             outputs={"project-builds": {"name": ""}}, event="issues")
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"}, {"comment"})
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

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
        self.runs((10, 25, "pull_request_target", "o0", "success"),  # over 24 hours old
                  (11, 1, "pull_request_target", "o1", "skipped"),  # no screen: held, or a label run
                  (12, 1, "pull_request_target", "alice", "success"),  # a writer's
                  (13, 1, "issues", "sjawhar-agent[bot]", "success"),  # an App of ALLOWED_BOTS
                  (14, 1, "workflow_dispatch", "alice", "success", "Measure the screen"),  # charged to no one
                  (1000, 1, "pull_request_target", "o2", "success"),  # this run
                  (1001, 1, "pull_request_target", "o3", "success"),  # a later run
                  (15, 2, "pull_request_target", "mallory", "success"),
                  (16, 3, "issues", "mallory", None),  # its screen has not finished
                  (17, 4, "pull_request_target", "mallory", "failure"))
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (0, {"count": "3", "account_count": "3", "capped": "false", "free": ""}), out)
        # Writers' runs are dropped before any jobs read, with one permission read for each account.
        self.assertEqual(self.jobs_read(), {"11", "15", "16", "17"})
        self.assertEqual(sorted(self.read("/permission")), sorted(f"repos/{REPO}/collaborators/{a}/permission"
                                                              for a in ("o1", "alice", "mallory")))

    def test_a_run_by_hand_is_charged_to_the_items_author(self):
        """A person's re-runs use up the author's share, never the starter's."""
        self.serve(f"repos/{REPO}/issues/9", {"user": {"login": "eve"}})
        self.serve(f"repos/{REPO}/issues/7", {"user": {"login": "mallory"}})
        self.runs(*[(20 + i, 0.5 * (i + 1), "workflow_dispatch", "alice", "success", "Pull request 7")
                    for i in range(11)], (40, 7, "workflow_dispatch", "sjawhar-agent[bot]", "success", "Issue 9"))
        self.assertEqual(self.cap("mallory")[2], {"count": "12", "account_count": "11", "capped": "false", "free": ""})
        self.assertEqual(self.cap("alice")[2]["account_count"], "0")
        self.assertEqual(self.read(f"repos/{REPO}/issues/7"), [f"repos/{REPO}/issues/7"] * 2)  # once per count
        # The 12th run of #7, by hand: charged to mallory, who reached the 12.
        self.runs(*[(20 + i, 0.5 * (i + 1), "workflow_dispatch", "alice", "success", "Pull request 7")
                    for i in range(12)])
        self.assertEqual(self.route("workflow_dispatch", "mallory", "alice", number="7"), ("cap", self.freed(6)))

    def test_an_events_run_is_charged_to_the_account_that_started_it(self):
        """A writer's push to an outside account's pull request is screened, charged to the writer: the author's 12
        do not hold it, the total of 24 does."""
        self.runs(*self.screened(12, account="mallory"))
        self.assertEqual(self.route("pull_request_target", "mallory", "alice"), ("screen", ""))
        self.runs(*self.screened(24))
        self.assertEqual(self.route("pull_request_target", "mallory", "alice"), ("cap", self.freed(12)))

    def test_a_count_it_cannot_finish_fails_route(self):
        rc, out, got = self.cap("mallory")
        self.assertEqual((rc, got), (1, {}), out)
        self.assertIn("::error::GitHub did not give this workflow's runs of the last 24 hours. Re-run this run.", out)
        jobs = self.api / f"repos_{REPO.replace('/', '_')}_actions_runs_15_jobs.json"
        for run, said in (((15, 1, "pull_request_target", "o200", "success"),
                           "GitHub did not say whether o200 has write access. Re-run this run."),
                          ((15, 1, "workflow_dispatch", "alice", "success", "Pull request 8"),
                           "GitHub did not say who wrote 8. Re-run this run."),
                          ((15, 1, "pull_request_target", "o1", "success"),
                           "GitHub did not give the jobs of run 15. Re-run this run.")):
            with self.subTest(said=said):
                self.runs(run)
                if "jobs" in said:
                    jobs.unlink()
                rc, out, got = self.cap("mallory")
                self.assertEqual((rc, got), (1, {}), out)
                self.assertIn(f"::error::{said}", out)
                # route fails with it: no trust, so no screen and no review.
                rc, out, got = Trust.trust(self, "pull_request_target", "mallory", "mallory")
                self.assertEqual((rc, got.get("trust")), (1, None), out)
                self.assertIn(f"::error::{said}", out)

    def test_it_reads_the_jobs_of_at_most_100_runs(self):
        self.runs(*self.screened(100, hours=0.2))
        self.assertEqual(self.cap("zed")[2]["count"], "100")
        self.runs(*self.screened(101, hours=0.2))
        self.api.joinpath("args").unlink()
        rc, out, got = self.cap("zed")
        self.assertEqual((rc, got), (1, {}), out)
        self.assertIn("could not all be counted. Re-run this run.", out)
        self.assertEqual(len(self.jobs_read()), 100)


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

    def test_at_the_daily_cap_it_is_held_without_a_screen(self):
        for kind in ("change", "issue"):
            with self.subTest(kind=kind):
                jobs, ctx = self.ran({"kind": kind, "sha": "a" * 40, "trust": "cap"})
                self.assertEqual(jobs, {"comment"})
                self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        jobs, ctx = self.ran(dict(self.ENROLLMENT, trust="cap"))
        self.assertEqual(jobs, self.BUILT | {"comment"})
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])

    STANDING = "The head's standing result, for a label run"
    COLLECT = "Every job route asked for passed, and no other ran"

    def test_a_label_run_builds_screens_and_reviews_nothing(self):
        """A label of another name asks for nothing; the label run that adds parked to an enrollment asks for the
        comment job alone. The job required copies the head's standing project-builds and collects nothing."""
        for route, want in (({"kind": "", "label_run": "true"}, set()),
                            (dict(self.ENROLLMENT, label_run="true", parked="true"), {"comment"}),
                            ({"kind": "change", "sha": "a" * 40, "label_run": "true", "parked": "true"}, set())):
            with self.subTest(route=route):
                jobs, ctx = self.ran(route)
                self.assertEqual(jobs, want)
                self.assertEqual(required_steps(ctx), {self.STANDING})
                if want:
                    # The comment job holds nothing on it: no label review-held, no comment.
                    env = {f"env.{k}": as_text(evaluate(JOBS["comment"]["env"][k], ctx)) for k in ("HOLDING", "KIND")}
                    ran = {s.get("name") for s in JOBS["comment"]["steps"]
                           if "if" not in s or evaluate(s["if"], dict(ctx, **env))}
                    self.assertNotIn("Label it review-held and say so", ran)
                    self.assertNotIn("Post the comment, or update the one already there", ran)
        # Every other run collects, and copies nothing.
        _, ctx = self.ran(dict(self.ENROLLMENT, trust="writer"))
        self.assertEqual(required_steps(ctx), {self.COLLECT})

    def test_parked_holds_a_push_run_after_the_build(self):
        """A push to a pull request that parked holds builds it, and route gives no trust: no gather, screen or
        review. The required check passes on the build."""
        jobs, ctx = self.ran(dict(self.ENROLLMENT, parked="true"))
        self.assertEqual(jobs, self.BUILT)
        self.assertEqual(required(ctx)[0], 0, required(ctx)[1])
        _, ctx = self.ran(dict(self.ENROLLMENT, parked="true"), results={"project-builds": "failure"})
        self.assertEqual(required(ctx)[0], 1)

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
        jobs, _ = self.ran(dict(self.ENROLLMENT, trust="cap"), outputs={"project-builds": {"name": ""}})
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
        """Any failure of the review a clean screen let run: the comment job holds it."""
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

    def hold(self, trust, pr="7", number="7", comments=(), head="a" * 40, review="skipped", free=""):
        """free: route's output free, the time the daily cap frees, for trust cap."""
        self.serve(f"repos/{REPO}/issues/{number}/comments", list(comments))
        self.serve(f"repos/{REPO}/issues/{number}/labels", [{"name": "review-held"}])
        self.serve(f"repos/{REPO}/labels/review-held", {"name": "review-held"})
        self.serve(f"repos/{REPO}/issues/comments/5", {})
        self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": head}})
        rc, out, _ = self.run_script(step("comment", self.STEP)["run"], PR=pr, NUMBER=number, TRUST=trust,
                                     HEAD_SHA="a" * 40, REVIEW=review, RUN_ID="100", FREE=free)
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

    def test_a_capped_item_is_told_the_cap_and_when_it_frees(self):
        """c3 (f), and an issue or a change pull request held at the daily cap: the cap and the time it frees, and
        that a push or a run by hand reviews it from then. No marker that anything tries it again."""
        for pr, number, start in (("", "9", "-f issue=9"), ("7", "7", "-f pr=7")):
            with self.subTest(number=number):
                self.api.joinpath("args").unlink(missing_ok=True)
                _calls, bodies, _ = self.hold("cap", pr=pr, number=number, free="2026-11-10T00:00:00Z")
                self.assertEqual(bodies, [
                    "<!-- oss-verify-held -->\n**Automated review held.**\n\nIt comes from an account without write "
                    f"access to this repository, and the automated reviews of such accounts reached their cap of "
                    f"{WF['env']['REVIEW_CAP']} in 24 hours, {WF['env']['REVIEW_CAP_AUTHOR']} for one author. From "
                    f"2026-11-10 00:00 UTC, a push or `gh workflow run build.yaml -R {REPO} {start}` reviews it.\n\n"
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

    def test_a_review_that_did_not_finish_is_left_to_a_maintainer(self):
        for trust in ("screen", "writer"):
            with self.subTest(trust=trust):
                self.api.joinpath("args").unlink(missing_ok=True)
                _calls, bodies, _ = self.hold(trust, review="failure")
                self.assertIn("The automated screen passed it, but the automated review did not finish. A maintainer "
                              "will look at it.", bodies[0])
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
        self.assertEqual(set(e), {"GH_TOKEN", "REPO", "PR", "NUMBER", "TRUST", "REVIEW", "HEAD_SHA", "RUN_ID", "FREE"})
        self.assertEqual(e["FREE"], "${{ needs.route.outputs.free }}")
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
        """An issue held once (at the daily cap, say), whose later screen passes and whose review makes its
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

    def screen(self, trust="writer", comments=(), reviews=(), review_authors=(), status=0, event="pull_request_target"):
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


class LabelRun(Runner):
    """The job required's step "The head's standing result, for a label run", with a stand-in check-runs and runs API:
    a label run copies the newest project-builds of another Build run at the head, and never reports a pass of its
    own."""

    STEP = "The head's standing result, for a label run"
    HEAD = "a" * 40
    HEAD_REPO, HEAD_BRANCH = "mallory/oss-verify", "libx"
    RUN_ID = "500"
    CLEARS = "A push, or a re-run of this run after the head's build passes, clears it."

    def checks(self, *checks):
        """Serve the head's project-builds check runs: (check id, conclusion, the run its details_url names[, app id,
        status, repository of its details_url])."""
        self.serve(f"repos/{REPO}/commits/{self.HEAD}/check-runs", {"total_count": len(checks), "check_runs": [
            {"id": c[0], "name": "project-builds", "status": c[4] if len(c) > 4 else "completed",
             "conclusion": c[1] if (c[4] if len(c) > 4 else "completed") == "completed" else None,
             "details_url": f"https://github.com/{c[5] if len(c) > 5 else REPO}/actions/runs/{c[2]}/job/{9000 + c[0]}",
             "app": {"id": c[3] if len(c) > 3 else 15368}} for c in checks]})

    def build_run(self, run_id, path=".github/workflows/build.yaml", event="pull_request_target", head=HEAD,
                  repo=HEAD_REPO, branch=HEAD_BRANCH):
        self.serve(f"repos/{REPO}/actions/runs/{run_id}", {"id": run_id, "path": path, "event": event, "head_sha": head,
                                                         "head_repository": {"full_name": repo}, "head_branch": branch})

    def standing(self):
        return self.run_script(step("required", self.STEP)["run"], RUN_ID=self.RUN_ID, HEAD_SHA=self.HEAD,
                               HEAD_REPO=self.HEAD_REPO, HEAD_BRANCH=self.HEAD_BRANCH)[:2]

    def test_after_a_passing_full_run_it_passes(self):
        self.checks((5, "success", 40))
        self.build_run(40)
        rc, out = self.standing()
        self.assertEqual(rc, 0, out)
        self.assertIn(f"project-builds passed at aaaaaaa in run https://github.com/{REPO}/actions/runs/40", out)

    def test_after_a_failing_full_run_it_fails(self):
        for conclusion in ("failure", "cancelled", "timed_out"):
            with self.subTest(conclusion=conclusion):
                self.checks((5, conclusion, 40))
                self.build_run(40)
                rc, out = self.standing()
                self.assertEqual(rc, 1, out)
                self.assertIn(f"::error::project-builds is {conclusion} at aaaaaaa in run "
                              f"https://github.com/{REPO}/actions/runs/40, and this label run reports the same. "
                              + self.CLEARS, out)

    def test_with_none_it_fails(self):
        for checks in ((), ((9, "success", int(self.RUN_ID)),)):
            with self.subTest(checks=checks):
                self.checks(*checks)
                rc, out = self.standing()
                self.assertEqual(rc, 1, out)
                self.assertIn("::error::No other Build run reported project-builds at aaaaaaa, so this label run fails. "
                              "A push clears it, or a re-run of the head's cancelled Build run and then of this run.",
                              out)

    def test_the_newest_bound_run_decides(self):
        """A chain of label runs copies one result: an earlier label run is a pull_request_target run at the head too."""
        self.build_run(40)
        self.build_run(41)
        self.checks((5, "failure", 40), (6, "success", 41))
        self.assertEqual(self.standing()[0], 0)
        self.checks((6, "failure", 40), (5, "success", 41))
        self.assertEqual(self.standing()[0], 1)
        # A newer run still going: its status, not a pass.
        self.checks((5, "success", 40), (6, None, 41, 15368, "in_progress"))
        rc, out = self.standing()
        self.assertEqual(rc, 1, out)
        self.assertIn("project-builds is in_progress at aaaaaaa", out)

    def test_it_skips_its_own_run_and_runs_of_other_heads_or_workflows(self):
        self.build_run(40)
        self.build_run(42, head="b" * 40)
        self.build_run(43, path=".github/workflows/validate.yaml")
        self.build_run(44, event="workflow_dispatch")
        self.build_run(45, repo="eve/oss-verify")
        self.build_run(46, branch="other")
        self.build_run(47)
        newer = [(9, "success", int(self.RUN_ID)), (8, "success", 42), (7, "success", 43), (10, "success", 44),
                 (11, "success", 45), (12, "success", 46), (13, "success", 47, 999), (14, "success", 47, 15368,
                                                                                      "completed", "eve/oss-verify")]
        for older, want in (("failure", 1), ("success", 0)):
            with self.subTest(older=older):
                self.checks((5, older, 40), *newer)
                rc, out = self.standing()
                self.assertEqual(rc, want, out)
                self.assertIn(f"https://github.com/{REPO}/actions/runs/40,", out)

    def test_a_read_that_fails_fails_it(self):
        rc, out = self.standing()
        self.assertEqual(rc, 1, out)
        self.assertIn("::error::GitHub did not give the project-builds checks of aaaaaaa. Re-run this run.", out)
        self.checks((5, "success", 40))
        rc, out = self.standing()
        self.assertEqual(rc, 1, out)
        self.assertIn("::error::GitHub did not give run 40. Re-run this run.", out)

    def test_the_required_job_keeps_its_static_name_and_reads_checks_and_runs(self):
        job = JOBS["required"]
        self.assertEqual(job["name"], "project-builds")
        self.assertEqual(job["permissions"], {"contents": "read", "checks": "read", "actions": "read"})
        e = step("required", self.STEP)["env"]
        self.assertEqual((e["HEAD_SHA"], e["HEAD_REPO"], e["HEAD_BRANCH"], e["RUN_ID"]),
                         ("${{ github.event.pull_request.head.sha }}",
                          "${{ github.event.pull_request.head.repo.full_name }}",
                          "${{ github.event.pull_request.head.ref }}", "${{ github.run_id }}"))


class LabelEvents(unittest.TestCase):
    """build.yaml starts on label events, and a label run shares the pull request's concurrency group and cancels
    nothing, while a push cancels."""

    @staticmethod
    def group(ctx):
        return re.sub(r"\$\{\{(.*?)\}\}", lambda m: as_text(evaluate(m.group(1), ctx)), WF["concurrency"]["group"])

    @staticmethod
    def cancels(ctx):
        return evaluate(WF["concurrency"]["cancel-in-progress"], ctx)

    def test_it_starts_on_label_events(self):
        on = WF.get("on", WF.get(True))
        self.assertEqual(on["pull_request_target"]["types"],
                         ["opened", "reopened", "synchronize", "ready_for_review", "labeled", "unlabeled"])
        self.assertEqual(sorted(on["workflow_dispatch"]["inputs"]),
                         ["issue", "measure", "measure_repeats", "measure_set", "pr"])

    def test_a_label_run_waits_in_the_pull_requests_group_and_a_push_cancels(self):
        pr = {"github.event_name": "pull_request_target", "github.event.pull_request.number": 7}
        for action in ("labeled", "unlabeled"):
            with self.subTest(action=action):
                ctx = dict(pr, **{"github.event.action": action})
                self.assertEqual((self.group(ctx), self.cancels(ctx)), ("build-pull_request_target-7", False))
        for action in ("opened", "reopened", "synchronize", "ready_for_review"):
            with self.subTest(action=action):
                ctx = dict(pr, **{"github.event.action": action})
                self.assertEqual((self.group(ctx), self.cancels(ctx)), ("build-pull_request_target-7", True))
        by_hand = {"github.event_name": "workflow_dispatch", "inputs.pr": 7}
        self.assertEqual((self.group(by_hand), self.cancels(by_hand)), ("build-workflow_dispatch-7", True))
        issue = {"github.event_name": "issues", "github.event.action": "edited", "github.event.issue.number": 9,
                 "github.event.sender.login": "eve", "github.event.issue.user.login": "eve"}
        self.assertEqual((self.group(issue), self.cancels(issue)), ("build-issues-9", False))

    def test_a_screened_review_that_ran_out_of_time_is_held(self):
        """A review job that runs out of its own time ends cancelled, and the run goes on (a newer push cancels the
        whole run, and then no job after it runs): the comment job holds the item."""
        route = {"kind": "change", "sha": "a" * 40, "trust": "screen"}
        got, ctx = run_graph(route, results={"review": "cancelled"},
                             outputs={"screen": {"verdict": "clean", "checks": "model_armor"}})
        self.assertEqual({n for n, r in got.items() if r != "skipped"} - {"route", "required"},
                         {"gather", "screen", "review", "comment"})
        self.assertEqual(evaluate(JOBS["comment"]["env"]["HOLDING"], ctx), True)
        self.assertNotEqual(required(ctx)[0], 0)

    def test_the_review_admits_the_apps_of_allowed_bots_alone(self):
        self.assertEqual(step("review", "Review")["with"]["allowed_bots"], "${{ env.ALLOWED_BOTS }}")
