# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of build.yaml's screen of pull requests and issues from accounts without write access:  python3 -m pytest
tools/tests

route's trust step (who is screened, the hourly limit), which jobs run for each route and each answer of the screen
(the jobs' conditions, evaluated as GitHub does), what the required check reports, what each job holds, how the screen
and the review take the gathered data (.github/scripts/take-review-data), the gather job's check that the head did not
move, the comment job's hold, and the review comment's line on the checks that ran. .github/scripts/screen.py itself
is tested in test_screen.py."""
import hashlib
import io
import json
import os
import pathlib
import re
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
    boolean and null literals, contexts looked up whole in ctx (a missing one is null), == and != (strings compared
    without case), !, && and || (which give an operand, not a boolean), parentheses, and the functions cancelled and
    always. cancelled() is false: these tests run no cancelled run."""
    text = str(expression).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    tokens = re.findall(r"\s*('(?:[^']|'')*'|&&|\|\||==|!=|!|\(|\)|,|[A-Za-z_][A-Za-z0-9_.\-]*)", text)
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
        if t in ("true", "false"):
            return t == "true"
        if t == "null":
            return None
        if peek() == "(":
            take("(")
            take(")")
            assert t in ("cancelled", "always"), "no such function here: " + t
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
    and outputs give a job that runs another result than success, and its outputs. Return (results, the context)."""
    results, outputs = dict(results or {}), dict(outputs or {})
    assert set(ORDER) == set(JOBS), set(JOBS)
    ctx = {"github.event_name": event, "github.event.pull_request.number": "7"}
    got = {}
    defaults = {"project-builds": {"name": "libx", "sha": "a" * 40},
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
        out = route if name == "route" else outputs.get(name, defaults.get(name, {})) if ran else {}
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

    def trust(self, event, author="", actor="", runs=()):
        self.serve(f"repos/{REPO}/actions/workflows/build.yaml/runs", {"workflow_runs": [
            {"id": i, "triggering_actor": {"login": who}, "event": e} for i, who, e in runs]})
        return self.run_script(step("route", self.STEP)["run"], EVENT=event, AUTHOR=author, ACTOR=actor,
                               RUN_ID="100")

    def assertTrust(self, want, *args, **kwargs):
        rc, out, got = self.trust(*args, **kwargs)
        self.assertEqual((rc, got.get("trust")), (0, want), out)
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

    def test_nothing_reviewable_holds_nothing(self):
        """An enrollment pull request whose build took no project is not reviewed, so nothing is held either."""
        jobs, _ = self.ran(dict(self.ENROLLMENT, trust="limit"), outputs={"project-builds": {"name": ""}})
        self.assertEqual(jobs, {"project-builds"})
        jobs, _ = self.ran({"kind": "", "trust": ""})
        self.assertEqual(jobs, set())

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
        self.assertEqual(runs, ['.github/scripts/take-review-data "$RUNNER_TEMP/review-data/review.tar"',
                                'python3 .github/scripts/screen.py .review ${NAME:+"projects/$NAME"}'])

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
        return self.run_script(step("gather", self.STEP)["run"], PR="7", HEAD_SHA="a" * 40, TRUST=trust)[0]

    def test_the_same_head_passes(self):
        self.assertEqual(self.check("a" * 40, "a" * 40, "screen"), 0)

    def test_a_head_that_moved_fails_it(self):
        for read, now in (("b" * 40, "a" * 40), ("a" * 40, "b" * 40)):
            for trust in ("screen", "writer"):
                with self.subTest(read=read[0], now=now[0], trust=trust):
                    self.assertEqual(self.check(read, now, trust), 1)

    def test_a_head_that_cannot_be_read_fails_only_a_screened_one(self):
        self.assertEqual(self.check("a" * 40, None, "screen"), 1)
        self.assertEqual(self.check("a" * 40, None, "writer"), 0)


class Hold(Runner):
    """The comment job's hold: the label, and one comment in fixed words that says nothing of why."""

    STEP = "Label it review-held and say so"

    def hold(self, trust, pr="7", number="7", comments=(), head="a" * 40):
        self.serve(f"repos/{REPO}/issues/{number}/comments", list(comments))
        self.serve(f"repos/{REPO}/issues/{number}/labels", [{"name": "review-held"}])
        self.serve(f"repos/{REPO}/labels/review-held", {"name": "review-held"})
        self.serve(f"repos/{REPO}/issues/comments/5", {})
        self.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": head}})
        rc, out, _ = self.run_script(step("comment", self.STEP)["run"], PR=pr, NUMBER=number, TRUST=trust,
                                     HEAD_SHA="a" * 40)
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
        self.assertIn("the screen did not pass it", bodies[0])
        self.assertIn(f"gh workflow run build.yaml -R {REPO} -f pr=7", bodies[0])
        # nothing that notifies anyone or links an issue
        self.assertNotIn("@", bodies[0])
        self.assertNotRegex(bodies[0], r"#[0-9]|(?i:gh-)[0-9]")

    def test_an_issue_is_told_how_to_start_its_review(self):
        _calls, bodies, _ = self.hold("screen", pr="", number="9")
        self.assertIn(f"-f issue=9", bodies[0])

    def test_at_the_limit_it_says_so(self):
        _calls, bodies, _ = self.hold("limit")
        self.assertIn(f"the limit of {WF['env']['OUTSIDE_HOURLY_LIMIT']} an hour", bodies[0])

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
        self.assertEqual(set(e), {"GH_TOKEN", "REPO", "PR", "NUMBER", "TRUST", "HEAD_SHA"})
        self.assertNotIn("needs.screen", json.dumps(e))
        self.assertNotIn("needs.gather", json.dumps(e))

    def test_a_posted_review_takes_the_label_off(self):
        s = step("comment", "Take the label review-held off")
        self.serve(f"repos/{REPO}/issues/7/labels/review-held", [])
        rc, out, _ = self.run_script(s["run"], PR="7")
        self.assertEqual(rc, 0, out)
        self.assertIn(["--method", "DELETE", f"repos/{REPO}/issues/7/labels/review-held"], self.calls())
        (self.api / f"repos_{REPO.replace('/', '_')}_issues_7_labels_review-held.json").unlink()
        rc, out, _ = self.run_script(s["run"], PR="7")
        self.assertEqual(rc, 0, out)


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
                         "${{ needs.route.outputs.trust == 'screen' && needs.screen.outputs.checks || '' }}")

    def test_anything_else_is_refused(self):
        for screened in ("x; rm -rf /", "model_armor,", "@octocat", "model_armor,other"):
            with self.subTest(screened=screened):
                self.assertNotEqual(self.body(screened).returncode, 0)
