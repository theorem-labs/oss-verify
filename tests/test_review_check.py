# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The check run `review` that review.yml's comment job posts as the oss-verify App (R14 of dispatch://INFRA-5359/spec):
.github/scripts/review-check, which decides it, and the comment job's steps that post it, run with a stand-in gh.

The fixtures under tests/fixtures/review-check/ are GitHub's answers and the reviews' own outputs, saved on 2026-11-26:
change-person.json and change-blocking.json are the structured outputs of the change reviews of runs 45730191964
(#316's head e881b02) and 45730739547; enrollment-*.json are the env of the comment jobs of runs 45557506785 (#312,
Enrollment review failure), 45483369292 (#302, action_required) and 45044199839 (#277, whose review job failed);
reviews-315.json is #315's reviews (sjawhar approved c4582dd), permission-sjawhar.json his collaborator permission,
and check-runs-316.json the oss-verify App's check runs at #316's head."""
import json
import os
import pathlib
import re
import subprocess

import pytest

from test_outside_screen import ITEMS, REVIEW, as_text, comment_job_env, evaluate, read_workflow, run_graph, step

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "review-check"
FIXTURES = ROOT / "tests" / "fixtures" / "review-check"
REPO = "theorem-labs/oss-verify"
HEAD = "c4582ddc3db499ee2b85350adbe6923d74a48d92"  # #315's head, which sjawhar approved
OLDER = "b" * 40
RUN_URL = f"https://github.com/{REPO}/actions/runs/77"
PASSED = "Nothing blocks this pull request."

# gh api [--paginate] [--slurp] [--jq <filter>] [--method M] [-f|-F|-H k=v] [--input -] [--] <endpoint>, answered from
# <dir>/<endpoint>.json (slashes as underscores, the query dropped) through jq, and wrapped in a list with --slurp, as
# gh does; an endpoint with no file answers as GitHub's 404 does. Each call's arguments go to <dir>/args, one call a
# line of NUL-separated arguments, and what it read with --input - to <dir>/input.<n>.
STAND_IN_GH = r"""#!/usr/bin/env bash
[ "$1" = api ] || { echo "gh: only api is served here: $*" >&2; exit 9; }
shift
all=("$@") filter=. endpoint= input= slurp=
while [ $# -gt 0 ]; do
  case $1 in
    --paginate|--) shift ;;
    --slurp) slurp=1; shift ;;
    --jq) filter=$2; shift 2 ;;
    --input) input=$2; shift 2 ;;
    --method|-f|-F|-H) shift 2 ;;
    *) endpoint=$1; shift ;;
  esac
done
printf '%s\0' "${all[@]}" >> "$STAND_IN/args"; printf '\n' >> "$STAND_IN/args"
n=$(wc -l < "$STAND_IN/args")
[ "$input" != - ] || cat > "$STAND_IN/input.$n"
endpoint=${endpoint%%\?*}
file="$STAND_IN/${endpoint//\//_}.json"
[ -f "$file" ] || { echo "gh: Not Found (HTTP 404): $endpoint" >&2; exit 1; }
if [ -n "$slurp" ]; then jq -c '[.]' "$file"; else jq -r "$filter" "$file"; fi
"""


class StandIn:
    """A directory with the stand-in gh at the front of PATH and the answers it serves."""

    def __init__(self, root):
        self.root = root
        self.answers = root / "answers"
        self.answers.mkdir()
        (root / "bin").mkdir()
        (root / "bin" / "gh").write_text(STAND_IN_GH)
        (root / "bin" / "gh").chmod(0o755)
        (root / "temp").mkdir()
        self.output = root / "output"
        self.output.write_text("")

    def serve(self, endpoint, data):
        (self.answers / (endpoint.replace("/", "_") + ".json")).write_text(json.dumps(data))

    def env(self, **given):
        base = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        return {**base, **{k: str(v) for k, v in REVIEW["env"].items()},
                "PATH": f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}", "STAND_IN": str(self.answers),
                "GH_TOKEN": "stand-in", "REPO": REPO, "RUNNER_TEMP": str(self.root / "temp"),
                "GITHUB_OUTPUT": str(self.output), "GITHUB_STEP_SUMMARY": os.devnull, **given}

    def requests(self):
        """Each call the stand-in served: (method, endpoint, the JSON it read, or None)."""
        path = self.answers / "args"
        if not path.exists():
            return []
        found = []
        for n, line in enumerate(path.read_text().splitlines(), 1):
            call = line.split("\0")[:-1]
            method = call[call.index("--method") + 1] if "--method" in call else "GET"
            endpoint = next(a for a in call if a.startswith("repos/"))
            sent = json.loads((self.answers / f"input.{n}").read_text()) if "--input" in call else None
            found.append((method, endpoint, sent))
        return found

    def posted_checks(self):
        return [body for method, endpoint, body in self.requests()
                if (method, endpoint) == ("POST", f"repos/{REPO}/check-runs")]


@pytest.fixture
def gh(tmp_path):
    return StandIn(tmp_path)


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def check(gh, **env):
    """review-check's check run, for pull request 8 at HEAD unless `env` says otherwise."""
    run = subprocess.run([str(SCRIPT)], capture_output=True, text=True, timeout=60,
                         env=gh.env(**{"KIND": "change", "HEAD_SHA": HEAD, "PR": "8", **env}))
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def passing(*choices):
    """A change review's verdicts and choices: every check pass, with `choices`."""
    return json.dumps({"verdicts": {str(n): "pass" for n in range(1, 6)}, "choices": list(choices)})


def ordinary(basis="The description says why, and main's tests.yaml shows it."):
    return {"check": "5", "choice": "The suite runs on one more event.", "reserved": False, "basis": basis}


RESERVED = {"check": "4", "choice": "The comment job gets a new environment.", "reserved": True,
            "basis": "The description names Sami as the person who decides."}


def approval(**changed):
    """#315's real review, sjawhar's APPROVED of HEAD, with `changed` in place (user: its keys)."""
    [review] = fixture("reviews-315.json")
    user = {**review["user"], **changed.pop("user", {})}
    return {**review, **changed, "user": user}


def serve_approvals(gh, reviews, permission="admin", author="sjawhar-agent[bot]"):
    gh.serve(f"repos/{REPO}/pulls/8", {"number": 8, "user": {"login": author, "type": "Bot"}, "head": {"sha": HEAD}})
    gh.serve(f"repos/{REPO}/pulls/8/reviews", reviews)
    answer = fixture("permission-sjawhar.json")
    gh.serve(f"repos/{REPO}/collaborators/sjawhar/permission", {**answer, "permission": permission})


# The decision rule (review-change.md, checks 4 and 5; R14): an ordinary choice passes with the basis the pull request
# records; a choice reserved for a person passes only with that person's approval of the exact head.
APPROVAL_CASES = {
    "an ordinary choice with its basis": ([ordinary()], None, "success"),
    "an ordinary choice with no basis": ([ordinary(basis="  ")], None, "failure"),
    "a reserved choice, approved on its head by a User with write access": ([RESERVED], [approval()], "success"),
    "a reserved choice approved on an older head": ([RESERVED], [approval(commit_id=OLDER)], "failure"),
    "a reserved choice approved by a Bot": ([RESERVED], [approval(user={"type": "Bot"})], "failure"),
    "a reserved choice approved by a User without write access": ([RESERVED], [approval()], "failure"),
    "a reserved choice approved by the pull request's author": ([RESERVED], [approval()], "failure"),
    "a reserved choice approved, then changes requested": (
        [RESERVED], [approval(), approval(id=6066731381, state="CHANGES_REQUESTED",
                                          submitted_at="2026-11-26T00:05:00Z")], "failure"),
    "a reserved choice with no review at all": ([RESERVED], [], "failure"),
}


@pytest.mark.parametrize("label", APPROVAL_CASES)
def test_a_choice_passes_only_with_its_record(gh, label):
    choices, reviews, want = APPROVAL_CASES[label]
    if reviews is not None:
        serve_approvals(gh, reviews, permission="read" if "without write access" in label else "admin",
                        author="sjawhar" if "author" in label else "sjawhar-agent[bot]")
    got = check(gh, CHANGE=passing(*choices))
    assert (got["name"], got["head_sha"], got["external_id"], got["status"]) == ("review", HEAD, "8", "completed")
    assert got["conclusion"] == want, got["output"]
    if want == "success":
        assert got["output"]["title"] == PASSED
    elif choices[0]["reserved"]:
        assert got["output"]["title"] == ("Blocked: a choice of check 4 that is reserved for a person waits for a "
                                          "person's approval of this head.")
    else:
        assert got["output"]["title"] == "Blocked: an ordinary choice of check 5 records no basis."


def test_a_pull_request_that_cannot_be_read_gives_no_approval(gh):
    # No answer for the pull request: the reserved choice fails, and the check run is still posted.
    got = check(gh, CHANGE=passing(RESERVED))
    assert got["conclusion"] == "failure"


def test_an_approval_never_passes_a_verdict_the_review_did_not_pass(gh):
    serve_approvals(gh, [approval()])
    change = json.loads(passing(RESERVED))
    change["verdicts"]["4"] = "fail"
    got = check(gh, CHANGE=json.dumps(change))
    assert (got["conclusion"], got["output"]["title"]) == ("failure", "Blocked: check 4 (secrets) fails.")


@pytest.mark.parametrize("name, change, title", [
    # #316's review: check 5 person, under the old rule, and no choices (the old schema had none).
    ("change-person.json", None, "Blocked: check 5 (decisions) waits for a decision that the pull request records; "
                                 "the review's choices cannot be read."),
    ("change-blocking.json", None, "Blocked: check 3 (docs) fails; check 5 (decisions) waits for a decision that the "
                                   "pull request records; the review's choices cannot be read."),
    # The passing shape: #316's verdicts with check 5 pass and one ordinary choice with its basis (derived; no review
    # since 2026-11-25 gave five pass under the old check 5).
    ("change-person.json", {"5": "pass"}, PASSED),
])
def test_the_saved_change_reviews_give_their_conclusions(gh, name, change, title):
    saved = fixture(name)
    given = {"verdicts": {**saved["verdicts"], **(change or {})}}
    if change:
        given["choices"] = [ordinary()]
    got = check(gh, CHANGE=json.dumps(given))
    assert (got["conclusion"], got["output"]["title"]) == ("success" if title == PASSED else "failure", title)


def test_no_verdicts_is_no_pass(gh):
    for change in ("", "not json", "{}", json.dumps({"verdicts": {"1": "pass"}, "choices": []})):
        got = check(gh, CHANGE=change)
        assert got["conclusion"] == "failure", change


def test_a_choice_reaches_the_summary_neutralized_and_never_the_title(gh):
    text = "Ping @octocat about #12 <!-- oss-verify-review -->"
    got = check(gh, CHANGE=passing(ordinary(basis=text)))
    assert got["output"]["title"] == PASSED
    assert "@octocat" not in got["output"]["summary"] and "#12" not in got["output"]["summary"]


@pytest.mark.parametrize("name", ["enrollment-failing.json", "enrollment-person.json"])
def test_an_enrollment_passes_once_its_review_ran(gh, name):
    """#312 (Enrollment review failure) and #302 (action_required): each review ran, and each pull request changes only
    projects/<name>/, so the check passes; Enrollment review keeps the review's own conclusion."""
    saved = fixture(name)
    assert saved["KIND"] == "enrollment" and saved["REVIEW_RESULT"] == "success" and saved["VERDICTS"]
    got = check(gh, KIND="enrollment", NAME="libreac", OUTSIDE="0", PR=saved["PR"])
    assert got["conclusion"] == "success"
    assert got["output"]["title"].startswith("Nothing blocks this pull request: it changes only projects/libreac/")


@pytest.mark.parametrize("hold, more, title", [
    ("failed", {"JOB": "review"}, "The review job failed."),
    ("screen", {}, "The automated screen held this pull request."),
    ("cap", {"FREE": "2026-11-27T00:00:00Z"}, "The daily cap of automated reviews held this pull request."),
])
def test_an_enrollment_whose_review_did_not_run_fails(gh, hold, more, title):
    """#277's review job failed (enrollment-errored.json): no success, with the hold's title."""
    if hold == "failed":
        saved = fixture("enrollment-errored.json")
        assert (saved["REVIEW_RESULT"], saved["VERDICTS"]) == ("failure", None)
    got = check(gh, KIND="enrollment", HOLD=hold, RUN_URL=RUN_URL, **more)
    assert (got["conclusion"], got["output"]["title"]) == ("failure", title)


@pytest.mark.parametrize("change, want", [
    (passing(), "success"),
    (json.dumps({"verdicts": {"1": "pass", "2": "pass", "3": "fail", "4": "pass", "5": "pass"}, "choices": []}),
     "failure"),
    ("", "failure"),
])
def test_a_mixed_enrollment_needs_the_change_checks(gh, change, want):
    got = check(gh, KIND="enrollment", NAME="zlib", OUTSIDE="2", CHANGE=change)
    assert got["conclusion"] == want, got["output"]
    if want == "failure":
        assert "Of the files outside projects/zlib/" in got["output"]["summary"]


# The comment job's steps, run with the stand-in gh.
POST_STEP = "Post the comment and record the verdict"
HOLD_STEP = "Label it review-held and say so"


def run_step(gh, name, needs, **given):
    """The comment job's step `name`, run in this checkout with the job's env for `needs` and the step's `given`."""
    job = comment_job_env(needs)
    run = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", step("comment", name)["run"]], cwd=ROOT,
                         capture_output=True, text=True, timeout=120, env=gh.env(**job, **given))
    return run.returncode, run.stdout + run.stderr


def post(gh, change="", kind="change", head=HEAD, pr_head=None, name="", **env):
    """The step POST_STEP for pull request 8, a writer's, whose run reviewed `head` while the pull request is at
    `pr_head` (by default `head`); `env` replaces what the job gives the step."""
    gh.serve(f"repos/{REPO}/pulls/8", {"number": 8, "user": {"login": "sjawhar-agent[bot]", "type": "Bot"},
                                        "head": {"sha": pr_head or head}})
    gh.serve(f"repos/{REPO}/issues/8/comments", [])
    gh.serve(f"repos/{REPO}/check-runs", {"id": 1})
    given = {"PR": "8", "HEAD_SHA": head, "RUN_URL": RUN_URL, "REVIEW": "One change is needed.\n", "VERDICTS": "",
             "REASONS": "{}", "CHANGE": change, "OUTSIDE": "0" if kind == "enrollment" else "", "NAME": name,
             "CHECKS": "", "SCREENED": "", "TRUST": "writer", "FREE": "", "GATHER_RESULT": "success",
             "SCREEN_RESULT": "skipped", "SCREEN_VERDICT": "", "REVIEW_RESULT": "success", "HELD": "false",
             "HOLD_RESULT": "skipped", "CRITICALITY_SCORE": "", "OSS_FUZZ": "", "SIZES": "", **env}
    needs = {"needs.route.outputs.kind": kind, "needs.route.outputs.trust": given["TRUST"],
             "needs.route.outputs.held": "false", "needs.gather.outputs.name": name,
             "needs.review.result": given["REVIEW_RESULT"], "needs.screen.result": given["SCREEN_RESULT"],
             "needs.screen.outputs.verdict": given["SCREEN_VERDICT"]}
    assert set(step("comment", POST_STEP)["env"]) - {"GH_TOKEN", "REPO"} == set(given)
    return run_step(gh, POST_STEP, needs, **given)


def test_review_posts_one_check_named_review_for_the_reviewed_head(gh):
    # The step's head is route's: the head the run reviewed.
    assert step("comment", POST_STEP)["env"]["HEAD_SHA"] == "${{ needs.route.outputs.sha }}"
    code, out = post(gh, passing())
    assert code == 0, out
    [posted] = gh.posted_checks()
    assert (posted["name"], posted["head_sha"], posted["conclusion"], posted["output"]["title"]) == (
        "review", HEAD, "success", PASSED)
    # The comment opens with the same words.
    [comment] = [body["body"] for method, endpoint, body in gh.requests() if endpoint.endswith("/comments")
                 and method == "POST"]
    assert comment.startswith(f"<!-- oss-verify-review -->\n{PASSED}\n\n<sub>")


def test_a_blocking_verdict_posts_failure(gh):
    saved = fixture("change-blocking.json")
    code, out = post(gh, json.dumps({"verdicts": saved["verdicts"], "choices": []}))
    assert code == 0, out
    [posted] = gh.posted_checks()
    assert posted["conclusion"] == "failure"
    assert posted["output"]["title"] == ("Blocked: check 3 (docs) fails; check 5 (decisions) waits for a decision that "
                                         "the pull request records.")


def test_an_errored_or_cancelled_review_posts_no_success(gh):
    # A screened change whose review failed or was cancelled: the hold step posts review as failure.
    needs = {"needs.route.outputs.kind": "change", "needs.route.outputs.trust": "screen",
             "needs.route.outputs.held": "false", "needs.review.result": "failure"}
    for result in ("failure", "cancelled"):
        (gh.answers / "args").unlink(missing_ok=True)
        gh.serve(f"repos/{REPO}/pulls/7", {"head": {"sha": HEAD}})
        gh.serve(f"repos/{REPO}/issues/7/comments", [])
        gh.serve(f"repos/{REPO}/labels/review-held", {"name": "review-held"})
        gh.serve(f"repos/{REPO}/issues/7/labels", [{"name": "review-held"}])
        gh.serve(f"repos/{REPO}/check-runs", {"id": 1})
        code, out = run_step(gh, HOLD_STEP, needs, PR="7", NUMBER="7", TRUST="screen", REVIEW=result, HEAD_SHA=HEAD,
                             RUN_ID="77", FREE="", RUN_URL=RUN_URL)
        assert code == 0, out
        [posted] = gh.posted_checks()
        assert (posted["head_sha"], posted["conclusion"], posted["output"]["title"], posted["details_url"]) == (
            HEAD, "failure", "The review job failed.", RUN_URL), result
    # A writer's change whose review failed or was cancelled: the comment job does not run, so nothing posts
    # success, or anything: the head has no check run review, and GitHub holds the merge.
    for result in ("failure", "cancelled"):
        got, _ = run_graph(dict(ITEMS["change"], trust="writer"), {"review": result},
                           {"gather": {"digest": "d" * 64, "screen": "false", "name": ""}})
        assert (got["review"], got["comment"]) == (result, "skipped")
    # An enrollment whose review failed: Enrollment review records the hold, and review fails with it.
    for result in ("failure", "cancelled"):
        (gh.answers / "args").unlink(missing_ok=True)
        code, out = post(gh, kind="enrollment", name="libreac", REVIEW="", REVIEW_RESULT=result)
        assert code == 0, out
        assert [(p["name"], p["conclusion"], p["output"]["title"]) for p in gh.posted_checks()] == [
            ("Enrollment review", "action_required", "The review job failed."),
            ("review", "failure", "The review job failed.")], result


def test_a_new_head_gets_no_earlier_verdict(gh):
    """A run of an older head posts its check run at that head alone, and never at the pull request's newer head,
    which gets its own from its own review."""
    code, out = post(gh, passing(), head=OLDER, pr_head=HEAD)
    assert code == 0, out
    assert [(posted["head_sha"], posted["conclusion"]) for posted in gh.posted_checks()] == [(OLDER, "success")]
    # No comment: the newer head's run posts it.
    assert [endpoint for method, endpoint, _ in gh.requests() if method != "GET"] == [f"repos/{REPO}/check-runs"]
    # Its link is this run, since it posted no comment.
    assert gh.posted_checks()[0]["details_url"] == RUN_URL


def test_review_is_posted_by_the_app_that_posts_the_four_required_checks():
    """main's ruleset requires the four checks from integration 5447700, and R14 requires review from it too: GitHub's
    check runs at #316's head (check-runs-316.json) show the four from the oss-verify App, 5447700, whose client id
    they give. The comment job makes its token for review from that client id, as required-checks.yml's post job
    does."""
    saved = fixture("check-runs-316.json")
    assert {(run["name"], run["app"]["id"], run["app"]["slug"]) for run in saved["check_runs"]} == {
        (name, 5447700, "oss-verify") for name in ("tests", "enrollment", "project-builds", "terms-accepted")}
    [client_id] = {run["app"]["client_id"] for run in saved["check_runs"]}
    required = read_workflow("required-checks.yml")["jobs"]["post"]["steps"]
    assert [s["with"]["client-id"] for s in required if "create-github-app-token" in str(s.get("uses"))] == [client_id]
    [app] = [s["with"] for s in REVIEW["jobs"]["comment"]["steps"] if s.get("id") == "app"]
    assert (app["client-id"], app["permission-checks"]) == (client_id, "write")


# The refresh (R14, decision of 2026-11-26): after a review of the pull request is submitted or dismissed, the check
# run review of the head is posted again from its record, with the approvals read then. GitHub's newest check run of
# that name decides.
def recorded(gh, change):
    """The check run that review-check posts for `change` at HEAD, as GitHub keeps it, with its record."""
    return check(gh, CHANGE=change)


def refreshed(gh, newest):
    """review-check --refresh on the output.text of `newest`: the check run it prints, or None."""
    run = subprocess.run([str(SCRIPT), "--refresh"], capture_output=True, text=True, timeout=60,
                         env=gh.env(HEAD_SHA=HEAD, PR="8", RECORD=newest["output"]["text"]))
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout) if run.stdout.strip() else None


def test_the_record_holds_no_text_of_a_choice(gh):
    got = recorded(gh, passing({**RESERVED, "choice": "Ping @octocat -->", "basis": "<b>x</b>"}))
    text = got["output"]["text"]
    assert text.startswith("<!-- ") and text.endswith(" -->") and "-->" not in text[5:-4]
    record = json.loads(text[5:-4])
    assert record == {"schema": "oss-verify/review/1", "head": HEAD, "kind": "change", "name": None, "outside": None,
                      "hold": None, "job": None, "verdicts": {str(n): "pass" for n in range(1, 6)},
                      "choices": [{"check": "4", "reserved": True, "based": True}]}


def test_an_approval_after_the_review_passes_its_reserved_choice(gh):
    newest = recorded(gh, passing(RESERVED))
    assert newest["conclusion"] == "failure"
    serve_approvals(gh, [approval()])
    again = refreshed(gh, newest)
    assert (again["name"], again["head_sha"], again["conclusion"], again["output"]["title"]) == (
        "review", HEAD, "success", PASSED)
    assert again["output"]["text"] == newest["output"]["text"]


@pytest.mark.parametrize("later", ["dismissed", "changes requested"])
def test_a_dismissal_turns_a_success_back_into_a_failure(gh, later):
    serve_approvals(gh, [approval()])
    newest = recorded(gh, passing(RESERVED))
    assert newest["conclusion"] == "success"
    taken_back = approval(state="DISMISSED") if later == "dismissed" else approval(
        id=6066731381, state="CHANGES_REQUESTED", submitted_at="2026-11-26T00:05:00Z")
    serve_approvals(gh, [taken_back] if later == "dismissed" else [approval(), taken_back])
    again = refreshed(gh, newest)
    assert (again["conclusion"], again["output"]["title"]) == (
        "failure", "Blocked: a choice of check 4 that is reserved for a person waits for a person's approval of this "
        "head.")


@pytest.mark.parametrize("newest", [
    {"output": {"text": None}}, {"output": {"text": "<!-- {} -->"}},
    {"output": {"text": '<!-- {"schema":"oss-verify/review/1","head":"' + OLDER + '"} -->'}}],
    ids=["no record", "another schema", "another head"])
def test_a_check_run_with_no_record_of_this_head_is_not_refreshed(gh, newest):
    newest = {"output": {"text": newest["output"]["text"] or ""}}
    assert refreshed(gh, newest) is None


def test_no_approval_changes_a_hold_or_an_enrollment_of_its_project_alone(gh):
    held = check(gh, HOLD="screen", RUN_URL=RUN_URL)
    alone = check(gh, KIND="enrollment", NAME="libreac", OUTSIDE="0")
    serve_approvals(gh, [approval()])
    assert (refreshed(gh, held), refreshed(gh, alone)) == (None, None)


REFRESH_STEP = "Post the check run review again, with the approvals read now"


def refresh_job(gh, newest_runs, reviews):
    """The refresh job's posting step for pull request 8 at HEAD, with the check runs review at HEAD that GitHub
    lists (`newest_runs`, each also served by its id) and the pull request's reviews."""
    gh.serve(f"repos/{REPO}/commits/{HEAD}/check-runs", {"check_runs": newest_runs})
    for run in newest_runs:
        gh.serve(f"repos/{REPO}/check-runs/{run['id']}", run)
    gh.serve(f"repos/{REPO}/check-runs", {"id": 1})
    serve_approvals(gh, reviews)
    run = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", step("comment", REFRESH_STEP)["run"]], cwd=ROOT,
                         capture_output=True, text=True, timeout=120, env=gh.env(PR="8", HEAD_SHA=HEAD))
    return run.returncode, run.stdout + run.stderr


def as_listed(posted, run_id, app=5447700):
    return {**posted, "id": run_id, "app": {"id": app}, "details_url": f"{RUN_URL}#{run_id}"}


def test_the_refresh_job_posts_only_a_changed_verdict_of_the_newest_check_run(gh):
    failing = recorded(gh, passing(RESERVED))
    # The newest of the App's check runs for this pull request decides; another App's and an older one do not.
    runs = [as_listed(failing, 20), {**as_listed(failing, 30), "external_id": "9"}, as_listed(failing, 40, app=1)]
    code, out = refresh_job(gh, runs, [approval()])
    assert code == 0, out
    [posted] = gh.posted_checks()
    assert (posted["conclusion"], posted["details_url"]) == ("success", f"{RUN_URL}#20")
    # Read again with no approval, the same verdict: nothing is posted.
    (gh.answers / "args").unlink()
    code, out = refresh_job(gh, [as_listed(failing, 20)], [])
    assert (code, gh.posted_checks()) == (0, []), out
    assert "stands" in out


def comment_steps_that_run(ctx):
    """The names of the comment job's steps whose if is true for the jobs' context `ctx` (run_graph's), with the job's
    env evaluated from it as GitHub gives it to the steps; a step's outputs that no step wrote are null. An if that YAML
    reads as a boolean (if: true) is that boolean."""
    job = REVIEW["jobs"]["comment"]
    env = {f"env.{key}": as_text(evaluate(value, ctx)) if "${{" in str(value) else str(value)
           for key, value in job["env"].items()}
    return [s.get("name") or s.get("uses") for s in job["steps"]
            if "if" not in s or (s["if"] if isinstance(s["if"], bool) else bool(evaluate(s["if"], {**ctx, **env})))]


def test_the_refresh_runs_after_a_review_approvals_run_alone():
    """A Review approvals run asks for the comment job alone, and in it only the steps that make the App's token and
    post the check run review again: no comment, no Enrollment review, no label, no approval and no replay. No job of
    a review runs, and no job gains a credential."""
    got, ctx = run_graph({"refresh": "true", "pr": "8", "sha": HEAD}, event="workflow_run", ref="refs/heads/main")
    assert {job for job, result in got.items() if result != "skipped"} == {"route", "comment", "collect"}, got
    sign_in = [s.get("name") or s.get("uses") for s in REVIEW["jobs"]["comment"]["steps"][:4]]
    assert sign_in[1:] == ["Sign in to Google Cloud", "Read the oss-verify App's key", "Get the oss-verify App's token"]
    assert comment_steps_that_run(ctx) == [*sign_in, REFRESH_STEP]
    # The control: a change's review runs the post and not the refresh.
    gathered = {"digest": "d" * 64, "screen": "false", "name": "", "kind": "change"}
    got, ctx = run_graph(dict(ITEMS["change"], trust="writer"), outputs={"gather": gathered})
    assert got["comment"] == "success"
    # (The step that takes the label off reads the post's output, which no step has written here.)
    assert comment_steps_that_run(ctx) == [*sign_in, "Post the comment and record the verdict"]
    # Not on a run by hand, which never carries route's refresh.
    got, _ = run_graph({"refresh": "true", "pr": "8", "sha": HEAD}, event="workflow_dispatch", ref="refs/heads/main")
    assert got["comment"] == "skipped"


def test_a_completed_failing_rerun_replaces_a_success_and_an_errored_one_leaves_it(gh):
    """The newest completed review of a head stands: a by-hand review of the same head that finds a blocking item posts
    a failure, the newest check run of the name; one whose review failed posts nothing."""
    code, out = post(gh, passing())
    assert code == 0, out
    code, out = post(gh, json.dumps({"verdicts": {**json.loads(passing())["verdicts"], "1": "fail"}, "choices": []}))
    assert code == 0, out
    assert [p["conclusion"] for p in gh.posted_checks()] == ["success", "failure"]
    # The errored re-run: the comment job does not run for a writer's change whose review failed or was cancelled,
    # so no check run is posted and the newest completed verdict stands.
    for result in ("failure", "cancelled"):
        got, _ = run_graph(dict(ITEMS["change"], trust="writer"), {"review": result},
                           {"gather": {"digest": "d" * 64, "screen": "false", "name": ""}})
        assert got["comment"] == "skipped", result


def gather_change(gh, tmp_path, changed, files):
    """review-gather for a change pull request 8 at HEAD whose API gives `changed` files and lists `files` (None: the
    list cannot be read)."""
    gh.serve(f"repos/{REPO}/pulls/8", {"number": 8, "changed_files": changed})
    if files is not None:
        gh.serve(f"repos/{REPO}/pulls/8/files", [{"filename": name} for name in files])
    run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-gather"), str(tmp_path / "out")], cwd=ROOT,
                         capture_output=True, text=True, timeout=120,
                         env=gh.env(KIND="change", PR="8", HEAD_SHA=HEAD, NAME=""))
    return run.returncode, run.stdout + run.stderr


@pytest.mark.parametrize("changed, files, said", [
    (2, None, "the pull request's files could not be listed"),
    (3001, ["a.txt"], "the pull request changes 3001 files, which the API cannot list whole")])
def test_a_change_whose_files_cannot_all_be_read_is_not_gathered(gh, tmp_path, changed, files, said):
    code, out = gather_change(gh, tmp_path, changed, files)
    assert code == 1 and f"review-gather: {said}" in out, out
    # The control: the same pull request, its files listed.
    code, out = gather_change(gh, tmp_path, 1, ["a.txt"])
    assert code == 0, out


@pytest.mark.parametrize("outside", ["", "two"])
def test_an_enrollment_whose_outside_files_were_not_counted_fails(gh, outside):
    got = check(gh, KIND="enrollment", NAME="zlib", OUTSIDE=outside, CHANGE=passing())
    assert (got["conclusion"], got["output"]["title"]) == (
        "failure", "Blocked: the files that this pull request changes outside projects/zlib/ were not counted.")
    # No approval counts them: a refresh of its record posts nothing, so the failure stands.
    serve_approvals(gh, [approval()])
    assert refreshed(gh, got) is None


def test_a_mixed_enrollment_whose_outside_files_cannot_be_listed_is_not_gathered(gh, tmp_path):
    gh.serve(f"repos/{REPO}/pulls/8", {"number": 8, "changed_files": 3})
    env = gh.env(KIND="enrollment", PR="8", HEAD_SHA=HEAD, NAME="zlib", OUTSIDE="2")
    run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-gather"), str(tmp_path / "out")], cwd=ROOT,
                         capture_output=True, text=True, timeout=120, env=env)
    assert run.returncode == 1 and "review-gather: the pull request's files could not be listed" in run.stderr, (
        run.stdout + run.stderr)
    # The control: with the list, the outside files are named, whatever the rest of the gather then does.
    gh.serve(f"repos/{REPO}/pulls/8/files", [{"filename": "projects/zlib/build.sh"}, {"filename": "NOTICE"},
                                             {"filename": "docs/seeded-projects.tsv"}])
    run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-gather"), str(tmp_path / "again")], cwd=ROOT,
                         capture_output=True, text=True, timeout=120, env=env)
    assert "could not be listed" not in run.stderr
    assert (tmp_path / "again" / "outside.txt").read_text() == "NOTICE\ndocs/seeded-projects.tsv\n"


PROJECT_STEP = "Take projects/<name>/ from the pull request, as the build did"


@pytest.mark.parametrize("kind, held, code, wrote, want_code, want, refused", [
    ("enrollment", "false", 0, "name=\n", 0, {"kind": "change"}, ""),
    # A change that an App the review's action refuses opened (Dependabot's, say): no kind, so nothing reviews,
    # holds or fails it, as on main.
    ("enrollment", "false", 0, "name=\n", 0, {}, "true"),
    ("enrollment", "false", 0, "name=zlib\noutside=0\n", 0, {"name": "zlib", "kind": "enrollment", "outside": "0"},
     "true"),
    ("enrollment", "false", 0, "name=zlib\noutside=0\n", 0, {"name": "zlib", "kind": "enrollment", "outside": "0"},
     ""),
    ("enrollment", "false", 0, "name=zlib\noutside=2\n", 0, {"name": "zlib", "kind": "enrollment", "outside": "2"},
     ""),
    ("enrollment", "false", 0, "name=zlib\n", 1, {}, ""),
    ("enrollment", "false", 1, "", 1, {}, ""),
    ("enrollment", "true", 1, "", 0, {"kind": "change"}, ""),
    ("enrollment", "true", 0, "name=\n", 0, {"kind": "change"}, ""),
    ("change", "false", 0, "", 0, {"kind": "change"}, ""),
], ids=["no project: a change", "an App the action refuses, no project: nothing",
        "an App the action refuses, its project: an enrollment", "its project alone", "with files outside it",
        "no count", "refused", "held and refused: a change", "held, no project: a change", "a change stays one"])
def test_the_gather_job_reviews_a_pull_request_with_no_project_as_a_change(tmp_path, kind, held, code, wrote,
                                                                          want_code, want, refused):
    """The gather job's project step, with a stand-in take-project that writes `wrote` and ends with `code`: a pull
    request it takes no project from gets the kind change, which the later jobs read in place of route's."""
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "take-project").write_text(f"#!/usr/bin/env bash\nprintf '{wrote}' >> \"$GITHUB_OUTPUT\"\nexit {code}\n")
    (scripts / "take-project").chmod(0o755)
    output = tmp_path / "output"
    output.write_text("")
    (tmp_path / "temp").mkdir()
    run = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", step("gather", PROJECT_STEP)["run"]],
                         cwd=tmp_path, capture_output=True, text=True, timeout=60,
                         env={**os.environ, "KIND": kind, "HELD_RUNS": held, "REFUSED": refused,
                              "GITHUB_OUTPUT": str(output), "RUNNER_TEMP": str(tmp_path / "temp")})
    assert run.returncode == want_code, run.stdout + run.stderr
    assert dict(line.split("=", 1) for line in output.read_text().splitlines()) == want
    # Every later job reads the gather job's kind first.
    assert REVIEW["jobs"]["comment"]["env"]["KIND"] == "${{ needs.gather.outputs.kind || needs.route.outputs.kind }}"
    assert REVIEW["jobs"]["gather"]["outputs"]["kind"] == "${{ steps.project.outputs.kind }}"
    assert REVIEW["jobs"]["gather"]["env"]["REFUSED"] == "${{ needs.route.outputs.refused }}"


RESULT_STEP = "Keep the draft, and the held finding apart from it"


def result_change(tmp_path, output):
    """The review job's result step on a change review whose structured output is `output`: its output change, the
    line review-check reads."""
    result_step = step("review", RESULT_STEP)
    execution = tmp_path / "execution.json"
    execution.write_text(json.dumps([{"type": "system", "subtype": "init"},
                                     {"type": "result", "subtype": "success", "structured_output": output}]))
    ctx = {"steps.review.outputs.execution_file": str(execution),
           "steps.review.outputs.session_id": "09227178-7bbf-4e5f-86db-8736e530ef01"}
    for name in ("temp", "home"):
        (tmp_path / name).mkdir(exist_ok=True)
    written = tmp_path / "output"
    written.write_text("")
    run = subprocess.run(["bash", "-e", "-c", result_step["run"]], cwd=tmp_path, capture_output=True, text=True,
                         timeout=60,
                         env={**os.environ, "HOME": str(tmp_path / "home"), "RUNNER_TEMP": str(tmp_path / "temp"),
                              "GITHUB_OUTPUT": str(written),
                              "RESULT": as_text(evaluate(result_step["env"]["RESULT"], ctx)),
                              "SESSION": as_text(evaluate(result_step["env"]["SESSION"], ctx)), "HEAD_SHA": HEAD,
                              "KIND": "change", "ISSUE": "", "GITHUB_STEP_SUMMARY": os.devnull})
    assert run.returncode == 0, run.stdout + run.stderr
    [line] = [line for line in written.read_text().splitlines() if line.startswith("change=")]
    return line[len("change="):]


@pytest.mark.parametrize("choices, kept, title", [
    ([{**RESERVED, "choice": "x" * 1500, "extra": 1}],
     [{"check": "4", "reserved": True, "choice": "x" * 1000, "basis": RESERVED["basis"]}],
     "Blocked: a choice of check 4 that is reserved for a person waits for a person's approval of this head."),
    ([ordinary()] * 21, "not read", "Blocked: the review's choices cannot be read."),
    (["a choice as text"], [None], "Blocked: the review's choices cannot be read."),
], ids=["a reserved choice, its text cut", "more than 20 choices", "a choice that is no object"])
def test_the_review_job_keeps_each_choice_for_the_check(gh, tmp_path, choices, kept, title):
    """The result step keeps the five verdicts and, of at most 20 choices, the four keys of each, its texts cut to 1,000
    characters; a list it cannot keep whole becomes a text, which review-check fails, so no reserved choice is lost."""
    output = {"comment": "Thanks.\n", "verdicts": {str(n): "pass" for n in range(1, 6)}, "choices": choices}
    change = result_change(tmp_path, output)
    assert json.loads(change) == {"verdicts": output["verdicts"], "choices": kept}
    got = check(gh, CHANGE=change)
    assert (got["conclusion"], got["output"]["title"]) == ("failure", title)


TRUST_STEP = "Whether the author and the account that started the run have write access"


def test_a_dependabot_pull_request_that_bumps_an_action_gets_a_review_and_its_check(gh, tmp_path):
    """Dependabot's pull requests bump the pinned actions, so once main requires review they merge only with it: the
    review's action admits Dependabot (ALLOWED_BOTS), route makes its change a change review, its text is screened as
    an account's without write access (it is not one of WRITER_BOTS), and the review posts review on its head."""
    from test_routed_workflows import PULL, route_review
    env = REVIEW["env"]
    assert "dependabot[bot]" in env["ALLOWED_BOTS"].split(",")
    assert "dependabot[bot]" not in env["WRITER_BOTS"].split(",")
    # route: a change of a workflow file, opened and pushed by Dependabot, is a change.
    (tmp_path / "route").mkdir()
    code, outputs, _ = route_review(tmp_path / "route", [".github/workflows/build.yaml"], actor="dependabot[bot]")
    assert (code, outputs) == (0, PULL + ["kind=change"])
    # trust: route's rule for trusted accounts does not trust it, so its text is screened.
    function = re.search(r"# trusted\n(.*?)# end of trusted\n", step("route", TRUST_STEP)["run"], re.S)[1]
    run = subprocess.run(["bash", "-c", "set -uo pipefail\n" + function + 'trusted "$1"\n', "trusted",
                          "dependabot[bot]"], capture_output=True, text=True, timeout=60,
                         env={**os.environ, "WRITER_BOTS": env["WRITER_BOTS"], "REPO": REPO})
    assert run.returncode == 1, run.stderr
    # The jobs: screened clean, it is reviewed, and the comment job posts the review comment and the check.
    got, _ = run_graph({"kind": "change", "trust": "screen", "pr": "8", "sha": HEAD},
                       outputs={"gather": {"digest": "d" * 64, "screen": "true", "name": "", "kind": "change"},
                                "screen": {"verdict": "clean"}})
    assert (got["screen"], got["review"], got["comment"]) == ("success", "success", "success"), got
    code, out = post(gh, passing(), TRUST="screen", SCREEN_RESULT="success", SCREEN_VERDICT="clean")
    assert code == 0, out
    [posted] = gh.posted_checks()
    assert (posted["name"], posted["head_sha"], posted["conclusion"]) == ("review", HEAD, "success")
