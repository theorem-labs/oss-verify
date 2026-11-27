# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Two costs of review.yml's model review (R6 of dispatch://INFRA-5359/spec, no run for a replaced push):

- a review of a head that a newer push replaced, which ran on to its end, because the run's concurrency group is its
  Build run's: the review job now has a group keyed on its pull request's or issue's number, with cancel-in-progress,
  so a newer run's review cancels it; collect passes a cancelled review only when its head is no longer the pull
  request's, and the comment job's post step records nothing for such a review;
- a first attempt that ended with no structured output, which a second attempt resuming the same failing session
  repeated: the failure is named (.github/scripts/review-attempt), and the second attempt of a resumed review starts a
  fresh session."""
import json
import os
import pathlib
import re
import subprocess

import pytest

from test_outside_screen import REVIEW, evaluate, interpolated, required, run_graph, step
from test_review_check import HEAD, OLDER, REPO, StandIn, post

ROOT = pathlib.Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / ".github" / "scripts" / "review-attempt"
PROMPT = ROOT / ".github" / "scripts" / "review-prompt"
REPLACED = ROOT / ".github" / "scripts" / "review-replaced"
REVIEW_JOB = REVIEW["jobs"]["review"]


@pytest.fixture
def gh(tmp_path):
    return StandIn(tmp_path)


def group(pr="", issue="", sha=HEAD, branch="INFRA-5359-demo"):
    """The review job's concurrency group, and its cancel-in-progress, for a run of route's pr or issue, after a Build
    run of `sha` on `branch`."""
    ctx = {"needs.route.outputs.pr": pr, "needs.route.outputs.issue": issue, "needs.route.outputs.sha": sha,
           "github.event.workflow_run.head_sha": sha, "github.event.workflow_run.head_branch": branch,
           "github.run_id": "777"}
    concurrency = REVIEW_JOB["concurrency"]
    return interpolated(concurrency["group"], ctx), concurrency["cancel-in-progress"]


def test_the_review_of_a_newer_head_cancels_the_review_of_an_older_head():
    # Two runs of pull request 8, of two heads: one group, and the newer review cancels the one that runs.
    assert group(pr="8", sha=OLDER) == group(pr="8", sha=HEAD) == ("review-change-8", True)


def test_two_pull_requests_from_one_branch_never_share_a_group():
    # Two open pull requests from the same branch into two bases: one head and one branch, two numbers.
    assert group(pr="8")[0] != group(pr="9")[0]
    # An issue's runs have a group by its number, which no pull request has.
    assert group(issue="9") == ("review-change-9", True)
    assert group(issue="9")[0] != group(issue="10")[0]


def collect_for(result, replaced, kind="change"):
    """What the check review jobs answers for a writer's run of pull request 8 whose review ended `result`, with the
    answer `replaced` of collect's step "Whether a newer head replaced a cancelled review" (empty: it did not run)."""
    route = {"kind": kind, "pr": "8", "sha": HEAD, "trust": "writer",
             **({"build_run": "900"} if kind == "enrollment" else {})}
    _, ctx = run_graph(route, results={"review": result})
    ctx["steps.replaced.outputs.replaced"] = replaced
    return required(ctx)


@pytest.mark.parametrize("kind", ["change", "enrollment"])
def test_a_cancelled_review_passes_only_when_a_newer_head_replaced_it(kind):
    # A newer head's review cancelled it: it passes, as cancelled.
    code, said = collect_for("cancelled", "true", kind)
    assert code == 0 and "review (cancelled)" in said, said
    # The head is still the pull request's (the job ran out of time, or a run admitted later cancelled it), or the pull
    # request could not be read: the review did not finish, and the check fails.
    for replaced in ("false", ""):
        code, said = collect_for("cancelled", replaced, kind)
        assert code == 1 and "review: cancelled, where the run asks for success" in said, (replaced, said)
    # A failed review of a change fails it whatever the head, and a review that passed passes.
    assert collect_for("failure", "true")[0] == 1
    assert collect_for("success", "")[0] == 0
    # Another job that the run asked for still fails it when it was cancelled: the screen, here.
    _, ctx = run_graph({"kind": "change", "pr": "8", "sha": HEAD, "trust": "screen"}, results={"screen": "cancelled"},
                       outputs={"screen": {"verdict": "clean"}})
    assert required(ctx)[0] == 1


def replaced(gh, head, pr_head):
    """review-replaced for a cancelled review of `head` of pull request 8, whose head GitHub gives as `pr_head` (None:
    the pull request cannot be read): (its GITHUB_OUTPUT, its output)."""
    if pr_head is not None:
        gh.serve(f"repos/{REPO}/pulls/8", {"number": 8, "head": {"sha": pr_head}})
    run = subprocess.run([str(REPLACED)], capture_output=True, text=True, timeout=60,
                         env=gh.env(PR="8", HEAD_SHA=head))
    assert run.returncode == 0, run.stderr
    return gh.output.read_text(), run.stdout


def test_the_step_reads_whether_the_pull_request_still_has_the_cancelled_reviews_head(gh):
    assert replaced(gh, OLDER, HEAD)[0] == "replaced=true\n"
    gh.output.write_text("")
    output, said = replaced(gh, HEAD, HEAD)
    assert output == "replaced=false\n" and said.startswith("::error::")
    gh.output.write_text("")
    (gh.answers / f"repos_{REPO.replace('/', '_')}_pulls_8.json").unlink()
    output, said = replaced(gh, OLDER, None)
    assert output == "replaced=false\n" and said.startswith("::warning::")
    # The step runs for a cancelled review of a pull request only, and collect reads its answer.
    collect = REVIEW["jobs"]["collect"]
    [step_] = [s for s in collect["steps"] if s.get("id") == "replaced"]
    assert step_["run"] == ".github/scripts/review-replaced"
    for result, pr, runs in (("cancelled", "8", True), ("failure", "8", False), ("success", "8", False),
                             ("cancelled", "", False)):
        assert bool(evaluate(step_["if"], {"needs.review.result": result, "needs.route.outputs.pr": pr})) is runs
    assert "steps.replaced.outputs.replaced" in step("collect", "Every job route asked for passed, and no other ran")[
        "env"]["CANCELLABLE"]


def test_a_cancelled_review_of_an_older_head_records_and_posts_nothing(gh):
    code, out = post(gh, kind="enrollment", name="libreac", head=OLDER, pr_head=HEAD, REVIEW="",
                     REVIEW_RESULT="cancelled")
    assert code == 0, out
    assert gh.posted_checks() == [], out
    assert f"the pull request's head is now {HEAD}" in out
    # The control: cancelled at the pull request's own head (a person cancelled it), the hold is recorded as before.
    (gh.answers / "args").unlink()
    code, out = post(gh, kind="enrollment", name="libreac", REVIEW="", REVIEW_RESULT="cancelled")
    assert code == 0, out
    assert [p["name"] for p in gh.posted_checks()] == ["Enrollment review", "review"]


def on_a_cancelled_run(condition):
    """Whether GitHub starts, or keeps running, a job with this if once its run is cancelled: cancelled() is then true,
    and a job with no status function in its if has an implicit success(), which is then false."""
    text = str(condition or "")
    if not re.search(r"\b(cancelled|always|success|failure)\(\)", text):
        return False
    return bool(evaluate(text.replace("cancelled()", "run.cancelled"), {"run.cancelled": True}))


def test_a_cancelled_run_ends_cancelled_with_no_job_failed():
    # No job of review.yml starts or keeps running once a person, or a newer run of the same Build run, cancels its
    # run: each is cancelled or skipped, so the run is grey and no check of it fails. collect is skipped too.
    assert {name: on_a_cancelled_run(job.get("if")) for name, job in REVIEW["jobs"].items() if name != "route"} == {
        name: False for name in REVIEW["jobs"] if name != "route"}
    assert REVIEW["jobs"]["collect"]["if"] == "${{ !cancelled() }}"
    # The control: the if collect had, always(), keeps it running.
    assert on_a_cancelled_run("always()") is True


def attempt(tmp_path, records, resumed):
    path = tmp_path / "execution.json"
    if records is not None:
        path.write_text(json.dumps(records))
    output, summary = tmp_path / "output", tmp_path / "summary"
    output.write_text("")
    run = subprocess.run([str(ATTEMPT)], capture_output=True, text=True, timeout=60,
                         env={**os.environ, "RESULT": str(path), "RESUMED": resumed, "GITHUB_OUTPUT": str(output),
                              "GITHUB_STEP_SUMMARY": str(summary)})
    assert run.returncode == 0, run.stderr
    return output.read_text().strip(), run.stdout.strip()


# #305's failing attempts, as their logs gave the result record (run 45470802681, 2026-11-24): one turn, an error.
RESUMED_FAILURE = {"type": "result", "subtype": "success", "is_error": True, "duration_ms": 265730, "num_turns": 1,
                   "total_cost_usd": 2.2478772}


@pytest.mark.parametrize("records, resumed, ended", [
    ([{"type": "system", "subtype": "init"}, RESUMED_FAILURE], "true", "no-output"),
    ([RESUMED_FAILURE], "false", "no-output"),
    ([{"type": "system", "subtype": "init"}], "false", "no-result"),
    (None, "false", "unreadable"),
    ([{**RESUMED_FAILURE, "structured_output": {"comment": "x"}}], "false", "failed"),
], ids=["a resumed attempt with no output", "a fresh attempt with no output", "no result record", "no file",
        "an output, and still a failure"])
def test_a_failed_attempt_is_named_and_never_read_as_a_review_that_found_nothing(tmp_path, records, resumed, ended):
    output, shown = attempt(tmp_path, records, resumed)
    assert output == f"ended={ended}"
    assert shown.startswith("::warning::") and len(shown.splitlines()) == 1


def prompt(tmp_path, session, kind="change"):
    output = tmp_path / f"prompt-{kind}-{bool(session)}"
    output.write_text("")
    env = {**os.environ, "KIND": kind, "PR": "8", "NAME": "libreac", "OUTSIDE": "0", "HEAD_SHA": HEAD,
           "SESSION": session, "LAST": OLDER if session else "", "GITHUB_OUTPUT": str(output)}
    run = subprocess.run([str(PROMPT)], capture_output=True, text=True, timeout=60, env=env, cwd=ROOT)
    assert run.returncode == 0, run.stderr
    text = output.read_text()
    return text


@pytest.mark.parametrize("kind", ["change", "enrollment"])
def test_the_second_attempt_of_a_resumed_review_starts_a_fresh_session(tmp_path, kind):
    session = "a02b811e-8e07-4cc1-a05f-01f2b93e3cd9"
    # The control: the first attempt resumes the earlier review's session.
    assert f"--resume {session}" in prompt(tmp_path, session, kind)
    fresh = prompt(tmp_path, "", kind)
    assert "--resume" not in fresh and OLDER not in fresh
    # The fresh prompt step runs only after a failed first attempt of a resumed review, with no session.
    fresh_step = step("review", "What the second attempt reads, in a fresh session")
    assert (fresh_step["env"]["SESSION"], fresh_step["env"]["LAST"]) == ("", "")
    assert fresh_step["if"] == "steps.review.outcome == 'failure' && needs.gather.outputs.session != ''"
    # The second attempt takes its prompt and arguments, and the first's only when it did not run.
    again = step("review", "Review again")["with"]
    for key, field in (("prompt", "prompt"), ("claude_args", "arguments")):
        ctx = {f"steps.prompt-fresh.outputs.{field}": "FRESH", f"steps.prompt.outputs.{field}": "FIRST"}
        assert "FRESH" in interpolated(again[key], ctx) and "FIRST" not in interpolated(again[key], ctx)
        ctx[f"steps.prompt-fresh.outputs.{field}"] = ""
        assert "FIRST" in interpolated(again[key], ctx)
