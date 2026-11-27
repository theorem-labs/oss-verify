# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of app/sentences.yaml, version 11:

    python3 -P -m pytest -q -p no:cacheprovider -c pyproject.toml tests/test_sentences.py

app/sentences.yaml holds each text that OSS Verify's two GitHub Apps write. The App Theorem Verify writes its check
runs and their buttons, its pull requests, its comments and its commit messages. The App OSS Verify writes its texts on
theorem-labs/oss-verify-proofs, such as a publication's commit message and release texts. Each App takes each text from
this file. A code owner (.github/CODEOWNERS) approves each change of the file (R1 of OSSV-660). This test reads the file
as text for the comments that give the kinds of the parts, and with PyYAML for the keys. It changes no byte of it.

Each check below takes the text of the file and gives a list of problems. Each problem names its key. The file passes
when each list is empty:
  part_kinds        Each {name} part of a sentence has a kind, and the kind is one of KINDS. A comment gives the kind:
                    at the end of the key's line, or in the comment lines just above the key.
  long_buttons      A label of check_run.buttons has at most 20 characters, and a text of check_run.button_descriptions
                    at most 40. GitHub refuses a longer one.
  missing_keys      The file holds each key of REQUIRED.
  dropped_keys      The file holds no key of DROPPED, and no key under one: version 11 of the file dropped them.
  check_run_states  No key of the file has the conclusion neutral, because GitHub counts a neutral required check
                    as passed: each key conclusion, at any depth, is one of ALLOWED. Each state of CONCLUSIONS, under
                    check_run, has its conclusion, its button of BUTTONS and its title of TITLES.
  statement_states  The keys of check_run.statement_line.statement_states are those of STATEMENT_STATES.
  does_not_hold     No sentence of the check run says that a statement does not hold. A finding stays private until
                    the maintainer makes it public.
  check_lines       The summary of each state of CHECK_LINES holds the part {check_lines}.
Each control (test_control) changes a copy of the file in tmp_path, and shows that its check names the fault.
"""
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SENTENCES = ROOT / "app" / "sentences.yaml"

# The kinds of value that fill a {name} part, as R1 of OSSV-660 lists them. No part takes free text.
KINDS = ("a number", "a commit id", "a time", "a fuzz target's line", "a fuzz target's name", "a statement's name",
         "a repository's name", "a login", "a link to a public page", "a release's version",
         "a sentence of another key of this file")
# A {name} part of a sentence.
PART = re.compile(r"\{(\w+)\}")
# In a comment, the parts that the kind after the colon is for: "{count}:", or "{failed}, {count}:".
GIVEN = re.compile(r"\{\w+\}(?:(?:,\s*|,?\s+and\s+)\{\w+\})*:")

# The states of the check run, each with its conclusion, as R1 of OSSV-660 gives them.
CONCLUSIONS = {
    "check_needed": "action_required",
    "holds": "success", "no_statements": "success", "not_enrolled": "success", "setup_ready": "success",
    "proving": "failure", "waiting_for_maintainer": "failure", "did_not_build": "failure", "our_fault": "failure",
    "setup": "failure", "setup_missing_step": "failure", "merged_unchecked": "failure",
    "merge_group_unchecked": "failure",
}
# The conclusions that a state can have: each key conclusion of the file, at any depth, not only under check_run.
ALLOWED = ("success", "failure", "action_required")
# The states that show a button, with the key of check_run.buttons that each shows, as R1 of OSSV-660 gives them.
# Every other state shows none.
BUTTONS = {"check_needed": "check", "setup": "check", "merged_unchecked": "check", "did_not_build": "rerun",
           "our_fault": "rerun"}
# The states whose title the design gives.
TITLES = {
    "check_needed": "Not checked yet.",
    "waiting_for_maintainer": "Proof work is waiting for the maintainer.",
    "merged_unchecked": "This commit reached the default branch past the rule.",
}
# The most characters of each text of a button: GitHub's limits for a check run's action.
LIMITS = {"buttons": 20, "button_descriptions": 40}
# The states of a statement, the keys of check_run.statement_line.statement_states. None says that it does not hold.
STATEMENT_STATES = ("holds", "needs_work", "not_met")
# A sentence that says that something does not hold.
NOT_HOLD = re.compile(r"\bnot\s+hold", re.IGNORECASE)
# The states whose summary holds the lines of the checks of the binaries, check_run.build_checks.line.form.
CHECK_LINES = ("setup", "setup_ready")
# The keys that version 11 of the file dropped, each with the keys under it.
DROPPED = ("enrollment_review", "enrollment_checks_comment")

# The keys that the file must hold. They come from five sources: the keys that the `app` plug-in of theorem-cli posts
# (c-app-4 of OSSV-654); the states of the check run and their buttons, CONCLUSIONS and BUTTONS (R1 of OSSV-660); the
# keys of the checks of the binaries, check_run.build_checks (R7 of OSSV-745); the two comments on the open enrollment
# pull requests, open_pull_requests (R6 of OSSV-747); and the texts of `theorem publish`, commit_messages.publication
# and releases.publication (OSSV-656).
REQUIRED = (
    "check_run.name",
    "check_run.text",
    "check_run.target_line",
    "check_run.target_line.form",
    "check_run.target_line.build_states",
    "check_run.target_line.not_verified",
    "check_run.statement_line",
    "check_run.statement_line.form",
    *(f"check_run.statement_line.statement_states.{state}" for state in STATEMENT_STATES),
    *(f"check_run.{state}" for state in CONCLUSIONS),
    "check_run.setup_checks",
    "check_run.buttons",
    "check_run.buttons.check",
    "check_run.buttons.rerun",
    "check_run.button_descriptions",
    "check_run.button_descriptions.check",
    "check_run.button_descriptions.rerun",
    "check_run.build_checks.line.form",
    "check_run.build_checks.result.form",
    "check_run.build_checks.names",
    "check_run.build_checks.names.elf",
    "check_run.build_checks.names.system_calls",
    "check_run.build_checks.names.quiet_loud",
    "check_run.build_checks.names.instrumented",
    "check_run.build_checks.names.reach",
    "check_run.build_checks.names.breakage",
    "check_run.build_checks.results.pass",
    "check_run.build_checks.results.fail",
    "setup_pull_request.terms_line",
    "commit_messages.publication",
    "releases.publication.title",
    "releases.publication.body",
    "open_pull_requests.enrollment",
    "open_pull_requests.deleted_code",
)


def comment_after(lines, mark):
    """The comment at the end of the line of `mark`, after it, without its #. "" when the line has no comment there."""
    rest = lines[mark.line][mark.column:].lstrip(" :")
    return rest[1:].strip() if rest.startswith("#") else ""


def comment_above(lines, line):
    """The comment lines just above line `line` (counted from 0), joined with spaces, without their #."""
    above = []
    while line > 0 and lines[line - 1].lstrip().startswith("#"):
        line -= 1
        above.insert(0, lines[line].lstrip()[1:].strip())
    return " ".join(above)


def key_comments(lines, key, value):
    """The two comments of a key: the comment at the end of its line, and the comment lines just above it. A value
    that starts on the key's line and ends on a later line leaves no comment on the key's line."""
    line = key.start_mark.line
    if value.start_mark.line > line:
        # A mapping or a list in block style: the key's line holds the key alone.
        end = comment_after(lines, key.end_mark)
    elif value.end_mark.line == line:
        end = comment_after(lines, value.end_mark)
    else:
        end = ""
    return end, comment_above(lines, line)


def sentences(text):
    """Each string value of the text, list items too, as (its key's path, the value, the comments of its key)."""
    lines = text.splitlines()
    found = []

    def walk(node, path, comments):
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                walk(value, f"{path}.{key.value}" if path else key.value, key_comments(lines, key, value))
        elif isinstance(node, yaml.SequenceNode):
            for index, item in enumerate(node.value):
                walk(item, f"{path}[{index}]", comments)
        elif node.tag == "tag:yaml.org,2002:str":
            found.append((path, node.value, comments))

    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if root is not None:
        walk(root, "", ("", ""))
    return found


def kinds_given(comment):
    """Each part that `comment` gives a kind, with the text of each kind that it gives the part. The text of a kind
    runs from the colon after the part to the next part with a colon, or to the end of the comment."""
    given = {}
    groups = list(GIVEN.finditer(comment))
    for group, after in zip(groups, groups[1:] + [None]):
        kind = comment[group.end():after.start() if after else len(comment)].strip()
        for name in PART.findall(group.group()):
            given.setdefault(name, []).append(kind)
    return given


def is_kind(text):
    """Whether the text of a kind starts with a kind of KINDS, as whole words. More text can come after it."""
    return any(re.match(re.escape(kind) + r"(?![\w'])", text) for kind in KINDS)


def part_kinds(text):
    """Each {name} part of a sentence with no kind, or with a kind that is not in KINDS."""
    problems = []
    for path, sentence, comments in sentences(text):
        given = {}
        for comment in comments:
            for name, kinds in kinds_given(comment).items():
                given.setdefault(name, []).extend(kinds)
        for name in dict.fromkeys(PART.findall(sentence)):
            if name not in given:
                problems.append(f"{path}: the part {{{name}}} has no kind, in a comment at the end of the key's line "
                                "or just above the key")
            for kind in given.get(name, []):
                if not is_kind(kind):
                    leading = re.split(r"[,.]", kind)[0]
                    problems.append(f"{path}: the part {{{name}}} has the kind \"{leading}\", which is not in KINDS")
    return problems


def mapping(value):
    return value if isinstance(value, dict) else {}


def check_run_of(text):
    return mapping(mapping(yaml.safe_load(text)).get("check_run"))


def keys(value, path=""):
    """Each key under `value`, at any depth, list items too, as (its key's path, its value)."""
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            found.append((key_path, item))
            found.extend(keys(item, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(keys(item, f"{path}[{index}]"))
    return found


def long_buttons(text):
    """Each text of a button with more characters than LIMITS gives it."""
    check_run = check_run_of(text)
    problems = []
    for group, limit in LIMITS.items():
        for key, value in mapping(check_run.get(group)).items():
            if len(str(value)) > limit:
                problems.append(f"check_run.{group}.{key}: \"{value}\" has {len(str(value))} characters, more than "
                                f"{limit}")
    return problems


def missing_keys(text):
    """Each key of REQUIRED that the file does not hold."""
    data = yaml.safe_load(text)
    problems = []
    for path in REQUIRED:
        node = data
        for key in path.split("."):
            if not isinstance(node, dict) or key not in node:
                problems.append(f"{path}: the key is missing")
                break
            node = node[key]
    return problems


def dropped_keys(text):
    """Each key of DROPPED that the file holds, and each key under it."""
    data = mapping(yaml.safe_load(text))
    problems = []
    for key in DROPPED:
        if key in data:
            for path in [key, *(path for path, _ in keys(data[key], key))]:
                problems.append(f"{path}: version 11 of the file dropped {key} and each key under it")
    return problems


def check_run_states(text):
    """Each key conclusion of the file with a value outside ALLOWED, at any depth, and each state of CONCLUSIONS
    without its conclusion, its button or its title. A state of the check run is a key of check_run whose mapping has
    the key conclusion; CONCLUSIONS, BUTTONS and TITLES are for these states only. A key conclusion elsewhere, such as
    in a state of outside_proof_check_run, has the rule of ALLOWED alone. When the file does not hold a state of
    CONCLUSIONS, missing_keys names it."""
    check_run = check_run_of(text)
    states = [*CONCLUSIONS, *(key for key, value in check_run.items()
                               if "conclusion" in mapping(value) and key not in CONCLUSIONS)]
    allowed = f"{', '.join(ALLOWED[:-1])} or {ALLOWED[-1]}"
    problems = []
    for state in states:
        if state not in check_run:
            continue
        value = mapping(check_run[state])
        conclusion = value.get("conclusion")
        if conclusion not in ALLOWED:
            problems.append(f"check_run.{state}.conclusion: {conclusion}, but the conclusion of a state is {allowed}")
        elif state in CONCLUSIONS and conclusion != CONCLUSIONS[state]:
            problems.append(f"check_run.{state}.conclusion: {conclusion}, not {CONCLUSIONS[state]}")
        button = value.get("button")
        if button != BUTTONS.get(state):
            problems.append(f"check_run.{state}.button: {button or 'none'}, not {BUTTONS.get(state) or 'none'}")
        if state in TITLES and value.get("title") != TITLES[state]:
            problems.append(f"check_run.{state}.title: \"{value.get('title')}\", not \"{TITLES[state]}\"")
    # The loop above names each state of check_run whose conclusion is outside ALLOWED, so this loop skips them.
    named = {f"check_run.{key}.conclusion" for key in check_run}
    for path, conclusion in keys(yaml.safe_load(text)):
        if path.rpartition(".")[2] == "conclusion" and path not in named and conclusion not in ALLOWED:
            problems.append(f"{path}: {conclusion}, but the conclusion of a state is {allowed}")
    return problems


def statement_states(text):
    """Each key of check_run.statement_line.statement_states that is not in STATEMENT_STATES. When the file does not
    hold one of STATEMENT_STATES, missing_keys names it."""
    states = mapping(mapping(check_run_of(text).get("statement_line")).get("statement_states"))
    expected = f"{', '.join(STATEMENT_STATES[:-1])} and {STATEMENT_STATES[-1]}"
    return [f"check_run.statement_line.statement_states.{key}: a state of a statement other than {expected}"
            for key in states if key not in STATEMENT_STATES]


def does_not_hold(text):
    """Each sentence under check_run that says that something does not hold. The comments are not sentences. And
    outside_proof_check_run is not under check_run: its sentences are about proofs on theorem-labs/oss-verify-proofs,
    not about statements."""
    return [f"{path}: \"{sentence}\" says that a statement does not hold" for path, sentence, _ in sentences(text)
            if path.startswith("check_run.") and NOT_HOLD.search(sentence)]


def check_lines(text):
    """The summary of each state of CHECK_LINES that does not hold the part {check_lines}. When the file does not hold
    the state, missing_keys names it."""
    check_run = check_run_of(text)
    return [f"check_run.{state}.summary: the summary has no part {{check_lines}}" for state in CHECK_LINES
            if state in check_run and "{check_lines}" not in str(mapping(check_run[state]).get("summary", ""))]


CHECKS = (part_kinds, long_buttons, missing_keys, dropped_keys, check_run_states, statement_states, does_not_hold,
          check_lines)


def problems(text):
    """The problems of each check of CHECKS, in the order of CHECKS."""
    return [problem for check in CHECKS for problem in check(text)]


@pytest.mark.parametrize("check", CHECKS, ids=lambda check: check.__name__)
def test_the_file_passes_the_check(check):
    assert check(SENTENCES.read_text(encoding="utf-8")) == []


NEUTRAL = "neutral, but the conclusion of a state is success, failure or action_required"


# Each control: the changes (old, new) that it makes in a copy of the file, each old text in the file once, and the
# problems of the copy, in the order of CHECKS.
@pytest.mark.parametrize("changes, said", [
    pytest.param([('summary: "Nothing is needed from the author."',
                   'summary: "Nothing is needed from the author: {reason}."'),
                  ('    check: "Check"\n', '    check: "Check this commit now"\n')],
                 ["check_run.our_fault.summary: the part {reason} has no kind, in a comment at the end of the key's "
                  "line or just above the key",
                  "check_run.buttons.check: \"Check this commit now\" has 21 characters, more than 20"],
                 id="a part with no kind and a button of 21 characters"),
    pytest.param([('title: "All {count} statements hold."  # {count}: a number',
                   'title: "All {count} statements hold."  # {count}: a text, from the pull request')],
                 ["check_run.holds.title: the part {count} has the kind \"a text\", which is not in KINDS"],
                 id="a kind outside the list"),
    pytest.param([("  our_fault:\n    conclusion: failure\n", "  our_fault:\n    conclusion: neutral\n")],
                 [f"check_run.our_fault.conclusion: {NEUTRAL}"], id="a state with the conclusion neutral"),
    # R1 of OSSV-660: no key has the conclusion neutral, because GitHub counts a neutral required check as passed. The
    # check run of outside proof pull requests on theorem-labs/oss-verify-proofs has states too.
    pytest.param([("  fails:\n    conclusion: failure\n", "  fails:\n    conclusion: neutral\n")],
                 [f"outside_proof_check_run.fails.conclusion: {NEUTRAL}"],
                 id="a state of the outside proof check with the conclusion neutral"),
    pytest.param([('  publication: "Publish the proofs of {count} fuzz targets"  # {count}: a number\n', "")],
                 ["commit_messages.publication: the key is missing"], id="a required key deleted"),
    pytest.param([("\nopen_pull_requests:",
                   '\nenrollment_review:\n  check_run_name: "Enrollment review"\n\nopen_pull_requests:')],
                 ["enrollment_review: version 11 of the file dropped enrollment_review and each key under it",
                  "enrollment_review.check_run_name: version 11 of the file dropped enrollment_review and each key "
                  "under it"],
                 id="a key under enrollment_review added back"),
    pytest.param([('      not_met: "needs a proof"  # it has no proof yet\n',
                   '      not_met: "needs a proof"  # it has no proof yet\n      does_not_hold: "does not hold"\n')],
                 ["check_run.statement_line.statement_states.does_not_hold: a state of a statement other than holds, "
                  "needs_work and not_met",
                  "check_run.statement_line.statement_states.does_not_hold: \"does not hold\" says that a statement "
                  "does not hold"],
                 id="a statement state does_not_hold"),
    pytest.param([('summary: "This commit has no statements in `.theorem/statements/`."',
                   'summary: "This statement does not hold."')],
                 ["check_run.no_statements.summary: \"This statement does not hold.\" says that a statement does not "
                  "hold"],
                 id="a sentence of the check run that says a statement does not hold"),
])
def test_control(tmp_path, changes, said):
    text = SENTENCES.read_text(encoding="utf-8")
    for old, new in changes:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    copy = tmp_path / "sentences.yaml"
    copy.write_text(text, encoding="utf-8")
    assert problems(copy.read_text(encoding="utf-8")) == said
