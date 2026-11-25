# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of app/sentences.yaml:

    python3 -P -m pytest -q -p no:cacheprovider -c pyproject.toml tests/test_sentences.py

app/sentences.yaml holds each text that OSS Verify's two GitHub Apps write. The App Theorem Verify writes its check
runs and their buttons, its pull requests, its comments and its commit messages. The App OSS Verify writes its texts on
theorem-labs/oss-verify-proofs, such as the texts of a release. Each App takes each text from this file. A code owner
(.github/CODEOWNERS) approves each change to it. This test reads the file as data and changes no byte of it.

Each check below takes the text of the file and gives a list of problems. Each problem names its key. The file passes
when each list is empty:
  part_kinds        Each {name} part of a sentence has a kind, and the kind is one of KINDS. A comment gives the kind:
                    at the end of the key's line, or in the comment lines just above the key.
  long_buttons      A label of check_run.buttons has at most 20 characters, and a text of check_run.button_descriptions
                    at most 40. GitHub refuses a longer one.
  missing_keys      The file holds each key of REQUIRED.
  check_run_states  No key of the file has the conclusion neutral, because GitHub counts a neutral required check
                    as passed: each key conclusion, at any depth, is one of ALLOWED. Each state of CONCLUSIONS, under
                    check_run, has its conclusion, its button of BUTTONS and its title of TITLES.
  does_not_hold     No sentence of the check run says that a statement does not hold. A finding stays private until
                    the maintainer makes it public.
Each control (its name starts with test_control) changes a copy of the text, and shows that its check names the fault.
"""
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SENTENCES = ROOT / "app" / "sentences.yaml"

# The kinds of value that fill a {name} part. No part takes free text.
KINDS = ("a number", "a commit id", "a time", "a fuzz target's line", "a fuzz target's name", "a statement's name",
         "a repository's name", "a login", "a link to a public page", "a release's version",
         "a sentence of another key of this file")
# A {name} part of a sentence.
PART = re.compile(r"\{(\w+)\}")
# In a comment, the parts that the kind after the colon is for: "{count}:", or "{failed}, {count}:".
GIVEN = re.compile(r"\{\w+\}(?:(?:,\s*|,?\s+and\s+)\{\w+\})*:")

# The states of the check run, each with its conclusion, as the design of the setup route gives them.
CONCLUSIONS = {
    "check_needed": "action_required",
    "holds": "success", "no_statements": "success", "not_enrolled": "success", "setup_ready": "success",
    "proving": "failure", "waiting_for_maintainer": "failure", "did_not_build": "failure", "our_fault": "failure",
    "setup": "failure", "setup_missing_step": "failure", "merged_unchecked": "failure",
    "merge_group_unchecked": "failure",
}
# The conclusions that a state can have: each key conclusion of the file, at any depth, not only under check_run.
ALLOWED = ("success", "failure", "action_required")
# The states that show a button, with the key of check_run.buttons that each shows. Every other state shows none.
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
# A sentence that says that something does not hold.
NOT_HOLD = re.compile(r"\bnot\s+hold", re.IGNORECASE)

# The keys that the file must hold. They come from four sources: the keys that the `app` plug-in of theorem-cli posts,
# the states of the check run and their buttons (CONCLUSIONS), the two comments on the open enrollment pull requests
# (open_pull_requests), and the keys of the checks of the binaries (check_run.build_checks).
REQUIRED = (
    "check_run.name",
    "check_run.text",
    "check_run.target_line",
    "check_run.target_line.form",
    "check_run.target_line.build_states",
    "check_run.target_line.not_verified",
    "check_run.statement_line",
    "check_run.statement_line.form",
    "check_run.statement_line.statement_states.holds",
    "check_run.statement_line.statement_states.needs_work",
    "check_run.statement_line.statement_states.not_met",
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
    "enrollment_review.check_run_name",
    "enrollment_review.comment.hidden_first_line",
    "enrollment_review.comment.first_line",
    "enrollment_review.conclusion_sentences",
    "enrollment_review.conclusion_sentences.success",
    "enrollment_review.conclusion_sentences.failure",
    "enrollment_review.conclusion_sentences.action_required",
    "enrollment_review.comment.footer",
    "enrollment_checks_comment",
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


def conclusions(value, path=""):
    """Each key conclusion under `value`, at any depth, list items too, as (its key's path, its value)."""
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if key == "conclusion":
                found.append((key_path, item))
            found.extend(conclusions(item, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(conclusions(item, f"{path}[{index}]"))
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
    for path, conclusion in conclusions(yaml.safe_load(text)):
        if path not in named and conclusion not in ALLOWED:
            problems.append(f"{path}: {conclusion}, but the conclusion of a state is {allowed}")
    return problems


def does_not_hold(text):
    """The key does_not_hold of check_run.statement_line.statement_states, and each sentence under check_run that
    says that something does not hold. outside_proof_check_run is not under check_run: its sentences are about proofs
    on theorem-labs/oss-verify-proofs, not about statements."""
    states = mapping(mapping(check_run_of(text).get("statement_line")).get("statement_states"))
    problems = []
    if "does_not_hold" in states:
        problems.append("check_run.statement_line.statement_states.does_not_hold: a state for a statement that does "
                        "not hold")
    for path, sentence, _ in sentences(text):
        if path.startswith("check_run.") and NOT_HOLD.search(sentence):
            problems.append(f"{path}: \"{sentence}\" says that a statement does not hold")
    return problems


CHECKS = (part_kinds, long_buttons, missing_keys, check_run_states, does_not_hold)


def problems(text):
    """The problems of each check of CHECKS, in the order of CHECKS."""
    return [problem for check in CHECKS for problem in check(text)]


class Sentences(unittest.TestCase):
    """app/sentences.yaml passes each check."""

    def test_the_file_passes_each_check(self):
        text = SENTENCES.read_text(encoding="utf-8")
        for check in CHECKS:
            with self.subTest(check.__name__):
                self.assertEqual(check(text), [])


class Controls(unittest.TestCase):
    """Each control changes a copy of the text of app/sentences.yaml, and shows that its check names the fault."""

    def setUp(self):
        self.text = SENTENCES.read_text(encoding="utf-8")

    def changed(self, *changes):
        """The text with each (old, new) of `changes` made. Each old text is in the file once."""
        text = self.text
        for old, new in changes:
            self.assertEqual(text.count(old), 1, old)
            text = text.replace(old, new)
        return text

    def test_control_a_part_with_no_kind_and_a_button_of_21_characters(self):
        text = self.changed(('summary: "Nothing is needed from the author."',
                             'summary: "Nothing is needed from the author: {reason}."'),
                            ('    check: "Check"\n', '    check: "Check this commit now"\n'))
        self.assertEqual(problems(text), [
            "check_run.our_fault.summary: the part {reason} has no kind, in a comment at the end of the key's line or "
            "just above the key",
            "check_run.buttons.check: \"Check this commit now\" has 21 characters, more than 20"])

    def test_control_a_part_whose_kind_is_not_in_the_list(self):
        text = self.changed(('title: "All {count} statements hold."  # {count}: a number',
                             'title: "All {count} statements hold."  # {count}: a text, from the pull request'))
        self.assertEqual(problems(text), [
            "check_run.holds.title: the part {count} has the kind \"a text\", which is not in KINDS"])

    def test_control_a_state_with_the_conclusion_neutral(self):
        text = self.changed(("  our_fault:\n    conclusion: failure\n", "  our_fault:\n    conclusion: neutral\n"))
        self.assertEqual(problems(text), [
            "check_run.our_fault.conclusion: neutral, but the conclusion of a state is success, failure or "
            "action_required"])

    def test_control_a_state_of_the_outside_proof_check_with_the_conclusion_neutral(self):
        """R1: no key has the conclusion neutral, because GitHub counts a neutral required check as passed. The check
        run of outside proof pull requests on theorem-labs/oss-verify-proofs (outside_proof_check_run) has states
        too, and its state fails is a proof that does not hold."""
        text = self.changed(("  fails:\n    conclusion: failure\n", "  fails:\n    conclusion: neutral\n"))
        found = problems(text)
        self.assertTrue([problem for problem in found
                         if problem.startswith("outside_proof_check_run.fails.conclusion: neutral")], found)

    def test_control_a_required_key_deleted(self):
        line, = [line for line in self.text.splitlines(keepends=True) if line.startswith("  deleted_code: ")]
        text = self.changed((line, ""))
        self.assertEqual(problems(text), ["open_pull_requests.deleted_code: the key is missing"])

    def test_control_a_statement_state_that_does_not_hold(self):
        not_met = '      not_met: "needs a proof"  # it has no proof yet\n'
        text = self.changed((not_met, not_met + '      does_not_hold: "does not hold"\n'))
        self.assertEqual(problems(text), [
            "check_run.statement_line.statement_states.does_not_hold: a state for a statement that does not hold",
            "check_run.statement_line.statement_states.does_not_hold: \"does not hold\" says that a statement does "
            "not hold"])


if __name__ == "__main__":
    unittest.main()
