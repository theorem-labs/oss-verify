# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check_checks.py and .github/scripts/review-comment and review-run that need no Docker:
python3 -m pytest tools/tests"""
import base64
import html.parser
import itertools
import shlex
import json
import os
import importlib.machinery
import importlib.util
import pathlib
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import time
import zipfile

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_checks  # noqa: E402
import check_records  # noqa: E402
import validate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
REVIEW_COMMENT = ROOT / ".github" / "scripts" / "review-comment"
LOADER = importlib.machinery.SourceFileLoader("review_comment", str(REVIEW_COMMENT))
SPEC = importlib.util.spec_from_loader("review_comment", LOADER)
review_comment = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(review_comment)
# Records of what answered a review, as .github/scripts/review-served writes them: the provider asked for answered every
# turn; another provider answered.
SERVED_OK = ("asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\nusage firstParty/claude-opus-5-5\n"
             "firstParty/claude-opus-5-5 3\n")
ANSWERED_OK = "firstParty/claude-opus-5-5 (3 turns)"
SERVED_OTHER = ("asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\nusage bedrock/claude-opus-5-5\n"
                "bedrock/claude-opus-5-5 2\n")


def posted(review, head, served=SERVED_OK):
    """review-comment's comment of `review` at `head`, with the record `served` of what answered it."""
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "served"
        path.write_text(served)
        return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", "/dev/stdin", "--head", head,
                               "--served", str(path)], input=review, capture_output=True, text=True,
                              check=True).stdout

class Shifts(unittest.TestCase):
    def test_a_patch_moves_the_lines_after_its_hunks(self):
        patch = (b"diff --git a/fuzz/f.c b/fuzz/f.c\n--- a/fuzz/f.c\n+++ b/fuzz/f.c\n"
                 b"@@ -10,3 +10,2 @@\n a\n-b\n c\n@@ -40 +39,3 @@\n-x\n+y\n+z\n+w\n")
        shifts = check_checks.hunk_shifts(patch, "/src/p")
        self.assertEqual(shifts, {"/src/p/fuzz/f.c": [(11, -1), (40, -1), (41, 1), (41, 1), (41, 1)]})

        def check(line):
            return check_records.Check(line, None, path="/src/p/fuzz/f.c")
        self.assertEqual(check_checks.moved(check(5), shifts), 5)
        self.assertEqual(check_checks.moved(check(20), shifts), 19)
        self.assertEqual(check_checks.moved(check(50), shifts), 51)
        # A check in the trailing context of a hunk moves too.
        near = check_checks.hunk_shifts(b"+++ b/fuzz/f.c\n@@ -10,7 +10,6 @@\n a\n b\n-c\n d\n e\n f\n g\n", "/src/p")
        self.assertEqual(check_checks.moved(check(15), near), 14)

    def test_two_files(self):
        patch = (b"--- a/fuzz/f.c\n+++ b/fuzz/f.c\n@@ -10,1 +10,1 @@\n-x\n+y\n"
                 b"--- a/src/lib.c\n+++ b/src/lib.c\n@@ -5 +5,2 @@\n-p\n+q\n+r\n")
        shifts = check_checks.hunk_shifts(patch, "/src/p")
        self.assertEqual(shifts["/src/p/fuzz/f.c"], [(10, -1), (11, 1)])
        self.assertEqual(check_checks.moved(check_records.Check(40, None, path="/src/p/fuzz/f.c"), shifts), 40)

    def test_record_patches_apply_on_the_last_lines(self):
        import subprocess, tempfile
        for ending in (b"\n", b""):
            data = b"a\nb\nc\nd\ne" + ending
            for line in range(1, 6):
                with tempfile.TemporaryDirectory() as directory:
                    directory = pathlib.Path(directory)
                    (directory / "f.c").write_bytes(data)
                    record = check_records.Record("f.c", line, "abcde"[line - 1], "X", "s")
                    changed, _ = check_records.mutate(data, record)
                    import difflib
                    diff = b"".join(difflib.diff_bytes(difflib.unified_diff, check_checks.diff_lines(data),
                                                       check_checks.diff_lines(changed), b"a/f.c", b"b/f.c"))
                    (directory / "p").write_bytes(b"diff --git a/f.c b/f.c\n" + diff)
                    subprocess.run(["git", "apply", "p"], cwd=directory, check=True, capture_output=True)
                    self.assertEqual((directory / "f.c").read_bytes(), changed, (line, ending))

    def test_record_patches_split_on_newlines_only(self):
        data = "int x;\n/* \u00c5 */\nif (a) abort();\n".encode()
        record = check_records.Record("fuzz/f.c", 3, "(a)", "(!a)", "s")
        changed, _ = check_records.mutate(data, record)
        import difflib
        before = [line + b"\n" for line in data.split(b"\n")]
        after = [line + b"\n" for line in changed.split(b"\n")]
        diff = b"".join(difflib.diff_bytes(difflib.unified_diff, before, after, b"a/f", b"b/f"))
        self.assertIn("\u00c5".encode(), diff)
        self.assertEqual(diff.count(b"\n-"), 1)


class Positions(unittest.TestCase):
    def test_the_reader_gives_columns_for_coverage(self):
        source = "int f(int a) {\n\tif (a > 4 &&\n\t    a < 9)\n\t\tabort();\n\treturn 0;\n}\n"
        (found,) = check_records.find_checks(source, "/src/x/f.c")
        self.assertEqual((found.path, found.line, found.column, found.guard_at), ("/src/x/f.c", 4, 3, (2, 2)))
        self.assertEqual(found.text, "if (a > 4 &&")


class Coverage(unittest.TestCase):
    def test_counts_add_up_across_targets(self):
        coverage = check_checks.Coverage()
        export = {"data": [{"files": [{"filename": "/src/f.c", "segments": [
            [1, 1, 5, True, True, False], [2, 3, 0, True, True, False], [2, 10, 5, True, False, False],
            [4, 1, 0, False, False, False]]}]}]}
        coverage.add(export)
        coverage.add(export)
        self.assertEqual(coverage.count("/src/f.c", 1, 7), 10)
        self.assertEqual(coverage.count("/src/f.c", 2, 3), 0)
        self.assertEqual(coverage.count("/src/f.c", 2, 12), 10)
        self.assertIsNone(coverage.count("/src/f.c", 5, 1))
        self.assertIsNone(coverage.count("/src/other.c", 1, 1))

    def test_fuzz_target_files(self):
        export = {"data": [{"functions": [{"name": "LLVMFuzzerTestOneInput", "filenames": ["/src/a/f.c", "/x.h"]},
                                          {"name": "helper", "filenames": ["/src/lib.c"]}]}]}
        self.assertEqual(check_checks.fuzz_target_files(export), {"/src/a/f.c"})


class Report(unittest.TestCase):
    def test_code_cannot_be_ended_by_its_text(self):
        self.assertEqual(check_checks.code("a`b"), "``a`b``")
        self.assertEqual(check_checks.code("x\x1b[31m"), "`x [31m`")
        self.assertEqual(check_checks.cell("a|b"), "`a\\|b`")
        self.assertTrue(check_checks.code("y" * 500, 10).endswith("…`"))

    def test_runs(self):
        self.assertTrue(check_checks.Run("t", "s", 2, "coverage").passed())
        self.assertTrue(check_checks.Run("t", "s", 134, "coverage").caught())
        # A run stopped at the time limit neither passes nor catches a breakage.
        self.assertFalse(check_checks.Run("t", "s", None, "coverage").passed())
        self.assertFalse(check_checks.Run("t", "s", None, "coverage").caught())
        self.assertIn("abort()", check_checks.describe(check_checks.Run("t", "s", 134, "asan")))

    def test_seeds_get_the_driver_header(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            with zipfile.ZipFile(directory / "demo_seed_corpus.zip", "w") as archive:
                archive.writestr("one", b"\x01")
                archive.writestr("two", b"\x02\x03")
            names = check_checks.write_seeds(directory, ["demo", "none"], directory / "inputs")
            self.assertEqual(names, {"demo": ["one", "two"]})
            self.assertEqual((directory / "inputs" / "demo" / "1").read_bytes(), b"\0" * 6 + b"\x02\x03")


class Mutants(unittest.TestCase):
    def test_validate(self):
        base = "repo: https://github.com/a/b\nprimary_contact: a@b.cd\nlanguage: c\n"
        for good in ("fuzz/sabotage", "mutants"):
            self.assertEqual(list(validate.check_types(validate.yaml.safe_load(base + f"mutants: {good}\n"))), [])
        for bad in ("../x", "/abs", "[a]"):
            problems = list(validate.check_types(validate.yaml.safe_load(base + f"mutants: {bad}\n")))
            self.assertTrue(problems, bad)


class ReviewComment(unittest.TestCase):
    def comment(self, review, checks="### report\n", *extra, served=SERVED_OK):
        """The comment; served: the record of what answered the review, or None for no --served."""
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            record = []
            if served is not None:
                (directory / "served").write_text(served)
                record = ["--served", str(directory / "served")]
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md"), *record, *extra],
                                  capture_output=True, text=True, check=True).stdout

    def kept(self, previous, head, run="https://github.com/theorem-labs/oss-verify/actions/runs/7", served=SERVED_OK):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "previous.md").write_text(previous)
            return self.comment("", "### new report\n", "--head", head, "--run", run,
                                "--previous", str(pathlib.Path(directory) / "previous.md"), served=served)

    def meta(self, text):
        return review_comment.META.match(text.split("\n")[1])

    def test_the_marker_comes_first(self):
        # A marker in the review is posted as written, last: build.yaml finds the comment by its first line only.
        text = self.comment("Thanks.\n<!-- oss-verify-review -->\n")
        self.assertTrue(text.startswith(review_comment.MARKER + "\n"))
        self.assertEqual(self.meta(text).group("status"), "review")
        self.assertTrue(text.endswith("\n\nThanks.\n<!-- oss-verify-review -->\n"))
        self.assertIn("<details>", text)
        self.assertIn("### report", text)

    def test_no_review(self):
        text = self.comment("")
        self.assertIn("did not run on this push: it wrote no comment", text)
        self.assertEqual(self.meta(text).group("status"), "none")

    def test_a_review_names_what_answered_it_after_the_footer(self):
        text = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        blocks = text.split("\n\n")
        self.assertTrue(blocks[2].startswith("<sub>Claude wrote this review"))
        self.assertEqual(blocks[3], f"<sub>Answered by `{ANSWERED_OK}`, as Claude Code reported it.</sub>")
        self.assertEqual(self.meta(text).group("status"), "review")

    def test_a_review_another_provider_answered_is_not_published(self):
        for served in (SERVED_OTHER, SERVED_OK.replace("endpoint api.anthropic.com", "endpoint https:proxy.example"),
                       SERVED_OK.replace("firstParty/claude-opus-5-5 3", "firstParty/gpt-5.6-terra 3"),
                       SERVED_OK.replace("firstParty/claude-opus-5-5 3",
                                         "firstParty/claude-opus-5-5 2\nfirstParty/claude-haiku-4-5-20251001 1")):
            with self.subTest(served=served):
                text = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40, served=served)
                self.assertNotIn("1. Fix X.", text)
                self.assertEqual(self.meta(text).group("status"), "none")
                self.assertIn(f"The review of this push (`{'a' * 7}`) is not published. What answered it, as Claude "
                              "Code reported it: `it asked for anthropic/claude-opus-5-5, ", text)

    def test_another_provider_without_review_text_says_the_review_is_not_published(self):
        # In CI a review that another provider or model answered reaches this script as no text at all.
        text = self.comment("", "### report\n", "--head", "a" * 40, served=SERVED_OTHER)
        self.assertIn(f"The review of this push (`{'a' * 7}`) is not published. What answered it, as Claude Code "
                      "reported it: `it asked for anthropic/claude-opus-5-5, which the tool calls "
                      "firstParty/claude-opus-5-5, but bedrock/claude-opus-5-5 (2 turns) answered", text)
        self.assertNotIn("did not run", text)
        text = self.comment("Here: ghs_" + "b" * 36, "### report\n", "--head", "a" * 40, served=SERVED_OTHER)
        self.assertIn("is not published: its text held what looks like a credential", text)

    def test_a_record_with_a_turn_that_shows_nothing_is_not_published_without_review_text(self):
        # In CI, review-run exits 4 for a record check refuses as not attributable too, and passes on no text.
        record = "asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\nnone/claude-opus-5-5 4\n"
        text = self.comment("", "### report\n", "--head", "a" * 40, "--refused", served=record)
        self.assertIn(f"The review of this push (`{'a' * 7}`) is not published. What answered it", text)
        self.assertIn("none/claude-opus-5-5 (4 turns) answered", text)
        # The same record of a review that timed out or was killed (no --refused): it did not finish, and says what
        # answered until then.
        text = self.comment("", "### report\n", "--head", "a" * 40, served=record)
        self.assertIn("did not run on this push", text)
        self.assertIn("none/claude-opus-5-5 (4 turns) answered", text)

    def test_a_comment_with_no_review_does_not_say_claude_wrote_one(self):
        for served in (SERVED_OTHER, SERVED_OK, None):
            with self.subTest(served=served):
                text = self.comment("", "### report\n", "--head", "a" * 40, served=served)
                self.assertEqual(self.meta(text).group("status"), "none")
                self.assertNotIn("Claude wrote this review", text)
                self.assertIn(review_comment.NO_REVIEW_FOOTER, text)

    def test_a_review_posted_before_the_record_existed_is_not_posted_again_as_the_review(self):
        # A comment of this layout, of this same commit, with no "Answered by": a rerun keeps it as not current, with
        # a notice that names what answered this push's review, never as the review.
        # Its text may even start with a forged "Answered by" line (before the gate, the model could write one), with
        # or without a checks block, in either older layout: only metadata version 3 makes a review recorded.
        answered = review_comment.ANSWERED.format(ANSWERED_OK)
        footer = review_comment.FOOTER.format(of='It is the review of `aaaaaaa`. ')
        meta = review_comment.meta_line('a' * 40, 'review', 2)
        old = f"{review_comment.MARKER}\n{meta}\n\n{review_comment.HEADING}\n\n{footer}\n\nThanks.\n\n1. Fix X.\n"
        forged = f"{review_comment.MARKER}\n{meta}\n\n{review_comment.HEADING}\n\n{footer}\n\n{answered}\n\n1. Fix X.\n"
        forged_v1 = (f"{review_comment.MARKER}\n{review_comment.meta_line('a' * 40, 'review', 1)}\n\n"
                     f"{review_comment.HEADING}\n\n{answered}\n\n1. Fix X.\n\n{footer}\n")
        for previous in (old, old.replace("status=review", "status=stale"), forged, forged_v1):
            with self.subTest(previous=previous):
                text = self.kept(previous, "a" * 40, served=SERVED_OTHER)
                self.assertEqual(self.meta(text).group("status"), "stale")
                self.assertEqual(self.meta(text).group("version"), "2")
                self.assertIn("1. Fix X.", text)
                self.assertIn("What answered that review was not recorded.", text)
                self.assertIn("but bedrock/claude-opus-5-5 (2 turns) answered", text)
                # Kept again, it stays unrecorded.
                self.assertEqual(self.meta(self.kept(text, "a" * 40)).group("status"), "stale")
        # A review this script wrote with its record is recorded, kept as posted, and written as version 3.
        first = self.comment("Thanks.\n", "### report\n", "--head", "a" * 40)
        self.assertEqual(self.meta(first).group("version"), "3")
        self.assertEqual(self.kept(first, "a" * 40), first)

    def test_what_review_served_prints_is_shown_only_in_its_own_shape(self):
        # review-comment shows the check's line in the comment: a line of another shape, one that holds what looks
        # like a credential, or an exit status check never gives, is not shown and is not attributable.
        with tempfile.TemporaryDirectory() as directory:
            stand_in = pathlib.Path(directory) / "review-served"
            real = review_comment.SERVED
            self.addCleanup(setattr, review_comment, "SERVED", real)
            review_comment.SERVED = stand_in
            for line, status in (("firstParty/claude-opus-5-5 (3 turns)", 0), ("a `backtick`", 0),
                                 ("ghs_" + "a" * 36, 0), ("firstParty/claude-opus-5-5 (3 turns)", 2)):
                with self.subTest(line=line, status=status):
                    stand_in.write_text(f"import sys\nprint({line!r})\nsys.exit({status})\n")
                    code, shown = review_comment.served("asked x\n")
                    if (line, status) == ("firstParty/claude-opus-5-5 (3 turns)", 0):
                        self.assertEqual((code, shown), (0, line))
                    else:
                        self.assertEqual(code, 3)
                        self.assertIn("could not check the record", shown)

    def test_a_review_with_no_record_or_one_that_shows_nothing_is_not_published(self):
        for served, why in ((None, "nothing recorded which provider answered the review: it is not attributable"),
                            ("", "nothing recorded which provider answered the review: it is not attributable"),
                            ("asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\n",
                             "no turn named the provider and model that answered it"),
                            ("asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\nnone/claude-opus-5-5 2\n",
                             "none/claude-opus-5-5 (2 turns) answered, where none is"),
                            ("asked anthropic/claude-opus-5-5\nfirstParty/claude-opus-5-5 \u00b2\n",
                             "a line of the record of what answered the review is not one")):
            with self.subTest(served=served):
                text = self.comment("Thanks.\n\n1. Fix X.\n", served=served)
                self.assertNotIn("1. Fix X.", text)
                self.assertIn("is not published. What answered it, as Claude Code reported it: `", text)
                self.assertIn(why, text)

    def test_no_review_names_what_answered_or_that_nothing_did(self):
        text = self.comment("", "### report\n", "--head", "a" * 40)
        self.assertIn(f"did not run on this push (`{'a' * 7}`): it wrote no comment. What answered it, as Claude Code "
                      f"reported it: `{ANSWERED_OK}`.", text)
        text = self.comment("", served=None)
        self.assertIn("What answered it, as Claude Code reported it: `nothing recorded which provider answered the "
                      "review: it is not attributable`.", text)

    def test_a_kept_review_says_what_answered_the_push_that_had_none(self):
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        second = self.kept(first, "b" * 40, served=SERVED_OTHER)
        notice = second.split("\n\n")[2]
        self.assertTrue(notice.startswith("**Not current:**"))
        self.assertIn("What answered it, as Claude Code reported it: `it asked for anthropic/claude-opus-5-5, which "
                      "the tool calls firstParty/claude-opus-5-5, but bedrock/claude-opus-5-5 (2 turns) answered",
                      notice)
        self.assertTrue(notice.endswith("A person at Theorem reviews the enrollment."))
        # The kept review keeps what answered it; a second keep writes the notice afresh, and nothing stacks.
        self.assertIn(f"<sub>Answered by `{ANSWERED_OK}`, as Claude Code reported it.</sub>", second)
        third = self.kept(second, "c" * 40)
        self.assertEqual(third.count("What answered it"), 1)
        self.assertEqual(third.count("<sub>Answered by"), 1)
        self.assertIn(f"What answered it, as Claude Code reported it: `{ANSWERED_OK}`.", third)

    def test_a_review_with_details_is_posted_whole(self):
        text = self.comment("Thanks.\n\n<details><summary>x</summary>y</details>\n\n1. Fix X.\n\n2. Fix Y.\n")
        self.assertIn("1. Fix X.", text)
        self.assertIn("2. Fix Y.", text)
        self.assertEqual(text.count("<sub>Claude wrote this review"), 1)

    def test_a_credential_is_never_posted(self):
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOngifQ.c2lnbmF0dXJl"
        for leak in (token, "sk-ant-oat01-abcdefghijkl", "ghs_" + "a" * 36):
            text = self.comment(f"Here: {leak}")
            self.assertNotIn(leak, text)
            self.assertIn("looks like a credential", text)

    def test_the_commit_is_in_the_metadata_and_the_footer(self):
        text = self.comment("Thanks.\n", "### report\n", "--head", "abc1234" + "0" * 33)
        self.assertEqual(self.meta(text).group("head"), "abc1234" + "0" * 33)
        self.assertIn("It is the review of `abc1234`.", text)

    def test_a_review_that_did_not_finish_keeps_the_last_one_as_not_current(self):
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        second = self.kept(first, "b" * 40)
        self.assertTrue(second.startswith(review_comment.MARKER + "\n"))
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertEqual(self.meta(second).group("head"), "a" * 40)
        self.assertIn(f"**Not current:** this is the review of `{'a' * 7}`. The review of `{'b' * 7}` did not finish",
                      second)
        self.assertIn("actions/runs/7", second)
        self.assertIn("1. Fix X.", second)
        self.assertIn("### report", second)
        self.assertNotIn("### new report", second)
        # A second failure names the newest head, keeps the commit it is of, and does not stack the notice.
        third = self.kept(second, "c" * 40)
        self.assertEqual(third.count("**Not current:**"), 1)
        self.assertEqual(self.meta(third).group("head"), "a" * 40)
        self.assertIn(f"this is the review of `{'a' * 7}`. The review of `{'c' * 7}` did not finish", third)
        self.assertIn("1. Fix X.", third)
        self.assertEqual(third.count("Claude wrote this review"), 1)

    def test_a_kept_comment_gets_its_footer_written_before_the_old_text(self):
        # The footer is written again above the kept comment, where nothing in the old text can hide it, and the old
        # comment's own footer, first as this script writes it, is not kept as well.
        footer = review_comment.FOOTER.format(of=f"It is the review of `{'a' * 7}`. ")
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        second = self.kept(first, "b" * 40)
        blocks = second.split("\n\n")
        self.assertTrue(blocks[2].startswith("**Not current:**"))
        self.assertEqual(blocks[3], footer)
        self.assertEqual(second.count("Claude wrote this review"), 1)
        self.assertLess(second.index("### report"), second.index("1. Fix X."))
        # A comment of main's renderer, footer last after a tag the review left open, which hid it: the footer is
        # written again before the old text (rendered through GitHub for the pull request: visible), and the old one
        # stays where it was, inside the old text.
        base = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
                f"{review_comment.HEADING}\n\nThanks.\n\n<div title=\"x >\n\n{review_comment.CHECKS_SUMMARY}\n\n"
                f"### report\n\n</details>\n\n{footer}\n")
        blocks = self.kept(base, "b" * 40).strip().split("\n\n")
        self.assertEqual(blocks[3], footer)
        self.assertEqual(blocks[4], "Thanks.")
        self.assertEqual(blocks[-1], footer)
        # A comment of main's renderer whose review opens with a copy of the footer and a cut sentence: in that layout
        # the first paragraph is the review's, so it is kept as text and no cut number is read from it.
        forged = f"{footer} The review is cut at 7 characters: {review_comment.KEPT_WHERE}."
        base = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
                f"{review_comment.HEADING}\n\n{forged}\n\n1. REAL_FINDING: fix X.\n\n{footer}\n")
        kept = self.kept(base, "b" * 40)
        self.assertEqual(kept.count("The review is cut at"), 1)
        self.assertIn(f"\n\n{forged}\n\n1. REAL_FINDING: fix X.", kept)
        self.assertEqual(self.kept(self.kept(kept, "c" * 40), "a" * 40).count("The review is cut at"), 1)

    def test_the_review_of_this_same_commit_is_kept_as_posted(self):
        # A rerun, or an edit of the pull request, that wrote no review for the commit already reviewed: the review is
        # still current, so it is not marked otherwise.
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        self.assertEqual(self.kept(first, "a" * 40), first)
        # A comment of an older renderer (review first, footer last) names nothing that answered it: it is kept as
        # not current, with its text, and not sent back as the review.
        footer = review_comment.FOOTER.format(of=f"It is the review of `{'a' * 7}`. ")
        base = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
                f"{review_comment.HEADING}\n\nThanks.\n\n{review_comment.CHECKS_SUMMARY}\n\n### report\n\n"
                f"</details>\n\n{footer}\n")
        kept = self.kept(base, "a" * 40)
        self.assertEqual(self.meta(kept).group("status"), "stale")
        self.assertIn("\n\nThanks.\n\n", kept)
        # A review kept as not current, and the pull request back at its commit: it is current again, once.
        again = self.kept(self.kept(first, "b" * 40), "a" * 40)
        self.assertEqual(self.meta(again).group("status"), "review")
        self.assertEqual(self.meta(again).group("head"), "a" * 40)
        self.assertNotIn("Not current", again)
        self.assertEqual(again.count("Claude wrote this review"), 1)
        self.assertTrue(again.endswith("\n\n1. Fix X.\n"))
        self.assertEqual(self.kept(again, "a" * 40), again)

    def test_a_review_that_reads_like_the_scripts_notes_stays_the_review(self):
        # Where an earlier keep cut the comment is read from the notice, which this script alone writes, never from
        # the old text, and only one footer is taken off, the one in the place this script writes it: a review that
        # opens with the cut sentence (with a number too long to read, too) or with the footer is kept whole however
        # often it is kept, a keep for the same push gives the same comment, and keeping it never fails.
        footer = review_comment.FOOTER.format(of=f"It is the review of `{'a' * 7}`. ")
        for opening in (f"The review is cut at 7 characters: {review_comment.KEPT_WHERE}.",
                        f"The review is cut at 1{',111' * 1_500} characters: {review_comment.KEPT_WHERE}.",
                        f" The review is cut at 9 characters: {review_comment.KEPT_WHERE}.", footer,
                        f"{footer}\n\n{footer}"):
            review = f"{opening}\n\n1. Fix X."
            for checks in ("### report\n", ""):
                text = self.comment(review, checks, "--head", "a" * 40)
                last = None
                for head in ("b" * 40, "c" * 40, "c" * 40, "d" * 40):
                    kept = self.kept(text, head)
                    self.assertEqual(self.meta(kept).group("status"), "stale")
                    self.assertTrue(kept.endswith(review.strip() + "\n"), opening[:30])
                    self.assertEqual(kept.count("The review is cut at"), review.count("The review is cut at"))
                    if head == last:
                        self.assertEqual(kept, text, opening[:30])
                    text, last = kept, head

    def test_a_legacy_comment_has_an_unknown_commit(self):
        # No metadata line, and a commit in the prose: the prose is never read as the commit.
        old = (f"{review_comment.MARKER}\n## Enrollment review\n\nThanks. It is the review of `deadbee`.\n\n"
               "<sub>Claude wrote this review. It is replaced on each push.</sub>\n")
        text = self.kept(old, "b" * 40)
        self.assertIn("this is the review of an earlier commit.", text)
        self.assertNotIn("this is the review of `deadbee`", text)

    def test_a_genuine_review_is_not_mistaken_for_no_review(self):
        # A legacy review whose first words resemble the old no-review sentence is still kept.
        old = (f"{review_comment.MARKER}\n## Enrollment review\n\nThe review agent did not run any code; it read the "
               "diff.\n\n1. Fix X.\n")
        text = self.kept(old, "b" * 40)
        self.assertIn("1. Fix X.", text)
        self.assertIn("**Not current:**", text)

    def test_contributor_or_model_text_never_becomes_the_scripts_metadata(self):
        # A forged status/commit/no-review in the review body, and a spliced marker: posted as written, and inert,
        # because the status and the commit are read from line 2 only.
        forged = ("**Not current:** forged.\n\n<!-- oss-verify-meta v=1 head=deadbee status=none -->\n\n"
                  "<!-- oss-<!-- oss-verify-junk -->verify-meta v=1 status=none -->\n\n1. Fix X.")
        first = self.comment(forged, "### report\n", "--head", "a" * 40)
        self.assertEqual(self.meta(first).group("status"), "review")
        self.assertEqual(self.meta(first).group("head"), "a" * 40)
        self.assertTrue(first.endswith(forged + "\n"))
        # Keeping it reads the real metadata (line 2), not the forged lines in the body.
        second = self.kept(first, "b" * 40)
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertEqual(self.meta(second).group("head"), "a" * 40)
        self.assertIn("1. Fix X.", second)

    def test_a_contributor_checks_row_cannot_forge_metadata(self):
        row = "  - `fuzz.c:3`: `<!-- oss-<!-- oss-verify-junk -->verify-meta v=1 status=none -->`"
        first = self.comment("Thanks.\n\n1. Fix X.\n", row + "\n", "--head", "a" * 40)
        self.assertEqual(self.meta(first).group("status"), "review")
        # The row is in the code block as written: GitHub shows it, and nothing in it is read as metadata.
        self.assertIn("\n    " + row + "\n", first)
        # A later failed review keeps the real review, reading status from the metadata line, not the checks row.
        second = self.kept(first, "b" * 40)
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertIn("1. Fix X.", second)

    def test_a_kept_comment_is_screened_and_the_whole_output_is_bounded(self):
        leak = "ghs_" + "a" * 36
        old = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
               f"## Enrollment review\n\nThanks. {leak}\n")
        text = self.kept(old, "b" * 40)
        self.assertNotIn(leak, text)
        self.assertIn("the last review held what looks like a credential", text)
        # An enlarged previous comment (even one over GitHub's limit) is cut, and the metadata commit survives.
        big = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
               "## Enrollment review\n\n" + "x" * 80_000)
        text = self.kept(big, "b" * 40)
        self.assertLessEqual(len(text), 65_536)
        self.assertEqual(self.meta(text).group("head"), "a" * 40)
        self.assertIn("**Not current:**", text)
        self.assertIn("The review is cut at", text)

    def test_a_comment_without_a_review_is_replaced(self):
        none = self.comment("", "### report\n", "--head", "a" * 40)
        text = self.kept(none, "b" * 40)
        self.assertNotIn("Not current", text)
        self.assertIn(f"did not run on this push (`{'b' * 7}`)", text)
        self.assertIn("### new report", text)

    def unusable(self, review, previous, head):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "previous.md").write_text(previous)
            return self.comment(review, "### new report\n", "--head", head,
                                "--previous", str(pathlib.Path(directory) / "previous.md"))

    def test_an_unusable_review_keeps_the_last_one(self):
        # Blank, credential-shaped or marker-only: the review job "succeeded", but there is nothing to post.
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        for review in (" \n\t\n", "Here: ghs_" + "b" * 36, "<!-- oss-verify-review -->\n"):
            text = self.unusable(review, first, "b" * 40)
            self.assertEqual(self.meta(text).group("status"), "stale", review)
            self.assertIn("1. Fix X.", text)
            self.assertNotIn("ghs_" + "b" * 36, text)

    def test_a_credential_in_the_checks_is_refused_and_the_review_kept(self):
        # A contributor's source line, rendered into a checks row by tools/check_checks.py.
        leak = "ghs_" + "A" * 36
        first = self.comment("Thanks.\n\n1. Fix X.\n", f"  - `fuzz.c:3`: `{leak}`\n", "--head", "a" * 40)
        self.assertNotIn(leak, first)
        self.assertEqual(self.meta(first).group("status"), "review")
        self.assertIn("1. Fix X.", first)
        self.assertIn("The report held what looks like a credential", first)
        # So a later failed review still keeps it.
        second = self.kept(first, "b" * 40)
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertIn("1. Fix X.", second)

    def test_only_the_whole_legacy_no_review_sentence_means_no_review(self):
        legacy = f"{review_comment.MARKER}\n## Enrollment review\n\n"
        similar = self.kept(legacy + "The review agent did not run on this push's test machine; it read the diff.\n\n"
                            "1. Fix X.\n", "b" * 40)
        self.assertIn("1. Fix X.", similar)
        self.assertEqual(self.meta(similar).group("status"), "stale")
        for why in ("it wrote no comment", "the review job ended with the result failure"):
            none = self.kept(legacy + f"The review agent did not run on this push: {why}. A person at Theorem reviews "
                             "the enrollment.\n\n<sub>Claude wrote this review.</sub>\n", "b" * 40)
            self.assertEqual(self.meta(none).group("status"), "none", why)

    def test_neutralize_is_linear_and_a_fixed_point(self):
        # It removes only a comment that is complete and names this script; it never rewrites anything else.
        hostile = "<!--oss-verify" * 5_000  # 70,000 characters, no -->
        # Many closed comments, and the other ending only at the very end: a scan that looked for each ending afresh
        # at each comment would read the rest of the text each time.
        closed = "<!-- x -->" * 60_000
        for text in (hostile, closed + "--!>", "<!-- x --!>" * 60_000 + "-->"):
            started = time.monotonic()
            self.assertEqual(review_comment.neutralize(text), text)
            self.assertLess(time.monotonic() - started, 1.0, text[:20])
        for sample in (hostile, "<!-- oss-<!-- oss-verify-junk -->verify-meta v=1 status=none -->",
                       "a <!-- keep --> b <!-- oss-verify-x --> c <!-- tail", "<!-<!--oss-verify-->- oss-verify-x -->",
                       "<!--> <!-- oss-verify --!> x", "<!-- a --!> <!-- oss-verify-meta --> b"):
            once = review_comment.neutralize(sample)
            self.assertEqual(review_comment.neutralize(once), once, sample)
            self.assertFalse(self.holds_a_complete_marker(once), sample)

    def holds_a_complete_marker(self, text):
        """Whether a complete HTML comment naming this script is left: from each <!-- to where HTML ends it (<!-->,
        <!--->, or the first --> or --!>). A forward scan, not a regular expression: the obvious one backtracks for
        minutes on 70,000 characters that hold no -->."""
        at = 0
        while (start := text.find("<!--", at)) != -1:
            if text.startswith(">", start + 4):
                end = start + 5
            elif text.startswith("->", start + 4):
                end = start + 6
            else:
                ends = [found + len(close) for close in ("-->", "--!>")
                        if (found := text.find(close, start + 4)) != -1]
                if not ends:
                    return False
                end = min(ends)
            if "oss-verify" in text[start:end].lower():
                return True
            at = end
        return False


class WorkflowArguments(unittest.TestCase):
    """What build.yaml, triage.yaml and enroll-dispatch.yml do with the credentials they hold, as far as their text
    shows it: each named credential reaches a command through a pipe or a shell builtin and never as a process's
    argument, and only the jobs that run no code of the pull request can ask for a GitHub identity token. This reads
    the files; it does not run them, so it proves nothing about what a called script does with what it is given."""

    # The jobs of each workflow that read the App's key, in the GitHub Environment `comment`: build.yaml's hold job
    # sends held findings with the App's token.
    KEY_JOBS = {"build.yaml": ("comment", "hold"), "triage.yaml": ("comment",), "enroll-dispatch.yml": ("dispatch",)}

    def workflow(self, name):
        return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())

    def steps(self, workflow):
        return [step for job in self.workflow(workflow)["jobs"].values() for step in job["steps"] if "run" in step]

    def argument_problems(self, run, name):
        """Where `run` gives $name to a process as an argument, as far as this test can read: [] if nowhere.

        It removes the forms in which only the shell itself reads the value, each in the exact place it is safe, and
        refuses any use of the name that is left. Anything new must be added here on purpose."""
        variable = re.escape(f'"${name}"')
        blank = re.escape(f'"${{{name}//[[:space:]]/}}"')
        # Where a test or a printf statement starts a command: the builtin is read only there, never after a path
        # (/usr/bin/[) or a wrapper (env [), which would be a process with the value in its arguments.
        start = r"(?m)(^\s*|\bif\s+|\belif\s+|&&\s*|\|\|\s*|;\s*|\{\s*|\bthen\s+|\bdo\s+|!\s+)"
        rest = run
        for form in (
                # printf into a process substitution: curl reads a pipe, never the value.
                rf"<\((?:builtin )?printf '[^']*' {variable}\)",
                # The decoded key, assigned to a shell variable: the value goes through a pipe into base64.
                rf"(?m)^\s*\w+=\$\(builtin printf '[^']*' {variable} \| base64 -d\)\s*$",
                # A here-string into a `while read` loop, and a [[ ]] pattern, both the shell's own.
                rf"<<< {variable}", rf"== \*{variable}\*"):
            rest = re.sub(form, "", rest)
        for form in (rf"\[ -[zn] {variable} \]", rf"\[ -z {blank} \]",
                     rf"builtin printf '[^']*' {variable}(?=\s*(?:$|;|>>?|\||&&|\}}))"):
            rest = re.sub(start + form, r"\1", rest)
        problems = []
        if f"${name}" in rest:
            problems.append(f"${name} is an argument")
        # ${NAME…} in any other spelling is refused outright rather than matched: a step that starts using it must be
        # read again.
        if "${" + name in rest:
            problems.append("${" + name + "…} is not one of the forms this test reads")
        return problems

    def test_no_credential_is_an_argument(self):
        # The App's key and the base64 it is decoded from are shell variables of their step, so they are named here
        # by those names, beside the environment variables.
        for workflow, names in (("build.yaml", ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OTEL_COLLECTOR_TOKEN",
                                                "GCP_ACCESS_TOKEN", "key", "payload")),
                                ("triage.yaml", ("GCP_ACCESS_TOKEN", "key", "payload")),
                                ("enroll-dispatch.yml", ("GCP_ACCESS_TOKEN", "key", "payload"))):
            steps = self.steps(workflow)
            for name in names:
                used = 0
                for step in steps:
                    used += step["run"].count(f"${name}")
                    self.assertEqual(self.argument_problems(step["run"], name), [], f"{workflow} {step.get('name')}")
                self.assertGreater(used, 0, f"{workflow} {name}")

    def test_the_argument_forms_are_refused(self):
        for run in ('curl -H "$(builtin printf \'Authorization: Bearer %s\\n\' "$X")" https://x',
                    'curl -H "Authorization: Bearer ${X:-}" https://x', 'echo "$X"',
                    'curl -H "$(printf \'%s\' "$X")" https://x', 'f "$(builtin printf \'%s\' "$X")"',
                    'curl -H "$(builtin printf \'%s\' "$X" | cat)" https://x',
                    'curl -H "$(builtin printf \'%s\' "$X" | base64 -d)" https://x',
                    'if /usr/bin/[ -z "$X" ]; then :; fi', 'env [ -n "$X" ]',
                    'if /usr/bin/[ -z "${X//[[:space:]]/}" ]; then :; fi', 'echo *"$X"*',
                    'env builtin printf \'%s\' "$X"', 'k=$(builtin printf \'%s\' "$X" | base64 -d) other'):
            self.assertTrue(self.argument_problems(run, "X"), run)
        for run in ('curl -H @<(builtin printf \'Authorization: Bearer %s\\n\' "$X") https://x',
                    'builtin printf \'::add-mask::%s\\n\' "$X"', 'k=$(builtin printf \'%s\' "$X" | base64 -d)',
                    '{ echo a; builtin printf \'%s\\n\' "$X"; echo b; } >> out', 'if [ -n "$X" ]; then :; fi',
                    'done <<< "$X"', 'if [ -z "${X//[[:space:]]/}" ]; then', '[[ $s == *"$X"* ]]'):
            self.assertEqual(self.argument_problems(run, "X"), [], run)

    def test_only_the_jobs_that_run_no_pull_request_code_hold_an_identity_token(self):
        # A GitHub identity token names no job; the GitHub Environment a job declares is what holds each Google account
        # to its job, and these files must also keep id-token: write off every other job. project-builds builds the
        # pull request's code and triage's gather reads its text, so neither may ever ask for one. A job with no permissions of its own inherits the workflow's, so the effective
        # permission is what is read here: a workflow-level id-token: write would reach every job.
        for workflow, want in (("build.yaml", {"review", "comment", "hold"}), ("triage.yaml", {"comment"}),
                               ("enroll-dispatch.yml", {"dispatch"})):
            parsed = self.workflow(workflow)
            default = parsed.get("permissions") or {}
            got = set()
            for name, job in parsed["jobs"].items():
                permissions = job["permissions"] if "permissions" in job else default
                if (permissions or {}).get("id-token") == "write":
                    got.add(name)
            self.assertEqual(got, want, f"{workflow}: the jobs whose effective permissions hold id-token: write")

    def test_the_helpers_use_no_argv_form_for_the_github_token(self):
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        # env NAME=value puts the value in env's argument vector; -c http.extraheader= puts the header in git's.
        self.assertNotIn("env GITHUB_TOKEN=", gather)
        self.assertIn('GITHUB_TOKEN="${GH_TOKEN:-}" keep', gather)
        self.assertNotIn("-c http.extraheader=", take)
        self.assertIn("--config-env=http.extraheader=", take)

    def test_the_credential_steps_put_no_credential_in_any_argv(self):
        # The text test above reads the steps; this one runs them. Each step that holds a credential is run in its
        # own shell (bash -e, as the runner does) under strace, with stand-ins for curl, base64's input and
        # review-run, and every credential's value must be absent from every program's arguments.
        if not shutil.which("strace"):
            self.skipTest("strace is not installed (the tests workflow installs it)")
        token, gcp, request = "collector-token-not-a-secret", "gcp-not-a-secret", "request-token-not-a-secret"
        key_lines = ["-----BEGIN RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4",
                     "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==", "-----END RSA PRIVATE KEY-----"]
        key = "\n".join(key_lines) + "\n"

        def steps(workflow, job, name):
            found = [s for s in self.workflow(workflow)["jobs"][job]["steps"] if s.get("name") == name]
            self.assertEqual(len(found), 1, f"{workflow} {job} {name}")
            return found[0]["run"]

        cases = [
            ("build.yaml review Review", steps("build.yaml", "review", "Review"),
             json.dumps({"payload": {"data": base64.b64encode(token.encode()).decode()}}),
             {"GCP_ACCESS_TOKEN": gcp}, [token, base64.b64encode(token.encode()).decode(), gcp]),
            ("build.yaml review identity token", steps("build.yaml", "review", "Get the GitHub identity token for Anthropic"),
             json.dumps({"value": "jwt-not-a-secret"}),
             {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": request, "ACTIONS_ID_TOKEN_REQUEST_URL": "http://127.0.0.1:9/?x=1"},
             [request, "jwt-not-a-secret"]),
            ("build.yaml review held finding store", steps("build.yaml", "review", "Store the held finding for the hold job"),
             json.dumps({"generation": "1761500000000000"}),
             {"GCP_ACCESS_TOKEN": gcp, "RUN_ID": "7", "PR": "68", "NAME": "libreac", "HEAD_SHA": "1" * 40,
              "RUN_URL": "https://github.com/theorem-labs/oss-verify/actions/runs/7"}, [gcp]),
            ("build.yaml hold listing", steps("build.yaml", "hold", "Look for stored held findings"),
             json.dumps({"items": [{"name": "held/7/" + "a" * 32}]}), {"GCP_ACCESS_TOKEN": gcp}, [gcp]),
            ("build.yaml hold repository", steps("build.yaml", "hold", "Where the held findings go"),
             json.dumps({"payload": {"data": base64.b64encode(b"private-repository").decode()}}),
             {"GCP_ACCESS_TOKEN": gcp}, [gcp]),
        ]
        for workflow, job in [(w, j) for w, js in self.KEY_JOBS.items() for j in js]:
            cases.append((f"{workflow} {job} key", steps(workflow, job, "Read the oss-verify App's key"),
                          json.dumps({"payload": {"data": base64.b64encode(key.encode()).decode()}}),
                          {"GCP_ACCESS_TOKEN": gcp}, [gcp, base64.b64encode(key.encode()).decode()] + key_lines[1:3]))
        for label, run, answer, environment, secrets in cases:
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                bin = directory / "bin"
                bin.mkdir()
                # curl answers on standard output, or into the file -o names.
                (bin / "curl").write_text("#!/bin/bash\nout=\"\"\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n"
                                          f"if [ -n \"$out\" ]; then printf '%s' {shlex.quote(answer)} > \"$out\"; "
                                          f"else printf '%s' {shlex.quote(answer)}; fi\n")
                (bin / "curl").chmod(0o755)
                (directory / ".github" / "scripts").mkdir(parents=True)
                (directory / ".github" / "scripts" / "review-run").write_text("#!/bin/bash\nexit 0\n")
                (directory / ".github" / "scripts" / "review-run").chmod(0o755)
                (directory / ".review").mkdir()
                (directory / ".review" / "comment.md").write_text("Thanks.\n")
                (directory / ".review" / "held-finding.md").write_text("<!-- held finding -->\ntitle: x\n")
                trace = directory / "trace"
                env = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "RUNNER_TEMP": str(directory / "tmp"),
                       "GITHUB_OUTPUT": str(directory / "output"), "GITHUB_STEP_SUMMARY": str(directory / "summary"),
                       "ANTHROPIC_IDENTITY_TOKEN_FILE": str(directory / "jwt"),
                       "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9", **environment}
                (directory / "tmp").mkdir()
                result = subprocess.run(["strace", "-f", "-qq", "-s", "65536", "-e", "trace=execve", "-o", str(trace),
                                         "bash", "--noprofile", "--norc", "-e", "-c", run],
                                        cwd=directory, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f"{label}: {result.stderr}")
                text = trace.read_text()
                self.assertIn('"curl"', text, f"{label}: the stand-in curl was not started")
                for secret in secrets:
                    self.assertNotIn(secret, text, f"{label}: a credential is in a program's arguments")
                    self.assertNotIn(secret, result.stderr, f"{label}: a credential is on stderr")

    def test_the_helpers_production_definitions_keep_the_token_out_of_argv(self):
        # The production keep, the triage call and fetch_head, taken from the scripts and run under strace with a fake
        # python3 and git that record their arguments and environment: the token reaches the environment only.
        if not shutil.which("strace"):
            self.skipTest("strace is not installed (the tests workflow installs it)")
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        keep = re.search(r"^keep\(\) \{.*\}$", gather, re.M).group(0)
        call = re.search(r"^.*\bkeep triage-today\.md .*$", gather, re.M).group(0)
        fetch = re.search(r"^fetch_head\(\) \{\n.*?^\}$", take, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            (directory / "out").mkdir()
            for name in ("git", "python3"):
                (bin / name).write_text(f'#!/bin/bash\nprintf "%s\\n" "$@" >> {directory}/{name}-argv\n'
                                        f"env >> {directory}/{name}-env\n")
                (bin / name).chmod(0o755)
            secret = "ghs_" + "Q" * 36
            auth = base64.b64encode(f"x-access-token:{secret}".encode()).decode()
            script = "\n".join(["set -euo pipefail", f"out={directory}/out REPO=o/r PR=1 sha={'a' * 40} fetched=false",
                                keep, call, fetch, "fetch_head", "fetch_head"])
            run = subprocess.run(["strace", "-f", "-qq", "-s", "8192", "-e", "trace=execve", "-o",
                                  str(directory / "trace"), "bash", "-c", script], cwd=directory,
                                 env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": secret},
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            trace = (directory / "trace").read_text()
            self.assertIn("python3", trace)
            self.assertIn("--config-env=http.extraheader=", trace)
            for value in (secret, auth):
                self.assertNotIn(value, trace)
                self.assertNotIn(value, run.stdout + run.stderr)
            self.assertIn(f"GITHUB_TOKEN={secret}", (directory / "python3-env").read_text())
            self.assertIn(f"Authorization: Basic {auth}", (directory / "git-env").read_text())
            # fetch_head fetches once, however often it is called.
            self.assertEqual((directory / "git-argv").read_text().split("\n").count("fetch"), 1)
            # Nor in what keep gathered (python3-env and git-env are the fakes' deliberate captures of the environment).
            gathered = sorted((directory / "out").iterdir())
            self.assertTrue(gathered)
            for path in gathered:
                for value in (secret, auth):
                    self.assertNotIn(value, path.read_text(), path.name)

    APP_ACCOUNT = "ossv-app-comment@theorem-agent-infra.iam.gserviceaccount.com"

    def app_key_jobs_problems(self, jobs, key_jobs=("comment",)):
        """Why these jobs could let a job other than `key_jobs` read the App's key, or [] if they cannot.

        The account that reads the key can be acted as only by an oss-verify job whose identity token carries
        `environment: comment` (Theorem's infrastructure code). GitHub accepts an environment as a string,
        as an object with `name`, and through an expression, and compares names without regard to case. An expression
        can compute `comment` from text that does not contain it (format('com{0}', 'ment')), so another job's
        environment is refused if it holds an expression at all, or if its text names `comment` in any case; the
        review job's own, the plain name enroll-review, passes. The key jobs' must be the plain name `comment`, with
        nothing but `deployment: false` beside it."""
        problems = []
        for name, job in jobs.items():
            if name in key_jobs:
                if job.get("environment") not in ("comment", {"name": "comment", "deployment": False}):
                    problems.append(f"{name}: environment {job.get('environment')!r}, want the plain name 'comment'")
                if (job.get("env") or {}).get("GCP_SERVICE_ACCOUNT") != self.APP_ACCOUNT:
                    problems.append(f"{name}: does not sign in as {self.APP_ACCOUNT}")
            else:
                text = json.dumps(job.get("environment", ""))
                if "${{" in text:
                    problems.append(f"{name}: its environment ({job['environment']!r}) is an expression")
                if "comment" in text.lower():
                    problems.append(f"{name}: its environment ({job['environment']!r}) names comment; only "
                                    f"{', '.join(key_jobs)} may")
                if self.APP_ACCOUNT in json.dumps(job):
                    problems.append(f"{name}: names {self.APP_ACCOUNT}")
        return problems

    def test_only_the_key_jobs_can_read_the_app_key(self):
        for workflow, key_jobs in self.KEY_JOBS.items():
            jobs = self.workflow(workflow)["jobs"]
            for key_job in key_jobs:
                self.assertIn(key_job, jobs, workflow)
            self.assertEqual(self.app_key_jobs_problems(jobs, key_jobs), [], workflow)

    def test_only_the_review_job_can_read_the_collector_token(self):
        # ossv-ci can be acted as only from oss-verify's GitHub Environment `enroll-review` (Theorem's
        # infrastructure code), which the review job declares; no other job of either file may name that account or
        # that environment, and the review job must keep it, or its sign-in stops working.
        account = "ossv-ci@theorem-agent-infra.iam.gserviceaccount.com"
        for workflow in self.KEY_JOBS:
            for name, job in self.workflow(workflow)["jobs"].items():
                review = workflow == "build.yaml" and name == "review"
                environment = json.dumps(job.get("environment", "")).lower()
                if review:
                    self.assertEqual(job.get("environment"), {"name": "enroll-review", "deployment": False})
                    self.assertEqual((job.get("env") or {}).get("GCP_SERVICE_ACCOUNT"), account)
                else:
                    self.assertNotIn(account, json.dumps(job), f"{workflow} {name} names {account}")
                    self.assertNotIn("enroll-review", environment, f"{workflow} {name} is in enroll-review")

    @unittest.skipUnless(shutil.which("jq") and shutil.which("base64"), "the key step needs jq and base64")
    def test_the_app_key_is_masked_in_every_key_job(self):
        # The key-reading step is in each of these files, and the runner logs the private-key input of the next step:
        # these masks are what keep a key that does not expire out of a public log. Each copy is run with a stand-in
        # curl for Secret Manager, and every non-blank line of the key, and its base64 form, must be masked.
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" \
              "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----\n"
        payload = base64.b64encode(key.encode()).decode()
        for workflow, key_job in [(w, j) for w, js in self.KEY_JOBS.items() for j in js]:
            steps = [s for s in self.workflow(workflow)["jobs"][key_job]["steps"]
                     if s.get("name") == "Read the oss-verify App's key"]
            self.assertEqual(len(steps), 1, workflow)
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                bin = directory / "bin"
                bin.mkdir()
                (bin / "curl").write_text("#!/bin/bash\nprintf '%s' "
                                          + shlex.quote(json.dumps({"payload": {"data": payload}})) + "\n")
                (bin / "curl").chmod(0o755)
                run = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", steps[0]["run"]], cwd=directory,
                                     env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}",
                                          "GCP_ACCESS_TOKEN": "gcp-not-a-secret",
                                          "GITHUB_OUTPUT": str(directory / "output")},
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, f"{workflow}: {run.stderr}")
                masked = {line[len("::add-mask::"):] for line in run.stdout.splitlines()
                          if line.startswith("::add-mask::")}
                for line in [payload] + [line for line in key.splitlines() if line.strip()]:
                    self.assertIn(line, masked, f"{workflow}: {line[:20]}… is not masked")
                # Every line of the key, and the payload, appears only inside its own mask line.
                for line in [payload] + [line for line in key.splitlines() if line.strip()]:
                    outside = [o for o in run.stdout.splitlines() if line in o and o != f"::add-mask::{line}"]
                    self.assertEqual(outside, [], f"{workflow}: {line[:20]}… is printed outside its mask")
                    self.assertNotIn(line, run.stderr, f"{workflow}: {line[:20]}… is on stderr")
                self.assertIn(key.splitlines()[1], (directory / "output").read_text(), workflow)

    def test_every_google_sign_in_keeps_its_token_to_one_step(self):
        # Each auth step writes no credentials file, exports no variable, and mints a five-minute access token: its
        # output is all that holds it. Six steps: build.yaml's review job signs in before the review and again, for a
        # held finding, after it (the first token has expired by then); its hold and comment jobs, triage's comment job
        # and enroll-dispatch's dispatch job sign in once each.
        found = 0
        for workflow in self.KEY_JOBS:
            for name, job in self.workflow(workflow)["jobs"].items():
                for step in job["steps"]:
                    if step.get("uses", "").startswith("google-github-actions/auth@"):
                        found += 1
                        self.assertEqual({k: step["with"].get(k) for k in ("token_format", "access_token_lifetime",
                                          "create_credentials_file", "export_environment_variables")},
                                         {"token_format": "access_token", "access_token_lifetime": "300s",
                                          "create_credentials_file": False, "export_environment_variables": False},
                                         f"{workflow} {name}")
        self.assertEqual(found, 6)

    def test_another_job_in_the_comment_environment_is_refused_in_every_shape(self):
        # The shapes GitHub takes for `environment` (workflow syntax, jobs.<job_id>.environment), each put on the
        # review job of the real build.yaml: every one must be refused.
        for shape in ("comment", {"name": "comment"}, {"name": "comment", "url": "https://example.invalid"},
                      "${{ 'comment' }}", {"name": "${{ 'comment' }}"}, "Comment",
                      {"name": "${{ github.ref == 'x' && 'enroll-review' || 'COMMENT' }}", "deployment": False},
                      "${{ format('com{0}', 'ment') }}", {"name": "${{ format('com{0}', 'ment') }}"}):
            jobs = self.workflow("build.yaml")["jobs"]
            jobs["review"]["environment"] = shape
            self.assertTrue(self.app_key_jobs_problems(jobs, self.KEY_JOBS["build.yaml"]),
                            f"review with environment {shape!r} was not refused")
        for shape in ({"name": "comment"}, "${{ 'comment' }}", {"name": "comment", "url": "https://example.invalid"}):
            jobs = self.workflow("build.yaml")["jobs"]
            jobs["comment"]["environment"] = shape
            self.assertTrue(self.app_key_jobs_problems(jobs, self.KEY_JOBS["build.yaml"]),
                            f"comment with environment {shape!r} was not refused")


class PostingStep(unittest.TestCase):
    """build.yaml's own "Post the comment" step, run with a fake gh: what it sends GitHub."""
    OLD = "Thanks.\n\n1. Fix X.\n"

    def post(self, review, existing=True, previous=None, head="b" * 40, pr_head=None, served=SERVED_OK, refused="",
             post_to_pr="post", summary=None):
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        name = "Post the comment, or update the one already there"
        matches = [s for s in workflow["jobs"]["comment"]["steps"] if s.get("name") == name]
        # Exactly one, so this cannot run a same-name copy instead of the step the job really uses.
        self.assertEqual(len(matches), 1, f"{len(matches)} steps named {name!r}")
        step = matches[0]
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            if previous is None:
                previous = posted(self.OLD, "a" * 40)
            (directory / "existing.md").write_text(previous)
            # Like the real gh: --jq prints the body and then a newline, and the pull request's head is pr_head.
            (bin / "gh").write_text(
                "#!/bin/bash\n"
                f'case "$*" in\n'
                f'  *"pulls/8 "*) echo {pr_head or head} ;;\n'
                f'  *"--method PATCH"*) cat > {directory}/patch.json ;;\n'
                f'  *"--method POST"*) cat > {directory}/post.json ;;\n'
                f'  *"--paginate"*) {"echo 4242" if existing else "true"} ;;\n'
                f'  *"issues/comments/4242"*) cat {directory}/existing.md; echo ;;\n'
                '  *) echo "unexpected gh $*" >&2; exit 1 ;;\n'
                "esac\n")
            (bin / "gh").chmod(0o755)
            (directory / "temp").mkdir()
            environment = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                           "PR": "8", "REVIEW": review, "CHECKS": "### new report\n", "HEAD_SHA": head,
                           "SERVED": served, "REFUSED": refused, "POST_TO_PR": post_to_pr,
                           "RUN_URL": "https://github.com/o/r/actions/runs/7", "RUNNER_TEMP": str(directory / "temp"),
                           "GITHUB_OUTPUT": str(directory / "output"),
                           "GITHUB_STEP_SUMMARY": str(directory / "summary")}
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=ROOT, env=environment, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            if summary is not None:
                summary.append((directory / "summary").read_text() if (directory / "summary").exists() else "")
            sent = [name for name in ("patch.json", "post.json") if (directory / name).exists()]
            self.assertLessEqual(len(sent), 1, sent)
            if sent:
                self.assertEqual(sent[0], "patch.json" if existing else "post.json")
            return json.loads((directory / sent[0]).read_text())["body"] if sent else None

    def test_without_the_variable_it_posts_nothing_and_writes_the_draft_to_the_summary(self):
        # OSSV_POST_REVIEW unset, or any value but post: no PATCH and no POST, with or without a comment already there,
        # and the comment that would have been sent is in the job summary, each line indented as code.
        for value in ("", "draft", "Post"):
            for existing in (True, False):
                summary = []
                self.assertIsNone(self.post("Fix Y.\n", existing=existing, post_to_pr=value, summary=summary),
                                  (value, existing))
                self.assertIn("Draft of the review comment (not posted)", summary[0])
                self.assertIn("\n    Fix Y.\n", summary[0])
                self.assertIn(f"\n    {review_comment.MARKER}\n", summary[0])

    def test_the_triage_comment_is_a_draft_without_its_variable(self):
        # triage.yaml's own posting step: with OSSV_POST_TRIAGE anything but post, it calls gh not at all and writes the
        # draft to the summary; with post, it posts.
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "triage.yaml").read_text())
        name = "Post the comment, or update the one already there"
        matches = [s for s in workflow["jobs"]["comment"]["steps"] if s.get("name") == name]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["env"]["POST_TO_PR"], "${{ vars.OSSV_POST_TRIAGE }}")
        for value, posts in (("", False), ("draft", False), ("Post", False), ("post", True)):
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                (directory / "bin").mkdir()
                (directory / "bin" / "gh").write_text(
                    f'#!/bin/bash\necho "$*" >> {directory}/calls\n'
                    f'case "$*" in *"--method POST"*) cat > {directory}/post.json ;; esac\n')
                (directory / "bin" / "gh").chmod(0o755)
                environment = {**os.environ, "PATH": f"{directory / 'bin'}:{os.environ['PATH']}", "GH_TOKEN": "x",
                               "REPO": "o/r", "PR": "8", "COMMENT": "<!-- oss-verify-triage -->\n### Triage\n",
                               "POST_TO_PR": value, "GITHUB_STEP_SUMMARY": str(directory / "summary")}
                run = subprocess.run(["bash", "-e", "-c", matches[0]["run"]], env=environment, capture_output=True,
                                     text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual((directory / "post.json").exists(), posts, value)
                if not posts:
                    self.assertFalse((directory / "calls").exists(), value)
                    self.assertIn("\n    ### Triage\n", (directory / "summary").read_text())

    def status(self, body):
        return review_comment.META.match(body.split("\n")[1]).group("status")

    def test_an_unusable_review_keeps_the_posted_one(self):
        # The review job succeeded with text that cannot be posted: the step still fetches and keeps the last review.
        for review in ("", " \n\t\n", "Here: ghs_" + "b" * 36, "<!-- oss-verify-review -->\n"):
            body = self.post(review)
            self.assertEqual(self.status(body), "stale", repr(review))
            self.assertIn("1. Fix X.", body)
            self.assertNotIn("ghs_" + "b" * 36, body)

    def test_a_usable_review_replaces_the_posted_one(self):
        body = self.post("Thanks again.\n\n2. Fix Y.\n")
        self.assertEqual(self.status(body), "review")
        self.assertIn("2. Fix Y.", body)
        self.assertNotIn("1. Fix X.", body)
        self.assertIn("### new report", body)

    def test_a_run_of_an_older_head_posts_nothing(self):
        # The pull request moved on while this run worked: its newer head's run posts, and this one neither replaces
        # that review nor marks it not current.
        for review in ("Thanks again.\n\n2. Fix Y.\n", ""):
            self.assertIsNone(self.post(review, pr_head="c" * 40))
            self.assertIsNone(self.post(review, existing=False, pr_head="c" * 40))

    def test_a_rerun_for_the_same_commit_sends_the_comment_as_it_is(self):
        # A rerun, or an edit of the pull request, that writes no review for the commit already reviewed: the body
        # sent is the body stored, rerun after rerun, though gh adds a newline to what it fetches.
        stored = posted(self.OLD, "b" * 40)
        once = self.post("", previous=stored)
        self.assertEqual(once, stored)
        self.assertEqual(self.post("", previous=once), stored)

    def test_a_review_another_provider_answered_is_posted_as_not_published(self):
        # The review job passes on no review text when another provider or model answered, only the record.
        body = self.post("", existing=False, served=SERVED_OTHER)
        self.assertEqual(self.status(body), "none")
        self.assertIn("is not published ([the run](https://github.com/o/r/actions/runs/7)). What answered it, as "
                      "Claude Code reported it: `it asked for", body)
        kept = self.post("", served=SERVED_OTHER)
        self.assertEqual(self.status(kept), "stale")
        self.assertIn("but bedrock/claude-opus-5-5 (2 turns) answered", kept)

    def test_a_refused_review_is_posted_as_not_published(self):
        record = "asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\nnone/claude-opus-5-5 4\n"
        body = self.post("", existing=False, served=record, refused="true")
        self.assertIn("is not published ([the run]", body)
        body = self.post("", existing=False, served=record)
        self.assertIn("did not run on this push", body)

    def test_without_a_posted_comment_it_posts_one(self):
        self.assertEqual(self.status(self.post(" \n", existing=False)), "none")

    def test_keeping_the_same_comment_again_and_again_changes_nothing(self):
        # A posted review just under GitHub's limit, kept by three runs of the step for the same push: the first keep
        # cuts it to make room for the notice and the footer; the second and the third post that same comment, with
        # one cut note and every character of the review that the first kept.
        big = (f"{review_comment.MARKER}\n{review_comment.meta_line('a' * 40, 'review')}\n\n"
               f"{review_comment.HEADING}\n\n" + "R" * 64_800 + "\n")
        once = self.post("", previous=big)
        twice = self.post("", previous=once)
        thrice = self.post("", previous=twice)
        self.assertEqual(self.status(once), "stale")
        self.assertIn("The review is cut at", once)
        self.assertEqual(twice, once)
        self.assertEqual(thrice, once)
        self.assertEqual(thrice.count("The review is cut at"), 1)
        self.assertEqual(thrice.count("**Not current:**"), 1)
        self.assertEqual(thrice.count("Claude wrote this review"), 1)
        self.assertLessEqual(len(thrice), 65_536)

    def test_a_review_that_goes_stale_and_current_again_is_not_cut_again(self):
        # The pull request goes back to the reviewed commit between pushes whose reviews do not finish: the review is
        # stale, current, stale again. Where the first keep cut it is carried each time, so it is never cut again.
        big = (f"{review_comment.MARKER}\n{review_comment.meta_line('a' * 40, 'review')}\n\n"
               f"{review_comment.HEADING}\n\n{review_comment.ANSWERED.format(ANSWERED_OK)}\n\n"
               + "R" * 64_700 + "TAIL_END\n")
        body, kept = big, []
        for head in "baacadab":
            body = self.post("", previous=body, head=head * 40)
            self.assertEqual(self.status(body), "review" if head == "a" else "stale", head)
            self.assertEqual(body.count("The review is cut at"), 1, head)
            self.assertEqual(body.count("Claude wrote this review"), 1, head)
            kept.append(body.count("R"))
        self.assertEqual(len(set(kept)), 1, kept)


class Screening(unittest.TestCase):
    """review-comment's credential scan and its cuts."""
    OLD = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|sk-ant-[A-Za-z0-9_-]{8,}|gh[opsu]_[A-Za-z0-9]{20,}"
                     r"|github_pat_[A-Za-z0-9_]{20,}")

    def test_the_scan_finds_what_the_regular_expression_found(self):
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOngifQ.c2lnbmF0dXJl"
        for text in (jwt, f"a {jwt} b", "sk-ant-oat01-abcdefghijkl", "x sk-ant-abcdefgh", "ghs_" + "a" * 20,
                     "ghp_" + "a" * 19 + "_", "github_pat_" + "a" * 20, "github_pat_-github_pat_" + "a" * 20,
                     "gho_" + "-" * 20 + "ghu_" + "B" * 20, "eyJ" + "a" * 10 + ".", "eyJ" + "a" * 9 + "." + "b" * 10,
                     "eyJ" + "a" * 10 + ". " + "b" * 10, "eyJ" + "a" * 10 + "." + "b" * 10, "sk-ant-" + "a" * 7,
                     "eyJ" * 30, "plain words", ""):
            self.assertEqual(review_comment.credential(text), bool(self.OLD.search(text)), text)
        # And on random text over the characters these patterns turn on.
        import random
        rng = random.Random(36)
        pieces = ["eyJ", "sk-ant-", "gho_", "ghs_", "github_pat_", ".", "-", "_", " ", "a", "B", "7", "aaaaaaaaaa"]
        for _ in range(20_000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randrange(1, 14)))
            self.assertEqual(review_comment.credential(text), bool(self.OLD.search(text)), text)

    def test_the_scan_is_linear(self):
        # Inputs that hold no credential, built to make a backtracking scan reread the text at every prefix.
        for hostile in ("eyJ" * 100_000, "eyJ" + "a" * 300_000, "ghs_" * 75_000, "github_pat_-" * 25_000,
                        ("eyJ" + "a" * 9 + ".") * 20_000):
            self.assertFalse(self.OLD.search(hostile[:2_000]))
            started = time.monotonic()
            self.assertFalse(review_comment.credential(hostile))
            self.assertLess(time.monotonic() - started, 1.0, hostile[:20])

    def comment(self, review, checks="### report\n", *extra):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            (directory / "served").write_text(SERVED_OK)
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md"), "--head", "a" * 40,
                                   "--served", str(directory / "served"), *extra],
                                  capture_output=True, text=True, check=True).stdout

    def generated_before_the_review(self, text):
        """What this script writes, which must all come before the review the model wrote."""
        review_at = text.rindex("\n\n") if "\n\n" in text else len(text)
        return text[:review_at]

    def test_what_the_script_writes_comes_before_the_review(self):
        # The review is last, so nothing it leaves open has anything of this script's after it to hide.
        text = self.comment("The model's text.", "### report\n")
        self.assertTrue(text.rstrip().endswith("The model's text."))
        head = self.generated_before_the_review(text)
        for mine in (review_comment.MARKER, "oss-verify-meta", review_comment.HEADING, "Claude wrote this review",
                     review_comment.CHECKS_SUMMARY, "### report"):
            self.assertIn(mine, head, mine)

    def report(self, text):
        """The checks report as posted: the code block between the summary and </details>, every line of it four spaces
        in (so that no line of it can end the block), with those four spaces taken off."""
        block = text.split(review_comment.CHECKS_SUMMARY + "\n\n", 1)[1].split("\n\n</details>\n\n", 1)[0]
        lines = block.split("\n")
        for line in lines:
            self.assertTrue(line.startswith("    "), line)
        return "\n".join(line[4:] for line in lines)

    def test_no_character_of_the_review_or_the_checks_is_changed(self):
        # Markdown code holds characters that look like markup, spaced and unspaced, and a first line indented into a
        # code block. Each must arrive as written. So must a span from <!-- that names this script to a later -->
        # where GitHub shows it as text: in code, after a backslash, in an attribute, or from inside a paragraph
        # across a blank line. Markers are not removed from what is posted, since only line 2 is read.
        for text in ("Use `a<b` here.", "Use `a < b` here.", "```c\nif (a<b) return a;\n```",
                     "See `<div title=\"x >`.", "`<!-- not mine -->`", "a <b> b </b> c", "&#", "<b", "1<2 and 3>2",
                     "    *dst = *src; /* no bound */\n\nAfter the code.",
                     "The source has `<!-- oss-verify` on line 3.\n\n1. CRITICAL_BETWEEN_SPANS\n\n2. And `-->` on 9.",
                     "Para B <!-- oss-verify-y\n\nCRITICAL_SPANS_PARAGRAPHS\n\n--> AFTER_B",
                     "~~~\n/* <!-- oss-verify */\n~~~\n\nCRITICAL_IN_FENCES\n\n~~~\n/* --> */\n~~~",
                     '# libfoo: oss-verify pull request #12, "Add libfoo <!-- comment parser fuzzers"\n\n'
                     "1. **fail** FINDING_ONE.\n\n2. **fail** FINDING_TWO: no seed holds `-->`.",
                     "Writes \\<!-- oss-verify x\n\n1. CRITICAL_ESCAPED\n\nThen \\--> too.",
                     '<a title="<!-- oss-verify">LINK_TEXT</a> CRITICAL_ATTR fix X -->'):
            posted = self.comment(text, "### report\n")
            self.assertTrue(posted.endswith("\n\n" + text + "\n"), text)
            posted = self.comment("Thanks.", text)
            self.assertEqual(self.report(posted), text, text)

    def test_no_row_of_the_checks_is_lost_to_a_marker(self):
        # A contributor's source line and a patch's file name both reach rows of the report: one that opens a marker
        # and one that closes it, with the rows that say what was not caught between. In the code block GitHub shows
        # every one of them, and so every one is posted.
        report = ("  - `fuzz/f.c:10`, under `if (len > 4) abort(); // <!-- oss-verify`\n"
                  "  - `fuzz/f.c:20`: `mutant: x -> y on seed1`: **mutant not met**: the input passes (coverage 0)\n"
                  "  | `mutants/aa.patch` | **not caught** by any seed input (coverage builds) | none |\n"
                  "  | `zz-->.patch` | **not caught** by any seed input (coverage builds) | none |")
        posted = self.comment("Thanks.", report)
        self.assertEqual(self.report(posted), report)
        self.assertEqual(posted.count("not caught"), 2)
        self.assertEqual(posted.count("mutant not met"), 1)

    def test_nothing_in_the_checks_can_end_its_code_block(self):
        # Every line of the report is indented into the code block, so nothing in it ends the block early.
        for report in ("```\nnot a close\n", "`````\nlonger\n", "a ``` b ```` c", "<!-- open", '<div title="x >',
                       "line\n\n\n    deeper\n\n<!--"):
            text = self.comment("Thanks.", report)
            self.assertEqual(self.report(text), review_comment.trim(report))
            # The review follows the block.
            self.assertTrue(text.rstrip().endswith("\n\n</details>\n\nThanks."))

    def test_a_carriage_return_ends_a_line_of_the_block_too(self):
        # CommonMark ends a line at a carriage return alone, so each such line is indented as well.
        block, whole = review_comment.code_block("a\r<!--\r\nb\nc", 100)
        self.assertTrue(whole)
        self.assertEqual(block, "    a\n    <!--\n    b\n    c")

    def test_the_whole_comment_stays_within_githubs_limit(self):
        # The indent adds four characters a line, so a report of many short lines is the one that grows most.
        for review, checks in ((("<!--" * 11_000 + "-->"), "### report\n" + "<!--" * 2_000),
                               ("x" * 90_000, "y" * 90_000), ("`" * 30_000, "`" * 30_000),
                               ("x" * 90_000, "a\n" * 30_000), ("x" * 90_000, "a" + "\n" * 60_000 + "b")):
            text = self.comment(review, checks)
            self.assertLessEqual(len(text), 65_536, (len(review), len(checks)))
            block = text.split(review_comment.CHECKS_SUMMARY + "\n\n", 1)[1].split("\n\n</details>\n\n", 1)[0]
            self.assertLessEqual(len(block), review_comment.MAX_CHECKS)
            self.report(text)
            self.assertIn("Claude wrote this review", text)

    def test_nothing_generated_ever_follows_the_review(self):
        # The review-last guarantee: in every path, including a cut review and a kept comment, the review or the kept
        # body is the last block, and the note about a cut comes before it.
        long = "R" * (review_comment.MAX_REVIEW + 50)
        for text in (self.comment("The model's text.", "### report\n"), self.comment(long, "### report\n"),
                     self.comment("", "### report\n"),
                     review_comment.not_current(f"{review_comment.MARKER}\n"
                                                f"{review_comment.meta_line('a' * 40, 'review')}\n\n"
                                                "## Enrollment review\n\nOLD_BODY <b", "b" * 40, "")):
            blocks = text.strip().split("\n\n")
            last = blocks[-1]
            for mine in (review_comment.MARKER, "oss-verify-meta", review_comment.HEADING, "Claude wrote this review",
                         review_comment.CHECKS_SUMMARY, "is cut at", "**Not current:**", "did not run on this push"):
                self.assertNotIn(mine, last, f"{mine} follows the review")
        text = self.comment(long, "### report\n")
        self.assertLess(text.index("The review is cut at"), text.index("R" * 100))

    def test_nothing_in_the_report_can_end_the_code_block(self):
        # GitHub's renderer closes a fence of more than 255 backticks at any backtick line of 255 or more, so no fence
        # holds a report with such a line: the reviewer's case was 255 backticks and then <!--, which hid the review.
        # An indented code block has no length to beat. These are that boundary and the six fence cases of the last
        # round, each rendered through GitHub's Markdown endpoint for the pull request (the review, the footer and the
        # report all visible); here, the structure that rendering rests on.
        for report in ("`" * 254 + "\n<!--\n", "`" * 255 + "\n<!--\n", "`" * 256 + "\n<!--\n",
                       "`" * 1000 + "\n<!--\n", "~~~\nstill inside\n~~~\n", "```   \nstill inside\n",
                       "   ```\nstill inside\n", "``````\nstill inside\n", "a``````b\nstill inside\n",
                       "~~~text\nstill inside\n"):
            text = self.comment("REVIEW_SENTINEL", report)
            self.assertEqual(self.report(text), review_comment.trim(report), report[:20])
            self.assertTrue(text.endswith("\n\n</details>\n\nREVIEW_SENTINEL\n"), report[:20])

    def test_a_marker_spanning_a_blank_line_is_one_comment(self):
        # GitHub ends an HTML comment at its -->, as the scan does, even across a blank line: rendering the case
        # through GitHub's Markdown endpoint showed the text after the --> and hid the text inside the comment. So a
        # marker that spans a blank line is one span to both, and a review of only that is no review.
        review = "Thanks.\n\n<!-- oss-verify-meta v=1\n\nstatus=none -->\n\nAFTER_MARKER"
        out = review_comment.neutralize(review)
        self.assertNotIn("oss-verify-meta", out)
        self.assertNotIn("status=none", out)
        self.assertIn("Thanks.", out)
        self.assertIn("AFTER_MARKER", out)
        # A comment that does not name this script keeps every character, blank line and all.
        plain = "Thanks.\n\n<!-- plain\n\nstill -->\n\nAFTER_PLAIN"
        self.assertEqual(review_comment.neutralize(plain), plain)
        text = self.comment("<!-- oss-verify-meta v=1\n\nstatus=none -->\n")
        self.assertEqual(review_comment.META.match(text.split("\n")[1]).group("status"), "none")

    def test_neutralize_removes_only_a_complete_marker_of_this_script(self):
        # An independent implementation of the rule, by regular expression rather than by scan, on inputs small enough
        # that its backtracking does not matter: as HTML's tokenizer reads a comment, <!--> and <!---> are whole
        # comments, and any other ends at the first --> or --!> after its <!--.
        def expected(text):
            return re.sub(r"<!--(?:>|->|.*?(?:-->|--!>))",
                          lambda m: " " if "oss-verify" in m.group().lower() else m.group(), text, flags=re.S)
        rng = random.Random(37)
        pieces = ["<!--", "-->", "--!>", "<!-->", "<!--->", "oss-verify", "OSS-Verify", "<!", "x", " ", "\n", "-", "!",
                  ">", "`"]
        for _ in range(20_000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 12)))
            got = review_comment.neutralize(text)
            self.assertEqual(got, expected(text), text)
            self.assertEqual(review_comment.neutralize(got), got, text)
            if "oss-verify" not in text.lower():
                self.assertEqual(got, text, text)

    def test_a_comment_that_html_ends_early_keeps_the_prose_after_it(self):
        # GitHub ends a comment at <!-->, <!---> and --!>, and shows what follows. The scan ends it there too, so it
        # never runs on to a later --> and takes the visible prose between. Each case was rendered through GitHub's
        # Markdown endpoint for the pull request: CRITICAL_FINDING and AFTER_VISIBLE both visible.
        for opener in ("<!-->", "<!--->", "<!-- plain --!>"):
            review = f"BEFORE\n\n{opener} CRITICAL_FINDING about oss-verify here.\n\nAFTER_VISIBLE -->\n\nEND"
            self.assertEqual(review_comment.neutralize(review), review, opener)
            text = self.comment(review)
            self.assertEqual(review_comment.META.match(text.split("\n")[1]).group("status"), "review")
            self.assertTrue(text.endswith(review + "\n"), opener)
        # A review that is all one such case is a review, not an empty one that would keep the last.
        whole = "<!--> CRITICAL_FINDING in oss-verify. -->"
        text = self.comment(whole)
        self.assertEqual(review_comment.META.match(text.split("\n")[1]).group("status"), "review")
        self.assertTrue(text.endswith(whole + "\n"))
        # A marker that --!> ends goes, and the text after it stays.
        self.assertEqual(review_comment.neutralize("a <!-- oss-verify-meta --!> AFTER -->"), "a   AFTER -->")

    def test_a_cut_says_so_before_the_text_it_cut(self):
        text = self.comment("x" * (review_comment.MAX_REVIEW + 10), "y" * (review_comment.MAX_CHECKS + 10))
        for note in ("The checks report is cut to fit in 20,000 characters", "The review is cut at 40,000 characters"):
            self.assertIn(note, text)
            self.assertLess(text.index(note), text.rindex("x" * 100), note)


class ReviewRun(unittest.TestCase):
    """review-run with a fake claude, and, on 127.0.0.1, a collector that takes one token and a GitHub identity token
    endpoint that gives a new token each time to the request token it takes."""
    TOKEN = "collector-token-not-a-secret"
    REQUEST_TOKEN = "request-token-not-a-secret"
    SECRETS = (TOKEN, REQUEST_TOKEN, "sk-ant-oat01-notasecret", "ghs_notasecretnotasecret", "dotted-not-a-secret")
    FOLDER = "-home-runner-work-oss-verify-oss-verify"
    HEAD = "1" * 40
    LAST = "2" * 40
    OLD = "0f97bfe1-152c-4ec0-a947-fb9d1ba5c35b"

    def setUp(self):
        import http.server
        import threading
        self.headers = []
        self.answers = []
        self.issued = []
        self.identity_fails = False
        test = self

        class Collector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                test.headers.append((self.path, self.headers.get("Authorization")))
                right = self.headers.get("Authorization") == f"Bearer {test.TOKEN}"
                self.send_response(test.answers.pop(0) if test.answers else 200 if right else 401)
                self.end_headers()

            def do_GET(self):
                right = (self.headers.get("Authorization") == f"Bearer {test.REQUEST_TOKEN}"
                         and self.path == "/token?x=1&audience=https://api.anthropic.com")
                if test.identity_fails or not right:
                    self.send_response(500 if right else 401)
                    self.end_headers()
                    return
                test.issued.append(f"jwt-{len(test.issued) + 1}")
                body = json.dumps({"value": test.issued[-1]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        bin = self.directory / "bin"
        bin.mkdir()
        # Each command review-run runs records its arguments; claude records its arguments and environment too.
        for command in ("python3", "curl", "jq", "awk", "realpath", "tail", "wc", "env"):
            real = shutil.which(command)
            (bin / command).write_text(f"#!/bin/bash\nprintf '%s\\0' {command} \"$@\" >> {self.directory}/argv\n"
                                       f"exec {real} \"$@\"\n")
        (self.directory / "stream").write_text(stream({"type": "result", "is_error": False, "result": "Thanks."}))
        # claude also keeps its conversation as the real one does, in $HOME/.claude/projects/<folder>/<id>.jsonl, and
        # refuses to resume one that is not there, or any one at all when the file fail-resume exists.
        (bin / "claude").write_text(
            f"#!/bin/bash\nprintf '%s\\0' claude \"$@\" >> {self.directory}/argv\n"
            f"{{ printf '%s\\0' \"$@\"; printf '\\0'; }} >> {self.directory}/calls\n"
            f"cat /proc/$$/environ > {self.directory}/environ\n"
            'id="" resume=""\n'
            'while [ $# -gt 0 ]; do case $1 in --session-id) id=$2 ;; --resume) resume=$2 ;; esac; shift; done\n'
            'if [ -n "$resume" ]; then\n'
            f'  if [ -e {self.directory}/fail-resume ] || ! [ -f "$HOME/.claude/projects/{self.FOLDER}/$resume.jsonl" ]; then\n'
            '    echo "No conversation found with session ID: $resume" >&2; exit 1\n'
            '  fi\n'
            # A resume without --session-id goes on in the same session, appending to its conversation.
            '  [ -n "$id" ] || id=$resume\n'
            'fi\n'
            'if [ -n "$id" ]; then\n'
            f'  mkdir -p "$HOME/.claude/projects/{self.FOLDER}"\n'
            f'  {{ echo "{{\\"resumed\\": \\"$resume\\"}}"; cat {self.directory}/said 2> /dev/null; }} \\\n'
            f'    >> "$HOME/.claude/projects/{self.FOLDER}/$id.jsonl"\n'
            'fi\n'
            f"cat {self.directory}/stream\n")
        for script in bin.iterdir():
            script.chmod(0o755)
        (self.directory / "review").mkdir()
        (self.directory / "home").mkdir()
        self.session = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.session)

    def fake_claude(self, *calls, until_new=0):
        """A claude that, on its call N, appends the identity token file's text to `tokens` (and, with `until_new`,
        again as soon as the file holds another token, as Claude Code reads it again for each exchange, polling for at
        most that many seconds), then prints the stream of a review whose turn
        calls[N-1][2] (by default claude-opus-5-5) answered and whose result is calls[N-1][0], and exits with
        calls[N-1][1]."""
        for n, (result, status, *model) in enumerate(calls, 1):
            (self.directory / f"result.{n}").write_text(stream(result, *model))
            (self.directory / f"status.{n}").write_text(str(status))
        # With until_new, the second read waits for the file to hold another token than the first, at most that long.
        poll = (f'first=$(cat "$ANTHROPIC_IDENTITY_TOKEN_FILE")\n'
                f'for _ in $(seq {until_new * 10}); do\n'
                f'  [ "$(cat "$ANTHROPIC_IDENTITY_TOKEN_FILE")" != "$first" ] && break; sleep 0.1\n'
                f'done\nread_token\n') if until_new else ""
        (self.directory / "bin" / "claude").write_text(
            "#!/bin/bash\n"
            f"cd {self.directory}\n"
            "n=$(( $(cat calls 2> /dev/null || echo 0) + 1 )); echo $n > calls\n"
            'read_token() { { cat "$ANTHROPIC_IDENTITY_TOKEN_FILE"; echo; } >> tokens; }\n'
            "read_token\n"
            f"{poll}"
            '[ -f err.$n ] && cat err.$n >&2\n'
            'cat result.$n; exit "$(cat status.$n)"\n')

    def identity(self, **environment):
        """The review step's environment for workload identity: the token file the step before wrote, and the URL and
        request token a new one is fetched with."""
        token_file = self.directory / "oidc" / "jwt"
        token_file.parent.mkdir(exist_ok=True)
        token_file.write_text("jwt-0\n")
        return {"ANTHROPIC_IDENTITY_TOKEN_FILE": str(token_file), "ACTIONS_ID_TOKEN_REQUEST_TOKEN": self.REQUEST_TOKEN,
                "ACTIONS_ID_TOKEN_REQUEST_URL": f"http://127.0.0.1:{self.server.server_port}/token?x=1",
                **environment}

    def tokens(self):
        return (self.directory / "tokens").read_text().split()

    def failure(self):
        paths = (self.directory / "review" / "failure.txt", self.directory / "review" / "failure-detail.txt")
        return tuple(path.read_text() if path.exists() else None for path in paths)

    def run_review(self, **environment):
        base = {"PATH": f"{self.directory / 'bin'}:{os.environ['PATH']}", "HOME": str(self.directory / "home"),
                "PR": "8", "NAME": "libreac", "GH_TOKEN": "ghs_notasecretnotasecret",
                "ANTHROPIC_API_KEY": "sk-ant-oat01-notasecret", "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "1000",
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://elsewhere", "A.B": "dotted-not-a-secret",
                "BASH_FUNC_f%%": "() { echo dotted-not-a-secret; }"}
        return subprocess.run([str(ROOT / ".github" / "scripts" / "review-run"), "review"], cwd=self.directory,
                              env={**base, **environment}, capture_output=True, text=True)

    def collector(self, **environment):
        return {"OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{self.server.server_port}/",
                "OTEL_COLLECTOR_TOKEN": self.TOKEN, **environment}

    def resume(self, **environment):
        return {"REVIEW_SESSION": str(self.session), "HEAD_SHA": self.HEAD, **environment}

    def last_review(self, said="I asked for a seed corpus."):
        (self.session / "session").write_text(f"id={self.OLD}\nhead={self.LAST}\ndir={self.FOLDER}\n")
        (self.session / f"{self.OLD}.jsonl").write_text(said + "\n")
        # review-gather's diff since the last review's commit, which keep ends with its exit status.
        (self.directory / "review" / "since-last-review.diff").write_text("diff --git a/x b/x\n(exit status 0)\n")

    def claude_calls(self):
        calls = (self.directory / "calls").read_text().split("\0\0")[:-1]
        return [call.split("\0") for call in calls]

    def kept(self):
        fields = dict(line.split("=", 1) for line in (self.session / "session").read_text().splitlines())
        return fields, (self.session / f"{fields['id']}.jsonl").read_text()

    def child(self):
        entries = (self.directory / "environ").read_bytes().split(b"\0")
        return dict(entry.decode().split("=", 1) for entry in entries if entry)

    def test_no_value_is_an_argument_and_the_environment_is_the_allow_list(self):
        # A record left by an earlier run in the same directory is not this run's: review-run clears it.
        (self.directory / "review").mkdir(exist_ok=True)
        (self.directory / "review" / "export-lost.txt").write_text("the cost collector answered 401 earlier\n")
        out = self.run_review(**self.collector(**self.identity()))
        self.assertEqual(out.returncode, 0, out.stderr)
        # The collector took the token before and after the review, so there is no lost export to warn about.
        self.assertFalse((self.directory / "review" / "export-lost.txt").exists())
        argv = (self.directory / "argv").read_text()
        self.assertIn("claude", argv)
        for secret in self.SECRETS:
            self.assertNotIn(secret, argv)
            self.assertNotIn(secret, out.stdout + out.stderr)
        child = self.child()
        self.assertEqual(set(child), {"PATH", "HOME", "LANG", "ANTHROPIC_API_KEY", "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
                                      "ANTHROPIC_IDENTITY_TOKEN_FILE", "CLAUDE_CODE_ENABLE_TELEMETRY",
                                      "OTEL_LOGS_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_EXPORTER_OTLP_PROTOCOL",
                                      "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS",
                                      "OTEL_RESOURCE_ATTRIBUTES"})
        self.assertEqual(child["OTEL_EXPORTER_OTLP_HEADERS"], f"Authorization=Bearer {self.TOKEN}")
        self.assertEqual(child["CLAUDE_CODE_ENABLE_TELEMETRY"], "1")
        self.assertNotIn("theorem.credential", child["OTEL_RESOURCE_ATTRIBUTES"])
        # Before the review and after it.
        self.assertEqual(self.headers, [("/v1/logs", f"Bearer {self.TOKEN}")] * 2)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")

    def test_the_ci_label_only_with_the_ci_service_account(self):
        self.run_review(**self.collector(ANTHROPIC_SERVICE_ACCOUNT_ID="svac_01WdHTLcJPEfiPttcuLK1hGT",
                                         ANTHROPIC_IDENTITY_TOKEN_FILE="/x/jwt"))
        self.assertTrue(self.child()["OTEL_RESOURCE_ATTRIBUTES"].endswith(",theorem.credential=oss-verify-ci"))
        self.run_review(**self.collector(ANTHROPIC_SERVICE_ACCOUNT_ID="svac_other",
                                         ANTHROPIC_IDENTITY_TOKEN_FILE="/x/jwt"))
        self.assertNotIn("theorem.credential", self.child()["OTEL_RESOURCE_ATTRIBUTES"])

    def test_a_token_the_collector_refuses_does_not_stop_the_review(self):
        # Fail-soft: the export is a measurement, so a refused token loses this run's usage and nothing else. The
        # review runs, with no telemetry in the child's environment, and the run says so.
        out = self.run_review(**self.collector(OTEL_COLLECTOR_TOKEN="wrong-token-not-a-secret"))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("answered 401", out.stderr)
        self.assertIn("this review's usage is not exported", out.stderr)
        self.assertNotIn("wrong-token-not-a-secret", out.stdout + out.stderr)
        self.assertFalse((self.directory / "review" / "failure.txt").exists())
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")
        self.assertEqual((self.directory / "review" / "export-lost.txt").read_text(),
                         "the cost collector answered 401, not 200, before the review, so its usage is not exported\n")
        self.assertNoTelemetry()

    def assertNoTelemetry(self):
        for name in self.child():
            self.assertFalse(name.startswith("OTEL_") or name.startswith("CLAUDE_CODE_ENABLE"), name)

    def test_a_curlrc_never_prints_the_token(self):
        (self.directory / ".curlrc").write_text(f"verbose\ntrace-ascii {self.directory}/trace\n")
        out = self.run_review(**self.collector(CURL_HOME=str(self.directory)))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn(self.TOKEN, out.stdout + out.stderr)
        self.assertFalse((self.directory / "trace").exists())

    def test_a_token_refused_after_the_review_keeps_the_review_and_says_so(self):
        self.answers = [200, 401]
        # With workload identity too: stopping the identity token loop at the end leaves the exit status as it is.
        out = self.run_review(**self.collector(**self.identity()))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("answered 401", out.stderr)
        self.assertIn("usage is likely lost", out.stderr)
        self.assertNotIn(self.TOKEN, out.stdout + out.stderr)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")
        self.assertEqual((self.directory / "review" / "export-lost.txt").read_text(),
                         "the cost collector answered 401, not 200, after the review, so its usage is likely lost\n")

    def test_a_collector_that_does_not_answer_does_not_stop_the_review(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        out = self.run_review(**self.collector(OTEL_EXPORTER_OTLP_ENDPOINT=f"http://127.0.0.1:{port}"))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("answered 000", out.stderr)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")
        self.assertIn("answered 000", (self.directory / "review" / "export-lost.txt").read_text())
        self.assertNoTelemetry()

    def test_without_the_collector_nothing_is_exported(self):
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(set(self.child()), {"PATH", "HOME", "LANG", "ANTHROPIC_API_KEY",
                                             "CLAUDE_CODE_MAX_OUTPUT_TOKENS"})
        self.assertEqual(self.headers, [])

    def test_a_first_review_is_fresh_reads_review_md_and_keeps_its_session(self):
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("a fresh review", out.stdout)
        [call] = self.claude_calls()
        self.assertNotIn("--resume", call)
        self.assertIn("Read review.md, at the root of this checkout", call[call.index("-p") + 1])
        new = call[call.index("--session-id") + 1]
        self.assertEqual(self.kept(), ({"id": new, "head": self.HEAD, "dir": self.FOLDER}, '{"resumed": ""}\n'))
        self.assertIn(f"kept the session {new}, the review of {self.HEAD}", out.stdout)

    def test_a_later_review_resumes_the_same_session_and_reviews_only_the_diff(self):
        self.last_review()
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"resuming the session {self.OLD} (the review of {self.LAST}), to review only "
                      f"{self.LAST}..{self.HEAD}", out.stdout)
        [call] = self.claude_calls()
        self.assertEqual(call[call.index("--resume") + 1], self.OLD)
        self.assertNotIn("--fork-session", call)
        self.assertNotIn("--session-id", call)
        prompt = call[call.index("-p") + 1]
        self.assertIn(f"you reviewed its commit {self.LAST}", prompt)
        self.assertIn("This review looks only at the diff since the head you last reviewed: "
                      f"review/since-last-review.diff holds the changes to projects/libreac/ from {self.LAST} to "
                      f"{self.HEAD}.", prompt)
        self.assertIn("Do not review again what the diff does not change: a new request comes only from the diff.",
                      prompt)
        self.assertIn("drop the request when that input shows its fix, and keep it otherwise", prompt)
        self.assertIn("review.md (read it again: main can have changed it)", prompt)
        # The same session, its conversation now one push longer, with the commit of this review.
        self.assertEqual(self.kept(), ({"id": self.OLD, "head": self.HEAD, "dir": self.FOLDER},
                                       f'I asked for a seed corpus.\n{{"resumed": "{self.OLD}"}}\n'))
        self.assertIn(f"kept the session {self.OLD}, the review of {self.HEAD}", out.stdout)

    def test_without_the_diff_since_the_last_review_the_review_is_fresh(self):
        # None (a force-push, the same head) and a failed compare: each gives a fresh review.
        for diff in (None, "gh: Not Found (HTTP 404)\n(exit status 1)\n"):
            with self.subTest(diff=diff):
                self.last_review()
                path = self.directory / "review" / "since-last-review.diff"
                if diff is None:
                    path.unlink()
                else:
                    path.write_text(diff)
                (self.directory / "calls").unlink(missing_ok=True)
                out = self.run_review(**self.resume())
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn(f"review-gather wrote no diff since {self.LAST}", out.stdout)
                [call] = self.claude_calls()
                self.assertNotIn("--resume", call)

    def test_an_empty_diff_on_a_new_head_resumes_the_same_session(self):
        # A push that changed nothing in projects/<name>/ (a merge of main): the same session, told the diff is empty.
        self.last_review()
        (self.directory / "review" / "since-last-review.diff").write_text("(exit status 0)\n")
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        [call] = self.claude_calls()
        self.assertEqual(call[call.index("--resume") + 1], self.OLD)
        self.assertIn("When the diff is empty, the push changed nothing in projects/libreac/.",
                      call[call.index("-p") + 1])
        self.assertEqual(self.kept()[0]["id"], self.OLD)

    def test_a_session_that_cannot_be_resumed_gives_a_fresh_review(self):
        self.last_review()
        (self.directory / "fail-resume").touch()
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"the resumed review of the session {self.OLD} ended without a review: a fresh review",
                      out.stdout)
        self.assertIn("(try 2)", out.stdout)
        resumed, fresh = self.claude_calls()
        self.assertIn("--resume", resumed)
        self.assertNotIn("--resume", fresh)
        self.assertEqual(self.kept()[0]["id"], fresh[fresh.index("--session-id") + 1])

    HELD = ("<!-- held finding -->\ntitle: [held] libreac/fuzz: heap-buffer-overflow in parse_SECRETBUG\n"
            "project: libreac\nwhy held: memory safety\n\nparse_SECRETBUG reads past the end.\n")

    def test_a_held_finding_is_cut_from_the_comment_never_shown_and_its_session_not_kept(self):
        self.last_review()
        (self.directory / "stream").write_text(stream({"type": "result", "is_error": False,
                                                        "result": "Thanks.\n\nA finding was sent for private review.\n\n"
                                                                  + self.HELD}))
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        review = self.directory / "review"
        self.assertEqual((review / "comment.md").read_text(), "Thanks.\n\nA finding was sent for private review.\n\n")
        self.assertEqual((review / "held-finding.md").read_text().rstrip("\n"), self.HELD.rstrip("\n"))
        self.assertNotIn("SECRETBUG", out.stdout + out.stderr)
        self.assertIn("holds back a finding for private review", out.stdout)
        self.assertIn(f"the session {self.OLD} holds a finding held back for private review, so it is not kept",
                      out.stdout)
        self.assertEqual(list(self.session.iterdir()), [])

    def test_every_way_a_model_writes_the_marker_cuts_the_finding(self):
        for marker in ("  <!-- held finding -->", "<!--held finding-->", "<!-- Held Finding -->",
                       "- <!-- held finding -->",
                       "> <!-- held_finding -->"):
            with self.subTest(marker=marker):
                (self.directory / "stream").write_text(stream({"type": "result", "is_error": False,
                                                                "result": "Thanks.\n\nA finding was sent for private "
                                                                          "review.\n\n" + self.HELD.replace(
                                                                              "<!-- held finding -->", marker)}))
                out = self.run_review()
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertNotIn("SECRETBUG", (self.directory / "review" / "comment.md").read_text())
                self.assertIn("SECRETBUG", (self.directory / "review" / "held-finding.md").read_text())

    def test_a_comment_that_still_names_a_held_finding_is_not_published(self):
        # A marker inside a sentence is no marker line: nothing is cut, and the comment names a held finding.
        for result in ("Thanks. <!-- held finding --> parse_SECRETBUG reads past the end.\n",
                       "Thanks.\n\nA held finding: parse_SECRETBUG.\n\n" + self.HELD):
            with self.subTest(result=result):
                (self.directory / "stream").write_text(stream({"type": "result", "is_error": False,
                                                                "result": result}))
                out = self.run_review()
                self.assertEqual(out.returncode, 1, out.stderr)
                self.assertIn("named a held finding outside its own part", self.failure()[0])
                # The held part is kept, for the review job to store all the same; only the comment is refused.
                held = self.directory / "review" / "held-finding.md"
                # Nothing is lost: what the cut did not take is held too, for the review job to store.
                self.assertIn("SECRETBUG", held.read_text())
                self.assertNotIn("SECRETBUG", out.stdout + out.stderr)

    def test_the_opening_line_cut_runs_after_the_held_cut(self):
        # A line that ends in a colon and a rule (---) in the first six lines are cut as an opening line. Run before the
        # held cut, that cut would remove the marker and leave the finding's text in the comment.
        result = "<!-- held finding -->\ntitle: crash in f:\n---\nparse_SECRETBUG at f.c:3\n"
        (self.directory / "stream").write_text(stream({"type": "result", "is_error": False, "result": result}))
        out = self.run_review()
        comment = self.directory / "review" / "comment.md"
        self.assertNotIn("SECRETBUG", comment.read_text() if comment.exists() else "")
        self.assertIn("SECRETBUG", (self.directory / "review" / "held-finding.md").read_text())
        self.assertNotIn("SECRETBUG", out.stdout + out.stderr)

    def test_a_failed_try_never_shows_a_held_finding(self):
        for text in (self.HELD, "<!-- held: finding -->\nparse_SECRETBUG\n", "a Held  Finding: parse_SECRETBUG\n"):
            with self.subTest(text=text):
                (self.directory / "calls").unlink(missing_ok=True)
                self.fake_claude(({"type": "result", "subtype": "success", "is_error": True, "num_turns": 3,
                                   "duration_ms": 1000, "result": "Thanks.\n" + text}, 1),
                                 ({"type": "result", "subtype": "success", "is_error": True, "num_turns": 3,
                                   "duration_ms": 1000, "result": "Thanks.\n" + text}, 1))
                out = self.run_review(**self.identity())
                self.assertEqual(out.returncode, 1, out.stderr)
                self.assertNotIn("SECRETBUG", out.stdout + out.stderr + (self.failure()[1] or ""))
                self.assertIn("not shown: it holds a finding held back for private review", out.stderr)

    def test_claude_codes_standard_error_never_shows_a_held_finding(self):
        (self.directory / "err.1").write_text("<!-- held finding --> parse_SECRETBUG\n")
        (self.directory / "err.2").write_text("a held finding: parse_SECRETBUG\n")
        self.fake_claude((API_401[0], 1), (API_401[0], 1))
        out = self.run_review(**self.identity())
        self.assertEqual(out.returncode, 1, out.stderr)
        self.assertNotIn("SECRETBUG", out.stdout + out.stderr)
        self.assertIn("standard error is not shown: it names a finding held back for private review", out.stderr)

    def test_a_comment_that_says_held_in_another_sense_is_published(self):
        result = "Thanks for libreac.\n\nThe determinism check held. Finding 2 of the build is fine."
        (self.directory / "stream").write_text(stream({"type": "result", "is_error": False, "result": result}))
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), result + "\n")
        self.assertFalse((self.directory / "review" / "held-finding.md").exists())

    def test_a_session_file_that_is_not_whole_gives_a_fresh_review(self):
        (self.session / "session").write_text(f"id=../../x\nhead={self.LAST}\ndir={self.FOLDER}\n")
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("does not name a whole session", out.stdout)
        [call] = self.claude_calls()
        self.assertNotIn("--resume", call)

    def test_a_conversation_that_holds_a_token_of_the_run_is_not_kept(self):
        # The collector's token, the identity token in the file now, and one shaped like an earlier identity token:
        # the file gets a new one every minute, so an earlier one is no longer in it.
        jwt = self.directory / "jwt"
        jwt.write_text("identity-token-not-a-secret")
        for token in (self.TOKEN, "identity-token-not-a-secret", JWT):
            with self.subTest(token=token):
                self.last_review()
                (self.directory / "said").write_text(f"the token is {token}\n")
                out = self.run_review(**self.collector(**self.resume(ANTHROPIC_IDENTITY_TOKEN_FILE=str(jwt))))
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn("holds what looks like a credential, so it is not kept", out.stdout)
                self.assertNotIn(token, out.stdout + out.stderr)
                self.assertEqual(list(self.session.iterdir()), [])

    def test_the_conversation_is_kept_outside_the_checkout_with_its_commit(self):
        out = self.run_review(**self.resume(REVIEW_SESSION=str(self.directory / "session")))
        self.assertEqual(out.returncode, 2)
        self.assertIn("REVIEW_SESSION is inside this checkout", out.stderr)
        out = self.run_review(**self.resume(HEAD_SHA="main"))
        self.assertEqual(out.returncode, 2)
        self.assertIn("REVIEW_SESSION needs HEAD_SHA", out.stderr)

    def test_the_identity_token_file_gets_a_new_token_while_claude_runs(self):
        # #48, #49 and #50 (runs 40275097872, 40275102913, 40275107446): Claude Code read the file again about ten
        # minutes in, found the token it had exchanged at the start, and the exchange answered 401. Here it reads the
        # file at its start and again as soon as it holds another token, with a new token due every second. It polls
        # for that, up to 30 seconds, rather than reading once after a fixed 3 seconds: on a loaded machine the first
        # rotation can come later than that, which failed the test with no fault in review-run.
        self.fake_claude(({"is_error": False, "result": "Thanks."}, 0), until_new=30)
        out = self.run_review(**self.identity(REVIEW_TOKEN_EVERY="1"))
        self.assertEqual(out.returncode, 0, out.stderr)
        first, later = self.tokens()
        self.assertEqual(first, "jwt-0")
        self.assertIn(later, self.issued)
        argv = (self.directory / "argv").read_text()
        self.assertNotIn(self.REQUEST_TOKEN, argv + out.stdout + out.stderr)
        self.assertIn("audience=https://api.anthropic.com", argv)
        # Once review-run has ended, no token is written any more, and no temporary file is left.
        token_file = self.directory / "oidc" / "jwt"
        written = token_file.read_text()
        time.sleep(2.5)
        self.assertEqual(token_file.read_text(), written)
        self.assertEqual(sorted(path.name for path in token_file.parent.iterdir()), ["jwt"])

    def test_a_401_mid_review_is_tried_again_with_a_new_identity_token(self):
        out = self.run_review_twice(API_401, (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.tokens(), ["jwt-0", "jwt-1"])
        self.assertIn(f"review-run: {WHY_401} (try 1): API Error: Token exchange failed with status 401", out.stderr)
        self.assertIn("success after 31 turns and 250 seconds (try 2)", out.stdout)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")
        self.assertEqual(self.failure(), (None, None))

    def test_a_review_that_fails_twice_says_why(self):
        out = self.run_review_twice(API_401, API_401)
        self.assertEqual(out.returncode, 1, out.stderr)
        why, detail = self.failure()
        self.assertEqual(why, WHY_401 + ", on both tries\n")
        self.assertEqual(detail, API_401[0]["result"].replace("\n", " ") + "\n")
        self.assertFalse((self.directory / "review" / "comment.md").exists())

    def test_without_a_new_identity_token_there_is_no_second_try(self):
        self.identity_fails = True
        out = self.run_review_twice(API_401, (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 1, out.stderr)
        self.assertEqual(self.tokens(), ["jwt-0"])
        self.assertEqual(self.failure()[0], WHY_401 + "\n")

    def test_a_result_that_is_not_json_says_so(self):
        out = self.run_review_twice(("not json", 1), ("not json", 1))
        self.assertEqual(out.returncode, 1, out.stderr)
        self.assertEqual(self.failure(), ("Claude Code ended with exit status 1, and wrote no review, on both tries\n",
                                          "no message\n"))

    def test_the_review_step_shows_each_line_review_run_writes(self):
        pattern = re.compile(re.search(r"grep -m1 -xE '([^']+)' \.review/failure\.txt", review_step()["run"]).group(1))
        long_kind = ({**API_401[0], "subtype": "e" * 40, "num_turns": 10 ** 9 - 1, "duration_ms": 10 ** 12 - 1}, 1)
        for calls in ((API_401, API_401), (API_401, long_kind), (("x", 124), ("x", 124))):
            with self.subTest(calls=calls):
                self.run_review_twice(*calls)
                why = self.failure()[0]
                self.assertRegex(why, r"\A.+\n\Z")
                self.assertTrue(pattern.fullmatch(why.rstrip("\n")), why)

    def test_a_message_that_holds_a_credential_is_not_shown(self):
        # A run whose result or standard error quotes a credential, such as the identity token it could read: the log
        # and failure-detail.txt, which the public job summary shows, hold neither. A credential just past the
        # 1,000-character cut is found too, since the check reads the message before the cut.
        for leak, padding in ((JWT, ""), (JWT, "x" * 990 + " "), ("sk-ant-oat01-" + "a" * 20, ""),
                              ("ghs_" + "b" * 36, "")):
            with self.subTest(leak=leak[:12], padding=len(padding)):
                for n in (1, 2):
                    (self.directory / f"err.{n}").write_text(f"stderr {leak}\n")
                failed = ({**API_401[0], "result": f"API Error: {padding}{leak}"}, 1)
                out = self.run_review_twice(failed, failed)
                self.assertEqual(out.returncode, 1, out.stderr)
                why, detail = self.failure()
                self.assertEqual(detail, "(not shown: it holds what looks like a credential)\n")
                self.assertNotIn(leak, out.stdout + out.stderr)
                self.assertIn("standard error is not shown: it holds what looks like a credential", out.stderr)
        for n in (1, 2):
            (self.directory / f"err.{n}").write_text("plain stderr\n")
        out = self.run_review_twice(API_401, API_401)
        self.assertIn("plain stderr", out.stderr)
        self.assertIn("Token exchange failed", self.failure()[1])

    def test_a_model_or_provider_review_served_cannot_check_starts_no_review(self):
        for variables in ({"REVIEW_MODEL": "a model"}, {"REVIEW_PROVIDER": "openai"}):
            with self.subTest(variables=variables):
                out = self.run_review(**variables)
                self.assertEqual(out.returncode, 2, out.stderr)
                self.assertIn("REVIEW_PROVIDER/REVIEW_MODEL is not one review-served can check", out.stderr)
                self.assertFalse((self.directory / "environ").exists(), "Claude Code ran")

    def test_a_credential_that_nul_bytes_split_is_not_shown(self):
        # A regression guard: the scan reads standard error without its NUL bytes, which a log can drop, so a token
        # that one splits is found, and nothing of the file is shown.
        split = b"sk-ant-oat0\x001" + b"a" * 20
        for n in (1, 2):
            (self.directory / f"err.{n}").write_bytes(b"stderr " + split + b"\n")
        out = self.run_review_twice(API_401, API_401)
        self.assertEqual(out.returncode, 1, out.stderr)
        self.assertIn("standard error is not shown: it holds what looks like a credential", out.stderr)
        self.assertNotIn("aaaaaaaaaa", out.stderr)
        # And when the review is not published: the same scan.
        (self.directory / "err.1").write_bytes(b"stderr " + split + b"\n")
        out = self.run_review_twice((REVIEW_OK, 0, "gpt-5.6-terra"))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertIn("standard error is not shown: it holds what looks like a credential", out.stderr)
        self.assertNotIn("aaaaaaaaaa", out.stderr)

    def test_the_file_tools_may_not_read_the_identity_token_or_runner_temp(self):
        # --restricted keeps Read, Glob and Grep in the checkout; the deny rules name the two directories too, for each
        # of the three tools, so that the rule does not rest on Claude Code applying a Read rule to Grep and Glob.
        # Claude Code reads `//` as the start of an absolute path in a rule (a `/` rule is relative to the project).
        temp = self.directory / "temp"
        self.fake_claude((REVIEW_OK, 0))
        out = self.run_review(**self.identity(RUNNER_TEMP=str(temp)))
        self.assertEqual(out.returncode, 0, out.stderr)
        argv = (self.directory / "argv").read_text().split("\0")
        claude = argv[len(argv) - 1 - argv[::-1].index("claude"):]
        at = claude.index("--disallowedTools")
        rules = [f"{tool}(/{directory}/**)" for directory in (temp, self.directory / "oidc")
                 for tool in ("Read", "Grep", "Glob")]
        self.assertEqual(claude[at + 1:at + 7], rules)
        self.assertTrue(all(rule.startswith(("Read(//", "Grep(//", "Glob(//")) for rule in claude[at + 1:at + 7]))
        self.assertEqual(claude[at + 7], "--model")
        # A person's own run has neither directory, and no rule.
        for name in ("argv", "calls"):
            (self.directory / name).unlink()
        self.fake_claude((REVIEW_OK, 0))
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("--disallowedTools", (self.directory / "argv").read_text())

    def test_the_review_names_what_answered_it(self):
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("asked for anthropic/claude-opus-5-5, answered by firstParty/claude-opus-5-5 (1 turn),",
                      out.stdout)
        self.assertEqual((self.directory / "review" / "served").read_text(),
                         "asked anthropic/claude-opus-5-5\nendpoint api.anthropic.com\n"
                         "usage firstParty/claude-opus-5-5\nfirstParty/claude-opus-5-5 1\n")
        argv = (self.directory / "argv").read_text().split("\0")
        claude = argv[len(argv) - 1 - argv[::-1].index("claude"):]
        self.assertEqual(claude[claude.index("--output-format") + 1], "stream-json")
        self.assertIn("--verbose", claude)

    def test_a_review_another_model_answered_is_not_published_or_tried_again(self):
        out = self.run_review_twice((REVIEW_OK, 0, "gpt-5.6-terra"), (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertEqual((self.directory / "calls").read_text().strip(), "1")
        self.assertFalse((self.directory / "review" / "comment.md").exists())
        self.assertEqual(self.failure()[0], "the review is not published: it asked for anthropic/claude-opus-5-5, "
                                            "which the tool calls firstParty/claude-opus-5-5, but none/gpt-5.6-terra "
                                            "(1 turn) answered, and the tool's usage names nothing\n")
        self.assertIn("stopped Claude Code: turn 1 was answered by gpt-5.6-terra", out.stderr)

    def test_a_review_another_provider_answered_is_not_published(self):
        bedrock = {**REVIEW_OK, "modelUsage": {"claude-opus-5-5": {"provider": "bedrock",
                                                                   "canonicalModel": "claude-opus-5-5"}}}
        out = self.run_review_twice((bedrock, 0), (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertIn("but bedrock/claude-opus-5-5 (1 turn) answered", self.failure()[0])
        self.assertFalse((self.directory / "review" / "comment.md").exists())

    def test_a_review_that_names_no_provider_is_not_published(self):
        out = self.run_review_twice(({**REVIEW_OK, "modelUsage": {}}, 0), (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertIn("it is not attributable", self.failure()[0])

    def test_a_message_named_as_claude_code_s_own_but_not_marked_so_is_another_model(self):
        # "<synthetic>" is the model Claude Code gives a message it writes itself, which it marks
        # is_api_error_message; from a response, the name alone is another model's.
        out = self.run_review_twice((REVIEW_OK, 0, "<synthetic>"), (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertIn("but none/?synthetic? (1 turn) answered", self.failure()[0])

    def test_a_try_that_ends_well_without_running_review_served_is_not_published(self):
        # A launcher that ends at once (Python's os.execve on Windows starts a new process and returns) leaves the
        # records of an earlier run in place: each try removes them first, and a try that ended well with no record
        # that passes is refused.
        review = self.directory / "review"
        (review / "served").write_text(SERVED_OK)
        (review / "claude.json").write_text(json.dumps(REVIEW_OK))
        # It reads the environment the launcher is given, as the real one does, then ends without starting anything.
        (self.directory / "bin" / "timeout").write_text("#!/bin/sh\ncat > /dev/null\nexit 0\n")
        (self.directory / "bin" / "timeout").chmod(0o755)
        out = self.run_review()
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertFalse((review / "comment.md").exists())
        self.assertIn("nothing recorded which provider answered the review", self.failure()[0])

    def test_a_resumed_review_another_model_answered_is_not_published_or_tried_fresh(self):
        # The first try resumes the last conversation; review-served refuses it, so there is no fresh second try, and
        # the last review's conversation is not replaced.
        self.last_review()
        self.fake_claude((REVIEW_OK, 0, "gpt-5.6-terra"), (REVIEW_OK, 0))
        out = self.run_review(**self.resume(**self.identity()))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertIn(f"resuming the session {self.OLD}", out.stdout)
        self.assertEqual((self.directory / "calls").read_text().strip(), "1")
        self.assertIn("but none/gpt-5.6-terra (1 turn) answered", self.failure()[0])
        self.assertEqual((self.session / "session").read_text(),
                         f"id={self.OLD}\nhead={self.LAST}\ndir={self.FOLDER}\n")
        self.assertFalse((self.directory / "review" / "comment.md").exists())

    def test_another_provider_for_a_run_that_also_failed_is_not_published_or_tried_again(self):
        bedrock = {**API_401[0], "modelUsage": {"claude-opus-5-5": {"provider": "bedrock",
                                                                    "canonicalModel": "claude-opus-5-5"}}}
        out = self.run_review_twice((bedrock, 1), (REVIEW_OK, 0))
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertEqual((self.directory / "calls").read_text().strip(), "1")
        self.assertIn("but bedrock/claude-opus-5-5 (1 turn) answered", self.failure()[0])

    def test_an_endpoint_other_than_anthropic_s_api_starts_no_review(self):
        # Claude Code calls its provider firstParty also when ANTHROPIC_BASE_URL names a proxy, which could answer
        # with any model under any name.
        for variables, where in (({"ANTHROPIC_BASE_URL": "https://proxy.example"}, "https:proxy.example"),
                                 ({"CLAUDE_CODE_USE_BEDROCK": "1"}, "CLAUDE_CODE_USE_BEDROCK")):
            with self.subTest(variables=variables):
                (self.directory / "environ").unlink(missing_ok=True)
                out = self.run_review(**variables)
                self.assertEqual(out.returncode, 4, out.stderr)
                self.assertFalse((self.directory / "environ").exists(), "Claude Code ran")
                self.assertIn(f"the tool's environment or settings set {where}, which", self.failure()[0])
        (self.directory / "home" / ".claude").mkdir()
        (self.directory / "home" / ".claude" / "settings.json").write_text(
            json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://proxy.example"}}))
        out = self.run_review()
        self.assertEqual(out.returncode, 4, out.stderr)
        self.assertFalse((self.directory / "environ").exists(), "Claude Code ran")

    def test_the_review_step_shows_the_line_of_a_review_that_is_not_published(self):
        found = re.search(r'grep -m1 -xE "([^"]+)" \\\n\s*\.review/failure\.txt', review_step()["run"])
        pattern = re.compile(found.group(1))
        for calls in (((REVIEW_OK, 0, "gpt-5.6-terra"),), (({**REVIEW_OK, "modelUsage": {}}, 0),),
                      ((REVIEW_OK, 0, "x" * 300),)):
            with self.subTest(calls=calls):
                self.assertEqual(self.run_review_twice(*calls).returncode, 4)
                why = self.failure()[0]
                self.assertTrue(pattern.fullmatch(why.rstrip("\n")), why)

    def run_review_twice(self, *calls):
        for name in ("calls", "tokens"):
            (self.directory / name).unlink(missing_ok=True)
        self.fake_claude(*calls)
        return self.run_review(**self.identity())


def stream(result, model="claude-opus-5-5"):
    """What Claude Code prints with --output-format stream-json --verbose for a review that ends in `result`: a turn
    that `model` answered, then the result, whose modelUsage names the provider unless `result` has its own. For a
    result that is not an object (a stand-in for no result), nothing: Claude Code writes only JSON objects."""
    if not isinstance(result, dict):
        return ""
    turn = {"type": "assistant", "message": {"id": "msg_01", "model": model, "role": "assistant", "content": []}}
    usage = {"claude-opus-5-5": {"provider": "firstParty", "canonicalModel": "claude-opus-5-5"}}
    return json.dumps(turn) + "\n" + json.dumps({"type": "result", "modelUsage": usage, **result}) + "\n"


def review_step():
    steps = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]["review"]["steps"]
    matches = [step for step in steps if step.get("id") == "review"]
    assert len(matches) == 1, matches
    return matches[0]


@unittest.skipUnless(shutil.which("jq"), "needs jq, which the gh stand-in runs the script's filters with")
class ReviewHeld(unittest.TestCase):
    """review-held opens one private issue for each held finding, through a fake gh, and prints none of it."""

    RUN = "https://github.com/theorem-labs/oss-verify/actions/runs/7"
    OBJECT = "held/7/" + "a" * 32
    HEADER = f"oss-verify held finding v1\npr: 68\nhead: {'1' * 40}\nproject: libreac\nrun: {RUN}\n---\n"

    @staticmethod
    def body(key):
        """An issue body as review-held writes it: its key on the fifth line."""
        return f"enrollment PR: x\nenrollment PR head: y\npublic PR comment: z\nreview run: r\n{key}\n"

    # A stand-in for `gh api`: it answers each call with the JSON GitHub would (from state.json), applies the script's
    # own --jq filter to it with the real jq, and records each call and each body it is sent. So the tests check the
    # script's filters, not a copy of them.
    GH = r'''#!@@PYTHON@@
import json, os, pathlib, subprocess, sys
root = pathlib.Path(@@ROOT@@)
state = json.loads((root / "state.json").read_text())
a = sys.argv[2:]
with open(root / "calls", "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
with open(root / "tokens", "a") as f:
    f.write(os.environ.get("GH_TOKEN", "") + "\n")
path = next(x for x in a if x.startswith("repos/"))
fields = [x for i, x in enumerate(a) if i and a[i - 1] in ("-f", "-F")]
# The body as GitHub would store it: bytes that are not UTF-8 become U+FFFD.
body = next((open(x[6:], "rb").read().decode("utf-8", "replace") for x in fields if x.startswith("body=@")), None)
if body is not None:
    with open(root / "bodies", "a") as f:
        f.write(body + "\0")
repo = path.split("/")[1] + "/" + path.split("/")[2]
private = repo == state["variable"]
if path.endswith("/labels/held-finding"):
    sys.exit(0 if state["label"] else 1)
if path == "repos/" + state["variable"]:
    answer = {"visibility": state["visibility"]}
elif "/issues?" in path:
    answer = [{"number": i, "body": b} for i, b in enumerate(state["issues"], 1)]
elif path.endswith("/comments") and not fields:
    answer = state["comments"] if private else state["public_comments"]
elif path.endswith("/comments"):
    answer = {"id": 7, "html_url": "https://example.test/comment"}
elif path.endswith("/issues"):
    answer = {"number": 42, "html_url": "https://example.test/issue"}
else:
    answer = {}
if "--jq" in a:
    out = subprocess.run(["jq", "-r", a[a.index("--jq") + 1]], input=json.dumps(answer), capture_output=True, text=True,
                         check=True).stdout
    sys.stdout.write(out)
else:
    print(json.dumps(answer))
'''

    def run_held(self, held, bodies_on_github=(), label=True, variable="theorem-labs/private", visibility="private",
                 header=None, comments=(), public_comments=()):
        """bodies_on_github: the bodies of the label's issues already there, open or closed, numbered from 1. comments:
        the bodies of comments already on a private issue. public_comments: the pull request's comments, as
        (login, body, html_url). held follows the six lines the review job writes (header, by default HEADER)."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "bin").mkdir()
            (root / "review").mkdir()
            (root / "review" / "object").write_text((self.HEADER if header is None else header) + held)
            (root / "state.json").write_text(json.dumps({
                "variable": variable, "visibility": visibility, "label": label, "issues": list(bodies_on_github),
                "comments": [{"id": i, "body": c} for i, c in enumerate(comments)],
                "public_comments": [{"user": {"login": login}, "body": b, "html_url": u}
                                    for login, b, u in public_comments]}))
            gh = root / "bin" / "gh"
            gh.write_text(self.GH.replace("@@PYTHON@@", sys.executable).replace("@@ROOT@@", repr(str(root))))
            gh.chmod(0o755)
            run = subprocess.run([str(ROOT / ".github" / "scripts" / "review-held"), str(root / "review")],
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                                      "HELD_FINDINGS_REPO": variable, "REPO": "theorem-labs/oss-verify",
                                      "GH_TOKEN": "app-not-a-secret", "READ_TOKEN": "read-not-a-secret",
                                      "HELD_OBJECT": self.OBJECT},
                                 capture_output=True, text=True)
            # The token of each call, in the order of calls.
            run.tokens = (root / "tokens").read_text().splitlines() if (root / "tokens").exists() else []
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] \
                if (root / "calls").exists() else []
            bodies = (root / "bodies").read_text().split("\0")[:-1] if (root / "bodies").exists() else []
            return run, calls, bodies

    def test_each_finding_is_one_labelled_issue_with_the_pull_request_and_nothing_is_printed(self):
        two = ReviewRun.HELD + ReviewRun.HELD.replace("parse_SECRETBUG", "other_SECRETBUG")
        run, calls, bodies = self.run_held(two, label=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("SECRETBUG", run.stdout + run.stderr)
        self.assertIn(["api", "repos/theorem-labs/private/labels", "-f", "name=held-finding", "-f", "color=b60205",
                       "-f", "description=A finding held back from a public review, for the disclosure route"], calls)
        created = [c for c in calls if c[1] == "repos/theorem-labs/private/issues"]
        self.assertEqual([c[c.index("-f") + 1] for c in created],
                         ["title=[held] libreac/fuzz: heap-buffer-overflow in parse_SECRETBUG",
                          "title=[held] libreac/fuzz: heap-buffer-overflow in other_SECRETBUG"])
        self.assertTrue(all("labels[]=held-finding" in c for c in created))
        self.assertEqual(len(bodies), 2)
        self.assertTrue(bodies[0].startswith(f"enrollment PR: theorem-labs/oss-verify#68\nenrollment PR head: {'1' * 40}\n"
                                             "public PR comment: not posted yet: the review comment on "
                                             "theorem-labs/oss-verify#68\n"
                                             f"review run: {self.RUN}\nheld finding key: {self.OBJECT} 1\n"))
        self.assertIn(f"held finding key: {self.OBJECT} 2\n", bodies[1])
        self.assertNotIn("theorem-labs/private", run.stdout + run.stderr)
        self.assertIn("project: libreac\nwhy held: memory safety\n", bodies[0])
        self.assertNotIn("title:", bodies[0])

    def test_a_re_run_sends_only_what_its_run_did_not_send_and_the_title_routes_nothing(self):
        # The first of two untitled findings was sent before the run failed; a closed issue counts too. Another run's
        # issue with the same title does not stop either.
        two = "<!-- held finding -->\nproject: libreac\n<!-- held finding -->\nproject: libreac\nsecond\n"
        run, calls, bodies = self.run_held(two, bodies_on_github=[
            self.body(f"held finding key: {self.OBJECT} 1"), self.body(f"held finding key: held/1/{'b' * 32} 2"),
            # A key anywhere but the fifth line is no key.
            f"held finding key: {self.OBJECT} 2\n"])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"1 of {self.OBJECT} was already sent", run.stdout)
        self.assertEqual(len(bodies), 1)
        self.assertIn(f"held finding key: {self.OBJECT} 2\n", bodies[0])
        self.assertIn("second", bodies[0])

    def test_a_finding_with_only_a_title_is_sent(self):
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: [held] libreac/x: crash in f\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)

    def test_every_object_is_settled_the_first_time(self):
        # Empty markers are no findings; an object with none sends nothing and succeeds; more than 10 go as one issue.
        run, calls, bodies = self.run_held("<!-- held finding -->\n<!-- held finding -->\nproject: libreac\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        run, _, bodies = self.run_held("<!-- held finding -->\n")
        self.assertEqual((run.returncode, bodies), (0, []))
        eleven = "".join(f"<!-- held finding -->\ntitle: t{i}\nproject: libreac SECRET{i}\n" for i in range(11))
        run, calls, bodies = self.run_held(eleven)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        self.assertIn(f"held finding key: {self.OBJECT} all\n", bodies[0])
        self.assertIn("SECRET10", bodies[0])

    def test_a_long_finding_goes_whole_in_parts_and_a_re_run_posts_only_the_missing_ones(self):
        # 130,000 bytes in lines of 1,000: the issue and two comments, each at most 60,000 bytes, which hold it all.
        long = "".join(f"{i:05d}" + "x" * 994 + "\n" for i in range(130))
        run, calls, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + long + "END-OF-FINDING\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 3)
        self.assertTrue(all(len(b.encode()) <= 60500 for b in bodies))
        self.assertIn("(Part 1 of 3: the rest follows in the comments.)", bodies[0])
        self.assertTrue(bodies[1].startswith(f"held finding part: {self.OBJECT} 1 2/3\n"))
        self.assertIn("END-OF-FINDING", bodies[2])
        joined = "".join(bodies)
        self.assertTrue(all(f"{i:05d}" in joined for i in range(130)))
        self.assertEqual([c[1] for c in calls if "-F" in c][1:], ["repos/theorem-labs/private/issues/42/comments"] * 2)
        # A run that stopped after part 2: the next posts only part 3, on the issue that is there.
        run, calls, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + long + "END-OF-FINDING\n",
                                           bodies_on_github=[self.body(f"held finding key: {self.OBJECT} 1")],
                                           comments=[f"held finding part: {self.OBJECT} 1 2/3\n\n..."])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 1)
        self.assertTrue(bodies[0].startswith(f"held finding part: {self.OBJECT} 1 3/3\n"))
        self.assertEqual([c[1] for c in calls if "-F" in c], ["repos/theorem-labs/private/issues/1/comments"])

    @staticmethod
    def finding_of(issue_body, comment_bodies):
        """The finding as the disclosure route reads it back: the issue after its five lines, without the part note,
        then each comment after its part line and the blank line."""
        text = issue_body.split("\n", 5)[5]
        text = re.sub(r"\n\n\(Part 1 of \d+: the rest follows in the comments\.\)\n$", "", text)
        return text + "".join(c.split("\n", 2)[2] for c in comment_bodies)

    def test_a_long_finding_comes_back_byte_for_byte_whatever_the_comment_address(self):
        # Run 1 finds no review comment yet (the long fallback text) and stops after part 2. Run 2 finds the comment
        # (a short address) and posts the rest. The parts must join to the finding exactly.
        # Short lines, so that a change of a few bytes in the lines the script adds would move where a part ends.
        lines = [f"{i:05d} " + "é" * (i % 7) + "y" * (30 + i % 13) + "\n" for i in range(2800)]
        finding = "".join(lines) + "END-OF-FINDING\n"
        held = "<!-- held finding -->\ntitle: big\n" + finding
        run, _, first = self.run_held(held)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertGreater(len(first), 2)
        self.assertEqual(self.finding_of(first[0], first[1:]), finding)
        issue = first[0].replace("public PR comment: not posted yet: the review comment on theorem-labs/oss-verify#68",
                                 "public PR comment: https://example.test/c")
        run, _, second = self.run_held(held, bodies_on_github=[issue], comments=first[1:2],
                                       public_comments=[("oss-verify[bot]", "<!-- oss-verify-review -->\nx",
                                                         "https://example.test/c")])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(second, first[2:])
        self.assertEqual(self.finding_of(first[0], first[1:2] + second), finding)

    def test_only_the_first_title_line_leaves_the_finding(self):
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: crash in f\nlog:\ntitle: from the input\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.finding_of(bodies[0], []), "log:\ntitle: from the input\n")

    def test_a_line_longer_than_a_part_is_cut_between_characters(self):
        # One long line of two-, three- or four-byte characters, after a prefix of 0 to 3 bytes, so that byte 60,000
        # falls at every place inside a character. The stand-in stores bytes that are not UTF-8 as U+FFFD, as GitHub.
        for char in ("é", "€", "😀"):
            for prefix in range(4):
                with self.subTest(char=char, prefix=prefix):
                    finding = "x" * prefix + char * (130000 // len(char.encode())) + "\n"
                    run, _, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + finding)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(len(bodies), 3)
                    self.assertNotIn("\ufffd", "".join(bodies))
                    self.assertEqual(self.finding_of(bodies[0], bodies[1:]), finding)

    def test_a_part_ends_at_a_line_end_when_the_line_fits(self):
        finding = "".join(f"{i:05d} " + "y" * 994 + "\n" for i in range(130))
        run, _, bodies = self.run_held("<!-- held finding -->\ntitle: big\n" + finding)
        self.assertEqual(run.returncode, 0, run.stderr)
        texts = [re.sub(r"\n\n\(Part 1 of \d+: the rest follows in the comments\.\)\n$", "",
                        bodies[0].split("\n", 5)[5])] + [b.split("\n", 2)[2] for b in bodies[1:]]
        self.assertTrue(all(t.endswith("\n") and t.split("\n")[0][:5].isdigit() for t in texts), texts[1][:20])

    def test_the_public_comment_is_the_bots_review_comment_of_the_pull_request(self):
        # Another user's comment with the marker, the bot's other comment, then the bot's review comment; and a comment
        # with the marker on the private repository's issue, which is not the pull request's.
        public = [("someone", "<!-- oss-verify-review -->\nfake", "https://example.test/other-user"),
                  ("oss-verify[bot]", "Thanks for the enrollment.", "https://example.test/other-bot-comment"),
                  ("oss-verify[bot]", "Quoted: <!-- oss-verify-review -->", "https://example.test/quoting-comment"),
                  ("oss-verify[bot]", "<!-- oss-verify-review -->\nreview", "https://example.test/review-comment"),
                  ("oss-verify[bot]", "<!-- oss-verify-review -->\nlater", "https://example.test/later-comment")]
        run, calls, bodies = self.run_held(ReviewRun.HELD, public_comments=public,
                                           comments=["<!-- oss-verify-review -->\nprivate"])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(bodies[0].split("\n")[2], "public PR comment: https://example.test/review-comment")
        lookups = [c for c in calls if c[1].endswith("/comments") and "-F" not in c]
        self.assertEqual([c[1] for c in lookups], ["repos/theorem-labs/oss-verify/issues/68/comments"])
        # It reads the public comments with the token for this repository, not the App's token for the private one,
        # and every call to the private repository uses the App's token.
        tokens = dict(zip(map(json.dumps, calls), run.tokens))
        self.assertEqual(tokens[json.dumps(lookups[0])], "read-not-a-secret")
        self.assertEqual({t for c, t in zip(calls, run.tokens) if "theorem-labs/private" in c[1]}, {"app-not-a-secret"})

    def test_a_loose_marker_splits_findings_as_review_run_cuts_them(self):
        run, _, bodies = self.run_held("  - <!--Held Finding-->\nproject: a\n> <!-- held_finding -->\nproject: b\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(bodies), 2)

    def test_without_a_private_repository_or_a_held_object_it_fails(self):
        run, calls, _ = self.run_held(ReviewRun.HELD, variable="")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(calls, [])
        for visibility in ("public", "internal", ""):
            with self.subTest(visibility=visibility):
                run, calls, _ = self.run_held(ReviewRun.HELD, visibility=visibility)
                self.assertEqual(run.returncode, 2)
                self.assertIn("names is not private, so nothing is sent", run.stderr)
                self.assertFalse([c for c in calls if "-F" in c or "-f" in c])
        self.OBJECT = "held/7/short"
        run, calls, _ = self.run_held(ReviewRun.HELD)
        self.assertEqual((run.returncode, calls), (2, []))

    def test_an_object_that_does_not_start_with_the_workflows_lines_is_sent_whole(self):
        for header in ("", "oss-verify held finding v1\npr: 68\nhead: x\nproject: libreac\nrun: r\n---\n",
                       self.HEADER.replace("runs/7", "runs/8")):
            with self.subTest(header=header):
                run, calls, bodies = self.run_held(ReviewRun.HELD, header=header)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(len(bodies), 1)
                self.assertIn(f"held finding key: {self.OBJECT} raw\n", bodies[0])
                self.assertIn("SECRETBUG", bodies[0])

    def test_the_finding_reaches_the_hold_job_only_through_the_private_bucket(self):
        jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]
        text = (ROOT / ".github" / "workflows" / "build.yaml").read_text()
        # No job holds the App's key as a repository secret, and nothing reads a variable for the repository.
        self.assertNotIn("OSS_VERIFY_APP_PRIVATE_KEY", text)
        self.assertNotIn("HELD_FINDINGS_REPO }}", text)
        review = {s.get("name"): s for s in jobs["review"]["steps"]}
        store = review["Store the held finding for the hold job"]["run"]
        self.assertIn("ifGenerationMatch=0", store)
        self.assertIn('name="held/$RUN_ID/$(openssl rand -hex 16)"', store)
        self.assertIn("oss-verify held finding v1", store)
        self.assertEqual(jobs["review"]["outputs"]["held_object"], "${{ steps.held.outputs.object }}")
        # The review job passes names only: no output holds a file's text or the finding.
        self.assertNotIn("held-finding.md", json.dumps(jobs["review"]["outputs"]))
        # The finding is stored also when the review job fails after cutting it out (a comment that still names it).
        for name in ("Sign in to Google Cloud to store the held finding", "Store the held finding for the hold job"):
            self.assertEqual(review[name]["if"], "${{ always() && steps.review.outputs.held == 'yes' }}")
        self.assertLess(review["Review"]["run"].index("held=yes"), review["Review"]["run"].index("exit \"$code\""))
        hold = jobs["hold"]
        self.assertEqual(hold["environment"], {"name": "comment", "deployment": False})
        self.assertEqual(hold["needs"], ["project-builds", "review"])
        # Every run that reviewed anything sweeps the bucket, so a cancelled run's finding goes with the next run.
        self.assertEqual(hold["if"], "${{ !cancelled() && needs.review.result != 'skipped' }}")
        # One sweep at a time in the repository; every waiting one keeps its place, so none is cancelled by another.
        self.assertEqual(hold["concurrency"], {"group": "build-hold", "cancel-in-progress": False, "queue": "max"})
        steps = {s.get("name"): s for s in hold["steps"]}
        where = steps["Where the held findings go"]["run"]
        self.assertIn("secrets/oss-verify-held-findings-repo/versions/latest:access", where)
        self.assertLess(where.index("::add-mask::"), where.index('echo "name=$name"'))
        token = steps["Get the oss-verify App's token for the held findings' repository"]["with"]
        self.assertEqual((token["owner"], token["repositories"], token["permission-issues"]),
                         ("${{ github.repository_owner }}", "${{ steps.where.outputs.name }}", "write"))
        send = steps["Send every stored held finding to the disclosure route"]
        self.assertEqual(send["run"], '.github/scripts/review-hold "$RUNNER_TEMP/held"')
        self.assertEqual(send["env"]["CURRENT_OBJECT"], "${{ needs.review.outputs.held_object }}")
        # The comment job posts no review unless the review job succeeded and, if it held a finding, hold sent it.
        self.assertIn("hold", jobs["comment"]["needs"])
        self.assertEqual(jobs["comment"]["steps"][-1]["env"]["REVIEW"],
                         "${{ needs.review.result == 'success' && (needs.review.outputs.held_object == '' || "
                         "needs.hold.result == 'success') && needs.review.outputs.comment || '' }}")


class ReviewHold(unittest.TestCase):
    """review-hold sends every stored finding in the bucket, its own run's and a cancelled run's, through a fake curl for
    the bucket and a stand-in review-held, and deletes each object once it is sent."""

    def sweep(self, objects, held_fails=(), delete_fails=False, current="", gone=(), sizes=None, cut=(), late=()):
        """objects: name -> stored bytes. held_fails: names whose review-held fails. current: this run's object. gone:
        names another hold job deleted (404). sizes: name -> the size the listing reports. cut: names whose download
        the connection cuts after the 200 line (half the bytes, curl exit 18). late: names whose download has every
        byte but curl still exits 18 (the connection fails at the end)."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy(ROOT / ".github" / "scripts" / "review-hold", scripts / "review-hold")
            (root / "store").mkdir()
            listing = {"items": [{"name": n, "generation": str(100 + i), "size": str((sizes or {}).get(n, len(b)))}
                                 for i, (n, b) in enumerate(objects.items())]}
            (root / "listing.json").write_text(json.dumps(listing))
            for name, data in objects.items():
                (root / "store" / name.replace("/", "%2F")).write_bytes(data)
            # review-held stand-in: records the object it was given, and fails for the names in held_fails.
            (scripts / "review-held").write_text(
                f"#!/bin/bash\necho \"$HELD_OBJECT $(head -c 20 \"$1/object\")\" >> {root}/sent\n"
                f"case \"$HELD_OBJECT\" in {'|'.join(held_fails) or 'none'}) exit 1 ;; esac\n")
            (scripts / "review-held").chmod(0o755)
            bin = root / "bin"
            bin.mkdir()
            (bin / "curl").write_text(
                f"#!{sys.executable}\nimport pathlib, sys, urllib.parse\nroot = pathlib.Path({str(root)!r})\n"
                "a = sys.argv[1:]\nurl = a[-1]\n"
                "with open(root / 'curl', 'a') as f: f.write(' '.join(a) + '\\n')\n"
                "if '-X' in a and a[a.index('-X') + 1] == 'DELETE':\n"
                f"    sys.exit(22 if {delete_fails} else 0)\n"
                "if '?prefix=' in url: print((root / 'listing.json').read_text()); sys.exit(0)\n"
                "name = url.split('/o/')[1].split('?')[0]\n"
                f"if urllib.parse.unquote(name) in {list(gone)!r}: print('404', end=''); sys.exit(0)\n"
                "data = (root / 'store' / name).read_bytes()\n"
                f"if urllib.parse.unquote(name) in {list(cut) + list(late)!r}:\n"
                f"    keep = data if urllib.parse.unquote(name) in {list(late)!r} else data[:len(data) // 2]\n"
                "    pathlib.Path(a[a.index('-o') + 1]).write_bytes(keep); print('200', end='')\n"
                "    sys.exit(18)\n"
                "pathlib.Path(a[a.index('-o') + 1]).write_bytes(data)\n"
                "print('200', end='')\n")
            (bin / "curl").chmod(0o755)
            run = subprocess.run([str(scripts / "review-hold"), str(root / "work")],
                                 env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}",
                                      "GCP_ACCESS_TOKEN": "gcp-not-a-secret", "CURRENT_OBJECT": current},
                                 capture_output=True, text=True)
            sent = (root / "sent").read_text().splitlines() if (root / "sent").exists() else []
            curl = (root / "curl").read_text()
            return run, sent, curl

    def test_a_cancelled_runs_finding_is_sent_by_the_next_run_and_both_are_deleted(self):
        mine, cancelled = "held/9/" + "a" * 32, "held/8/" + "b" * 32
        run, sent, curl = self.sweep({cancelled: b"oss-verify held finding v1\n", mine: b"oss-verify held finding v1\n"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sorted(s.split()[0] for s in sent), sorted([mine, cancelled]))
        self.assertEqual(curl.count("-X DELETE"), 2)
        self.assertIn(f"sent and deleted {cancelled}", run.stdout)
        self.assertNotIn("gcp-not-a-secret", curl)

    def test_only_this_runs_own_object_fails_the_job(self):
        mine, other = "held/9/" + "a" * 32, "held/8/" + "b" * 32
        # Another run's object that cannot be sent is a warning; this run's is a failure.
        run, sent, curl = self.sweep({other: b"x", mine: b"x"}, held_fails=(other,), current=mine)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(curl.count("-X DELETE"), 1)
        self.assertIn(f"::warning::review-hold: could not send {other}", run.stdout)
        run, sent, curl = self.sweep({other: b"x", mine: b"x"}, held_fails=(mine,), current=mine)
        self.assertEqual(run.returncode, 1)
        self.assertIn(f"could not send {mine}, this run's own finding", run.stderr)

    def test_this_runs_object_goes_first_and_the_cap_leaves_the_rest(self):
        mine = "held/99/" + "f" * 32
        objects = {f"held/{i}/" + "a" * 32: b"x" for i in range(25)}
        objects[mine] = b"x"
        run, sent, curl = self.sweep(objects, current=mine)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sent[0].split()[0], mine)
        self.assertEqual(len(sent), 20)
        self.assertIn("more than 20 stored findings", run.stdout)

    def test_an_object_another_hold_job_sent_is_gone_not_failed(self):
        mine = "held/9/" + "a" * 32
        run, sent, curl = self.sweep({mine: b"x"}, current=mine, gone=(mine,))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sent, [])
        self.assertIn(f"{mine} is no longer in the bucket", run.stdout)

    def test_a_cut_download_is_not_sent_or_deleted(self):
        # curl exit 18 after the 200 line, and a download shorter than the listing's size with exit 0.
        mine = "held/9/" + "a" * 32
        for kwargs in ({"cut": (mine,)}, {"late": (mine,)}, {"sizes": {mine: 40}}):
            with self.subTest(kwargs=kwargs):
                run, sent, curl = self.sweep({mine: b"oss-verify held finding v1\n" + b"y" * 20}, current=mine,
                                             **kwargs)
                self.assertEqual(run.returncode, 1)
                self.assertEqual(sent, [])
                self.assertNotIn("-X DELETE", curl)

    def test_a_sent_object_that_cannot_be_deleted_does_not_fail_the_job(self):
        run, sent, curl = self.sweep({"held/9/" + "a" * 32: b"x"}, delete_fails=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("could not delete it: the next run finds its issues and sends nothing twice", run.stdout)

    def test_an_object_that_is_not_a_held_finding_or_too_large_is_skipped(self):
        big = "held/9/" + "c" * 32
        run, sent, curl = self.sweep({"held/9/short": b"x", "other/9/" + "a" * 32: b"x", big: b"x"},
                                     sizes={big: 1100001})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sent, [])
        self.assertEqual(run.stdout.count("skipped an object that is not a held finding"), 3)

    def test_the_object_is_read_at_its_listed_generation(self):
        run, sent, curl = self.sweep({"held/9/" + "a" * 32: b"x"})
        self.assertIn("alt=media&generation=100", curl)
        self.assertIn("--max-filesize 1100000", curl)


class SinceLastReview(unittest.TestCase):
    """review-gather writes the diff since the last review's commit only when the head descends from it."""

    def gathered(self, status):
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        keep = re.search(r"^keep\(\) \{.*\}$", gather, re.M).group(0)
        block = gather[gather.index("since=$(sed"):gather.index('ls -la "$out"')]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for sub in ("bin", "out", "session"):
                (root / sub).mkdir()
            (root / "session" / "session").write_text(f"id=x\nhead={'2' * 40}\ndir=-x\n")
            # gh: the compare's status for --jq .status, else a diff of the project and of another file.
            gh = root / "bin" / "gh"
            gh.write_text("#!/bin/bash\n"
                          f'case "$*" in *"--jq .status"*) echo "{status}" ;;\n'
                          '  *) printf "diff --git a/projects/p/f b/projects/p/f\\n+x\\ndiff --git a/o b/o\\n+y\\n" ;;\n'
                          "esac\n")
            gh.chmod(0o755)
            run = subprocess.run(["bash", "-c", f"set -euo pipefail\nout={root / 'out'}\ndir=projects/p\n{keep}\n{block}"],
                                 env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "REPO": "o/r",
                                      "HEAD_SHA": "1" * 40, "REVIEW_SESSION": str(root / "session")},
                                 capture_output=True, text=True)
            diff = root / "out" / "since-last-review.diff"
            return run, diff.read_text() if diff.exists() else None

    def test_a_head_that_descends_gets_the_projects_diff(self):
        run, diff = self.gathered("ahead")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(diff, "diff --git a/projects/p/f b/projects/p/f\n+x\n(exit status 0)\n")

    def test_a_force_push_or_the_same_head_gets_no_diff(self):
        # A three-dot compare after a force-push diffs from the merge base: it can show nothing that changed.
        for status in ("diverged", "behind", "identical", ""):
            with self.subTest(status=status):
                run, diff = self.gathered(status)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIsNone(diff)
                self.assertIn(f"does not descend from {'2' * 40}", run.stdout)


class ReviewSessionStore(unittest.TestCase):
    """build.yaml keeps the review's session in the Actions cache: the review job reads it, the keep job alone writes
    it, and only review.md has an owner in CODEOWNERS."""

    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        self.jobs = self.workflow["jobs"]

    def test_only_the_review_job_reads_the_cache_and_only_the_keep_job_writes_it(self):
        self.assertEqual(self.workflow["cache-mode"], "none")
        self.assertEqual({name: job["cache-mode"] for name, job in self.jobs.items() if "cache-mode" in job},
                         {"review": "read", "keep": "write-only"})
        key = ("enroll-review/${{ github.event.pull_request.number || inputs.pr }}/"
               "${{ needs.project-builds.outputs.name }}/${{ github.run_id }}-${{ github.run_attempt }}")
        [restore] = [s for s in self.jobs["review"]["steps"] if "actions/cache" in s.get("uses", "")]
        self.assertTrue(restore["uses"].startswith("actions/cache/restore@"))
        self.assertEqual(restore["with"]["key"], key)
        self.assertEqual(restore["with"]["restore-keys"], key.rsplit("/", 1)[0] + "/")
        keep = self.jobs["keep"]
        self.assertEqual(keep["permissions"], {})
        self.assertNotIn("environment", keep)
        # No script and no checkout: the artifact the review job handed it, saved under the same key.
        self.assertEqual([s["uses"].split("@")[0] for s in keep["steps"]],
                         ["actions/download-artifact", "actions/cache/save"])
        self.assertFalse([s for s in keep["steps"] if "run" in s])
        self.assertEqual(keep["steps"][1]["with"]["key"], key)
        self.assertEqual(keep["steps"][0]["with"]["name"], "${{ needs.review.outputs.artifact }}")

    def test_no_step_holds_a_key_for_the_session(self):
        text = (ROOT / ".github" / "workflows" / "build.yaml").read_text()
        self.assertNotIn("REVIEW_CONVERSATION_KEY", text)
        self.assertFalse((ROOT / ".github" / "scripts" / "review-session").exists())

    def test_review_md_and_codeowners_are_the_only_files_with_an_owner_and_the_last_patterns(self):
        lines = [line.split() for line in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        owned = [["/review.md", "@theorem-labs/engineering"], ["/.github/CODEOWNERS", "@theorem-labs/engineering"]]
        self.assertEqual([line for line in lines if len(line) > 1], owned)
        self.assertEqual(lines[-2:], owned)
        self.assertTrue((ROOT / "review.md").is_file())


@unittest.skipUnless(shutil.which("openssl"), "the review step needs openssl")
class ReviewStep(unittest.TestCase):
    """build.yaml's own Review step, over a stand-in review-run that fails: what the run's page and summary say."""

    TOKEN = "collector-token-not-a-secret"

    def run_step(self, code, failure=None, detail=None, scan=True, served=None, output=None, secret_manager=True,
                 secret=None, signed_in=True, lost=None, trace=None, raw_answer=None):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / ".github" / "scripts").mkdir(parents=True)
            if scan:
                shutil.copy(REVIEW_COMMENT, directory / ".github" / "scripts" / "review-comment")
            (directory / ".review").mkdir()
            # What review-run leaves when the review is written.
            (directory / ".review" / "comment.md").write_text("Thanks.\n")
            if lost is not None:
                (directory / ".review" / "export-lost.txt").write_text(lost)
            script = directory / ".github" / "scripts" / "review-run"
            # It announces itself and says what it inherited: never the Google access token, always the collector's
            # token when there is one. So a test can tell that the review ran, and with what.
            script.write_text("#!/bin/bash\necho review-run: ran\necho \"review-run: gcp=${GCP_ACCESS_TOKEN-unset} "
                              f"otel=${{OTEL_COLLECTOR_TOKEN:+set}}\"\nexit {code}\n")
            script.chmod(0o755)
            for name, text in (("failure.txt", failure), ("failure-detail.txt", detail), ("served", served)):
                if text is not None:
                    (directory / ".review" / name).write_text(text)
            token = directory / "jwt"
            token.write_text("jwt-0\n")
            (directory / "summary").write_text("")
            # A stand-in curl for Secret Manager's access call: the token as the API gives it, or the failure curl -f
            # gives for an error status.
            bin = directory / "bin"
            bin.mkdir()
            value = self.TOKEN if secret is None else secret
            payload = raw_answer if raw_answer is not None else \
                json.dumps({"payload": {"data": base64.b64encode(value.encode()).decode()}})
            # A curl that is called when it must not be leaves a mark the tests read.
            (bin / "curl").write_text(f"#!/bin/bash\ntouch {shlex.quote(str(directory / 'curl-called'))}\n"
                                      + (f"printf '%s' {shlex.quote(payload)}\n" if secret_manager else "exit 22\n"))
            (bin / "curl").chmod(0o755)
            environment = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}",
                           "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
                           "GCP_ACCESS_TOKEN": "gcp-not-a-secret" if signed_in else "",
                           "ANTHROPIC_IDENTITY_TOKEN_FILE": str(token), "GITHUB_OUTPUT": str(directory / "output"),
                           "GITHUB_STEP_SUMMARY": str(directory / "summary")}
            # With trace, the step runs under strace, and the trace of every program it starts is appended to it.
            prefix = ["strace", "-f", "-qq", "-s", "65536", "-e", "trace=execve", "-o", str(directory / "trace")] \
                if trace is not None else []
            run = subprocess.run(prefix + ["bash", "--noprofile", "--norc", "-e", "-c", review_step()["run"]],
                                 cwd=directory, env=environment, capture_output=True, text=True)
            if trace is not None:
                trace.append((directory / "trace").read_text() + "\n" + run.stderr)
            self.assertFalse(token.exists(), "the identity token file is removed")
            self.curl_called = (directory / "curl-called").exists()
            if output is not None:
                output.append((directory / "output").read_text() if (directory / "output").exists() else "")
            return run.returncode, run.stdout, (directory / "summary").read_text()

    def test_no_ending_of_the_review_step_puts_a_credential_in_an_argument(self):
        # Every ending of the step, under strace: a review that finished, one that did not (with a message to scan),
        # one that was refused, and a lost export. The collector token, its base64 form and the access token must be
        # in no program's arguments and nowhere on stderr.
        if not shutil.which("strace"):
            self.skipTest("strace is not installed (the tests workflow installs it)")
        secrets = [self.TOKEN, base64.b64encode(self.TOKEN.encode()).decode(), "gcp-not-a-secret"]
        lost = "the cost collector answered 401, not 200, before the review, so its usage is not exported\n"
        for code, failure, detail, served in ((0, None, None, None), (1, "plain words\n", "API Error: x\n", None),
                                              (4, "the review is not published: x\n", None, SERVED_OTHER),
                                              (0, None, None, SERVED_OK)):
            with self.subTest(code=code, served=bool(served)):
                traces = []
                self.run_step(code, failure, detail, served=served, lost=lost, trace=traces)
                self.assertIn("execve(", traces[0])
                self.assertIn("review-run", traces[0], "the stand-in review-run was not started")
                for secret in secrets:
                    self.assertNotIn(secret, traces[0], f"exit {code}: a credential is in an argument or on stderr")

    def test_a_response_with_no_payload_is_no_token(self):
        # Secret Manager answering 200 with no payload (or a payload of null) must give the warning, never a token
        # made of "null" or an empty string.
        for body in ('{}', '{"payload": {}}', '{"payload": {"data": null}}', '{"payload": {"data": ""}}'):
            with self.subTest(body=body):
                code, out, _ = self.run_step(0, raw_answer=body)
                self.assertEqual(code, 0, out)
                self.assertIn("::warning::Could not read the cost collector's token", out)
                self.assertIn("review-run: gcp=unset otel=\n", out)

    def test_a_token_that_cannot_be_read_does_not_stop_the_review(self):
        # Fail-soft: the export is a measurement. A read that fails, a value of whitespace alone, or a sign-in that
        # gave no access token is one warning; the review runs without the token and the step's result is the review's.
        warning = "::warning::Could not read the cost collector's token"
        for case in ({"secret_manager": False}, {"secret": "\n\n"}, {"secret": " \t\n"}, {"signed_in": False}):
            with self.subTest(**case):
                code, out, summary = self.run_step(0, **case)
                self.assertEqual(code, 0, out)
                self.assertIn(warning, out)
                self.assertNotIn("::error::", out)
                self.assertIn("review-run: ran\n", out)
                self.assertIn("review-run: gcp=unset otel=\n", out)
                self.assertEqual(summary, "")
                if case == {"signed_in": False}:
                    self.assertFalse(self.curl_called, "Secret Manager is called with no access token")
                # A line of spaces alone is never sent to ::add-mask::, which the runner answers with a warning.
                self.assertNotRegex(out, r"(?m)^::add-mask::\s*$")
        # The review's own failure still fails the step.
        code, _, _ = self.run_step(1, "plain words\n", secret_manager=False)
        self.assertEqual(code, 1)

    def test_the_sign_in_never_fails_the_review_job(self):
        steps = {s.get("name"): s for s in yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
                 ["jobs"]["review"]["steps"]}
        self.assertIs(steps["Sign in to Google Cloud"].get("continue-on-error"), True)

    def test_the_token_read_is_masked(self):
        code, out, summary = self.run_step(0)
        self.assertEqual(code, 0, out)
        self.assertIn(f"::add-mask::{self.TOKEN}\n", out)
        self.assertIn("review-run: gcp=unset otel=set\n", out)
        self.assertNotIn("::warning::", out)
        # The mask must be registered while the runner still reads commands: after ::stop-commands:: it would be
        # plain text, and the token in it would be in the public log.
        self.assertLess(out.index(f"::add-mask::{self.TOKEN}\n"), out.index("::stop-commands::"))
        self.assertEqual(out.count(self.TOKEN), 1, "the token appears outside its mask line")

    def test_a_lost_export_is_a_warning_on_the_run_page_and_changes_nothing(self):
        lost = "the cost collector answered 401, not 200, before the review, so its usage is not exported\n"
        for code in (0, 1):
            with self.subTest(code=code):
                status, out, _ = self.run_step(code, "plain words\n", lost=lost)
                self.assertEqual(status, code)
                warning = f"::warning::Usage export: {lost.strip()}.\n"
                self.assertIn(warning, out)
                # After the runner reads commands again, or the warning would be plain text in the log.
                resume = re.search(r"^::stop-commands::([0-9a-f]{32})$", out, re.M).group(1)
                self.assertLess(out.index(f"::{resume}::\n"), out.index(warning))
        # A line that is not plain words is never shown, so review-run's file cannot carry a workflow command.
        status, out, _ = self.run_step(0, lost="::error::x\n")
        self.assertEqual(status, 0)
        self.assertNotIn("Usage export", out)
        self.assertNotIn("::error::x", out)
        status, out, _ = self.run_step(0)
        self.assertEqual(status, 0)
        self.assertNotIn("Usage export", out)

    def test_every_line_review_run_writes_passes_the_steps_filter(self):
        # review-run writes export-lost.txt and the Review step shows it only if it matches its filter, so the two are
        # tied by text: a reworded line that the filter refused would drop the warning with no failing test. Each
        # line review-run can write, with each answer the collector can give, must pass the filter as it is.
        script = (ROOT / ".github" / "scripts" / "review-run").read_text()
        lines = []
        for chunk in re.findall(r'echo ("the cost collector answered.*?)\s*> "\$in/export-lost\.txt"', script, re.S):
            lines.append(" ".join(re.findall(r'"([^"]*)"', chunk)))
        self.assertEqual(len(lines), 2, "review-run writes export-lost.txt in two places")
        pattern = re.search(r"grep -m1 -xE '([^']*)' \.review/export-lost\.txt", review_step()["run"]).group(1)
        for written in lines:
            for answer in ("401", "403", "500", "000", "nothing"):
                line = written.replace("${answer:-nothing}", answer)
                self.assertRegex(line, "^" + pattern + "$", line)

    def test_a_review_that_did_not_finish_says_why_in_the_summary(self):
        code, out, summary = self.run_step(1, WHY_401 + ", on both tries\n", API_401[0]["result"] + "\n")
        self.assertEqual(code, 1)
        self.assertIn(f"::error::The review did not finish: {WHY_401}, on both tries\n", out)
        self.assertIn("### The review did not finish\n", summary)
        self.assertIn(f"\n{WHY_401}, on both tries.\n", summary)
        self.assertIn("\n```\nAPI Error: Token exchange failed with status 401", summary)

    def test_the_summary_shows_no_other_text(self):
        # A failure.txt line that is not plain words is not shown, and Claude Code's message cannot leave its code
        # block or carry the collector's token.
        generic = "review-run ended with exit status 1 before Claude Code wrote a result"
        for failure, detail, shown in (
                (None, None, generic), ("::warning::x\n", None, generic), ("x" * 201 + "\n", None, generic),
                ("plain words\n", "a\n```\n# Heading `x`\n", "plain words")):
            with self.subTest(failure=failure, detail=detail):
                code, out, summary = self.run_step(1, failure, detail)
                self.assertEqual(code, 1)
                self.assertIn(f"::error::The review did not finish: {shown}\n", out)
                self.assertNotIn("::warning::", out + summary)
                self.assertEqual(summary.count("```"), 2 if detail else 0, summary)
                self.assertNotIn("\n# Heading", summary)
        _, _, summary = self.run_step(1, "plain words\n", "it was collector-token-not-a-secret\n")
        self.assertNotIn("collector-token-not-a-secret", summary)
        self.assertNotIn("```", summary)

    def test_a_review_that_is_not_published_says_what_answered(self):
        why = ("the review is not published: it asked for anthropic/claude-opus-5-5, which the tool calls "
               "firstParty/claude-opus-5-5, but bedrock/claude-opus-5-5 (2 turns) answered, and the tool's usage names "
               "bedrock/claude-opus-5-5")
        output = []
        code, out, summary = self.run_step(4, why + "\n", served=SERVED_OTHER, output=output)
        self.assertEqual(code, 4)
        self.assertIn(f"::error::T{why[1:]}\n", out)
        self.assertEqual(summary, f"### The review is not published\n\n    {why}\n")
        self.assertRegex(output[0], r"(?m)^served<<(served-[0-9a-f]{32})\n" + re.escape(SERVED_OTHER) + r"\n\1$")
        self.assertIn("refused=true\n", output[0])
        _, out, _ = self.run_step(4, "::warning::x\n")
        self.assertIn("::error::The review is not published: review-run gave no reason\n", out)

    def test_the_record_of_what_answered_reaches_the_comment_job_whatever_the_ending(self):
        for code in (0, 1, 4):
            with self.subTest(code=code):
                output = []
                self.run_step(code, "plain words\n", served=SERVED_OK, output=output)
                self.assertIn(SERVED_OK, output[0])

    def test_a_review_that_finished_writes_no_summary(self):
        # review-run returns 0 when the review is written, also when the collector refused its token: the export is
        # fail-soft, so the step passes and the comment is posted.
        code, out, summary = self.run_step(0)
        self.assertEqual((code, summary), (0, ""))
        self.assertNotIn("::error::", out)

    def test_a_message_that_holds_a_credential_is_not_in_the_summary(self):
        for detail in (f"API Error: {JWT}\n", "x" * 1100 + f" {JWT}\n", "it was collector-token-not-a-secret\n"):
            with self.subTest(detail=detail[:20]):
                code, out, summary = self.run_step(1, "plain words\n", detail)
                self.assertEqual(code, 1)
                self.assertIn("plain words.", summary)
                self.assertNotIn("```", summary)
                self.assertNotIn(JWT[:20], summary + out)
                # The step's own ::add-mask:: line is the runner's command that hides the token, never shown.
                shown = "".join(line for line in out.splitlines(True) if not line.startswith("::add-mask::"))
                self.assertNotIn("collector-token-not-a-secret", summary + shown)
        # If the scan cannot run, the message is not shown either.
        _, _, summary = self.run_step(1, "plain words\n", "API Error: harmless\n", scan=False)
        self.assertNotIn("harmless", summary)


# A JWT in the shape of a GitHub identity token, {"alg":"RS256"} and {"sub":"not-a-secret"}: not a real one.
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJub3QtYS1zZWNyZXQifQ.c2lnbmF0dXJlLW5vdC1yZWFs"
REVIEW_OK = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 31, "duration_ms": 250400,
             "result": "Thanks."}
# The result Claude Code wrote on #48, #49 and #50 when its second token exchange was refused.
API_401 = ({"type": "result", "subtype": "success", "is_error": True, "num_turns": 40, "duration_ms": 596000,
            "result": "API Error: Token exchange failed with status 401 (request-id req_x):\n"
                      '{"error":{"type":"authentication_error","message":"Authentication failed"}} Ensure your '
                      "federation rule matches your identity token."}, 1)
WHY_401 = "Claude Code ended with exit status 1, success after 40 turns and 596 seconds, and wrote no review"

if __name__ == "__main__":
    unittest.main()
