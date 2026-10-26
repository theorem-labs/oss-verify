# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check_checks.py and .github/scripts/review-comment and review-run that need no Docker:
python3 -m pytest tools/tests"""
import base64
import html.parser
import io
import itertools
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
    def comment(self, review, checks="### report\n", *extra):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md"), *extra],
                                  capture_output=True, text=True, check=True).stdout

    def kept(self, previous, head, run="https://github.com/theorem-labs/oss-verify/actions/runs/7"):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "previous.md").write_text(previous)
            return self.comment("", "### new report\n", "--head", head, "--run", run,
                                "--previous", str(pathlib.Path(directory) / "previous.md"))

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
        # A comment of main's renderer (review first, footer last) is sent back as it was, not written again.
        footer = review_comment.FOOTER.format(of=f"It is the review of `{'a' * 7}`. ")
        base = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
                f"{review_comment.HEADING}\n\nThanks.\n\n{review_comment.CHECKS_SUMMARY}\n\n### report\n\n"
                f"</details>\n\n{footer}\n")
        self.assertEqual(self.kept(base, "a" * 40), base)
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


class CredentialArguments(unittest.TestCase):
    """The workflow and its helpers give credentials to commands through env/pipes, never as a process's argument."""

    def test_build_yaml_keeps_the_three_credentials_out_of_argv(self):
        steps = [step for job in yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]
                 .values() for step in job["steps"] if "run" in step]
        for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OTEL_COLLECTOR_TOKEN"):
            used = 0
            for step in steps:
                variable = re.escape(f'"${name}"')
                # The forms a builtin or a pipe reads, not argv: printf into a process substitution, a test, a pattern.
                rest = re.sub(rf"<\(printf '[^']*' {variable}\)|\[ -[zn] {variable} \]|\*{variable}\*", "",
                              step["run"])
                used += step["run"].count(f"${name}")
                self.assertNotIn(f"${name}", rest, f"{step.get('name')}: ${name} is an argument")
            self.assertGreater(used, 0, name)

    def test_the_helpers_use_no_argv_form_for_the_github_token(self):
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        # env NAME=value puts the value in env's argument vector; -c http.extraheader= puts the header in git's.
        self.assertNotIn("env GITHUB_TOKEN=", gather)
        self.assertIn('GITHUB_TOKEN="${GH_TOKEN:-}" keep', gather)
        self.assertNotIn("-c http.extraheader=", take)
        self.assertIn("--config-env=http.extraheader=", take)

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


class PostingStep(unittest.TestCase):
    """build.yaml's own "Post the comment" step, run with a fake gh: what it sends GitHub."""
    OLD = "Thanks.\n\n1. Fix X.\n"

    def post(self, review, existing=True, previous=None, head="b" * 40, pr_head=None):
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
                previous = subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", "/dev/stdin", "--head",
                                           "a" * 40], input=self.OLD, capture_output=True, text=True, check=True).stdout
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
                           "RUN_URL": "https://github.com/o/r/actions/runs/7", "RUNNER_TEMP": str(directory / "temp"),
                           "GITHUB_OUTPUT": str(directory / "output")}
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=ROOT, env=environment, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            sent = directory / ("patch.json" if existing else "post.json")
            return json.loads(sent.read_text())["body"] if sent.exists() else None

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
        stored = subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", "/dev/stdin", "--head", "b" * 40],
                                input=self.OLD, capture_output=True, text=True, check=True).stdout
        once = self.post("", previous=stored)
        self.assertEqual(once, stored)
        self.assertEqual(self.post("", previous=once), stored)

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
               f"{review_comment.HEADING}\n\n" + "R" * 64_800 + "TAIL_END\n")
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
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md"), "--head", "a" * 40, *extra],
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
            'fi\n'
            'if [ -n "$id" ]; then\n'
            f'  mkdir -p "$HOME/.claude/projects/{self.FOLDER}"\n'
            f'  {{ echo "{{\\"resumed\\": \\"$resume\\"}}"; cat {self.directory}/said 2> /dev/null; }} \\\n'
            f'    > "$HOME/.claude/projects/{self.FOLDER}/$id.jsonl"\n'
            'fi\n'
            'echo \'{"is_error": false, "result": "Thanks."}\'\n')
        for script in bin.iterdir():
            script.chmod(0o755)
        (self.directory / "review").mkdir()
        (self.directory / "home").mkdir()
        self.session = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.session)

    def fake_claude(self, *calls, wait=0):
        """A claude that, on its call N, appends the identity token file's text to `tokens` (and again after `wait`
        seconds, as Claude Code reads it again for each exchange), then prints calls[N-1][0] as its result and exits
        with calls[N-1][1]."""
        for n, (result, status) in enumerate(calls, 1):
            (self.directory / f"result.{n}").write_text(json.dumps(result))
            (self.directory / f"status.{n}").write_text(str(status))
        (self.directory / "bin" / "claude").write_text(
            "#!/bin/bash\n"
            f"cd {self.directory}\n"
            "n=$(( $(cat calls 2> /dev/null || echo 0) + 1 )); echo $n > calls\n"
            'read_token() { { cat "$ANTHROPIC_IDENTITY_TOKEN_FILE"; echo; } >> tokens; }\n'
            f"read_token\n{f'sleep {wait}; read_token' if wait else ''}\n"
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
                "ANTHROPIC_API_KEY": "sk-ant-oat01-notasecret", "CLAUDE_CODE_EFFORT": "x",
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
        out = self.run_review(**self.collector(**self.identity()))
        self.assertEqual(out.returncode, 0, out.stderr)
        argv = (self.directory / "argv").read_text()
        self.assertIn("claude", argv)
        for secret in self.SECRETS:
            self.assertNotIn(secret, argv)
            self.assertNotIn(secret, out.stdout + out.stderr)
        child = self.child()
        self.assertEqual(set(child), {"PATH", "HOME", "LANG", "ANTHROPIC_API_KEY", "CLAUDE_CODE_EFFORT",
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

    def test_a_token_the_collector_refuses_stops_the_review(self):
        out = self.run_review(**self.collector(OTEL_COLLECTOR_TOKEN="wrong-token-not-a-secret"))
        self.assertEqual(out.returncode, 1)
        self.assertIn("answered 401", out.stderr)
        self.assertNotIn("wrong-token-not-a-secret", out.stdout + out.stderr)
        self.assertFalse((self.directory / "environ").exists())
        self.assertEqual(self.failure()[0], "the cost collector answered 401, not 200, to an empty export with "
                                            "OTEL_COLLECTOR_TOKEN before the review\n")

    def test_a_curlrc_never_prints_the_token(self):
        (self.directory / ".curlrc").write_text(f"verbose\ntrace-ascii {self.directory}/trace\n")
        out = self.run_review(**self.collector(CURL_HOME=str(self.directory)))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn(self.TOKEN, out.stdout + out.stderr)
        self.assertFalse((self.directory / "trace").exists())

    def test_a_token_refused_after_the_review_keeps_the_review_and_fails(self):
        self.answers = [200, 401]
        # With workload identity too: stopping the identity token loop at the end leaves the exit status as it is.
        out = self.run_review(**self.collector(**self.identity()))
        self.assertEqual(out.returncode, 3, out.stderr)
        self.assertIn("answered 401", out.stderr)
        self.assertIn("usage is likely lost", out.stderr)
        self.assertNotIn(self.TOKEN, out.stdout + out.stderr)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")

    def test_a_collector_that_does_not_answer_stops_the_review(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        out = self.run_review(**self.collector(OTEL_EXPORTER_OTLP_ENDPOINT=f"http://127.0.0.1:{port}"))
        self.assertEqual(out.returncode, 1)
        self.assertIn("answered 000", out.stderr)
        self.assertFalse((self.directory / "environ").exists())

    def test_without_the_collector_nothing_is_exported(self):
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(set(self.child()), {"PATH", "HOME", "LANG", "ANTHROPIC_API_KEY", "CLAUDE_CODE_EFFORT"})
        self.assertEqual(self.headers, [])

    def test_a_first_review_is_fresh_and_keeps_its_conversation(self):
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("a fresh review", out.stdout)
        [call] = self.claude_calls()
        self.assertNotIn("--resume", call)
        new = call[call.index("--session-id") + 1]
        self.assertEqual(self.kept(), ({"id": new, "head": self.HEAD, "dir": self.FOLDER}, '{"resumed": ""}\n'))
        self.assertIn(f"kept the conversation {new} of the review of {self.HEAD}", out.stdout)

    def test_a_later_review_resumes_the_last_conversation_in_a_fork(self):
        self.last_review()
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"resuming the conversation {self.OLD} of the review of {self.LAST}", out.stdout)
        [call] = self.claude_calls()
        self.assertEqual(call[call.index("--resume") + 1], self.OLD)
        self.assertIn("--fork-session", call)
        new = call[call.index("--session-id") + 1]
        self.assertNotEqual(new, self.OLD)
        prompt = call[call.index("-p") + 1]
        self.assertIn(f"you reviewed its commit {self.LAST[:12]}, and your last message", prompt)
        self.assertIn("review/since-last-review.diff", prompt)
        # The new conversation, which holds the last one, in place of it.
        self.assertEqual(self.kept(), ({"id": new, "head": self.HEAD, "dir": self.FOLDER},
                                       f'{{"resumed": "{self.OLD}"}}\n'))
        self.assertFalse((self.session / f"{self.OLD}.jsonl").exists())

    def test_a_conversation_that_cannot_be_resumed_gives_a_fresh_review(self):
        self.last_review()
        (self.directory / "fail-resume").touch()
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"the resumed review of the conversation {self.OLD} ended without a review: a fresh review",
                      out.stdout)
        self.assertIn("(try 2)", out.stdout)
        resumed, fresh = self.claude_calls()
        self.assertIn("--resume", resumed)
        self.assertNotIn("--resume", fresh)
        self.assertEqual(self.kept()[0]["id"], fresh[fresh.index("--session-id") + 1])

    def test_a_session_file_that_is_not_whole_gives_a_fresh_review(self):
        (self.session / "session").write_text(f"id=../../x\nhead={self.LAST}\ndir={self.FOLDER}\n")
        out = self.run_review(**self.resume())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("does not name a whole conversation", out.stdout)
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
        # file at its start and again 3 seconds later, with a new token due every second.
        self.fake_claude(({"is_error": False, "result": "Thanks."}, 0), wait=3)
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

    def test_the_file_tools_may_not_read_the_identity_token_or_runner_temp(self):
        # --restricted keeps Read, Glob and Grep in the checkout; the deny rule names the two directories too. Claude
        # Code reads `//` as the start of an absolute path in a rule (a `/` rule is relative to the project).
        temp = self.directory / "temp"
        self.fake_claude((REVIEW_OK, 0))
        out = self.run_review(**self.identity(RUNNER_TEMP=str(temp)))
        self.assertEqual(out.returncode, 0, out.stderr)
        argv = (self.directory / "argv").read_text().split("\0")
        at = argv.index("--disallowedTools")
        self.assertEqual(argv[at + 1:at + 3], [f"Read(/{temp}/**)", f"Read(/{self.directory / 'oidc'}/**)"])
        self.assertTrue(argv[at + 1].startswith("Read(//"))
        self.assertEqual(argv[at + 3], "--model")
        # A person's own run has neither directory, and no rule.
        for name in ("argv", "calls"):
            (self.directory / name).unlink()
        self.fake_claude((REVIEW_OK, 0))
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("--disallowedTools", (self.directory / "argv").read_text())

    def run_review_twice(self, *calls):
        for name in ("calls", "tokens"):
            (self.directory / name).unlink(missing_ok=True)
        self.fake_claude(*calls)
        return self.run_review(**self.identity())


def review_step():
    steps = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]["review"]["steps"]
    matches = [step for step in steps if step.get("id") == "review"]
    assert len(matches) == 1, matches
    return matches[0]


class ReviewSession(unittest.TestCase):
    """review-session seals the conversation for one pull request and project, and restores only what opens with the
    key from build.yaml's own runs and is of the review the review comment shows, through a fake gh that serves the
    GitHub API from files."""
    SCRIPT = ROOT / ".github" / "scripts" / "review-session"
    KEY = base64.b64encode(b"k" * 32).decode()
    ID = "0f97bfe1-152c-4ec0-a947-fb9d1ba5c35b"
    HEAD = "2" * 40
    FOLDER = "-home-runner-work-oss-verify-oss-verify"
    REPO = "theorem-labs/oss-verify"
    TOKEN = "ghs_notasecretnotasecret"
    ARTIFACTS = f"repos/{REPO}/actions/artifacts?name=enroll-review-8-libreac&per_page=100"
    COMMENTS = f"repos/{REPO}/issues/8/comments?per_page=100"

    def setUp(self):
        self.directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        (self.directory / "bin").mkdir()
        (self.directory / "api").mkdir()
        # gh api [--paginate --slurp] <path>: the file api/<path with / ? & = as _> (in a list, one page, with --slurp),
        # or exit 1 as gh does on a 404. Its arguments, its GH_TOKEN and whether it has the key are recorded.
        gh = self.directory / "bin" / "gh"
        gh.write_text(f"#!{sys.executable}\nimport os, pathlib, re, sys\n"
                      f"root = pathlib.Path({str(self.directory)!r})\n"
                      "with open(root / 'argv', 'a') as f: f.write(' '.join(sys.argv[1:]) + '\\n')\n"
                      "(root / 'gh-token').write_text(os.environ.get('GH_TOKEN', ''))\n"
                      "if 'REVIEW_CONVERSATION_KEY' in os.environ: (root / 'gh-had-the-key').touch()\n"
                      "page = root / 'api' / re.sub(r'[/?&=]', '_', sys.argv[-1])\n"
                      "if not page.exists(): sys.exit('gh: Not Found (HTTP 404)')\n"
                      "body = page.read_bytes()\n"
                      "sys.stdout.buffer.write(b'[' + body + b']' if '--slurp' in sys.argv else body)\n")
        gh.chmod(0o755)
        self.session = self.directory / "session"
        self.session.mkdir()
        (self.session / "session").write_text(f"id={self.ID}\nhead={self.HEAD}\ndir={self.FOLDER}\n")
        (self.session / f"{self.ID}.jsonl").write_text('{"said": "I asked for a seed corpus."}\n')
        self.artifacts = []
        self.comment(self.HEAD)
        self.page(f"repos/{self.REPO}", json.dumps({"default_branch": "main"}).encode())

    def run_session(self, *arguments, **environment):
        base = {"PATH": f"{self.directory / 'bin'}:{os.environ['PATH']}", "REPO": self.REPO, "PR": "8",
                "NAME": "libreac", "REVIEW_CONVERSATION_KEY": self.KEY, "GH_TOKEN": self.TOKEN}
        return subprocess.run([str(self.SCRIPT), *arguments], env={**base, **environment}, capture_output=True,
                              text=True)

    def page(self, path, body):
        (self.directory / "api" / re.sub(r"[/?&=]", "_", path)).write_bytes(body)

    def comment(self, head, status="review", login="oss-verify[bot]"):
        """The pull request's review comment, as review-comment writes it, after a forged one by someone else."""
        meta = review_comment.meta_line(head, status)
        self.page(self.COMMENTS, json.dumps([
            {"user": {"login": "someone"},
             "body": f"{review_comment.MARKER}\n{review_comment.meta_line('9' * 40, 'review')}\n"},
            {"user": {"login": login}, "body": f"{review_comment.MARKER}\n{meta}\n\n## Enrollment review\n"}]).encode())

    def upload(self, sealed, run, event="pull_request_target", path=".github/workflows/build.yaml",
               created="2026-10-26T01:00:00Z", name="enroll-review-8-libreac", branch="enroll/libreac"):
        """An artifact of the given run, which the fake Actions API lists and serves. A pull_request_target run's
        head_branch is the pull request's head branch; a workflow_dispatch run's is the branch it was started on."""
        artifact = 100 + len(self.artifacts)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("conversation.sealed", sealed.read_bytes() if isinstance(sealed, pathlib.Path) else sealed)
        self.page(f"repos/{self.REPO}/actions/artifacts/{artifact}/zip", archive.getvalue())
        self.page(f"repos/{self.REPO}/actions/runs/{run}",
                  json.dumps({"path": path, "event": event, "head_branch": branch,
                              "repository": {"full_name": self.REPO}}).encode())
        self.artifacts.append({"id": artifact, "name": name, "expired": False, "created_at": created,
                               "size_in_bytes": 1000, "workflow_run": {"id": run}})
        self.page(self.ARTIFACTS, json.dumps({"artifacts": self.artifacts}).encode())

    def seal(self, head=None, **environment):
        if head:
            (self.session / "session").write_text(f"id={self.ID}\nhead={head}\ndir={self.FOLDER}\n")
        sealed = self.directory / f"sealed-{len(list(self.directory.glob('sealed-*')))}"
        out = self.run_session("seal", str(self.session), str(sealed), **environment)
        self.assertEqual(out.returncode, 0, out.stderr)
        return sealed

    def restored(self, **environment):
        target = self.directory / "restored"
        shutil.rmtree(target, ignore_errors=True)
        out = self.run_session("restore", str(target), **environment)
        self.assertEqual(out.returncode, 0, out.stderr)
        files = sorted(p.name for p in target.iterdir()) if target.exists() else []
        return out.stdout, files, target

    def test_a_sealed_conversation_is_restored_whole_and_holds_no_plain_text(self):
        sealed = self.seal()
        self.assertNotIn(b"seed corpus", sealed.read_bytes())
        self.assertNotIn(self.ID.encode(), sealed.read_bytes())
        self.upload(sealed, 41)
        stdout, files, target = self.restored()
        self.assertIn(f"restored the conversation {self.ID} of the review of {self.HEAD}, from run 41", stdout)
        self.assertEqual(files, sorted(["session", f"{self.ID}.jsonl"]))
        self.assertEqual((target / "session").read_text(), (self.session / "session").read_text())
        self.assertEqual((target / f"{self.ID}.jsonl").read_text(), '{"said": "I asked for a seed corpus."}\n')

    def test_a_conversation_opens_only_for_its_own_pull_request_project_and_key(self):
        # Sealed for another pull request, project, repository or key, and uploaded under this one's name.
        for other in ({"PR": "9"}, {"NAME": "other"}, {"REPO": "someone/oss-verify"},
                      {"REVIEW_CONVERSATION_KEY": base64.b64encode(b"x" * 32).decode()}):
            with self.subTest(other=other):
                self.artifacts = []
                self.upload(self.seal(**other), 41)
                stdout, files, _ = self.restored()
                self.assertIn("does not open with the key for pull request #8 and libreac", stdout)
                self.assertEqual(files, [])

    def test_a_changed_byte_does_not_open(self):
        blob = bytearray(self.seal().read_bytes())
        blob[-20] ^= 1
        self.upload(bytes(blob), 41)
        stdout, files, _ = self.restored()
        self.assertIn("does not open with the key", stdout)
        self.assertIn("a fresh review", stdout)
        self.assertEqual(files, [])

    def test_only_build_yaml_on_the_default_branchs_events_is_read(self):
        good = self.seal()
        self.upload(good, 41, created="2026-10-26T01:00:00Z")
        # Newer, from a pull request's own run (which can upload an artifact of any name), or another workflow: never
        # downloaded.
        self.upload(b"forged", 42, event="pull_request", created="2026-10-26T02:00:00Z")
        self.upload(b"forged", 43, path=".github/workflows/tests.yaml", created="2026-10-26T03:00:00Z")
        # Newer, from build.yaml, but not sealed with the key: skipped for the older one that is.
        self.upload(b"forged", 44, created="2026-10-26T04:00:00Z")
        stdout, files, _ = self.restored()
        self.assertIn("from run 41", stdout)
        self.assertIn("run 42: it is not build.yaml of main", stdout)
        self.assertIn("run 43: it is not build.yaml of main", stdout)
        self.assertIn("artifact 103 of run 44: it does not open", stdout)
        zips = [line for line in (self.directory / "argv").read_text().splitlines() if line.endswith("/zip")]
        self.assertEqual(zips, [f"api repos/{self.REPO}/actions/artifacts/103/zip",
                                f"api repos/{self.REPO}/actions/artifacts/100/zip"])
        self.assertEqual(len(files), 2)

    def test_a_run_started_by_hand_on_another_branch_is_not_read(self):
        # Its build.yaml is that branch's copy, which anyone who can push a branch can change. Started on main, it is
        # read.
        self.upload(self.seal(), 41, event="workflow_dispatch", branch="main", created="2026-10-26T01:00:00Z")
        self.upload(b"forged", 42, event="workflow_dispatch", branch="ci-test/x", created="2026-10-26T02:00:00Z")
        stdout, files, _ = self.restored()
        self.assertIn("run 42: it is not build.yaml of main", stdout)
        self.assertIn("from run 41", stdout)
        zips = [line for line in (self.directory / "argv").read_text().splitlines() if line.endswith("/zip")]
        self.assertEqual(zips, [f"api repos/{self.REPO}/actions/artifacts/100/zip"])

    def test_a_flood_of_artifacts_from_pull_requests_own_runs_does_not_hide_the_review(self):
        # One artifact of the name per run; 30 runs of a fork's own, newer than the review's, cost a lookup each and no
        # download, and do not count against the artifacts tried.
        self.upload(self.seal(), 41, created="2026-10-26T01:00:00Z")
        for run in range(1000, 1030):
            self.upload(b"forged", run, event="pull_request", created=f"2026-10-26T02:{run - 1000:02d}:00Z")
        stdout, files, _ = self.restored()
        self.assertIn("from run 41", stdout)
        zips = [line for line in (self.directory / "argv").read_text().splitlines() if line.endswith("/zip")]
        self.assertEqual(len(zips), 1)

    def test_a_conversation_whose_review_is_not_the_one_posted_is_not_resumed(self):
        # The last review kept no conversation, or its comment was not posted: the newest artifact that opens is of
        # another commit than the one the review comment shows, and an older one of that commit is resumed.
        self.upload(self.seal(head="3" * 40), 41, created="2026-10-26T01:00:00Z")
        self.upload(self.seal(head="4" * 40), 42, created="2026-10-26T02:00:00Z")
        self.comment("3" * 40)
        stdout, files, target = self.restored()
        self.assertIn(f"artifact 101 of run 42: its review is of {'4' * 40}, and the review comment shows the review "
                      f"of {'3' * 40}", stdout)
        self.assertIn("from run 41", stdout)
        self.comment("5" * 40)
        stdout, files, _ = self.restored()
        self.assertIn(f"no sealed conversation of the review of {'5' * 40} on pull request #8 and libreac: a fresh "
                      "review", stdout)
        self.assertEqual(files, [])

    def test_without_a_review_comment_of_a_commit_the_review_is_fresh(self):
        self.upload(self.seal(), 41)
        for status, login, said in (("none", "oss-verify[bot]", "shows no review of a commit"),
                                    ("review", "someone-else", "has no review comment")):
            with self.subTest(status=status, login=login):
                self.comment(self.HEAD, status, login)
                stdout, files, _ = self.restored()
                self.assertIn(said, stdout)
                self.assertEqual(files, [])

    def test_the_comment_is_read_as_review_comment_reads_it(self):
        # A comment edited in the web page can come back with CRLF line ends; review-comment still reads it as a
        # review of its commit, and so does restore.
        self.upload(self.seal(), 41)
        meta = review_comment.meta_line(self.HEAD, "stale")
        self.page(self.COMMENTS, json.dumps([{"user": {"login": "oss-verify[bot]"},
                                              "body": f"{review_comment.MARKER}\r\n{meta}\r\n\r\nThanks.\r\n"}]).encode())
        stdout, files, _ = self.restored()
        self.assertIn("from run 41", stdout)
        self.assertEqual(len(files), 2)

    def test_no_artifact_or_no_api_gives_a_fresh_review(self):
        stdout, files, _ = self.restored()
        self.assertIn(f"the GitHub API call {self.ARTIFACTS} failed (exit 1): a fresh review", stdout)
        self.page(self.ARTIFACTS, b'{"artifacts": []}')
        stdout, files, _ = self.restored()
        self.assertIn(f"no sealed conversation of the review of {self.HEAD} on pull request #8 and libreac", stdout)
        self.assertEqual(files, [])
        # Anything else that goes wrong: still a fresh review, never a failed step.
        self.page(self.ARTIFACTS, b"not json")
        stdout, files, _ = self.restored()
        self.assertIn("could not restore a conversation (JSONDecodeError", stdout)

    def test_without_the_key_nothing_is_kept_or_restored_and_it_says_so(self):
        sealed = self.directory / "sealed"
        out = self.run_session("seal", str(self.session), str(sealed), REVIEW_CONVERSATION_KEY="")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("::warning::The secret REVIEW_CONVERSATION_KEY of the environment enroll-review is not set",
                      out.stdout)
        self.assertFalse(sealed.exists())
        stdout, files, _ = self.restored(REVIEW_CONVERSATION_KEY="")
        self.assertIn("::warning::", stdout)
        self.assertFalse((self.directory / "argv").exists())
        # A key that is not one: seal fails, and restore gives a fresh review with a warning.
        out = self.run_session("seal", str(self.session), str(sealed), REVIEW_CONVERSATION_KEY="c2hvcnQ=")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("fewer than 32 bytes", out.stderr)
        stdout, files, _ = self.restored(REVIEW_CONVERSATION_KEY="not base64!")
        self.assertIn("::warning::review-session: REVIEW_CONVERSATION_KEY is not base64", stdout)

    def test_the_token_is_never_an_argument_and_gh_never_gets_the_key(self):
        self.upload(self.seal(), 41)
        self.restored()
        self.assertNotIn(self.TOKEN, (self.directory / "argv").read_text())
        self.assertEqual((self.directory / "gh-token").read_text(), self.TOKEN)
        self.assertFalse((self.directory / "gh-had-the-key").exists())

    def test_build_yaml_keeps_the_conversation_out_of_the_cache_and_the_key_in_the_review_jobs_environment(self):
        review = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]["review"]
        steps = {step.get("name", ""): step for step in review["steps"]}
        self.assertFalse([s for s in review["steps"] if "actions/cache" in s.get("uses", "")])
        holders = sorted(name for name, step in steps.items()
                         if "REVIEW_CONVERSATION_KEY" in json.dumps(step.get("env", {})))
        self.assertEqual(holders, ["Restore the last review's conversation",
                                   "Seal this review's conversation for the next push's review"])
        self.assertEqual(review["environment"], {
            "name": "${{ startsWith(github.ref, 'refs/heads/ci-test/') && 'enroll-review-test' || 'enroll-review' }}",
            "deployment": False})
        upload = steps["Keep the sealed conversation for the next push's review"]
        # Without the key, Seal writes no file, so nothing is uploaded and no step fails.
        self.assertEqual(upload["if"], "${{ steps.seal.outputs.sealed != '' }}")
        # A failed Restore step gives a fresh review, never no review.
        self.assertIs(steps["Restore the last review's conversation"].get("continue-on-error"), True)
        self.assertIn('if [ -s "$sealed" ]', steps["Seal this review's conversation for the next push's review"]["run"])
        self.assertTrue(upload["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["name"], "enroll-review-${{ github.event.pull_request.number || inputs.pr }}"
                         "-${{ needs.project-builds.outputs.name }}")
        self.assertEqual(review["permissions"].get("actions"), "read")


@unittest.skipUnless(shutil.which("openssl"), "the review step needs openssl")
class ReviewStep(unittest.TestCase):
    """build.yaml's own Review step, over a stand-in review-run that fails: what the run's page and summary say."""

    def run_step(self, code, failure=None, detail=None, scan=True):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / ".github" / "scripts").mkdir(parents=True)
            if scan:
                shutil.copy(REVIEW_COMMENT, directory / ".github" / "scripts" / "review-comment")
            (directory / ".review").mkdir()
            # What review-run leaves after exit status 3: the review is written.
            (directory / ".review" / "comment.md").write_text("Thanks.\n")
            script = directory / ".github" / "scripts" / "review-run"
            script.write_text(f"#!/bin/bash\nexit {code}\n")
            script.chmod(0o755)
            for name, text in (("failure.txt", failure), ("failure-detail.txt", detail)):
                if text is not None:
                    (directory / ".review" / name).write_text(text)
            token = directory / "jwt"
            token.write_text("jwt-0\n")
            (directory / "summary").write_text("")
            environment = {**os.environ, "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
                           "OTEL_COLLECTOR_TOKEN": "collector-token-not-a-secret",
                           "ANTHROPIC_IDENTITY_TOKEN_FILE": str(token), "GITHUB_OUTPUT": str(directory / "output"),
                           "GITHUB_STEP_SUMMARY": str(directory / "summary")}
            run = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", review_step()["run"]],
                                 cwd=directory, env=environment, capture_output=True, text=True)
            self.assertFalse(token.exists(), "the identity token file is removed")
            return run.returncode, run.stdout, (directory / "summary").read_text()

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

    def test_a_review_that_finished_writes_no_summary(self):
        code, out, summary = self.run_step(3)
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
                self.assertNotIn("collector-token-not-a-secret", summary + out)
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
