# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .claude/skills/write-to-maintainer/measure.py, which counts what GitHub shows of a message to a
maintainer:  python3 -m pytest tools/tests"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MEASURE = ROOT / ".claude" / "skills" / "write-to-maintainer" / "measure.py"
SPEC = importlib.util.spec_from_file_location("measure", MEASURE)
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)

DECISION = "2 changes are needed before the merge."
# 400 words of text that GitHub shows: alone it breaks the review's limit of 1,500 characters.
LONG = " ".join(["word"] * 400)


class Visible(unittest.TestCase):
    def chars(self, text):
        return measure.measure(text, "review")["visible_chars"]

    def items(self, text):
        return measure.measure(text, "review")["items"]

    def test_an_inline_comment_start_in_a_code_span_hides_nothing(self):
        text = f"{DECISION}\n\n1. The target treats `<!--` as a comment start.\n\n{LONG}\n"
        self.assertGreater(self.chars(text), 1500)
        self.assertIn("<!-- as a comment start", measure.visible(text))

    def test_a_details_tag_in_a_code_span_hides_nothing(self):
        text = f"{DECISION}\n\n1. Write `<details>` here.\n\n{LONG}\n"
        self.assertGreater(self.chars(text), 1500)
        self.assertIn("Write <details> here.", measure.visible(text))

    def test_a_code_span_of_two_backticks_holds_one(self):
        self.assertEqual(measure.visible("a ``x ` <!-- y`` b"), "a x ` <!-- y b")

    def test_an_unmatched_backtick_is_text(self):
        self.assertEqual(measure.visible("a ` <!-- hidden -->b"), "a ` b")

    def test_a_real_comment_is_hidden_and_one_nothing_closes_runs_to_the_end(self):
        self.assertEqual(measure.visible("a <!-- x -->b"), "a b")
        self.assertEqual(measure.visible("a\n<!-- x\ny -->\nb"), "a\n\n\nb")
        self.assertEqual(self.chars(f"{DECISION}\n<!--\n{LONG}\n"), len(DECISION))

    def test_a_comment_closes_only_at_its_end_marker(self):
        self.assertEqual(measure.visible("<!-- a > b -- c -->d"), "d")

    def test_items_indented_up_to_3_spaces_count(self):
        for indent in ("", " ", "  ", "   "):
            with self.subTest(indent=len(indent)):
                text = f"{DECISION}\n\n" + "".join(f"{indent}{n}. item {n}\n" for n in range(1, 7))
                self.assertEqual(self.items(text), 6)
                self.assertEqual(measure.measure(text, "review")["broken"],
                                 ["6 numbered items are visible; the limit is 5"])

    def test_items_indented_4_spaces_are_code_and_do_not_count(self):
        self.assertEqual(self.items("".join(f"    {n}. item\n" for n in range(1, 7))), 0)

    def test_a_number_with_no_space_after_it_is_no_item(self):
        self.assertEqual(self.items("1.5 is a version.\n2)x\n3.\n"), 1)

    def test_the_summary_of_a_details_block_is_visible(self):
        text = f"<details><summary>{LONG}</summary>\n\nhidden\n</details>\n"
        self.assertEqual(self.chars(text), len(LONG))
        self.assertEqual(self.chars("<details>\n<summary>Details</summary>\n\nhidden\n</details>"), len("Details"))

    def test_details_hide_their_body_and_nested_blocks_count_once(self):
        text = ("Shown.\n<details><summary>Details</summary>\n1. a\n<details><summary>inner</summary>\n2. b\n"
                "</details>\nstill hidden\n</details>\nAfter.\n")
        shown = measure.visible(text)
        self.assertEqual(" ".join(shown.split()), "Shown. Details After.")
        self.assertEqual(self.items(text), 0)

    def test_a_details_block_that_nothing_closes_runs_to_the_end(self):
        self.assertEqual(self.chars(f"{DECISION}\n<details>\n{LONG}\n"), len(DECISION))

    def test_an_open_details_block_counts(self):
        text = f"{DECISION}\n<details open><summary>Details</summary>\n\n{LONG}\n</details>\n"
        self.assertEqual(self.chars(text), len(f"{DECISION} Details {LONG}"))
        self.assertEqual(measure.measure(text, "review")["broken"],
                         [f"visible text is {len(f'{DECISION} Details {LONG}')} characters; the limit is under 1500"])
        self.assertEqual(self.items("<details open>\n" + "".join(f"{n}. item\n" for n in range(1, 7))), 6)
        # A closed block inside an open one is hidden, all but its summary.
        text = "<details open>\nA\n<details><summary>B</summary>\nhidden\n</details>\nC\n</details>\nD"
        self.assertEqual(" ".join(measure.visible(text).split()), "A B C D")
        # An open block inside a closed one is hidden with it, its summary too.
        text = "<details><summary>A</summary>\n<details open><summary>B</summary>\nhidden\n</details>\n</details>\nD"
        self.assertEqual(" ".join(measure.visible(text).split()), "A D")

    def test_fenced_code_outside_a_closed_details_block_counts(self):
        text = f"{DECISION}\n\n```\n{LONG}\n```\n"
        self.assertEqual(self.chars(text), len(f"{DECISION} {LONG}"))
        self.assertEqual(measure.measure(text, "review")["broken"],
                         [f"visible text is {len(f'{DECISION} {LONG}')} characters; the limit is under 1500"])
        hidden = f"{DECISION}\n<details><summary>Details</summary>\n\n```\n{LONG}\n```\n</details>\n"
        self.assertEqual(self.chars(hidden), len(f"{DECISION} Details"))

    def test_fenced_code_shows_tags_as_text_and_holds_no_items(self):
        text = "a\n```\n<details>\n<!--\n1. x\n```\nb\n~~~~\nc\n~~~\nd\n~~~~\ne\n"
        self.assertEqual(" ".join(measure.visible(text).split()), "a <details> <!-- 1. x b c ~~~ d e")
        self.assertEqual(self.items(text), 0)

    def test_a_fence_that_nothing_closes_runs_to_the_end_and_counts(self):
        self.assertEqual(self.chars(f"{DECISION}\n```\n<details>\n{LONG}\n"), len(f"{DECISION} <details> {LONG}"))

    def test_a_code_span_runs_onto_the_next_lines_of_its_paragraph(self):
        text = f"{DECISION}\n\n1. The target treats `x\n<!-- as` a comment start.\n\n{LONG}\n"
        self.assertGreater(self.chars(text), 1500)
        self.assertIn("x <!-- as a comment start.", " ".join(measure.visible(text).split()))
        # A blank line ends the paragraph: a backtick with no close before it is text.
        self.assertEqual(" ".join(measure.visible("a `b\n\nc <!-- d --> e`").split()), "a `b c e`")

    def test_items_inside_a_blockquote_count(self):
        text = f"{DECISION}\n\n" + "".join(f"> {n}. item\n" for n in range(1, 7))
        self.assertEqual(self.items(text), 6)
        self.assertEqual(self.items("".join(f">> {n}) item\n" for n in range(1, 4))), 3)

    def test_crlf_and_cr_line_ends_count_as_line_feeds(self):
        text = f"{DECISION}\r\n\r\n" + "".join(f"   {n}. item\r\n" for n in range(1, 7)) + "<!-- x\r\n-->\rEnd."
        self.assertEqual(self.items(text), 6)
        self.assertEqual(" ".join(measure.visible(text).split()),
                         f"{DECISION} " + " ".join(f"{n}. item" for n in range(1, 7)) + " End.")

    def test_the_command_line_prints_json_and_exits_1_on_a_broken_limit(self):
        text = f"{DECISION}\n\n1. Write `<details>` here.\n\n{LONG}\n"
        out = subprocess.run([sys.executable, str(MEASURE), "--kind", "review"], input=text, capture_output=True,
                             text=True)
        self.assertEqual(out.returncode, 1, out.stderr)
        result = json.loads(out.stdout)
        self.assertEqual(result["kind"], "review")
        self.assertGreater(result["visible_chars"], 1500)
        out = subprocess.run([sys.executable, str(MEASURE), "--kind", "reply"], input="Merged.\n",
                             capture_output=True, text=True)
        self.assertEqual((out.returncode, json.loads(out.stdout)["visible_words"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
