# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for src/oss_verify/check_records.py, the reader of a fuzz target's checks and their records:  uv run pytest

Written for theorem-labs/oss-verify#24, and moved here with the reader.
"""
import pathlib
import sys
import time
import tracemalloc
import unittest

from oss_verify import check_records

def checks(text):
    """{abort() line: (guard, records, not a property, problems)} of a source."""
    return {check.line: (check.guard, [str(record) for record in check.records], check.not_property, check.problems)
            for check in check_records.find_checks(text)}


class Reader(unittest.TestCase):
    """find_checks: each abort() call, its guard, and the records in its comment."""

    def test_comments_strings_and_directives_are_not_code(self):
        code, comments = check_records.blank('a = "abort()"; /* abort() */ b = \'"\'; // abort()\n#define X abort()\nc;\n')
        self.assertNotIn("abort", code)
        self.assertEqual(len(comments), 2)
        self.assertEqual(code.count("\n"), 3)
        self.assertIn("c;", code)

    def test_guards(self):
        source = "\n".join([
            "int f(int a, int b) {",            # 1
            "  if (a)",                          # 2
            "    abort();",                      # 3
            "  if (a > 1 &&",                    # 4
            "      b > 2) {",                    # 5
            "    abort();",                      # 6
            "  }",                               # 7
            "  if (b) {",                        # 8
            "    g();",                          # 9
            "  } else {",                        # 10
            "    abort();",                      # 11
            "  }",                               # 12
            "  if (b == 3) g(); else if (a == 4) std::abort();",  # 13
            "  switch (a +",                     # 14
            "          b) {",                    # 15
            "  case 1: break;",                  # 16
            "  default: abort();",               # 17
            "  }",                               # 18
            "  g();",                            # 19
            "  abort();",                        # 20
            "  while (a--) __builtin_abort();",  # 21
            "}",                                 # 22
            "void abort(void);",                 # 23
            "[[noreturn]] void abort();",        # 24
        ])
        found = checks(source)
        self.assertEqual({line: guard for line, (guard, *_) in found.items()},
                         {3: (2, 2), 6: (4, 5), 11: (8, 8), 13: (13, 13), 17: (14, 15), 20: None, 21: (21, 21)})
        self.assertIn("no condition", check_records.find_checks(source)[-2].note)  # line 20: not read as a check

    def test_records(self):
        source = "\n".join([
            "/* A comment that is not the check's. */",            # 1
            "int x;",                                               # 2
            "/* The sum is right.",                                 # 3
            " * mutant: src/a.c:12 `a + b` -> `a - b`",             # 4
            " * input: seed-1",                                     # 5
            " * mutant: src/a.c:13 `return 0;` -> ``",              # 6
            " * input: seed two */",                                # 7
            "if (sum(a, b) != a + b)",                              # 8
            "\tabort();",                                           # 9
            "// mutant: fuzz/x.c:3 `<` -> `<=`",                     # 10
            "// input: s",                                          # 11
            "if (x) abort();",                                      # 12
            "if (y)   /* not a property: malloc failed */",         # 13
            "\tabort();",                                           # 14
            "/* mutant: a.c:1 `a` -> `b` */",                       # 15
            "if (z) abort();",                                      # 16
            "/* input: s */",                                       # 17
            "if (w) abort();",                                      # 18
            "/* mutant: a.c `a` -> `b`",                            # 19
            "   input: s */",                                       # 20
            "if (v) abort();",                                      # 21
            "if (u) abort();",                                      # 22
        ])
        found = checks(source)
        self.assertEqual(found[9][1], ["src/a.c:12 `a + b` -> `a - b` on seed-1", "src/a.c:13 `return 0;` -> `` on seed two"])
        self.assertEqual(found[9][3], [])
        self.assertEqual(found[12][1], ["fuzz/x.c:3 `<` -> `<=` on s"])
        self.assertEqual(found[14][2], "malloc failed")
        self.assertEqual(found[14][1], [])
        self.assertEqual(found[16][1], [])
        self.assertIn("has no `input:` line", found[16][3][0])
        self.assertIn("no `mutant:` line before it", found[18][3][0])
        self.assertIn("is not `mutant:", found[21][3][0])
        # The check on line 22 is right after another: no comment is its own.
        self.assertEqual(found[22], ((22, 22), [], None, []))

    def test_mutate(self):
        record = check_records.Record("a.c", 2, "x + 1", "x - 1", "s")
        self.assertEqual(check_records.mutate(b"one\nreturn x + 1;\nthree\n", record), (b"one\nreturn x - 1;\nthree\n", None))
        self.assertIn("occurs 2 times", check_records.mutate(b"\nx + 1 + x + 1\n", record)[1])
        self.assertIn("occurs 0 times", check_records.mutate(b"\nx\n", record)[1])
        self.assertIn("has 1 lines, not 2", check_records.mutate(b"x + 1", record)[1])

    def test_safe_path(self):
        self.assertTrue(check_records.safe_path("src/a.c"))
        # A NUL, or another control character, cannot be in a command's arguments (image_files() runs docker).
        for path in ("/etc/passwd", "../a.c", "src/../../a.c", "", "a\\b.c", "a\x00.c", "a\nb.c", "a\x7f.c"):
            self.assertFalse(check_records.safe_path(path), repr(path))

    def test_a_text_that_ends_in_an_escape_is_read(self):
        """A string or character literal whose last character, at the end of the text, is a backslash: blank() stops
        at the end, rather than read past it, and the checks before it are found."""
        for literal in ('"\\', "'\\", 'x = "\\', "char c = '\\"):
            code, _ = check_records.blank(literal)
            self.assertEqual(len(code), len(literal), repr(literal))
            (found,) = check_records.find_checks("void f(int x) {\n  if (x) abort();\n}\n" + literal)
            self.assertEqual(found.line, 2)

    def test_a_line_number_that_no_file_has_is_a_problem(self):
        """int() refuses a number of more than 4300 digits: such a line is a problem with the record, not an error
        that ends the step."""
        source = ("void f(int x) {\n  // mutant: a.c:" + "1" * 5000 + " `x` -> `y`\n  // input: s\n"
                  "  if (x) abort();\n}\n")
        (found,) = check_records.find_checks(source)
        self.assertEqual(found.records, [])
        self.assertIn("names line 111111111111..., which no file has", found.problems[0])
        (found,) = check_records.find_checks(source.replace("1" * 5000, "999999999"))
        self.assertEqual([record.line for record in found.records], [999999999])


# A harness source is the project's to write, and check --checks reads each one the coverage build compiled in the
# directory of a fuzz target, up to 16 MiB (check_checks.MAX_IMAGE_FILE_BYTES). The reader that read back over the
# source for each separator, abort() or case label took from 46 seconds to over 4 minutes on the first four cases here,
# and the long line's copies took 1.4 GB; the bound leaves room for a slow machine.
LINEAR_SECONDS = 10


class Speed(unittest.TestCase):
    def timed(self, source):
        start = time.monotonic()
        found = check_records.find_checks(source)
        self.assertLess(time.monotonic() - start, LINEAR_SECONDS)
        return found

    def test_a_number_with_many_digit_separators_is_read_in_linear_time(self):
        """Each `'` of 1'1'1'...'1 is a digit separator, not a character literal: the number is read once, not once
        for each of its separators."""
        (found,) = self.timed("int f(int x) {\n  int n = " + "1'" * 32768 + "1; if (x) abort();\n}\n")
        self.assertEqual((found.line, found.guard, found.note), (2, (2, 2), None))

    def test_many_aborts_in_one_block_are_read_in_linear_time(self):
        """Each abort() after another statement is guarded by the block that holds it, found without reading back
        over the block."""
        unit = "    g(); abort();\n"
        found = self.timed("void f(int x) {\n  if (x) {\n" + unit * (256 * 1024 // len(unit)) + "  }\n}\n")
        self.assertEqual(len(found), 256 * 1024 // len(unit))
        self.assertEqual({(check.guard, check.note) for check in found}, {((2, 2), None)})

    def test_many_case_labels_in_one_switch_are_read_in_linear_time(self):
        """Each `case 1: abort();` is guarded by its switch, found without reading back over the switch."""
        unit = "  case 1: abort();\n"
        found = self.timed("void f(int x) {\n  switch (x) {\n" + unit * (256 * 1024 // len(unit)) + "  }\n}\n")
        self.assertEqual(len(found), 256 * 1024 // len(unit))
        self.assertEqual({(check.guard, check.note) for check in found}, {((2, 2), None)})

    def test_many_aborts_under_a_guard_of_many_lines_are_read_in_linear_time(self):
        """The guard of a block, or the switch of its case labels, is found once for the block, and of its lines only
        those with a comment are read for records: each check does not read back over the whole guard."""
        for head, unit in (("if", "g(); abort(); "), ("switch", "case 1: abort(); ")):
            source = "void f(int x) {\n  " + head + " (x" + "\n" * 262144 + ") {\n" + unit * 4096 + "\n  }\n}\n"
            found = self.timed(source)
            self.assertEqual(len(found), 4096)
            self.assertEqual({(check.guard, check.note) for check in found}, {((2, 262146), None)})

    def test_a_directive_with_many_digit_separators_is_read_in_linear_time(self):
        """A directive's separators are read as the code's are: the number is read once, not once for each `'`."""
        (found,) = self.timed("#if X == " + "1'" * 32768 + "1\n#endif\nvoid f(int x) {\n  if (x) abort();\n}\n")
        self.assertEqual((found.line, found.guard, found.note), (4, (4, 4), None))

    def test_the_checks_on_one_long_line_share_its_text(self):
        """The text of a line is found once, however many checks are on it. A copy for each check took memory that
        grew with the square of the line: 8,192 checks on one line of 172 KB held 1.4 GB of copies."""
        line = "if (x) g();" + " else if (x) abort();" * 8192
        source = "void f(int x) {\n  " + line + "\n}\n"
        found = self.timed(source)  # tracemalloc slows the reader several times over: time it without
        tracemalloc.start()
        try:
            check_records.find_checks(source)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 64 << 20)
        self.assertEqual(len(found), 8192)
        self.assertEqual({(check.line, check.guard, check.text) for check in found}, {(2, (2, 2), line)})


class Macros(unittest.TestCase):
    def test_an_abort_on_a_continued_directive_line_is_noted(self):
        source = "#define CHECK(c) \\\n  do { if (!(c)) { abort(); } } while (0)\nint f(void) { return 0; }\n"
        (found,) = check_records.find_checks(source)
        self.assertEqual(found.line, 2)
        self.assertIn("macro", found.note)

    def test_an_abort_in_a_comment_on_a_directive_line_is_not_noted(self):
        """Comments go before directives: an abort() in a comment on a directive line is in no macro."""
        for comment in ("// for abort()", "/* for abort() */", "/* for\n   abort() */"):
            source = "#include <stdlib.h>  " + comment + "\nvoid f(int x) {\n  if (x) abort();\n}\n"
            (found,) = check_records.find_checks(source)
            self.assertEqual((found.line, found.note), (source.count("\n") - 1, None), repr(comment))

    def test_a_comment_that_a_directive_line_opens_is_not_code(self):
        """A /* on a directive line runs on to its */: the lines up to it are the comment, not code."""
        source = "#include <stdlib.h> /* for\n   abort() */\nvoid f(int x) {\n  if (x) abort();\n}\n"
        code, _ = check_records.blank(source)
        self.assertEqual(code.count("abort"), 1)
        self.assertEqual([(found.line, found.guard) for found in check_records.find_checks(source)], [(4, (4, 4))])

    def test_a_comment_mark_in_a_directive_literal_opens_no_comment(self):
        source = '#define S "/*"\n#define T abort()\nint x = 1\'000; /* */\n'
        self.assertEqual([found.line for found in check_records.find_checks(source)], [2])
        source = "#if N == 1'000 // abort()\n#endif\n"
        self.assertEqual(check_records.find_checks(source), [])

    def test_a_comment_in_an_if_directive_does_not_mask_it(self):
        """#if 0 with comments inside or after it is recognized as #if 0, skipping enclosed checks."""
        source = "#if 0/* comment */\nvoid f() { abort(); }\n#endif\n"
        self.assertEqual(check_records.find_checks(source), [])
        source = "#if/* comment */0\nvoid f() { abort(); }\n#endif\n"
        self.assertEqual(check_records.find_checks(source), [])

    def test_a_multiline_comment_in_a_directive_keeps_line_numbers(self):
        source = "#define M /* line 1\n line 2\n line 3 */ 1\nvoid f(int x) {\n  if (x) abort();\n}\n"
        (found,) = check_records.find_checks(source)
        self.assertEqual(found.line, 5)


if __name__ == "__main__":
    unittest.main()
