# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check_checks.py, .github/scripts/review-comment and .github/scripts/slack-notice that need no Docker:
python3 -m pytest tools/tests"""
import json
import importlib.machinery
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

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
    def comment(self, review, checks="### report\n"):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md")],
                                  capture_output=True, text=True, check=True).stdout

    def test_the_marker_comes_first_once(self):
        text = self.comment("Thanks.\n<!-- oss-verify-review -->\n")
        self.assertTrue(text.startswith(review_comment.MARKER + "\n"))
        self.assertEqual(text.count(review_comment.MARKER), 1)
        self.assertIn("<details>", text)
        self.assertIn("### report", text)

    def test_no_review(self):
        text = self.comment("")
        self.assertIn("did not run on this push: it wrote no comment", text)

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


class SlackNotice(unittest.TestCase):
    def notice(self, table, name="libreac", language="c"):
        with tempfile.TemporaryDirectory() as directory:
            binaries = pathlib.Path(directory) / "binaries.md"
            binaries.write_text(table)
            out = subprocess.run([sys.executable, str(ROOT / ".github" / "scripts" / "slack-notice"), "--name", name,
                                  "--language", language, "--url", "https://github.com/theorem-labs/oss-verify/pull/19",
                                  "--result", "`projects/libreac/` at `abc1234` builds",
                                  "--binaries", str(binaries)], capture_output=True, text=True, check=True).stdout
        return json.loads(out)["text"]

    def test_the_facts_of_each_binary(self):
        text = self.notice("| target | build | file bytes | `.text` bytes | static |\n|---|---|---:|---:|---|\n"
                           "| `fuzz_ctrl` | plain | 812,345 | 400,000 | yes |\n"
                           "| `fuzz_ctrl` | address | 2,812,345 | 1,400,000 | yes |\n")
        self.assertIn("Language: c.", text)
        self.assertIn("pull/19", text)
        self.assertEqual(text.count("fuzz_ctrl"), 2)
        self.assertIn("812,345", text)
        self.assertIn("1,400,000", text)
        self.assertNotIn("---", text)

    def test_no_text_becomes_a_mention_or_a_link(self):
        text = self.notice("", name="<!channel> <https://x|y> &")
        self.assertNotIn("<!channel>", text)
        self.assertIn("&lt;!channel&gt;", text)
        self.assertIn("&amp;", text)
        self.assertIn("No binaries", text)


if __name__ == "__main__":
    unittest.main()
