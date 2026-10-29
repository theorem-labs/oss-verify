# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/seeds/seeded_projects.py, and that docs/seeded-projects.tsv is what it writes:
python3 -m pytest tools/tests"""
import difflib
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "seeds"))
import seeded_projects  # noqa: E402

LANGUAGE_HEADER = ("# project\toss_fuzz\tlanguage\trepo\tcommit\thomepage\tsanitizers\tfuzz_targets\trelease_targets"
                   "\theld\n")


def language_row(project, oss_fuzz, language, targets, held="-"):
    return "\t".join((project, oss_fuzz, language, f"https://github.com/example/{project}", "0" * 40,
                      f"https://github.com/example/{project}", "address,undefined", targets, targets, held)) + "\n"


class Committed(unittest.TestCase):
    def test_docs_seeded_projects_tsv_is_what_the_generator_writes(self):
        committed = seeded_projects.TABLE.read_bytes()
        made = seeded_projects.table().encode("utf-8")
        if committed != made:
            diff = difflib.unified_diff(committed.decode("utf-8", "replace").splitlines(keepends=True),
                                        made.decode("utf-8").splitlines(keepends=True), "docs/seeded-projects.tsv",
                                        "tools/seeds/seeded_projects.py's output", n=0)
            self.fail("docs/seeded-projects.tsv is not what tools/seeds/seeded_projects.py writes. Run it, and commit "
                      "the result:\n" + "".join(list(diff)[:20]))


class Table(unittest.TestCase):
    """table() on a small tools/seeds/ made here."""

    FILES = {
        "oss-fuzz-projects.tsv": (
            "# the release's projects\nproject\treason or notes\n"
            "cee\tcee_fuzzer: the release modified this harness\n"
            "dee\t-\n"
            "gone\tthe release did not build it (status held: held)\n"
            "multi\t-\n"
            "py\t-\n"),
        "languages.tsv": (
            "# the release's language builds\n" + LANGUAGE_HEADER
            + language_row("multi-b", "multi", "rust", "fuzz_b")
            + language_row("multi-a", "multi", "rust", "fuzz_a", held="asan")
            + language_row("py", "py", "python", "fuzz_one,fuzz_two")),
        "builds.tsv": (
            "# the result of tools/check\nproject\tresult\tdetail\n"
            "cee\treproduces\tall binaries match the release's\n"
            "dee\treproducible\t4 binaries; a second build is identical; the release has none to compare\n"
            "multi-a\treproducible\t4 binaries\n"
            "multi-b\treproducible\t8 binaries\n"
            "py\treproducible\t8 binaries\n"),
    }

    def table(self, changes=None):
        with tempfile.TemporaryDirectory() as scratch:
            seeds = pathlib.Path(scratch)
            for name, text in {**self.FILES, **(changes or {})}.items():
                (seeds / name).write_text(text, encoding="utf-8")
            return seeded_projects.table(seeds)

    def test_rows(self):
        self.assertEqual(self.table().splitlines()[1:], [
            "project\tseedable\tbuild\tbuild notes\treason or notes",
            "cee\tyes\treproduces\tall binaries match the release's\tcee_fuzzer: the release modified this harness",
            "dee\tyes\treproducible\t4 binaries; a second build is identical; the release has none to compare\t-",
            "gone\tno\t-\t-\tthe release did not build it (status held: held)",
            "multi\tno\t-\t-\tseeded as multi-a, multi-b: one project for each of its repositories",
            "multi-a\tyes\treproducible\t4 binaries\tthe release built it in its Rust build, which it did not publish; "
            "one of the repositories of OSS-Fuzz's project multi, each a project here; the release held back these "
            "builds: asan",
            "multi-b\tyes\treproducible\t8 binaries\tthe release built it in its Rust build, which it did not publish; "
            "one of the repositories of OSS-Fuzz's project multi, each a project here",
            "py\tyes\treproducible\t8 binaries\tthe release built it in its Python build, which it did not publish",
        ])

    def test_a_project_without_a_builds_row_is_not_seeded(self):
        builds = self.FILES["builds.tsv"].replace("cee\treproduces\tall binaries match the release's\n", "")
        self.assertIn("\ncee\tno\t-\t-\tcee_fuzzer: the release modified this harness\n",
                      self.table({"builds.tsv": builds}))

    def test_refusals(self):
        release, builds = self.FILES["oss-fuzz-projects.tsv"], self.FILES["builds.tsv"]
        refused = {
            "a builds row for a project that no file names": {"builds.tsv": builds + "stray\treproduces\tall\n"},
            "notes on a project that languages.tsv seeds": {
                "oss-fuzz-projects.tsv": release.replace("py\t-", "py\tthe release built it")},
            "no reason why a project is not seeded": {"oss-fuzz-projects.tsv": release + "zed\t-\n"},
            "an empty reason": {"oss-fuzz-projects.tsv": release + "zed\t\n"},
            "a row with a missing column": {"oss-fuzz-projects.tsv": release + "zed\n"},
            "two rows for one project": {"builds.tsv": builds + "cee\tfails\tit fails\n"},
            "a language seed with no builds row": {"builds.tsv": builds.replace("py\treproducible\t8 binaries\n", "")},
            "a language seed of a project that oss-fuzz-projects.tsv does not name": {
                "oss-fuzz-projects.tsv": release.replace("multi\t-\n", "")},
            "a line of column names that is not the file's": {
                "oss-fuzz-projects.tsv": release.replace("project\treason or notes", "project\treason")},
            "a builds row for a project seeded as one project for each repository": {
                "builds.tsv": builds + "multi\treproduces\tall\n"},
        }
        for case, changes in refused.items():
            with self.subTest(case), self.assertRaises(seeded_projects.Error):
                self.table(changes)


if __name__ == "__main__":
    unittest.main()
