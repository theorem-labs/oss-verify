# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check that need no Docker, with the builds replaced:  python3 -m pytest tools/tests"""
import contextlib
import importlib.machinery
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_build  # noqa: E402
import manifest  # noqa: E402
import validate  # noqa: E402
from test_manifest import PT_DYNAMIC, PT_INTERP, PT_LOAD, elf  # noqa: E402

TOOLS = pathlib.Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("check_tool", str(TOOLS / "check"))
SPEC = importlib.util.spec_from_loader("check_tool", LOADER)
check_tool = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(check_tool)

BUILDS = ["plain", "ubsan", "asan", "asan-ubsan"]
COMMIT = "a" * 40
TOOLCHAIN = "example.org/toolchain@sha256:" + "0" * 64


def entries(sha256s):
    """collect()'s entries for one fuzz target, `demo_fuzzer`, with these SHA-256s, one for each build."""
    return {"demo_fuzzer": {build: {"file": f"demo_fuzzer.{build}", "bytes": 1000 + i, "sha256": sha256}
                            for i, (build, sha256) in enumerate(zip(BUILDS, sha256s))}}


FIRST = entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64])


def binaries(out, collected, segments=(PT_LOAD,), data=None):
    """Write a published binary for each of collect()'s entries in `out`, as collect() does: `data`, or a small ELF
    file with these program header types."""
    data = elf(symtab=False, sections=[(".text", 1234)], segments=segments) if data is None else data
    for target, builds in collected.items():
        for entry in builds.values():
            path = pathlib.Path(out) / target / entry["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)


class Rebuild(unittest.TestCase):
    """manifest.rebuild: the block that tools/check --twice adds to the manifest."""

    def block(self, second):
        return manifest.rebuild(FIRST, second, list(second), host="host", at="2026-10-19T00:00:00Z",
                                builder={"toolchain": TOOLCHAIN, "image": "sha256:b", "project_image": "sha256:p"},
                                builds=BUILDS)

    def test_identical(self):
        block, differences, matched = self.block(entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64]))
        self.assertEqual((differences, matched), ([], 4))
        self.assertEqual(block, {
            "kind": "same-host", "host": "host", "at": "2026-10-19T00:00:00Z",
            "builder": {"toolchain": TOOLCHAIN, "image": "sha256:b", "project_image": "sha256:p"},
            "builds": BUILDS, "targets": {"demo_fuzzer": {"builds": FIRST["demo_fuzzer"]}}, "result": "identical",
        })

    def test_differs(self):
        block, differences, matched = self.block(entries(["1" * 64, "2" * 64, "f" * 64, "4" * 64]))
        self.assertEqual(block["result"], "differs")
        self.assertEqual(matched, 3)
        self.assertEqual(len(differences), 1)
        self.assertIn("demo_fuzzer.asan: sha256 " + "f" * 64, differences[0])
        # Its own SHA-256 for every binary, not the first build's.
        self.assertEqual(block["targets"]["demo_fuzzer"]["builds"]["asan"]["sha256"], "f" * 64)

    def test_a_different_set_of_binaries_differs(self):
        second = entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64])
        second["other_fuzzer"] = {"plain": {"file": "other_fuzzer.plain", "bytes": 1, "sha256": "5" * 64}}
        del second["demo_fuzzer"]["ubsan"]
        block, differences, _ = self.block(second)
        self.assertEqual(block["result"], "differs")
        self.assertEqual(differences, ["demo_fuzzer.ubsan: in the lock, not in this build",
                                       "other_fuzzer.plain: in this build, not in the lock"])


class Project(unittest.TestCase):
    """A project to give tools/check, whose builds are replaced."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        root = pathlib.Path(self.scratch.name)
        self.project = root / "demo"
        self.project.mkdir()
        (self.project / "project.yaml").write_text(
            "repo: https://example.org/demo\nprimary_contact: security@example.org\nlanguage: c\n")
        (self.project / "Dockerfile").write_text("FROM x\n")
        (self.project / "build.sh").write_text("#!/bin/bash\n")
        self.work = root / "work"

    def main(self, options, build_all):
        """Run tools/check with these options and build_all in place of the builds: (exit code, output, errors)."""
        argv = ["tools/check", "--no-shell", "--toolchain", TOOLCHAIN, "--dir", str(self.work), *options,
                str(self.project)]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(check_tool, "build_all", build_all))
            stack.enter_context(mock.patch.object(check_build, "resolve", lambda repo, ref: COMMIT))
            stack.enter_context(mock.patch.object(check_build, "image_id", lambda tag: f"sha256:{tag}"))
            stack.enter_context(mock.patch.object(check_build, "sources", lambda tag, *, labels: {}))
            stack.enter_context(mock.patch.object(check_build, "oss_verify_state", lambda job: None))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            code = check_tool.main()
        return code, output.getvalue(), errors.getvalue()


class Twice(Project):
    """tools/check --twice writes the rebuild block after its comparison, identical or not, and exits 3 if the builds
    differ."""

    def check(self, second):
        calls = []

        def build_all(*args, **kwargs):
            calls.append(yaml.safe_load((self.work / "manifest.yaml").read_text()) if calls else None)
            if len(calls) == 1:
                binaries(self.work / "out", FIRST)
                return "builder", "project", ["demo_fuzzer"], FIRST
            binaries(self.work / "twice" / "out", second)
            return "builder-twice", "project-twice", ["demo_fuzzer"], second

        code, _, _ = self.main(["--twice"], build_all)
        # While the second build ran, the manifest had no rebuild block yet.
        self.assertEqual(len(calls), 2)
        self.assertNotIn("rebuild", calls[1])
        data = yaml.safe_load((self.work / "manifest.yaml").read_text())
        return code, data

    def test_identical(self):
        code, data = self.check(entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64]))
        self.assertEqual(code, 0)
        self.assertEqual(list(data)[-1], "rebuild")
        rebuild = data["rebuild"]
        self.assertEqual(rebuild["result"], "identical")
        self.assertEqual(rebuild["kind"], "same-host")
        self.assertEqual(rebuild["builder"], {"toolchain": TOOLCHAIN, "image": "sha256:builder-twice",
                                              "project_image": "sha256:project-twice"})
        self.assertEqual(rebuild["builds"], BUILDS)
        self.assertEqual(rebuild["targets"], data["targets"])
        self.assertRegex(rebuild["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        # The first build's fields are as they are without --twice.
        self.assertEqual(data["builder"],
                         {"toolchain": TOOLCHAIN, "image": "sha256:builder", "project_image": "sha256:project"})
        self.assertEqual(data["targets"], {"demo_fuzzer": {"builds": FIRST["demo_fuzzer"]}})
        self.assertEqual(manifest.load_lock(self.work / "manifest.yaml")[0], COMMIT)

    def test_a_language_with_no_builder_yet(self):
        text = (self.project / "project.yaml").read_text().replace("language: c", "language: javascript")
        (self.project / "project.yaml").write_text(text)
        with mock.patch.object(sys, "argv", ["tools/check", "--no-shell", str(self.project)]), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stop:
            check_tool.main()
        self.assertIn("which the builder cannot build yet", str(stop.exception.code))

    def test_differs(self):
        code, data = self.check(entries(["1" * 64, "e" * 64, "3" * 64, "4" * 64]))
        self.assertEqual(code, check_tool.DIFFERENT)
        self.assertEqual(data["rebuild"]["result"], "differs")
        self.assertEqual(data["rebuild"]["targets"]["demo_fuzzer"]["builds"]["ubsan"]["sha256"], "e" * 64)
        self.assertEqual(data["targets"]["demo_fuzzer"]["builds"]["ubsan"]["sha256"], "2" * 64)


class Binaries(Project):
    """tools/check lists each binary's .text size and linkage, writes them as a Markdown table with --summary, records
    them in the manifest, and refuses a binary that is not statically linked."""

    def check(self, segments, published=None):
        summary = self.work.parent / "summary.md"

        def build_all(*args, **kwargs):
            binaries(self.work / "out", FIRST, segments, published)
            return "builder", "project", ["demo_fuzzer"], FIRST

        code, output, errors = self.main(["--summary", str(summary)], build_all)
        rows = [line.split("|")[1:-1] for line in summary.read_text().splitlines()[2:]]
        data = yaml.safe_load((self.work / "manifest.yaml").read_text())
        return code, output, errors, [[cell.strip() for cell in row] for row in rows], data

    def test_a_static_binary(self):
        code, output, errors, rows, data = self.check([PT_LOAD])
        self.assertEqual(code, 0)
        self.assertEqual(errors, "")
        self.assertEqual(rows, [["`demo_fuzzer`", build, f"{1000 + i:,}", "1,234", "yes"]
                                for i, build in enumerate(BUILDS)])
        self.assertEqual(data["layout"], {"demo_fuzzer": {build: {"text_bytes": 1234, "static": True}
                                                          for build in BUILDS}})
        for build in BUILDS:
            self.assertIn(f"demo_fuzzer.{build}", output)

    def test_a_dynamic_binary_breaks_the_enrollment_rules(self):
        for segment in (PT_INTERP, PT_DYNAMIC):
            with self.subTest(segment=segment):
                code, _, errors, rows, data = self.check([PT_LOAD, segment])
                self.assertEqual(code, 2)
                self.assertEqual(len(errors.splitlines()), len(BUILDS))
                self.assertEqual([row[4] for row in rows], ["no"] * len(BUILDS))
                self.assertEqual({entry["static"] for entry in data["layout"]["demo_fuzzer"].values()}, {False})

    def test_an_unreadable_binary_breaks_the_enrollment_rules(self):
        code, _, errors, rows, data = self.check([], b"\x7fELF")
        self.assertEqual(code, 2)
        self.assertEqual(len(errors.splitlines()), len(BUILDS))
        self.assertEqual([row[3:] for row in rows], [["unknown", "unknown"]] * len(BUILDS))
        self.assertEqual(data["layout"]["demo_fuzzer"]["plain"], {"text_bytes": None, "static": None})

    def test_target_names_are_escaped_in_the_summary(self):
        name = "a|b`c\n<d>@e"
        table = check_tool.summary_table([name], ["plain"], {name: {"plain": {"bytes": 1}}},
                                         {name: {"plain": {"text_bytes": 1, "static": True}}})
        lines = table.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[-1].count("|"), 6)
        self.assertEqual(lines[-1].count("`"), 2)
        self.assertFalse(any(character in lines[-1] for character in "<>@"))


class UbsanSettings(unittest.TestCase):
    """The UBSan checks that tools/check gives compile, by the toolchain's row in infra/toolchains.tsv."""

    def job(self, checks=None, language="c"):
        return check_build.Job(name="demo", directory=pathlib.Path("/nowhere"), repo="https://example.org/demo",
                               ref="", dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=checks,
                               language=language)

    def test_a_fixed_toolchain_keeps_its_flags(self):
        with mock.patch.object(check_build, "ubsan_mode", return_value="fixed"):
            self.assertIsNone(check_tool.ubsan_settings(self.job(), TOOLCHAIN))
            with contextlib.redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit) as stop:
                check_tool.ubsan_settings(self.job(["null"]), TOOLCHAIN)
        self.assertEqual(stop.exception.code, 2)
        self.assertIn("keeps the release's fixed UBSan flags", error.getvalue())

    def test_a_toolchain_that_applies_the_checks(self):
        with mock.patch.object(check_build, "ubsan_mode", return_value="checks"):
            # C's default has no function; C++'s has it, but its C compiles leave it out, as OSS-Fuzz's do.
            self.assertEqual(check_tool.ubsan_settings(self.job(), TOOLCHAIN), (validate.DEFAULT_UBSAN_CHECKS["c"],
                                                                                ["vptr"], []))
            self.assertEqual(check_tool.ubsan_settings(self.job(language="c++"), TOOLCHAIN),
                             (validate.DEFAULT_UBSAN_CHECKS["c++"], ["vptr"], ["function"]))
            self.assertEqual(check_tool.ubsan_settings(self.job(language="python"), TOOLCHAIN)[0],
                             validate.DEFAULT_UBSAN_CHECKS["c"])
            # A project's checks in effect (the default, changed): less those that trap mode leaves out.
            self.assertEqual(check_tool.ubsan_settings(self.job(["null", "alignment", "vptr"]), TOOLCHAIN)[0],
                             ["null", "alignment"])

    def test_today_s_toolchains_keep_the_fixed_flags(self):
        self.assertEqual(check_build.ubsan_mode(check_build.newest_toolchain()), "fixed")
        self.assertEqual(check_build.ubsan_mode(TOOLCHAIN), "fixed")


class Buildkit(unittest.TestCase):
    """tools/check refuses, with the fix, a `docker build` that refuses --progress (the legacy builder of Docker 23 and
    later), before it builds anything."""

    PROBE = ("docker", "build", "--progress=plain", "--help")

    def builds(self, probe_status):
        self.calls = []

        def run(*argv, quiet=False):
            self.calls.append(argv)
            return probe_status if argv == self.PROBE else 0

        with mock.patch.object(check_build, "run", run), mock.patch.object(check_build, "step"):
            check_build.build_builder(TOOLCHAIN)

    def test_a_legacy_builder_stops_before_the_builder_is_built(self):
        with self.assertRaises(check_build.Failed) as failed:
            self.builds(125)
        self.assertIn("apt install docker-buildx", str(failed.exception))
        self.assertIn("unset DOCKER_BUILDKIT", str(failed.exception))
        self.assertEqual(self.calls, [self.PROBE])

    def test_with_buildkit_the_builder_is_built(self):
        self.builds(0)
        self.assertEqual(self.calls[0], self.PROBE)
        self.assertEqual(self.calls[1][:3], ("docker", "build", "--progress=plain"))
        self.assertNotIn("--help", self.calls[1])


class ProjectTag(unittest.TestCase):
    """The project image's tag names the oss-verify tree that builds it and the run's work directory, so two trees, or
    two runs, on one Docker host keep two images."""

    COMMIT = "0123456789abcdef" * 2 + "01234567"
    BUILDER = "oss-verify-base-builder:0123456789abcdef-toolchain"
    HOME = pathlib.Path("/work/demo")

    def tag(self, files, builder=BUILDER, suffix="", home=HOME):
        with tempfile.TemporaryDirectory() as scratch:
            directory = pathlib.Path(scratch) / "demo"
            directory.mkdir()
            for name, text in files.items():
                (directory / name).write_text(text)
            job = check_build.Job(name="demo", directory=directory, repo="https://example.org/demo", ref="",
                                  dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=None, language="c")
            return check_build.project_tag(job, self.COMMIT, builder, home, suffix)

    def test_identical_trees_give_the_same_tag(self):
        files = {"project.yaml": "repo: x\n", "Dockerfile": "FROM a\n"}
        self.assertEqual(self.tag(files), self.tag(dict(files)))
        self.assertTrue(self.tag(files).startswith(f"oss-verify-check/demo:{self.COMMIT[:12]}-"))

    def test_a_different_project_directory_gives_a_different_tag(self):
        self.assertNotEqual(self.tag({"project.yaml": "repo: x\n", "Dockerfile": "FROM a\n"}),
                            self.tag({"project.yaml": "repo: x\n", "Dockerfile": "FROM b\n"}))
        self.assertNotEqual(self.tag({"project.yaml": "repo: x\n"}),
                            self.tag({"project.yaml": "repo: x\n", "build.sh": "true\n"}))

    def test_a_different_builder_gives_a_different_tag(self):
        files = {"project.yaml": "repo: x\n"}
        self.assertNotEqual(self.tag(files), self.tag(files, builder=self.BUILDER + "-other"))

    def test_a_different_work_directory_gives_a_different_tag(self):
        files = {"project.yaml": "repo: x\n"}
        self.assertNotEqual(self.tag(files), self.tag(files, home=pathlib.Path("/work/other")))

    def test_build_all_records_the_tag_before_the_build(self):
        with tempfile.TemporaryDirectory() as scratch, tempfile.TemporaryDirectory() as project:
            home = pathlib.Path(scratch)
            record = home / check_build.IMAGES
            seen = []

            def build_project(job, commit, builder, tag, work, no_cache=False):
                seen.append(check_build.recorded_images(record))
                raise check_build.Failed("stop here")

            job = check_build.Job(name="demo", directory=pathlib.Path(project), repo="https://example.org/demo",
                                  ref="", dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=None,
                                  language="c")
            with mock.patch.object(check_build, "build_builder", lambda *args: self.BUILDER), \
                    mock.patch.object(check_build, "build_project", build_project):
                with self.assertRaises(check_build.Failed):
                    check_tool.build_all(job, self.COMMIT, home / "twice", TOOLCHAIN, home, "-twice")
            self.assertEqual(seen, [[check_build.project_tag(job, self.COMMIT, self.BUILDER, home, "-twice")]])

    def test_every_container_carries_the_work_label(self):
        label = check_build.work_label(self.HOME)
        commands = []

        def run(*argv, quiet=False):
            commands.append(argv)
            if "rm" in argv:  # empty_directory's docker rm -rf of a directory that rmtree could not remove
                out.rmdir()
            return 0

        with tempfile.TemporaryDirectory() as scratch, \
                mock.patch.object(check_build, "run", run), \
                mock.patch.object(check_build, "output", lambda *argv: commands.append(argv) or ""), \
                mock.patch.object(check_build.shutil, "rmtree", mock.Mock(side_effect=PermissionError)), \
                contextlib.redirect_stdout(io.StringIO()):
            out = pathlib.Path(scratch) / "out"
            out.mkdir()
            check_build.compile_build("t", "plain", "none", out, None, labels=label)  # empty_directory's rm, then compile
            check_build.sources("t", labels=label)
        docker_runs = [argv for argv in commands if argv[:2] == ("docker", "run")]
        self.assertEqual(len(docker_runs), 3)
        for argv in docker_runs:
            self.assertIn(f"{label[0]} {label[1]}", " ".join(argv))

    def test_the_suffix_stays_last(self):
        self.assertTrue(self.tag({"project.yaml": "repo: x\n"}, suffix="-twice").endswith("-twice"))


class Toolchains(unittest.TestCase):
    """The toolchain that tools/check builds a project with, by its language (infra/toolchains.tsv)."""

    def test_the_newest_for_a_language(self):
        self.assertEqual(check_build.newest_toolchain(), check_build.newest_toolchain("c"))
        self.assertEqual(check_build.newest_toolchain("c"), check_build.newest_toolchain("c++"))
        self.assertIn("oss-fuzz-theorems-toolchain-rust@sha256:", check_build.newest_toolchain("rust"))
        self.assertEqual(check_build.languages_of(check_build.newest_toolchain("rust")), ("rust",))
        self.assertIn("oss-fuzz-theorems-toolchain-python@sha256:", check_build.newest_toolchain("python"))
        self.assertEqual(check_build.languages_of(check_build.newest_toolchain("python")), ("python",))
        self.assertIsNone(check_build.languages_of("example.org/not-listed:1"))
        with self.assertRaises(check_build.Failed):
            check_build.newest_toolchain("javascript")

    def test_a_toolchain_for_another_language_is_refused(self):
        project = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "demo"
        project.mkdir()
        (project / "project.yaml").write_text(
            "repo: https://example.org/demo#" + "a" * 40 + "\nprimary_contact: a@example.org\nlanguage: python\n")
        (project / "Dockerfile").write_text("FROM x\n")
        (project / "build.sh").write_text("#!/bin/bash\n")
        c_toolchain = check_build.newest_toolchain("c")
        with mock.patch.object(sys, "argv", ["tools/check", "--no-shell", "--toolchain", c_toolchain, str(project)]), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stop:
            check_tool.main()
        self.assertIn("builds c, c++, not python", str(stop.exception.code))


if __name__ == "__main__":
    unittest.main()
