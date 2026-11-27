# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for oss-verify check that need no Docker, with the builds replaced:  uv run pytest"""
import contextlib
import functools
import hashlib
import io
import itertools
import json
import os
import pathlib
import re
import select
import shutil
import subprocess
import sys
import threading
import time

import pytest
import yaml

from oss_verify import check as check_tool
from oss_verify import check_binaries
from oss_verify import check_build
from oss_verify import check_checks
from oss_verify import manifest
from oss_verify import model_release
from oss_verify import validate
from test_layout import layout as layout_script, out_tree
from test_manifest import PT_DYNAMIC, PT_INTERP, PT_LOAD, elf

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The package, for a child process: python3 -P -m oss_verify finds it on PYTHONPATH, as the workflows run it.
SRC = ROOT / "src"

BUILDS = ["plain", "ubsan", "asan", "asan-ubsan"]
COMMIT = "a" * 40
TOOLCHAIN = "example.org/toolchain@sha256:" + "0" * 64
# The Config.Env of the newest C toolchain image of 2026-11-27, which is the list that `docker image inspect --format
# '{{json .Config.Env}}'` prints. It was captured from the registry with this command:
#   digest=sha256:6a6b4816865c7ec61801ae0fcab6d9c81a599ffcb20616576a9c668abd8b0a7b
#   go run github.com/google/go-containerregistry/cmd/crane@v0.20.3 config \
#     ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@$digest | jq -c .config.Env
TOOLCHAIN_ENV = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "MUSL_SYSROOT=/opt/musl-sysroot",
    "ASAN_RESOURCE_DIR=/opt/asan-rt/lib/clang/20",
    "PKG_CONFIG_LIBDIR=/opt/musl-sysroot/usr/lib/pkgconfig",
    "PKG_CONFIG_PATH=",
    "OFT_DEP_CC=/opt/oft/bin/riscv64-linux-musl-clang-plain",
    "OFT_DEP_CFLAGS=-march=rv64g -mabi=lp64d -Os -g -ffunction-sections -fdata-sections -fno-stack-protector -fPIC",
    "OFT_DEP_CXX=/opt/oft/bin/riscv64-linux-musl-clang++-plain",
]


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


def raises(error):
    """A stand-in for a function that raises `error`, whatever it is called with."""

    def stand_in(*args, **kwargs):
        raise error

    return stand_in


class TestRebuild:
    """manifest.rebuild: the block that oss-verify check --twice adds to the manifest."""

    def block(self, second):
        return manifest.rebuild(FIRST, second, list(second), host="host", at="2026-10-19T00:00:00Z",
                                builder={"toolchain": TOOLCHAIN, "image": "sha256:b", "project_image": "sha256:p"},
                                builds=BUILDS)

    def test_identical(self):
        block, differences, matched = self.block(entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64]))
        assert (differences, matched) == ([], 4)
        assert block == {
            "kind": "same-host", "host": "host", "at": "2026-10-19T00:00:00Z",
            "builder": {"toolchain": TOOLCHAIN, "image": "sha256:b", "project_image": "sha256:p"},
            "builds": BUILDS, "targets": {"demo_fuzzer": {"builds": FIRST["demo_fuzzer"]}}, "result": "identical",
        }

    def test_differs(self):
        block, differences, matched = self.block(entries(["1" * 64, "2" * 64, "f" * 64, "4" * 64]))
        assert block["result"] == "differs"
        assert matched == 3
        assert len(differences) == 1
        assert "demo_fuzzer.asan: sha256 " + "f" * 64 in differences[0]
        # Its own SHA-256 for every binary, not the first build's.
        assert block["targets"]["demo_fuzzer"]["builds"]["asan"]["sha256"] == "f" * 64

    def test_a_different_set_of_binaries_differs(self):
        second = entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64])
        second["other_fuzzer"] = {"plain": {"file": "other_fuzzer.plain", "bytes": 1, "sha256": "5" * 64}}
        del second["demo_fuzzer"]["ubsan"]
        block, differences, _ = self.block(second)
        assert block["result"] == "differs"
        assert differences == ["demo_fuzzer.ubsan: in the lock, not in this build",
                               "other_fuzzer.plain: in this build, not in the lock"]

    def test_a_program_and_its_link_map_are_compared(self):
        program = {"hello": {"plain": {"file": "hello", "bytes": 900, "sha256": "1" * 64}}}
        first_map = {"hello": {"file": "hello.map", "bytes": 40, "sha256": "2" * 64}}

        def block(second_map):
            return manifest.rebuild(program, program, ["hello"], host="host", at="2026-11-27T00:00:00Z",
                                    builder={"toolchain": TOOLCHAIN}, builds=["plain"], programs=["hello"],
                                    link_maps=(first_map, second_map))

        same, differences, matched = block({"hello": dict(first_map["hello"])})
        assert (same["result"], differences, matched) == ("identical", [], 1)
        assert same["targets"] == {"hello": {"kind": "program", "builds": program["hello"],
                                             "link_map": first_map["hello"]}}
        # The second build's link map has other bytes: its own SHA-256 is recorded, and the difference names it.
        other = {"hello": {"file": "hello.map", "bytes": 41, "sha256": "3" * 64}}
        changed, differences, matched = block(other)
        assert (changed["result"], matched) == ("differs", 1)
        assert len(differences) == 1
        assert "hello" in differences[0] and "the link map hello.map" in differences[0]
        assert "3" * 64 in differences[0] and "2" * 64 in differences[0]
        assert changed["targets"]["hello"]["link_map"] == other["hello"]
        # The second build has no link map: that differs too, and the block's entry has no link_map key.
        missing, differences, _ = block({})
        assert missing["result"] == "differs"
        assert len(differences) == 1 and "the link map hello.map" in differences[0]
        assert missing["targets"] == {"hello": {"kind": "program", "builds": program["hello"]}}


class Project:
    """A project to give oss-verify check, whose builds are replaced."""

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.project = tmp_path / "demo"
        self.project.mkdir()
        (self.project / "project.yaml").write_text(
            "repo: https://example.org/demo\nprimary_contact: security@example.org\nlanguage: c\n")
        (self.project / "Dockerfile").write_text("FROM x\n")
        (self.project / "build.sh").write_text("#!/bin/bash\n")
        self.work = tmp_path / "work"

    def main(self, options, build_all):
        """Run oss-verify check with these options and build_all in place of the builds: (exit code, output, errors)."""
        argv = ["oss-verify", "--no-shell", "--toolchain", TOOLCHAIN, "--dir", str(self.work), *options,
                str(self.project)]
        with contextlib.ExitStack() as stack:
            patch = stack.enter_context(pytest.MonkeyPatch.context())
            patch.setattr(sys, "argv", argv)
            patch.setattr(check_tool, "build_all", build_all)
            patch.setattr(check_build, "resolve", lambda repo, ref, token=None: COMMIT)
            patch.setattr(check_build, "image_id", lambda tag: f"sha256:{tag}")
            patch.setattr(check_build, "sources", lambda tag, *, labels: {})
            patch.setattr(check_build, "oss_verify_state", lambda job: None)
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            code = check_tool.main()
        return code, output.getvalue(), errors.getvalue()


class TestTwice(Project):
    """oss-verify check --twice writes the rebuild block after its comparison, identical or not, and exits 3 if the
    builds differ."""

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
        assert len(calls) == 2
        assert "rebuild" not in calls[1]
        data = yaml.safe_load((self.work / "manifest.yaml").read_text())
        return code, data

    def test_identical(self):
        code, data = self.check(entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64]))
        assert code == 0
        assert list(data)[-1] == "rebuild"
        rebuild = data["rebuild"]
        assert rebuild["result"] == "identical"
        assert rebuild["kind"] == "same-host"
        assert rebuild["builder"] == {"toolchain": TOOLCHAIN, "image": "sha256:builder-twice",
                                      "project_image": "sha256:project-twice"}
        assert rebuild["builds"] == BUILDS
        assert rebuild["targets"] == data["targets"]
        assert re.search(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", rebuild["at"])
        # The first build's fields are as they are without --twice.
        assert data["builder"] == {"toolchain": TOOLCHAIN, "image": "sha256:builder",
                                   "project_image": "sha256:project"}
        assert data["targets"] == {"demo_fuzzer": {"builds": FIRST["demo_fuzzer"]}}
        assert manifest.load_lock(self.work / "manifest.yaml")[0] == COMMIT

    def test_a_language_with_no_builder_yet(self, monkeypatch):
        text = (self.project / "project.yaml").read_text().replace("language: c", "language: javascript")
        (self.project / "project.yaml").write_text(text)
        monkeypatch.setattr(sys, "argv", ["oss-verify", "--no-shell", str(self.project)])
        with contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as stop:
            check_tool.main()
        assert "which the builder cannot build yet" in str(stop.value.code)

    def test_differs(self):
        code, data = self.check(entries(["1" * 64, "e" * 64, "3" * 64, "4" * 64]))
        assert code == check_tool.DIFFERENT
        assert data["rebuild"]["result"] == "differs"
        assert data["rebuild"]["targets"]["demo_fuzzer"]["builds"]["ubsan"]["sha256"] == "e" * 64
        assert data["targets"]["demo_fuzzer"]["builds"]["ubsan"]["sha256"] == "2" * 64


class TestBinaries(Project):
    """oss-verify check lists each binary's .text size and linkage, writes them as a Markdown table with --summary,
    records them in the manifest, and refuses a binary that is not statically linked."""

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
        assert code == 0
        assert errors == ""
        assert rows == [["`demo_fuzzer`", build, f"{1000 + i:,}", "1,234", "yes"]
                        for i, build in enumerate(BUILDS)]
        assert data["layout"] == {"demo_fuzzer": {build: {"text_bytes": 1234, "static": True}
                                                  for build in BUILDS}}
        for build in BUILDS:
            assert f"demo_fuzzer.{build}" in output

    @pytest.mark.parametrize("segment", [PT_INTERP, PT_DYNAMIC], ids=["PT_INTERP", "PT_DYNAMIC"])
    def test_a_dynamic_binary_breaks_the_enrollment_rules(self, segment):
        code, _, errors, rows, data = self.check([PT_LOAD, segment])
        assert code == 2
        assert len(errors.splitlines()) == len(BUILDS)
        assert [row[4] for row in rows] == ["no"] * len(BUILDS)
        assert {entry["static"] for entry in data["layout"]["demo_fuzzer"].values()} == {False}

    def test_an_unreadable_binary_breaks_the_enrollment_rules(self):
        code, _, errors, rows, data = self.check([], b"\x7fELF")
        assert code == 2
        assert len(errors.splitlines()) == len(BUILDS)
        assert [row[3:] for row in rows] == [["unknown", "unknown"]] * len(BUILDS)
        assert data["layout"]["demo_fuzzer"]["plain"] == {"text_bytes": None, "static": None}

    def test_target_names_are_escaped_in_the_summary(self):
        name = "a|b`c\n<d>@e"
        table = check_tool.summary_table([name], ["plain"], {name: {"plain": {"bytes": 1}}},
                                         {name: {"plain": {"text_bytes": 1, "static": True}}})
        lines = table.splitlines()
        assert len(lines) == 3
        assert lines[-1].count("|") == 6
        assert lines[-1].count("`") == 2
        assert not any(character in lines[-1] for character in "<>@")


class TestProgram(Project):
    """oss-verify check of a port that lists a whole program: records it as the build wrote it, with its link map,
    refuses a file that is not the pin, and checks it with the checks that apply to a program. The build_all stand-in
    writes out/hello/hello and out/hello/hello.map, as build_all does for a program."""

    PROGRAM = elf(sections=[(".text", 1234)], segments=[PT_LOAD])
    PIN = hashlib.sha256(PROGRAM).hexdigest()
    LINK_MAP = b"hello.map: the symbols of the link\n"

    def pin_in(self, pin):
        """Make the project one that lists the program hello, with its link map and this pin."""
        (self.project / "project.yaml").write_text(
            "repo: https://example.org/demo\nprimary_contact: security@example.org\nlanguage: c\n"
            f"programs:\n  - file: hello\n    sha256: {pin}\n    link_map: hello.map\n")

    def build_all_of(self, *builds):
        """A build_all that writes the program that builds[n] holds on its nth call (the last one on each later call),
        and returns what build_all returns. A build that is an exception is raised instead. Each call is in
        self.calls, as (job, work, keyword arguments)."""
        self.calls = []

        def build_all(job, commit, work, *args, **kwargs):
            self.calls.append((job, work, kwargs))
            build = builds[min(len(self.calls), len(builds)) - 1]
            if isinstance(build, Exception):
                raise build
            out = work / "out" / "hello"
            out.mkdir(parents=True, exist_ok=True)
            (out / "hello").write_bytes(build)
            (out / "hello.map").write_bytes(self.LINK_MAP)
            return "builder", "project", ["hello"], {"hello": {"plain": manifest.file_entry(out / "hello")}}

        return build_all

    def manifest(self):
        return yaml.safe_load((self.work / "manifest.yaml").read_text())

    def test_a_fuzz_target_port_has_no_programs(self):
        assert check_tool.load(str(self.project)).programs is None

    def test_a_program_is_recorded(self):
        self.pin_in(self.PIN)
        summary = self.work.parent / "summary.md"
        code, output, errors = self.main(["--summary", str(summary)], self.build_all_of(self.PROGRAM))
        assert (code, errors) == (0, "")
        (job, _, _), = self.calls
        assert job.programs == [{"file": "hello", "sha256": self.PIN, "link_map": "hello.map"}]
        assert job.builds == ["plain"]
        data = self.manifest()
        assert data["builds"] == ["plain"]
        assert data["fuzz_targets"] == []
        assert data["targets"] == {"hello": {
            "kind": "program",
            "builds": {"plain": {"file": "hello", "bytes": len(self.PROGRAM), "sha256": self.PIN}},
            "link_map": {"file": "hello.map", "bytes": len(self.LINK_MAP),
                         "sha256": hashlib.sha256(self.LINK_MAP).hexdigest()},
        }}
        assert data["layout"] == {"hello": {"plain": {"text_bytes": 1234, "static": True}}}
        assert "rebuild" not in data and "binary_checks" not in data
        rows = [[cell.strip() for cell in line.split("|")[1:-1]] for line in summary.read_text().splitlines()[2:]]
        assert rows == [["`hello`", "plain", f"{len(self.PROGRAM):,}", "1,234", "yes"]]
        assert "NOT THE PINNED PROGRAM" not in output

    def test_a_program_that_is_not_the_pinned_file_exits_3(self):
        pin = "f" * 64
        self.pin_in(pin)
        code, output, errors = self.main(["--twice"], self.build_all_of(self.PROGRAM))
        assert code == check_tool.DIFFERENT
        assert errors.splitlines() == [
            f"demo: program hello: the build wrote sha256 {self.PIN} ({len(self.PROGRAM)} bytes) FROM the toolchain "
            f"{TOOLCHAIN}, and project.yaml pins {pin}"]
        assert "NOT THE PINNED PROGRAM" in output.splitlines()
        # The check goes on to the second build, and the manifest keeps the built value.
        assert len(self.calls) == 2
        data = self.manifest()
        assert data["targets"]["hello"]["builds"]["plain"]["sha256"] == self.PIN
        assert data["rebuild"]["result"] == "identical"

    def test_a_wrong_pin_is_named_when_the_second_build_fails(self):
        pin = "f" * 64
        self.pin_in(pin)
        code, output, errors = self.main(["--twice"], self.build_all_of(self.PROGRAM, check_build.Failed("no luck")))
        assert code == 1
        assert "THE SECOND BUILD FAILED: no luck" in output
        assert f"program hello: the build wrote sha256 {self.PIN} " in errors
        assert f"project.yaml pins {pin}" in errors
        assert "rebuild" not in self.manifest()

    def test_a_dynamic_program_exits_2_before_the_pin(self):
        self.pin_in("f" * 64)
        code, output, errors = self.main(
            ["--twice"], self.build_all_of(elf(sections=[(".text", 1234)], segments=[PT_LOAD, PT_DYNAMIC])))
        assert code == 2
        assert errors.splitlines() == [
            "demo: out/hello/hello is dynamically linked: a program must be statically linked (no PT_INTERP or "
            "PT_DYNAMIC program header)"]
        assert "NOT THE PINNED PROGRAM" not in output
        assert len(self.calls) == 1

    def test_the_pin_holds_with_twice_and_a_lock(self):
        self.pin_in(self.PIN)
        lock = self.work.parent / "lock.yaml"
        assert self.main([], self.build_all_of(self.PROGRAM))[0] == 0
        shutil.copyfile(self.work / "manifest.yaml", lock)
        code, output, errors = self.main(["--twice", "--lock", str(lock)], self.build_all_of(self.PROGRAM))
        assert (code, errors) == (0, "")
        assert len(self.calls) == 2
        lines = output.splitlines()
        second = f"second build: out/hello/hello sha256 {self.PIN}"
        assert lines.count(second) == 1
        # After the comparison of the two builds, and before the lock's.
        compared = [n for n, line in enumerate(lines) if line.startswith("reproducible:")]
        locked = [n for n, line in enumerate(lines) if line.startswith("matches the lock:")]
        assert len(compared) == len(locked) == 1
        assert compared[0] < lines.index(second) < locked[0]

    @pytest.mark.parametrize("options", [["--layout-out"], ["--base-layout", "--layout-out"]],
                             ids=["layout-out", "base-layout-and-layout-out"])
    def test_layout_options_are_refused_for_a_program(self, options):
        self.pin_in(self.PIN)
        base, tree = self.work.parent / "base", self.work.parent / "layout"
        base.mkdir()
        argv = ["--no-shell", "--toolchain", TOOLCHAIN, "--dir", str(self.work),
                *(part for option in options for part in (option, str(base if option == "--base-layout" else tree))),
                str(self.project)]
        build_all = self.build_all_of(self.PROGRAM)
        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as errors, pytest.raises(SystemExit) as stop:
            patch.setattr(check_tool, "build_all", build_all)
            check_tool.main(argv)
        assert stop.value.code == 2
        message = errors.getvalue().splitlines()[-1]
        assert "--layout-out" in message and "--base-layout" in message
        assert "link-fuzz-target" in message and "program" in message
        # Before anything is built, and before the work directory is made.
        assert self.calls == []
        assert not self.work.exists()

    def test_the_checks_of_a_program(self):
        self.pin_in(self.PIN)
        checks = self.work.parent / "checks.md"
        calls, seen = [], []

        def stand_in(name):
            def call(*args, **kwargs):
                calls.append(name)
                raise check_build.Failed(f"{name} was called")
            return call

        def release_model():
            raise check_build.Failed("no release.yaml")

        def isa(path):
            seen.append(path)
            return {"result": "pass", "detail": "isa ok"}

        # check.main catches every exception of its two --checks steps, so a stand-in that raises proves nothing: the
        # calls that each one records do.
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_checks, "checks", stand_in("check_checks.checks"))
            patch.setattr(check_binaries, "run_job", stand_in("run_job"))
            patch.setattr(check_binaries, "record_of", stand_in("record_of"))
            patch.setattr(check_checks, "qemu", stand_in("qemu"))
            patch.setattr(model_release, "release_model", release_model)
            patch.setattr(model_release, "fetch", stand_in("model_release.fetch"))
            patch.setattr(check_binaries.binary_isa, "check", isa)
            code, output, errors = self.main(["--checks", str(checks)], self.build_all_of(self.PROGRAM))
        assert (code, errors, calls) == (0, "", [])
        assert seen == [str(self.work / "out" / "hello" / "hello")]
        data = self.manifest()
        assert data["binary_checks"]["qemu"] == "" and data["binary_checks"]["inputs"] == {"hello": []}
        results = data["binary_checks"]["targets"]["hello"]["plain"]
        assert list(results) == ["elf", "system_calls", "quiet_loud", "instrumented"]
        assert results["elf"]["result"] == "stale" and results["elf"]["detail"].startswith("isa ok; ")
        for key in ("system_calls", "quiet_loud"):
            assert results[key]["result"] == "not-run" and results[key]["detail"].startswith("a program: ")
        assert results["instrumented"]["result"] == "plain"
        assert results["instrumented"]["detail"].startswith("a program: ")
        assert "uninstrumented" not in data["targets"]["hello"]["builds"]["plain"]
        text = checks.read_text()
        section = text.split("### The checks of the binaries")[0]
        assert section.startswith("### The checks of the fuzz targets")
        assert "`hello`" in section and "do not run for a program" in section
        assert "not run (a program)" in text and "no list (a program)" in text
        assert "Each fuzz target ran" not in text
        assert text.rstrip("\n") in output


def tree_files(root):
    """{path below root: bytes} of each file of a directory tree."""
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


class TestLayoutOptions(Project):
    """oss-verify check --layout-out writes the layout tree of the first build (infra/base-builder/layout.py
    collect), and --base-layout, which needs it, makes each build, the second of --twice too, an append build."""

    @pytest.fixture(autouse=True)
    def set_up_layout(self, set_up):
        self.tree = self.work.parent / "layout"
        self.base = self.work.parent / "base"
        self.base.mkdir()

    def check(self, options, damage=None):
        """Run oss-verify check with `options`, each build_all leaving raw/<build>/ for each build of the run as compile
        does with link records (test_layout.out_tree; the second one's with a placement.tsv), with `damage` done to
        the first one's plain record: (exit code, output, record, layout and base_layout of each build_all, with
        build_all's default for one it is not given, and the layout tree's files when the second build ran)."""
        calls, seen = [], []

        def build_all(job, commit, work, *args, **kwargs):
            calls.append(kwargs)
            if len(calls) > 1:
                seen.append(tree_files(self.tree) if self.tree.exists() else None)
            record = out_tree(work / "raw", placement=None if len(calls) == 1 else "the second build's\n")
            for build in job.builds:
                if build != "plain":
                    shutil.copytree(work / "raw" / "plain", work / "raw" / build, symlinks=True)
            if damage is not None and len(calls) == 1:
                damage(record)
            built = {target: {build: entry for build, entry in by_build.items() if build in job.builds}
                     for target, by_build in FIRST.items()}
            binaries(work / "out", built)
            return "builder", "project", ["demo_fuzzer"], built

        code, output, _ = self.main(options, build_all)
        defaults = {"record": False, "layout": False, "base_layout": None}
        return code, output, [{name: kwargs.get(name, default) for name, default in defaults.items()}
                              for kwargs in calls], seen

    def collected(self):
        """The files that layout.py collect writes for the first build's raw/."""
        expected = self.work.parent / "expected"
        assert layout_script.main(["collect", str(self.work / "raw"), str(expected)]) == 0
        return tree_files(expected)

    def test_layout_out_records_the_links_and_writes_the_layout_tree(self):
        code, output, calls, _ = self.check(["--layout-out", str(self.tree)])
        assert code == 0, output
        # layout=True records the links too: compile_build gives such a build OV_RECORD=1 (TestCompileBuild).
        assert calls == [{"record": False, "layout": True, "base_layout": None}]
        assert sorted(path.name for path in (self.tree / "plain" / "fuzz_shim").iterdir()) == \
            ["binary.sha256", "calls.tsv", "map", "output.tsv", "sections.tsv", "wraps"]
        assert tree_files(self.tree) == self.collected()
        assert f"layout tree: {self.tree}" in output

    def test_base_layout_makes_each_build_an_append_build_and_the_layout_tree_is_the_first_build_s(self):
        code, output, calls, seen = self.check(["--twice", "--layout-out", str(self.tree), "--base-layout",
                                                str(self.base)])
        assert code == 0, output
        assert calls == [{"record": False, "layout": True, "base_layout": self.base.resolve()}] * 2
        # Written from the first build's raw/, before the second build ran; the second one's is twice/raw/.
        assert seen == [self.collected()]
        assert tree_files(self.tree) == self.collected()

    def test_without_the_options_nothing_changes(self):
        code, output, calls, _ = self.check(["--twice"])
        assert code == 0, output
        assert calls == [{"record": False, "layout": False, "base_layout": None}] * 2
        assert "layout tree" not in output
        assert not self.tree.exists()

    def test_a_record_with_no_wraps_stops_the_run_with_exit_1(self):
        code, output, _, _ = self.check(["--layout-out", str(self.tree)], lambda record: (record / "wraps").unlink())
        assert code == 1
        failure = [line for line in output.splitlines() if "LAYOUT TREE WAS NOT WRITTEN" in line]
        assert len(failure) == 1, output
        assert "plain/fuzz_shim" in failure[0]
        assert "wraps" in failure[0]
        assert not self.tree.exists()

    def test_a_build_directory_that_another_run_left_is_not_read(self):
        # An earlier run's asan build, whose record has no wraps: a collect of each directory of raw/ stops on it.
        out_tree(self.work.parent / "earlier")
        shutil.copytree(self.work.parent / "earlier" / "plain", self.work / "raw" / "asan", symlinks=True)
        for wraps in (self.work / "raw" / "asan" / ".records").glob("*/wraps"):
            wraps.unlink()
        code, output, _, _ = self.check(["--build", "plain", "--layout-out", str(self.tree)])
        assert code == 0, output
        assert [path.relative_to(self.tree).as_posix() for path in sorted(self.tree.glob("*/*"))] == \
            ["plain/fuzz_shim"]
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            assert layout_script.main(["collect", str(self.work / "raw"), str(self.work.parent / "all")]) == 2
        assert "asan/fuzz_shim" in errors.getvalue()
        assert "wraps" in errors.getvalue()

    def test_layout_out_may_be_an_empty_directory(self):
        self.tree.mkdir()
        code, output, _, _ = self.check(["--layout-out", str(self.tree)])
        assert code == 0, output
        assert tree_files(self.tree) == self.collected()

    def refused(self, options):
        """Run oss-verify check with `options`, which it must refuse as argparse does: the line of the error it prints
        after the usage, which names every option."""
        built = []
        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as errors, pytest.raises(SystemExit) as stop:
            patch.setattr(check_tool, "build_all", lambda *args, **kwargs: built.append(args))
            check_tool.main(["--no-shell", "--toolchain", TOOLCHAIN, "--dir", str(self.work), *options,
                             str(self.project)])
        assert stop.value.code == 2
        # Before anything is built: no build, and not even the work directory.
        assert built == []
        assert not self.work.exists()
        return errors.getvalue().splitlines()[-1]

    def test_base_layout_without_layout_out_is_refused(self):
        errors = self.refused(["--base-layout", str(self.base)])
        assert "--base-layout" in errors
        assert "--layout-out" in errors

    @pytest.mark.parametrize("name", ["file", "missing"])
    def test_base_layout_must_be_a_directory(self, name):
        (self.work.parent / "file").write_text("")
        path = self.work.parent / name
        errors = self.refused(["--layout-out", str(self.tree), "--base-layout", str(path)])
        assert f"--base-layout {path.resolve()}" in errors

    @pytest.mark.parametrize("name", ["layout", "file"])
    def test_layout_out_that_is_there_and_not_an_empty_directory_is_refused(self, name):
        (self.tree / "plain" / "fuzz_shim").mkdir(parents=True)
        (self.work.parent / "file").write_text("")
        path = self.work.parent / name  # self.tree, or the file
        errors = self.refused(["--layout-out", str(path)])
        assert f"--layout-out {path}" in errors

    @pytest.mark.parametrize("name, filled", [("base", False), ("base", True), ("new", True)])
    def test_layout_out_in_the_base_layout_is_refused(self, name, filled):
        # The base layout directory itself, even while it is empty, and a directory in it.
        path = self.base if name == "base" else self.base / name
        if filled:
            (self.base / "plain" / "fuzz_shim").mkdir(parents=True, exist_ok=True)
        errors = self.refused(["--layout-out", str(path), "--base-layout", str(self.base)])
        assert f"--layout-out {path}" in errors
        assert "--base-layout" in errors


class TestCompileBuild:
    """The docker run command of compile_build: with a base layout tree, the tree mounted read-only and named by
    OV_BASE_LAYOUT, with the records and OV_LAYOUT; with a program's environment file, the file mounted read-only and
    named by OV_PROGRAM_ENV, with none of those, and the builder's compile-program in place of compile; with none of
    them, today's command."""

    LABELS = ["--label", "work=/w"]

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.scratch, self.count = tmp_path, itertools.count()  # a new directory for each call of command()

    def command(self, build="asan", sanitizer="address", **options):
        """(the one docker run command of compile_build for this build, an asan build unless told, into a new
        directory, that directory)."""
        commands = []

        def run(*argv, quiet=False):
            commands.append(list(argv))
            return 0

        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()):
            patch.setattr(check_build, "run", run)
            patch.delenv("OFT_MAKE_JOBS", raising=False)
            out = self.scratch / f"call{next(self.count)}" / "out"
            check_build.compile_build("tag", build, sanitizer, out, labels=self.LABELS, **options)
        assert len(commands) == 1
        return commands[0], out

    def test_without_a_layout_the_command_is_today_s(self):
        owner = f"OV_OWNER={os.getuid()}:{os.getgid()}"
        command, out = self.command()
        assert command == ["docker", "run", "--rm", "--init", "--network=none", "--label", "work=/w",
                           "-e", "SANITIZER=address", "-e", owner, "-v", f"{out}:/out", "tag", "compile"]
        command, out = self.command(record=True)
        assert command == ["docker", "run", "--rm", "--init", "--network=none", "--label", "work=/w",
                           "-e", "SANITIZER=address", "-e", owner, "-e", "OV_RECORD=1", "-v", f"{out}:/out",
                           "tag", "compile"]

    @pytest.mark.parametrize("options", [{"layout": True}, {"layout": True, "record": True}],
                             ids=["layout", "layout-record"])
    def test_a_layout_records_the_links_with_ov_layout(self, options):
        owner = f"OV_OWNER={os.getuid()}:{os.getgid()}"
        command, out = self.command(**options)
        assert command == ["docker", "run", "--rm", "--init", "--network=none", "--label", "work=/w",
                           "-e", "SANITIZER=address", "-e", owner, "-e", "OV_RECORD=1",
                           "-e", "OV_LAYOUT=1", "-v", f"{out}:/out", "tag", "compile"]

    @pytest.mark.parametrize("options", [{}, {"layout": True, "record": True}],
                             ids=["no-options", "layout-record"])
    def test_a_base_layout_is_mounted_read_only(self, options):
        owner = f"OV_OWNER={os.getuid()}:{os.getgid()}"
        base = pathlib.Path("/layouts/base")
        command, out = self.command(base_layout=base, **options)
        assert command == ["docker", "run", "--rm", "--init", "--network=none", "--label", "work=/w",
                           "-e", "SANITIZER=address", "-e", owner, "-e", "OV_RECORD=1",
                           "-e", "OV_LAYOUT=1", "-v", "/layouts/base:/ov-base-layout:ro",
                           "-e", "OV_BASE_LAYOUT=/ov-base-layout", "-v", f"{out}:/out", "tag", "compile"]

    def test_a_program_build_mounts_the_toolchain_environment(self):
        owner = f"OV_OWNER={os.getuid()}:{os.getgid()}"
        command, out = self.command("plain", "none", program_env=pathlib.Path("/w/program-env"))
        assert command == ["docker", "run", "--rm", "--init", "--network=none", "--label", "work=/w",
                           "-e", "SANITIZER=none", "-e", owner, "-v", "/w/program-env:/ov-program-env:ro",
                           "-e", "OV_PROGRAM_ENV=/ov-program-env", "-v", f"{out}:/out",
                           "tag", "/usr/local/lib/oss-verify/compile-program"]


class TestToolchainEnvironment:
    """check_build.toolchain_environment: the environment that the toolchain image sets itself, read on the host for
    the build of a whole program, with `output` replaced by one that answers each command with the next reply."""

    INSPECT = ("docker", "image", "inspect", "--format", "{{json .Config.Env}}", TOOLCHAIN)
    PULL = ("docker", "pull", "--quiet", TOOLCHAIN)
    DEFAULT_PATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def read(self, *replies):
        """toolchain_environment(TOOLCHAIN), each command that it runs in `self.commands`. A reply that is an
        exception is raised by that command, and any other reply is what it prints."""
        self.commands, answers = [], iter(replies)

        def output(*argv, env=None, token=None):
            self.commands.append(argv)
            reply = next(answers)
            if isinstance(reply, Exception):
                raise reply
            return reply

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "output", output)
            return check_build.toolchain_environment(TOOLCHAIN)

    @staticmethod
    def printed(entries):
        """What `docker image inspect --format '{{json .Config.Env}}'` prints for these entries."""
        return json.dumps(entries, separators=(",", ":")) + "\n"

    def test_the_image_s_own_environment(self):
        environment = self.read(self.printed(TOOLCHAIN_ENV))
        assert environment == TOOLCHAIN_ENV
        assert "PKG_CONFIG_PATH=" in environment
        assert self.commands == [self.INSPECT]

    def test_docker_s_default_path_when_the_image_has_none(self):
        without = [entry for entry in TOOLCHAIN_ENV if not entry.startswith("PATH=")]
        assert self.read(self.printed(without)) == [self.DEFAULT_PATH, *without]
        assert self.read("null\n") == [self.DEFAULT_PATH]
        # A name that only starts with PATH is not PATH.
        assert self.read('["PATHEXT=.exe"]\n') == [self.DEFAULT_PATH, "PATHEXT=.exe"]

    def test_an_image_that_is_not_here_is_pulled_first(self):
        missing = check_build.Failed("docker image inspect ... exited 1: Error: No such image")
        assert self.read(missing, "sha256:" + "0" * 64 + "\n", self.printed(TOOLCHAIN_ENV)) == TOOLCHAIN_ENV
        assert self.commands == [self.INSPECT, self.PULL, self.INSPECT]

    @pytest.mark.parametrize("replies, commands", [
        ((check_build.Failed("no such image"), "", check_build.Failed("no such image")), 3),
        ((check_build.Failed("no such image"), check_build.Failed("pull access denied")), 2),
    ], ids=["inspected-twice", "not-pulled"])
    def test_an_image_that_cannot_be_read_stops_the_build(self, replies, commands):
        with pytest.raises(check_build.Failed) as failed:
            self.read(*replies)
        assert TOOLCHAIN in str(failed.value)
        assert self.commands == [self.INSPECT, self.PULL, self.INSPECT][:commands]

    @pytest.mark.parametrize("entry", ["NOEQUALS", "=x", "-x=1"])
    def test_an_entry_with_no_name_is_refused(self, entry):
        with pytest.raises(check_build.Failed) as failed:
            self.read(self.printed(["PATH=/bin", entry]))
        assert entry in str(failed.value)

    @pytest.mark.parametrize("entry", ["A=x\0B=y", "A\0B=x"], ids=["in-the-value", "in-the-name"])
    def test_an_entry_with_a_nul_is_refused(self, entry):
        """program-env ends each entry with a NUL, so compile-program would read an entry that holds one as two."""
        with pytest.raises(check_build.Failed) as failed:
            self.read(self.printed(["PATH=/bin", entry]))
        assert repr(entry) in str(failed.value)

    @pytest.mark.parametrize("printed", ["[1]", "[null]", '"PATH=/bin"', '{"PATH": "/bin"}', "not json", ""],
                             ids=["number", "null-entry", "string", "mapping", "not-json", "nothing"])
    def test_what_is_not_a_list_of_strings_is_refused(self, printed):
        with pytest.raises(check_build.Failed) as failed:
            self.read(printed + "\n")
        assert TOOLCHAIN in str(failed.value)


class TestUbsanSettings:
    """The UBSan checks that oss-verify check gives compile, by the toolchain's row in infra/toolchains.tsv."""

    def job(self, checks=None, language="c"):
        return check_build.Job(name="demo", directory=pathlib.Path("/nowhere"), repo="https://example.org/demo",
                               ref="", dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=checks,
                               language=language)

    def test_a_fixed_toolchain_keeps_its_flags(self):
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "ubsan_mode", lambda *args, **kwargs: "fixed")
            assert check_tool.ubsan_settings(self.job(), TOOLCHAIN) is None
            with contextlib.redirect_stderr(io.StringIO()) as error, pytest.raises(SystemExit) as stop:
                check_tool.ubsan_settings(self.job(["null"]), TOOLCHAIN)
        assert stop.value.code == 2
        assert "keeps the release's fixed UBSan flags" in error.getvalue()

    def test_a_toolchain_that_applies_the_checks(self):
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "ubsan_mode", lambda *args, **kwargs: "checks")
            # C's default has no function; C++'s has it, but its C compiles leave it out, as OSS-Fuzz's do.
            assert check_tool.ubsan_settings(self.job(), TOOLCHAIN) == \
                (validate.DEFAULT_UBSAN_CHECKS["c"], ["vptr"], [])
            # C++'s default has vptr, which the toolchain makes through its handler, so nothing is left out.
            assert check_tool.ubsan_settings(self.job(language="c++"), TOOLCHAIN) == \
                (validate.DEFAULT_UBSAN_CHECKS["c++"], [], ["function"])
            assert check_tool.ubsan_settings(self.job(language="python"), TOOLCHAIN)[0] == \
                validate.DEFAULT_UBSAN_CHECKS["c"]
            # A project's checks in effect (the default, changed). vptr stays when they name it.
            assert check_tool.ubsan_settings(self.job(["null", "alignment", "vptr"]), TOOLCHAIN) == \
                (["null", "alignment", "vptr"], [], [])
            assert check_tool.ubsan_settings(self.job(["null", "libcxx-hardening"], "c++"), TOOLCHAIN) == \
                (["null", "libcxx-hardening"], ["vptr"], [])

    def test_an_unlisted_toolchain_keeps_the_fixed_flags(self):
        assert check_build.ubsan_mode(TOOLCHAIN) == "fixed"


class TestBuildkit:
    """oss-verify check refuses, with the fix, a `docker build` that refuses --progress (the legacy builder of Docker 23
    and later), before it builds anything."""

    PROBE = ("docker", "build", "--progress=plain", "--help")

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.cache = tmp_path

    def builds(self, probe_status):
        self.calls = []

        def run(*argv, quiet=False):
            self.calls.append(argv)
            return probe_status if argv == self.PROBE else 0

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "CACHE", self.cache)
            patch.setattr(check_build, "run", run)
            patch.setattr(check_build, "step", lambda text: None)
            patch.setattr(check_build.shutil, "which", lambda name: f"/usr/bin/{name}")
            check_build.build_builder(TOOLCHAIN)

    def test_no_docker_command_stops_with_a_message_not_a_traceback(self, tmp_path):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("PATH", str(tmp_path))  # an empty directory
            patch.setattr(check_build, "step", lambda text: None)
            with pytest.raises(check_build.Failed) as failed:
                check_build.build_builder(TOOLCHAIN)
        assert "no docker command on PATH" in str(failed.value)

    def test_a_legacy_builder_stops_before_the_builder_is_built(self):
        with pytest.raises(check_build.Failed) as failed:
            self.builds(125)
        assert "apt install docker-buildx" in str(failed.value)
        assert "unset DOCKER_BUILDKIT" in str(failed.value)
        assert self.calls == [self.PROBE]

    def test_with_buildkit_the_builder_is_built(self):
        self.builds(0)
        assert self.calls[0] == self.PROBE
        assert self.calls[1][:3] == ("docker", "build", "--progress=plain")
        assert "--help" not in self.calls[1]


class TestBuilderTurns:
    """build_builder: two runs that build the same builder at once take turns. Two BuildKit builds that export one tag
    together fail the second with "image ... already exists" (Docker 29's containerd image store), as two pytest-xdist
    workers of the Docker tests did on the C builder (INFRA-5359)."""

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.scratch, self.count = tmp_path, itertools.count()  # a new cache for each call of most_at_once()

    def most_at_once(self, toolchains, turn, lock=check_build.cache_lock):
        """The most `docker build`s of a builder that ran at once, with build_builder called for each of `toolchains`
        in a thread of its own (check_build.in_threads), and the tag that each call returned; a call's failure is
        raised. The turns are `lock` (cache_lock by default). Each stand-in `docker build` waits until every call has
        asked for its turn, then until every build has started a `docker build`, for at most `turn` seconds: a build
        that waits for its turn has not started one by then, and a build that does not wait starts one at once."""
        changed, active, most, asked, started = threading.Condition(), [0], [0], [0], [0]

        @contextlib.contextmanager
        def asking(entry):
            with changed:
                asked[0] += 1
                changed.notify_all()
            with lock(entry):
                yield

        def run(*argv, quiet=False):
            if "--help" in argv:
                return 0
            with changed:
                active[0] += 1
                started[0] += 1
                most[0] = max(most[0], active[0])
                changed.notify_all()
                assert changed.wait_for(lambda: asked[0] == len(toolchains), timeout=60), "a call never asked"
                changed.wait_for(lambda: started[0] == len(toolchains), timeout=turn)
                active[0] -= 1
            return 0

        cache = self.scratch / f"cache{next(self.count)}"
        cache.mkdir()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "CACHE", cache)
            patch.setattr(check_build, "run", run)
            patch.setattr(check_build, "step", lambda text: None)
            patch.setattr(check_build, "cache_lock", asking)
            patch.setattr(check_build.shutil, "which", lambda name: f"/usr/bin/{name}")
            tags = check_build.in_threads(check_build.build_builder, toolchains, len(toolchains))
        for tag in tags:
            if isinstance(tag, BaseException):
                raise tag
        return most[0], tags

    def test_two_builds_of_one_builder_take_turns(self):
        most, tags = self.most_at_once([TOOLCHAIN, TOOLCHAIN], turn=1)
        assert (most, len(set(tags))) == (1, 1), tags
        # The control: without the turns, the two builds are in `docker build` at once, and this finds it. Both start
        # one at once, so the long bound costs no time.
        most, _ = self.most_at_once([TOOLCHAIN, TOOLCHAIN], turn=60, lock=lambda entry: contextlib.nullcontext())
        assert most == 2

    def test_two_builders_build_at_once(self):
        most, tags = self.most_at_once([TOOLCHAIN, check_build.newest_toolchain("rust")], turn=60)
        assert (most, len(set(tags))) == (2, 2), tags

    def test_a_cache_that_cannot_hold_the_lock_still_builds(self):
        """The lock is a courtesy to a second run: a run whose cache directory cannot be written (a read-only home,
        with --dir elsewhere) still builds the builder, with --no-cache too."""
        calls = []

        def run(*argv, quiet=False):
            calls.append(argv)
            return 0

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "run", run)
            patch.setattr(check_build, "step", lambda text: None)
            patch.setattr(check_build, "say", lambda text="": None)
            patch.setattr(check_build.shutil, "which", lambda name: f"/usr/bin/{name}")
            blocked = self.scratch / "a-file"
            blocked.write_text("")
            patch.setattr(check_build, "CACHE", blocked)
            check_build.build_builder(TOOLCHAIN, no_cache=True)
        builds = [argv for argv in calls if "--help" not in argv]
        assert len(builds) == 1, calls
        assert "--no-cache" in builds[0]


class TestProjectTag:
    """The project image's tag names the oss-verify tree that builds it and the run's work directory, so two trees, or
    two runs, on one Docker host keep two images."""

    COMMIT = "0123456789abcdef" * 2 + "01234567"
    BUILDER = "oss-verify-base-builder:0123456789abcdef-toolchain"
    HOME = pathlib.Path("/work/demo")

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.scratch, self.count = tmp_path, itertools.count()  # a new directory for each call of tag()

    def tag(self, files, builder=BUILDER, suffix="", home=HOME):
        directory = self.scratch / f"call{next(self.count)}" / "demo"
        directory.mkdir(parents=True)
        for name, text in files.items():
            (directory / name).write_text(text)
        job = check_build.Job(name="demo", directory=directory, repo="https://example.org/demo", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=None, language="c")
        return check_build.project_tag(job, self.COMMIT, builder, home, suffix)

    def test_identical_trees_give_the_same_tag(self):
        files = {"project.yaml": "repo: x\n", "Dockerfile": "FROM a\n"}
        assert self.tag(files) == self.tag(dict(files))
        assert self.tag(files).startswith(f"oss-verify-check/demo:{self.COMMIT[:12]}-")

    def test_a_different_project_directory_gives_a_different_tag(self):
        assert self.tag({"project.yaml": "repo: x\n", "Dockerfile": "FROM a\n"}) != \
            self.tag({"project.yaml": "repo: x\n", "Dockerfile": "FROM b\n"})
        assert self.tag({"project.yaml": "repo: x\n"}) != \
            self.tag({"project.yaml": "repo: x\n", "build.sh": "true\n"})

    def test_a_different_builder_gives_a_different_tag(self):
        files = {"project.yaml": "repo: x\n"}
        assert self.tag(files) != self.tag(files, builder=self.BUILDER + "-other")

    def test_a_different_work_directory_gives_a_different_tag(self):
        files = {"project.yaml": "repo: x\n"}
        assert self.tag(files) != self.tag(files, home=pathlib.Path("/work/other"))

    def test_build_all_records_the_tag_before_the_build(self):
        home = self.scratch / "home"
        home.mkdir()
        project = self.scratch / "project"
        project.mkdir()
        record = home / check_build.IMAGES
        seen = []

        def build_project(job, commit, builder, tag, work, no_cache=False, token=None):
            seen.append(check_build.recorded_images(record))
            raise check_build.Failed("stop here")

        job = check_build.Job(name="demo", directory=project, repo="https://example.org/demo",
                              ref="", dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=None,
                              language="c")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "build_builder", lambda *args: self.BUILDER)
            patch.setattr(check_build, "build_project", build_project)
            with pytest.raises(check_build.Failed):
                check_tool.build_all(job, self.COMMIT, home / "twice", TOOLCHAIN, home, "-twice")
        assert seen == [[check_build.project_tag(job, self.COMMIT, self.BUILDER, home, "-twice")]]

    def test_every_container_carries_the_work_label(self):
        label = check_build.work_label(self.HOME)
        commands = []

        def run(*argv, quiet=False):
            commands.append(argv)
            if "rm" in argv:  # empty_directory's docker rm -rf of a directory that rmtree could not remove
                out.rmdir()
            return 0

        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()):
            patch.setattr(check_build, "run", run)
            patch.setattr(check_build, "output", lambda *argv: commands.append(argv) or "")
            patch.setattr(check_build.shutil, "rmtree", raises(PermissionError))
            out = self.scratch / "out"
            out.mkdir()
            check_build.compile_build("t", "plain", "none", out, None, labels=label)  # empty_directory's rm, then compile
            check_build.sources("t", labels=label)
        docker_runs = [argv for argv in commands if argv[:2] == ("docker", "run")]
        assert len(docker_runs) == 3
        for argv in docker_runs:
            assert f"{label[0]} {label[1]}" in " ".join(argv)

    def test_the_suffix_stays_last(self):
        assert self.tag({"project.yaml": "repo: x\n"}, suffix="-twice").endswith("-twice")


class TestBuildAll:
    """check.build_all, with the Docker steps of check_build replaced."""

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.scratch = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir()
        (tmp_path / "project").mkdir()

    def test_a_program_build(self):
        programs = [{"file": "hello", "sha256": "1" * 64, "link_map": "hello.map"},
                    {"file": "world", "sha256": "2" * 64}]
        job = check_build.Job(name="demo", directory=self.scratch / "project", repo="https://example.org/demo",
                              ref="", dockerfile="", builds=["plain"], fuzz_targets=None, ubsan_checks=None,
                              language="c", programs=programs)
        compiles, images, written = [], [], {}

        def compile_build(*args, **kwargs):
            compiles.append((args, kwargs))
            out = args[3]
            out.mkdir(parents=True)
            for name, (data, mode) in written.items():
                (out / name).write_bytes(data)
                os.chmod(out / name, mode)

        def toolchain_environment(image):
            images.append(image)
            return TOOLCHAIN_ENV

        def build_all(work, suffix=""):
            return check_tool.build_all(job, COMMIT, work, TOOLCHAIN, self.home, suffix, record=True)

        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()):
            patch.setattr(check_build, "build_builder", lambda *args: "builder-tag")
            patch.setattr(check_build, "project_tag", lambda *args: "project-tag")
            patch.setattr(check_build, "build_project", lambda *args, **kwargs: None)
            patch.setattr(check_build, "toolchain_environment", toolchain_environment)
            patch.setattr(check_build, "compile_build", compile_build)
            # What build.sh leaves in $OUT: the programs, one link map, and a file that nothing lists.
            written.update({"hello": (elf(sections=[(".text", 10)]), 0o755), "world": (elf(), 0o755),
                            "hello.map": (b"map\n", 0o644), "env.txt": (b"A=1\n", 0o644)})
            work = self.scratch / "work"
            builder, tag, targets, entries = build_all(work)
            assert (builder, tag, targets) == ("builder-tag", "project-tag", ["hello", "world"])
            # The environment of the toolchain image alone, each entry ended by a NUL byte.
            assert images == [TOOLCHAIN]
            assert (work / "program-env").read_bytes() == b"".join(f"{entry}\0".encode() for entry in TOOLCHAIN_ENV)
            # One build, the plain one, with the environment and with no record, layout or base layout, though the
            # call asked for the records of --checks.
            (args, kwargs), = compiles
            assert args == ("project-tag", "plain", "none", work / "raw" / "plain")
            assert kwargs == {"labels": check_build.work_label(self.home), "program_env": work / "program-env"}
            # The programs and the link map are taken from the plain build's $OUT as it holds them.
            assert entries == {name: {"plain": manifest.file_entry(work / "out" / name / name)} for name in targets}
            assert entries["hello"]["plain"]["sha256"] == manifest.sha256_of(work / "raw" / "plain" / "hello")
            assert sorted(path.relative_to(work / "out").as_posix() for path in (work / "out").rglob("*")
                          if path.is_file()) == ["hello/hello", "hello/hello.map", "world/world"]
            # The second build of --twice writes the environment into its own work directory.
            build_all(work / "twice", "-twice")
            assert (work / "twice" / "program-env").read_bytes() == (work / "program-env").read_bytes()
            assert len(compiles) == 2 and compiles[1][1]["program_env"] == work / "twice" / "program-env"
            # A problem of collect_programs stops the build, with its text.
            written.clear()
            with pytest.raises(check_build.Failed) as failed:
                build_all(self.scratch / "empty")
        text = str(failed.value)
        assert "program hello, which project.yaml lists, is not in $OUT: build.sh did not write it" in text
        assert "program world, which project.yaml lists, is not in $OUT: build.sh did not write it" in text
        assert "the link map hello.map of program hello, which project.yaml names, is not in $OUT" in text

    @pytest.mark.parametrize("collector", ["collect", "collect_programs"], ids=["fuzz-targets", "programs"])
    def test_a_file_of_out_that_cannot_be_read_fails_the_build(self, collector):
        """An OSError of the steps that read $OUT after the compiles, for example for a file that build.sh left
        unreadable, is Failed: check.main then prints BUILD FAILED and exits 1, with no traceback."""
        programs = [{"file": "hello", "sha256": "1" * 64}] if collector == "collect_programs" else None
        job = check_build.Job(name="demo", directory=self.scratch / "project", repo="https://example.org/demo",
                              ref="", dockerfile="", builds=["plain"], fuzz_targets=None, ubsan_checks=None,
                              language="c", programs=programs)
        unreadable = PermissionError(13, "Permission denied", str(self.scratch / "work" / "raw" / "plain" / "hello"))
        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()):
            patch.setattr(check_build, "build_builder", lambda *args: "builder-tag")
            patch.setattr(check_build, "project_tag", lambda *args: "project-tag")
            patch.setattr(check_build, "build_project", lambda *args, **kwargs: None)
            patch.setattr(check_build, "toolchain_environment", lambda image: TOOLCHAIN_ENV)
            patch.setattr(check_build, "compile_build", lambda *args, **kwargs: args[3].mkdir(parents=True))
            patch.setattr(manifest, collector, raises(unreadable))
            with pytest.raises(check_build.Failed) as failed:
                check_tool.build_all(job, COMMIT, self.scratch / "work", TOOLCHAIN, self.home)
        assert str(unreadable) in str(failed.value)
        assert failed.value.__suppress_context__


class TestTreeHash:
    """check_build.tree_hash, which names the builder image and the project image: one tree, one hash."""

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.scratch, self.count = tmp_path, itertools.count()  # a new directory for each call of hash_of()

    def hash_of(self, files, links=()):
        root = self.scratch / f"call{next(self.count)}"
        root.mkdir()
        for name, data in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)
        for name, target in links:
            (root / name).symlink_to(target)
        return check_build.tree_hash(root)

    def test_a_file_cannot_pass_for_two(self):
        # Without lengths, the stream of a, with these bytes, was the stream of the files a and b.
        assert self.hash_of({"a": b"x", "b": b"y"}) != self.hash_of({"a": b"x\0b\x000\0y"})

    def test_the_same_tree_gives_the_same_hash(self):
        files = {"Dockerfile": b"FROM a\n", "sub/build.sh": b"true\n"}
        assert self.hash_of(files) == self.hash_of(dict(files))
        assert self.hash_of(files) != self.hash_of({**files, "sub/build.sh": b"false\n"})
        assert self.hash_of(files) != self.hash_of({"Dockerfile": b"FROM a\n", "sub/build.SH": b"true\n"})

    def test_bytecode_caches_are_left_out(self):
        files = {"tool.py": b"print(1)\n"}
        assert self.hash_of(files) == self.hash_of({**files, "__pycache__/tool.pyc": b"\0\0"})

    def test_a_link_counts_as_its_text(self):
        # docker build sends a link as a link: the hash is of where it points, never of the file it reaches, and a
        # link to a directory counts too.
        files = {"target": b"data"}
        link = self.hash_of(files, links=[("alias", "target")])
        assert link != self.hash_of({**files, "alias": b"data"})
        assert link != self.hash_of(files, links=[("alias", "elsewhere")])
        assert self.hash_of(files) != self.hash_of(files, links=[("dir", "/etc")])


class TestCacheLock:
    """check_build.cache_lock: one run at a time fills a cache entry."""

    def test_a_second_holder_waits(self, tmp_path):
        import fcntl
        entry = tmp_path / "model" / COMMIT
        with check_build.cache_lock(entry):
            with open(entry.parent / f"{entry.name}.lock", "a") as other:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with open(entry.parent / f"{entry.name}.lock", "a") as other:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released: no wait
            fcntl.flock(other, fcntl.LOCK_UN)

    def test_validate_runs_without_fcntl(self):
        """fcntl is POSIX only. oss-verify validate, and the triage preview of CONTRIBUTING.md, import check_build, so
        it must import, and validate, where there is no fcntl (as on Windows); only cache_lock needs it."""
        code = ("import sys; sys.modules['fcntl'] = None;"
                " from oss_verify import check_build, validate;"
                " problems, _, summary = validate.check_project(validate.PROJECTS / 'bzip2');"
                " print(problems, bool(summary))")
        done = subprocess.run([sys.executable, "-P", "-c", code], capture_output=True, text=True,
                              env={**os.environ, "PYTHONPATH": str(SRC)})
        assert (done.returncode, done.stdout.strip()) == (0, "[] True"), done.stderr

    def test_the_model_is_fetched_once_under_the_lock(self, tmp_path):
        import fcntl
        from oss_verify import model_release
        calls = []
        cache = tmp_path
        home = cache / "model" / COMMIT

        def clone(repository, commit, checkout):
            with open(home.parent / f"{home.name}.lock", "a") as other:
                with pytest.raises(BlockingIOError):  # fetch() holds the entry's lock while git writes
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            checkout.mkdir(parents=True, exist_ok=True)
            calls.append((repository, commit))

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "clone", clone)
            assert model_release.fetch("https://github.com/o/m", COMMIT, cache) == home
            assert model_release.fetch("https://github.com/o/m", COMMIT, cache) == home
        assert calls == [("https://github.com/o/m", COMMIT)]


class TestContainerCleanup:
    """A container outlives its docker run client: oss-verify check removes the containers it started when it ends,
    however it ends, and they keep no log on the Docker host."""

    # A stand-in for docker on PATH: it logs each command; `docker run` runs until it is killed, or until `docker rm`
    # removes its container, which ends the real client too; `docker ps` lists two containers; `docker stop` is a
    # docker that does not answer, and runs until it is killed, or until that `docker rm` removes the container that
    # it waits for. With DOCKER_STARTED set, `docker run` writes a line to that FIFO once it has logged its command,
    # and `docker stop` to DOCKER_STOPPING. A signal can land while subprocess.run is still starting either client,
    # after the client has written that line: subprocess.run then never kills it, and only the `docker rm` ends it
    # (seen for `docker run` in 1 run of 30 on a loaded machine).
    DOCKER = ('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
              'case $1 in\n'
              '  run) echo $$ > "$DOCKER_LOG.run"; [ -z "${DOCKER_STARTED-}" ] || echo > "$DOCKER_STARTED"\n'
              '       exec sleep 30 ;;\n'
              '  stop) echo $$ > "$DOCKER_LOG.stop"; [ -z "${DOCKER_STOPPING-}" ] || echo > "$DOCKER_STOPPING"\n'
              '        exec sleep 30 ;;\n'
              '  ps) printf "c1\\nc2\\n" ;;\n'
              '  rm) for client in run stop; do\n'
              '        [ ! -e "$DOCKER_LOG.$client" ] || kill "$(cat "$DOCKER_LOG.$client")" 2>/dev/null\n'
              '      done; exit 0 ;;\n'
              'esac\n')
    # A run as oss-verify check's __main__ makes it, whose one step is a docker run. Ctrl-C as from a terminal, and
    # SIGHUP and SIGTERM at their defaults, even where the tests run with one ignored (nohup pytest): a child keeps an
    # ignored signal ignored, and containers_stopped() then leaves it so.
    CHILD = ("import signal, subprocess, sys; from oss_verify import check_build\n"
             "signal.signal(signal.SIGINT, signal.default_int_handler)\n"
             "signal.signal(signal.SIGHUP, signal.SIG_DFL)\n"
             "signal.signal(signal.SIGTERM, signal.SIG_DFL)\n"
             "with check_build.containers_stopped():\n"
             "    try:\n"
             "        subprocess.run(['docker', 'run', *check_build.work_label('/work'), 'image', 'compile'])\n"
             "    except KeyboardInterrupt:\n"
             "        sys.exit(130)\n")

    def fake_docker(self, scratch):
        directory = pathlib.Path(scratch)
        (directory / "docker").write_text(self.DOCKER, encoding="utf-8")
        (directory / "docker").chmod(0o755)
        log = directory / "log"
        log.touch()
        env = {**os.environ, "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}", "DOCKER_LOG": str(log)}
        return env, log

    def test_every_container_carries_the_run_label_and_keeps_no_log(self):
        options = check_build.work_label(pathlib.Path("/work"))
        assert options == ["--label", f"{check_build.WORK_LABEL}=/work",
                           "--label", f"{check_build.RUN_LABEL}={check_build.RUN}", "--log-driver=none"]

    def test_stop_containers_removes_this_process_containers(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "c1\nc2\n" if argv[1] == "ps" else "", "")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build.subprocess, "run", run)
            check_build.stop_containers()
        mine = f"label={check_build.RUN_LABEL}={check_build.RUN}"
        assert calls == [["docker", "ps", "-aq", "--filter", mine], ["docker", "rm", "-f", "c1", "c2"]]

    def test_stop_containers_with_none_left_or_no_docker_does_nothing(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build.subprocess, "run", run)
            check_build.stop_containers()
        assert [argv[1] for argv in calls] == ["ps"]
        for error in (FileNotFoundError("docker"), subprocess.TimeoutExpired("docker", 60)):
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(check_build.subprocess, "run", raises(error))
                check_build.stop_containers()  # no error

    @pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt],
                             ids=["no-error", "RuntimeError", "KeyboardInterrupt"])
    def test_containers_are_stopped_however_the_block_ends(self, error):
        """At its end, normal or by an error, with no signal able to cut the removal short; then each signal's handler
        is what it was."""
        import signal
        before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        seen = []

        def stop():
            seen.append({number: signal.getsignal(number) for number in before})

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "stop_containers", stop)
            with contextlib.suppress(*([error] if error else [])):
                with check_build.containers_stopped():
                    if error:
                        raise error()
            assert seen == [{number: signal.SIG_IGN for number in before}]
            assert {number: signal.getsignal(number) for number in before} == before

    def test_a_signal_ignored_at_the_start_stays_ignored(self):
        """nohup oss-verify check: the SIGHUP that nohup ignores still does not end the run, in the block or after
        it."""
        import signal
        previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
        try:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(check_build, "stop_containers", lambda: None)
                with check_build.containers_stopped():
                    assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
                    assert signal.getsignal(signal.SIGTERM) not in (signal.SIG_IGN, signal.SIG_DFL)
            assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
        finally:
            signal.signal(signal.SIGHUP, previous)

    @pytest.mark.parametrize("signame, code", [("SIGTERM", 143), ("SIGHUP", 129), ("SIGINT", 130)])
    def test_a_signal_ends_the_run_and_its_containers(self, signame, code, tmp_path, request):
        """SIGTERM, SIGHUP or Ctrl-C while a docker run runs: the run ends with 128 + the signal's number, and removes
        each container that carries its own label."""
        import signal
        number = getattr(signal, signame)
        env, log = self.fake_docker(tmp_path)
        # The signal is sent once the docker run has started: the stand-in writes to this FIFO then. It is
        # opened first, and without waiting for a writer, so that the stand-in's write never waits for it.
        started = tmp_path / "started"
        os.mkfifo(started)
        reader = os.open(started, os.O_RDONLY | os.O_NONBLOCK)
        request.addfinalizer(functools.partial(os.close, reader))
        process = subprocess.Popen([sys.executable, "-P", "-c", self.CHILD],
                                   env={**env, "PYTHONPATH": str(SRC), "DOCKER_STARTED": str(started)},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        request.addfinalizer(process.kill)  # if it does not end, as a test that fails leaves it
        select.select([reader], [], [], 20)
        process.send_signal(number)
        _, errors = process.communicate(timeout=20)
        assert process.returncode == code, errors
        started, listed, removed = log.read_text(encoding="utf-8").splitlines()
        run = next(arg for arg in started.split() if arg.startswith(f"{check_build.RUN_LABEL}="))
        assert listed == f"ps -aq --filter label={run}"
        assert removed == "rm -f c1 c2"

    # A run whose main thread is inside a write that a full pipe blocks, which nothing else interrupts, when another
    # thread takes SIGTERM: Python then has the signal, and its handler waits for the main thread.
    BLOCKED = ("import os, select, signal, threading; from oss_verify import check_build\n"
               "check_build.stop_containers = lambda: None\n"
               "signal.signal(signal.SIGTERM, signal.SIG_DFL)\n"
               "reading, writing = os.pipe()\n"
               "def take():\n"
               "    select.select([reading], [], [], 20)  # data: the main thread is inside its write\n"
               "    os.read(reading, 1)\n"
               "    signal.pthread_kill(threading.get_ident(), signal.SIGTERM)\n"
               "threading.Thread(target=take, daemon=True).start()\n"
               "with check_build.containers_stopped():\n"
               "    os.write(writing, bytes(1 << 20))  # more than a pipe holds\n")

    def test_a_signal_taken_while_the_main_thread_waits_ends_the_run(self):
        """Python runs a handler in the main thread, between bytecodes. A signal that arrives just before the main
        thread blocks in a wait, or that another thread takes, interrupts no wait, so the run would go on until the wait
        ends: here, never. containers_stopped() still ends it, with 143. In a child, so that a run that does not end
        is killed at the deadline."""
        try:
            done = subprocess.run([sys.executable, "-P", "-c", self.BLOCKED],
                                  env={**os.environ, "PYTHONPATH": str(SRC)}, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            pytest.fail("the run went on after SIGTERM until it was killed at the deadline")
        assert done.returncode == 143, done.stderr

    # A run whose Ctrl-C another thread, one that runs already, takes just after containers_stopped() has set its
    # wakeup fd: Python then runs the handler in the main thread, in the setup. The wakeup fd before is a pipe of the
    # run's own.
    SETTING_UP = ("import os, signal, threading; from oss_verify import check_build\n"
                  "stopped = []\n"
                  "check_build.stop_containers = lambda: stopped.append(None)\n"
                  "signal.signal(signal.SIGINT, signal.default_int_handler)\n"
                  "reading, writing = os.pipe()\n"
                  "os.set_blocking(writing, False)\n"
                  "signal.set_wakeup_fd(writing)\n"
                  "send, sent = threading.Event(), threading.Event()\n"
                  "def take():\n"
                  "    send.wait()\n"
                  "    signal.pthread_kill(threading.get_ident(), signal.SIGINT)\n"
                  "    sent.set()\n"
                  "threading.Thread(target=take, daemon=True).start()\n"
                  "set_wakeup_fd = signal.set_wakeup_fd\n"
                  "def set_then_signal(fd, **options):\n"
                  "    signal.set_wakeup_fd = set_wakeup_fd  # once\n"
                  "    previous = set_wakeup_fd(fd, **options)\n"
                  "    send.set()\n"
                  "    sent.wait()  # the handler now waits for the main thread, which runs it here\n"
                  "    return previous\n"
                  "signal.set_wakeup_fd = set_then_signal\n"
                  "interrupted = False\n"
                  "try:\n"
                  "    with check_build.containers_stopped():\n"
                  "        pass\n"
                  "except KeyboardInterrupt:\n"
                  "    interrupted = True\n"
                  "print(f'interrupted={interrupted} stopped={len(stopped)}',\n"
                  "      f'wakeup_fd_restored={signal.set_wakeup_fd(-1) == writing}',\n"
                  "      f'handler_restored={signal.getsignal(signal.SIGINT) is signal.default_int_handler}')\n")

    def test_a_signal_taken_while_the_run_sets_up_ends_it_and_the_setup_is_put_back(self):
        """A thread holds a signal back only for itself: one that runs already can take Ctrl-C while
        containers_stopped() changes the process's signal state, and Python then runs the handler in the main thread,
        in the setup. The run still ends with KeyboardInterrupt and removes its containers, and the wakeup fd is the one
        before again, not the run's pipe, which it closed. In a child, whose signal state is its own."""
        done = subprocess.run([sys.executable, "-P", "-c", self.SETTING_UP],
                              env={**os.environ, "PYTHONPATH": str(SRC)}, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=20)
        assert done.returncode == 0, done.stderr
        assert done.stdout.split() == ["interrupted=True", "stopped=1", "wakeup_fd_restored=True",
                                       "handler_restored=True"], done.stderr

    # The run of CHILD, whose unwinding from the first signal waits on a docker that does not answer: `docker stop`.
    STOPPING = ("import signal, subprocess, sys; from oss_verify import check_build\n"
                "signal.signal(signal.SIGINT, signal.default_int_handler)\n"
                "signal.signal(signal.SIGHUP, signal.SIG_DFL)\n"
                "signal.signal(signal.SIGTERM, signal.SIG_DFL)\n"
                "with check_build.containers_stopped():\n"
                "    try:\n"
                "        try:\n"
                "            subprocess.run(['docker', 'run', *check_build.work_label('/work'), 'image', 'compile'])\n"
                "        except (KeyboardInterrupt, SystemExit):\n"
                "            subprocess.run(['docker', 'stop', 'c1'])\n"
                "            raise\n"
                "    except KeyboardInterrupt:\n"
                "        sys.exit(130)\n")

    @pytest.mark.parametrize("signame, code", [("SIGTERM", 143), ("SIGHUP", 129), ("SIGINT", 130)])
    def test_a_second_signal_stops_a_wait_for_a_docker_that_does_not_answer(self, signame, code, tmp_path, request):
        """The first SIGTERM, SIGHUP or Ctrl-C ends the run; a second one stops whatever that ending waits for, as a
        command's user expects, and the run still removes its containers and ends with 128 + the signal's number. A
        user whose docker does not answer would otherwise need SIGKILL, which leaves the containers behind."""
        import signal
        number = getattr(signal, signame)
        env, log = self.fake_docker(tmp_path)
        fifos = {}
        for name in ("started", "stopping"):
            os.mkfifo(tmp_path / name)
            fifos[name] = os.open(tmp_path / name, os.O_RDONLY | os.O_NONBLOCK)
            request.addfinalizer(functools.partial(os.close, fifos[name]))
        process = subprocess.Popen([sys.executable, "-P", "-c", self.STOPPING],
                                   env={**env, "PYTHONPATH": str(SRC),
                                        "DOCKER_STARTED": str(tmp_path / "started"),
                                        "DOCKER_STOPPING": str(tmp_path / "stopping")},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        request.addfinalizer(process.kill)  # if it does not end, as a test that fails leaves it
        select.select([fifos["started"]], [], [], 20)
        process.send_signal(number)
        select.select([fifos["stopping"]], [], [], 20)
        process.send_signal(number)
        # Well before `docker stop` would end by itself, after 30 s.
        _, errors = process.communicate(timeout=10)
        assert process.returncode == code, errors
        assert [line.split()[0] for line in log.read_text(encoding="utf-8").splitlines()] == \
            ["run", "stop", "ps", "rm"]

    def test_the_check_command_removes_its_containers_when_it_ends(self, tmp_path):
        """`oss-verify check` runs within containers_stopped(): even a run that starts none asks for its own."""
        env, log = self.fake_docker(tmp_path)
        done = subprocess.run([sys.executable, "-P", "-m", "oss_verify", "check", "--print-toolchain", "bzip2"],
                              env={**env, "PYTHONPATH": str(SRC)},
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        assert done.returncode == 0, done.stderr
        assert re.search(rf"\Aps -aq --filter label={check_build.RUN_LABEL}=[0-9a-f]{{32}}\nrm -f c1 c2\n\Z",
                         log.read_text(encoding="utf-8"))

    def test_in_threads_gives_each_result_or_error_in_order(self):
        def job(n):
            if n == 1:
                raise check_build.Failed("no run")
            return n * 10

        first, second, third = check_build.in_threads(job, [0, 1, 2], 2)
        assert (first, third) == (0, 20)
        assert isinstance(second, check_build.Failed)

    @pytest.mark.parametrize("stop", [KeyboardInterrupt(), SystemExit(143)],
                             ids=["KeyboardInterrupt", "SystemExit"])
    def test_in_threads_abandons_its_calls_when_its_wait_is_stopped(self, stop):
        """Ctrl-C, or SIGTERM or SIGHUP through containers_stopped(), while in_threads() waits: no queued call starts,
        the containers of the running one are stopped, and the stop is raised again. Both pools of docker runs, the
        binaries' runs (check_binaries) and the breakages (check_checks), run in in_threads()."""
        import threading
        running, released, started, stopped = threading.Event(), threading.Event(), [], []

        def job(n):
            started.append(n)
            running.set()
            released.wait(20)  # until its container is removed

        def wait(futures, *args, **kwargs):  # stopped once a call runs
            assert running.wait(20)
            raise stop

        def stop_containers():
            stopped.append(True)
            released.set()

        with pytest.MonkeyPatch.context() as patch, pytest.raises(type(stop)):
            patch.setattr(check_build.concurrent.futures, "wait", wait)
            patch.setattr(check_build, "stop_containers", stop_containers)
            check_build.in_threads(job, range(4), 1)
        assert (started, stopped) == ([0], [True])

    def test_abandon_starts_no_queued_job_and_stops_the_running_one(self):
        import concurrent.futures
        import threading
        running, released, started = threading.Event(), threading.Event(), []

        def job(n):
            started.append(n)
            running.set()
            released.wait(20)  # until its container is removed

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "stop_containers", released.set)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                futures = [pool.submit(job, n) for n in range(4)]
                assert running.wait(20)
                check_build.abandon(pool)
        assert started == [0]
        assert all(future.cancelled() for future in futures[1:])


class TestToolchains:
    """The toolchain that oss-verify check builds a project with, by its language (infra/toolchains.tsv)."""

    def test_the_newest_for_a_language(self):
        assert check_build.newest_toolchain() == check_build.newest_toolchain("c")
        assert check_build.newest_toolchain("c") == check_build.newest_toolchain("c++")
        assert "oss-fuzz-theorems-toolchain-rust@sha256:" in check_build.newest_toolchain("rust")
        assert check_build.languages_of(check_build.newest_toolchain("rust")) == ("rust",)
        # The newest Python toolchain is the prebuilt image, which publish-prebuilt puts in the package of the
        # frame-pointer images (.github/workflows/toolchain-images-publish.yaml), not in the one of the row it is made
        # from.
        assert "oss-fuzz-theorems-toolchain@sha256:" in check_build.newest_toolchain("python")
        assert check_build.languages_of(check_build.newest_toolchain("python")) == ("python",)
        assert check_build.languages_of("example.org/not-listed:1") is None
        with pytest.raises(check_build.Failed):
            check_build.newest_toolchain("javascript")

    def test_a_toolchain_for_another_language_is_refused(self, tmp_path, monkeypatch):
        project = tmp_path / "demo"
        project.mkdir()
        (project / "project.yaml").write_text(
            "repo: https://example.org/demo#" + "a" * 40 + "\nprimary_contact: a@example.org\nlanguage: python\n")
        (project / "Dockerfile").write_text("FROM x\n")
        (project / "build.sh").write_text("#!/bin/bash\n")
        c_toolchain = check_build.newest_toolchain("c")
        monkeypatch.setattr(sys, "argv", ["oss-verify", "--no-shell", "--toolchain", c_toolchain, str(project)])
        with contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as stop:
            check_tool.main()
        assert "builds c, c++, not python" in str(stop.value.code)

    def test_a_seeded_project_with_no_build_files_is_refused_with_exit_1(self, tmp_path, monkeypatch):
        # oss-verify validate only warns about it (it breaks no enrollment rule, so not exit 2); there is nothing to
        # build
        project = tmp_path / "demo"
        project.mkdir()
        (project / "project.yaml").write_text(
            "repo: https://example.org/demo#" + "a" * 40 + "\nprimary_contact: n/a\nlanguage: c\n")
        monkeypatch.setattr(sys, "argv", ["oss-verify", "--no-shell", str(project)])
        with contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as stop:
            check_tool.main()
        assert isinstance(stop.value.code, str)  # sys.exit(message): exit status 1
        assert "has no Dockerfile" in stop.value.code
