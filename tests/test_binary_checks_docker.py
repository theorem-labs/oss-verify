# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example with the link records of oss-verify check --checks, and check what the records and the
runs of the checks of the binaries give. TestProgram runs oss-verify check on tests/fixtures/program, a port of one
whole program, and checks what it records and refuses, and the environment that the program's build sees. Needs Docker
and the toolchain image:

    OV_DOCKER_TESTS=1 uv run pytest

The runs need qemu-riscv64-static on PATH; without it, they are skipped.
"""
import contextlib
import dataclasses
import io
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import traceback

import pytest
import yaml

from oss_verify import binary_isa
from oss_verify import check
from oss_verify import check_binaries
from oss_verify import check_build
from oss_verify import check_links
from oss_verify import manifest
from oss_verify import validate
from test_builder import RUN, compile_builds, docker_ready

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = f"oss-verify-test/example-records:{RUN}"
QEMU = shutil.which("qemu-riscv64-static")
BUILDS = ["plain", "ubsan", "asan"]

# tests/fixtures/program: a port of one whole program, hello, that its own Makefile builds with the link map hello.map.
PROGRAM_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "program"
PROGRAM, LINK_MAP = "hello", "hello.map"
# The string literal that the program prints, and the same literal with one byte changed.
GREETING, CHANGED_GREETING = '"hello from a whole program"', '"Hello from a whole program"'
# oss-verify check takes the copies of tests/fixtures/program with two stand-ins, as tests/test_append_docker.py does:
# validate refuses its src/ directory (only regular files may sit beside project.yaml), and its repo,
# https://example.invalid/program, is no repository to resolve. Its Dockerfile copies the build context, so the commit
# only names the image.
COMMIT = "0" * 40
# The two environment listings of the main run: build.sh writes env.txt to $OUT, and raw/plain is the $OUT of a build.
ENV_FILES = ("raw/plain/env.txt", "twice/raw/plain/env.txt")
# The variables that each container or shell sets for itself, which the comparison of two environments leaves out.
# Docker sets HOSTNAME. bash sets PWD, SHLVL and _, and OLDPWD after a cd.
OWN_VARIABLES = ("HOSTNAME", "PWD", "OLDPWD", "SHLVL", "_")
# What the build of a program sees in addition to the toolchain image's own environment and HOME=/tmp
# (docs/build-contract.md, "The environment of a program's build").
ADDED_VARIABLES = ("SRC=/src", "WORK=/work", "OUT=/out")
# The settings of the fuzz builds, which the build of a program must not see (docs/build-contract.md, "The environment
# of a program's build"): those that infra/base-builder/compile and toolchain.sh set and export, those that
# check_build.compile_build passes, and the ENV of the port (tests/fixtures/program/Dockerfile). SOURCE_DATE_EPOCH and
# the PATH entry /tmp/shim have checks of their own in test_no_setting_of_the_fuzz_builds.
FUZZ_SETTINGS = ("SANITIZER", "OV_TEST_PORT_SETTING", "OV_OWNER", "OFT_MAKE_JOBS", "OV_RECORD", "OV_RECORDS", "FLAV",
                 "CHOST", "CC", "CXX", "CFLAGS", "CXXFLAGS", "DRVCC", "DRVCXX", "BASE_CFLAGS", "SAN", "AR", "NM",
                 "RANLIB", "STRIP", "OBJCOPY", "CMAKE_TOOLCHAIN_FILE", "LIB_FUZZING_ENGINE",
                 "LIB_ALLOCATION_FAILURE_ENGINE", "LIB_ALLOCATION_COUNTING_ENGINE", "LIB_DSL_ENGINE", "ARCHITECTURE",
                 "FUZZING_ENGINE")
# Run (d): after make, a text file in place of the program. It has the execute bit, so the check refuses it because it
# is not an ELF file.
TEXT_PROGRAM = 'printf "not a program\\n" > "$OUT/hello"\nchmod 0755 "$OUT/hello"\n'
# Run (e): the program linked dynamically, in place of the fixture's make. First as a static PIE, which has a PT_DYNAMIC
# header. If the toolchain cannot link one, the partial output is removed, and the program is linked as a shared
# object. musl.cfg links with -static, so -Wl,-shared gives -shared to the linker also if clang does not pass it on.
DYNAMIC_LINK = ("if ! make LDFLAGS=-static-pie; then\n"
                "  rm -f hello hello.map\n"
                "  make LDFLAGS='-shared -nostdlib -Wl,-shared'\n"
                "fi\n")
# How much of the end of a run's log a row shows when it fails.
LOG_TAIL = 6000


@pytest.mark.skipif(os.environ.get("OV_DOCKER_TESTS") != "1" or not docker_ready(),
                    reason="set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class TestRecords:
    @pytest.fixture(scope="class", autouse=True)
    def set_up_class(self, request, tmp_path_factory):
        cls = request.cls
        cls.work = tmp_path_factory.mktemp("ov-test-records")
        # A finalizer runs when this fixture fails too, so a compile failure removes this process's image as well.
        request.addfinalizer(lambda: subprocess.run(["docker", "image", "rm", TAG], capture_output=True))
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, TAG, cls.work)
        labels = check_build.work_label(cls.work)
        for kind, record in (("recorded", True), ("unrecorded", False)):
            compile_builds(TAG, {build: cls.work / kind / build for build in BUILDS}, labels, record=record)
        cls.raw = {build: cls.work / "recorded" / build for build in BUILDS}
        cls.targets, _ = manifest.resolve_targets({b: manifest.discover(d) for b, d in cls.raw.items()})
        cls.entries, _ = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    def test_records_change_no_byte(self):
        for build in BUILDS:
            recorded = sorted(p.name for p in (self.work / "recorded" / build / ".stripped").iterdir())
            unrecorded = sorted(p.name for p in (self.work / "unrecorded" / build / ".stripped").iterdir())
            assert recorded == unrecorded, build
            for name in recorded:
                assert manifest.sha256_of(self.work / "recorded" / build / ".stripped" / name) == \
                    manifest.sha256_of(self.work / "unrecorded" / build / ".stripped" / name)
            assert not (self.work / "unrecorded" / build / ".records").exists()

    def test_every_fuzz_target_has_a_record_and_a_quiet_twin(self):
        for build in BUILDS:
            for target in self.targets:
                record, quiet = check_binaries.record_of(self.raw[build], target)
                assert isinstance(record, check_links.Record), (build, target, record)
                assert quiet is not None, (build, target)
                assert any(path.endswith("/cli.o") for path in record.driver)

    def test_the_lists_and_the_instrumentation(self):
        # As check_binaries.binary_checks does: each build's compile records, read from its own $OUT.
        records = {build: check_binaries.record_of(self.raw[build], "example_fuzzer",
                                                   check_links.read_compiles(self.raw[build]))[0] for build in BUILDS}
        assert records["ubsan"].compiles is not None
        wanted = {real for record in records.values() for real, _, _ in record.inputs.values()
                  if real.startswith("/opt/")}
        toolchain = check_build.newest_toolchain()
        image = check_binaries.image_hashes(toolchain, wanted, labels=[])
        results = check_links.analyse(records, image, check_binaries.dwarf_reader(toolchain, []))
        assert results["plain"]["instrumented"]["result"] == "plain"
        for build in ("ubsan", "asan"):
            assert results[build]["instrumented"]["result"] == "pass", results[build]["instrumented"]
        # The compile records that compile and record-compile wrote decide the fixture's own objects in the ubsan build.
        assert "by the compile that wrote them" in results["ubsan"]["instrumented"]["detail"]
        kinds = {entry["kind"] for entry in results["asan"]["uninstrumented"]}
        assert {"libc", "compiler-rt", "sanitizer-runtime"} <= kinds, kinds
        assert "sanitizer-runtime" not in {entry["kind"] for entry in results["plain"]["uninstrumented"]}

    def test_dwarf_of_assembly(self):
        """The toolchain's clang writes no STT_FILE for an assembly source, only a DWARF unit in the assembler's
        language: check_links reads that unit to list hand-written assembly."""
        script = ('cd /tmp && printf ".globl f\\nf:\\n ret\\n" > x.S && clang --config=/opt/asan-static/musl.cfg '
                  '-march=rv64g -g -c x.S -o x.o && cat x.o')
        toolchain = check_build.newest_toolchain()
        data = subprocess.run(["docker", "run", "--rm", "--network=none", "--entrypoint", "sh", toolchain,
                               "-c", script], capture_output=True, check=True).stdout
        facts = check_links.object_facts(data)
        assert not facts.compiled
        unit = check_binaries.dwarf_reader(toolchain, [])([data])[0]
        assert (unit[0], unit[1]) == ("DW_LANG_Mips_Assembler", "x.S"), unit

    @pytest.mark.skipif(not QEMU, reason="no qemu-riscv64-static on PATH")
    def test_the_runs(self):
        inputs = [(check_binaries.EMPTY, check_binaries.HEADER), ("returns 1", check_binaries.HEADER + b"r")]
        for build in ("plain", "asan"):
            job_dir = self.work / "jobs" / build
            files = job_dir / "job"
            (files / "inputs").mkdir(parents=True)
            shutil.copyfile(self.work / "out" / "example_fuzzer" / f"example_fuzzer.{build}", files / "binary")
            (files / "quiet").write_bytes(check_binaries.record_of(self.raw[build], "example_fuzzer")[1])
            os.chmod(files / "binary", 0o755)
            os.chmod(files / "quiet", 0o755)
            runs = []
            for n, (_, data) in enumerate(inputs):
                (files / "inputs" / str(n)).write_bytes(data)
                runs += [f"l{n} binary inputs/{n} example_fuzzer", f"q{n} quiet inputs/{n} example_fuzzer"]
            (files / "runs").write_text("".join(f"{run}\n" for run in runs))
            results = check_binaries.run_job(job_dir, check_build.newest_toolchain(), pathlib.Path(QEMU).resolve(), [],
                                             600)
            assert [(results / f"l{n}.status").read_text().strip() for n in range(2)] == ["0", "78"]
            assert (results / "l0.out").read_text().strip() != "0", "the loud binary writes"
            agreement = check_binaries.quiet_loud(True, "", inputs, results)
            assert agreement["result"] == "pass", agreement
            trace = (results / "l0.trace").read_text()
            assert re.search(r'openat\(AT_FDCWD,"input\.bin"', trace)
            calls = (results / "l0.calls").read_text().split("\n")
            assert calls[0] == "exec"
            mmaps = [line.split() for line in calls if line.startswith("mmap ")]
            assert mmaps, "the host-side log has no mmap"
            if build == "asan":
                # The AddressSanitizer runtime's shadow: a mapping of 4 GiB or more, which qemu's log cannot print.
                assert any(int(fields[3], 16) >= 1 << 32 for fields in mmaps), mmaps[:5]


@dataclasses.dataclass
class Run:
    """One oss-verify check run of TestProgram: its arguments, its exit status (None if it raised an exception), its log
    (its standard output and standard error together) and its work directory."""
    argv: list
    code: int | None
    log: str
    work: pathlib.Path


def outside_build(toolchain, cflags=None):
    """The SHA-256 of the program of tests/fixtures/program as its own Makefile builds it outside oss-verify check: in a
    container of the toolchain image `toolchain`, with no network, with the image's own environment and HOME=/tmp,
    with CFLAGS=`cflags` if it is given, at the fixed path /opt/hello. It writes nothing on the host."""
    settings = [] if cflags is None else ["-e", f"CFLAGS={cflags}"]
    done = subprocess.run(["docker", "run", "--rm", "--network", "none", "-e", "HOME=/tmp", *settings,
                           "-v", f"{PROGRAM_FIXTURE / 'src'}:/in:ro", "--entrypoint", "sh", toolchain, "-c",
                           "cp -R /in /opt/hello && make -C /opt/hello >&2 && sha256sum /opt/hello/hello"],
                          capture_output=True, text=True)
    found = re.fullmatch(r"([0-9a-f]{64})  /opt/hello/hello\n", done.stdout)
    if done.returncode != 0 or found is None:
        pytest.fail(f"the build outside oss-verify check (CFLAGS {cflags!r}) exited {done.returncode} and printed "
                    f"{done.stdout!r}; the end of its standard error:\n{done.stderr[-LOG_TAIL:]}")
    return found.group(1)


def expected_environment(toolchain):
    """The environment that the build of a program must see (docs/build-contract.md, "The environment of a program's
    build"): the lines that `env` prints in a container of the toolchain image `toolchain`, with no network and
    HOME=/tmp, with ADDED_VARIABLES, less OWN_VARIABLES."""
    done = subprocess.run(["docker", "run", "--rm", "--network", "none", "-e", "HOME=/tmp", toolchain, "env"],
                          capture_output=True, text=True)
    if done.returncode != 0:
        pytest.fail(f"env in the toolchain image {toolchain} exited {done.returncode}: {done.stderr[-LOG_TAIL:]}")
    return variables([*done.stdout.splitlines(), *ADDED_VARIABLES])


def variables(lines):
    """The lines of an environment listing, as a set, less the lines of OWN_VARIABLES."""
    return {line for line in lines if line.partition("=")[0] not in OWN_VARIABLES}


def compared(lines, expected):
    """The comparison of an environment listing `lines` (the lines of an env.txt) with the environment `expected`, less
    OWN_VARIABLES: (each line that `expected` does not have, each line of `expected` that the listing does not have),
    each sorted. Both are empty when the two environments are the same."""
    have = variables(lines)
    return sorted(have - expected), sorted(expected - have)


def exit_status(stop):
    """The exit status of a SystemExit, as Python gives it: 0 for no code, and 1 for a message, which it prints."""
    if stop.code is None:
        return 0
    if isinstance(stop.code, int):
        return stop.code
    print(stop.code, file=sys.stderr)
    return 1


def told(run):
    """What a row that fails shows of a run: its command, its exit status and the end of its log."""
    status = "raised an exception" if run.code is None else f"exited {run.code}"
    return f"oss-verify check {shlex.join(run.argv)} {status}; the end of its log:\n{run.log[-LOG_TAIL:]}"


def manifest_of(run):
    """The manifest.yaml of a run."""
    path = run.work / "manifest.yaml"
    assert path.is_file(), f"the run wrote no manifest.yaml. {told(run)}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def listing(run, path):
    """The lines of the environment listing `path` of a run (an env.txt, relative to its work directory)."""
    file = run.work / path
    assert file.is_file(), f"the run wrote no {path}. {told(run)}"
    return file.read_text(encoding="utf-8").splitlines()


def held(directory):
    """The names in `directory`, sorted, or [] if there is no such directory."""
    return sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []


def configure(project, change):
    """Write the project.yaml of the copy `project` again, as change(its mapping) leaves the mapping."""
    path = project / "project.yaml"
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(config)
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


def pin_in(project, pin):
    """Write the pin `pin` into the copy `project`: the sha256 of its program in project.yaml."""
    configure(project, lambda config: config["programs"][0].update(sha256=pin))


def replace_once(path, old, new):
    """Write `path` again with its one copy of `old` replaced by `new`. Raise ValueError if it has not one copy."""
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise ValueError(f"{path} has {text.count(old)} copies of {old!r}, not one")
    path.write_text(text.replace(old, new), encoding="utf-8")


@pytest.mark.skipif(os.environ.get("OV_DOCKER_TESTS") != "1" or not docker_ready(),
                    reason="set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class TestProgram:
    """oss-verify check of tests/fixtures/program, a port of one whole program that its own Makefile builds at a fixed
    path. The fixture of the class does each run once, and records the exit status, the log and the work directory of
    each run. It asserts nothing: each row reads what it needs, so that each row fails on its own."""

    @pytest.fixture(scope="class", autouse=True)
    def set_up_class(self, request, tmp_path_factory):
        # A finalizer runs when this fixture fails too, unlike code after a yield: each run registers one that removes
        # its images before it runs. tmp_path_factory keeps the work directory that lists them past the finalizers.
        cls = request.cls
        root = tmp_path_factory.mktemp("ov-test-program")
        cls.toolchain = check_build.newest_toolchain("c")
        # Step 1: the pin is the SHA-256 of the program's own build in the toolchain image, outside the check.
        pin = cls.pin = outside_build(cls.toolchain)
        # Step 2: the environment that the build of a program must see.
        cls.expected = expected_environment(cls.toolchain)

        def pinned(project):
            pin_in(project, pin)

        def change_one_byte(project):
            pinned(project)
            replace_once(project / "src" / "hello.c", GREETING, CHANGED_GREETING)

        def remove_programs(project):
            configure(project, lambda config: config.pop("programs"))
            configure(project, lambda config: config.update(sanitizers=[]))

        def add_absent(project):
            pinned(project)
            configure(project, lambda config: config["programs"].append({"file": "absent", "sha256": "0" * 64}))

        def write_text(project):
            pinned(project)
            with open(project / "build.sh", "a", encoding="utf-8") as handle:
                handle.write(TEXT_PROGRAM)

        def link_dynamically(project):
            pinned(project)
            replace_once(project / "build.sh", "\nmake\n", f"\n{DYNAMIC_LINK}")

        # Step 3: the main run.
        cls.main = cls.checked(request, root, "main", pinned,
                               "--twice", "--checks", root / "checks.md", "--summary", root / "summary.md")
        # Step 4: the negative runs, each on its own copy, in its own work directory, with --no-shell alone. (a) One
        # byte of the string literal changed; (b) no programs, and sanitizers: []; (c) a second program that the build
        # does not write; (d) a text file in place of the program; (e) the program linked dynamically.
        cls.changed = cls.checked(request, root, "changed", change_one_byte)
        cls.no_programs = cls.checked(request, root, "no-programs", remove_programs)
        cls.absent = cls.checked(request, root, "absent", add_absent)
        cls.text_file = cls.checked(request, root, "text-file", write_text)
        cls.dynamic = cls.checked(request, root, "dynamic", link_dynamically)

    @staticmethod
    def remove_images(work):
        """Remove the project images of the oss-verify check run with the work directory `work`, which it lists in
        work/images (check_build.record_image), as tests/test_append_docker.py does. The builder images stay, as the
        other Docker tests leave them."""
        tags = check_build.recorded_images(work / check_build.IMAGES)
        if tags:
            subprocess.run(["docker", "image", "rm", *tags], capture_output=True)

    @staticmethod
    def checked(request, root, name, prepare, *options):
        """Run oss-verify check, with --no-shell and `options`, on a copy of tests/fixtures/program that prepare(copy)
        changes, in a work directory of its own. validate.check_project and check_build.resolve are replaced by
        stand-ins (COMMIT), and OFT_MAKE_JOBS is 2: compile_build passes it to the builder's compile-program, and the
        build of a program must not see it. Return the Run. A finalizer of `request` removes the images of the run."""
        project, work = root / f"program-{name}", root / f"{name}-work"
        request.addfinalizer(lambda: TestProgram.remove_images(work))
        argv = ["--no-shell", *map(str, options), "--dir", str(work), str(project)]
        log = io.StringIO()
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log), pytest.MonkeyPatch.context() as patch:
            patch.setattr(validate, "check_project", lambda directory: ([], [], None))
            patch.setattr(check_build, "resolve", lambda repo, ref, token=None: COMMIT)
            patch.setenv("OFT_MAKE_JOBS", "2")
            try:
                shutil.copytree(PROGRAM_FIXTURE, project)
                prepare(project)
                code = check.main(argv)
            except SystemExit as stop:
                code = exit_status(stop)
            # An exception ends this run alone, with its traceback in the log: each row that reads the run then fails
            # with it, and the other runs still run.
            except Exception:
                traceback.print_exc()
                code = None
        return Run(argv, code, log.getvalue(), work)

    def test_the_program_is_recorded(self):
        run = self.main
        assert run.code == 0, told(run)
        data = manifest_of(run)
        entry = data["targets"][PROGRAM]
        out = run.work / "out" / PROGRAM / PROGRAM
        assert entry["kind"] == "program", entry
        assert data["builds"] == ["plain"] and list(entry["builds"]) == ["plain"], (data["builds"], entry)
        assert data["fuzz_targets"] == [], data["fuzz_targets"]
        plain = entry["builds"]["plain"]
        assert plain["file"] == PROGRAM, plain
        assert plain["sha256"] == self.pin == manifest.sha256_of(out) == \
            manifest.sha256_of(run.work / "raw" / "plain" / PROGRAM), (plain, self.pin)
        assert plain["bytes"] == out.stat().st_size, plain

    def test_the_file_is_the_build_s_own(self):
        run = self.main
        out = run.work / "out" / PROGRAM / PROGRAM
        assert out.is_file(), f"no out/{PROGRAM}/{PROGRAM}. {told(run)}"
        assert manifest.has_symbol_table(out), f"out/{PROGRAM}/{PROGRAM} has no symbol table"
        for name in (manifest.STRIPPED, ".records"):
            assert held(run.work / "raw" / "plain" / name) == [], f"raw/plain/{name} is not empty"
        layout = manifest_of(run)["layout"][PROGRAM]["plain"]
        assert type(layout["text_bytes"]) is int and layout["text_bytes"] > 0, layout
        assert layout["static"] is True, layout

    def test_the_link_map_is_kept(self):
        run = self.main
        kept = run.work / "out" / PROGRAM / LINK_MAP
        assert kept.is_file(), f"no out/{PROGRAM}/{LINK_MAP}. {told(run)}"
        record = manifest_of(run)["targets"][PROGRAM]["link_map"]
        assert record["sha256"] == manifest.sha256_of(kept) == \
            manifest.sha256_of(run.work / "raw" / "plain" / LINK_MAP), record

    def test_the_second_build_is_identical(self):
        run = self.main
        data = manifest_of(run)
        assert "rebuild" in data, f"the manifest has no rebuild block. {told(run)}"
        assert data["rebuild"]["result"] == "identical", f"{data['rebuild']}\n{told(run)}"
        assert data["rebuild"]["targets"][PROGRAM] == data["targets"][PROGRAM]
        assert f"second build: out/{PROGRAM}/{PROGRAM} sha256 {self.pin}" in run.log.splitlines(), told(run)

    def test_the_checks_of_the_program(self):
        run = self.main
        data = manifest_of(run)
        assert "binary_checks" in data, f"the manifest has no binary_checks block. {told(run)}"
        results = data["binary_checks"]["targets"][PROGRAM]["plain"]
        own = binary_isa.check(str(run.work / "out" / PROGRAM / PROGRAM))
        assert own["result"] == "pass", own
        # When the release's model cannot be read, the result is stale, and its detail carries the pass.
        elf = results["elf"]
        assert elf["result"] == "pass" or (elf["result"] == "stale" and elf["detail"].startswith(own["detail"])), elf
        assert {key: results[key]["result"] for key in ("system_calls", "quiet_loud", "instrumented")} == \
            {"system_calls": "not-run", "quiet_loud": "not-run", "instrumented": "plain"}, results
        assert "uninstrumented" not in data["targets"][PROGRAM]["builds"]["plain"]
        assert not [line for line in run.log.splitlines() if "--checks: the coverage build" in line], told(run)
        assert not (run.work / "checks").exists()
        assert not (run.work / "binaries" / f"{PROGRAM}.plain" / "results").exists()

    def test_the_build_log(self):
        run = self.main
        lines = run.log.splitlines()
        assert "compile: the plain build (SANITIZER=none)" in lines, told(run)
        settings = [line for line in lines if line.startswith(("compile: CC=", "compile: CFLAGS="))]
        assert settings == [], f"the build of the program got the compilers and flags of a fuzz build: {settings}"

    def test_the_environment_of_both_builds(self):
        for path in ENV_FILES:
            lines = listing(self.main, path)
            extra, missing = compared(lines, self.expected)
            assert (extra, missing) == ([], []), (
                f"{path}: the lines that the environment of the toolchain image does not have: {extra}; the lines of "
                f"that environment that the build did not see: {missing}")
            assert [line for line in lines if line.startswith("HOME=")] == ["HOME=/tmp"], path

    def test_no_setting_of_the_fuzz_builds(self):
        own = {line for line in self.expected if line.startswith("SOURCE_DATE_EPOCH=")}
        for path in ENV_FILES:
            lines = listing(self.main, path)
            settings = sorted(line for line in lines if line.partition("=")[0] in FUZZ_SETTINGS)
            assert settings == [], f"{path}: the settings of the fuzz builds: {settings}"
            # toolchain.sh sets SOURCE_DATE_EPOCH for the fuzz builds. A program's build has it only as the toolchain
            # image itself gives it.
            epoch = {line for line in lines if line.startswith("SOURCE_DATE_EPOCH=")}
            assert epoch <= own, f"{path}: {epoch}, and the toolchain image gives {own or 'none'}"
            entries = [entry for line in lines if line.startswith("PATH=")
                       for entry in line.removeprefix("PATH=").split(":")]
            assert "/tmp/shim" not in entries, f"{path}: PATH has /tmp/shim, the compiler shims of toolchain.sh"

    def test_one_extra_variable_fails_the_comparison(self):
        # The comparison of test_the_environment_of_both_builds reports one line more, and one line less, than the
        # build saw.
        lines = listing(self.main, ENV_FILES[0])
        extra, missing = compared(lines, self.expected)
        more_extra, more_missing = compared([*lines, "OV_TEST_EXTRA=1"], self.expected)
        assert (set(more_extra) - set(extra), more_missing) == ({"OV_TEST_EXTRA=1"}, missing), more_extra
        _, less_missing = compared([line for line in lines if not line.startswith("HOME=")], self.expected)
        assert set(less_missing) - set(missing) == {"HOME=/tmp"}, (less_missing, missing)

    def test_the_check_gives_the_bytes_of_the_program_s_own_build(self):
        # The pin is the SHA-256 of the program's own build outside the check (outside_build), and the main run exits 0
        # only when the program that it builds is that file.
        assert self.main.code == 0, told(self.main)
        assert manifest_of(self.main)["targets"][PROGRAM]["builds"]["plain"]["sha256"] == self.pin
        # The negative control of the environment comparison: the same build with the CFLAGS of the plain fuzz build
        # gives other bytes, so the comparison can fail. Run (b) is a plain fuzz build, and compile prints its CFLAGS.
        found = re.search(r"^compile: CFLAGS=(.*)$", self.no_programs.log, re.MULTILINE)
        assert found, f"the log of run (b) has no line compile: CFLAGS=... {told(self.no_programs)}"
        assert outside_build(self.toolchain, found.group(1)) != self.pin, found.group(1)

    def test_a_changed_source_is_not_the_pinned_program(self):
        run = self.changed
        assert run.code == 3, told(run)
        found = re.search(rf"program {PROGRAM}: the build wrote sha256 ([0-9a-f]{{64}}) \(\d+ bytes\) FROM the "
                          r"toolchain \S+, and project\.yaml pins ([0-9a-f]{64})", run.log)
        assert found, told(run)
        built, pinned = found.groups()
        assert pinned == self.pin and built != self.pin, found.group(0)

    def test_without_programs_there_is_no_fuzz_target(self):
        # Run (b) also sets sanitizers: [], so that the plain build alone runs. With no programs and no sanitizers, a C
        # port has four builds, and a sanitizer build of a program that links no driver may fail before the check looks
        # for a fuzz target (not measured). So the control that removes the programs field is read with the plain build
        # alone.
        run = self.no_programs
        assert run.code == 1, told(run)
        assert "the build produced no fuzz target" in run.log, told(run)

    def test_a_listed_program_that_the_build_does_not_write(self):
        run = self.absent
        assert run.code == 1, told(run)
        assert "program absent" in run.log, told(run)

    def test_a_listed_file_that_is_not_an_executable_elf(self):
        run = self.text_file
        assert run.code == 1, told(run)
        assert f"program {PROGRAM} is not an executable ELF file" in run.log, told(run)

    def test_a_dynamic_program_exits_2(self):
        run = self.dynamic
        # First, that the case is a dynamic program: the file that the build wrote has a PT_INTERP or PT_DYNAMIC header.
        layout = manifest.binary_layout(run.work / "raw" / "plain" / PROGRAM)
        assert layout is not None and layout["static"] is False, f"raw/plain/{PROGRAM}: {layout}. {told(run)}"
        assert run.code == 2, told(run)
        assert "is dynamically linked" in run.log, told(run)
        assert "NOT THE PINNED PROGRAM" not in run.log, told(run)
