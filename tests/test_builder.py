# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example, tests/fixtures/cjson, tests/fixtures/rust-example, tests/fixtures/python-example and
tests/fixtures/go-example with the builder and run what they make. Needs Docker and the toolchain images (and, for cJSON, the Rust crates and the
Python build backend, the network):

    OV_DOCKER_TESTS=1 uv run pytest

The fixture's Dockerfile and build.sh are templates/Dockerfile and templates/build.sh (in its C and C++ forms). Its
fuzz targets do one thing per first input byte, and the test checks the exit status of each in every build against
docs/build-contract.md. Running the riscv64 binaries needs qemu-riscv64 (static) on this machine; without it, that part
is skipped.

FramePointersC and FramePointersRust also need the frame-pointer images that .github/workflows/toolchain-images.yaml
makes, named by OV_FP_TOOLCHAIN_C and OV_FP_TOOLCHAIN_RUST: each skips unless its own is set. The job docker of
.github/workflows/tests.yaml runs every test of this file in shards: each shard pulls the toolchain images that its
classes need, makes the frame-pointer images of its FramePointers class again and sets its variable, and fails if a
test skips. So does toolchain-images.yaml's job docker-tests (.github/workflows/frame-pointer-tests.yaml) for these two
classes, on the images that it makes; toolchain-images.yaml's job compare-digests fails unless they are the images of
its job make.
"""
import contextlib
import fcntl
import hashlib
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from oss_verify import check_build
from oss_verify import manifest
from oss_verify import validate

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
# Each tag here, and in the Docker tests that import RUN, ends in RUN, a suffix that is this process's own, so that two
# processes on one Docker daemon (two workers of pytest-xdist, or two runs of the suite) never build, run or remove each
# other's image. Each class removes its image with a class cleanup, which runs when setUpClass fails too, unlike
# tearDownClass: a failed build leaves no image behind, under a tag that no later run would use again.
RUN = secrets.token_hex(6)
TAG = f"oss-verify-test/example:{RUN}"
QEMU = shutil.which("qemu-riscv64-static") or shutil.which("qemu-riscv64")
BUILDS = list(validate.BUILDS)

# Payload first byte -> exit status in each build (plain, ubsan, asan, asan-ubsan), after the six-byte header.
# A load through a null pointer is a segmentation fault ('s'), except where UBSan's null check catches it first ('n'):
# clang does not check a volatile access ('s') for null.
EXPECTED = {
    "": (0, 0, 0, 0),
    "z": (0, 0, 0, 0),
    "m": (0, 0, 0, 0),
    "r": (78, 78, 78, 78),
    "x": (77, 77, 77, 77),
    # The guard is one atexit() handler the driver registers before LLVMFuzzerInitialize, and handlers run
    # last-registered-first: a handler the target registers later runs first. One that ends the process itself
    # ('L': _Exit(0)) gives its own status, and the exit() never reaches the guard; one that returns ('G') leaves
    # the guard to give 77 (docs/build-contract.md, "What the driver does not intercept").
    "L": (0, 0, 0, 0),
    "G": (77, 77, 77, 77),
    # Only exit() is turned into 77: _exit, _Exit and quick_exit end the process with the target's own status.
    "u": (5, 5, 5, 5),
    "U": (6, 6, 6, 6),
    "k": (7, 7, 7, 7),
    "a": (134, 134, 134, 134),
    "s": (139, 139, 139, 139),
    "n": (139, 132, 139, 132),
    "o": (0, 132, 0, 132),
    "h": (0, 0, 134, 134),
    # The fixed flags have no -fstrict-flex-arrays=1, so array-bounds does not check a trailing array, and the write
    # stays inside the allocation, where AddressSanitizer sees nothing.
    "f": (0, 0, 0, 0),
    "l": (0, 0, 0, 0),
}
CXX_ONLY = {"t": (134, 134, 134, 134)}  # an uncaught C++ exception

# The allocation-failure variants are the same objects linked with $LIB_ALLOCATION_FAILURE_ENGINE (example_fuzzer_af,
# example_fuzzer_cc_af), which ignores counting mode, and with $LIB_ALLOCATION_COUNTING_ENGINE (example_fuzzer_count,
# example_fuzzer_cc_count), in which counting mode makes the status the number of allocations counted. With no
# allocation mask they behave as their fuzz targets do (the cases above). These inputs set the mask (bit n: the n-th
# allocation fails) or ask for counting mode (bit 15 of the config word). 'h' allocates once, with malloc; 'N', in the
# C++ fuzz target, once with new[]; 'r' allocates nothing and returns 1. Input -> (header, payload, {fuzz target:
# statuses in each build}); a fuzz target not named has the status of the one before it in its group.
HEAP, ZERO, ONE, ABORT, BAD = (0, 0, 134, 134), (0, 0, 0, 0), (1, 1, 1, 1), (134, 134, 134, 134), (78, 78, 78, 78)
FAIL_FIRST, COUNT, COUNT_FAIL_FIRST, COUNT_FAIL_SECOND = (b"\0\0\1\0\0\0", b"\0\x80\0\0\0\0", b"\0\x80\1\0\0\0",
                                                         b"\0\x80\2\0\0\0")
TARGETS = ("example_fuzzer", "example_fuzzer_cc", "example_fuzzer_af", "example_fuzzer_cc_af", "example_fuzzer_count",
           "example_fuzzer_cc_count")


def statuses(fuzz_target, af, count, cxx_af=None, cxx_count=None, cxx=None):
    """The statuses of a case for each fuzz target: those of the C ones, and of the C++ ones where they differ."""
    cxx = fuzz_target if cxx is None else cxx
    return dict(zip(TARGETS, (fuzz_target, cxx, af, af if cxx_af is None else cxx_af, count,
                              count if cxx_count is None else cxx_count)))


ALLOCATION_FAILURE = {
    "af-h-fails": (FAIL_FIRST, "h", statuses(HEAP, ZERO, ZERO)),  # the heap read is never reached
    "af-h-count": (COUNT_FAIL_FIRST, "h", statuses(HEAP, ZERO, ONE)),
    "af-z-count": (COUNT, "z", statuses(ZERO, ZERO, ZERO)),
    "af-r-count": (COUNT, "r", statuses(ZERO, BAD, ZERO)),  # counting mode ignored: the return value counts
    "af-N-count": (COUNT, "N", statuses(ZERO, ZERO, ZERO, cxx_count=ONE)),
    "af-N-fails": (FAIL_FIRST, "N", statuses(ZERO, ZERO, ZERO, cxx_af=ABORT, cxx_count=ABORT)),  # std::bad_alloc
    "af-N-second": (COUNT_FAIL_SECOND, "N", statuses(ZERO, ZERO, ZERO, cxx_count=ONE)),
}

# Runs every case of the build that $B names (each_build_at_once): prints "<target> <build> <case> <status>" per line.
RUNNER = r"""
cd /in
for t in example_fuzzer example_fuzzer_cc example_fuzzer_af example_fuzzer_cc_af example_fuzzer_count example_fuzzer_cc_count; do
  for b in $B; do
    for c in /in/case-*; do
      q /bin/$t.$b "$c" > /dev/null 2>&1; echo "$t $b ${c#/in/case-} $?"
    done
    q /bin/$t.$b /in/short > /dev/null 2>&1; echo "$t $b short $?"
    q /bin/$t.$b /in/missing > /dev/null 2>&1; echo "$t $b missing $?"
    q /bin/$t.$b > /dev/null 2>&1; echo "$t $b no-argument $?"
    printf '%s ' "$t $b calls"; q /bin/$t.$b /in/three-calls | tr '\n' ,; echo
  done
done
"""


def docker_ready(image=None):
    """Whether Docker runs and a toolchain image is here: `image`, else the one the fixture builds FROM (the newest for
    C)."""
    try:
        return subprocess.run(["docker", "image", "inspect", image or check_build.newest_toolchain()],
                              capture_output=True).returncode == 0
    except OSError:
        return False


# The first line of each script that run_in_container runs, as in infra/checks/run-seeds. The container's shell writes
# 0 to /proc/self/coredump_filter, and every qemu run it starts keeps that value, so a run's core dump holds no memory.
# Otherwise the dump of an ASan build's run holds its reserved address space of more than 100 GiB: where the host's
# core_pattern is a pipe, that dump can outlast the time limit, and the run reads the time limit's status. A core
# limit of 0 does not stop a dump to a pipe (OSSV-729's measurement).
NO_CORE_MEMORY = "if [ -e /proc/self/coredump_filter ]; then echo 0 > /proc/self/coredump_filter; fi"
# The core-file limit of each container that run_in_container starts: 1 byte. A run that a test makes crash on purpose
# (its status, 132, 134 or 139, is what the test checks) then hands no core to the host at all: Linux aborts a dump to
# a pipe when the limit is 1, and a core file cannot be written in 1 byte. A limit of 0 does not: the dump still goes to
# the pipe. On GitHub's ubuntu-24.04 runner, whose core_pattern pipes each dump to systemd-coredump and on to Apport's
# coredump hook, a run under qemu that aborted, took a SIGSEGV or trapped took 120-256 ms with no limit or a limit of
# 0, and the hook then spent about 2 CPU-s on each dump; with this limit it took 3-4 ms, as a run that returns 0 does,
# with the same status and no dump (run 46033445302, INFRA-5359). infra/checks/run-seeds and run-binaries, which
# oss-verify check --checks runs, set no such limit: their tests (tests/test_seed_runs_docker.py) run them as they run
# on a project's runner, with the host's handler.
NO_CORE_LIMIT = ["--ulimit", "core=1"]


def run_in_container(image, runner, *mounts):
    """Run the sh script runner in a container of image with no network, with qemu-riscv64 at /qemu and each (host
    path, container path) of mounts read-only, and no core dump (NO_CORE_LIMIT). image is a tag that the test built, so
    docker never pulls it from a registry. Returns the completed process, with its output as text."""
    volumes = [arg for host, container in ((QEMU, "/qemu"), *mounts) for arg in ("-v", f"{host}:{container}:ro")]
    return subprocess.run(["docker", "run", "--rm", "--network=none", "--pull=never", *NO_CORE_LIMIT, *volumes,
                           "--entrypoint", "sh", image, "-c", f"{NO_CORE_MEMORY}\n{runner}"], capture_output=True,
                          text=True, check=True)


def each_build_at_once(image, runner, builds, *mounts):
    """run_in_container(image, runner, *mounts) for each build of `builds`, all at once, each in a container of its own
    whose shell has the build's name in B: the standard output of every container, joined in the order of `builds`.
    Each run under qemu is one process, on one hardware thread: in one container, the runs of four builds one after
    another leave the others idle (on an n2d-standard-4, Builder.test_exit_statuses took 31.5 s that way, 21.1 s at
    once)."""
    return "".join(done.stdout for done in at_once(
        lambda build: run_in_container(image, f"B={build}\n{runner}", *mounts), builds))


def at_once(function, items):
    """function(item) for each of `items`, all at once, each in a thread of its own (check_build.in_threads): what each
    call returned, in the order of `items`. The first failure is raised once every call has ended."""
    items = list(items)
    outcomes = check_build.in_threads(function, items, len(items))
    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            raise outcome
    return outcomes


def compile_builds(tag, raw, labels, **options):
    """check_build.compile_build of each build of `raw` ({build: the directory of its $OUT}), all at once, each in a
    container of its own, with `options`. Most of one build is one process at a time (CPython's configure in a Python
    build, rustc on core and std in a Rust one), so one after another the builds left most of the cores idle."""
    at_once(lambda build: check_build.compile_build(tag, build, validate.BUILDS[build], raw[build], labels=labels,
                                                    **options), raw)


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class Builder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-builder.")
        # Class cleanups run last first, so the image goes before its scratch directory.
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", TAG], capture_output=True)
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, TAG, cls.work)
        cls.raw = {build: cls.work / "raw" / build for build in BUILDS}
        compile_builds(TAG, cls.raw, check_build.work_label(cls.work))
        cls.found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(cls.found)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    def test_discovery(self):
        self.assertEqual(self.problems, [])
        self.assertEqual(self.missing, [])
        self.assertEqual(self.targets, sorted(TARGETS))
        for build in BUILDS:
            self.assertTrue((self.raw[build] / "tool").is_file(), "the non-target executable was built")
            self.assertNotIn("tool", self.found[build])

    def test_published_bytes_are_stripped(self):
        for target in self.targets:
            for build in BUILDS:
                path = self.work / "out" / target / f"{target}.{build}"
                self.assertFalse(manifest.has_symbol_table(path), path)
                self.assertEqual(self.entries[target][build]["sha256"], manifest.sha256_of(path))
                self.assertTrue(manifest.has_symbol_table(self.raw[build] / target))

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_exit_statuses(self):
        inputs = self.work / "in"
        inputs.mkdir()
        cases = {**EXPECTED, **CXX_ONLY}
        for case in cases:
            (inputs / f"case-{case or 'empty'}").write_bytes(b"\0" * 6 + case.encode())
        for case, (header, payload, _) in ALLOCATION_FAILURE.items():
            (inputs / f"case-{case}").write_bytes(header + payload.encode())
        (inputs / "short").write_bytes(b"\0\0\0")
        # A config word of 1, config byte 2: three calls.
        (inputs / "three-calls").write_bytes(b"\x01\x00\x02\0\0\0\0z")
        binaries = self.work / "bin"
        binaries.mkdir()
        for target in self.targets:
            for build in BUILDS:
                shutil.copy(self.work / "out" / target / f"{target}.{build}", binaries)
        runner = f"q() {{ timeout 60 /qemu \"$@\"; }}\n{RUNNER}"
        output = each_build_at_once(TAG, runner.replace("/bin/", "/bin2/"), BUILDS, (inputs, "/in"),
                                    (binaries, "/bin2"))
        results = {}
        for line in output.splitlines():
            target, build, case, status = line.split(" ", 3)
            results[(target, build, case)] = status
        for target in self.targets:
            expected = {**EXPECTED, **(CXX_ONLY if "_cc" in target else {})}
            expected.update({case: statuses[target] for case, (_, _, statuses) in ALLOCATION_FAILURE.items()})
            for case, statuses in expected.items():
                for build, status in zip(BUILDS, statuses):
                    with self.subTest(target=target, build=build, case=case):
                        self.assertEqual(results[(target, build, case or "empty")], str(status))
            for build in BUILDS:
                for case in ("short", "missing", "no-argument"):
                    self.assertEqual(results[(target, build, case)], "2", (target, build, case))
                self.assertEqual(results[(target, build, "calls")], "0,0,0,", (target, build))


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class UbsanChecks(unittest.TestCase):
    """The UBSan checks that oss-verify check gives compile on a toolchain that applies a project's ubsan_checks."""

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_only_the_given_checks_trap(self):
        tag = f"oss-verify-test/example-ubsan:{RUN}"
        with tempfile.TemporaryDirectory(prefix="ov-test-ubsan.") as scratch:
            work = pathlib.Path(scratch)
            job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                                  dockerfile="", builds=["ubsan"], fuzz_targets=None)
            try:
                check_build.build_project(job, "0" * 40, check_build.build_builder(), tag, work)
                raw = work / "raw"
                # null only: the null load traps, and the signed overflow, which the fixed flags catch, does not.
                # The C compiles also leave out function, as a c++ project's do.
                check_build.compile_build(tag, "ubsan", "undefined", raw, (["null"], ["vptr"], ["function"]),
                                          labels=check_build.work_label(work))
                inputs = work / "in"
                inputs.mkdir()
                for case in "no":
                    (inputs / f"case-{case}").write_bytes(b"\0" * 6 + case.encode())
                runner = ('for c in /in/*; do timeout 60 /qemu /raw/example_fuzzer "$c" > /dev/null 2>&1; '
                          'echo "${c#/in/} $?"; done')
                done = run_in_container(tag, runner, (inputs, "/in"), (raw, "/raw"))
            finally:
                subprocess.run(["docker", "image", "rm", tag], capture_output=True)
        results = dict(line.split() for line in done.stdout.splitlines())
        self.assertEqual(results, {"case-n": "132", "case-o": "0"})

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_strict_flex_arrays_checks_a_trailing_array(self):
        """array-bounds traps on an index past a struct's trailing char[16] only with strict-flex-arrays, in the ubsan
        and the asan-ubsan build. The legacy [1] flexible array, used as intended, and a correct input exit 0."""
        tag = f"oss-verify-test/example-flex:{RUN}"
        with tempfile.TemporaryDirectory(prefix="ov-test-flex.") as scratch:
            work = pathlib.Path(scratch)
            job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                                  dockerfile="", builds=["ubsan", "asan-ubsan"], fuzz_targets=None)
            inputs = work / "in"
            inputs.mkdir()
            for case in "flm":
                (inputs / f"case-{case}").write_bytes(b"\0" * 6 + case.encode())
            results = {}
            variants = [(build, sanitizer, checks)
                        for build, sanitizer in (("ubsan", "undefined"), ("asan-ubsan", "address-undefined"))
                        for checks in (["array-bounds"], ["array-bounds", "strict-flex-arrays"])]
            runner = ('for c in /in/*; do timeout 600 /qemu /raw/example_fuzzer "$c" > /dev/null 2>&1; '
                      'echo "${c#/in/} $?"; done')

            def compile_and_run(variant):
                build, sanitizer, checks = variant
                raw = work / f"raw-{build}-{len(checks)}"
                check_build.compile_build(tag, build, sanitizer, raw, (checks, ["vptr"], []),
                                          labels=check_build.work_label(work))
                done = run_in_container(tag, runner, (inputs, "/in"), (raw, "/raw"))
                return dict(line.split() for line in done.stdout.splitlines())

            try:
                check_build.build_project(job, "0" * 40, check_build.build_builder(), tag, work)
                for (build, _, checks), found in zip(variants, at_once(compile_and_run, variants)):
                    results[build, checks[-1]] = found
            finally:
                subprocess.run(["docker", "image", "rm", tag], capture_output=True)
        for build in ("ubsan", "asan-ubsan"):
            self.assertEqual(results[build, "array-bounds"], {"case-f": "0", "case-l": "0", "case-m": "0"}, build)
            self.assertEqual(results[build, "strict-flex-arrays"], {"case-f": "132", "case-l": "0", "case-m": "0"},
                             build)


PYTHON_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "python-example"
PYTHON_TAG = f"oss-verify-test/python-example:{RUN}"
# Payload first byte -> exit status in each build of the Python fixture (fixtures/python-example/pkg/example): an
# uncaught exception exits 79, a MemoryError 2, a SystemExit 77. The same in all four builds.
PYTHON_EXPECTED = {"": 0, "a": 0, "p": 0, "e": 79, "m": 2, "x": 77}


def toolchain_ready(language):
    """Whether Docker runs and the newest toolchain image for a language is here."""
    try:
        image = check_build.newest_toolchain(language)
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
    except (OSError, check_build.Failed):
        return False


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and toolchain_ready("python"),
                     "set OV_DOCKER_TESTS=1, with Docker and the Python toolchain image, to build the Python fixture")
class PythonBuilder(unittest.TestCase):
    """fixtures/python-example: an atheris harness, built with python/recipes.sh in each build. Getting its build
    backend needs the network."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-python.")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", PYTHON_TAG], capture_output=True)
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="python-example", directory=PYTHON_FIXTURE,
                              repo="https://example.invalid/python-example", ref="", dockerfile="", builds=BUILDS,
                              fuzz_targets=["fuzz_example"], language="python")
        builder = check_build.build_builder(check_build.newest_toolchain("python"))
        check_build.build_project(job, "0" * 40, builder, PYTHON_TAG, cls.work)
        cls.raw = {build: cls.work / "raw" / build for build in BUILDS}
        compile_builds(PYTHON_TAG, cls.raw, check_build.work_label(cls.work))
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, job.fuzz_targets)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    def test_discovery(self):
        self.assertEqual((self.problems, self.missing, self.targets), ([], [], ["fuzz_example"]))

    def test_each_build_names_the_same_paths(self):
        """The debug information of each build's unstripped fuzz target names the paths of its build, and none that
        differs between two builds, such as a directory that mktemp names. Each path is a whole string of the binary
        (between two NULs) under /work, /src or /tmp, with the build's own directory, /work/build/lib/<flav>, written
        with <flav>; the paths of the runtime's own build, /work/build/pyrt/ and /src/repo/build/pyrt/, are left out.
        - The target's own directories (/work/build/lib/<flav>/example and /src/example, the neutral name that
          release-target.sh gives it) are named only as the scratch directory that python/recipes.sh gives every build,
          /work/build/lib/<flav>/example/py: no other entry, and nothing below it.
        - The plain and the ubsan build name the same paths, and so do the asan and the asan-ubsan build: each pair is
          two builds of one CPython runtime's sources, and the asan builds name one more source file. A name that a
          build makes anew, anywhere under /work, /src or /tmp, differs between the two builds of a pair."""
        named = {}
        for build in BUILDS:
            flav = build.replace("-", "").encode()
            data = (self.raw[build] / "fuzz_example").read_bytes()
            found = set(re.findall(rb"(?<=\0)/(?:work|src|tmp)/[^\0]*(?=\0)", data))
            named[build] = {path.replace(b"/work/build/lib/" + flav + b"/", b"/work/build/lib/<flav>/")
                            for path in found if not path.startswith((b"/work/build/pyrt/", b"/src/repo/build/pyrt/"))}
            own = {path for path in named[build]
                   if re.match(rb"/work/build/lib/<flav>/example(/|$)|/src/example(/|$)", path)}
            self.assertEqual(own, {b"/work/build/lib/<flav>/example/py"}, build)
        self.assertEqual(named["plain"], named["ubsan"])
        self.assertEqual(named["asan"], named["asan-ubsan"])

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_exit_statuses(self):
        inputs = self.work / "in"
        inputs.mkdir()
        for case in PYTHON_EXPECTED:
            (inputs / f"case-{case or 'empty'}").write_bytes(b"\0" * 6 + case.encode())
        binaries = self.work / "bin"
        binaries.mkdir()
        for build in BUILDS:
            shutil.copy(self.work / "out" / "fuzz_example" / f"fuzz_example.{build}", binaries)
        runner = ('for b in $B; do for c in /in/*; do '
                  'timeout 600 /qemu /bin2/fuzz_example.$b "$c" > /dev/null 2>&1; echo "$b ${c#/in/case-} $?"; done; '
                  'printf "%s " "$b printed"; timeout 600 /qemu /bin2/fuzz_example.$b /in/case-p | tr "\\n" ,; echo; '
                  'done')
        output = each_build_at_once(PYTHON_TAG, runner, BUILDS, (inputs, "/in"), (binaries, "/bin2"))
        results = {tuple(line.split(" ", 2)[:2]): line.split(" ", 2)[2] for line in output.splitlines()}
        for case, status in PYTHON_EXPECTED.items():
            for build in BUILDS:
                with self.subTest(build=build, case=case):
                    self.assertEqual(results[(build, case or "empty")], str(status))
        for build in BUILDS:
            # The loud build writes what the harness prints, then the driver writes the return value.
            self.assertEqual(results[(build, "printed")], "printed,0,", build)


RUST_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "rust-example"
RUST_TAG = f"oss-verify-test/rust-example:{RUN}"
# Payload first byte -> exit status in each build (plain, ubsan, asan, asan-ubsan) of the Rust fixture
# (fixtures/rust-example/crate/src/lib.rs): a panic, a capacity overflow and a UB check exit 79; handle_alloc_error
# exits 2, also when the fixture calls it itself, with no allocation refused.
RUST_EXPECTED = {
    "": (0, 0, 0, 0),
    "r": (0, 0, 0, 0),  # Corpus::Reject: the fuzz target returns -1
    "p": (79, 79, 79, 79),
    "c": (79, 79, 79, 79),
    "o": (2, 2, 2, 2),
    "x": (77, 77, 77, 77),
    "h": (0, 0, 134, 134),
    "u": (0, 79, 0, 79),
}


def compile_plain(tag, out, labels, settings=()):
    """compile, the plain build, in the image `tag`, with compile_build's docker run arguments and an -e for each of
    `settings`, into the $OUT `out`: its exit status, and its standard output and standard error together."""
    check_build.empty_directory(out, tag, labels=labels)
    environment = [word for setting in settings for word in ("-e", setting)]
    done = subprocess.run(
        ["docker", "run", "--rm", "--init", "--network=none", *labels, "-e", "SANITIZER=none",
         "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}", *environment, "-v", f"{out}:/out", tag, "compile"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    return done.returncode, done.stdout


# RustBuilder's plain build and FramePointersRust's run on the base image with no setting are one compile: the same
# project image, FROM the same toolchain image, with the same docker run arguments and no other input. A Rust compile is
# about 175 CPU-seconds, most of it the standard library (-Zbuild-std), and the shard that runs both classes is
# CPU-bound, so shared_rust_plain compiles it once for both. FramePointersRust's run with OFT_FRAME_POINTERS= (empty)
# has an input of its own, and its test is for that input: it is compiled on its own, as is each other build.
RUST_PLAIN = "ov-test-rust-plain"


@contextlib.contextmanager
def locked(root):
    """The directory `root`, made if missing, with the exclusive lock on root/lock held. A lock file that the last user
    removed with `root` while this waited is not held: this takes the new one."""
    while True:
        root.mkdir(exist_ok=True)
        try:
            handle = open(root / "lock", "a")
        except FileNotFoundError:
            continue
        with handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                same = os.fstat(handle.fileno()).st_ino == os.stat(root / "lock").st_ino
            except FileNotFoundError:
                same = False
            if same:
                yield root
                return


def shared_rust_plain(toolchain, cls):
    """The plain build of fixtures/rust-example FROM `toolchain`, compiled once for every class that asks for it in one
    run of pytest, across its pytest-xdist workers (PYTEST_XDIST_TESTRUNUID, else this process's RUN): (compile's exit
    status, its standard output and standard error together, the directory of its $OUT). The first caller builds the
    project image and compiles (compile_plain), holding the lock that each caller takes; a caller that waited reads what
    it left. The image goes once the compile ends. Each caller counts itself, and a class cleanup of `cls` takes its
    count off: the last one removes the directory. A caller that comes after that compiles again."""
    run = os.environ.get("PYTEST_XDIST_TESTRUNUID", RUN)
    key = hashlib.sha256(f"{run} {toolchain}".encode()).hexdigest()[:16]
    root = pathlib.Path(tempfile.gettempdir()) / f"{RUST_PLAIN}-{key}"
    with locked(root):
        users = root / "users"
        users.write_text(f"{int(users.read_text()) + 1 if users.exists() else 1}")
        cls.addClassCleanup(release_rust_plain, root)
        result = root / "result"
        if not (result / "status").exists():
            # A caller that failed part of the way left no status, and what it left goes.
            shutil.rmtree(result, ignore_errors=True)
            result.mkdir()
            tag = f"oss-verify-test/{RUST_PLAIN}:{key}-{RUN}"
            job = check_build.Job(name="rust-example", directory=RUST_FIXTURE,
                                  repo="https://example.invalid/rust-example", ref="", dockerfile="", builds=["plain"],
                                  fuzz_targets=["example_fuzzer"], language="rust")
            try:
                check_build.build_project(job, "0" * 40, check_build.build_builder(toolchain), tag, result)
                code, output = compile_plain(tag, result / "out", check_build.work_label(root))
            finally:
                subprocess.run(["docker", "image", "rm", tag], capture_output=True)
            (result / "output").write_text(output)
            # The status last: a result with a status is whole.
            (result / "status").write_text(f"{code}")
        return int((result / "status").read_text()), (result / "output").read_text(), result / "out"


def release_rust_plain(root):
    """Take one caller's count off shared_rust_plain's directory `root`, and remove it when no caller is left."""
    with locked(root):
        users = root / "users"
        left = int(users.read_text()) - 1
        if left:
            users.write_text(f"{left}")
        else:
            shutil.rmtree(root)


class RustPlainShared(unittest.TestCase):
    """shared_rust_plain, with stand-ins for the image builds and the compile: callers at once get one compile and the
    same result; the directory goes with the last caller's cleanup; a caller after that compiles again; another toolchain
    is another compile. Needs no Docker, and runs in the rust shard of tests.yaml's job docker, beside the classes that
    use it."""

    class Caller:
        def __init__(self):
            self.cleanups = []

        def addClassCleanup(self, function, *args):
            self.cleanups.append((function, args))

        def cleanup(self):
            for function, args in reversed(self.cleanups):
                function(*args)

    def setUp(self):
        self.compiles = []
        patches = [unittest.mock.patch.object(check_build, "build_builder", lambda toolchain: f"builder {toolchain}"),
                   unittest.mock.patch.object(check_build, "build_project", lambda *args, **kwargs: None),
                   unittest.mock.patch(f"{__name__}.compile_plain", self.compile),
                   unittest.mock.patch.object(subprocess, "run", lambda *args, **kwargs: None)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.toolchain = f"stand-in@{secrets.token_hex(6)}"

    def compile(self, tag, out, labels, settings=()):
        self.compiles.append(tag)
        time.sleep(0.2)
        out.mkdir()
        (out / "binary").write_text(f"built {len(self.compiles)}")
        return 0, f"compile {len(self.compiles)}"

    def test_callers_at_once_share_one_compile_and_the_last_cleanup_removes_it(self):
        callers = [self.Caller(), self.Caller()]
        found = at_once(lambda caller: shared_rust_plain(self.toolchain, caller), callers)
        self.assertEqual(len(self.compiles), 1, self.compiles)
        self.assertEqual([(code, output) for code, output, _ in found], [(0, "compile 1")] * 2)
        out = found[0][2]
        self.assertEqual(found[1][2], out)
        callers[0].cleanup()
        self.assertEqual((out / "binary").read_text(), "built 1")
        callers[1].cleanup()
        self.assertFalse(out.parent.parent.exists())
        later = self.Caller()
        self.addCleanup(later.cleanup)
        self.assertEqual(shared_rust_plain(self.toolchain, later)[:2], (0, "compile 2"))
        other = self.Caller()
        self.addCleanup(other.cleanup)
        self.assertEqual(shared_rust_plain(self.toolchain + "0", other)[:2], (0, "compile 3"))



@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and toolchain_ready("rust"),
                     "set OV_DOCKER_TESTS=1, with Docker and the Rust toolchain image, to build the Rust fixture")
class RustBuilder(unittest.TestCase):
    """fixtures/rust-example: a cargo-fuzz fuzz target, built with rust/recipes.sh in each build. Getting its crates
    needs the network."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-rust.")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", RUST_TAG], capture_output=True)
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="rust-example", directory=RUST_FIXTURE, repo="https://example.invalid/rust-example",
                              ref="", dockerfile="", builds=BUILDS, fuzz_targets=["example_fuzzer"], language="rust")
        toolchain = check_build.newest_toolchain("rust")
        check_build.build_project(job, "0" * 40, check_build.build_builder(toolchain), RUST_TAG, cls.work)
        cls.raw = {build: cls.work / "raw" / build for build in BUILDS}
        labels = check_build.work_label(cls.work)

        def compile(build):
            if build != "plain":
                check_build.compile_build(RUST_TAG, build, validate.BUILDS[build], cls.raw[build], labels=labels)
                return
            # The plain build is FramePointersRust's run on the base image too: shared_rust_plain compiles it once.
            code, output, out = shared_rust_plain(toolchain, cls)
            if code != 0:
                raise check_build.Failed(f"compile exited {code} in the plain build:\n{output[-4000:]}")
            shutil.copytree(out, cls.raw[build])

        at_once(compile, BUILDS)
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, job.fuzz_targets)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    def test_discovery(self):
        self.assertEqual((self.problems, self.missing, self.targets), ([], [], ["example_fuzzer"]))

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_exit_statuses(self):
        inputs = self.work / "in"
        inputs.mkdir()
        for case in RUST_EXPECTED:
            (inputs / f"case-{case or 'empty'}").write_bytes(b"\0" * 6 + case.encode())
        binaries = self.work / "bin"
        binaries.mkdir()
        for build in BUILDS:
            shutil.copy(self.work / "out" / "example_fuzzer" / f"example_fuzzer.{build}", binaries)
        # An AddressSanitizer detection in a Rust fuzz target took minutes under qemu (about 160 s here, 234 s on
        # ubuntu-24.04-16core): that was the core dump of the qemu process. With run_in_container's write to
        # coredump_filter the dump held no memory, and all the cases of this test ran in less than a second there
        # (OSSV-729's measurement); its containers now make no dump at all (NO_CORE_LIMIT). OSSV-729 keeps each
        # helper's time limit, as its R2 asks, and measured no lower limit.
        runner = ('for b in plain ubsan asan asan-ubsan; do for c in /in/*; do '
                  'timeout 600 /qemu /bin2/example_fuzzer.$b "$c" > /dev/null 2>&1; echo "$b ${c#/in/case-} $?"; done; '
                  'printf "%s " "$b printed"; timeout 60 /qemu /bin2/example_fuzzer.$b /in/case-r | tr "\\n" ,; echo; '
                  'done')
        done = run_in_container(RUST_TAG, runner, (inputs, "/in"), (binaries, "/bin2"))
        results = {tuple(line.split(" ", 2)[:2]): line.split(" ", 2)[2] for line in done.stdout.splitlines()}
        for case, statuses in RUST_EXPECTED.items():
            for build, status in zip(BUILDS, statuses):
                with self.subTest(build=build, case=case):
                    self.assertEqual(results[(build, case or "empty")], str(status))
        for build in BUILDS:
            # The driver writes each return value: -1 for Corpus::Reject.
            self.assertEqual(results[(build, "printed")], "-1,", build)


GO_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "go-example"
GO_TAG = f"oss-verify-test/go-example:{RUN}"
# Payload first byte -> exit status of the Go fixture's plain build (fixtures/go-example/example/fuzz.go): a panic, a
# runtime error and a make() larger than the runtime's limit exit 79, a load through a nil pointer is a segmentation
# fault, os.Exit exits 77, and a fatal error of the runtime 80. A header shorter than six bytes is 2.
GO_EXPECTED = {"": 0, "r": 0, "z": 0, "p": 79, "n": 79, "M": 79, "s": 139, "x": 77, "d": 80}


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and toolchain_ready("go"),
                     "set OV_DOCKER_TESTS=1, with Docker and the Go toolchain image, to build the Go fixture")
class GoBuilder(unittest.TestCase):
    """fixtures/go-example: a go-fuzz Fuzz function, built by OSS-Fuzz's compile_go_fuzzer in the Go toolchain image,
    in the plain build, the only one of a Go project."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-go.")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", GO_TAG], capture_output=True)
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="go-example", directory=GO_FIXTURE, repo="https://example.invalid/go-example",
                              ref="", dockerfile="", builds=["plain"], fuzz_targets=["example_fuzzer"], language="go")
        builder = check_build.build_builder(check_build.newest_toolchain("go"))
        check_build.build_project(job, "0" * 40, builder, GO_TAG, cls.work)
        cls.raw = {"plain": cls.work / "raw" / "plain"}
        check_build.compile_build(GO_TAG, "plain", "none", cls.raw["plain"], labels=check_build.work_label(cls.work))
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, job.fuzz_targets)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    def test_discovery(self):
        self.assertEqual((self.problems, self.missing, self.targets), ([], [], ["example_fuzzer"]))
        # The helper's quiet program is not kept, and the published bytes are the program itself.
        self.assertEqual(sorted(path.name for path in self.raw["plain"].iterdir() if path.name.startswith("example")),
                         ["example_fuzzer"])
        self.assertEqual(self.entries["example_fuzzer"]["plain"]["sha256"],
                         manifest.sha256_of(self.raw["plain"] / "example_fuzzer"))

    def test_the_sanitizer_builds_are_refused(self):
        done = subprocess.run(["docker", "run", "--rm", "--network=none", "-e", "SANITIZER=address", GO_TAG, "compile"],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("plain build only", done.stderr)

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_exit_statuses(self):
        inputs = self.work / "in"
        inputs.mkdir()
        for case in GO_EXPECTED:
            (inputs / f"case-{case or 'empty'}").write_bytes(b"\0" * 6 + case.encode())
        (inputs / "short").write_bytes(b"\0" * 5)
        binaries = self.work / "bin"
        binaries.mkdir()
        shutil.copy(self.work / "out" / "example_fuzzer" / "example_fuzzer.plain", binaries)
        runner = ('for c in /in/*; do timeout 120 /qemu /bin2/example_fuzzer.plain "$c" > /dev/null 2>&1; '
                  'echo "${c#/in/} $?"; done; printf "printed "; timeout 60 /qemu /bin2/example_fuzzer.plain '
                  '/in/case-r | tr "\\n" ,; echo')
        done = run_in_container(GO_TAG, runner, (inputs, "/in"), (binaries, "/bin2"))
        results = dict(line.split(" ", 1) for line in done.stdout.splitlines())
        for case, status in GO_EXPECTED.items():
            with self.subTest(case=case):
                self.assertEqual(results[f"case-{case or 'empty'}"], str(status))
        self.assertEqual(results["short"], "2")
        # The driver writes what Fuzz returned, for each call.
        self.assertEqual(results["printed"], "-1,")


CJSON = pathlib.Path(__file__).resolve().parent / "fixtures" / "cjson"
CJSON_TAG = f"oss-verify-test/cjson:{RUN}"
# cJSON 1.7.18, as the oss-fuzz-theorems 2026.10 release built it.
CJSON_COMMIT = "acc76239bee01d8e9c858ae2cab296704e52d916"
# That release's cjson_read_fuzzer binaries (its projects/cjson/cjson_read_fuzzer/harness.yaml).
CJSON_RELEASE = {
    "plain": "b40ed189a37beb50da46f04a457ec144b05319a845fa3b0639d7a117ffd1696d",
    "ubsan": "73d8f136684412bc2827dd90598b3b66fa023b78537ce674aa5007e9be78cbd0",
    "asan": "09e0835df41a2bab7c8e4af1e6b990748fde19337e65f5b2993ae8be5e9d3a5f",
    "asan-ubsan": "57f377d242bdd8fa074ec06428b9785e4d6357af953724e1c9a0533f271847d8",
}
# An input for cjson_read_fuzzer (flags 1010: minify, no termination required, formatted, unbuffered) on which a run
# makes 21 allocations: cJSON's, through its hooks, and the harness's copy for minifying.
CJSON_INPUT = b'1010{"a":[1,2,{"b":"c"}],"d":"e","f":[true,false,null,1.5e3]}\0'
CJSON_ALLOCATIONS = 21
CJSON_RUNNER = r"""
for b in $B; do
  for t in cjson_read_fuzzer_allocation_failure cjson_read_fuzzer_allocation_counting; do
    for c in /in/*; do q /bin2/$t.$b "$c" > /dev/null 2>&1; echo "$t $b ${c#/in/} $?"; done
  done
done
"""


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class AllocationFailureOnCjson(unittest.TestCase):
    """fixtures/cjson: cJSON's own fuzz target, as projects/cjson builds it, and its allocation-failure variants.
    Building cJSON needs the network."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-cjson.")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", CJSON_TAG], capture_output=True)
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="cjson", directory=CJSON, repo="https://github.com/DaveGamble/cJSON", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, CJSON_COMMIT, builder, CJSON_TAG, cls.work)
        raw = {build: cls.work / "raw" / build for build in BUILDS}
        compile_builds(CJSON_TAG, raw, check_build.work_label(cls.work))
        found = {build: manifest.discover(directory) for build, directory in raw.items()}
        cls.targets, _ = manifest.resolve_targets(found)
        cls.entries, _ = manifest.collect(raw, cls.targets, cls.work / "out")

    def test_the_fuzz_target_keeps_the_release_s_bytes(self):
        self.assertEqual(self.targets, ["cjson_read_fuzzer", "cjson_read_fuzzer_allocation_counting",
                                        "cjson_read_fuzzer_allocation_failure"])
        for build, sha256 in CJSON_RELEASE.items():
            self.assertEqual(self.entries["cjson_read_fuzzer"][build]["sha256"], sha256, build)

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_allocations(self):
        inputs = self.work / "in"
        inputs.mkdir()
        mask = lambda n: (1 << n).to_bytes(4, "little")
        (inputs / "count").write_bytes(b"\0\x80" + bytes(4) + CJSON_INPUT)
        for n in range(32):
            (inputs / f"fail-{n:02d}").write_bytes(b"\0\0" + mask(n) + CJSON_INPUT)
        (inputs / "fail-all").write_bytes(b"\0\0" + b"\xff" * 4 + CJSON_INPUT)
        for n in (0, 5, 12, 20, 21):
            (inputs / f"count-fail-{n:02d}").write_bytes(b"\0\x80" + mask(n) + CJSON_INPUT)
        binaries = self.work / "bin"
        binaries.mkdir()
        for target in self.targets:
            for build in BUILDS:
                shutil.copy(self.work / "out" / target / f"{target}.{build}", binaries)
        runner = f"q() {{ timeout 60 /qemu \"$@\"; }}\n{CJSON_RUNNER}"
        output = each_build_at_once(CJSON_TAG, runner, BUILDS, (inputs, "/in"), (binaries, "/bin2"))
        results = {tuple(line.split(" ")[:3]): line.split(" ")[3] for line in output.splitlines()}
        for build in BUILDS:
            for case in sorted(path.name for path in inputs.iterdir()):
                published = results[("cjson_read_fuzzer_allocation_failure", build, case)]
                counting = results[("cjson_read_fuzzer_allocation_counting", build, case)]
                with self.subTest(build=build, case=case):
                    # cJSON survives each allocation failing, and a published build ignores counting mode.
                    self.assertEqual(published, "0")
                    if case == "count":
                        self.assertEqual(counting, str(CJSON_ALLOCATIONS))  # the same count in every build
                    elif case.startswith("count-fail-"):
                        n = int(case.rsplit("-", 1)[1])  # the run stops allocating after the one that fails
                        self.assertEqual(counting, str(min(n + 1, CJSON_ALLOCATIONS)))
                    else:
                        self.assertEqual(counting, "0")


# The frame-pointer images of .github/workflows/toolchain-images.yaml that FramePointersC and FramePointersRust build
# on, by the language of the fixture: the row of infra/toolchains.tsv that the image is made from, and the variable that
# names the image. The rows are taken by name, never as the newest for a language, so that these tests read the same
# images after infra/toolchains.tsv has the frame-pointer rows too.
FRAME_POINTER_IMAGES = {"c": ("oss-fuzz-theorems-2026.10", "OV_FP_TOOLCHAIN_C"),
                        "rust": ("oss-fuzz-theorems-2026.10-rust", "OV_FP_TOOLCHAIN_RUST")}
# What toolchain.sh adds to the C flags, and rust/recipes.sh to rustc's, on a frame-pointer image.
FP_C_FLAG = "-fno-omit-frame-pointer"
FP_RUST_FLAG = "-Cforce-frame-pointers=yes"


def row_image(name):
    """The image of the row of infra/toolchains.tsv named `name`."""
    images = [image for row, image, _, _ in check_build.toolchains() if row == name]
    if len(images) != 1:
        raise check_build.Failed(f"infra/toolchains.tsv has {len(images)} rows named {name}, not 1")
    return images[0]


def frame_pointer_images_here(language):
    """Whether the tests of `language` can run: OV_DOCKER_TESTS is 1, the variable of its frame-pointer image is set,
    and Docker has the base image of that image."""
    row, variable = FRAME_POINTER_IMAGES[language]
    return os.environ.get("OV_DOCKER_TESTS") == "1" and bool(os.environ.get(variable)) and docker_ready(row_image(row))


def frame_pointers_skip(language):
    """The reason a class of FramePointers skips without the images of `language`."""
    row, variable = FRAME_POINTER_IMAGES[language]
    return (f"set OV_DOCKER_TESTS=1, and {variable} to the frame-pointer image made from {row} "
            "(.github/workflows/toolchain-images.yaml makes it), with Docker and that base image, to build the "
            "fixture on them")


class FramePointers:
    """OFT_FRAME_POINTERS: the plain build of one fixture on a frame-pointer image and on the base image it is made from,
    in a class for each language: FramePointersC (fixtures/example) and FramePointersRust (fixtures/rust-example). Each
    class needs only its own language's two images, and builds the fixture's project image on each of them, so the two
    classes run apart, each on a pytest-xdist worker of its own. compile_build passes no -e of its caller and keeps no
    output, so these tests run compile with compile_build's docker run arguments and their own -e, and read its output.
    A Rust build compiles the standard library (minutes), so each compile that a test of the class reads (runs) runs
    once, in setUpClass, all at once, each into an $OUT of its own, as do the builds of the two project images."""

    # The language of the fixture: a key of FRAME_POINTER_IMAGES.
    language = None
    # The compiles that the tests of the class read: (kind, settings), for compile().
    runs = ()

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix=f"ov-test-frame-pointers-{cls.language}.")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.work = pathlib.Path(cls.scratch.name)
        cls.labels = check_build.work_label(cls.work)
        if cls.language == "rust":
            job = check_build.Job(name="rust-example", directory=RUST_FIXTURE,
                                  repo="https://example.invalid/rust-example", ref="", dockerfile="", builds=["plain"],
                                  fuzz_targets=["example_fuzzer"], language="rust")
        else:
            job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                                  dockerfile="", builds=["plain"], fuzz_targets=None)
        row, variable = FRAME_POINTER_IMAGES[cls.language]
        # The project image of the fixture, on the base image ("base") and on the frame-pointer image ("fp").
        toolchains = {"base": row_image(row), "fp": os.environ[variable]}
        cls.toolchains = toolchains
        cls.tags = {kind: f"oss-verify-test/{job.name}-frame-pointers:{kind}-{RUN}" for kind in toolchains}
        for tag in cls.tags.values():
            cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", tag], capture_output=True)
        at_once(lambda kind: check_build.build_project(job, "0" * 40, check_build.build_builder(toolchains[kind]),
                                                       cls.tags[kind], cls.work), toolchains)
        cls.results = dict(zip(cls.runs, at_once(cls.compile, cls.runs)))

    @classmethod
    def compile(cls, run):
        """compile, the plain build, for run = (kind, settings): in the project image on the image of `kind` ("base" or
        "fp"), with compile_build's docker run arguments and an -e for each of `settings`, into an $OUT of its own: its
        exit status, and its standard output and standard error together. The Rust run on the base image with no
        setting is RustBuilder's plain build, which shared_rust_plain compiles once for both classes."""
        kind, settings = run
        if cls.language == "rust" and run == ("base", ()):
            code, output, _ = shared_rust_plain(cls.toolchains["base"], cls)
            return code, output
        tag = cls.tags[kind]
        out = cls.work / f"out-{cls.runs.index(run)}"
        return compile_plain(tag, out, cls.labels, settings)

    def flag_lines(self, output):
        """[(line, the flag it has on a frame-pointer image)] for the lines of a build's output that give its flags:
        compile's CFLAGS line and, in a Rust build, the Rust recipe's RUSTFLAGS line. A missing line fails the test."""
        wanted = [(r"^compile: CFLAGS=.*$", FP_C_FLAG)]
        if self.language == "rust":
            wanted.append((r"^oft-rust: .* RUSTFLAGS=.*$", FP_RUST_FLAG))
        lines = []
        for pattern, flag in wanted:
            found = re.findall(pattern, output, re.M)
            self.assertTrue(found, f"no line {pattern} in the output of compile:\n{output[-4000:]}")
            lines += [(line, flag) for line in found]
        return lines

    def built_with_frame_pointers(self):
        code, output = self.results["fp", ()]
        self.assertEqual(code, 0, output[-4000:])
        for line, flag in self.flag_lines(output):
            self.assertIn(flag, line)

    def built_without_frame_pointers(self, *settings):
        code, output = self.results["base", settings]
        self.assertEqual(code, 0, output[-4000:])
        for line, _ in self.flag_lines(output):
            for flag in (FP_C_FLAG, FP_RUST_FLAG):
                self.assertNotIn(flag, line)


@unittest.skipUnless(frame_pointer_images_here("c"), frame_pointers_skip("c"))
class FramePointersC(FramePointers, unittest.TestCase):
    language = "c"
    runs = (("fp", ()), ("base", ()), ("base", ("OFT_FRAME_POINTERS=",)), ("base", ("OFT_FRAME_POINTERS=0",)))

    def test_the_frame_pointer_image_builds_c_with_frame_pointers(self):
        self.built_with_frame_pointers()

    def test_the_base_image_builds_c_without_frame_pointers(self):
        self.built_without_frame_pointers()

    def test_an_empty_oft_frame_pointers_on_the_base_image_builds_c_without_frame_pointers(self):
        self.built_without_frame_pointers("OFT_FRAME_POINTERS=")

    def test_oft_frame_pointers_0_fails_the_build(self):
        code, output = self.results["base", ("OFT_FRAME_POINTERS=0",)]
        self.assertEqual(code, 1, output[-4000:])
        # The message names the variable and the value it refuses.
        self.assertRegex(output, r"OFT_FRAME_POINTERS.*'0'")


@unittest.skipUnless(frame_pointer_images_here("rust"), frame_pointers_skip("rust"))
class FramePointersRust(FramePointers, unittest.TestCase):
    language = "rust"
    runs = (("fp", ()), ("base", ()), ("base", ("OFT_FRAME_POINTERS=",)))

    def test_the_frame_pointer_image_builds_rust_with_frame_pointers(self):
        self.built_with_frame_pointers()

    def test_the_base_image_builds_rust_without_frame_pointers(self):
        self.built_without_frame_pointers()

    def test_an_empty_oft_frame_pointers_on_the_base_image_builds_rust_without_frame_pointers(self):
        self.built_without_frame_pointers("OFT_FRAME_POINTERS=")


if __name__ == "__main__":
    unittest.main()
