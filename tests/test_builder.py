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
classes, on the images that its job make made.
"""
import contextlib
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

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

# Runs every case in one container: prints "<target> <build> <case> <status>" per line.
RUNNER = r"""
cd /in
for t in example_fuzzer example_fuzzer_cc example_fuzzer_af example_fuzzer_cc_af example_fuzzer_count example_fuzzer_cc_count; do
  for b in plain ubsan asan asan-ubsan; do
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


def run_in_container(image, runner, *mounts):
    """Run the sh script runner in a container of image with no network, with qemu-riscv64 at /qemu and each (host
    path, container path) of mounts read-only. image is a tag that the test built, so docker never pulls it from a
    registry. Returns the completed process, with its output as text."""
    volumes = [arg for host, container in ((QEMU, "/qemu"), *mounts) for arg in ("-v", f"{host}:{container}:ro")]
    return subprocess.run(["docker", "run", "--rm", "--network=none", "--pull=never", *volumes, "--entrypoint", "sh",
                           image, "-c", f"{NO_CORE_MEMORY}\n{runner}"], capture_output=True, text=True, check=True)


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


class Streams:
    """sys.stdout for builds that run at once (compile_builds): check_build.run copies the output of each docker run in
    a thread of its own, so a thread's text is one run's. Each thread's text is kept apart, so that no line of one run
    is cut by another's, and all of it goes to `out` as well."""

    def __init__(self, out):
        self.out, self.written = out, {}

    def write(self, text):
        self.written.setdefault(threading.current_thread(), []).append(text)
        return self.out.write(text)

    def flush(self):
        self.out.flush()

    def texts(self):
        """What each thread wrote, a text for each."""
        return ["".join(parts) for parts in self.written.values()]


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
        done = run_in_container(TAG, runner.replace("/bin/", "/bin2/"), (inputs, "/in"), (binaries, "/bin2"))
        results = {}
        for line in done.stdout.splitlines():
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
# Payload first byte -> exit status in each build of the Python fixture (fixtures/python-example/pkg/example): an
# uncaught exception exits 79, a MemoryError 2, a SystemExit 77. The same in all four builds.
PYTHON_EXPECTED = {"": 0, "a": 0, "p": 0, "e": 79, "m": 2, "x": 77}
# The answers of CPython's configure in the Python builder (infra/base-builder/python/config-cache): for each build, in
# <this>/<flav>/config.cache, which that build's configure starts from (python/recipes.sh, oft_py_runtime), with what
# that configure could see in <this>/<flav>/seen (oft_py_seen).
PYTHON_CONFIG = "/usr/local/lib/oss-verify/python/config"
# For each flavour given: the flavour, then the number of answers of its config.cache, the compiler and the flags that
# they were got with, the number of lines of its seen and the first of them; or "none". configure reads the cache by
# sourcing it, and so does this.
PYTHON_CACHES = r"""for f; do
  c=/usr/local/lib/oss-verify/python/config/$f/config.cache s=/usr/local/lib/oss-verify/python/config/$f/seen
  if [ -s "$c" ]; then
    (. "$c"; printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$(grep -c '^ac_cv_' "$c")" "$ac_cv_env_CC_value" \
      "$ac_cv_env_CFLAGS_value" "$(wc -l < "$s")" "$(head -n 1 "$s")")
  else
    printf '%s\tnone\n' "$f"
  fi
done
"""
# A package of Alpine's that the Python toolchain image does not hold, which a project's Dockerfile could install.
PYTHON_EXTRA_PACKAGE = "tree"
# Layers of a project's Dockerfile that change what CPython's configure can see without a file of the builder's
# directories (python/seen.py): {name: the Dockerfile's lines after FROM}. tools: an ENV PATH that adds a directory
# holding a pkg-config, which configure looks for on PATH; variable: one more variable.
PYTHON_GUARD_LAYERS = {
    "tools": ("RUN mkdir -p /opt/oft-test-tools/bin"
              " && printf '#!/bin/sh\\nexit 1\\n' > /opt/oft-test-tools/bin/pkg-config"
              " && chmod 755 /opt/oft-test-tools/bin/pkg-config\nENV PATH=/opt/oft-test-tools/bin:$PATH\n"),
    "variable": "ENV OFT_TEST_VARIABLE=1\n",
}
# A build.sh for compile, as the plain build: the guard of the builder's answers (python/recipes.sh,
# oft_py_answers_seen) and its status, and nothing more.
PYTHON_GUARD = r"""#!/bin/sh -e
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh
mkdir -p /work/ext/oft-py-control/src
(
ov_target_begin oft-py-control
. /usr/local/lib/oss-verify/python/recipes.sh
rt=$OFT_PY_RTS/$FLAV
oft_py_new_rt "$rt"
status=0; oft_py_answers_seen "$rt" || status=$?
echo "control: the guard returned $status"
)
"""
# A build.sh for compile, as the plain build: CPython's configure of the build's runtime (python/recipes.sh,
# oft_py_runtime_configure), then its exit status and how many times configure loaded a cache, and nothing more of the
# build. With a file answers beside it that names a build's flavour, the answers of that build stand in this build's
# place first: a file, not a variable, which the guard would see (python/seen.py).
PYTHON_CONTROL = r"""#!/bin/sh -e
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh
mkdir -p /work/ext/oft-py-control/src
(
ov_target_begin oft-py-control
. /usr/local/lib/oss-verify/python/recipes.sh
if [ -f "$SRC/answers" ]; then
  cp "$OFT_PY_CONFIG/$(cat "$SRC/answers")/config.cache" "$OFT_PY_CONFIG/$FLAV/config.cache"
fi
rt=$OFT_PY_RTS/$FLAV
status=0; oft_py_runtime_configure "$rt" || status=$?
echo "control: configure exited $status, and loaded a cache $(grep -c '^configure: loading cache ' "$rt/configure.log") times"
)
"""


def flav(build):
    """compile's FLAV of a build: its name without the hyphen (the directory of its runtime and of its answers)."""
    return build.replace("-", "")


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
    """fixtures/python-example: an atheris harness, built with python/recipes.sh in each build, and beside the builds
    the controls of the configure cache: two stop once configure has run, and the others once its guard has decided.
    Getting the fixture's build backend needs the network."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-python.")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.tag = f"oss-verify-test/python-example:{RUN}"
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", cls.tag], capture_output=True)
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="python-example", directory=PYTHON_FIXTURE,
                              repo="https://example.invalid/python-example", ref="", dockerfile="",
                              builds=BUILDS, fuzz_targets=["fuzz_example"], language="python")
        cls.builder = check_build.build_builder(check_build.newest_toolchain("python"))
        check_build.build_project(job, "0" * 40, cls.builder, cls.tag, cls.work)
        cls.raw = {build: cls.work / "raw" / build for build in BUILDS}
        # What the builds print, a text for each docker run (test_each_configure_started_from_its_builds_answers), and,
        # beside them, the controls of test_a_build_refuses_the_answers_of_another_build,
        # test_a_build_with_one_more_package_asks_every_question_itself and the guard's (guard_controls).
        streams = Streams(sys.stdout)
        with contextlib.redirect_stdout(streams):
            _, cls.refused, cls.with_package, cls.guarded = at_once(lambda run: run(), (
                lambda: compile_builds(cls.tag, cls.raw, check_build.work_label(cls.work)), cls.refuse,
                cls.configure_with_one_more_package, cls.guard_controls))
        cls.outputs = streams.texts()
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, job.fuzz_targets)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    @classmethod
    def control_configure(cls, name, image, *settings, script=PYTHON_CONTROL, answers=None):
        """compile of `script` (by default PYTHON_CONTROL), as the plain build, in a container of `image`, with an -e
        for each of `settings`, its build.sh in <work>/<name>, with a file answers that names `answers` if given: the
        completed process, with its standard output and standard error together."""
        source = cls.work / name
        source.mkdir()
        (source / "build.sh").write_text(script)
        if answers:
            (source / "answers").write_text(answers)
        environment = [word for setting in settings for word in ("-e", setting)]
        return subprocess.run(["docker", "run", "--rm", "--init", "--network=none", "--pull=never",
                               *check_build.work_label(cls.work), "-e", "SANITIZER=none", "-e", "SRC=/control",
                               *environment, "-v", f"{source}:/control:ro", image, "compile"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              errors="replace")

    def configured_in_full(self, done, why):
        """A control, control_configure's completed process `done`: the plain build's configure did not start from the
        builder's answers, said `why` (a pattern), asked every question itself, exited 0 and loaded no cache; compile
        then ended, as PYTHON_CONTROL builds nothing more. The rest of a build after a whole configure is the
        release's recipe, which a build with no answers of the builder runs, and the bytes of such a build are the same
        as from the answers (INFRA-5359)."""
        self.assertEqual(done.returncode, 0, done.stdout[-4000:])
        lines = re.findall(r"(?m)^oft-py: runtime plain: .*$|^control: .*$", done.stdout)
        self.assertEqual(len(lines), 3, done.stdout[-4000:])
        self.assertRegex(lines[0], why)
        self.assertEqual(lines[1:], ["oft-py: runtime plain: configure asked every question itself",
                                     "control: configure exited 0, and loaded a cache 0 times"], done.stdout[-4000:])

    @classmethod
    def refuse(cls):
        """The plain build's configure in the builder, with the asan build's answers in place of its own."""
        return cls.control_configure("refusal", cls.builder, answers="asan")

    @classmethod
    def configure_with_one_more_package(cls):
        """The plain build's configure in the fixture's project image with PYTHON_EXTRA_PACKAGE installed, as a layer
        of a project's Dockerfile installs it (apk, with the network)."""
        tag = f"oss-verify-test/python-example-package:{RUN}"
        cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", tag], capture_output=True)
        context = cls.work / "package"
        context.mkdir()
        (context / "Dockerfile").write_text(f"FROM {cls.tag}\nRUN apk add --no-cache {PYTHON_EXTRA_PACKAGE}\n")
        if check_build.run("docker", "build", "--progress=plain", "-t", tag, str(context)) != 0:
            raise check_build.Failed(f"the image with {PYTHON_EXTRA_PACKAGE} does not build")
        return cls.control_configure("package-control", tag)

    @classmethod
    def guard_controls(cls):
        """The guard alone (PYTHON_GUARD), as the plain build: in the fixture's project image as oss-verify check
        --checks runs a build (with its records), and in that image with each layer of PYTHON_GUARD_LAYERS. {name:
        the completed process}, "checks" for the first."""
        done = {"checks": cls.control_configure("guard-checks", cls.tag, "OV_RECORD=1", "OFT_MAKE_JOBS=2",
                                                script=PYTHON_GUARD)}
        for name, layers in PYTHON_GUARD_LAYERS.items():
            tag = f"oss-verify-test/python-example-{name}:{RUN}"
            cls.addClassCleanup(subprocess.run, ["docker", "image", "rm", tag], capture_output=True)
            context = cls.work / f"guard-{name}"
            context.mkdir()
            (context / "Dockerfile").write_text(f"FROM {cls.tag}\n{layers}")
            if check_build.run("docker", "build", "--progress=plain", "-t", tag, str(context)) != 0:
                raise check_build.Failed(f"the image with the layer {name} does not build")
            done[name] = cls.control_configure(f"guard-{name}-run", tag, script=PYTHON_GUARD)
        return done

    def guard_said(self, name):
        """The guard's lines of the guard control `name`: what it said, and its status."""
        done = self.guarded[name]
        self.assertEqual(done.returncode, 0, done.stdout[-4000:])
        return re.findall(r"(?m)^oft-py: runtime plain: .*$|^control: .*$", done.stdout)

    def test_discovery(self):
        self.assertEqual((self.problems, self.missing, self.targets), ([], [], ["fuzz_example"]))

    def test_each_build_has_its_own_answers_of_configure(self):
        """The Python builder holds a config.cache for each build, of CPython's configure as that build runs it: each
        holds answers, and records the compiler and the flags that they were got with (ac_cv_env_CC_value,
        ac_cv_env_CFLAGS_value), which autoconf compares with a later configure's, and what that configure could see
        (seen). So each build's flags name its own build directory, and only the sanitizer builds' flags sanitize,
        those of asan and asan-ubsan for addresses."""
        done = subprocess.run(["docker", "run", "--rm", "--network=none", "--pull=never", "--entrypoint", "sh",
                               self.builder, "-c", PYTHON_CACHES, "sh", *map(flav, BUILDS)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        caches = {fields[0]: fields[1:] for fields in (line.split("\t") for line in done.stdout.splitlines())}
        self.assertEqual(sorted(caches), sorted(map(flav, BUILDS)), done.stdout)
        for build in BUILDS:
            with self.subTest(build=build):
                self.assertEqual(len(caches[flav(build)]), 5, f"no config.cache for {build}: {caches[flav(build)]}")
                answers, cc, cflags, seen, first = caches[flav(build)]
                self.assertGreater(int(answers), 0)
                self.assertTrue(cc, cflags)
                self.assertIn(f"-fmacro-prefix-map=/work/build/pyrt/{flav(build)}/=", cflags)
                self.assertEqual("-fsanitize=" in cflags, build != "plain", cflags)
                self.assertEqual("-fsanitize=address" in cflags, "asan" in build, cflags)
                # What its configure could see: the package database's hash, then the paths.
                self.assertGreater(int(seen or 0), 1, first)
                self.assertRegex(first, r"^package database \S+ [0-9a-f]{64}$")
        self.assertEqual(len({tuple(caches[flav(build)][1:3]) for build in BUILDS}), len(BUILDS), caches)

    def test_each_configure_started_from_its_builds_answers(self):
        """The configure of each build loaded its own build's config.cache, as configure's own output says
        (oft_py_runtime_configure's line from its configure.log): the fixture's project image shows configure what
        the builder's did. The runtime's directory is the build's flavour (flav)."""
        runtimes = [line for text in self.outputs for line in re.findall(r"(?m)^oft-py: runtime .*$", text)]
        started = [found.groups() for line in runtimes
                   if (found := re.match(r"oft-py: runtime (\S+): configure started from the builder's \d+ answers "
                                         r"\((\S+)\)$", line))]
        self.assertEqual(sorted(started),
                         sorted((flav(build), f"{PYTHON_CONFIG}/{flav(build)}/config.cache") for build in BUILDS),
                         runtimes)

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
        runner = (f'for b in {" ".join(BUILDS)}; do for c in /in/*; do '
                  'timeout 600 /qemu /bin2/fuzz_example.$b "$c" > /dev/null 2>&1; echo "$b ${c#/in/case-} $?"; done; '
                  'printf "%s " "$b printed"; timeout 600 /qemu /bin2/fuzz_example.$b /in/case-p | tr "\\n" ,; echo; '
                  'done')
        done = run_in_container(self.tag, runner, (inputs, "/in"), (binaries, "/bin2"))
        results = {tuple(line.split(" ", 2)[:2]): line.split(" ", 2)[2] for line in done.stdout.splitlines()}
        for case, status in PYTHON_EXPECTED.items():
            for build in BUILDS:
                with self.subTest(build=build, case=case):
                    self.assertEqual(results[(build, case or "empty")], str(status))
        for build in BUILDS:
            # The loud build writes what the harness prints, then the driver writes the return value.
            self.assertEqual(results[(build, "printed")], "printed,0,", build)

    def test_a_build_refuses_the_answers_of_another_build(self):
        """The control of autoconf's own check (oft_py_configure_from_cache): the plain build's configure, given the
        asan build's answers in place of its own, refuses them, since the compiler and the flags recorded with them
        changed, and asks every question itself."""
        self.configured_in_full(self.refused, r"configure refused the builder's answers \(\S+\): configure: error: "
                                              r"`(CC|CFLAGS)' has changed since the previous run")

    def test_a_build_with_one_more_package_asks_every_question_itself(self):
        """The control of the package guard (oft_py_seen): in the project image with one more package, which a
        project's Dockerfile installed, the plain build's configure does not start from the builder's answers, says
        that the package database differs, and asks every question itself."""
        self.configured_in_full(self.with_package, r"configure can see another environment or other files here than "
                                                   r"when the builder got its answers \(\S+\): \d+ lines differ, such "
                                                   r"as .*package database")

    def test_the_guard_takes_the_answers_in_a_build_with_the_records_of_the_checks(self):
        """The guard's control: in the fixture's project image, as oss-verify check --checks runs the plain build (with
        OV_RECORD and OFT_MAKE_JOBS, which seen.py leaves out), it takes the builder's answers."""
        self.assertEqual(self.guard_said("checks"), ["control: the guard returned 0"],
                         self.guarded["checks"].stdout[-4000:])

    def test_a_directory_of_tools_on_path_refuses_the_answers(self):
        """A project's Dockerfile that adds a directory holding a pkg-config to PATH (ENV PATH): the guard refuses the
        builder's answers, and says that PATH differs."""
        said = self.guard_said("tools")
        self.assertEqual(said[1:], ["control: the guard returned 1"], self.guarded["tools"].stdout[-4000:])
        self.assertRegex(said[0], r"configure can see another environment or other files here than when the builder "
                                  r"got its answers \(\S+\): \d+ lines differ, such as -environment PATH=\S+ "
                                  r"\+environment PATH=\S*/opt/oft-test-tools/bin:")

    def test_one_more_variable_refuses_the_answers(self):
        """A project's Dockerfile that sets one more variable (ENV): the guard refuses the builder's answers, and names
        the variable."""
        said = self.guard_said("variable")
        self.assertEqual(said[1:], ["control: the guard returned 1"], self.guarded["variable"].stdout[-4000:])
        self.assertRegex(said[0], r"configure can see another environment or other files here than when the builder "
                                  r"got its answers \(\S+\): 1 lines differ, such as "
                                  r"\+environment OFT_TEST_VARIABLE=1 $")


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
        builder = check_build.build_builder(check_build.newest_toolchain("rust"))
        check_build.build_project(job, "0" * 40, builder, RUST_TAG, cls.work)
        cls.raw = {build: cls.work / "raw" / build for build in BUILDS}
        compile_builds(RUST_TAG, cls.raw, check_build.work_label(cls.work))
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
        # coredump_filter the dump holds no memory, and all the cases of this test run in less than a second there
        # (OSSV-729's measurement). OSSV-729 keeps each helper's time limit, as its R2 asks, and measured no lower
        # limit.
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
for b in plain ubsan asan asan-ubsan; do
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
        done = run_in_container(CJSON_TAG, runner, (inputs, "/in"), (binaries, "/bin2"))
        results = {tuple(line.split(" ")[:3]): line.split(" ")[3] for line in done.stdout.splitlines()}
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
        exit status, and its standard output and standard error together."""
        kind, settings = run
        tag = cls.tags[kind]
        out = cls.work / f"out-{cls.runs.index(run)}"
        check_build.empty_directory(out, tag, labels=cls.labels)
        environment = [word for setting in settings for word in ("-e", setting)]
        done = subprocess.run(
            ["docker", "run", "--rm", "--init", "--network=none", *cls.labels, "-e", "SANITIZER=none",
             "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}", *environment, "-v", f"{out}:/out", tag, "compile"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        return done.returncode, done.stdout

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
