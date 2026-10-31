# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example, tests/fixtures/program, tests/fixtures/cjson, tests/fixtures/rust-example,
tests/fixtures/python-example and tests/fixtures/go-example with the builder and run what they make. Needs Docker and
the toolchain images (and, for cJSON, the Rust crates and the Python build backend, the network):

    OV_DOCKER_TESTS=1 python3 -m pytest tools/tests

The fixture's Dockerfile and build.sh are templates/Dockerfile and templates/build.sh (in its C and C++ forms). Its
fuzz targets do one thing per first input byte, and the test checks the exit status of each in every build against
docs/build-contract.md. Running the riscv64 binaries needs qemu-riscv64 (static) on this machine; without it, that part
is skipped.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_binaries  # noqa: E402
import check_build  # noqa: E402
import manifest  # noqa: E402
import validate  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = "oss-verify-test/example:latest"
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


def docker_ready():
    """Whether Docker runs and the toolchain image the fixture builds FROM (the newest for C) is here."""
    try:
        return subprocess.run(["docker", "image", "inspect", check_build.newest_toolchain()],
                              capture_output=True).returncode == 0
    except OSError:
        return False


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class Builder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-builder.")
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, TAG, cls.work)
        cls.raw = {}
        for build in BUILDS:
            cls.raw[build] = cls.work / "raw" / build
            check_build.compile_build(TAG, build, validate.BUILDS[build], cls.raw[build],
                                      labels=check_build.work_label(cls.work))
        cls.found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(cls.found)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

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
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", TAG, "-c", runner.replace("/bin/", "/bin2/")],
            capture_output=True, text=True, check=True,
        )
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
    """The UBSan checks that tools/check gives compile on a toolchain that applies a project's ubsan_checks."""

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_only_the_given_checks_trap(self):
        tag = "oss-verify-test/example-ubsan:latest"
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
                done = subprocess.run(
                    ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
                     "-v", f"{raw}:/raw:ro", "--entrypoint", "sh", tag, "-c", runner],
                    capture_output=True, text=True, check=True,
                )
            finally:
                subprocess.run(["docker", "image", "rm", tag], capture_output=True)
        results = dict(line.split() for line in done.stdout.splitlines())
        self.assertEqual(results, {"case-n": "132", "case-o": "0"})


PROGRAM_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "program"
PROGRAM_TAG = "oss-verify-test/program:latest"
# The fixture's whole program (fixtures/program/program.c), on each first argument: its exit status in each build
# (plain, ubsan, asan, asan-ubsan) and what it writes on standard output, each line ended with a comma.
PROGRAM_EXPECTED = {
    "none": ((0, 0, 0, 0), "hello,"),
    "env": ((0, 0, 0, 0), "seen,"),
    "huge": ((3, 3, 3, 3), ""),
    "overflow": ((0, 0, 134, 134), ""),
}
# Text that only a sanitizer's report holds. When the run aborts, standard error also holds what the shell or qemu
# says about the signal ("Aborted (core dumped)"), which is not the program's.
REPORT_TEXT = re.compile(r"Sanitizer|ERROR:|SUMMARY:|==\d+==")
PROGRAM_RUNNER = r"""
for b in plain ubsan asan asan-ubsan; do
  for c in none env huge overflow; do
    if [ "$c" = none ]; then set --; else set -- "$c"; fi
    OV_TEST_VALUE=seen q /bin2/ov_program.$b "$@" > /tmp/out 2> /tmp/err; s=$?
    printf '%s ' "$b $c $s"; tr '\n' , < /tmp/out; printf ' '; tr '\n' , < /tmp/err; echo
  done
done
"""


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class ProgramBuilder(unittest.TestCase):
    """fixtures/program: a whole program, with its own main, linked with $OV_PROGRAM_LDFLAGS in each build, with no
    driver and no seals (docs/build-contract.md, "Whole programs")."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-program.")
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="program", directory=PROGRAM_FIXTURE, repo="https://example.invalid/program",
                              ref="", dockerfile="", builds=BUILDS, fuzz_targets=None, programs=["ov_program"])
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, PROGRAM_TAG, cls.work)
        cls.raw = {}
        for build in BUILDS:
            cls.raw[build] = cls.work / "raw" / build
            check_build.compile_build(PROGRAM_TAG, build, validate.BUILDS[build], cls.raw[build],
                                      labels=check_build.work_label(cls.work), programs=job.programs)
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, programs=job.programs)
        cls.problems += manifest.find_programs(cls.raw, job.programs)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out", job.programs)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", PROGRAM_TAG], capture_output=True)

    def test_discovery(self):
        self.assertEqual((self.problems, self.missing, self.targets), ([], [], []))
        self.assertEqual(list(self.entries), ["ov_program"])

    def test_the_published_bytes_are_the_static_stripped_twin(self):
        for build in BUILDS:
            with self.subTest(build=build):
                raw = self.raw[build] / "ov_program"
                twin = self.raw[build] / ".stripped" / manifest.sha256_of(raw)
                published = self.work / "out" / "ov_program" / f"ov_program.{build}"
                self.assertTrue(twin.is_file())
                self.assertEqual(manifest.sha256_of(published), manifest.sha256_of(twin))
                self.assertEqual(self.entries["ov_program"][build]["sha256"], manifest.sha256_of(twin))
                self.assertTrue(manifest.has_symbol_table(raw))
                self.assertFalse(manifest.is_fuzz_target(raw))
                self.assertFalse(manifest.has_symbol_table(published))
                self.assertEqual(manifest.binary_layout(published)["static"], True)
                self.assertEqual(manifest.read_elf(published)[0]["type"], manifest.ET_EXEC)

    def compile_with(self, programs, build_sh=None):
        """Run compile for the plain build in the fixture's image, with OV_PROGRAMS `programs` and, if given, this
        build.sh in place of the fixture's: (status, standard output, standard error, $OUT/.ov-refused or None)."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="compile.", dir=self.work))
        mounts = ["-v", f"{scratch / 'out'}:/out"]
        if build_sh is not None:
            (scratch / "build.sh").write_text(build_sh)
            mounts += ["-v", f"{scratch / 'build.sh'}:/src/build.sh:ro"]
        done = subprocess.run(
            ["docker", "run", "--rm", "--init", "--network=none", *check_build.work_label(self.work),
             "-e", "SANITIZER=none", "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}", "-e", f"OV_PROGRAMS={programs}",
             *mounts, PROGRAM_TAG, "compile"],
            capture_output=True, text=True,
        )
        refused = scratch / "out" / check_build.REFUSED
        return done.returncode, done.stdout, done.stderr, refused.read_text() if refused.exists() else None

    def test_compile_names_each_program_and_refuses_one_that_breaks_a_rule(self):
        status, out, _, refusal = self.compile_with("ov_program")
        self.assertEqual((status, refusal), (0, None))
        self.assertIn("compile: program ov_program\n", out)
        self.assertIn("compile: OV_PROGRAM_LDFLAGS=-static -no-pie -Wl,--gc-sections\n", out)
        link = '$CC $CFLAGS program.c -o "$OUT/ov_program" $OV_PROGRAM_LDFLAGS'
        cases = {
            "is not a regular file in $OUT": ("ov_program absent", None),
            "is not a program name": ("ov_program ../ov_program", None),
            "is not executable": ("ov_program", f'{link}\nchmod -x "$OUT/ov_program"\n'),
            # Kept by -u, which --gc-sections would otherwise drop.
            "defines LLVMFuzzerTestOneInput": (
                "ov_program",
                "printf 'int LLVMFuzzerTestOneInput(const char *d, unsigned long n) { return 0; }\\n' > \"$WORK/f.c\"\n"
                f'{link} "$WORK/f.c" -Wl,-u,LLVMFuzzerTestOneInput\n'),
        }
        for rule, (programs, build_sh) in cases.items():
            with self.subTest(rule=rule):
                status, _, errors, refusal = self.compile_with(programs, build_sh)
                self.assertEqual(status, 2, errors[-2000:])
                self.assertRegex(errors, r"compile: program \S+, which OV_PROGRAMS names, " + re.escape(rule))
                # The same reason, without "compile: ", for tools/check (check_build.compile_build).
                self.assertIsNotNone(refusal)
                self.assertIn(f"compile: {refusal.strip()}\n", errors)
                self.assertRegex(refusal, r"^program \S+, which OV_PROGRAMS names, " + re.escape(rule))
        # A build.sh that leaves the file and builds is not refused.
        status, _, errors, refusal = self.compile_with(
            "ov_program", f'{link}\necho "program ov_program is not one" > "$OUT/{check_build.REFUSED}"\n')
        self.assertEqual((status, refusal), (0, None), errors[-2000:])

    def test_tools_check_reads_a_refusal_as_a_rule_break(self):
        with self.assertRaises(check_build.Broken) as refused:
            check_build.compile_build(PROGRAM_TAG, "plain", "none", self.work / "refused",
                                      labels=check_build.work_label(self.work), programs=["ov_program", "absent"])
        self.assertIn("compile refused the plain build: program absent, which OV_PROGRAMS names, is not a regular "
                      "file in $OUT", str(refused.exception))

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_exit_statuses_and_output(self):
        binaries = self.work / "bin"
        binaries.mkdir()
        for build in BUILDS:
            shutil.copy(self.work / "out" / "ov_program" / f"ov_program.{build}", binaries)
        runner = f"q() {{ timeout 60 /qemu \"$@\"; }}\n{PROGRAM_RUNNER}"
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{binaries}:/bin2:ro",
             "--entrypoint", "sh", PROGRAM_TAG, "-c", runner],
            capture_output=True, text=True, check=True,
        )
        results = {}
        for line in done.stdout.splitlines():
            build, case, status, out, errors = line.split(" ", 4)
            results[(build, case)] = (status, out, errors)
        for case, (statuses, expected_out) in PROGRAM_EXPECTED.items():
            for build, status in zip(BUILDS, statuses):
                with self.subTest(build=build, case=case):
                    got_status, out, errors = results[(build, case)]
                    self.assertEqual((got_status, out), (str(status), expected_out))
                    # No report in any build: an AddressSanitizer detection aborts silently. A run that ends normally
                    # writes nothing at all on standard error, the asan twin's included.
                    self.assertIsNone(REPORT_TEXT.search(errors), errors)
                    if status != 134:
                        self.assertEqual(errors, "")

    @unittest.skipUnless(shutil.which("qemu-riscv64-static"), "no qemu-riscv64-static on PATH")
    def test_the_binary_checks_run_it_with_no_argument(self):
        """tools/checks/run-binaries' run of a whole program: no input.bin, no argument, its own name as argv[0]."""
        for build in ("plain", "asan"):
            job_dir = self.work / "jobs" / build
            (job_dir / "job").mkdir(parents=True)
            shutil.copyfile(self.work / "out" / "ov_program" / f"ov_program.{build}", job_dir / "job" / "binary")
            os.chmod(job_dir / "job" / "binary", 0o755)
            (job_dir / "job" / "runs").write_text(f"l0 binary {check_binaries.NO_INPUT} ov_program\n")
            results = check_binaries.run_job(job_dir, check_build.newest_toolchain(),
                                             pathlib.Path(shutil.which("qemu-riscv64-static")).resolve(), [], 600)
            self.assertEqual((results / "l0.status").read_text().strip(), "0", build)
            self.assertEqual((results / "l0.out").read_text().strip(), str(len("hello\n")), build)
            self.assertEqual((results / "l0.err").read_text().strip(), "0", build)
            self.assertEqual((results / "l0.calls").read_text().split("\n")[0], "exec", build)
            trace = (results / "l0.trace").read_text()
            self.assertNotIn("input.bin", trace, build)
            self.assertRegex(trace, r"exit_group\(0\)", build)


PYTHON_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "python-example"
PYTHON_TAG = "oss-verify-test/python-example:latest"
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
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="python-example", directory=PYTHON_FIXTURE,
                              repo="https://example.invalid/python-example", ref="", dockerfile="", builds=BUILDS,
                              fuzz_targets=["fuzz_example"], language="python")
        builder = check_build.build_builder(check_build.newest_toolchain("python"))
        check_build.build_project(job, "0" * 40, builder, PYTHON_TAG, cls.work)
        cls.raw = {}
        for build in BUILDS:
            cls.raw[build] = cls.work / "raw" / build
            check_build.compile_build(PYTHON_TAG, build, validate.BUILDS[build], cls.raw[build],
                                      labels=check_build.work_label(cls.work))
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, job.fuzz_targets)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", PYTHON_TAG], capture_output=True)

    def test_discovery(self):
        self.assertEqual((self.problems, self.missing, self.targets), ([], [], ["fuzz_example"]))

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
        runner = ('for b in plain ubsan asan asan-ubsan; do for c in /in/*; do '
                  'timeout 600 /qemu /bin2/fuzz_example.$b "$c" > /dev/null 2>&1; echo "$b ${c#/in/case-} $?"; done; '
                  'printf "%s " "$b printed"; timeout 600 /qemu /bin2/fuzz_example.$b /in/case-p | tr "\\n" ,; echo; '
                  'done')
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", PYTHON_TAG, "-c", runner],
            capture_output=True, text=True, check=True,
        )
        results = {tuple(line.split(" ", 2)[:2]): line.split(" ", 2)[2] for line in done.stdout.splitlines()}
        for case, status in PYTHON_EXPECTED.items():
            for build in BUILDS:
                with self.subTest(build=build, case=case):
                    self.assertEqual(results[(build, case or "empty")], str(status))
        for build in BUILDS:
            # The loud build writes what the harness prints, then the driver writes the return value.
            self.assertEqual(results[(build, "printed")], "printed,0,", build)


RUST_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "rust-example"
RUST_TAG = "oss-verify-test/rust-example:latest"
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
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="rust-example", directory=RUST_FIXTURE, repo="https://example.invalid/rust-example",
                              ref="", dockerfile="", builds=BUILDS, fuzz_targets=["example_fuzzer"], language="rust")
        builder = check_build.build_builder(check_build.newest_toolchain("rust"))
        check_build.build_project(job, "0" * 40, builder, RUST_TAG, cls.work)
        cls.raw = {}
        for build in BUILDS:
            cls.raw[build] = cls.work / "raw" / build
            check_build.compile_build(RUST_TAG, build, validate.BUILDS[build], cls.raw[build],
                                      labels=check_build.work_label(cls.work))
        found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(found, job.fuzz_targets)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", RUST_TAG], capture_output=True)

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
        # An AddressSanitizer detection in a Rust fuzz target takes minutes under qemu (about 160 s here), where a C
        # fuzz target's takes seconds: the time limit is 600 s.
        runner = ('for b in plain ubsan asan asan-ubsan; do for c in /in/*; do '
                  'timeout 600 /qemu /bin2/example_fuzzer.$b "$c" > /dev/null 2>&1; echo "$b ${c#/in/case-} $?"; done; '
                  'printf "%s " "$b printed"; timeout 60 /qemu /bin2/example_fuzzer.$b /in/case-r | tr "\\n" ,; echo; '
                  'done')
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", RUST_TAG, "-c", runner],
            capture_output=True, text=True, check=True,
        )
        results = {tuple(line.split(" ", 2)[:2]): line.split(" ", 2)[2] for line in done.stdout.splitlines()}
        for case, statuses in RUST_EXPECTED.items():
            for build, status in zip(BUILDS, statuses):
                with self.subTest(build=build, case=case):
                    self.assertEqual(results[(build, case or "empty")], str(status))
        for build in BUILDS:
            # The driver writes each return value: -1 for Corpus::Reject.
            self.assertEqual(results[(build, "printed")], "-1,", build)


GO_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "go-example"
GO_TAG = "oss-verify-test/go-example:latest"
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

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", GO_TAG], capture_output=True)

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
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", GO_TAG, "-c", runner],
            capture_output=True, text=True, check=True,
        )
        results = dict(line.split(" ", 1) for line in done.stdout.splitlines())
        for case, status in GO_EXPECTED.items():
            with self.subTest(case=case):
                self.assertEqual(results[f"case-{case or 'empty'}"], str(status))
        self.assertEqual(results["short"], "2")
        # The driver writes what Fuzz returned, for each call.
        self.assertEqual(results["printed"], "-1,")


CJSON = pathlib.Path(__file__).resolve().parent / "fixtures" / "cjson"
CJSON_TAG = "oss-verify-test/cjson:latest"
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
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="cjson", directory=CJSON, repo="https://github.com/DaveGamble/cJSON", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, CJSON_COMMIT, builder, CJSON_TAG, cls.work)
        raw = {}
        for build in BUILDS:
            raw[build] = cls.work / "raw" / build
            check_build.compile_build(CJSON_TAG, build, validate.BUILDS[build], raw[build],
                                      labels=check_build.work_label(cls.work))
        found = {build: manifest.discover(directory) for build, directory in raw.items()}
        cls.targets, _ = manifest.resolve_targets(found)
        cls.entries, _ = manifest.collect(raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", CJSON_TAG], capture_output=True)

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
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", CJSON_TAG, "-c", runner],
            capture_output=True, text=True, check=True,
        )
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


if __name__ == "__main__":
    unittest.main()
