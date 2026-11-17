# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Run the asan-ubsan build of tests/fixtures/example on inputs that make it abort. Run it with the two scripts that run
fuzz targets for oss-verify check --checks: infra/checks/run-seeds (check_checks.run_all) and infra/checks/run-binaries
(check_binaries.run_job). Check that each run gives its own exit status, and that check 3 of the binary checks (quiet
and loud) counts an input on which the build aborts as agreed.

A run that aborts must give the status of its abort, 134. It must not give 137. 137 is the status of a run that the
time limit stopped, and such a run is neither a pass nor a catch. run-seeds and run-binaries write 0 to
/proc/self/coredump_filter, so a run's core dump holds no memory. Without that write, a core dump that could not end in
time made an abort read as 137.

Needs Docker, the newest C toolchain image, and qemu-riscv64-static on PATH:

    OV_DOCKER_TESTS=1 uv run pytest tests/test_seed_runs_docker.py
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from oss_verify import check_binaries
from oss_verify import check_build
from oss_verify import check_checks
from oss_verify import validate
from test_builder import docker_ready

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = "oss-verify-test/example-seed-runs:latest"
QEMU = shutil.which("qemu-riscv64-static")
BUILD = "asan-ubsan"
# The C fuzz target: tests/fixtures/example/build.sh links it to $OUT/example_fuzzer.
TARGET = "example_fuzzer"
# The time limit of each run here, in seconds, in place of check_checks.RUN_TIMEOUT and check_binaries.RUN_SECONDS.
# run-seeds and run-binaries write 0 to /proc/self/coredump_filter, so a run's core dump holds no memory. Without that
# write, the core dump of an aborting run did not end within this time on the CI runner: the runs on 'h' read 137 in
# theorem-labs/oss-verify's tests.yaml runs 44069641356 and 44070455751. With that write, an aborting run ends in less
# than a second: in OSSV-729's measurement on ubuntu-24.04-16core, the longest of 50 aborting runs took 0.86 s. The
# tests set this limit themselves, so a fix that only makes the limit longer still fails here. A short limit also keeps
# the tests fast.
LIMIT = 20
# Each input: its name, its payload after the driver's header, and the exit status of its run in the asan-ubsan build
# (tests/fixtures/example/example.c, and EXPECTED in tests/test_builder.py). The four that start with 'h' read one byte
# past the end of a heap block: AddressSanitizer finds it and calls abort(). run-seeds runs as many runs at once as
# the machine has CPUs, so with four CPUs or more these four run at the same time.
SEEDS = [
    ("h", b"h", 134),
    ("hh", b"hh", 134),
    ("hello", b"hello", 134),
    ("h and the bytes 0 to 63", b"h" + bytes(range(64)), 134),
    ("o", b"o", 132),  # a signed overflow: a UBSan trap
    ("s", b"s", 139),  # a load through a null pointer: a segmentation fault
    ("m", b"m", 0),  # the fuzz target returns -1, which passes
]


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and QEMU and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, and put qemu-riscv64-static on PATH, "
                     "to build and run the fixture")
class SeedRuns(unittest.TestCase):
    # unittest cuts a long diff by default. Show all of it, so that a failure shows the status of each input.
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-seed-runs.")
        cls.work = pathlib.Path(cls.scratch.name)
        cls.labels = check_build.work_label(cls.work)
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=[BUILD], fuzz_targets=None)
        check_build.build_project(job, "0" * 40, check_build.build_builder(), TAG, cls.work)
        cls.raw = cls.work / "raw" / BUILD
        # As oss-verify check --checks compiles: with records, so that compile also makes the quiet twin. The records
        # change no byte of the binary (tests/test_binary_checks_docker.py, test_records_change_no_byte).
        check_build.compile_build(TAG, BUILD, validate.BUILDS[BUILD], cls.raw, labels=cls.labels, record=True)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

    def setUp(self):
        # run_all and run_job read these when they start the runs.
        self.enterContext(mock.patch.object(check_checks, "RUN_TIMEOUT", LIMIT))
        self.enterContext(mock.patch.object(check_binaries, "RUN_SECONDS", LIMIT))

    def test_seed_runs_read_each_exit_status(self):
        inputs, results = self.work / "inputs", self.work / "results"
        (inputs / TARGET).mkdir(parents=True)
        for n, (_, payload, _) in enumerate(SEEDS):
            (inputs / TARGET / str(n)).write_bytes(check_checks.HEADER + payload)
        # As check_checks.checks does for its sanitizer build, the runs use the binary that compile wrote to $OUT.
        names = [name for name, _, _ in SEEDS]
        runs = check_checks.run_all(TAG, self.raw, inputs, {TARGET: names}, BUILD, results, labels=self.labels)
        self.assertEqual([run.seed for run in runs], names)
        # Compare the statuses of all inputs in one assertion, so that a failure shows the status of each input.
        texts = {name: (results / TARGET / f"{n}.status").read_text().strip() for n, (name, _, _) in enumerate(SEEDS)}
        self.assertEqual(texts, {name: str(expected) for name, _, expected in SEEDS},
                         f"{check_checks.KILLED} is the status of a run the time limit stopped")
        self.assertEqual({run.seed: run.status for run in runs}, {name: expected for name, _, expected in SEEDS})
        self.assertEqual({run.seed: run.caught() for run in runs}, {name: expected != 0 for name, _, expected in SEEDS})

    def test_binary_runs_read_each_exit_status(self):
        # The job's files as check_binaries.binary_checks lays them out. binary_checks runs the stripped copy that
        # compile publishes. Stripping removes no code, so the raw binary serves here. The quiet twin is the one that
        # compile recorded.
        job_dir = self.work / "binary-runs"
        files = job_dir / "job"
        (files / "inputs").mkdir(parents=True)
        shutil.copyfile(self.raw / TARGET, files / "binary")
        quiet = check_binaries.record_of(self.raw, TARGET)[1]
        self.assertIsNotNone(quiet, "compile recorded no quiet twin")
        (files / "quiet").write_bytes(quiet)
        os.chmod(files / "binary", 0o755)
        os.chmod(files / "quiet", 0o755)
        inputs = [("h", check_checks.HEADER + b"h"), ("m", check_checks.HEADER + b"m")]
        runs = []
        for n, (_, data) in enumerate(inputs):
            (files / "inputs" / str(n)).write_bytes(data)
            runs += [f"l{n} binary inputs/{n} {TARGET}", f"q{n} quiet inputs/{n} {TARGET}"]
        (files / "runs").write_text("".join(f"{run}\n" for run in runs))
        results = check_binaries.run_job(job_dir, check_build.newest_toolchain(), check_checks.qemu(), self.labels,
                                         600)
        loud = {name: (results / f"l{n}.status").read_text().strip() for n, (name, _) in enumerate(inputs)}
        self.assertEqual(loud, {"h": "134", "m": "0"},
                         f"{check_binaries.STOPPED} is the status of a run the time limit stopped")
        silent = {name: (results / f"q{n}.status").read_text().strip() for n, (name, _) in enumerate(inputs)}
        self.assertEqual(silent, loud, "the quiet twin must exit with the binary's status")
        # An ASan abort writes no report (docs/build-contract.md, the sealed AddressSanitizer runtime). Thus on 'h'
        # the binary and its quiet twin both exit 134, the twin writes nothing, and check 3 counts 'h' as agreed.
        agreement = check_binaries.quiet_loud(True, "", inputs, results)
        self.assertEqual(agreement,
                         {"result": "pass", "detail": "the same status on 2 inputs, and the quiet twin wrote nothing"})


if __name__ == "__main__":
    unittest.main()
