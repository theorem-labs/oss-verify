# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Run the asan-ubsan build of tests/fixtures/example on inputs that make it abort. Run it with the two scripts that run
fuzz targets for oss-verify check --checks: infra/checks/run-seeds (check_checks.run_all) and infra/checks/run-binaries
(check_binaries.run_job). Check that each run gives its own exit status.

A run that aborts must give the status of its abort, 134. It must not give 137. 137 is the status of a run that the
time limit stopped, and such a run is neither a pass nor a catch. Before the fix, a core dump that could not end in time
made an abort read as 137.

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

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = "oss-verify-test/example-seed-runs:latest"
QEMU = shutil.which("qemu-riscv64-static")
BUILD = "asan-ubsan"
# The C fuzz target: tests/fixtures/example/build.sh links it to $OUT/example_fuzzer.
TARGET = "example_fuzzer"
# The time limit of each run here, in seconds, in place of check_checks.RUN_TIMEOUT and check_binaries.RUN_SECONDS.
# Before the fix, the core dump of an aborting run did not end within this time on the CI runner: the runs on 'h' read
# 137 in theorem-labs/oss-verify's tests.yaml runs 44069641356 and 44070455751. With the fix, an aborting run ends in
# less than a second: in OSSV-729's measurement on ubuntu-24.04-16core, the longest of 50 aborting runs took 0.86 s.
# The tests set this limit themselves, so a fix that only makes the limit longer still fails here. A short limit also
# keeps the tests fast.
LIMIT = 20
# Each input: its name, its payload after the driver's header, and the exit status of its run in the asan-ubsan build
# (tests/fixtures/example/example.c, and EXPECTED in tests/test_builder.py). The four that start with 'h' read one byte
# past the end of a heap block: AddressSanitizer reports it and calls abort(). run-seeds runs as many runs at once as
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


def docker_ready():
    """Whether Docker runs and the toolchain image the fixture builds FROM (the newest for C) is here."""
    try:
        return subprocess.run(["docker", "image", "inspect", check_build.newest_toolchain()],
                              capture_output=True).returncode == 0
    except OSError:
        return False


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and QEMU and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, and put qemu-riscv64-static on PATH, "
                     "to build and run the fixture")
class SeedRuns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-seed-runs.")
        cls.work = pathlib.Path(cls.scratch.name)
        cls.labels = check_build.work_label(cls.work)
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=[BUILD], fuzz_targets=None)
        check_build.build_project(job, "0" * 40, check_build.build_builder(), TAG, cls.work)
        cls.raw = cls.work / "raw" / BUILD
        check_build.compile_build(TAG, BUILD, validate.BUILDS[BUILD], cls.raw, labels=cls.labels)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

    def setUp(self):
        # run_all and run_job read these when they start the runs.
        self.enterContext(mock.patch.object(check_checks, "RUN_TIMEOUT", LIMIT))
        self.enterContext(mock.patch.object(check_binaries, "RUN_SECONDS", LIMIT))

    def test_seed_runs_read_each_exit_status(self):
        inputs, binaries, results = self.work / "inputs", self.work / "binaries", self.work / "results"
        (inputs / TARGET).mkdir(parents=True)
        for n, (_, payload, _) in enumerate(SEEDS):
            (inputs / TARGET / str(n)).write_bytes(check_checks.HEADER + payload)
        # As check_checks.checks does for its sanitizer build, the runs use the binary that compile wrote to $OUT.
        binaries.mkdir()
        shutil.copy(self.raw / TARGET, binaries / TARGET)
        names = [name for name, _, _ in SEEDS]
        runs = check_checks.run_all(TAG, binaries, inputs, {TARGET: names}, BUILD, results, labels=self.labels)
        self.assertEqual([run.seed for run in runs], names)
        for n, (run, (name, _, expected)) in enumerate(zip(runs, SEEDS)):
            with self.subTest(seed=name):
                text = (results / TARGET / f"{n}.status").read_text().strip()
                self.assertEqual(text, str(expected),
                                 f"the run on {name!r}: {check_checks.KILLED} is the status of a run the time limit "
                                 "stopped")
                self.assertEqual(run.status, expected, name)
                self.assertEqual(run.caught(), expected != 0, name)

    def test_binary_runs_read_each_exit_status(self):
        # The job's files as check_binaries.binary_checks lays them out. binary_checks runs the stripped copy that
        # compile publishes. Stripping removes no code, so the raw binary serves here.
        job_dir = self.work / "binary-runs"
        files = job_dir / "job"
        (files / "inputs").mkdir(parents=True)
        shutil.copyfile(self.raw / TARGET, files / "binary")
        os.chmod(files / "binary", 0o755)
        (files / "inputs" / "0").write_bytes(check_checks.HEADER + b"h")
        (files / "inputs" / "1").write_bytes(check_checks.HEADER + b"m")
        (files / "runs").write_text(f"l0 binary inputs/0 {TARGET}\nl1 binary inputs/1 {TARGET}\n")
        results = check_binaries.run_job(job_dir, check_build.newest_toolchain(), check_checks.qemu(), self.labels,
                                         600)
        self.assertEqual((results / "l0.status").read_text().strip(), "134",
                         f"the run on 'h': {check_binaries.STOPPED} is the status of a run the time limit stopped")
        self.assertEqual((results / "l1.status").read_text().strip(), "0", "the run on 'm'")


if __name__ == "__main__":
    unittest.main()
