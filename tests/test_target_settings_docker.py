# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/target-settings in the four builds, with the link records of oss-verify check --checks, and
check the settings of one fuzz target: the driver objects of the input limits, the records of the links and the input
limit of the binaries. Needs Docker and the toolchain image:

    OV_DOCKER_TESTS=1 uv run pytest tests/test_target_settings_docker.py

The runs of the binaries need qemu-riscv64-static on PATH; without it, they are skipped.
"""
import os
import pathlib
import shutil
import subprocess

import pytest

from oss_verify import check_binaries
from oss_verify import check_build
from oss_verify import check_links
from oss_verify import validate
from test_builder import RUN, compile_builds, docker_ready, each_build_at_once

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "target-settings"
TAG = f"oss-verify-test/target-settings:{RUN}"
QEMU = shutil.which("qemu-riscv64-static")
BUILDS = list(validate.BUILDS)
LIMITS = range(27, 32)
# The runs of the binaries: (fuzz target, bytes of the input, exit status). An input is a file of zeros. The driver of
# limit_fuzzer and of limit_af_fuzzer refuses an input of 2^29 bytes or more (OV_MAX_INPUT_LOG2=29), and that of
# none_fuzzer refuses one of 2^26 bytes or more (no setting). A refusal is exit status 2.
RUNS = [("limit_fuzzer", (1 << 29) - 1, 0), ("limit_fuzzer", 1 << 29, 2), ("limit_af_fuzzer", (1 << 29) - 1, 0),
        ("limit_af_fuzzer", 1 << 29, 2), ("none_fuzzer", 1 << 26, 2)]


@pytest.mark.skipif(os.environ.get("OV_DOCKER_TESTS") != "1" or not docker_ready(),
                    reason="set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class TestTargetSettings:
    @pytest.fixture(scope="class", autouse=True)
    def set_up_class(self, request, tmp_path_factory):
        cls = request.cls
        work = tmp_path_factory.mktemp("ov-test-target-settings")
        # A finalizer runs when this fixture fails too, so a failed build removes this process's image as well.
        request.addfinalizer(lambda: subprocess.run(["docker", "image", "rm", TAG], capture_output=True))
        job = check_build.Job(name="target-settings", directory=FIXTURE,
                              repo="https://example.invalid/target-settings", ref="", dockerfile="", builds=BUILDS,
                              fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, TAG, work)
        labels = check_build.work_label(work)
        cls.raw = {build: work / build for build in BUILDS}
        compile_builds(TAG, cls.raw, labels, record=True)

    def record(self, build, target):
        """The record of the link of `target` in `build` (check_binaries.record_of), checked to be a whole record."""
        record, _ = check_binaries.record_of(self.raw[build], target)
        assert isinstance(record, check_links.Record), (build, target, record)
        return record

    def test_the_driver_objects_of_each_input_limit(self):
        """The driver objects that compile made before build.sh ran (build.sh copies them to $OUT/driver-objects): in
        each build, cli-limit<k>.o and cli-limit<k>-quiet.o for k = 27 to 31, and no other limit object. Each
        cli-limit<k>.o has other bytes than cli.o."""
        names = sorted(f"cli-limit{k}{suffix}.o" for k in LIMITS for suffix in ("", "-quiet"))
        for build in BUILDS:
            objects = self.raw[build] / "driver-objects"
            assert sorted(path.name for path in objects.glob("cli-limit*")) == names, build
            cli = (objects / "cli.o").read_bytes()
            for k in LIMITS:
                assert (objects / f"cli-limit{k}.o").read_bytes() != cli, (build, k)

    def test_the_records_of_the_settings(self):
        """In each build, the driver file of the record of limit_fuzzer and of limit_af_fuzzer names
        /tmp/ov/cli-limit29.o. The record of libc_fuzzer has a libc file of four rows, one for each file of the
        C library that its block declares (OV_LIBC). The records of none_fuzzer and undeclared_fuzzer have no libc
        file."""
        for build in BUILDS:
            for target in ("limit_fuzzer", "limit_af_fuzzer"):
                assert "/tmp/ov/cli-limit29.o" in self.record(build, target).driver, (build, target)
            assert sorted(self.record(build, "libc_fuzzer").libc) == sorted(check_links.DECLARED_LIBC), build
            for target in ("none_fuzzer", "undeclared_fuzzer"):
                assert self.record(build, target).libc == {}, (build, target)

    @pytest.mark.skipif(not QEMU, reason="no qemu-riscv64-static on PATH")
    def test_the_input_limit_of_the_binaries(self, tmp_path):
        """In each build, each run of RUNS ends with its exit status. The inputs are sparse files, so they use no disk
        space."""
        for size in {size for _, size, _ in RUNS}:
            zeros = tmp_path / f"zeros-{size}"
            zeros.touch()
            os.truncate(zeros, size)
        runner = "".join(f'timeout 600 /qemu /raw/$B/{target} /in/zeros-{size} > /dev/null 2>&1; '
                         f'echo "$B {target} {size} $?"\n' for target, size, _ in RUNS)
        output = each_build_at_once(check_build.newest_toolchain(), runner, BUILDS, (tmp_path, "/in"),
                                    *((self.raw[build], f"/raw/{build}") for build in BUILDS))
        results = {tuple(line.split()[:3]): int(line.split()[3]) for line in output.splitlines()}
        assert results == {(build, target, str(size)): status for build in BUILDS for target, size, status in RUNS}
