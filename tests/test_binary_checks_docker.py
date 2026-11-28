# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example with the link records of oss-verify check --checks, and check what the records and the
runs of the checks of the binaries give. Needs Docker and the toolchain image:

    OV_DOCKER_TESTS=1 uv run pytest

The runs need qemu-riscv64-static on PATH; without it, they are skipped.
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest

from oss_verify import check_binaries
from oss_verify import check_build
from oss_verify import check_links
from oss_verify import manifest
from test_builder import RUN, compile_builds, docker_ready

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = f"oss-verify-test/example-records:{RUN}"
QEMU = shutil.which("qemu-riscv64-static")
BUILDS = ["plain", "ubsan", "asan"]


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
