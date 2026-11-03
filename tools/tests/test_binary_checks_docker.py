# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example with the link records of tools/check --checks, and check what the records and the
runs of the checks of the binaries give. Needs Docker and the toolchain image:

    OV_DOCKER_TESTS=1 python3 -m pytest tools/tests

The runs need qemu-riscv64-static on PATH; without it, they are skipped.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_binaries  # noqa: E402
import check_build  # noqa: E402
import check_links  # noqa: E402
import manifest  # noqa: E402
import validate  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = "oss-verify-test/example-records:latest"
QEMU = shutil.which("qemu-riscv64-static")
BUILDS = ["plain", "ubsan", "asan"]


def docker_ready():
    """Whether Docker runs and the pinned toolchain image is here."""
    try:
        return subprocess.run(["docker", "image", "inspect", check_build.newest_toolchain()],
                              capture_output=True).returncode == 0
    except OSError:
        return False


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class Records(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-records.")
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, TAG, cls.work)
        labels = check_build.work_label(cls.work)
        for kind, record in (("recorded", True), ("unrecorded", False)):
            for build in BUILDS:
                check_build.compile_build(TAG, build, validate.BUILDS[build], cls.work / kind / build, labels=labels,
                                          record=record)
        cls.raw = {build: cls.work / "recorded" / build for build in BUILDS}
        cls.targets, _ = manifest.resolve_targets({b: manifest.discover(d) for b, d in cls.raw.items()})
        cls.entries, _ = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

    def test_records_change_no_byte(self):
        for build in BUILDS:
            recorded = sorted(p.name for p in (self.work / "recorded" / build / ".stripped").iterdir())
            unrecorded = sorted(p.name for p in (self.work / "unrecorded" / build / ".stripped").iterdir())
            self.assertEqual(recorded, unrecorded, build)
            for name in recorded:
                self.assertEqual(manifest.sha256_of(self.work / "recorded" / build / ".stripped" / name),
                                 manifest.sha256_of(self.work / "unrecorded" / build / ".stripped" / name))
            self.assertFalse((self.work / "unrecorded" / build / ".records").exists())

    def test_every_fuzz_target_has_a_record_and_a_quiet_twin(self):
        for build in BUILDS:
            for target in self.targets:
                record, quiet = check_binaries.record_of(self.raw[build], target)
                self.assertIsInstance(record, check_links.Record, (build, target, record))
                self.assertIsNotNone(quiet, (build, target))
                self.assertTrue(any(path.endswith("/cli.o") for path in record.driver))

    def test_the_lists_and_the_instrumentation(self):
        # As check_binaries.binary_checks does: each build's compile records, read from its own $OUT.
        records = {build: check_binaries.record_of(self.raw[build], "example_fuzzer",
                                                   check_links.read_compiles(self.raw[build]))[0] for build in BUILDS}
        self.assertIsNotNone(records["ubsan"].compiles)
        wanted = {real for record in records.values() for real, _, _ in record.inputs.values()
                  if real.startswith("/opt/")}
        toolchain = check_build.newest_toolchain()
        image = check_binaries.image_hashes(toolchain, wanted, labels=[])
        results = check_links.analyse(records, image, check_binaries.dwarf_reader(toolchain, []))
        self.assertEqual(results["plain"]["instrumented"]["result"], "plain")
        for build in ("ubsan", "asan"):
            self.assertEqual(results[build]["instrumented"]["result"], "pass", results[build]["instrumented"])
        # The compile records that compile and record-compile wrote decide the fixture's own objects in the ubsan build.
        self.assertIn("by the compile that wrote them", results["ubsan"]["instrumented"]["detail"])
        kinds = {entry["kind"] for entry in results["asan"]["uninstrumented"]}
        self.assertTrue({"libc", "compiler-rt", "sanitizer-runtime"} <= kinds, kinds)
        self.assertNotIn("sanitizer-runtime", {entry["kind"] for entry in results["plain"]["uninstrumented"]})

    def test_dwarf_of_assembly(self):
        """The toolchain's clang writes no STT_FILE for an assembly source, only a DWARF unit in the assembler's
        language: check_links reads that unit to list hand-written assembly."""
        script = ('cd /tmp && printf ".globl f\\nf:\\n ret\\n" > x.S && clang --config=/opt/asan-static/musl.cfg '
                  '-march=rv64g -g -c x.S -o x.o && cat x.o')
        toolchain = check_build.newest_toolchain()
        data = subprocess.run(["docker", "run", "--rm", "--network=none", "--entrypoint", "sh", toolchain,
                               "-c", script], capture_output=True, check=True).stdout
        facts = check_links.object_facts(data)
        self.assertFalse(facts.compiled)
        unit = check_binaries.dwarf_reader(toolchain, [])([data])[0]
        self.assertEqual((unit[0], unit[1]), ("DW_LANG_Mips_Assembler", "x.S"), unit)

    @unittest.skipUnless(QEMU, "no qemu-riscv64-static on PATH")
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
            self.assertEqual([(results / f"l{n}.status").read_text().strip() for n in range(2)], ["0", "78"])
            self.assertTrue((results / "l0.out").read_text().strip() != "0", "the loud binary writes")
            agreement = check_binaries.quiet_loud(True, "", inputs, results)
            self.assertEqual(agreement["result"], "pass", agreement)
            trace = (results / "l0.trace").read_text()
            self.assertRegex(trace, r'openat\(AT_FDCWD,"input\.bin"')
            calls = (results / "l0.calls").read_text().split("\n")
            self.assertEqual(calls[0], "exec")
            mmaps = [line.split() for line in calls if line.startswith("mmap ")]
            self.assertTrue(mmaps, "the host-side log has no mmap")
            if build == "asan":
                # The AddressSanitizer runtime's shadow: a mapping of 4 GiB or more, which qemu's log cannot print.
                self.assertTrue(any(int(fields[3], 16) >= 1 << 32 for fields in mmaps), mmaps[:5])


if __name__ == "__main__":
    unittest.main()
