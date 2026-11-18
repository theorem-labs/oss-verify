# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""infra/checks/run-seeds and infra/checks/run-binaries give each run a core dump that holds no memory: the script's own
shell writes 0 to /proc/self/coredump_filter, and every process that it starts keeps that value. Without it, the core
dump of an ASan build's run holds its reserved address space of more than 100 GiB, and an abort can read as a run that
did not end within the time limit (docs/build-contract.md, "The checks of a fuzz target").

The test calls check_checks.run_all and check_binaries.run_job, which run each script in a container, with a stand-in
for qemu-riscv64 at /ovc-qemu. The stand-in reports its own coredump_filter, the value that qemu would have, and exits 0
only when the value is 0. The container's root is an image of a few symbolic links that this test makes with docker
import, with the host's /usr mounted read-only, so the test pulls no image and needs no qemu.

A control reads the coredump_filter that a process of the same container setup starts with, with no script around it.
Linux starts processes with 0x33. Where they start with 0 (under gVisor, for one), the scripts' runs would read 0 with
or without the write, so the test fails there and says so. A pass thus means that the scripts wrote the 0.

Needs Docker on an x86-64 Linux host, and a cc that links statically: run-binaries compiles its tracer with the host's
cc, and the tracer reads x86-64 registers. Without them the test is skipped, except in the suite job of tests.yaml,
whose runner has them: there a missing one is a failure.
"""
import io
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from oss_verify import check_binaries
from oss_verify import check_checks

TAG = "oss-verify-test/host-usr:latest"
ZERO = "00000000"
NO_FAULT = "this host starts processes with coredump_filter 0, so this test cannot show the fix"
# The stand-in for qemu-riscv64. run-seeds runs it as /ovc-qemu /bins/<target> /inputs/<target>/<n>, as root, and it
# writes its coredump_filter to /results/<target>/<n>.filter. run-binaries runs it as user 65534, as
# /ovc-qemu -0 <name> -strace -D /ovt/trace /job/<binary> input.bin, and it writes the value to its trace, which
# run-binaries copies to /results/<id>.trace. `read` is a builtin, so /proc/self is this process, as it would be qemu.
STAND_IN = r"""#!/bin/sh
read filter < /proc/self/coredump_filter || exit 125
case $1 in
  /bins/*) printf '%s\n' "$filter" > "/results/${2#/inputs/}.filter" ;;
  -0) printf '%s\n' "$filter" > "$5" ;;
  *) exit 126 ;;
esac
[ "$filter" = 00000000 ]
"""
# The control: the shell that docker-init starts reads its own coredump_filter, with no script around it.
CONTROL = 'read filter < /proc/self/coredump_filter && printf "%s\\n" "$filter"'


def docker_answers():
    try:
        return subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True).returncode == 0
    except OSError:
        return False


def cc_links_statically():
    """Whether the host's cc links a static program, as run-binaries does with the host's /usr."""
    if not shutil.which("cc"):
        return False
    with tempfile.TemporaryDirectory(prefix="ov-test-cc.") as scratch:
        source = pathlib.Path(scratch) / "empty.c"
        source.write_text("int main(void) { return 0; }\n")
        return subprocess.run(["cc", "-static", "-o", str(source.with_suffix("")), str(source)],
                              capture_output=True).returncode == 0


def host_root():
    """The image's files, as a tar archive: the host's top-level links into /usr (bin -> usr/bin and the like), an
    /etc with the host's ld.so.cache and the links of /etc/alternatives (cc is one: /usr/bin/cc links to it), and /tmp
    and /var/tmp. /sbin is an empty directory of the image, so that docker run --init can put its docker-init there,
    beside a read-only /usr. Return (the archive, the host's top-level directories that are not links into /usr, which
    the container mounts read-only too)."""
    data, mounts = io.BytesIO(), ["/usr"]
    with tarfile.open(fileobj=data, mode="w") as archive:
        def add(name, kind, mode, target=""):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.linkname = kind, mode, target
            archive.addfile(info)
        for name in ("bin", "lib", "lib32", "lib64", "libx32"):
            path = pathlib.Path("/") / name
            if path.is_symlink():
                add(name, tarfile.SYMTYPE, 0o777, os.readlink(path))
            elif path.is_dir():
                mounts.append(str(path))
        for name, mode in (("etc", 0o755), ("sbin", 0o755), ("tmp", 0o1777), ("var", 0o755), ("var/tmp", 0o1777)):
            add(name, tarfile.DIRTYPE, mode)
        alternatives = pathlib.Path("/etc/alternatives")
        if alternatives.is_dir():
            add("etc/alternatives", tarfile.DIRTYPE, 0o755)
            for link in sorted(alternatives.iterdir()):
                if link.is_symlink():
                    add(f"etc/alternatives/{link.name}", tarfile.SYMTYPE, 0o777, os.readlink(link))
        cache = pathlib.Path("/etc/ld.so.cache")
        if cache.is_file():
            info = tarfile.TarInfo("etc/ld.so.cache")
            info.size, info.mode = cache.stat().st_size, 0o644
            archive.addfile(info, io.BytesIO(cache.read_bytes()))
    return data.getvalue(), mounts


class CoreDumpFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        needs = (("an x86-64 Linux host (the containers run the host's /usr, and infra/checks/host-calls.c reads "
                  "x86-64 registers)", sys.platform == "linux" and platform.machine() == "x86_64"),
                 ("Docker", docker_answers()),
                 ("a cc that links statically (run-binaries compiles its tracer with it)", cc_links_statically()))
        missing = [need for need, met in needs if not met]
        if missing:
            message = "the test needs " + " and ".join(missing)
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise AssertionError(message + ", which the runners of tests.yaml have")
            raise unittest.SkipTest(message)
        archive, mounts = host_root()
        imported = subprocess.run(["docker", "import", "-", TAG], input=archive, capture_output=True)
        if imported.returncode != 0:
            raise AssertionError(f"docker import exited {imported.returncode}: "
                                 f"{imported.stderr.decode(errors='replace')}")
        # docker run arguments that run_all and run_job put before their own: never pull the tag from a registry,
        # and the host's /usr (and any top-level directory that is not a link into it) read-only.
        cls.labels = ["--pull=never", *(arg for host in mounts for arg in ("-v", f"{host}:{host}:ro"))]
        cls.control = subprocess.run(["docker", "run", "--rm", "--init", "--network=none", *cls.labels, "--entrypoint",
                                      "/bin/sh", TAG, "-c", CONTROL], capture_output=True, text=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-core-dump-filter.")
        cls.work = pathlib.Path(cls.scratch.name)
        cls.stand_in = cls.work / "qemu"
        cls.stand_in.write_text(STAND_IN)
        cls.stand_in.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

    def setUp(self):
        if self.control.returncode != 0:
            self.fail(f"the control's docker run exited {self.control.returncode}: {self.control.stderr}")
        start = self.control.stdout.strip()
        self.assertRegex(start, r"^[0-9a-f]{8}$", "the control printed no coredump_filter")
        self.assertNotEqual(start, ZERO, NO_FAULT)

    # run_all and run_job drop the container's own output (check_build.run(..., quiet=True)), and raise Failed when
    # the script exits with a status other than 0. The test reads what each run of the stand-in wrote.
    def test_each_run_of_run_seeds_has_a_coredump_filter_of_0(self):
        bins, inputs, results = self.work / "bins", self.work / "inputs", self.work / "results"
        (inputs / "target").mkdir(parents=True)
        bins.mkdir()
        (bins / "target").write_bytes(b"")
        for n in range(4):
            (inputs / "target" / str(n)).write_bytes(check_checks.HEADER + bytes([n]))
        with mock.patch.object(check_checks, "qemu", return_value=self.stand_in):
            runs = check_checks.run_all(TAG, bins, inputs, {"target": [f"input {n}" for n in range(4)]}, "stand-in",
                                        results, labels=self.labels)
        found = {run.index: ((results / "target" / f"{run.index}.filter").read_text().strip(), run.status)
                 for run in runs}
        self.assertEqual(found, {n: (ZERO, 0) for n in range(4)}, "each run's (coredump_filter, exit status)")

    def test_each_run_of_run_binaries_has_a_coredump_filter_of_0(self):
        job_dir = self.work / "binary-job"
        job = job_dir / "job"
        (job / "inputs").mkdir(parents=True)
        (job / "binary").write_bytes(b"")
        for n in range(2):
            (job / "inputs" / str(n)).write_bytes(check_checks.HEADER + bytes([n]))
        (job / "runs").write_text("".join(f"l{n} binary inputs/{n} target\n" for n in range(2)))
        results = check_binaries.run_job(job_dir, TAG, self.stand_in, self.labels, 120)
        found = {n: ((results / f"l{n}.trace").read_text().strip(), (results / f"l{n}.status").read_text().strip())
                 for n in range(2)}
        self.assertEqual(found, {n: (ZERO, "0") for n in range(2)}, "each run's (coredump_filter, exit status)")


if __name__ == "__main__":
    unittest.main()
