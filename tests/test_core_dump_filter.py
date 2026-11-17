# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""infra/checks/run-seeds and infra/checks/run-binaries give each run a core dump that holds no memory: the script's own
shell writes 0 to /proc/self/coredump_filter, and every process that it starts keeps that value. Without it, the core
dump of an ASan build's run holds its reserved address space of more than 100 GiB, and an abort can read as a run that
did not end within the time limit (docs/build-contract.md, "The checks of a fuzz target").

Each script runs in a container, as oss-verify check runs it, with a stand-in for qemu-riscv64 at /ovc-qemu. The
stand-in reports its own coredump_filter, the value that qemu would have, and exits 0 only when the value is 0. The
container's root is an image of a few symbolic links that this test makes with docker import, with the host's /usr
mounted read-only, so the test pulls no image, needs no qemu and reads no setting of the host's kernel.

Needs Docker on Linux, and a C compiler that links statically (run-binaries compiles its tracer with the host's cc).
The suite job of tests.yaml runs it; there a missing Docker is a failure, not a skip.
"""
import io
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKS = ROOT / "infra" / "checks"
TAG = "oss-verify-test/host-usr:latest"
ZERO = "00000000"
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


def docker_answers():
    try:
        return subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True).returncode == 0
    except OSError:
        return False


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


@unittest.skipUnless(sys.platform == "linux", "the containers run the host's /usr, which needs a Linux host")
class CoreDumpFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not docker_answers():
            message = "Docker does not answer: the test runs each script in a container"
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise AssertionError(message + ", and the runners of tests.yaml have Docker")
            raise unittest.SkipTest(message)
        archive, cls.mounts = host_root()
        subprocess.run(["docker", "import", "-", TAG], input=archive, capture_output=True, check=True)
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-core-dump-filter.")
        cls.work = pathlib.Path(cls.scratch.name)
        cls.stand_in = cls.work / "qemu"
        cls.stand_in.write_text(STAND_IN)
        cls.stand_in.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

    def run_script(self, script, mounts, *args):
        """Run infra/checks/<script> in a container of the image, as run_all and run_job run it (no network, --init,
        OV_OWNER), with the stand-in at /ovc-qemu and the host's /usr read-only."""
        volumes = [arg for host in self.mounts for arg in ("-v", f"{host}:{host}:ro")]
        volumes += [arg for host, container in ((self.stand_in, "/ovc-qemu:ro"), (CHECKS, "/ovc:ro"), *mounts)
                    for arg in ("-v", f"{host}:{container}")]
        done = subprocess.run(["docker", "run", "--rm", "--init", "--network=none", "-e",
                               f"OV_OWNER={os.getuid()}:{os.getgid()}", *volumes, "--entrypoint", f"/ovc/{script}",
                               TAG, *args], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, f"{script} exited {done.returncode}: {done.stderr}")

    def test_each_run_of_run_seeds_has_a_coredump_filter_of_0(self):
        bins, inputs, results = self.work / "bins", self.work / "inputs", self.work / "results"
        (inputs / "target").mkdir(parents=True)
        bins.mkdir()
        (bins / "target").write_bytes(b"")
        for n in range(4):
            (inputs / "target" / str(n)).write_bytes(b"\0" * 6 + bytes([n]))
        results.mkdir()
        # 4 runs at once, each with a time limit of 60 s, as run_all passes <jobs> <seconds>.
        self.run_script("run-seeds", ((bins, "/bins:ro"), (inputs, "/inputs:ro"), (results, "/results")), "4", "60")
        found = {n: ((results / "target" / f"{n}.filter").read_text().strip(),
                     (results / "target" / f"{n}.status").read_text().strip()) for n in range(4)}
        self.assertEqual(found, {n: (ZERO, "0") for n in range(4)}, "each run's (coredump_filter, exit status)")

    def test_each_run_of_run_binaries_has_a_coredump_filter_of_0(self):
        job, results = self.work / "job", self.work / "binary-results"
        (job / "inputs").mkdir(parents=True)
        (job / "binary").write_bytes(b"")
        for n in range(2):
            (job / "inputs" / str(n)).write_bytes(b"\0" * 6 + bytes([n]))
        (job / "runs").write_text("".join(f"l{n} binary inputs/{n} target\n" for n in range(2)))
        results.mkdir()
        # A time limit of 60 s a run and 120 s in all, as run_job passes <seconds> <total>.
        self.run_script("run-binaries", ((job, "/job:ro"), (results, "/results")), "60", "120")
        found = {n: ((results / f"l{n}.trace").read_text().strip(), (results / f"l{n}.status").read_text().strip())
                 for n in range(2)}
        self.assertEqual(found, {n: (ZERO, "0") for n in range(2)}, "each run's (coredump_filter, exit status)")


if __name__ == "__main__":
    unittest.main()
