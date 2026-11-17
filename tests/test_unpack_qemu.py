# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/unpack-qemu, offline, with stand-ins for curl, sha256sum and dpkg-deb:  uv run pytest

They check what the script's header says. On success, the one line on standard output is the absolute path of
DIR/usr/bin, and there qemu-riscv64-static links to qemu-riscv64. A download that fails, a wrong SHA-256, a qemu that
does not say version 10.0.11, or a DIR that exists, exits non-zero, with nothing on standard output.
"""
import os
import pathlib
import shlex
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "unpack-qemu"
GOOD = "qemu-riscv64 version 10.0.11 (Debian 1:10.0.11+ds-0+deb13u1)"
# Each stand-in adds a line to $STUB/calls: its name and its arguments.
# curl writes a placeholder package to the file after -o. With $CURL_FAILS, it fails as on a missing file (exit 22).
STUB_CURL = r"""#!/bin/sh
echo "curl $*" >> "$STUB/calls"
if [ -n "${CURL_FAILS:-}" ]; then echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; fi
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then out=$2; fi
  shift
done
echo "not a real package" > "$out"
"""
# sha256sum -c reads "<SHA-256>  <file>" from standard input. With $SHA256_MISMATCH, or for a file that is not there, it
# fails as the real one does: "<file>: FAILED" on standard output.
STUB_SHA256SUM = r"""#!/bin/sh
read -r sha file
echo "sha256sum $* $sha $file" >> "$STUB/calls"
if [ -n "${SHA256_MISMATCH:-}" ] || [ ! -f "$file" ]; then
  echo "$file: FAILED"
  echo "sha256sum: WARNING: 1 computed checksum did NOT match" >&2
  exit 1
fi
"""
# dpkg-deb -x <package> <directory> puts $STUB/qemu-riscv64 at <directory>/usr/bin/qemu-riscv64.
STUB_DPKG_DEB = r"""#!/bin/sh
echo "dpkg-deb $*" >> "$STUB/calls"
if [ "$1" != -x ] || [ ! -f "$2" ]; then echo "dpkg-deb: error: cannot unpack" >&2; exit 2; fi
mkdir -p "$3/usr/bin"
cp "$STUB/qemu-riscv64" "$3/usr/bin/qemu-riscv64"
"""


def unpack(tmp_path, version=GOOD, **env):
    """Run unpack-qemu on qemu, a path relative to tmp_path, with the stand-ins first on PATH. The unpacked
    qemu-riscv64 prints `version` and a Copyright line for --version. `env` sets CURL_FAILS or SHA256_MISMATCH. Return
    the run and the lines of $STUB/calls."""
    bin = tmp_path / "bin"
    stub = tmp_path / "stub"
    bin.mkdir()
    stub.mkdir()
    qemu = ('#!/bin/sh\n[ "$1" = --version ] || exit 2\n'
            f"printf '%s\\n' {shlex.quote(version)} "
            "'Copyright (c) 2003-2025 Fabrice Bellard and the QEMU Project developers'\n")
    for path, text in ((bin / "curl", STUB_CURL), (bin / "sha256sum", STUB_SHA256SUM),
                       (bin / "dpkg-deb", STUB_DPKG_DEB), (stub / "qemu-riscv64", qemu)):
        path.write_text(text)
        path.chmod(0o755)
    run = subprocess.run([str(SCRIPT), "qemu"], cwd=tmp_path, capture_output=True, text=True,
                         env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "STUB": str(stub), **env})
    calls = stub / "calls"
    return run, calls.read_text().splitlines() if calls.exists() else []


def test_it_prints_the_absolute_directory_where_qemu_riscv64_static_links_to_qemu_riscv64(tmp_path):
    run, _ = unpack(tmp_path)
    assert run.returncode == 0, run.stderr
    directory = tmp_path.resolve() / "qemu" / "usr" / "bin"
    assert run.stdout == f"{directory}\n"
    assert (directory / "qemu-riscv64-static").is_symlink()
    assert os.readlink(directory / "qemu-riscv64-static") == "qemu-riscv64"


def test_a_wrong_sha256_exits_non_zero_with_nothing_on_standard_output_and_nothing_unpacked(tmp_path):
    # The stand-in writes "<file>: FAILED" to standard output, as sha256sum -c does.
    run, calls = unpack(tmp_path, SHA256_MISMATCH="1")
    assert run.returncode != 0
    assert run.stdout == ""
    assert not [call for call in calls if call.startswith("dpkg-deb ")], calls


@pytest.mark.parametrize("version", ["qemu-riscv64 version 10.0.1", "qemu-riscv64 version 10.0.110",
                                     "qemu-riscv64 version 10.0.11a"])
def test_a_qemu_that_does_not_say_version_10_0_11_exits_non_zero_with_nothing_on_standard_output(tmp_path, version):
    run, _ = unpack(tmp_path, version)
    assert run.returncode != 0, run.stdout
    assert run.stdout == ""


def test_a_download_that_fails_exits_non_zero_with_nothing_on_standard_output(tmp_path):
    run, _ = unpack(tmp_path, CURL_FAILS="1")
    assert run.returncode != 0
    assert run.stdout == ""


def test_a_directory_that_exists_exits_non_zero_before_the_download(tmp_path):
    (tmp_path / "qemu").mkdir()
    run, calls = unpack(tmp_path)
    assert run.returncode != 0
    assert run.stdout == ""
    assert not [call for call in calls if call.startswith("curl ")], calls
