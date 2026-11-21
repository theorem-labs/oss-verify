# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The settings that the build of one fuzz target can give, tested on the host:
uv run pytest tests/test_target_settings.py

OV_MAX_INPUT_LOG2: the host's cc compiles the driver (infra/base-builder/driver/cli.c and adapter.c) with a harness
that returns 0, with and without -DOV_MAX_INPUT_LOG2. The driver then runs on files of zeros, one byte below its limit
and at its limit. A file of zeros is a valid input: its config word is 0 and its allocation mask is 0. The files are
sparse, so they use no disk space."""
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = ROOT / "infra/base-builder/driver"
HARNESS = ("#include <stddef.h>\n#include <stdint.h>\n"
           "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }\n")
LIMIT_ERROR = "OV_MAX_INPUT_LOG2 must be 27, 28, 29, 30 or 31"


@pytest.fixture
def build(tmp_path):
    """build(<defines>): cc -c of cli.c with the defines, into tmp_path. When that compile succeeds, it links cli.o
    with adapter.c and the harness into tmp_path/driver. It returns the result of the compile of cli.c."""
    if shutil.which("cc") is None:
        pytest.skip("a native C compiler (cc) is required")
    (tmp_path / "harness.c").write_text(HARNESS)

    def run(*args):
        return subprocess.run(["cc", "-O0", "-I", str(DRIVER), *args], cwd=tmp_path, capture_output=True, text=True,
                              timeout=60)

    def compile_driver(*defines):
        compiled = run(*defines, "-c", str(DRIVER / "cli.c"), "-o", "cli.o")
        if compiled.returncode == 0:
            linked = run("cli.o", str(DRIVER / "adapter.c"), "harness.c", "-o", "driver")
            assert linked.returncode == 0, linked.stderr
        return compiled

    return compile_driver


@pytest.mark.parametrize("defines, limit", [((), 1 << 26), (("-DOV_MAX_INPUT_LOG2=27",), 1 << 27)],
                         ids=["default", "27"])
def test_the_driver_refuses_an_input_at_its_limit(build, tmp_path, defines, limit):
    """With no define, the driver runs the target on an input of 2^26 - 1 bytes (status 0) and refuses one of 2^26
    bytes, 64 MiB (status 2). With -DOV_MAX_INPUT_LOG2=27, the same at 2^27 bytes."""
    compiled = build(*defines)
    assert compiled.returncode == 0, compiled.stderr
    for size, status in ((limit - 1, 0), (limit, 2)):
        zeros = tmp_path / f"zeros-{size}"
        zeros.touch()
        os.truncate(zeros, size)
        done = subprocess.run([str(tmp_path / "driver"), str(zeros)], capture_output=True, text=True, timeout=300)
        zeros.unlink()
        assert done.returncode == status, (size, done.stderr)
        assert (f"cli: input >= {limit} bytes, refused" in done.stderr) == (status == 2), (size, done.stderr)


@pytest.mark.parametrize("value", ["26", "32"])
def test_a_limit_outside_27_to_31_does_not_compile(build, value):
    """cli.c does not compile with OV_MAX_INPUT_LOG2 below 27 or above 31, and the compiler prints input_limit.h's
    #error."""
    compiled = build(f"-DOV_MAX_INPUT_LOG2={value}")
    assert compiled.returncode != 0
    assert LIMIT_ERROR in compiled.stderr, compiled.stderr
