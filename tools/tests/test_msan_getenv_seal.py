# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Native tests of the msan build's getenv seal (driver/msan_getenv.c) at the real linker boundary.

The MemorySanitizer runtime wraps getenv itself (--wrap=getenv in its wrap list). A stand-in runtime does the same
here: a __wrap_getenv that calls __real_getenv, linked by a compiler script with -Wl,--wrap=getenv, as the msan
configuration links the runtime. link-fuzz-target is unchanged except for its scratch directory, and link.env holds
the seals that compile writes for the msan build. These tests need a native C compiler with a GNU-style linker
(Linux), and no Docker or target toolchain.
"""
import os
import pathlib
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / "infra/base-builder/driver"
LINKER = ROOT / "infra/base-builder/link-fuzz-target"
# compile's OV_SEALS in the msan build.
SEALS = ("msan_getenv.o wrap_mkstemp.o -Wl,--wrap=mkstemp -Wl,--wrap=mkostemp -Wl,--wrap=mkstemps "
         "-Wl,--wrap=mkostemps wrap_getpid.o -Wl,--wrap=getpid -Wl,--wrap=getppid")


@pytest.fixture
def msan_link(tmp_path):
    if shutil.which("cc") is None:
        pytest.skip("a native C compiler is required")
    if not sys.platform.startswith("linux"):
        pytest.skip("the links take GNU ld's flags (--gc-sections, --wrap), which this platform's linker does not")
    common = ["cc", "-O0", "-ffunction-sections", "-fdata-sections", "-I", str(DRIVER)]

    def run(*args):
        done = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert done.returncode == 0, done.stderr
        return done

    for name in ("cli", "adapter", "msan_options", "msan_getenv", "wrap_mkstemp", "wrap_getpid"):
        run(*common, "-c", str(DRIVER / f"{name}.c"), "-o", f"{name}.o")
    # The runtime's interceptor calls the real getenv, which the seal defines. The fuzz target returns 0 only when
    # getenv went through the interceptor and gave NULL, and 1 (status 78) otherwise.
    (tmp_path / "runtime.c").write_text(
        'int stand_in_calls;\n'
        'char *__real_getenv(const char *name);\n'
        'char *__wrap_getenv(const char *name) { stand_in_calls++; return __real_getenv(name); }\n')
    (tmp_path / "fuzzer.c").write_text(
        '#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n'
        'extern int stand_in_calls;\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '  int before = stand_in_calls;\n'
        '  (void)data; (void)size;\n'
        '  return getenv("OV_SEAL_PROBE") == NULL && stand_in_calls == before + 1 ? 0 : 1;\n}\n')
    run(*common, "-c", "runtime.c", "-o", "runtime.o")
    run(*common, "-c", "fuzzer.c", "-o", "fuzzer.o")
    compiler = tmp_path / "msan-cc"
    compiler.write_text(f'#!/bin/sh\nexec cc "$@" {tmp_path}/runtime.o -Wl,--wrap=getenv\n')
    compiler.chmod(0o755)
    twins = tmp_path / "twins"
    twins.mkdir()
    scratch = tmp_path / "ov"
    scratch.mkdir()
    script = tmp_path / "link-fuzz-target"
    script.write_text(LINKER.read_text().replace("/tmp/ov/", f"{scratch}/"))
    script.chmod(0o755)

    def link(*args, seals=SEALS):
        (scratch / "link.env").write_text(
            "OV_LFE='normal-engine'\nOV_DRIVER='cli.o msan_options.o adapter.o'\nOV_CLI='cli.o msan_options.o'\n"
            "OV_AFE='failure-engine'\nOV_AFC='counting-engine'\nOV_AF_DRIVER=''\nOV_AFC_DRIVER=''\nOV_AF_RENAME=''\n"
            f"OV_SEALS='{seals}'\nOV_SILENT_LD=''\nOV_TWINS='{twins}'\n")
        return subprocess.run([str(script), str(compiler), "fuzzer.o", "normal-engine", *args, "-o", "target"],
                              cwd=tmp_path, capture_output=True, text=True, timeout=30)

    def target(*args, seals=SEALS):
        linked = link(*args, seals=seals)
        assert linked.returncode == 0, linked.stderr
        (tmp_path / "input").write_bytes(bytes(6))
        return subprocess.run([str(tmp_path / "target"), str(tmp_path / "input")], cwd=tmp_path,
                              env={**os.environ, "OV_SEAL_PROBE": "set"}, capture_output=True, text=True, timeout=30)

    return SimpleNamespace(link=link, target=target)


def test_getenv_returns_null_through_the_runtime_wrapper(msan_link):
    assert msan_link.target().returncode == 0
    # Without the seal, the wrapper reaches the C library's getenv, which reads the environment.
    assert msan_link.target(seals="").returncode == 78


def test_a_link_that_wraps_getenv_itself_gets_no_second_seal(msan_link):
    # oft_seal_getenv's form in the msan build (recipes.sh): the seal and the flag that repeats the wrap list's.
    assert msan_link.target("msan_getenv.o", "-Wl,--wrap=getenv").returncode == 0
    # Without the flag, link-fuzz-target adds its own seal, and two objects define getenv.
    linked = msan_link.link("msan_getenv.o")
    assert linked.returncode != 0
    assert "getenv" in linked.stderr
