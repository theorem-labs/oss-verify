# Copyright 2026 Arunim Shukla
# SPDX-License-Identifier: Apache-2.0
"""Native reproductions of allocation-failure coverage at the real linker boundary.

The linker script is unchanged except for its internal scratch directory.
GNU objcopy supplies the same --redefine-sym operation when LLVM is unavailable.
These tests require no Docker, target toolchain or external repository.
"""
import os
import pathlib
import shutil
import signal
import subprocess
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = ROOT / "infra/base-builder/driver"
LINKER = ROOT / "infra/base-builder/link-fuzz-target"
TOOLS = ("cc", "ar", "objcopy", "objdump")
# What each link reads, the same in every test.
OBJECTS = ("cli.o", "adapter.o", "af.o", "count.o", "library.o", "fuzzer.o", "libfixture.a")


# Session, not module: a worker of pytest-xdist can run this module's tests between other modules' tests, and each
# return to the module would otherwise compile them again.
@pytest.fixture(scope="session")
def objects(tmp_path_factory):
    """The driver's objects, the fuzz target's and its library's, and the library's archive, compiled once: no test
    changes them, and each test links its own copies."""
    if any(shutil.which(tool) is None for tool in TOOLS):
        pytest.skip("native C compiler, ar, objcopy and objdump are required")
    directory = tmp_path_factory.mktemp("objects")
    common = ["cc", "-O0", "-ffunction-sections", "-fdata-sections", "-fno-builtin-malloc",
              "-I", str(DRIVER)]

    def run(*args):
        done = subprocess.run(args, cwd=directory, capture_output=True, text=True, timeout=30)
        assert done.returncode == 0, done.stderr
        return done

    run(*common, "-c", str(DRIVER / "cli.c"), "-o", "cli.o")
    run(*common, "-c", str(DRIVER / "adapter.c"), "-o", "adapter.o")
    run(*common, "-c", str(DRIVER / "allocation_failure.c"), "-o", "af.o")
    run(*common, "-DOV_ALLOCATION_COUNTING", "-c", str(DRIVER / "allocation_failure.c"), "-o", "count.o")
    (directory / "library.c").write_text(
        '#include <stdlib.h>\n'
        'void library_test(void) {\n'
        '  volatile unsigned char *p = malloc(8);\n'
        '  p[0] = 42; /* Deliberate missing allocation-failure check. */\n'
        '  free((void *)p);\n'
        '}\n')
    (directory / "fuzzer.c").write_text(
        '#include <stddef.h>\n#include <stdint.h>\n'
        'void library_test(void);\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '  (void)data; (void)size; library_test(); return 0;\n}\n')
    run(*common, "-c", "library.c", "-o", "library.o")
    run(*common, "-c", "fuzzer.c", "-o", "fuzzer.o")
    # ar names the object's format, so that it loads no linker plugin to recognise it. Without --target it loads
    # every plugin in bfd-plugins/, and GitHub's runner images put there one LLVM gold plugin for each clang they
    # carry, each with its libLLVM of over 100 MB. This ar ran past its 30 seconds twice on main (runs of 2026-10-28
    # and 2026-11-17), both times in the suite's first test, the first to load those plugins on a fresh runner.
    form = run("objdump", "-f", "library.o").stdout.split("file format ", 1)[1].split()[0]
    run("ar", f"--target={form}", "rcs", "libfixture.a", "library.o")
    return directory


@pytest.fixture
def native_link(objects, tmp_path):
    executable = tmp_path / "bin"
    executable.mkdir()
    (executable / "llvm-objcopy").symlink_to(shutil.which("objcopy"))
    env = {**os.environ, "PATH": f"{executable}:{os.environ['PATH']}"}
    for name in OBJECTS:
        shutil.copy(objects / name, tmp_path / name)
    (tmp_path / "input.ld").write_text("INPUT(libfixture.a)\n")
    (tmp_path / "objects.rsp").write_text("libfixture.a\n")
    twins = tmp_path / "twins"
    twins.mkdir()
    scratch = tmp_path / "ov"
    scratch.mkdir()
    settings = scratch / "link.env"
    settings.write_text(
        "OV_LFE='normal-engine'\nOV_DRIVER='cli.o adapter.o'\n"
        "OV_AFE='failure-engine'\nOV_AFC='counting-engine'\n"
        "OV_AF_DRIVER='cli.o af.o'\nOV_AFC_DRIVER='cli.o count.o'\n"
        "OV_SEALS=''\nOV_SILENT_LD=''\nOV_AF_RENAME='--redefine-sym malloc=__ov_malloc'\n"
        f"OV_TWINS='{twins}'\n")
    script = tmp_path / "link-fuzz-target"
    source = LINKER.read_text()
    script.write_text(source.replace("/tmp/ov/", f"{scratch}/"))
    script.chmod(0o755)

    def link(library, engine="failure-engine"):
        return subprocess.run([str(script), "cc", "fuzzer.o", engine, *library, "-o", "target"],
                              cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)

    def target(library, engine="failure-engine", header=bytes(6)):
        linked = link(library, engine)
        assert linked.returncode == 0, linked.stderr
        input_file = tmp_path / "input"
        input_file.write_bytes(header)
        return subprocess.run([str(tmp_path / "target"), str(input_file)], cwd=tmp_path,
                              env=env, capture_output=True, text=True, timeout=30)

    return SimpleNamespace(link=link, target=target)


def test_explicit_archive_control_reaches_allocation_failure(native_link):
    assert native_link.target(["libfixture.a"]).returncode == 0
    assert native_link.target(["libfixture.a"], header=b"\0\0\1\0\0\0").returncode == -signal.SIGSEGV


@pytest.mark.parametrize("library", [
    ["-L.", "-lfixture"],
    ["-L.", "-l:libfixture.a"],
    ["-L.", "-l", "fixture"],
    ["-Wl,-L.,-lfixture"],
    ["-Xlinker", "-L.", "-Xlinker", "-lfixture"],
    ["-Wl,libfixture.a"],
    ["-L.", "--for-linker", "-lfixture"],
    ["-L.", "--for-linker=-lfixture"],
    ["--config", "hidden.cfg"],
    ["--config=hidden.cfg"],
    ["input.ld"],
])
@pytest.mark.parametrize("engine", ["failure-engine", "counting-engine"])
def test_indirect_library_inputs_are_refused(native_link, library, engine):
    linked = native_link.link(library, engine)
    assert linked.returncode != 0, "the library's allocations were silently left uninstrumented"
    assert "link-fuzz-target:" in linked.stderr
    assert "object" in linked.stderr and "archive" in linked.stderr


def test_explicit_archive_control_counts_the_library_allocation(native_link):
    assert native_link.target(["libfixture.a"], "counting-engine", b"\0\x80\0\0\0\0").returncode == 1


def test_normal_engine_keeps_library_options_and_forwarded_inputs(native_link):
    for library in (["-L.", "-lfixture"], ["-Wl,-L.,-lfixture"], ["input.ld"]):
        assert native_link.target(library, "normal-engine").returncode == 0


def test_explicit_archive_keeps_compiler_options(native_link):
    assert native_link.target(["-L.", "-pthread", "libfixture.a"],
                              "counting-engine", b"\0\x80\0\0\0\0").returncode == 1


def test_response_files_remain_refused(native_link):
    linked = native_link.link(["@objects.rsp"])
    assert linked.returncode != 0
    assert "name an allocation-failure fuzz target's objects on the command line" in linked.stderr
