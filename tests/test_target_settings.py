# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The settings that the build of one fuzz target can give, tested on the host:
uv run pytest tests/test_target_settings.py

OV_MAX_INPUT_LOG2: the host's cc compiles the driver (infra/base-builder/driver/cli.c and adapter.c) with a harness
that returns 0, with and without -DOV_MAX_INPUT_LOG2. The driver then runs on files of zeros, one byte below its limit
and at its limit. A file of zeros is a valid input: its config word is 0 and its allocation mask is 0. The files are
sparse, so they use no disk space.

OV_PATH_REWRITE: sh runs a copy of infra/base-builder/release-target.sh, which writes the compiler shims of a target
and its dependency, with and without OV_PATH_REWRITE=off. The copy uses a scratch directory in place of /tmp/shim and
/work. Each shim then runs a stand-in clang, which writes the arguments that it got."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = ROOT / "infra/base-builder/driver"
HARNESS = ("#include <stddef.h>\n#include <stdint.h>\n"
           "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }\n")
LIMIT_ERROR = "OV_MAX_INPUT_LOG2 must be 27, 28, 29, 30 or 31"

RELEASE_TARGET = ROOT / "infra/base-builder/release-target.sh"
CHOST = "riscv64-linux-musl"
LIBREL = "build/lib/asan"
DEPENDENCY, TARGET = "dep", "tgt"
# The configuration that each compiler shim gives clang, by the shim's last word.
CONFIGS = {"sealed": "--config=/tmp/asan-musl-sealed-noiconv.cfg", "plain": "--config=/opt/asan-static/musl.cfg"}
# The sha256 of each file in the shim directory after ov_release_layout DEPENDENCY TARGET with no OV_PATH_REWRITE, as
# release-target.sh wrote them at commit 9579074d9e18. The text of each file has <tmp> in place of the scratch
# directory.
RELEASE_SHIMS = {
    "oft-nogc-discard.ld": "2e7c0d1634ba500d18e4cacc7153bcbfb13aa984e9fe7d7228fe63dd70cd55ca",
    f"{CHOST}-clang-plain": "81e7878743212daab1a9be6e32320a6d1c57a773e60e52d048ad2cad9585e27b",
    f"{CHOST}-clang++-plain": "4a1bc0f07d3053e5f9766017c6d6c16cad502dcefa6c0de3ecccf0628b921fd2",
    f"{CHOST}-clang-sealed": "b25e0bb138912a68d48c03c14dec4c3c3e948e2dbb8aa12596006680f466e5f2",
    f"{CHOST}-clang++-sealed": "52b9bf66712c25e8049135ca4f647834e1ddec6dc5bf8133f57c6d960aa7a893",
}
CLANG = r'''#!/usr/bin/env python3
"""A stand-in for clang: it writes its arguments, without its own name, to $FAKE_CLANG_LOG as JSON."""
import json
import os
import sys

with open(os.environ["FAKE_CLANG_LOG"], "w") as log:
    json.dump(sys.argv[1:], log)
'''
PATH_ERROR = "ov_release_layout: OV_PATH_REWRITE must be off or unset, not '{}'"


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


def compiles(work, name):
    """The compiles that a test runs for a target, from the source tree in its build directory. Each one is the
    arguments that the shim gets, with the neutral name of the source. The sources are: a file of that tree, by its
    absolute path, with -march=rv64gc; a vendored file, by its path relative to the tree; and a harness file, by its
    absolute path."""
    tree = f"{work}/{LIBREL}/{name}/src"
    return [(["-march=rv64gc", "-c", f"{tree}/x.c"], f"/src/{name}/src/x.c"),
            (["-c", "oft-vendor/v.c"], f"/src/vendor/{name}/v.c"),
            (["-c", f"{work}/targets/{name}/h.c"], f"/src/harness/{name}/h.c")]


def pinned(arguments, source):
    """The arguments with -march=rv64g in place of each -march, and with `source` in place of the last argument."""
    return ["-march=rv64g" if word.startswith("-march=") else word for word in arguments[:-1]] + [source]


def prefix_maps(work):
    """The prefix maps of the release's shims, in their order. Each path that has a neutral name gets two maps: a
    -fmacro-prefix-map from the path to the name, and a -fdebug-prefix-map from the name to the path. The paths are:
    for each target, its vendored files in its build directory and in its source tree, its build directory, its source
    tree and its harness files; then the driver, and the rest of /work. Last is the map of a relative vendored path."""
    pairs = []
    for name in (DEPENDENCY, TARGET):
        pairs += [(f"{work}/{LIBREL}/{name}/src/oft-vendor/", f"/src/vendor/{name}/"),
                  (f"{work}/ext/{name}/src/oft-vendor/", f"/src/ext-vendor/{name}/"),
                  (f"{work}/{LIBREL}/{name}/", f"/src/{name}/"),
                  (f"{work}/ext/{name}/", f"/src/ext/{name}/"),
                  (f"{work}/targets/{name}/", f"/src/harness/{name}/")]
    pairs += [(f"{work}/src/", "/src/driver/"), (f"{work}/", "/src/repo/")]
    return [flag for path, neutral in pairs
            for flag in (f"-fmacro-prefix-map={path}={neutral}", f"-fdebug-prefix-map={neutral}={path}")] + [
        "-fmacro-prefix-map=oft-vendor/=vendor/"]


@pytest.fixture
def release(tmp_path):
    """A copy of release-target.sh in tmp_path. In the copy, an empty file tmp_path/recipes.sh is in place of the
    recipes, tmp_path/shim is in place of /tmp/shim, and tmp_path/work/ is in place of /work/. The source files of
    `compiles` are in tmp_path/work for each target, and a stand-in clang is in tmp_path/tools. It gives:
    layout(<setting>): ov_release_layout DEPENDENCY TARGET in sh, as ov_target_begin calls it in the asan build, with
    no records. OV_PATH_REWRITE has the value <setting>, or is unset when <setting> is None. ov_neutral does nothing
    here, because its links under /src need root. It returns the result.
    cc(<shim>, <name>, <arguments>): the shim <CHOST>-clang-<shim> on the arguments, from the source tree in the build
    directory of <name>, with the stand-in clang first on PATH. It returns the arguments that clang got."""
    if shutil.which("sh") is None:
        pytest.skip("a POSIX shell (sh) is required")
    work, shims, tools = tmp_path / "work", tmp_path / "shim", tmp_path / "tools"
    shims.mkdir()
    tools.mkdir()
    (tmp_path / "recipes.sh").write_text("")
    script = tmp_path / "release-target.sh"
    script.write_text(RELEASE_TARGET.read_text()
                      .replace(". /usr/local/lib/oss-verify/recipes.sh", f". {tmp_path}/recipes.sh")
                      .replace("/tmp/shim", str(shims)).replace("/work/", f"{work}/"))
    clang = tools / "clang"
    clang.write_text(CLANG)
    clang.chmod(0o755)
    for name in (DEPENDENCY, TARGET):
        tree = work / LIBREL / name / "src"
        for source in (tree / "x.c", tree / "oft-vendor" / "v.c", work / "targets" / name / "h.c"):
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("int x;\n")
    log = tmp_path / "clang.json"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OV_", "OFT_"))}
    env.update(CHOST=CHOST, LIBREL=LIBREL, OV_RECORDS="")

    def layout(setting):
        return subprocess.run(["sh", "-c", '. "$1"; ov_neutral() { :; }; ov_release_layout "$2" "$3"', "sh",
                               str(script), DEPENDENCY, TARGET],
                              env=env if setting is None else {**env, "OV_PATH_REWRITE": setting},
                              capture_output=True, text=True, timeout=30)

    def cc(shim, name, *arguments):
        tree = work / LIBREL / name / "src"
        done = subprocess.run([str(shims / f"{CHOST}-clang-{shim}"), *arguments], cwd=tree,
                              env={**env, "PATH": f"{tools}:{env['PATH']}", "PWD": str(tree),
                                   "FAKE_CLANG_LOG": str(log)},
                              capture_output=True, text=True, timeout=30)
        assert done.returncode == 0, done.stderr
        return json.loads(log.read_text())

    return SimpleNamespace(layout=layout, cc=cc, root=tmp_path, work=work, shims=shims)


@pytest.mark.parametrize("shim", ["sealed", "plain"])
@pytest.mark.parametrize("name", [DEPENDENCY, TARGET])
def test_path_rewrite_unset_gives_each_source_its_neutral_name(release, name, shim):
    """With no OV_PATH_REWRITE, the shims rewrite each source path, the dependency's too. clang gets the shim's
    configuration, every prefix map, -DOFT_RELEASE_BUILD=1 and the shim's headers. Then it gets the arguments, with
    -march=rv64g, and with the source's neutral name in place of the path. The relative vendored path gets its neutral
    name too: the shim makes it absolute first."""
    done = release.layout(None)
    assert done.returncode == 0, done.stderr
    words = [CONFIGS[shim], *prefix_maps(release.work), "-DOFT_RELEASE_BUILD=1", "-isystem", f"{release.shims}/include"]
    for arguments, neutral in compiles(release.work, name):
        assert release.cc(shim, name, *arguments) == words + pinned(arguments, neutral)


def test_path_rewrite_unset_writes_the_shims_of_the_release(release):
    """With no OV_PATH_REWRITE, ov_release_layout writes each file in the shim directory byte for byte as before
    OV_PATH_REWRITE existed (RELEASE_SHIMS)."""
    done = release.layout(None)
    assert done.returncode == 0, done.stderr
    written = {path.name: hashlib.sha256(path.read_text().replace(str(release.root), "<tmp>").encode()).hexdigest()
               for path in release.shims.iterdir()}
    assert written == RELEASE_SHIMS


@pytest.mark.parametrize("shim", ["sealed", "plain"])
@pytest.mark.parametrize("name", [DEPENDENCY, TARGET])
def test_path_rewrite_off_gives_each_source_path_as_the_build_gives_it(release, name, shim):
    """With OV_PATH_REWRITE=off, the shims rewrite no source path, the dependency's too. clang gets the shim's
    configuration, -DOFT_RELEASE_BUILD=1 and the shim's headers, and no prefix map. Then it gets the arguments, with
    -march=rv64g, and with each source path as the build gave it: the relative vendored path stays relative."""
    done = release.layout("off")
    assert done.returncode == 0, done.stderr
    words = [CONFIGS[shim], "-DOFT_RELEASE_BUILD=1", "-isystem", f"{release.shims}/include"]
    for arguments, _ in compiles(release.work, name):
        assert release.cc(shim, name, *arguments) == words + pinned(arguments, arguments[-1])


@pytest.mark.parametrize("value", ["on", "OFF", ""])
def test_path_rewrite_refuses_a_value_other_than_off(release, value):
    """OV_PATH_REWRITE with any value but off, the empty value too, stops ov_release_layout before it writes a shim.
    The message names the variable."""
    done = release.layout(value)
    assert done.returncode != 0
    assert PATH_ERROR.format(value) in done.stderr, done.stderr
    assert list(release.shims.iterdir()) == []
