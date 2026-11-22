# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The settings that the build of one fuzz target can give, tested on the host:
uv run pytest tests/test_target_settings.py

OV_MAX_INPUT_LOG2: the host's cc compiles the driver (infra/base-builder/driver/cli.c and adapter.c) with a harness
that returns 0, with and without -DOV_MAX_INPUT_LOG2. The driver then runs on files of zeros, one byte below its limit
and at its limit. A file of zeros is a valid input: its config word is 0 and its allocation mask is 0. The files are
sparse, so they use no disk space.

The driver objects of each input limit: bash runs a copy of infra/base-builder/compile for the plain build, with and
without OV_RECORD=1. The copy uses scratch directories in place of /usr/local/lib/oss-verify and /tmp/ov. Stand-ins
take the place of toolchain.sh, record-compile, the driver's compiler and riscv64-linux-musl-ar. The stand-in compiler
writes the arguments that it got into its output.

OV_PATH_REWRITE: sh runs a copy of infra/base-builder/release-target.sh, which writes the compiler shims of a target
and its dependency, with and without OV_PATH_REWRITE=off. The copy uses a scratch directory in place of /tmp/shim and
/work. Each shim then runs a stand-in clang, which writes the arguments that it got."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = ROOT / "infra/base-builder/driver"
HARNESS = ("#include <stddef.h>\n#include <stdint.h>\n"
           "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }\n")

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

COMPILE = ROOT / "infra/base-builder/compile"
LIMITS = range(27, 32)
# A stand-in for toolchain.sh: the names that compile reads, for the plain build. compile runs only DRVCC.
TOOLCHAIN = f'''CHOST={CHOST}
SHIM=@TMP@/shim
BASE_CFLAGS="-march=rv64g -Os"
SAN=""
UBSAN="-fsanitize=undefined"
DRVCC=@TMP@/tools/drvcc
DRVCXX=$DRVCC
CC=$DRVCC
CXX=$DRVCXX
CFLAGS="$BASE_CFLAGS $SAN"
export CHOST CC CXX CFLAGS DRVCC DRVCXX BASE_CFLAGS SAN
suppress_unused_arg_werror() {{ :; }}
define_fuzzing_build_mode() {{ :; }}
'''
RECORD_COMPILE = "#!/bin/sh\n# A stand-in for record-compile: it puts no front before a shim.\nexit 0\n"
AR = (f'#!/bin/sh\n# A stand-in for {CHOST}-ar: it writes the archive, its second argument, as an empty file.\n'
      ': > "$2"\n')
DRVCC = r'''#!/usr/bin/env python3
"""A stand-in for the driver's compiler: it writes its arguments, without its own name, as JSON into the file of -o,
and adds them as one line of JSON to $FAKE_DRVCC_LOG."""
import json
import os
import sys

arguments = sys.argv[1:]
with open(arguments[arguments.index("-o") + 1], "w") as output:
    json.dump(arguments, output)
with open(os.environ["FAKE_DRVCC_LOG"], "a") as log:
    log.write(json.dumps(arguments) + "\n")
'''
# Each command that the driver's compiler got from compile at commit 9579074d9e18, which made no limit object (the
# base's), in the harness of compile_run, in order. The text of each command has <tmp> in place of the scratch
# directory. True marks a command that only a run with OV_RECORD=1 gave.
BASE_COMPILES = [
    (False, "-march=rv64g -Os -c -I<tmp>/lib/driver <tmp>/lib/driver/cli.c -o <tmp>/ov/cli.o"),
    (False, "-march=rv64g -Os -c -I<tmp>/lib/driver <tmp>/lib/driver/adapter.c -o <tmp>/ov/adapter.o"),
    (False, "-march=rv64g -Os -c <tmp>/lib/driver/wrap_getenv.c -o <tmp>/ov/wrap_getenv.o"),
    (False, "-march=rv64g -Os -c <tmp>/lib/driver/wrap_mkstemp.c -o <tmp>/ov/wrap_mkstemp.o"),
    (False, "-march=rv64g -Os -c <tmp>/lib/driver/wrap_getpid.c -o <tmp>/ov/wrap_getpid.o"),
    (True, "-march=rv64g -Os -DHARNESS_QUIET -c -I<tmp>/lib/driver <tmp>/lib/driver/cli.c -o <tmp>/ov/cli-quiet.o"),
    (True, "-march=rv64g -Os -DHARNESS_QUIET -c -I<tmp>/lib/driver <tmp>/lib/driver/adapter.c "
           "-o <tmp>/ov/adapter-quiet.o"),
    (True, "-march=rv64g -Os -DHARNESS_QUIET -c -I<tmp>/lib/driver <tmp>/lib/driver/allocation_failure.c "
           "-o <tmp>/ov/allocation_failure-quiet.o"),
    (True, "-march=rv64g -Os -DHARNESS_QUIET -DOV_ALLOCATION_COUNTING -c -I<tmp>/lib/driver "
           "<tmp>/lib/driver/allocation_failure.c -o <tmp>/ov/allocation_counting-quiet.o"),
    (False, "-march=rv64g -Os -c -I<tmp>/lib/driver <tmp>/lib/driver/allocation_failure.c "
            "-o <tmp>/ov/allocation_failure.o"),
    (False, "-march=rv64g -Os -DOV_ALLOCATION_COUNTING -c -I<tmp>/lib/driver <tmp>/lib/driver/allocation_failure.c "
            "-o <tmp>/ov/allocation_counting.o"),
]


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
    """cli.c does not compile with OV_MAX_INPUT_LOG2 below 27 or above 31, and the compiler's output names the
    variable."""
    compiled = build(f"-DOV_MAX_INPUT_LOG2={value}")
    assert compiled.returncode != 0
    assert "OV_MAX_INPUT_LOG2" in compiled.stderr, compiled.stderr


@pytest.fixture
def compile_run(tmp_path):
    """A copy of compile in tmp_path, with tmp_path/lib in place of /usr/local/lib/oss-verify and tmp_path/ov in place
    of /tmp/ov. tmp_path/lib holds the stand-ins for toolchain.sh and record-compile (TOOLCHAIN, RECORD_COMPILE).
    tmp_path/tools, first on PATH, holds the stand-ins for the driver's compiler (DRVCC) and for the archiver (AR).
    $SRC/build.sh does nothing. It gives:
    run(<record>): the copy in bash, for the plain build (SANITIZER=none), and with OV_RECORD=1 when <record> is true.
    It returns each command that the driver's compiler got, in order, with <tmp> in place of tmp_path.
    ov: tmp_path/ov, where compile writes the driver's objects."""
    if shutil.which("bash") is None:
        pytest.skip("bash is required")
    lib, tools, ov, src = (tmp_path / name for name in ("lib", "tools", "ov", "src"))
    for directory in (lib, tools, src):
        directory.mkdir()
    script = tmp_path / "compile"
    script.write_text(COMPILE.read_text().replace("/tmp/ov", str(ov))
                      .replace("/usr/local/lib/oss-verify", str(lib)))
    (lib / "toolchain.sh").write_text(TOOLCHAIN.replace("@TMP@", str(tmp_path)))
    for path, text in ((lib / "record-compile", RECORD_COMPILE), (tools / "drvcc", DRVCC),
                       (tools / f"{CHOST}-ar", AR)):
        path.write_text(text)
        path.chmod(0o755)
    (src / "build.sh").write_text("true\n")
    log = tmp_path / "drvcc.jsonl"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OV_", "OFT"))}
    env.update(SANITIZER="none", SRC=str(src), OUT=str(tmp_path / "out"), WORK=str(tmp_path / "work"),
               FAKE_DRVCC_LOG=str(log), PATH=f"{tools}:{env['PATH']}")

    def run(record):
        done = subprocess.run(["bash", str(script)], env={**env, "OV_RECORD": "1"} if record else env,
                              capture_output=True, text=True, timeout=60)
        assert done.returncode == 0, done.stderr
        return [[word.replace(str(tmp_path), "<tmp>") for word in json.loads(line)]
                for line in log.read_text().splitlines()]

    return SimpleNamespace(run=run, ov=ov)


def output(command):
    """The file that follows -o in `command`."""
    return command[command.index("-o") + 1]


def is_limit_compile(command):
    """Whether `command` (compile_run) writes a limit object, cli-limit<k>.o or cli-limit<k>-quiet.o."""
    return output(command).startswith("<tmp>/ov/cli-limit")


@pytest.mark.parametrize("record", [False, True], ids=["no-records", "records"])
def test_compile_builds_cli_once_for_each_input_limit(compile_run, record):
    """compile compiles cli.c once for each input limit, 27 to 31, into cli-limit<k>.o: with the arguments of the
    compile of cli.o, one -DOV_MAX_INPUT_LOG2=<k> more, and its own output. With OV_RECORD=1, it also compiles
    cli-limit<k>-quiet.o in the same way from the compile of cli-quiet.o. It makes no other limit object, such as one
    for 26 or 32."""
    commands = compile_run.run(record)
    suffixes = ["", "-quiet"] if record else [""]
    names = sorted(f"cli-limit{k}{suffix}.o" for k in LIMITS for suffix in suffixes)
    assert sorted(path.name for path in compile_run.ov.glob("cli-limit*")) == names
    assert sorted(output(command) for command in commands if is_limit_compile(command)) == [
        f"<tmp>/ov/{name}" for name in names]
    for suffix in suffixes:
        default = compile_run.ov / f"cli{suffix}.o"
        for k in LIMITS:
            limit = compile_run.ov / f"cli-limit{k}{suffix}.o"
            arguments = json.loads(limit.read_text())
            define = f"-DOV_MAX_INPUT_LOG2={k}"
            assert arguments.count(define) == 1, (limit.name, arguments)
            arguments.remove(define)
            assert arguments == [str(limit) if word == str(default) else word
                                 for word in json.loads(default.read_text())], limit.name


@pytest.mark.parametrize("record", [False, True], ids=["no-records", "records"])
def test_compile_runs_the_other_compiles_of_the_base(compile_run, record):
    """Without the compiles of the limit objects, the commands of the driver's compiler are those of the base
    (BASE_COMPILES), in the same order: the driver, the seals, the objects of an allocation-failure fuzz target and,
    with OV_RECORD=1, the quiet objects."""
    others = [command for command in compile_run.run(record) if not is_limit_compile(command)]
    assert others == [command.split() for only_records, command in BASE_COMPILES if record or not only_records]


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
    The message names the variable, and the value when it is not empty."""
    done = release.layout(value)
    assert done.returncode != 0
    assert "OV_PATH_REWRITE" in done.stderr, done.stderr
    if value:
        assert re.search(rf"\b{value}\b", done.stderr), done.stderr
    assert list(release.shims.iterdir()) == []
