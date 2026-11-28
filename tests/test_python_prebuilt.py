# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The prebuilt CPython runtime of a Python build, tested on the host with no Docker:
uv run pytest tests/test_python_prebuilt.py

infra/base-builder/python/runtime.sh: sh runs copies of python/recipes.sh and runtime.sh in which each absolute path
that the runtime reads (/usr/local/, /opt/, /work, /src/repo, /lib/apk/ and /tmp/asan-musl-sealed-noiconv.cfg) is under
a scratch directory, the root, as tests/test_target_settings.py moves the paths of release-target.sh, the file system
that the key reads (OFT_PY_FS) is the root, and the PATH of the runtime's build (OFT_PY_PATH) is the root's $SHIM and
/usr/bin, then the host's /usr/bin and /bin for the stand-ins' shell tools. No build sets a variable or a path for
this. The test runs as a user that is not root, so the runtime's build runs as that user. In the root are stand-ins:
the patched source tree, whose configure writes its arguments, its environment and a mark; in /usr/bin, first on
PATH, a make that writes its targets and a mark, and, unless PYTHONDONTWRITEBYTECODE is set, the bytecode of a script
in the source tree as CPython's build does, and clang, and clang++ (a link to it); the native Python, which runs this
one; the files of the toolchain image that the inputs read (the tarball, the --config files, the package database, a
musl sysroot, a library in /usr/lib, /etc and a directory that no build reads, /opt/unrelated); and copies of the
builder's files (the patches, Setup.local, release-target.sh, toolchain.sh, compile and record-compile). What the
stand-ins write that is not the build's goes outside the root. A runtime is made as
.github/scripts/python-runtime/make makes it (oft_py_runtime, then oft_py_prebuilt_stage) and laid out in the root's
/opt/oft-py/prebuilt/<flav>-<key>/ with its records; then a new build in the same root takes it, or builds its own.
Each build prints its key line first.

The hash of a tree (OFT_PY_TREE, which hashes the files in a process pool): sh runs it and the serial listing that it
replaced (find, sha256sum, stat and sort, SERIAL_TREE) on the same tree, with one processor, two and all that the test
may run on, and the hashes must be equal.

The read boundary (OFT_PY_BOUNDARY, which runs as root in a build): the native Python runs its program on a tree in
the test's scratch directory, and the root's build runs as root (an id that says so), after stand-ins for what this
user may not do (STAND_IN): give a file to root or to nobody, which a table records, switch to nobody, or kill. A
stand-in os.chown fails part of the way, and a TERM stops a build.

.github/scripts/python-runtime/layer.py: python3 writes the layer of a staging tree, and again after its files' times
and modes change, and after a file's bytes change.

.github/scripts/python-runtime/make: its usage errors, which it finds before it runs docker, and its list of a
runtime's files."""
import contextlib
import errno
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "infra/base-builder"
SCRIPTS = ROOT / ".github/scripts/python-runtime"
SOURCE = "work/build/pyrt/src-64ef29c99f3ea59d"
# The absolute paths that the runtime reads, which the copies put under the root.
MOVED = re.compile(r"/usr/local/|/opt/|/work\b|/src/repo\b|/lib/apk/|/tmp/asan-musl-sealed-noiconv\.cfg")
# The file system that the key reads: the root in the copies.
FS = "OFT_PY_FS=/\n"
# The builder's files that the inputs name, by their path in the image.
COPIED = {"usr/local/lib/oss-verify/python/Setup.local": BUILDER / "python/Setup.local",
          "usr/local/lib/oss-verify/python/patches/0001-signal-assume-default-dispositions.patch":
              BUILDER / "python/patches/0001-signal-assume-default-dispositions.patch",
          "usr/local/lib/oss-verify/python/patches/apply.py": BUILDER / "python/patches/apply.py",
          "usr/local/lib/oss-verify/release-target.sh": BUILDER / "release-target.sh",
          "usr/local/lib/oss-verify/toolchain.sh": BUILDER / "toolchain.sh",
          "usr/local/lib/oss-verify/record-compile": BUILDER / "record-compile",
          "usr/local/bin/compile": BUILDER / "compile"}
RUNTIME_SH = "usr/local/lib/oss-verify/python/runtime.sh"
PATCH = "usr/local/lib/oss-verify/python/patches/0001-signal-assume-default-dispositions.patch"
TARGETS = ["libpython3.11.a", "Modules/expat/libexpat.a", "Modules/_decimal/libmpdec/libmpdec.a"]
RUNTIME_FILES = TARGETS + ["pyconfig.h", "oft-linkvars.txt", "target-builtins.txt", "target-frozen.txt"]
# Variables that the runtime's environment (runtime.sh, oft_py_hermetic) does not hold, and so does not key: those that
# the shell sets, the target's own names, what compile records, make's -j, and variables that configure, make, clang
# or the native Python would read.
OUTSIDE = ["HOSTNAME", "PWD", "OLDPWD", "SHLVL", "_", "T", "SRCDIR", "BUILDDIR", "OFT_PREFIX", "DEPS", "OV_RECORD",
           "OV_RECORDS", "OV_LAYOUT", "OV_BASE_LAYOUT", "OFT_MAKE_JOBS", "OV_EXTRA", "LIBS", "CPP", "CPATH",
           "C_INCLUDE_PATH", "LIBRARY_PATH", "CCC_OVERRIDE_OPTIONS", "OFT_CC_PREFIX", "MAKEFLAGS", "CONFIG_SITE",
           "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "HOME", "TMPDIR"]
BASE_CFLAGS = "-march=rv64g -mabi=lp64d -Os -g"
SAN = "-fsanitize=address"
MADE_FROM = "made-from ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain-python@sha256:" + "1" * 64

CONFIGURE = r'''#!/bin/sh
# A stand-in for CPython's configure: it reads nothing, and writes its arguments and its CONFIG_SITE, a mark, and the
# files of the runtime that configure writes. Its precious variables, as autoconf writes them:
      ac_precious_vars='build_alias
host_alias
target_alias
CC
CFLAGS
LDFLAGS
LIBS
CPPFLAGS
CPP'
echo configure >> "{scratch}/marks"
printf '%s\n' "$@" > "{scratch}/configure.args"
echo "${{CONFIG_SITE-unset}}" > "{scratch}/configure.site"
env | LC_ALL=C sort > "{scratch}/configure.env"
pwd > "{scratch}/configure.pwd"
printf '/* configured in %s */\n' "$PWD" > pyconfig.h
printf '    {{"_bisect", PyInit__bisect}},\n    {{"zlib", PyInit_zlib}},\n' > Modules/config.c
'''
MAKE = r'''#!/bin/sh
# A stand-in for make: it writes a mark, and each target, or, with -s, the value of each print-<variable>. Like
# CPython's build, it writes the bytecode of one of CPython's own scripts into the source tree, unless
# PYTHONDONTWRITEBYTECODE is set, as Python does not then.
echo "make $*" >> "{scratch}/marks"
if [ "$1" = -s ]; then
  for a; do case "$a" in print-*) echo "${{a#print-}} of $PWD" ;; esac; done
  exit 0
fi
for t; do
  case "$t" in -j*) continue ;; esac
  mkdir -p "$(dirname "$t")" && echo "$t of $PWD" > "$t"
done
[ -n "${{PYTHONDONTWRITEBYTECODE:-}}" ] || {{ mkdir -p "{pycache}" && echo "the bytecode of umarshal.py" > "{pycache}/umarshal.cpython-311.pyc"; }}
'''
CLANG = '''#!/bin/sh
# A stand-in for clang and clang++: --version prints two lines.
case "$1" in --version) printf 'clang version 20.1.8 (a stand-in)\\nTarget: x86_64-alpine-linux-musl\\n' ;; esac
'''
# The hash of a tree as runtime.sh made it before it hashed the files in a process pool: one file after another, with
# find, sha256sum, stat and sort; each line but a link's with the entry's mode and owner, as stat's %a %u:%g.
SERIAL_TREE = r'''
oft_py_tree_serial() {
  { find "$1" -type d -exec stat -c '%n d %a %u:%g' {} +
    find "$1" -type f -exec sh -c 'for f; do printf "%s f %s %s\n" "$f" "$(sha256sum < "$f" | cut -d" " -f1)" "$(stat -c "%a %u:%g" "$f")"; done' sh {} +
    find "$1" -type l -exec stat -c '%n l %N' {} +
    find "$1" ! -type d ! -type f ! -type l -exec stat -c '%n o %a %u:%g' {} +
  } | LC_ALL=C sort | sha256sum | cut -d' ' -f1
}
'''


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def toolchain(tmp_path):
    """The root and its stand-ins (above). It gives:
    run(<script>, <name>=<value> ..., cpus=<set>, cwd=<directory>): <script> in sh after recipes.sh, with oft_jobs
    giving 2 and SAN set as toolchain.sh sets it, in the environment `env` with each <name> set to <value> (None:
    removed), on the processors of `cpus` (default: those of this test), from `cwd` (default: the root). The result.
    ship(<flav>, before=<script>, <name>=<value> ...): make the runtime of <flav> as the make script does (after
    <script>, in the environment with each change), lay it out with its records in the root's
    /opt/oft-py/prebuilt/<flav>-<key>/, and remove what its build wrote in /work, as a new container has not: its build
    directory, and the bytecode in the source tree. The directory.
    scratch: the directory outside the root where the stand-ins write their marks and arguments."""
    root, scratch = tmp_path / "root", tmp_path / "scratch"
    tools = root / "usr/bin"
    for name in ("usr/local/lib/oss-verify/python/patches", "usr/local/bin", "opt/oft-py/native/bin",
                 "opt/asan-static", "tmp/shim", "lib/apk/db", "opt/musl-sysroot/usr/lib",
                 "opt/musl-sysroot/usr/include", f"{SOURCE}/Modules", f"{SOURCE}/Lib", "src", "usr/bin", "usr/lib",
                 "etc", "opt/unrelated", "root", "opt/oft/bin", "var"):
        (root / name).mkdir(parents=True, exist_ok=True)
    scratch.mkdir()

    def move(text):
        return MOVED.sub(lambda match: f"{root}{match.group(0)}", text)

    for name in ("recipes.sh", "runtime.sh"):
        text = move((BUILDER / "python" / name).read_text())
        if name == "runtime.sh":
            assert text.count(FS) == 1
            text = text.replace(FS, f"OFT_PY_FS={root}\n")
            path = re.compile(r"^OFT_PY_PATH=.*$", re.M)
            assert len(path.findall(text)) == 1
            text = path.sub(f"OFT_PY_PATH={root}/tmp/shim:{tools}:/usr/bin:/bin", text)
        (root / "usr/local/lib/oss-verify/python" / name).write_text(text)
    for name, path in COPIED.items():
        shutil.copyfile(path, root / name)
    (root / "opt/oft-py/Python-3.11.13.tar.xz").write_bytes(b"a stand-in for the CPython tarball\n")
    python = root / "opt/oft-py/native/bin/python3.11"
    # With OFT_TEST_STANDIN set (stand_in), each program of runtime.sh runs after the stand-ins of that file.
    python.write_text(f"#!/bin/sh\nif [ -n \"${{OFT_TEST_STANDIN:-}}\" ] && [ \"$1 $2 $3\" = '-I -S -c' ]; then\n"
                      f"  program=$4; shift 4\n"
                      f"  exec '{sys.executable}' -I -S -c \"$(cat \"$OFT_TEST_STANDIN\")\" \"$program\" \"$@\"\n"
                      f"fi\nexec '{sys.executable}' \"$@\"\n")
    (root / "opt/asan-static/musl.cfg").write_text("--sysroot=/opt/musl-sysroot\n")
    # The sealed configuration names the wrap list that toolchain.sh writes beside it in /tmp, which the tree lines
    # leave out with the rest of /tmp.
    (root / "tmp/asan-noiconv.wrap").write_text("--wrap=posix_spawn\n")
    (root / "tmp/asan-musl-sealed-noiconv.cfg").write_text(
        f"-fsanitize=address\n-Wl,@{root}/tmp/asan-noiconv.wrap\n")
    (root / "lib/apk/db/installed").write_text("P:clang20\nV:20.1.8-r0\n")
    (root / "opt/musl-sysroot/usr/lib/libc.a").write_bytes(b"!<arch>\nlibc\n")
    (root / "opt/musl-sysroot/usr/include/stdio.h").write_text("int printf(const char *, ...);\n")
    (root / "opt/musl-sysroot/usr/lib/libc.so").symlink_to("libc.a")
    (root / "usr/lib/libz.a").write_bytes(b"!<arch>\nzlib\n")
    (root / "opt/unrelated/README").write_text("no build reads this\n")
    # The toolchain's own files in /opt/oft, which the key reads, beside the targets' prefixes, which it leaves out.
    (root / "opt/oft/bin/riscv64-linux-musl-clang-plain").write_text("#!/bin/sh\nexec clang \"$@\"\n")
    # What toolchain.sh writes in $SHIM: a tool wrapper, which the key reads.
    (root / "tmp/shim/riscv64-linux-musl-ar").write_text('#!/bin/sh\nexec llvm-ar "$@"\n')
    for name in ("hosts", "hostname", "resolv.conf"):
        (root / "etc" / name).write_text(f"{name} of the shipped build's container\n")
    (root / "etc/os-release").write_text("NAME=Alpine Linux\n")
    # The Java keystore, which each build of the builder writes anew with other random salts.
    (root / "etc/ssl/certs/java").mkdir(parents=True)
    (root / "etc/ssl/certs/java/cacerts").write_bytes(b"a keystore\n")
    (root / SOURCE / "configure").write_text(CONFIGURE.format(scratch=scratch))
    (root / SOURCE / "Lib/os.py").write_text("import sys\n")
    (root / SOURCE / ".oft-src-ok").write_text("")
    (root / "src/repo").symlink_to(root / "work")
    pycache = root / SOURCE / "Tools/scripts/__pycache__"
    (tools / "make").write_text(MAKE.format(scratch=scratch, pycache=pycache))
    (tools / "clang").write_text(CLANG)
    (tools / "clang++").symlink_to("clang")
    # id, which says that this user is root when OFT_TEST_ROOT is set, so that a build takes the read boundary.
    (tools / "id").write_text('#!/bin/sh\nif [ -n "${OFT_TEST_ROOT:-}" ] && [ "$*" = -u ]; then echo 0; exit 0; fi\n'
                              'exec /usr/bin/id "$@"\n')
    for path in (python, root / SOURCE / "configure", tools / "make", tools / "clang", tools / "id"):
        path.chmod(0o755)
    recipes = root / "usr/local/lib/oss-verify/python/recipes.sh"
    env = {"PATH": f"{root}/tmp/shim:{tools}:/usr/bin:/bin", "HOME": str(root / "root"), "FLAV": "asan",
           "CHOST": "riscv64-linux-musl", "SHIM": str(root / "tmp/shim"),
           "CC": "/tmp/shim/riscv64-linux-musl-clang-sealed", "BASE_CFLAGS": BASE_CFLAGS,
           "CFLAGS": f"{BASE_CFLAGS} {SAN}", "SOURCE_DATE_EPOCH": "1756684800", "OV_RECORDS": ""}

    def run(script, cpus=None, cwd=None, **changes):
        environment = {**env, **changes}
        environment = {name: value for name, value in environment.items() if value is not None}
        return subprocess.run(["sh", "-c", f'. "$1"; oft_jobs() {{ echo 2; }}; SAN="{SAN}"; {script}', "sh",
                               str(recipes)], env=environment, cwd=cwd or root, capture_output=True, text=True,
                              timeout=120, preexec_fn=None if cpus is None else lambda: os.sched_setaffinity(0, cpus))

    def ship(flav="asan", before="", **changes):
        stage = tmp_path / "stage" / flav
        done = run(f'{before}oft_py_runtime || exit 1; oft_py_prebuilt_stage "{stage}"', FLAV=flav, **changes)
        assert done.returncode == 0, done.stdout + done.stderr
        assert decided(SimpleNamespace(root=root), done, flav)[0] == (
            f"oft-py: runtime {flav}: built here: this toolchain image ships no prebuilt runtime "
            f"({root}/opt/oft-py/prebuilt/{flav}-*)")
        key = (stage / "manifest").read_text().splitlines()[-1].removeprefix("key ")
        shipped = root / "opt/oft-py/prebuilt" / f"{flav}-{key}"
        shutil.copytree(stage / "runtime", shipped / "runtime")
        (shipped / "manifest").write_text((stage / "manifest").read_text() + MADE_FROM + "\n")
        (shipped / "records/nosan").mkdir(parents=True)
        nosan = b"an object compiled without its source's no_sanitize attributes\n"
        (shipped / "records/nosan" / sha256(nosan)).write_bytes(nosan)
        (shipped / "records/compiles.jsonl").write_text(
            '{"sha256": "a", "output": "Objects/obmalloc.o"}\n{"sha256": "b", "output": "Python/ceval.o"}\n')
        shutil.rmtree(root / "work/build/pyrt" / flav)
        (scratch / "marks").unlink()
        return shipped

    return SimpleNamespace(root=root, tools=tools, scratch=scratch, env=env, run=run, ship=ship, move=move)


def tree_line(toolchain, path, cpus=None, left_out="", own=""):
    """The tree line of `path` alone (OFT_PY_TREE), on the processors of `cpus`, but `left_out` (a shell word: the
    paths left out, one per line). The lines of what its links lead to outside it, which follow, are not returned."""
    done = toolchain.run(f'"$OFT_PY_BPY" -I -S -c "$OFT_PY_TREE" {left_out or """''"""} "" {own or """''"""} "{path}"',
                         cpus=cpus)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()[0]


def tree_sha(toolchain, path, cpus=None):
    """The SHA-256 of the tree of `path` alone (OFT_PY_TREE)."""
    return tree_line(toolchain, path, cpus).rsplit(" ", 1)[1]


def serial_sha(toolchain, path):
    """The SHA-256 of the tree of `path` as the serial listing makes it (SERIAL_TREE)."""
    done = toolchain.run(f'{SERIAL_TREE}\noft_py_tree_serial "{path}"')
    assert done.returncode == 0 and re.fullmatch(r"[0-9a-f]{64}\n", done.stdout), done.stdout + done.stderr
    return done.stdout.strip()


def runtime_files(directory):
    return {name: (directory / name).read_bytes() for name in RUNTIME_FILES}


def marks(toolchain):
    path = toolchain.scratch / "marks"
    return path.read_text().splitlines() if path.exists() else []


def took(toolchain, shipped, flav="asan"):
    return f"oft-py: runtime {flav}: took the shipped runtime ({shipped}); ran no CPython configure or make"


KEY_LINE = re.compile(r"oft-py: runtime (\w+): key ([0-9a-f]{12}) in \d+\.\d s")


def decided(toolchain, done, flav="asan"):
    """The lines that `done` printed but its key line, which it asserts: one key line, of this build's key (the first
    12 hex digits of the manifest's), and right after it the line that says whether the build took the shipped
    runtime or builds its own."""
    lines = done.stdout.splitlines()
    keyed = [i for i, line in enumerate(lines) if KEY_LINE.fullmatch(line)]
    assert len(keyed) == 1, done.stdout + done.stderr
    match = KEY_LINE.fullmatch(lines[keyed[0]])
    key = (toolchain.root / f"work/build/pyrt/{flav}.manifest").read_text().splitlines()[-1]
    assert (match.group(1), key[:16]) == (flav, f"key {match.group(2)}"), (lines[keyed[0]], key)
    assert lines[keyed[0] + 1].startswith((f"oft-py: runtime {flav}: took the shipped runtime ",
                                           f"oft-py: runtime {flav}: built here: ")), done.stdout
    return lines[:keyed[0]] + lines[keyed[0] + 1:]


def built_here(toolchain, shipped, done, same_key=False):
    """The two lines of the built-here line that names the first input that differs: (the shipped one's, this
    build's). It asserts that the build built its own runtime, and that its key is not the shipped one's (or is,
    with `same_key`)."""
    lines = decided(toolchain, done)
    found = [re.fullmatch(r"oft-py: runtime asan: built here: the shipped runtime was built with (.*), this build has "
                          rf"(.*) \({re.escape(str(shipped))}/manifest\)", line) for line in lines]
    found = [match.groups() for match in found if match]
    assert len(found) == 1, done.stdout + done.stderr
    assert done.returncode == 0, done.stderr
    assert not any("took the shipped runtime" in line for line in lines), done.stdout
    assert any(line.startswith("oft-py: runtime asan built in ") for line in lines), done.stdout
    assert marks(toolchain) == ["configure", f"make -j2 {' '.join(TARGETS)}"] + [
        f"make -s -f Makefile -f oft-print.mk print-{name}" for name in ("LIBS", "MODLIBS", "SYSLIBS", "OPT")]
    manifest = (toolchain.root / "work/build/pyrt/asan.manifest").read_text().splitlines()
    assert (manifest[-1] == f"key {shipped.name.removeprefix('asan-')}") == same_key
    return found[0]


def configure_arguments(toolchain, base_cflags=BASE_CFLAGS):
    """The arguments that the runtime's build gives configure, as recipes.sh gave them before runtime.sh."""
    rt = toolchain.root / "work/build/pyrt/asan"
    return ["--host=riscv64-linux-musl", "--build=x86_64-pc-linux-gnu",
            f"--with-build-python={toolchain.root}/opt/oft-py/native/bin/python3.11", "--prefix=/oft/py",
            "--disable-shared", "--without-ensurepip", "--disable-test-modules", "--disable-ipv6",
            "ac_cv_file__dev_ptmx=no", "ac_cv_file__dev_ptc=no", "CC=/tmp/shim/riscv64-linux-musl-clang-sealed",
            f"CFLAGS={base_cflags} {SAN} -DOFT_SIGNAL_ASSUME_DEFAULT -fmacro-prefix-map={rt}/=/oft/pyrt/build/ "
            f"-fmacro-prefix-map={toolchain.root}/src/repo/build/pyrt/asan/=/oft/pyrt/build/",
            "CPPFLAGS=", "LDFLAGS="]


def test_an_image_that_ships_none_builds_here_as_before(toolchain):
    """With no /opt/oft-py/prebuilt, the build prints its key line, says that the image ships none, and builds its
    runtime: configure with the arguments that recipes.sh gave it before runtime.sh, and CONFIG_SITE empty, then make
    with the same targets."""
    done = toolchain.run('oft_py_runtime || exit 1; echo "rt=$OFT_PY_RT"')
    assert done.returncode == 0, done.stderr
    lines = decided(toolchain, done)
    assert lines[0] == ("oft-py: runtime asan: built here: this toolchain image ships no prebuilt runtime "
                        f"({toolchain.root}/opt/oft-py/prebuilt/asan-*)")
    assert re.fullmatch(r"oft-py: runtime asan built in \d+ s \(12 builtin modules\)", lines[1]), lines
    assert lines[2] == f"rt={toolchain.root}/work/build/pyrt/asan"
    assert (toolchain.scratch / "configure.args").read_text().splitlines() == configure_arguments(toolchain)
    assert (toolchain.scratch / "configure.site").read_text() == "\n"
    assert marks(toolchain)[:2] == ["configure", f"make -j2 {' '.join(TARGETS)}"]


@pytest.mark.parametrize("way", ["took", "built-here", "ships-none"])
def test_every_build_prints_its_key_and_what_it_took(toolchain, way):
    """The first line of each build's runtime is its key line: `oft-py: runtime <flav>: key <the first 12 hex digits
    of the key> in <seconds, to a tenth> s`, before the line that says what the build does: when it takes the shipped
    runtime, when it builds its own for another input, and on an image that ships none."""
    if way != "ships-none":
        toolchain.ship()
    done = toolchain.run("oft_py_runtime", **({"CFLAGS": f"{BASE_CFLAGS} {SAN} -O2"} if way == "built-here" else {}))
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    key = (toolchain.root / "work/build/pyrt/asan.manifest").read_text().splitlines()[-1].removeprefix("key ")
    assert re.fullmatch(rf"oft-py: runtime asan: key {key[:12]} in \d+\.\d s", lines[0]), lines
    assert lines[1].startswith({"took": "oft-py: runtime asan: took the shipped runtime ",
                                "built-here": "oft-py: runtime asan: built here: the shipped runtime was built with ",
                                "ships-none": "oft-py: runtime asan: built here: this toolchain image ships no "}[way])
    assert len(decided(toolchain, done)) == len(lines) - 1


def test_a_build_whose_inputs_cannot_be_read_builds_here(toolchain):
    """A build whose inputs cannot be read (here, a file of a tree that the key reads, which this user cannot read)
    says so, with the time it took, and builds its own runtime, though the image ships the runtime of the inputs it had:
    it does not fail, and it takes nothing."""
    toolchain.ship()
    unreadable = toolchain.root / "opt/unrelated/README"
    unreadable.chmod(0)
    try:
        done = toolchain.run("oft_py_runtime || exit 1")
    finally:
        unreadable.chmod(0o644)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert re.fullmatch(r"oft-py: runtime asan: no key, in \d+\.\d s: the inputs of this build cannot be read",
                        lines[0]), lines
    assert lines[1] == ("oft-py: runtime asan: built here: the inputs of this build cannot be read "
                        "(oft_py_runtime_inputs failed)")
    assert re.fullmatch(r"oft-py: runtime asan built in \d+ s \(12 builtin modules\)", lines[2]), lines
    assert "oft-py: a tree cannot be read: " in done.stderr
    assert marks(toolchain)[0] == "configure"
    assert not (toolchain.root / "work/build/pyrt/asan.manifest").exists()


# The paths that the key leaves out (runtime.sh, oft_py_fs_left_out), relative to the file system, in its order: the
# paths that the read boundary leaves open (oft_py_fs_own), what Docker writes in each container (oft_py_fs_container),
# then the others.
FS_OWN = ["proc", "sys", "dev", "out", "ov-base-layout", "sbin/docker-init"]
FS_CONTAINER = ["run", "etc/hostname", "etc/hosts", "etc/resolv.conf", ".dockerenv"]
FS_LEFT_OUT = FS_OWN + FS_CONTAINER + ["tmp/ov", "src", "work", "root/.cache", "var/tmp", "var/cache",
                                       "opt/oft-py/prebuilt", "usr/local/lib/oss-verify", "etc/ssl/certs/java/cacerts"]
# The trees of the root that the key reads: the patched source tree, then each entry of the root and of its usr, opt,
# var and tmp but those left out, sorted.
FS_TREES = [SOURCE, "etc", "lib", "opt/asan-static", "opt/musl-sysroot", "opt/oft", "opt/oft-py", "opt/unrelated",
            "root", "tmp/asan-musl-sealed-noiconv.cfg", "tmp/asan-noiconv.wrap", "tmp/shim", "usr/bin", "usr/lib",
            "usr/local"]


def meta_line(path):
    """The meta line of path (OFT_PY_META): `meta <path> [l ]<mode> <uid>:<gid>`."""
    info = path.lstat()
    kind = "l " if stat.S_ISLNK(info.st_mode) else ""
    return f"meta {path} {kind}{stat.S_IMODE(info.st_mode):o} {info.st_uid}:{info.st_gid}"


def runtime_environment(toolchain, **kept):
    """The runtime's environment (runtime.sh, oft_py_hermetic), as `NAME=value` lines, sorted by name: the variables of
    OFT_PY_ENV_KEPT that this build has (the fixture's, and `kept`), and the fixed ones."""
    rt = toolchain.root / "work/build/pyrt/asan"
    fixed = {"PATH": toolchain.env["PATH"], "HOME": f"{rt}/.home", "TMPDIR": f"{rt}/.tmp", "CONFIG_SITE": "",
             "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    own = {name: value for name, value in {**toolchain.env, **kept}.items()
           if name in ("CC", "CXX", "CFLAGS", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_PATH", "SOURCE_DATE_EPOCH")}
    return [f"{name}={value}" for name, value in sorted({**own, **fixed}.items())]


def test_the_staged_manifest_is_the_inputs_and_their_key(toolchain, tmp_path):
    """oft_py_prebuilt_stage stages each file of the runtime, and a manifest: the inputs, then `key <their SHA-256>`.
    The configure lines are the arguments that configure got, the env lines the runtime's environment, and the user
    line this test's user. Each path of a file line is under the root: the copies moved every path that the inputs read.
    After the file lines come one `excluded` line for each path left out, and then the tree lines of the whole root but
    those paths, each the hash of that tree alone. The build wrote no bytecode into the source tree."""
    stage = tmp_path / "stage"
    done = toolchain.run(f'oft_py_runtime || exit 1; oft_py_prebuilt_stage "{stage}"')
    assert done.returncode == 0, done.stderr
    assert not (toolchain.root / SOURCE / "Tools").exists()
    assert runtime_files(stage / "runtime") == runtime_files(toolchain.root / "work/build/pyrt/asan")
    # The manifest that oft_py_runtime wrote before the build, where a build that uses the runtime writes its own.
    assert (stage / "manifest").read_bytes() == (toolchain.root / "work/build/pyrt/asan.manifest").read_bytes()
    assert sorted(path.name for path in stage.iterdir()) == ["manifest", "runtime"]
    text = (stage / "manifest").read_bytes()
    lines = text.decode().splitlines()
    assert lines[-1] == f"key {sha256(text[:text.rindex(b'key ')])}"
    assert lines[0] == "flav asan"
    configure = (toolchain.scratch / "configure.args").read_text().splitlines()
    assert [line for line in lines if line.startswith("configure ")] == [f"configure {a}" for a in configure]
    assert [line for line in lines if line.startswith("make ")] == [f"make {target}" for target in TARGETS]
    assert [line.removeprefix("env ") for line in lines if line.startswith("env ")] == runtime_environment(toolchain)
    assert [line for line in lines if line.startswith("user ")] == [f"user {os.getuid()}"]
    assert not [line for line in lines if line.startswith(("precious ", "version "))]
    files = [line.split(" ")[1] for line in lines if line.startswith("file ")]
    # The tarball, the patch, Setup.local, the native Python and six scripts.
    assert len(files) == 10
    assert all(path.startswith(f"{toolchain.root}/") for path in files), files
    assert f"file {toolchain.root}/{RUNTIME_SH} {sha256((toolchain.root / RUNTIME_SH).read_bytes())}" in lines
    assert sum(line.startswith("packages ") for line in lines) == 1
    assert len(lines) == len(set(lines))
    # The mode and owner of each file of a file line, and of each directory above one, above the source tree and
    # /src/repo, and of the root and its split directories; no shim lines here (no release-target.sh shims).
    metas = [line for line in lines if line.startswith("meta ")]
    assert meta_line(toolchain.root / RUNTIME_SH) in metas
    for path in (toolchain.root, toolchain.root / "usr", toolchain.root / "opt", toolchain.root / "tmp",
                 toolchain.root / "work/build/pyrt", toolchain.root / "src/repo"):
        assert meta_line(path) in metas, path
    assert set(metas) >= {meta_line(pathlib.Path(path)) for path in files}
    assert metas == sorted(metas)
    # One excluded line for each path left out, the line for the targets' install prefixes, the line of /src/repo
    # (with no release-target.sh shims here, no shim lines), then the tree lines, each the hash of its tree alone, but
    # the paths left out: /etc's without Docker's files and the Java keystore; /usr/local's holds the builder's scripts,
    # which are left out.
    first = next(i for i, line in enumerate(lines) if line.startswith("excluded "))
    assert all(line.startswith(("flav ", "configure ", "make ", "env ", "user ", "file ", "packages ", "meta "))
               for line in lines[:first])
    after = first + len(FS_LEFT_OUT)
    assert lines[first:after] == [f"excluded {toolchain.root}/{path}" for path in FS_LEFT_OUT]
    assert lines[after:after + 2] == [
        f"excluded {toolchain.root}/opt/oft/<target>, each link to a directory under {toolchain.root}/work (a target's "
        "install prefix)", f"link {toolchain.root}/src/repo -> {toolchain.root}/work"]
    assert [line.rsplit(" ", 1)[0] for line in lines[after + 2:after + 2 + len(FS_TREES)]] == [
        f"tree {toolchain.root}/{path}" for path in FS_TREES]
    assert lines[after + 2 + len(FS_TREES):] == [lines[-1]]
    for path in FS_TREES:
        if path not in ("etc", "usr/local"):
            assert tree_line(toolchain, toolchain.root / path) in lines, path
    assert tree_line(toolchain, toolchain.root / "etc") not in lines
    for name in ("hosts", "hostname", "resolv.conf", "ssl/certs/java/cacerts"):
        (toolchain.root / "etc" / name).unlink()
    assert tree_line(toolchain, toolchain.root / "etc") in lines


def test_the_runtime_build_runs_in_its_own_environment(toolchain, tmp_path):
    """The runtime's build runs in the runtime's environment, whatever the build's own: configure sees the variables of
    OFT_PY_ENV_KEPT that the build has and the fixed ones (and what its shell adds: PWD, SHLVL, _), no other, and runs
    from the runtime's build directory, where HOME and TMPDIR are, made anew."""
    noise = {name: "a value of this build" for name in OUTSIDE if name not in ("PWD", "SHLVL", "_")}
    done = toolchain.run("oft_py_runtime", cwd=tmp_path, PKG_CONFIG_PATH="/opt/pc", **noise)
    assert done.returncode == 0, done.stdout + done.stderr
    rt = toolchain.root / "work/build/pyrt/asan"
    seen = [line for line in (toolchain.scratch / "configure.env").read_text().splitlines()
            if line.split("=", 1)[0] not in ("PWD", "OLDPWD", "SHLVL", "_")]
    assert seen == runtime_environment(toolchain, PKG_CONFIG_PATH="/opt/pc")
    assert (toolchain.scratch / "configure.pwd").read_text() == f"{rt}\n"
    assert (rt / ".home").is_dir() and (rt / ".tmp").is_dir()
    manifest = (toolchain.root / "work/build/pyrt/asan.manifest").read_text().splitlines()
    assert [line.removeprefix("env ") for line in manifest if line.startswith("env ")] == seen


def test_a_build_that_writes_into_the_source_tree_fails(toolchain):
    """The patched source tree is read-only to the runtime's build: a build whose make writes into it fails, and says
    so. (As root, the build runs as nobody, who cannot write the tree; this test's user owns it, so the check after
    the build is what fails it.)"""
    make = toolchain.tools / "make"
    make.write_text(make.read_text().replace("echo \"make $*\"",
                                             f'echo x >> "{toolchain.root / SOURCE}/Lib/os.py"; echo "make $*"', 1))
    done = toolchain.run("oft_py_runtime || exit 1")
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"oft-py: the runtime's build changed the patched source tree {toolchain.root / SOURCE}" in done.stderr
    assert not (toolchain.root / "work/build/pyrt/asan/.oft-built").exists()


def test_a_build_of_the_shipped_key_takes_the_shipped_runtime(toolchain):
    """A new build whose inputs are those of the shipped runtime takes it: it runs no configure and no make, its
    runtime's files are the shipped ones, it is marked built, and OFT_PY_RT names it. A second call in the same build
    finds it built. A build that records nothing copies no record."""
    shipped = toolchain.ship()
    done = toolchain.run('oft_py_runtime || exit 1; echo "rt=$OFT_PY_RT"; oft_py_runtime')
    assert done.returncode == 0, done.stderr
    rt = toolchain.root / "work/build/pyrt/asan"
    assert decided(toolchain, done) == [took(toolchain, shipped), f"rt={rt}",
                                        f"oft-py: runtime asan built already ({rt})"]
    assert marks(toolchain) == []
    assert runtime_files(rt) == runtime_files(shipped / "runtime")
    assert (rt / ".oft-built").exists()
    assert not list(toolchain.root.rglob("oft-py-runtime-*.jsonl"))


@pytest.mark.parametrize("ov_records", ["", None])
def test_a_build_that_records_nothing_takes_no_record(toolchain, ov_records):
    """With OV_RECORDS empty (compile without OV_RECORD=1) or unset, the build takes the runtime and no record."""
    shipped = toolchain.ship()
    done = toolchain.run("oft_py_runtime", OV_RECORDS=ov_records)
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done) == [took(toolchain, shipped)]
    assert not list(toolchain.root.rglob("oft-py-runtime-*.jsonl"))


def test_a_build_that_records_takes_the_shipped_records(toolchain, tmp_path):
    """With OV_RECORDS (compile with OV_RECORD=1), the shipped compile records go into $OV_RECORDS/compiles/ as one
    file, under a name that no record of record-compile can have, and the nosan objects into $OV_RECORDS/nosan/.
    compile's gathering then puts them in compiles.jsonl beside the build's own records, sorted."""
    shipped = toolchain.ship()
    records = tmp_path / "records"
    (records / "compiles").mkdir(parents=True)
    own = '{"sha256": "c", "output": "harness.o"}\n'
    (records / "compiles/Xq3vT9aPz0").write_text(own)
    done = toolchain.run("oft_py_runtime", OV_RECORDS=str(records))
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done) == [took(toolchain, shipped)]
    copied = [path for path in (records / "compiles").iterdir() if path.name != "Xq3vT9aPz0"]
    assert [path.name for path in copied] == ["oft-py-runtime-asan.jsonl"]
    assert not re.fullmatch(r"[A-Za-z0-9]{10}", copied[0].name)
    assert copied[0].read_bytes() == (shipped / "records/compiles.jsonl").read_bytes()
    assert {path.name: path.read_bytes() for path in (records / "nosan").iterdir()} == {
        path.name: path.read_bytes() for path in (shipped / "records/nosan").iterdir()}
    # compile's own command (infra/base-builder/compile).
    gathered = subprocess.run(["sh", "-c", 'find "$1" -type f -exec awk 1 {} + | LC_ALL=C sort', "sh",
                               str(records / "compiles")], capture_output=True, text=True, check=True).stdout
    assert gathered.splitlines() == sorted([own.strip()] + (shipped / "records/compiles.jsonl").read_text().splitlines())


def change_cflags(toolchain):
    return ({"CFLAGS": f"{BASE_CFLAGS} {SAN} -O2"}, f"env CFLAGS={BASE_CFLAGS} {SAN}",
            f"env CFLAGS={BASE_CFLAGS} {SAN} -O2")


def change_pkg_config(toolchain):
    # A variable of OFT_PY_ENV_KEPT that the shipped build had not.
    return {"PKG_CONFIG_PATH": "/opt/pc"}, "env PYTHONDONTWRITEBYTECODE=1", "env PKG_CONFIG_PATH=/opt/pc"


def change_base_cflags(toolchain):
    base = BASE_CFLAGS.replace("-Os", "-O2")
    return ({"BASE_CFLAGS": base}, f"configure {configure_arguments(toolchain)[11]}",
            f"configure {configure_arguments(toolchain, base)[11]}")


def change_file(toolchain, name, change):
    """Change the file `name` of the root with `change` (bytes -> bytes). The lines before and after."""
    path = toolchain.root / name
    before = path.read_bytes()
    path.write_bytes(change(before))
    return {}, f"file {path} {sha256(before)}", f"file {path} {sha256(path.read_bytes())}"


def change_compiler(toolchain):
    return change_tree(toolchain, "usr/bin", lambda tree: (tree / "clang").write_text(CLANG + "# a byte more\n"))


def change_wrap_list(toolchain):
    # The wrap list that the sealed configuration names, in /tmp, with the configuration as it is.
    return change_tree(toolchain, "tmp/asan-noiconv.wrap", lambda path: path.write_text(
        path.read_text() + "--wrap=iconv\n"))


def change_tool_in_tmp(toolchain):
    # A make in a directory of /tmp, first on the build's PATH: the key reads /tmp, and the runtime's PATH has no such
    # directory, so the build runs the image's make (built_here's marks) and makes what the shipped build made.
    def plant(tmp):
        (tmp / "make").write_text("#!/bin/sh\necho planted >> " + str(toolchain.scratch / "marks") + "\nexit 1\n")
        (tmp / "make").chmod(0o755)
    env, before, after = change_tree(toolchain, "tmp/tools", lambda tmp: tmp.mkdir() or plant(tmp))
    return ({"PATH": f"{toolchain.root}/tmp/tools:{toolchain.env['PATH']}"},
            f"tree {toolchain.root}/usr/bin " + tree_line(toolchain, toolchain.root / "usr/bin").rsplit(" ", 1)[1],
            after)


def change_link_target(toolchain):
    # What a link of /usr/bin leads to under /work, which the key leaves out: the key reads what it leads to.
    target = toolchain.root / "work/tools/tool"
    before = f"tree {target} {tree_line(toolchain, target).rsplit(' ', 1)[1]}"
    target.write_text("#!/bin/sh\necho another tool\n")
    return {}, before, f"tree {target} {tree_line(toolchain, target).rsplit(' ', 1)[1]}"


def change_script_mode(toolchain):
    # runtime.sh, which the runtime's build reads again, of another mode: the bytes alone are not the key.
    path = toolchain.root / RUNTIME_SH
    before = meta_line(path)
    path.chmod(0o600)
    return {}, before, meta_line(path)


def change_ancestor_mode(toolchain):
    # A directory that the tree lines split, /opt, which the runtime's build must search to reach its files there, of
    # another mode.
    path = toolchain.root / "opt"
    before = meta_line(path)
    path.chmod(0o711)
    return {}, before, meta_line(path)



def change_patch(toolchain):
    # One byte of the patch: the first letter of its description.
    return change_file(toolchain, PATCH, lambda data: bytes([data[0] ^ 1]) + data[1:])


def change_runtime_sh(toolchain):
    # One line of runtime.sh, a comment, so that the copy runs as before.
    return change_file(toolchain, RUNTIME_SH, lambda data: data.replace(b"Theorem Labs, PBC\n", b"Theorem Labs PBC\n", 1))


def change_tree(toolchain, name, change):
    """Change the tree `name` of the root with `change` (its path -> None). Its tree lines before and after."""
    tree = toolchain.root / name
    unfollowed = '"$(oft_py_fs_unfollowed)"'
    before = tree_line(toolchain, tree, left_out='"$(oft_py_fs_left_out)"', own=unfollowed) if tree.exists() else ""
    change(tree)
    return {}, before, tree_line(toolchain, tree, left_out='"$(oft_py_fs_left_out)"', own=unfollowed)


def change_sysroot_file(toolchain):
    return change_tree(toolchain, "opt/musl-sysroot", lambda tree: (tree / "usr/include/stdio.h").write_text(
        "int printf(const char *restrict, ...);\n"))


def change_sysroot_link(toolchain):
    def repoint(tree):
        (tree / "usr/lib/libc.so").unlink()
        (tree / "usr/lib/libc.so").symlink_to("../lib/libc.a")
    return change_tree(toolchain, "opt/musl-sysroot", repoint)


def same_size_and_time(path, change):
    """Change the bytes of the file at `path` with `change` (bytes -> bytes of the same length), and give it back its
    time: a check by size and time sees no change."""
    info = path.stat()
    data = path.read_bytes()
    path.write_bytes(change(data))
    assert len(path.read_bytes()) == len(data)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))


def change_make(toolchain):
    # make on PATH replaced by another make of the same size and time, which works as the first.
    return change_tree(toolchain, "usr/bin", lambda tree: same_size_and_time(
        tree / "make", lambda data: data.replace(b"A stand-in", b"A stand-iN", 1)))


def change_source_byte(toolchain):
    # One byte of the cached patched source tree, which oft_py_source does not lay out again (.oft-src-ok).
    return change_tree(toolchain, SOURCE, lambda tree: same_size_and_time(
        tree / "Lib/os.py", lambda data: data.replace(b"sys", b"sYs", 1)))


def change_source_configure(toolchain):
    # The cached source tree's configure, a comment of it.
    return change_tree(toolchain, SOURCE, lambda tree: same_size_and_time(
        tree / "configure", lambda data: data.replace(b"A stand-in", b"A stand-iN", 1)))


def change_usr_lib(toolchain):
    return change_tree(toolchain, "usr/lib", lambda tree: (tree / "libz.a").write_bytes(b"!<arch>\nanother zlib\n"))


def change_ld_path(toolchain):
    # The search path of musl's dynamic loader, which no file of the image had.
    return change_tree(toolchain, "etc", lambda tree: (tree / "ld-musl-x86_64.path").write_text("/opt/lib\n"))


def change_unrelated(toolchain):
    # A file of a directory that no build reads: the whole file system is keyed.
    return change_tree(toolchain, "opt/unrelated", lambda tree: (tree / "README").write_text("another text\n"))


def change_shim_make(toolchain):
    # A make in $SHIM, which is first on PATH: the runtime's build would run it.
    return change_tree(toolchain, "tmp/shim", lambda tree: (tree / "make").write_text(
        "#!/bin/sh\nexec make \"$@\"\n"))


def change_shim_clang(toolchain):
    # A clang in $SHIM, which the compiler shims run by its name.
    return change_tree(toolchain, "tmp/shim", lambda tree: (tree / "clang").write_text(
        "#!/bin/sh\nexec clang \"$@\"\n"))


def change_shim_tool(toolchain):
    # A tool wrapper that toolchain.sh writes in $SHIM, of other text.
    return change_tree(toolchain, "tmp/shim", lambda tree: (tree / "riscv64-linux-musl-ar").write_text(
        '#!/bin/sh\nexec llvm-ar-19 "$@"\n'))


def change_opt_oft(toolchain):
    # A file of the toolchain's own in /opt/oft, beside the targets' prefixes.
    return change_tree(toolchain, "opt/oft", lambda tree: (tree / "bin/riscv64-linux-musl-clang-plain").write_text(
        "#!/bin/sh\nexec clang -O0 \"$@\"\n"))


def change_user_site(toolchain):
    # A .pth file in the native Python's user site directory, under the home directory, which the build's Python reads.
    def add(tree):
        site = tree / ".local/lib/python3.11/site-packages"
        site.mkdir(parents=True)
        (site / "a.pth").write_text("import os\n")
    return change_tree(toolchain, "root", add)


def change_repo_link(toolchain):
    # /src/repo, through which the build reads its source tree, pointed at another tree: a copy of /work, here.
    repo, other = toolchain.root / "src/repo", toolchain.root / "elsewhere"
    shutil.copytree(toolchain.root / "work", other, symlinks=True)
    repo.unlink()
    repo.symlink_to(other)
    return {}, f"link {repo} -> {toolchain.root}/work", f"link {repo} -> {other}"


@pytest.mark.parametrize("change", [change_base_cflags, change_cflags, change_pkg_config, change_compiler,
                                    change_wrap_list, change_patch, change_runtime_sh, change_sysroot_file,
                                    change_sysroot_link, change_make, change_source_byte, change_source_configure,
                                    change_usr_lib, change_ld_path, change_unrelated, change_shim_make,
                                    change_shim_clang, change_shim_tool, change_opt_oft, change_user_site,
                                    change_repo_link, change_tool_in_tmp, change_link_target, change_script_mode,
                                    change_ancestor_mode])
def test_a_build_with_another_input_builds_its_own_and_names_it(toolchain, change):
    """A build that differs from the shipped runtime in one input builds its own runtime, and its built-here line
    names that input as the shipped runtime had it and as this build has it: other BASE_CFLAGS (configure's CFLAGS),
    other CFLAGS, a PKG_CONFIG_PATH set, a compiler of other bytes, the wrap list that the sealed configuration names
    in /tmp, a byte of a patch, a line of runtime.sh, a file of the sysroot of other bytes, a link of the sysroot to
    another target, make on PATH replaced with the same size and time, a byte of the cached source tree, the cached
    source tree's configure, a library in /usr/lib, /etc/ld-musl-x86_64.path added, a file of a directory that no
    build reads, a make or a clang added to $SHIM (first on PATH), a tool wrapper of $SHIM of other text, a file of the
    toolchain's own in /opt/oft, a .pth file in the user site directory of /root, /src/repo pointed at another tree, a
    make in a directory of /tmp first on the build's PATH, what a link of /usr/bin leads to under /work, runtime.sh of
    another mode, and /opt of another mode. Its key differs. Each makes the shipped runtime's files: the stand-ins read
    none of these inputs, and the build runs none of the tools that a change adds outside the runtime's PATH."""
    link = toolchain.tools / "tool"
    (toolchain.root / "work/tools").mkdir(parents=True)
    (toolchain.root / "work/tools/tool").write_text("#!/bin/sh\necho a tool\n")
    link.symlink_to(toolchain.root / "work/tools/tool")
    shipped = toolchain.ship()
    env, shipped_line, this_line = change(toolchain)
    assert built_here(toolchain, shipped, toolchain.run("oft_py_runtime", **env)) == (shipped_line, this_line)
    assert runtime_files(toolchain.root / "work/build/pyrt/asan") == runtime_files(shipped / "runtime")


@pytest.mark.parametrize("change", [
    pytest.param(lambda root: (root / "src/upstream").mkdir() or (root / "src/upstream/x.c").write_text("int x;\n"),
                 id="src"),
    pytest.param(lambda root: (root / "work/ext/example/src").mkdir(parents=True)
                 or (root / "work/ext/example/src/x.c").write_text("int x;\n"), id="work-outside-the-source-tree"),
    pytest.param(lambda root: (root / "etc/hosts").write_text("hosts of another container\n"), id="etc-hosts"),
    pytest.param(lambda root: (root / "tmp/ov").mkdir() or (root / "tmp/ov/cli.o").write_bytes(b"an object\n"),
                 id="tmp-ov"),
    pytest.param(lambda root: (root / "root/.cache/pip").mkdir(parents=True)
                 or (root / "root/.cache/pip/x").write_text("a cache\n"), id="root-cache"),
    pytest.param(lambda root: (root / "var/cache/apk").mkdir(parents=True)
                 or (root / "var/cache/apk/x").write_text("a cache\n"), id="var-cache"),
    pytest.param(lambda root: (root / "etc/ssl/certs/java/cacerts").write_bytes(b"a keystore of other salts\n"),
                 id="java-keystore"),
    pytest.param(lambda root: (root / "opt/oft/example").symlink_to(
        root / "work/build/lib/asan/example"), id="opt-oft-a-target-prefix"),
    pytest.param(lambda root: (root / "proc/mounts").write_text("mounts of another container\n"),
                 id="what-a-link-leads-to-in-proc"),
])
def test_a_change_of_a_path_left_out_changes_nothing(toolchain, change):
    """A build whose file system differs from the shipped runtime's only in paths that the key leaves out takes the
    shipped runtime: a file of the project's sources under /src, a file under /work outside the source tree,
    /etc/hosts, a file under /tmp/ov, a cache under the home directory and under /var/cache, the Java keystore (to
    which the Java runtime's keystore in /usr/lib/jvm is a link, as in the image), a target's install prefix in
    /opt/oft, and what a link of /etc leads to under /proc, the container's own."""
    (toolchain.root / "proc").mkdir()
    (toolchain.root / "proc/mounts").write_text("mounts of this container\n")
    (toolchain.root / "etc/mtab").symlink_to("../proc/mounts")
    (toolchain.root / "usr/lib/jvm/java-17-openjdk/lib/security").mkdir(parents=True)
    (toolchain.root / "usr/lib/jvm/java-17-openjdk/lib/security/cacerts").symlink_to(
        toolchain.root / "etc/ssl/certs/java/cacerts")
    shipped = toolchain.ship()
    change(toolchain.root)
    done = toolchain.run("oft_py_runtime")
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done) == [took(toolchain, shipped)]


def test_a_tool_under_a_path_left_out_is_not_run(toolchain):
    """A make under /work, which the key leaves out, first on the build's PATH, changes nothing: the runtime's PATH
    does not have it, so a build takes the shipped runtime, and a build on an image that ships none runs the image's
    make, and makes what it made before."""
    tools = toolchain.root / "work/bin"
    tools.mkdir(parents=True)
    (tools / "make").write_text(f"#!/bin/sh\necho planted >> {toolchain.scratch / 'marks'}\nexit 1\n")
    (tools / "make").chmod(0o755)
    planted = {"PATH": f"{tools}:{toolchain.env['PATH']}"}
    shipped = toolchain.ship()
    done = toolchain.run("oft_py_runtime", **planted)
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done) == [took(toolchain, shipped)]
    expected = runtime_files(shipped / "runtime")
    shutil.rmtree(toolchain.root / "opt/oft-py/prebuilt")
    shutil.rmtree(toolchain.root / "work/build/pyrt/asan")
    done = toolchain.run("oft_py_runtime || exit 1", **planted)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "planted" not in marks(toolchain)
    assert runtime_files(toolchain.root / "work/build/pyrt/asan") == expected


def release_functions(toolchain):
    """The functions of release-target.sh that lay out a target and write the four compiler shims of its release
    layout, as ov_release_layout runs them, as they are in the file, with the root's $SHIM in place of /tmp/shim."""
    text = (BUILDER / "release-target.sh").read_text()
    found = []
    for name in ("ov_neutral", "rel_pair", "rel_pair_libcopy", "oft_write_cc_shim", "ov_release_variables",
                 "ov_release_shims"):
        start = text.index(f"\n{name}() {{\n") + 1
        found.append(text[start:text.index("\n}\n", start) + 3])
    return "".join(found).replace("/tmp/shim", str(toolchain.root / "tmp/shim"))


SHIMS = [f"riscv64-linux-musl-{name}" for name in ("clang-plain", "clang++-plain", "clang-sealed", "clang++-sealed")]


def layout(toolchain, target, records=False):
    """A script that lays out `target` as ov_target_begin does, with no dependency, and writes the shims of its release
    layout in $SHIM as a new container's ov_release_layout writes them: its variables (ov_release_variables, with no
    links made under /src), the four shims (ov_release_shims), the link script, and, with `records`, the fronts that
    record-compile --front puts before the shims when compile records the build (OV_RECORD=1)."""
    script = ('rm -rf "$SHIM/.recorded"; ' + release_functions(toolchain)
              + f'T={target}; DEPS=""; LIBREL=build/lib/asan; ov_neutral() {{ :; }}; ov_release_variables "$T"; '
              + 'ov_release_shims "$SHIM"; printf "SECTIONS { }\\n" > "$SHIM/oft-nogc-discard.ld"; ')
    if records:
        script += (f'bash -p "{toolchain.root}/usr/local/lib/oss-verify/record-compile" --front "$OV_RECORDS" '
                   '$(oft_py_shim_names | sed "s|^|$SHIM/|") || exit 1; ')
    return script


def recording(tmp_path, name="records"):
    """The OV_RECORDS of a build that records: a new directory."""
    records = tmp_path / name
    records.mkdir()
    return str(records)


def test_the_release_shims_are_keyed_as_release_target_writes_them(toolchain, tmp_path):
    """The four compiler shims that release-target.sh writes for a target name the target, and their fronts the
    records' directory: each is in the key by the line `shim <name> as release-target.sh writes it, for no target
    <SHA-256>`, when it is the text that ov_release_shims writes from the layout's variables (behind the front that
    record-compile writes, when compile records), with the SHA-256 of the text that it writes for no target. So the
    shipped runtime, made for one target without records, is taken by a build of another target, and by a build that
    records."""
    shipped = toolchain.ship(before=layout(toolchain, "example"))
    example = (toolchain.root / "tmp/shim" / SHIMS[0]).read_text()
    assert "/work/ext/example/" in example
    lines = (shipped / "manifest").read_text().splitlines()
    shims = [line for line in lines if line.startswith("shim")]
    assert [line.rsplit(" ", 1)[0] for line in shims] == [
        f"shim {name} as release-target.sh writes it, for no target" for name in SHIMS], shims
    assert all(re.fullmatch(r"[0-9a-f]{64}", line.rsplit(" ", 1)[1]) for line in shims), shims
    other = toolchain.run(layout(toolchain, "other") + "oft_py_runtime")
    assert other.returncode == 0, other.stdout + other.stderr
    assert decided(toolchain, other) == [took(toolchain, shipped)]
    assert (toolchain.root / "tmp/shim" / SHIMS[0]).read_text() == example.replace("example", "other")
    shutil.rmtree(toolchain.root / "work/build/pyrt/asan")
    records = recording(tmp_path)
    recorded = toolchain.run(layout(toolchain, "example", records=True) + "oft_py_runtime", OV_RECORDS=records)
    assert recorded.returncode == 0, recorded.stdout + recorded.stderr
    assert (toolchain.root / "tmp/shim" / SHIMS[0]).read_text().splitlines()[1] == "# record-compile front"
    assert decided(toolchain, recorded) == [took(toolchain, shipped)]


def shim_text(toolchain):
    # A byte more in one shim, after release-target.sh wrote it.
    return "", f'echo "# a byte more" >> "$SHIM/{SHIMS[0]}"; ', f"shim {SHIMS[0]} "


def front_text(toolchain):
    # The front of one shim, of other text.
    return "records", f'sed -i "s|exec |exec env |" "$SHIM/{SHIMS[2]}"; ', f"shim {SHIMS[2]} "


def recorded_copy(toolchain):
    # The copy of one shim behind its front, of other text.
    return "records", f'echo "# a byte more" >> "$SHIM/.recorded/{SHIMS[1]}"; ', f"shim {SHIMS[1]} "


def path_rewrite_off(toolchain):
    # The layout with the path rewrite turned off, as a target's block may turn it off, unexported: release-target.sh
    # writes the shims of that mode, so they are its text, but not the text of the shipped runtime's layout.
    return "", "", f"shim {SHIMS[0]} as release-target.sh writes it, for no target "


def another_librel(toolchain):
    # The shims written again from a layout in another LIBREL, whose path pairs meet the runtime's own trees.
    return "", 'LIBREL=build/pyrt; ov_release_variables "$T"; ov_release_shims "$SHIM"; ', f"shim {SHIMS[0]} "


def changed_variables(toolchain):
    # The shims written again from changed variables of the layout: more flags, as a build.sh could give them.
    return "", 'OFT_REL_FLAGS="$OFT_REL_FLAGS -O0"; ov_release_shims "$SHIM"; ', f"shim {SHIMS[0]} "


def recorded_extra(toolchain):
    # An entry of $SHIM/.recorded that is no copy of a shim.
    return "records", 'printf "#!/bin/sh\\n" > "$SHIM/.recorded/make"; ', "shim-extra .recorded/make "


def shim_mode(toolchain):
    # One shim that its user may not run, its text as release-target.sh writes it.
    return "", f'chmod 644 "$SHIM/{SHIMS[0]}"; ', f"meta shim {SHIMS[0]} 444 "


def recorded_copy_mode(toolchain):
    # The copy behind one front that its user may not run, its text as release-target.sh writes it.
    return "records", f'chmod 644 "$SHIM/.recorded/{SHIMS[1]}"; ', f"meta shim {SHIMS[1]} 555 "


def recorded_directory_mode(toolchain):
    # The directory of the copies behind the fronts, which others (the runtime's user) may not search, the shims and
    # their copies as they are.
    return "records", 'chmod 754 "$SHIM/.recorded"; ', f"meta shim {SHIMS[0]} 555 "


@pytest.mark.parametrize("change", [shim_text, path_rewrite_off, another_librel, changed_variables, front_text,
                                    recorded_copy, recorded_extra, shim_mode, recorded_copy_mode,
                                    recorded_directory_mode])
def test_a_shim_of_other_text_builds_its_own_and_names_it(toolchain, tmp_path, change):
    """A compiler shim of other text than release-target.sh writes, the shims of the layout with the path rewrite
    turned off (by a variable that is not exported), the shims of a layout in another LIBREL, shims written again
    from changed variables of the layout, a front of other text, a copy behind a front of other text, another entry in
    $SHIM/.recorded, a shim that its user may not run, a copy behind a front that its user may not run, and
    $SHIM/.recorded that its user may not search each change the key: the build builds its own runtime, and the line
    names the shim."""
    records, edit, this = change(toolchain)
    changes = {"OV_RECORDS": recording(tmp_path, "shipped-records")} if records else {}
    shipped = toolchain.ship(before=layout(toolchain, "example", records=bool(records)), **changes)
    changes = {"OV_RECORDS": recording(tmp_path)} if records else {}
    mode = "OV_PATH_REWRITE=off; " if change is path_rewrite_off else ""
    done = toolchain.run(mode + layout(toolchain, "example", records=bool(records)) + edit + "oft_py_runtime",
                         **changes)
    shipped_line, this_line = built_here(toolchain, shipped, done)
    assert this_line.startswith(this), (shipped_line, this_line)


def test_a_target_name_that_is_not_plain_keys_the_shims_by_their_text(toolchain):
    """A target whose name has a slash gives path pairs that can meet the runtime's trees (/src/repo/build/... for the
    name repo/build), so the shims of its layout are keyed by their text, not as release-target.sh writes them: the
    build builds its own runtime, and the line names the shim by its SHA-256."""
    shipped = toolchain.ship(before=layout(toolchain, "example"))
    done = toolchain.run(layout(toolchain, "repo/build") + "oft_py_runtime")
    shipped_line, this_line = built_here(toolchain, shipped, done)
    assert shipped_line.startswith(f"shim {SHIMS[0]} as release-target.sh writes it, for no target "), shipped_line
    assert re.fullmatch(rf"shim {re.escape(SHIMS[0])} [0-9a-f]{{64}}", this_line), this_line


def test_a_manifest_with_other_exclusions_is_not_taken(toolchain):
    """The excluded lines are inputs too: a shipped manifest whose key is this build's, but that leaves out one path
    fewer, is not taken, and the line names the first excluded path where the two differ."""
    shipped = toolchain.ship()
    manifest = shipped / "manifest"
    hosts = f"excluded {toolchain.root}/etc/hosts\n"
    manifest.write_text(manifest.read_text().replace(hosts, "", 1))
    done = toolchain.run("oft_py_runtime")
    assert built_here(toolchain, shipped, done, same_key=True) == (
        f"excluded {toolchain.root}/etc/resolv.conf", hosts.strip())


@pytest.mark.parametrize("name", OUTSIDE)
def test_a_variable_outside_the_runtime_environment_changes_nothing(toolchain, tmp_path, name):
    """A build whose environment differs from the shipped runtime's in a variable that the runtime's environment does
    not hold takes the shipped runtime. (One that it holds builds its own: change_cflags and change_pkg_config above.)
    The value that a program reading the environment sees differs from the shipped build's: sh gives its children the
    working directory as PWD, whatever PWD it got, so the build with another PWD runs from another directory; busybox's
    sh adds one to SHLVL, so SHLVL is a number. OV_RECORDS names a directory, as compile's does."""
    shipped = toolchain.ship()
    value = {"OV_RECORDS": str(tmp_path / "records"), "SHLVL": "7"}.get(name, "a value of another build")
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    cwd = cwd if name == "PWD" else None
    seen = f"printenv {name} || echo unset"
    assert toolchain.run(seen, cwd=cwd, **{name: value}).stdout != toolchain.run(seen).stdout
    done = toolchain.run("oft_py_runtime", cwd=cwd, **{name: value})
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done) == [took(toolchain, shipped)]


def test_the_sysroot_counts_by_its_files_bytes_and_modes_not_their_times(toolchain):
    """The sysroot is in the key by its paths, types, files' bytes and modes and links' targets: a build whose sysroot
    files have other times takes the shipped runtime, and one whose header has another mode builds its own, since the
    runtime's build runs as a user whom the mode lets read it or not; the line names the tree."""
    shipped = toolchain.ship()
    tree = toolchain.root / "opt/musl-sysroot"
    for path in (tree / "usr/lib/libc.a", tree / "usr/include/stdio.h", tree / "usr/include"):
        os.utime(path, (1, 1))
    done = toolchain.run("oft_py_runtime")
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done) == [took(toolchain, shipped)]
    shutil.rmtree(toolchain.root / "work/build/pyrt/asan")
    before = tree_line(toolchain, tree)
    (tree / "usr/include/stdio.h").chmod(0o600)
    after = tree_line(toolchain, tree)
    assert before != after
    assert built_here(toolchain, shipped, toolchain.run("oft_py_runtime")) == (before, after)


# The stand-ins that the native Python of the root runs before a program of runtime.sh when OFT_TEST_STANDIN names
# this file: this user may not give a file to root or to nobody, nor switch to nobody. os.chown records each owner in
# the table OFT_TEST_OWNERS (by path), and fails when it gives root a path that ends with OFT_TEST_CHOWN_FAIL, as a
# close of the boundary does; os.stat and os.lstat report those owners; os.setgroups, os.setgid and os.setuid do
# nothing. With OFT_TEST_PROC, the program reads that directory for /proc, os.getuid and os.getgid give 0, and os.kill
# removes the process's directory there and records the call in OFT_TEST_KILLS.
STAND_IN = r'''
def _stand_in():
    import json, os, shutil, sys
    owners_file = os.environ["OFT_TEST_OWNERS"]
    fail = os.environ.get("OFT_TEST_CHOWN_FAIL", "")
    proc = os.environ.get("OFT_TEST_PROC", "")
    real_stat = os.stat
    def full(path, dir_fd):
        path = os.fsdecode(path)
        if dir_fd is not None and not path.startswith("/"):
            path = os.path.join(os.readlink("/proc/self/fd/%d" % dir_fd), path)
        return os.path.normpath(path)
    def owners():
        try:
            with open(owners_file) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    def chown(path, uid, gid, *, dir_fd=None, follow_symlinks=True):
        where = full(path, dir_fd)
        if fail and where.endswith(fail) and uid == 0:
            raise PermissionError(1, "a stand-in fault", where)
        real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        table = owners()
        table[where] = [uid, gid]
        with open(owners_file, "w") as f:
            json.dump(table, f)
    def stat(path, *, dir_fd=None, follow_symlinks=True):
        found = real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        owner = None if isinstance(path, int) else owners().get(full(path, dir_fd))
        if owner is None:
            return found
        values = list(found[:10])
        values[4:6] = owner
        return os.stat_result(values)
    def lstat(path, *, dir_fd=None):
        return stat(path, dir_fd=dir_fd, follow_symlinks=False)
    def kill(pid, signal):
        with open(os.environ["OFT_TEST_KILLS"], "a") as f:
            f.write("%d %d\n" % (pid, signal))
        shutil.rmtree(os.path.join(proc, str(pid)), ignore_errors=True)
    os.stat, os.lstat, os.chown = stat, lstat, chown
    os.setgroups = os.setgid = os.setuid = lambda *args: None
    program = sys.argv.pop(1)
    if proc:
        assert program.count('PROC = "/proc"') == 1
        program = program.replace('PROC = "/proc"', "PROC = %r" % proc)
        os.getuid = os.getgid = lambda: 0
        os.kill = kill
    return compile(program, "a program of runtime.sh", "exec")
# The program runs in this module, __main__, as with -c, so that its process pool finds its functions.
_program = _stand_in()
del _stand_in
exec(_program)
'''


def stand_in(toolchain, **options):
    """The environment that runs each program of runtime.sh after STAND_IN, with each option (OFT_TEST_<NAME>)."""
    prelude = toolchain.scratch / "stand-in.py"
    prelude.write_text(STAND_IN)
    return {"OFT_TEST_STANDIN": str(prelude), "OFT_TEST_OWNERS": str(toolchain.scratch / "owners.json"),
            **{f"OFT_TEST_{name.upper()}": value for name, value in options.items()}}


def boundary(toolchain, script, **options):
    """Run OFT_PY_BOUNDARY of runtime.sh, as `script` gives its arguments (a shell line after `set --`), after the
    stand-ins (stand_in, with each option). The result."""
    return toolchain.run(f'set -- {script}; "$OFT_PY_BPY" -I -S -c "$OFT_PY_BOUNDARY" "$@"',
                         **stand_in(toolchain, **options))


def states(toolchain, top):
    """{path: (mode, a link, uid, gid)} of top and each entry under it, each owner as the stand-ins record it."""
    table = toolchain.scratch / "owners.json"
    owners = json.loads(table.read_text()) if table.exists() else {}
    found = {}
    for path in [top, *top.rglob("*")]:
        info = path.lstat()
        uid, gid = owners.get(os.path.normpath(path), (info.st_uid, info.st_gid))
        found[str(path)] = (stat.S_IMODE(info.st_mode), stat.S_ISLNK(info.st_mode), uid, gid)
    return found


def boundary_tree(tmp_path):
    """A tree as the boundary meets it: a left-out /work, with the source tree and the build directory under it, a
    sibling of them, a file beside them, a link to the source tree, and the records directory, with a directory of
    records."""
    top = tmp_path / "fs"
    for directory in ("work/build/pyrt/src/Lib", "work/build/pyrt/asan", "work/ext/example/src",
                      "tmp/ov/records/compiles", "tmp/ov/bin"):
        (top / directory).mkdir(parents=True)
    (top / "work/build/pyrt/src/Lib/os.py").write_text("import sys\n")
    (top / "work/ext/example/src/x.h").write_text("#define X 1\n")
    (top / "work/x.h").write_text("#define X 2\n")
    (top / "work/link").symlink_to(top / "work/build/pyrt/src")
    (top / "tmp/ov/records/old").write_text("a record\n")
    (top / "tmp/ov/records/compiles/a").write_text("a compile record\n")
    (top / "tmp/ov/bin/cc").write_text("#!/bin/sh\n")
    return top


def close_args(state, top, user=65534):
    """The arguments of a close of the boundary on boundary_tree: the grants, the build directory and the records; the
    left-out /work and /tmp/ov; the needed source tree, build directory and records."""
    return (f'close "{state}" {user} "{top}/work/build/pyrt/asan\n{top}/tmp/ov/records" "{top}/work\n{top}/tmp/ov" '
            f'"{top}/work/build/pyrt/src\n{top}/work/build/pyrt/asan\n{top}/tmp/ov/records"')


def test_the_boundary_closes_what_the_build_does_not_need_and_gives_it_back(toolchain, tmp_path):
    """close takes the access of group and others off each left-out entry that holds no needed path, and gives it to
    root; it changes no needed path, nothing under one, no directory that holds one, and no link; it gives each entry
    of the grants to the user. open gives back each mode and owner, gives what the build made to this user, and the
    tree is as it was."""
    top = boundary_tree(tmp_path)
    state = tmp_path / "state"
    before = states(toolchain, top)
    done = boundary(toolchain, close_args(state, top))
    assert done.returncode == 0, done.stderr
    during = states(toolchain, top)
    closed = {path for path, (mode, link, uid, gid) in during.items() if not link and mode & 0o077 == 0}
    assert closed == {f"{top}/work/ext", f"{top}/work/x.h", f"{top}/tmp/ov/bin"}, closed
    assert all(during[path][2:] == (0, 0) for path in closed)
    granted = {path for path, (_, _, uid, gid) in during.items() if (uid, gid) == (65534, 65534)}
    assert granted == {f"{top}/work/build/pyrt/asan", f"{top}/tmp/ov/records", f"{top}/tmp/ov/records/old",
                       f"{top}/tmp/ov/records/compiles", f"{top}/tmp/ov/records/compiles/a"}, granted
    assert {path: value for path, value in during.items() if path not in closed | granted} == {
        path: value for path, value in before.items() if path not in closed | granted}
    (top / "tmp/ov/records/new").write_text("a record of the build\n")
    done = boundary(toolchain, f'open "{state}"')
    assert done.returncode == 0, done.stderr
    after = states(toolchain, top)
    assert after.pop(str(top / "tmp/ov/records/new"))[2:] == (os.getuid(), os.getgid())
    assert after == before


def test_the_boundary_is_given_back_when_its_taking_fails(toolchain, tmp_path):
    """A close that fails part of the way, after it has changed some entries, has written the state of what it
    changes, so that open gives each back, its mode and its owner."""
    top = boundary_tree(tmp_path)
    state = tmp_path / "state"
    before = states(toolchain, top)
    done = boundary(toolchain, close_args(state, top), chown_fail="/work/x.h")
    assert done.returncode != 0
    assert "a stand-in fault" in done.stderr
    assert states(toolchain, top)[f"{top}/work/ext"][0] & 0o077 == 0
    assert states(toolchain, top)[f"{top}/tmp/ov/records/old"][2] == 65534
    done = boundary(toolchain, f'open "{state}"')
    assert done.returncode == 0, done.stderr
    assert states(toolchain, top) == before


def test_the_boundary_gives_back_the_rest_when_an_entry_cannot_be_given_back(toolchain, tmp_path):
    """An entry that close closed, which is another entry at open (here, a file put in place of /work/x.h), is not
    changed: open fails and names it, and gives back every other entry."""
    top = boundary_tree(tmp_path)
    state = tmp_path / "state"
    before = states(toolchain, top)
    assert boundary(toolchain, close_args(state, top)).returncode == 0
    other = top / "work/x.h"
    os.chmod(other, 0o600)
    other.rename(top / "work/x.h.old")
    other.write_text("another file\n")
    done = boundary(toolchain, f'open "{state}"')
    assert done.returncode != 0
    assert f"oft-py: {other} cannot be given back: it is another entry than the one that close changed" in done.stderr
    after = states(toolchain, top)
    after.pop(str(top / "work/x.h.old"))
    assert {path: value for path, value in after.items() if path != str(other)} == {
        path: value for path, value in before.items() if path != str(other)}


def test_the_boundary_follows_no_link_that_the_build_put_in_place_of_a_directory(toolchain, tmp_path):
    """A link that the build put in place of a granted directory, to a directory outside the trees, leads nowhere:
    open changes nothing there, names each entry that it cannot reach, gives the link itself to this user, and gives
    back the rest."""
    top = boundary_tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a").write_text("a file of the host\n")
    os.chmod(outside / "a", 0o640)
    state = tmp_path / "state"
    before = states(toolchain, top)
    assert boundary(toolchain, close_args(state, top)).returncode == 0
    compiles = top / "tmp/ov/records/compiles"
    shutil.rmtree(compiles)
    compiles.symlink_to(outside)
    done = boundary(toolchain, f'open "{state}"')
    assert done.returncode != 0
    # The walk from / stops at the link itself (O_NOFOLLOW, with O_DIRECTORY: ENOTDIR, or ELOOP), before it opens
    # anything outside the trees.
    assert re.search(rf"oft-py: {re.escape(str(compiles))}/a cannot be given back: \[Errno "
                     rf"({errno.ENOTDIR}|{errno.ELOOP})\] ", done.stderr), done.stderr
    assert states(toolchain, outside) == {str(outside): states(toolchain, outside)[str(outside)],
                                          str(outside / "a"): (0o640, False, os.getuid(), os.getgid())}
    owners = json.loads((toolchain.scratch / "owners.json").read_text())
    assert not [path for path in owners if path.startswith(str(outside))], owners
    after = states(toolchain, top)
    assert after.pop(str(compiles))[1:] == (True, os.getuid(), os.getgid())
    assert after == {path: value for path, value in before.items() if not path.startswith(str(compiles))}


def fake_proc(tmp_path):
    """A /proc of the build's container: its mounts, a process of nobody, one of another user, and a zombie of
    nobody."""
    proc = tmp_path / "proc"
    (proc / "self").mkdir(parents=True)
    shutil.copyfile("/proc/self/mountinfo", proc / "self/mountinfo")
    for pid, state, uid in ((4242, "S (sleeping)", 65534), (4343, "S (sleeping)", 1000), (4444, "Z (zombie)", 65534)):
        (proc / str(pid)).mkdir()
        (proc / str(pid) / "status").write_text(f"Name:\tsh\nState:\t{state}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    return proc


@pytest.mark.parametrize("stops", [True, False], ids=["as-it-is", "control-with-no-stop"])
def test_the_boundary_stops_the_processes_of_the_build_user_before_it_gives_back(toolchain, tmp_path, stops):
    """As root, open first kills each process of the build's user that is no zombie, and no other process. The
    control: with open's call of stop taken out of runtime.sh, no process is killed, so this test can fail."""
    if not stops:
        path = toolchain.root / "usr/local/lib/oss-verify/python/runtime.sh"
        text = path.read_text()
        old = 'failed = stop(record["user"]) if os.getuid() == 0 and record["user"] != 0 else []'
        assert text.count(old) == 1
        path.write_text(text.replace(old, "failed = []"))
    top = boundary_tree(tmp_path)
    proc = fake_proc(tmp_path)
    state, kills = tmp_path / "state", tmp_path / "kills"
    options = {"proc": str(proc), "kills": str(kills)}
    assert boundary(toolchain, close_args(state, top), **options).returncode == 0
    done = boundary(toolchain, f'open "{state}"', **options)
    assert done.returncode == 0, done.stderr
    killed = kills.read_text().splitlines() if kills.exists() else []
    assert killed == (["4242 9"] if stops else [])
    assert ("oft-py: the boundary stopped process 4242 of user 65534" in done.stderr) == stops
    assert sorted(p.name for p in proc.iterdir()) == (["4343", "4444", "self"] if stops else
                                                       ["4242", "4343", "4444", "self"])


def test_the_boundary_enters_no_mount_point_of_a_grant(toolchain, tmp_path):
    """A mount point under a grant, here with the device of the grant (a bind mount has it), is not given to the user,
    nor anything under it, and open leaves it as it was. A grant that is a mount point itself: close fails and changes
    nothing. (The mount points are those of a stand-in /proc/self/mountinfo.)"""
    top = boundary_tree(tmp_path)
    proc = fake_proc(tmp_path)
    compiles = top / "tmp/ov/records/compiles"
    with open(proc / "self/mountinfo", "a") as f:
        f.write(f"99 35 8:1 / {compiles} rw,relatime - ext4 /dev/sda1 rw\n")
    state = tmp_path / "state"
    options = {"proc": str(proc), "kills": str(tmp_path / "kills")}
    before = states(toolchain, top)
    assert boundary(toolchain, close_args(state, top), **options).returncode == 0
    during = states(toolchain, top)
    assert [during[str(path)] for path in (compiles, compiles / "a")] == [before[str(path)]
                                                                         for path in (compiles, compiles / "a")]
    assert during[str(top / "tmp/ov/records/old")][2] == 65534
    done = boundary(toolchain, f'open "{state}"', **options)
    assert done.returncode == 0, done.stderr
    assert states(toolchain, top) == before
    with open(proc / "self/mountinfo", "a") as f:
        f.write(f"100 35 8:1 / {top}/work/build/pyrt/asan rw,relatime - ext4 /dev/sda1 rw\n")
    other = tmp_path / "other-state"
    done = boundary(toolchain, close_args(other, top), **options)
    assert done.returncode != 0
    assert f"oft-py: the grant {top}/work/build/pyrt/asan is a mount point: the boundary changes nothing" in done.stderr
    assert states(toolchain, top) == before
    assert not other.exists()


def fake_root(toolchain, **options):
    """The environment of a build of the root as root (id says so, OFT_TEST_ROOT), after the stand-ins: it takes the
    read boundary around the runtime's build, which runs as this user."""
    return {"OFT_TEST_ROOT": "1", **stand_in(toolchain, **options)}


def given_back(toolchain, before):
    """What is not given back after a build of the root as root, from `before` (of states): each entry that was there
    before and is not as it was, but in the runtime's build directory, which the build made anew; each entry that the
    build made and is not this user's; and whether the boundary's state is still there."""
    rt = str(toolchain.root / "work/build/pyrt/asan")
    after = states(toolchain, toolchain.root)
    changed = {path: (before[path], after.get(path)) for path in before
               if not path.startswith(rt + "/") and path != rt and after.get(path) != before[path]}
    made = {path: value for path, value in after.items() if path not in before and value[2:] != (os.getuid(),
                                                                                                   os.getgid())}
    return changed, made, (toolchain.root / "work/build/pyrt/asan.boundary").exists()


def no_exit_trap(toolchain):
    """Take out of the root's runtime.sh the trap that gives the boundary back when its subshell ends."""
    path = toolchain.root / "usr/local/lib/oss-verify/python/runtime.sh"
    text = path.read_text()
    old = re.compile(r"^        trap 'oft_py_boundary open .*' EXIT$", re.M)
    assert len(old.findall(text)) == 1
    path.write_text(old.sub("        :", text))


@pytest.mark.parametrize("trap", [True, False], ids=["as-it-is", "control-with-no-trap"])
@pytest.mark.parametrize("fault", ["close", "build"])
def test_a_build_as_root_gives_the_boundary_back_when_it_fails(toolchain, fault, trap):
    """A build as root whose boundary cannot be taken (the stand-in chown fails on /etc/hosts, after it closed other
    paths), or whose runtime's build fails (make exits 1), fails, and the trap gives back each path as it was. The
    control: with the trap taken out of runtime.sh, a path stays closed, so this test can fail."""
    if not trap:
        no_exit_trap(toolchain)
    if fault == "build":
        make = toolchain.tools / "make"
        make.write_text(make.read_text().replace("echo \"make $*\"", "exit 1", 1))
    before = states(toolchain, toolchain.root)
    options = {"chown_fail": "/etc/hosts"} if fault == "close" else {}
    done = toolchain.run("oft_py_runtime || exit 1", **fake_root(toolchain, **options))
    assert done.returncode == 1, done.stdout + done.stderr
    if fault == "close":
        assert "oft-py: the read boundary cannot be taken" in done.stderr
    changed, made, taken = given_back(toolchain, before)
    if trap:
        assert (changed, made, taken) == ({}, {}, False)
    else:
        assert changed, "with no trap, the boundary stays taken"


@pytest.mark.parametrize("trap", [True, False], ids=["as-it-is", "control-with-no-trap"])
def test_a_build_as_root_gives_the_boundary_back_when_it_is_stopped(toolchain, trap):
    """A build as root that a TERM signal stops while the runtime builds gives the boundary back: the subshell's TERM
    trap exits, and its EXIT trap gives back each path. The control: with the TERM trap taken out of runtime.sh, the
    subshell dies of the signal and runs no EXIT trap, so this test can fail."""
    if not trap:
        path = toolchain.root / "usr/local/lib/oss-verify/python/runtime.sh"
        text = path.read_text()
        assert text.count("trap 'exit 143' TERM") == 1
        path.write_text(text.replace("trap 'exit 143' TERM", ":"))
    started = toolchain.scratch / "started"
    make = toolchain.tools / "make"
    make.write_text(f"#!/bin/sh\necho started > {started}\nexec sleep 60\n")
    before = states(toolchain, toolchain.root)
    environment = {**toolchain.env, **fake_root(toolchain)}
    recipes = toolchain.root / "usr/local/lib/oss-verify/python/recipes.sh"
    build = subprocess.Popen(["sh", "-c", f'. "$1"; oft_jobs() {{ echo 2; }}; SAN="{SAN}"; oft_py_runtime', "sh",
                              str(recipes)], env=environment, cwd=toolchain.root, start_new_session=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 60
        while not started.exists():
            assert build.poll() is None and time.monotonic() < deadline, build.communicate()
            time.sleep(0.05)
        os.killpg(build.pid, signal.SIGTERM)
        build.communicate(timeout=60)
        state = toolchain.root / "work/build/pyrt/asan.boundary"
        while state.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(build.pid, signal.SIGKILL)
    changed, made, taken = given_back(toolchain, before)
    if trap:
        assert (changed, made, taken) == ({}, {}, False)
    else:
        assert changed, "with no TERM trap, the boundary stays taken"


def rich_tree(top):
    """A tree of each type of entry, with names of printable ASCII other than \\ and ' (spaces, $, ", !, `, * and
    others): files of many sizes, one of 4 MiB and one empty; links to a file, to a directory, to nothing and to an
    absolute path; an empty directory; a FIFO."""
    for directory in ("usr/lib/pkgconfig", "usr/include/sys", "usr/share/empty dir"):
        (top / directory).mkdir(parents=True)
    for n in range(40):
        (top / "usr/lib" / f"lib{n}.a").write_bytes(bytes([n]) * (n * 977))
    (top / "usr/lib/big.a").write_bytes(b"0123456789abcdef" * (1 << 18))
    (top / 'usr/include/sys/a b $c "d" !e `f` *g ~h:i.h').write_text("int x;\n")
    (top / "usr/include/empty.h").write_bytes(b"")
    (top / "usr/lib/pkgconfig/libc.pc").write_text("Name: c\n")
    (top / "usr/lib/libc.so").symlink_to("lib0.a")
    (top / "usr/lib/include").symlink_to("../include")
    (top / "usr/lib/gone").symlink_to("nowhere")
    (top / "usr/lib/abs").symlink_to('/opt/x y $z "w"')
    (top / 'usr/include/link $1 "q"').symlink_to("sys/a b")
    os.mkfifo(top / "usr/share/fifo")
    return top


def test_the_pooled_tree_hash_is_the_serial_one(toolchain, tmp_path):
    """OFT_PY_TREE gives the hash that the serial listing gives (SERIAL_TREE), on a tree of each type of entry, with
    one processor (no pool), two and every processor this test may run on; and on the root's sysroot."""
    tree = rich_tree(tmp_path / "tree")
    serial = serial_sha(toolchain, tree)
    available = sorted(os.sched_getaffinity(0))
    for cpus in ({available[0]}, set(available[:2]), set(available)):
        assert tree_sha(toolchain, tree, cpus) == serial, len(cpus)
    sysroot = toolchain.root / "opt/musl-sysroot"
    assert tree_sha(toolchain, sysroot) == serial_sha(toolchain, sysroot)


def test_the_trees_of_one_pass_are_each_trees_own(toolchain, tmp_path):
    """In one pass of OFT_PY_TREE, a directory to split gives a line for each entry in it, sorted, but those left out,
    and each line is that tree's own hash, which the serial listing gives too: here, of usr/include, of usr/lib
    without the file left out (its largest), and of usr/share, from the tree of each type of entry."""
    tree = rich_tree(tmp_path / "tree")
    big = tree / "usr/lib/big.a"
    done = toolchain.run(f'"$OFT_PY_BPY" -I -S -c "$OFT_PY_TREE" "{big}" "{tree} {tree}/usr" "" "{tree}"')
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    big.unlink()
    assert lines == [f"tree {tree}/usr/{name} {serial_sha(toolchain, tree / 'usr' / name)}"
                     for name in ("include", "lib", "share")]


def test_a_link_target_cannot_make_two_trees_hash_alike(toolchain, tmp_path):
    """A name or a link's target that is not all printable ASCII other than \\ and ' is written $'...', so that each
    entry is one line. Written as it is, a link whose target holds a newline and then the text of another link's line
    would list as the same lines as the two links: OFT_PY_TREE tells the two trees apart."""
    top = tmp_path / "tree"

    def tree_hash(links):
        shutil.rmtree(top, ignore_errors=True)
        top.mkdir()
        for name, target in links.items():
            (top / name).symlink_to(target)
        return tree_sha(toolchain, top)

    assert tree_hash({"l": f"v'\n{top}/m l '{top}/m' -> 'w"}) != tree_hash({"l": "v", "m": "w"})


def test_names_that_are_not_printable_ascii_are_told_apart(toolchain, tmp_path):
    """Trees that differ only in a name or a link's target that is not all printable ASCII other than \\ and ' hash
    apart, and each tree hashes the same twice."""
    top = tmp_path / "tree"
    names = [b"a\nb", b"a\\nb", b"a'b", b"a\\'b", b"$'a'", b"caf\xc3\xa9", b"caf\xe9", b"a\tb", b"a\\x09b", b"ab"]

    def tree_hash(kind, name):
        shutil.rmtree(top, ignore_errors=True)
        top.mkdir()
        if kind == "file":
            (top / os.fsdecode(name)).write_text("x")
        else:
            (top / "link").symlink_to(os.fsdecode(name))
        return tree_sha(toolchain, top)

    seen = {}
    for kind in ("file", "link"):
        for name in names:
            seen[kind, name] = tree_hash(kind, name)
            assert tree_hash(kind, name) == seen[kind, name]
    assert len(set(seen.values())) == len(seen)


def test_made_from_is_not_compared(toolchain):
    """The manifest's made-from line, after its key, is for an audit: a shipped runtime made from another image's
    digest is taken all the same."""
    shipped = toolchain.ship()
    manifest = shipped / "manifest"
    manifest.write_text(manifest.read_text().replace(MADE_FROM, MADE_FROM.replace("1" * 64, "2" * 64)))
    done = toolchain.run("oft_py_runtime")
    assert decided(toolchain, done) == [took(toolchain, shipped)], done.stderr


def test_a_manifest_of_other_inputs_under_this_key_is_not_taken(toolchain):
    """The shipped runtime is taken only when its manifest, up to its key, is this build's byte for byte: a manifest
    of other inputs in the directory of this build's key builds here, and the line names the input."""
    shipped = toolchain.ship()
    manifest = shipped / "manifest"
    path = f"env PATH={toolchain.env['PATH']}"
    manifest.write_text(manifest.read_text().replace(path, path + ":/elsewhere"))
    done = toolchain.run("oft_py_runtime")
    assert built_here(toolchain, shipped, done, same_key=True) == (path + ":/elsewhere", path)


def test_another_builds_runtime_is_not_taken(toolchain):
    """An image that ships the plain build's runtime ships none for the asan build."""
    toolchain.ship("plain")
    done = toolchain.run("oft_py_runtime")
    assert done.returncode == 0, done.stderr
    assert decided(toolchain, done)[0] == ("oft-py: runtime asan: built here: this toolchain image ships no prebuilt "
                                           f"runtime ({toolchain.root}/opt/oft-py/prebuilt/asan-*)")
    assert marks(toolchain)[0] == "configure"


def test_a_shipped_runtime_that_is_not_whole_fails_the_build(toolchain):
    """A shipped runtime of this build's key without one of its files fails the build, rather than linking without it."""
    shipped = toolchain.ship()
    (shipped / "runtime/target-frozen.txt").unlink()
    done = toolchain.run("oft_py_runtime || exit 1")
    assert done.returncode == 1
    assert f"oft-py: the shipped runtime {shipped} has no target-frozen.txt" in done.stderr


def test_a_taken_runtime_is_not_staged(toolchain, tmp_path):
    """oft_py_prebuilt_stage refuses a runtime that the build took from the image: only one built here is staged."""
    toolchain.ship()
    done = toolchain.run(f'oft_py_runtime || exit 1; oft_py_prebuilt_stage "{tmp_path / "again"}" || exit 3')
    assert done.returncode == 3
    assert "oft_py_prebuilt_stage: no runtime built here" in done.stderr
    assert not (tmp_path / "again").exists()


def test_the_stage_refuses_inputs_that_changed_while_the_runtime_was_built(toolchain, tmp_path):
    """oft_py_prebuilt_stage reads the inputs again, and fails, staging no manifest, when they differ from those that
    oft_py_runtime read before the build: no build could take that runtime. The message names the input."""
    stage = tmp_path / "stage"
    header = toolchain.root / "opt/musl-sysroot/usr/include/stdio.h"
    done = toolchain.run(f'oft_py_runtime || exit 1; echo "int puts(const char *);" >> "{header}"; '
                         f'oft_py_prebuilt_stage "{stage}" || exit 3')
    assert done.returncode == 3, done.stderr
    assert ("oft-py: oft_py_prebuilt_stage: the inputs of the asan runtime changed while it was built: it was built "
            f"with tree {toolchain.root}/opt/musl-sysroot ") in done.stderr
    assert not (stage / "manifest").exists()


def test_the_stage_reads_the_source_tree_again(toolchain, tmp_path):
    """The patched source tree is among the inputs that oft_py_prebuilt_stage reads again: one that changed after the
    runtime was built fails the stage, and the message names the tree."""
    stage = tmp_path / "stage"
    source = toolchain.root / SOURCE
    done = toolchain.run(f'oft_py_runtime || exit 1; echo x >> "{source}/Lib/os.py"; '
                         f'oft_py_prebuilt_stage "{stage}" || exit 3')
    assert done.returncode == 3, done.stderr
    assert f"it was built with tree {source} " in done.stderr
    assert not (stage / "manifest").exists()


def staging_tree(path, content=b"the archive\n"):
    """A staging tree as the make script lays it out, with an executable file too."""
    top = path / "opt/oft-py/prebuilt" / ("asan-" + "0" * 64)
    (top / "runtime/Modules/expat").mkdir(parents=True)
    (top / "records/nosan").mkdir(parents=True)
    (top / "runtime/libpython3.11.a").write_bytes(content)
    (top / "runtime/Modules/expat/libexpat.a").write_bytes(b"expat\n")
    (top / "records/compiles.jsonl").write_text('{"sha256": "a"}\n')
    (top / "manifest").write_text("flav asan\nkey " + "0" * 64 + "\n")
    (top / "runtime/tool").write_text("#!/bin/sh\n")
    (top / "runtime/tool").chmod(0o700)
    return path


def layer(staging, out):
    return subprocess.run([sys.executable, "-P", str(SCRIPTS / "layer.py"), str(staging), str(out)],
                          capture_output=True, text=True, timeout=60)


def test_the_layer_is_the_same_bytes_for_the_same_files(tmp_path):
    """The same files give the same layer, whatever their times and modes on disk; a file of other bytes gives
    another layer."""
    first = staging_tree(tmp_path / "first")
    assert layer(first, tmp_path / "first.tar").returncode == 0
    for directory, names, files in os.walk(first):
        for name in names + files:
            path = os.path.join(directory, name)
            os.utime(path, (1234567890, 1234567890))
            mode = os.stat(path).st_mode
            os.chmod(path, 0o700 if stat.S_ISDIR(mode) else (0o711 if mode & 0o100 else 0o600))
    assert layer(first, tmp_path / "again.tar").returncode == 0
    assert (tmp_path / "again.tar").read_bytes() == (tmp_path / "first.tar").read_bytes()
    other = staging_tree(tmp_path / "other", content=b"the archive, changed\n")
    assert layer(other, tmp_path / "other.tar").returncode == 0
    assert (tmp_path / "other.tar").read_bytes() != (tmp_path / "first.tar").read_bytes()


def test_the_layer_holds_the_tree_with_fixed_metadata(tmp_path):
    """The layer's entries are opt/oft-py/prebuilt and what is under it, sorted, with mtime 0, uid and gid 0, no user
    or group name, and mode 0755 (a directory or an executable file) or 0644. The files on disk are this user's."""
    staging = staging_tree(tmp_path / "staging")
    done = layer(staging, tmp_path / "layer.tar")
    assert done.returncode == 0, done.stderr
    top = "opt/oft-py/prebuilt"
    key = "asan-" + "0" * 64
    with tarfile.open(tmp_path / "layer.tar") as tar:
        members = tar.getmembers()
        assert [member.name for member in members] == [
            top, f"{top}/{key}", f"{top}/{key}/manifest", f"{top}/{key}/records", f"{top}/{key}/records/compiles.jsonl",
            f"{top}/{key}/records/nosan", f"{top}/{key}/runtime", f"{top}/{key}/runtime/Modules",
            f"{top}/{key}/runtime/Modules/expat", f"{top}/{key}/runtime/Modules/expat/libexpat.a",
            f"{top}/{key}/runtime/libpython3.11.a", f"{top}/{key}/runtime/tool"]
        for member in members:
            assert (member.mtime, member.uid, member.gid, member.uname, member.gname) == (0, 0, 0, "", "")
            assert member.isdir() or member.isfile()
            executable = member.isdir() or member.name.endswith("/tool")
            assert member.mode == (0o755 if executable else 0o644), member.name
        assert tar.extractfile(f"{top}/{key}/runtime/libpython3.11.a").read() == b"the archive\n"
    assert (staging / top).stat().st_uid == os.getuid()


@pytest.mark.parametrize("make_bad", ["link", "outside", "fifo"])
def test_the_layer_refuses_what_is_not_a_runtime_tree(tmp_path, make_bad):
    """layer.py refuses a symbolic link, a file outside opt/oft-py/prebuilt, and a FIFO, and writes nothing."""
    staging = staging_tree(tmp_path / "staging")
    top = staging / "opt/oft-py/prebuilt"
    if make_bad == "link":
        (top / "link").symlink_to("asan-" + "0" * 64)
    elif make_bad == "outside":
        (staging / "opt/oft-py/native").mkdir()
    else:
        os.mkfifo(top / "fifo")
    done = layer(staging, tmp_path / "layer.tar")
    assert done.returncode == 1, done.stderr
    assert done.stderr.startswith("layer.py: ")
    assert not (tmp_path / "layer.tar").exists()


def test_layer_usage(tmp_path):
    assert layer(tmp_path, "").returncode == 1
    done = subprocess.run([sys.executable, "-P", str(SCRIPTS / "layer.py")], capture_output=True, text=True)
    assert done.returncode == 2 and done.stderr.startswith("usage: ")


@pytest.mark.parametrize("arguments", [[], ["ghcr.io/x/y@sha256:" + "0" * 64], ["ghcr.io/x/y:latest", "localhost:5000/x:t"],
                                       ["ghcr.io/x/y@sha256:" + "0" * 64, "localhost:5000/x"],
                                       ["ghcr.io/x/y@sha256:" + "0" * 64, "localhost:5000/x@sha256:" + "0" * 64]])
def test_make_usage_errors_exit_2_before_docker(tmp_path, arguments):
    """make exits 2 on a usage error: not two arguments, a base image not named by its digest, a target that is not
    <repository>:<tag>. It runs no docker for them."""
    docker = tmp_path / "docker"
    docker.write_text(f"#!/bin/sh\necho ran > '{tmp_path}/docker-ran'\nexit 1\n")
    docker.chmod(0o755)
    done = subprocess.run(["bash", str(SCRIPTS / "make"), *arguments], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"})
    assert done.returncode == 2, done.stderr
    assert done.stderr.startswith("usage: make BASE_IMAGE TARGET")
    assert not (tmp_path / "docker-ran").exists()


def test_make_checks_the_files_of_runtime_sh(toolchain):
    """The files that make requires of each build are OFT_PY_RT_FILES of runtime.sh."""
    listed = toolchain.run('printf "%s\\n" $OFT_PY_RT_FILES').stdout.split()
    text = (SCRIPTS / "make").read_text()
    files = re.search(r'^runtime_files="([^"]*)"', text, re.M).group(1).split()
    assert listed == files == RUNTIME_FILES
