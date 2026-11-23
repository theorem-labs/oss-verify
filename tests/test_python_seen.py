# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for infra/base-builder/python/seen.py and the guard of python/recipes.sh that reads it: a build's configure
starts from the builder's answers only where its container shows what the builder's configure saw
(oft_py_runtime_configure). These run here, on a tree of their own, with this Python as the toolchain's and a stand-in
for CPython's configure; tests/test_builder.py's PythonBuilder runs the guard in the builder, on the toolchain image.
"""
import os
import pathlib
import stat
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON = ROOT / "infra" / "base-builder" / "python"
# recipes.sh, sourced as a build.sh sources it, with stand-ins for what needs the toolchain image: the CPython source
# tree, configure (which writes a cache of one answer, and says "loading cache" when it is given one), and oft_py_seen
# on $TREE; the build directories are under $WORK. Its argument is the step: cache, oft_py_config_cache as the
# builder's build runs it, or configure, oft_py_runtime_configure as a build does.
GUARD = r"""
set -e
. "$PYTHON/recipes.sh"
OFT_PY_DIR=$PYTHON OFT_PY_CONFIG=$CONFIG OFT_PY_BPY=$INTERPRETER OFT_PY_RTS=$WORK/pyrt FLAV=plain
oft_py_source() { :; }
oft_py_seen() { "$OFT_PY_BPY" "$OFT_PY_DIR/seen.py" "$TREE"; }
oft_py_configure() {
  _rt=$1; shift
  : >> "$_rt/configure.log"
  for _a; do
    if [ "$_a" = --cache-file=config.cache ]; then
      echo "configure: loading cache config.cache" >> "$_rt/configure.log"
    fi
  done
  echo 'ac_cv_func_x=${ac_cv_func_x=yes}' >> "$_rt/config.cache"
}
case $1 in
  cache) oft_py_config_cache "$CONFIG/plain" ;;
  configure) oft_py_runtime_configure "$OFT_PY_RTS/$FLAV" ;;
esac
"""
# The environment of each run here, and so what seen.py compares of it: no variable of this process's, a locale (so
# that Python sets none for itself), and a PATH. GUARD's PATH also has the system's own programs, which it runs.
LOCALE = {"LC_ALL": "C.UTF-8"}
SYSTEM_PATH = "/usr/bin:/bin"


def seen(*tops, environment=None):
    """seen.py's lines for the directories `tops`, in `environment` (by default LOCALE and a PATH of one directory,
    bin under the first of `tops`, that may not be there)."""
    environment = {**LOCALE, "PATH": str(tops[0] / "bin"), **(environment or {})}
    return subprocess.run([sys.executable, str(PYTHON / "seen.py"), *map(str, tops)], capture_output=True,
                          check=True, env=environment).stdout.decode().splitlines()


# The modification time of each file of tree(), in seconds: long before the test, as a builder's files are before a
# project's Dockerfile runs, so a rewrite moves it.
BUILT = 1_700_000_000


def tree(directory):
    """A tree of what configure reads: two headers, one in a subdirectory, a library and a symbolic link, each file
    with the time BUILT."""
    (directory / "include" / "sys").mkdir(parents=True)
    (directory / "lib").mkdir()
    files = {"include/a.h": b"#define A 1\n", "include/sys/b.h": b"int b(void);\n", "lib/libx.a": b"!<arch>\n"}
    for name, data in files.items():
        (directory / name).write_bytes(data)
        os.utime(directory / name, (BUILT, BUILT))
    (directory / "include" / "c.h").symlink_to("a.h")
    return directory


def guard(tmp_path, step, **environment):
    """GUARD's step `step` in `tmp_path`, on the tree tmp_path/tree, with LOCALE, a PATH of the system's programs and
    `environment`: its exit status, and its output."""
    done = subprocess.run(["sh", "-c", GUARD, "sh", step], capture_output=True, text=True,
                          env={**LOCALE, "PATH": SYSTEM_PATH, "PYTHON": str(PYTHON), "CONFIG": str(tmp_path / "config"),
                               "INTERPRETER": sys.executable, "TREE": str(tmp_path / "tree"), "WORK": str(tmp_path),
                               **environment})
    return done.returncode, done.stdout + done.stderr


def described(path):
    """The line of seen.py for the file at `path`: its permissions, size and time."""
    status = os.lstat(path)
    return f"file {path} {stat.S_IMODE(status.st_mode):o} {status.st_size} {int(status.st_mtime)}"


def mode(path):
    """The permissions of the entry at `path`, in octal, as seen.py writes them."""
    return f"{stat.S_IMODE(os.lstat(path).st_mode):o}"


def test_each_entry_is_seen_with_its_kind_and_its_metadata(tmp_path):
    top = tree(tmp_path / "tree")
    include, lib = top / "include", top / "lib"
    assert seen(top) == [
        "environment LC_ALL=C.UTF-8", f"environment PATH={top}/bin",
        f"directory {top} {mode(top)}", f"directory {include} {mode(include)}",
        f"file {include}/a.h {mode(include / 'a.h')} 12 {BUILT}", f"link {include}/c.h -> a.h",
        f"directory {include}/sys {mode(include / 'sys')}",
        f"file {include}/sys/b.h {mode(include / 'sys' / 'b.h')} 13 {BUILT}",
        f"directory {lib} {mode(lib)}", f"file {lib}/libx.a {mode(lib / 'libx.a')} 8 {BUILT}"]


# Variables that differ from one run to the next whatever a project does, with a value each (seen.py's
# ENVIRONMENT_LEFT_OUT).
LEFT_OUT = {"HOSTNAME": "f00", "PWD": "/", "OLDPWD": "/src", "SHLVL": "3", "_": "/usr/bin/sh", "T": "example",
            "SRCDIR": "/work/ext/example/src", "BUILDDIR": "/work/build/lib/plain/example",
            "OFT_PREFIX": "/opt/oft/example", "OV_RECORD": "1", "OV_RECORDS": "/tmp/ov/records", "OV_LAYOUT": "1",
            "OV_BASE_LAYOUT": "/ov/base-layout", "OFT_MAKE_JOBS": "8", "OV_CONFIG_CACHE_DIR": "/oft-py-config"}


def test_each_variable_of_the_environment_is_seen_but_those_that_differ_run_to_run(tmp_path):
    """A variable is seen with its value, a newline in it escaped; the variables of LEFT_OUT are not. Control: one more
    variable beside them is."""
    top = tree(tmp_path / "tree")
    before = seen(top)
    assert seen(top, environment=LEFT_OUT) == before
    after = seen(top, environment={**LEFT_OUT, "OFT_TEST_VARIABLE": "a\nb"})
    assert [line for line in after if line not in before] == ["environment OFT_TEST_VARIABLE=a\\nb"]


def test_each_directory_on_path_is_walked(tmp_path):
    """Each directory on PATH is walked as the others are: a tool in a directory that PATH names is seen."""
    top = tree(tmp_path / "tree")
    tools = with_a_tool(tmp_path / "tools")
    lines = seen(top, environment={"PATH": f"{tools}:{top}/bin"})
    assert f"environment PATH={tools}:{top}/bin" in lines
    assert [f"directory {tools} {mode(tools)}", described(tools / "pkg-config")] == [
        line for line in lines if line.startswith(("directory", "file")) and str(tools) in line]


def test_a_directory_on_path_through_a_link_is_walked(tmp_path):
    """A PATH entry that is a symbolic link to a directory of tools: the link is seen, and so is each tool of the
    directory that it reaches."""
    top = tree(tmp_path / "tree")
    tools = with_a_tool(tmp_path / "tools")
    (tmp_path / "linked").symlink_to(tools)
    lines = seen(top, environment={"PATH": f"{tmp_path}/linked"})
    assert f"link {tmp_path}/linked -> {tools}" in lines
    assert described(tools / "pkg-config") in lines


def with_a_tool(directory):
    """`directory`, with a pkg-config in it, a program that CPython's configure looks for on PATH."""
    directory.mkdir()
    (directory / "pkg-config").write_text("#!/bin/sh\nexit 1\n")
    (directory / "pkg-config").chmod(0o755)
    return directory


def appended(path):
    """A line added to the end of the file at `path`, as a project's build.sh might."""
    with open(path, "ab") as handle:
        handle.write(b"#define EXTRA 1\n")


def rewritten(path):
    """The file at `path` rewritten with sed -i, to bytes of the same length."""
    subprocess.run(["sed", "-i", "s/A 1/A 2/", str(path)], check=True)


def made_executable(path):
    path.chmod(0o755)


# The changes of a tree that what configure sees must show, and that the guard must refuse the answers for: {what:
# (the change, the file of tree() that it changes)}.
CHANGES = {
    "a line added to a header": (appended, "include/a.h"),
    "a header rewritten by sed -i, at its length": (rewritten, "include/a.h"),
    "a library made executable": (made_executable, "lib/libx.a"),
}


@pytest.mark.parametrize("change", sorted(CHANGES))
def test_a_change_of_a_file_is_seen(tmp_path, change):
    """A change that moves a file's size, time or permissions changes what is seen, and only that file's line. Control:
    the same tree is seen the same twice."""
    alter, name = CHANGES[change]
    top = tree(tmp_path / "tree")
    before, line = seen(top), described(top / name)
    assert seen(top) == before
    alter(top / name)
    after = seen(top)
    assert ([old for old in before if old not in after], [new for new in after if new not in before]) == (
        [line], [described(top / name)])


def test_a_link_that_points_elsewhere_is_seen(tmp_path):
    top = tree(tmp_path / "tree")
    (top / "include" / "c.h").unlink()
    (top / "include" / "c.h").symlink_to("sys/b.h")
    assert f"link {top}/include/c.h -> sys/b.h" in seen(top)


def test_an_edit_that_keeps_the_size_and_the_time_is_not_seen(tmp_path):
    """The limit, by design (seen.py): an edit at the same length whose time is put back (touch -r) is not seen. It
    takes intent, and reading every file's bytes in each build cost far more than the metadata (INFRA-5359)."""
    top = tree(tmp_path / "tree")
    before = seen(top)
    header = top / "include" / "a.h"
    header.write_bytes(b"#define A 2\n")
    os.utime(header, (BUILT, BUILT))
    assert seen(top) == before


# The changes of what configure sees for the guard: {what: (the change of the tree, the environment of the build's
# GUARD, the number of lines that differ, the first of them)}.
def guard_changes(tmp_path, top):
    tools, linked_tools = tmp_path / "tools", tmp_path / "linked-tools"
    changes = {what: (lambda alter=alter, name=name: alter(top / name), {}, 2, f"-file {top}/{name} ")
               for what, (alter, name) in CHANGES.items()}
    changes["one more variable"] = (lambda: None, {"OFT_TEST_VARIABLE": "1"}, 1, "+environment OFT_TEST_VARIABLE=1 ")
    changes["a directory of tools on PATH"] = (
        lambda: with_a_tool(tools), {"PATH": f"{tools}:{tmp_path}/bin:{SYSTEM_PATH}"}, 4,
        f"-environment PATH={tmp_path}/bin:{SYSTEM_PATH} +environment PATH={tools}:")
    changes["a tool changed in a directory that a link on PATH reaches"] = (
        lambda: appended(linked_tools / "pkg-config"), {}, 2, f"-file {linked_tools}/pkg-config ")
    return changes


@pytest.mark.parametrize("change", sorted([*CHANGES, "one more variable", "a directory of tools on PATH",
                                           "a tool changed in a directory that a link on PATH reaches"]))
def test_the_guard_refuses_the_answers_once_what_configure_sees_changes(tmp_path, change):
    """oft_py_runtime_configure where the builder's answers were got (the same tree, the same environment) starts from
    them (the control); once a file of the tree changes (CHANGES), the build has one more variable, or its PATH has a
    directory of tools, it says that configure can see another environment or other files, shows the first lines that
    differ, and asks every question itself."""
    top = tree(tmp_path / "tree")
    alter, environment, count, first = guard_changes(tmp_path, top)[change]
    # Every run has on PATH a link to a directory of tools: the tool that it reaches is seen as any other.
    with_a_tool(tmp_path / "linked-tools")
    (tmp_path / "bin").symlink_to(tmp_path / "linked-tools")
    linked = {"PATH": f"{tmp_path}/bin:{SYSTEM_PATH}"}
    code, out = guard(tmp_path, "cache", **linked)
    assert code == 0, out
    code, out = guard(tmp_path, "configure", **linked)
    assert (code, out.splitlines()) == (0, [f"oft-py: runtime plain: configure started from the builder's 1 answers "
                                            f"({tmp_path}/config/plain/config.cache)"]), out
    alter()
    code, out = guard(tmp_path, "configure", **{**linked, **environment})
    assert code == 0, out
    lines = out.splitlines()
    assert len(lines) == 2, out
    assert lines[0].startswith("oft-py: runtime plain: configure can see another environment or other files here "
                               f"than when the builder got its answers ({tmp_path}/config/plain/seen): {count} lines "
                               f"differ, such as {first}"), out
    assert lines[1] == "oft-py: runtime plain: configure asked every question itself", out
    assert "configure: loading cache" not in (tmp_path / "pyrt" / "plain" / "configure.log").read_text()
