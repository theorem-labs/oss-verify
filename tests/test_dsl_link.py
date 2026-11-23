# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The DSL form of infra/base-builder/link-fuzz-target, and its gates (infra/base-builder/dsl.py), at a real linker:
uv run pytest tests/test_dsl_link.py

The script runs as tests/test_allocation_library_links.py runs it: a copy, with /tmp/ov/ replaced by a scratch
directory, and native tools in place of the target's (objcopy as llvm-objcopy, nm as llvm-nm). The fixture is a small
DSL fuzz target: a driver object that defines what cli.c calls, a library whose malloc and open the maps rename, and a
trampoline object that defines the new names. No Docker, toolchain image or external repository."""
import os
import pathlib
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = ROOT / "infra/base-builder"
TOOLS = ("cc", "ar", "objcopy", "objdump", "nm")

LIBRARY = r'''#include <fcntl.h>
#include <stdlib.h>
int library_test(void) {
  void *p = malloc(8);
  if (!p) return 3;
  free(p);
  return open("/the-trampoline-answers", O_RDONLY) == 42 ? 0 : 4;
}
'''
DRIVER = r'''#include <stddef.h>
#include <stdlib.h>
int library_test(void);
void tramp_arm(unsigned bits);
unsigned tramp_count(void);
const char *target_name(void) { return "dsl"; }
void target_alloc_init(unsigned bits) { tramp_arm(bits); }
unsigned target_alloc_count(void) { return tramp_count(); }
int target_run(const unsigned char *c, size_t cn, const unsigned char *p, size_t pn) {
  (void)c; (void)cn; (void)p; (void)pn;
  void *q = malloc(4); /* the driver's own allocation, renamed by OV_DSL_REDEFS too */
  if (!q) return 5;
  free(q);
  return library_test();
}
'''
# A driver that calls a name of the library map itself.
OPENING_DRIVER = DRIVER.replace("return library_test();", 'return open("x", 0) + library_test();').replace(
    "#include <stdlib.h>", "#include <stdlib.h>\n#include <fcntl.h>")
TRAMPOLINES = r'''#include <stddef.h>
#include <stdlib.h>
static unsigned bits, calls;
void tramp_arm(unsigned b) { bits = b; calls = 0; }
unsigned tramp_count(void) { return calls; }
void *tramp_malloc(size_t n) { unsigned i = calls++; return i < 32 && (bits >> i & 1) ? NULL : malloc(n); }
int tramp_open(const char *path, int flags, ...) { (void)path; (void)flags; return 42; }
'''
# An object of the link's own that defines a new name of the library map, which only a trampoline may define.
IMPOSTOR = "int tramp_open(const char *path, int flags, ...) { (void)path; (void)flags; return 42; }\n"
# The review's bypass: with -Wl,--wrap=tramp_open, the library's renamed open goes to __wrap_tramp_open, which calls the
# real open. The linker writes its -y trace before it applies --wrap, so only the refusal of the wrap stops it.
WRAP = r'''#include <fcntl.h>
int __wrap_tramp_open(const char *path, int flags, ...) { return open(path, flags); }
'''
# Objects that already name a new name of a map, or that call one from where they may not.
EARLY = "#include <stddef.h>\nvoid *tramp_malloc(size_t);\nint early(void) { return tramp_malloc(1) != 0; }\n"
OWN = "#include <stddef.h>\nvoid *tramp_malloc(size_t);\nvoid *own_alloc(void) { return tramp_malloc(1); }\n"
TRAMP_CALLS_OPEN = "int tramp_open(const char *, int, ...);\nint tramp_two(void) { return tramp_open(\"x\", 0); }\n"
# A library split in two members: the one the driver pulls allocates and opens nothing; the other, which nothing
# pulls, calls open.
SPLIT_TEST = r'''#include <stdlib.h>
int library_test(void) { void *p = malloc(8); if (!p) return 3; free(p); return 0; }
'''
SPLIT_OPEN = "#include <fcntl.h>\nint unused_open(void) { return open(\"x\", O_RDONLY); }\n"
# A stand-in llvm-objcopy that copies its input to its output and renames nothing.
COPYING_OBJCOPY = '#!/bin/sh\neval "src=\\${$(($# - 1))}" "dst=\\${$#}"\ncp -- "$src" "$dst"\n'


@pytest.fixture(scope="session")
def objects(tmp_path_factory):
    """cli.o, the driver objects and their quiet builds, the trampolines and the library's archive, compiled once."""
    if any(shutil.which(tool) is None for tool in TOOLS):
        pytest.skip("native C compiler, ar, objcopy, objdump and nm are required")
    directory = tmp_path_factory.mktemp("dsl-objects")
    common = ["cc", "-O0", "-fno-stack-protector", "-fno-builtin-malloc", "-I", str(BASE / "driver")]

    def run(*args):
        done = subprocess.run(args, cwd=directory, capture_output=True, text=True, timeout=30)
        assert done.returncode == 0, done.stderr
        return done

    run(*common, "-c", str(BASE / "driver/cli.c"), "-o", "cli.o")
    run(*common, "-c", str(BASE / "driver/wrap_getenv.c"), "-o", "wrap_getenv.o")
    sources = {"library.c": LIBRARY, "dsl.c": DRIVER, "opening.c": OPENING_DRIVER, "tramp.c": TRAMPOLINES,
               "impostor.c": IMPOSTOR, "wrap.c": WRAP, "early.c": EARLY, "own.c": OWN,
               "tramp_two.c": TRAMP_CALLS_OPEN, "split_test.c": SPLIT_TEST, "split_open.c": SPLIT_OPEN}
    for name, text in sources.items():
        (directory / name).write_text(text)
        run(*common, "-c", name, "-o", name[:-2] + ".o")
    run(*common, "-DHARNESS_QUIET", "-c", "dsl.c", "-o", "dsl-quiet.o")
    # ar names the object's format, so that it loads no linker plugin (tests/test_allocation_library_links.py).
    form = run("objdump", "-f", "library.o").stdout.split("file format ", 1)[1].split()[0]
    run("ar", f"--target={form}", "rcs", "libfixture.a", "library.o")
    run("ar", f"--target={form}", "rcs", "libearly.a", "early.o")
    run("ar", f"--target={form}", "rcs", "libsplit.a", "split_test.o", "split_open.o")
    return directory


@pytest.fixture
def dsl(objects, tmp_path):
    executable = tmp_path / "bin"
    executable.mkdir()
    (executable / "llvm-objcopy").symlink_to(shutil.which("objcopy"))
    (executable / "llvm-nm").symlink_to(shutil.which("nm"))
    for path in objects.iterdir():
        shutil.copy(path, tmp_path / path.name)
    scratch = tmp_path / "ov"
    (scratch / "twins").mkdir(parents=True)
    (scratch / "link.env").write_text(
        "OV_LFE='normal-engine'\nOV_DRIVER='cli.o adapter.o'\nOV_CLI='cli.o'\n"
        "OV_AFE='failure-engine'\nOV_AFC='counting-engine'\nOV_DSLE='dsl-engine'\n"
        "OV_AF_DRIVER='cli.o af.o'\nOV_AFC_DRIVER='cli.o count.o'\n"
        "OV_SEALS=''\nOV_SILENT_LD=''\nOV_AF_RENAME=''\n"
        f"OV_TWINS='{scratch / 'twins'}'\nOV_RECORDS=''\nOV_BUILD='plain'\n")
    script = tmp_path / "link-fuzz-target"
    script.write_text((BASE / "link-fuzz-target").read_text().replace("/tmp/ov/", f"{scratch}/"))
    script.chmod(0o755)
    shutil.copy(BASE / "dsl.py", tmp_path / "dsl.py")
    (tmp_path / "both.redefs").write_text("# the allocator, for the library and the driver\nmalloc tramp_malloc\n")
    (tmp_path / "sys.redefs").write_text("open tramp_open\n")
    (tmp_path / "sys.allow").write_text("free  # allocates nothing\n")

    def settings(**changes):
        env = {k: v for k, v in os.environ.items() if not k.startswith("OV_")}
        env["PATH"] = f"{executable}:{os.environ['PATH']}"
        env.update(OV_DSL_DRIVER=str(tmp_path / "dsl.o"), OV_DSL_REDEFS=str(tmp_path / "both.redefs"),
                   OV_DSL_LIBRARY_REDEFS=str(tmp_path / "sys.redefs"), OV_DSL_TRAMPOLINES=str(tmp_path / "tramp.o"),
                   OV_DSL_ALLOW=str(tmp_path / "sys.allow"))
        for name, value in changes.items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        return env

    def link(*arguments, **changes):
        command = [str(script), "cc", "dsl-engine", *(arguments or ("libfixture.a",)), "-o", "target"]
        return subprocess.run(command, cwd=tmp_path, env=settings(**changes), capture_output=True, text=True,
                              timeout=60)

    def run(header):
        (tmp_path / "input").write_bytes(header)
        return subprocess.run([str(tmp_path / "target"), str(tmp_path / "input")], cwd=tmp_path,
                              capture_output=True, text=True, timeout=30).returncode

    return SimpleNamespace(link=link, run=run, dir=tmp_path, scratch=scratch)


def refused(done, words):
    assert done.returncode != 0, "the link was made"
    assert "link-fuzz-target:" in done.stderr and words in done.stderr, done.stderr


def test_the_dsl_link_renames_the_library_and_the_driver(dsl):
    """cli.o calls the driver object's target_run; the driver's malloc (call 0) and the library's (call 1) reach the
    trampoline, so the allocation mask fails each one; the library's open reaches the trampoline, never the kernel.
    The link leaves the mark from which compile lists the target in $OUT/.dsl-fuzz-targets, and nothing else of its
    own in the scratch directory."""
    done = dsl.link()
    assert done.returncode == 0, done.stderr
    assert dsl.run(bytes(6)) == 0
    assert dsl.run(b"\0\0\1\0\0\0") == 5
    assert dsl.run(b"\0\0\2\0\0\0") == 3
    assert dsl.run(b"\0\x80\0\0\0\0") == 2  # counting mode: the two allocations
    assert len(list((dsl.scratch / "dsl-targets").iterdir())) == 1
    assert not list(dsl.scratch.glob("dsl.*"))


def test_one_map_alone(dsl):
    """A target with no library map needs no allow list: the census is the library map's."""
    done = dsl.link(OV_DSL_LIBRARY_REDEFS=None, OV_DSL_ALLOW=None,
                    OV_DSL_TRAMPOLINES=str(dsl.dir / "tramp.o"))
    assert done.returncode == 0, done.stderr
    assert dsl.run(b"\0\0\2\0\0\0") == 3
    assert dsl.run(bytes(6)) == 4  # the real open, which finds no file


@pytest.mark.parametrize("arguments, words", [
    (("-L.", "-lfixture"), "without -l"),
    (("-Wl,--whole-archive", "libfixture.a"), "no linker option"),
    (("-Xlinker", "libfixture.a"), "without -l"),
    (("@objects.rsp",), "on the command line"),
    (("library.c",), "compile a DSL fuzz target's sources first"),
    (("library.o",), "names no archive of the library"),
])
def test_inputs_that_could_hide_a_call_are_refused(dsl, arguments, words):
    (dsl.dir / "objects.rsp").write_text("libfixture.a\n")
    refused(dsl.link(*arguments), words)


def test_a_driver_that_calls_a_library_map_name_is_refused(dsl):
    refused(dsl.link(OV_DSL_DRIVER=str(dsl.dir / "opening.o")), "of a library map")


def test_the_census_refuses_a_call_no_one_answers(dsl):
    (dsl.dir / "sys.allow").write_text("# nothing\n")
    refused(dsl.link(), "census: the library copies call free")


def test_a_map_over_nothing_is_refused(dsl):
    (dsl.dir / "sys.redefs").write_text("fcntl tramp_fcntl\n")
    refused(dsl.link(), "renames no reference")


def test_a_library_that_defines_an_old_name_is_refused(dsl):
    (dsl.dir / "both.redefs").write_text("malloc tramp_malloc\nlibrary_test renamed_test\n")
    refused(dsl.link(), "defines library_test itself")


@pytest.mark.parametrize("text, words", [
    ("malloc a\ncalloc a\n", "rename 2 names to a"),
    ("malloc a\nmalloc b\n", "rename malloc 2 times"),
    ("malloc open\n", "as an old name and as a new name"),
    ("malloc\n", "a pair is two names"),
    ("# only a comment\n", "the map has no pair"),
])
def test_bad_maps_are_refused(dsl, text, words):
    (dsl.dir / "both.redefs").write_text(text)
    refused(dsl.link(), words)


@pytest.mark.parametrize("changes, words", [
    ({"OV_DSL_DRIVER": None}, "OV_DSL_DRIVER must name at least one file"),
    ({"OV_DSL_REDEFS": None, "OV_DSL_LIBRARY_REDEFS": None}, "names at least one map"),
    ({"OV_DSL_ALLOW": None}, "needs OV_DSL_ALLOW"),
    ({"OV_DSL_DRIVER": "dsl.o"}, "is not an absolute path"),
])
def test_bad_declarations_are_refused(dsl, changes, words):
    refused(dsl.link(**changes), words)


def test_the_trace_refuses_a_new_name_that_no_trampoline_defines(dsl):
    """An object of the link's own that defines a new name of the library map takes the library's calls away from
    the trampolines; the -y trace of the first link shows it, and the output is removed."""
    (dsl.dir / "tramp-noopen.c").write_text(TRAMPOLINES.split("int tramp_open")[0])
    built = subprocess.run(["cc", "-O0", "-fno-stack-protector", "-c", "tramp-noopen.c", "-o", "tramp-noopen.o"],
                           cwd=dsl.dir, capture_output=True, text=True, timeout=30)
    assert built.returncode == 0, built.stderr
    done = dsl.link("libfixture.a", "impostor.o", OV_DSL_TRAMPOLINES=str(dsl.dir / "tramp-noopen.o"))
    refused(done, "tramp_open is defined by")
    assert not (dsl.dir / "target").exists()


def test_a_wrap_of_a_new_name_is_refused(dsl):
    """The review's bypass: a wrap of a trampoline's name, with an object that defines its __wrap_, sends the library's
    calls past the trampoline, and the -y trace does not show it. The link refuses every wrap but the seals'."""
    refused(dsl.link("libfixture.a", "wrap.o", "-Wl,--wrap=tramp_open"), "takes no linker option but the seals'")
    refused(dsl.link("libfixture.a", "-Wl,--wrap=malloc"), "takes no linker option but the seals'")
    assert not (dsl.dir / "target").exists()
    # a seal's wrap, with the seal that defines its __wrap_, is the one the link takes
    done = dsl.link("libfixture.a", "wrap_getenv.o", "-Wl,--wrap=getenv")
    assert done.returncode == 0, done.stderr
    assert dsl.run(bytes(6)) == 0


def test_a_map_that_names_a_seal_is_refused(dsl):
    (dsl.dir / "both.redefs").write_text("malloc tramp_malloc\ngetenv tramp_getenv\n")
    refused(dsl.link(), "the maps name getenv, of a seal")


def test_conservation_refuses_a_copy_that_was_not_renamed(dsl):
    """With an llvm-objcopy that copies and renames nothing, each copy keeps its old names."""
    objcopy = dsl.dir / "bin" / "llvm-objcopy"
    objcopy.unlink()
    objcopy.write_text(COPYING_OBJCOPY)
    objcopy.chmod(0o755)
    refused(dsl.link(), "conservation:")


def test_a_library_or_a_driver_that_already_names_a_new_name_is_refused(dsl):
    refused(dsl.link("libearly.a"), "already names tramp_malloc, a new name of a map")
    refused(dsl.link(OV_DSL_DRIVER=str(dsl.dir / "early.o")), "already names tramp_malloc, a new name of a map")


def test_the_trace_refuses_a_reference_from_an_object_of_the_links_own(dsl):
    refused(dsl.link("libfixture.a", "own.o"), "own.o references tramp_malloc")
    assert not (dsl.dir / "target").exists()


def test_the_trace_refuses_a_trampoline_that_calls_a_library_map_name(dsl):
    trampolines = f"{dsl.dir / 'tramp.o'} {dsl.dir / 'tramp_two.o'}"
    refused(dsl.link(OV_DSL_TRAMPOLINES=trampolines), "tramp_two.o references tramp_open")


def test_the_trace_refuses_a_library_map_that_the_link_never_reaches(dsl):
    """The library calls open only in a member that nothing pulls into the link: the map renames a reference, so the
    gates before the link pass, but the schedule of the six calls would cover nothing that runs."""
    refused(dsl.link("libsplit.a"), "the link takes no reference from the library to any of tramp_open")
    assert not (dsl.dir / "target").exists()
