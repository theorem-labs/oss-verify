# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checks of the binaries that need no Docker: tools/check_links.py, tools/model_release.py and
tools/check_binaries.py. python3 -m pytest tools/tests"""
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_binaries  # noqa: E402
import check_links  # noqa: E402
import model_release  # noqa: E402
from check_build import Failed  # noqa: E402

UNIMP = struct.pack("<I", check_links.TRAP)
NOP = struct.pack("<I", 0x00000013)  # addi x0, x0, 0
RET = struct.pack("<I", 0x00008067)  # jalr x0, 0(ra): a function with nothing for UBSan to check
LW = struct.pack("<I", 0x00052503)  # lw a0, 0(a0): a load UBSan checks (null, alignment)
ASAN = ["__asan_init", "__asan_version_mismatch_check_v8", "__asan_load4"]
# The release's fixed UBSan flags (infra/base-builder/toolchain.sh), and a compile's arguments with and without them.
UBSAN_FLAGS = ["-fsanitize=undefined", "-fno-sanitize-recover=all", "-fsanitize-trap=all", "-fno-sanitize=function"]
BASE = ["-march=rv64g", "-mabi=lp64d", "-Os", "-g", "-ffunction-sections", "-fdata-sections"]


def compile_arguments(source, flags=UBSAN_FLAGS, after=()):
    return BASE + list(flags) + ["-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION", "-c", source, "-o", "x.o", *after]


def elf_object(text=b"", defined=(), undefined=(), files=(), local=(), comment=False):
    """A minimal 64-bit little-endian relocatable ELF file: a .text section with `text`, a symbol table with the global
    functions `defined`, the local functions `local`, the undefined symbols `undefined` and the STT_FILE symbols
    `files`, and with `comment`, a .comment section as a compiler writes."""
    names = [b"", b".text", b".symtab", b".strtab", b".shstrtab"] + ([b".comment"] if comment else [])
    shstrtab = b"\0".join(names) + b"\0"
    offsets = {name: shstrtab.index(name + b"\0") if name else 0 for name in names}
    strtab, symbols = b"\0", [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]

    def symbol(name, info, shndx):
        nonlocal strtab
        symbols.append(struct.pack("<IBBHQQ", len(strtab), info, 0, shndx, 0, 0))
        strtab += name.encode() + b"\0"

    for name in files:
        symbol(name, 4, 0xFFF1)  # STT_FILE, LOCAL, ABS
    for name in local:
        symbol(name, 2, 1)  # STT_FUNC, LOCAL, .text
    for name in defined:
        symbol(name, (1 << 4) | 2, 1)  # STT_FUNC, GLOBAL, .text
    for name in undefined:
        symbol(name, 1 << 4, 0)  # NOTYPE, GLOBAL, undefined
    symtab = b"".join(symbols)
    blobs = [text, symtab, strtab, shstrtab] + ([b"clang version 20.1.8\0"] if comment else [])
    data, at = bytearray(64), []
    for blob in blobs:
        at.append(len(data))
        data += blob
    shoff = len(data)
    headers = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
               struct.pack("<IIQQQQIIQQ", offsets[b".text"], 1, 0x6, 0, at[0], len(text), 0, 0, 4, 0),
               struct.pack("<IIQQQQIIQQ", offsets[b".symtab"], 2, 0, 0, at[1], len(symtab), 3, 1, 8, 24),
               struct.pack("<IIQQQQIIQQ", offsets[b".strtab"], 3, 0, 0, at[2], len(strtab), 0, 0, 1, 0),
               struct.pack("<IIQQQQIIQQ", offsets[b".shstrtab"], 3, 0, 0, at[3], len(shstrtab), 0, 0, 1, 0)]
    if comment:
        headers.append(struct.pack("<IIQQQQIIQQ", offsets[b".comment"], 1, 0x30, 0, at[4], len(blobs[4]), 0, 0, 1, 1))
    data += b"".join(headers)
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack("<HHIQQQIHHHHHH", 1, 0xF3, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), 4)
    data[:64] = header
    return bytes(data)


GO_SETTINGS = {"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true", "CGO_ENABLED": "0", "GOARCH": "riscv64",
               "GOOS": "linux", "GORISCV64": "rva20u64"}


# The functions of a minimal Go program: Go's runtime's unqualified assembly, and package-qualified code.
GO_FUNCTIONS = ("_rt0_riscv64_linux", "runtime.rt0_go", "compare", "main.main", "main")
NOP16 = struct.pack("<I", 0x00000013) * 4


def trampoline(offset, size=16):
    """A trampoline as Go's linker makes it: auipc x31, hi; jalr x0, lo(x31), a jump of `offset` bytes from its own
    start; then zero padding to `size` bytes."""
    high = (offset + 0x800) >> 12
    low = offset - (high << 12)
    return struct.pack("<II", ((high << 12) & 0xFFFFF000) | 0xF97, ((low & 0xFFF) << 20) | 0xF8067) + bytes(size - 8)


def go_function(item):
    """(name, bytes, has a line table) for an item of a function list: a name is 16 bytes of Go-compiled code."""
    return (item, NOP16, True) if isinstance(item, str) else item


def gopclntab(functions, skip=0, entries=None, shared_name=False, name_offset=None):
    """Go 1.27.1's function table (src/runtime/symtab.go pcHeader, runtime/runtime2.go _func) for `functions`
    ([go_function items]), laid out in order from .text's start plus `skip` bytes. A function with a line table gets
    pcfile, pcln and a compilation unit; one without gets 0, 0 and no unit, as a host object's code does. `entries`
    ({index: entry offset}) overrides entries of the function table; with `shared_name`, every function's name is the
    first function's; `name_offset` replaces every function's name offset."""
    names = b"".join(name.encode() + b"\0" for name, _, _ in (functions[:1] if shared_name else functions))
    name_offsets, at = [], 0
    for name, _, _ in functions:
        name_offsets.append(name_offset if name_offset is not None else 0 if shared_name else at)
        at += len(name) + 1
    names_at = 72
    pcln_at = names_at + len(names)
    funcs_at = (len(functions) + 1) * 8         # the _func records, after the function table, from pcln_at
    offsets, records, entry = [], b"", skip
    for (name, body, lines), name_off in zip(functions, name_offsets):
        offsets.append((entry, funcs_at + len(records)))
        records += struct.pack("<IiiIIIIII", entry, name_off, 0, 0, 1 if lines else 0, 1 if lines else 0,
                               1 if lines else 0, 0, 0 if lines else 0xFFFFFFFF)
        entry += len(body)
    offsets.append((entry, 0))
    for index, value in (entries or {}).items():
        offsets[index] = (value, offsets[index][1])
    table = b"".join(struct.pack("<II", *pair) for pair in offsets)
    header = struct.pack("<IHBB", 0xFFFFFFF1, 0, 1, 8)
    header += struct.pack("<8Q", len(functions), 0, 0, names_at, pcln_at, pcln_at, pcln_at, pcln_at)
    return header + names + table + records


def go_executable(section=b".go.buildinfo", flags=2, truncate=False, functions=GO_FUNCTIONS, text_size=None,
                  skip=0, entries=None, shared_name=False, name_offset=None, **settings):
    """A minimal riscv64 executable with a .text section of `skip` bytes of code that no function covers, then
    `functions` (go_function items; then zero padding up to `text_size`), their .gopclntab (gopclntab: `skip`,
    `entries`, `shared_name`), and the section `section` that holds Go's build information as Go 1.27.1 writes it
    (src/debug/buildinfo/buildinfo.go), with the `build` settings GO_SETTINGS and `settings` (None drops one)."""
    functions = [go_function(f) for f in functions]
    lines = ["path\tcommand-line-arguments"] + [f"build\t{key}={value}" for key, value in
                                                {**GO_SETTINGS, **settings}.items() if value is not None]
    # The 16-byte frames Go puts around the module information (cmd/go/internal/modload: infoStart, infoEnd), which
    # are not UTF-8.
    module = (b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6" + "".join(f"{line}\n" for line in lines).encode()
              + b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2")
    version = b"go1.27.1"
    body = b"\xff Go buildinf:" + bytes([8, flags]) + bytes(16)
    body += bytes([len(version)]) + version
    size = len(module) + (1000 if truncate else 0)
    body += bytes([0x80 | (size & 0x7F), size >> 7]) + module
    text = NOP16[:skip] + bytes(max(0, skip - 16)) + b"".join(code for _, code, _ in functions)
    text += bytes((text_size or len(text)) - len(text))
    pcln = gopclntab(functions, skip, entries, shared_name, name_offset)
    blobs = [(b".text", 1, 0x6, 0x11000, text), (section, 1, 0x3, 0x100000, body),
             (b".gopclntab", 1, 0x2, 0x200000, pcln)]
    shstrtab = b"\0" + b"".join(name + b"\0" for name, *_ in blobs) + b".shstrtab\0"
    data = bytearray(64)
    headers = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    name_at = 1
    for name, kind, sflags, addr, blob in blobs:
        headers.append(struct.pack("<IIQQQQIIQQ", name_at, kind, sflags, addr, len(data), len(blob), 0, 0, 16, 0))
        name_at += len(name) + 1
        data += blob
    headers.append(struct.pack("<IIQQQQIIQQ", name_at, 3, 0, 0, len(data), len(shstrtab), 0, 0, 1, 0))
    data += shstrtab
    shoff = len(data)
    data += b"".join(headers)
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack("<HHIQQQIHHHHHH", 2, 0xF3, 1, 0x11000, 0, shoff, 0, 64, 56, 0, 64, len(headers),
                          len(headers) - 1)
    data[:64] = header
    return bytes(data)


def archive(members):
    """A System V ar archive of {name: bytes}, with a long-name table for names longer than 15 bytes."""
    longnames, out = b"", [b"!<arch>\n"]
    entries = []
    for name, body in members.items():
        if len(name) > 15:
            entries.append((f"/{len(longnames)}", body))
            longnames += name.encode() + b"/\n"
        else:
            entries.append((name + "/", body))
    if longnames:
        entries.insert(0, ("//", longnames))
    for name, body in entries:
        out.append(f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(body):<10}`\n".encode())
        out.append(body + (b"\n" if len(body) % 2 else b""))
    return b"".join(out)


def map_line(address, size, text):
    return f"{address:>16x} {address:>16x} {size:>8x} {4:>5}         {text}"


def good(name="f"):
    """An object instrumented by AddressSanitizer, compiled from C."""
    return elf_object(NOP, defined=[name], undefined=ASAN, files=["lib.c"], comment=True)


class MapParsing(unittest.TestCase):
    def test_input_sections_and_members(self):
        text = "\n".join([
            "             VMA              LMA     Size Align Out     In      Symbol",
            map_line(0x10000, 0x40, ".text"),
            map_line(0x10000, 0x10, "/opt/musl-sysroot/usr/lib/crt1.o:(.text)"),
            map_line(0x10010, 0x20, "/work/build/libfoo.a(foo.c.o):(.text.foo)"),
            map_line(0x10010, 0, "        foo"),  # a symbol line, indented further
            map_line(0x10030, 0x8, "<internal>:(.rodata.str1.1)"),
            map_line(0, 0x2b, "/opt/rt/libclang_rt.asan_static.a(asan_rtl_static.cpp.o):(.debug_info)"),
        ])
        self.assertEqual(check_links.parse_map(text), [
            ("/opt/musl-sysroot/usr/lib/crt1.o", None, ".text", 0x10),
            ("/work/build/libfoo.a", "foo.c.o", ".text.foo", 0x20),
        ])


class Archives(unittest.TestCase):
    def test_members_with_long_names(self):
        a, b = elf_object(NOP), elf_object(NOP * 2)
        members = check_links.ar_members(archive({"a.o": a, "a_very_long_member_name.c.o": b}))
        self.assertEqual(members, [("a.o", a), ("a_very_long_member_name.c.o", b)])

    def test_not_an_archive(self):
        self.assertEqual(check_links.ar_members(b"\x7fELF"), [])


class Objects(unittest.TestCase):
    def test_facts(self):
        facts = check_links.object_facts(elf_object(NOP + UNIMP + UNIMP, defined=["f"], undefined=ASAN,
                                                    files=["lib.c"], local=["core::ub_checks::precondition_check"],
                                                    comment=True))
        self.assertEqual((facts.code, facts.traps, facts.asan, facts.ub_checks), (12, 2, True, 1))
        self.assertEqual((facts.defined, facts.files, facts.compiled), (["f"], ["lib.c"], True))

    def test_only_the_constructor_symbols_mark_asan(self):
        # An uninstrumented object may still declare a public AddressSanitizer function.
        facts = check_links.object_facts(elf_object(NOP, defined=["f"], undefined=["__asan_poison_memory_region"]))
        self.assertFalse(facts.asan)

    def test_extended_section_numbering(self):
        data = bytearray(elf_object(NOP, defined=["f"], undefined=ASAN, comment=True))
        shoff, = struct.unpack_from("<Q", data, 40)
        shnum, = struct.unpack_from("<H", data, 60)
        struct.pack_into("<Q", data, shoff + 32, shnum)  # section 0's sh_size holds the count
        struct.pack_into("<H", data, 60, 0)
        facts = check_links.object_facts(bytes(data))
        self.assertEqual((facts.code, facts.asan), (4, True))

    def test_not_elf(self):
        self.assertIsNone(check_links.object_facts(b"not an object"))
        self.assertTrue(check_links.object_facts(b"BC\xc0\xde....").bitcode)


class Kinds(unittest.TestCase):
    def test_runtime_kinds(self):
        lib = "/opt/musl-sysroot/usr/lib/"
        rt = "/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/"
        self.assertEqual(check_links.runtime_kind(lib + "crt1.o"), "libc")
        self.assertEqual(check_links.runtime_kind(lib + "libc.a"), "libc")
        self.assertEqual(check_links.runtime_kind(lib + "libm.a"), "libc")
        self.assertEqual(check_links.runtime_kind(lib + "libc++.a"), "cxx-runtime")
        self.assertEqual(check_links.runtime_kind(lib + "libunwind.a"), "cxx-runtime")
        self.assertEqual(check_links.runtime_kind(rt + "libclang_rt.builtins.a"), "compiler-rt")
        self.assertEqual(check_links.runtime_kind(rt + "clang_rt.crtbegin.o"), "compiler-rt")
        self.assertEqual(check_links.runtime_kind(rt + "libclang_rt.asan.a"), "sanitizer-runtime")
        self.assertEqual(check_links.runtime_kind(lib + "libz.a"), "image-library")
        self.assertIsNone(check_links.runtime_kind("/opt/other/thing.o"))


class Records(unittest.TestCase):
    """Reading a record that a build wrote: never through a symbolic link, and the kept bytes checked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = pathlib.Path(self.tmp.name)
        self.directory = self.raw / ".records" / ("a" * 64)
        self.directory.mkdir(parents=True)
        (self.raw / ".records" / "store").mkdir()
        for name, text in (("map", ""), ("inputs.tsv", ""), ("driver", "/tmp/ov/cli.o\n")):
            (self.directory / name).write_text(text)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_complete_record(self):
        record = check_links.read_record(self.raw, "a" * 64)
        self.assertEqual(record.driver, {"/tmp/ov/cli.o"})
        self.assertIsNone(record.quiet)

    def test_links_are_refused(self):
        secret = self.raw / "secret"
        secret.write_text("x")
        (self.directory / "map").unlink()
        (self.directory / "map").symlink_to(secret)
        with self.assertRaises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)
        (self.directory / "map").unlink()
        (self.directory / "map").write_text("")
        (self.directory / "quiet").symlink_to(secret)
        self.assertIsNone(check_links.read_record(self.raw, "a" * 64).quiet)
        os.rename(self.raw / ".records", self.raw / "elsewhere")
        (self.raw / ".records").symlink_to(self.raw / "elsewhere")
        with self.assertRaises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_a_fifo_is_not_read(self):
        (self.directory / "map").unlink()
        os.mkfifo(self.directory / "map")
        with self.assertRaises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_the_kept_bytes_are_checked(self):
        record = check_links.read_record(self.raw, "a" * 64)
        body = b"object"
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        self.assertEqual(record.store(digest), body)
        (self.raw / ".records" / "store" / digest).write_bytes(b"other")
        with self.assertRaises(check_links.RecordError):
            record.store(digest)


class Analyse(unittest.TestCase):
    """check_links.analyse on records made by hand: the uninstrumented lists and the instrumentation verdicts."""

    LIBC = "/opt/musl-sysroot/usr/lib/libc.a"
    CRT1 = "/opt/musl-sysroot/usr/lib/crt1.o"
    ASAN_RT = "/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/libclang_rt.asan.a"
    ZLIB = "/opt/musl-sysroot/usr/lib/libz.a"
    IMAGE = {LIBC: "c" * 64, CRT1: "1" * 64, ASAN_RT: "a" * 64, ZLIB: "f" * 64}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = pathlib.Path(self.tmp.name)
        (self.raw / ".records" / "store").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def keep(self, body):
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        return digest

    def record(self, archives, runtimes=(LIBC, CRT1), driver=("/tmp/ov/cli.o",), loose=None, renamed=None,
               compiled=None, build="ubsan"):
        """A Record whose link took `runtimes` from the image, the members of `archives` ({archive path: {member:
        bytes}}), the objects `loose` ({path: bytes}) and the driver. With `compiled` ([(object bytes, source,
        language, arguments[, directory, source's sha256])]), the build has compile records: the flags.json compile
        writes for `build`, with the toolchain's fixed UBSan flags, and a line of compiles.jsonl as record-compile
        writes it for each compile (in /work/b, with no source_sha256, unless given), read back with
        check_links.read_compiles."""
        taken, inputs = [], {}
        for path in runtimes:
            taken.append((path, None, ".text", 4))
            inputs[path] = (path, self.IMAGE.get(path, "e" * 64), 1)
        for path, members in archives.items():
            body = archive(members)
            inputs[path] = (path, self.keep(body), len(body))
            taken += [(path, name, ".text", 4) for name in members]
        for path, body in (loose or {}).items():
            inputs[path] = (path, self.keep(body), len(body))
            taken.append((path, None, ".text", 4))
        for path in driver:
            taken.append((path, None, ".text", 4))
            inputs[path] = (path, "d" * 64, 1)
        compiles = None
        if compiled is not None:
            raw = pathlib.Path(tempfile.mkdtemp(dir=self.raw))
            (raw / ".records").mkdir()
            ubsan = UBSAN_FLAGS if build in check_links.UBSAN_BUILDS else []
            sanitizer = (["-fsanitize=address"] if build in check_links.ASAN_BUILDS else []) + ubsan
            (raw / ".records" / "flags.json").write_text(json.dumps(
                {"build": build, "sanitizer": {"c": sanitizer, "c++": sanitizer}, "ubsan": {"c": ubsan, "c++": ubsan}}))
            lines = []
            for body, source, language, arguments, *more in compiled:
                directory, source_sha256 = more if more else ("/work/b", None)
                line = {"sha256": hashlib.sha256(body).hexdigest(), "output": "x.o", "directory": directory,
                        "file": source, "language": language, "shim": "/tmp/shim/riscv64-linux-musl-clang-plain",
                        "arguments": arguments}
                if source_sha256 is not None:
                    line["source_sha256"] = source_sha256
                lines.append(json.dumps(line) + "\n")
            (raw / ".records" / "compiles.jsonl").write_text("".join(lines))
            compiles = check_links.read_compiles(raw)
            self.assertIsNotNone(compiles)
        return check_links.Record(taken, inputs, set(driver), renamed or {}, self.raw, None, compiles)

    def analyse(self, records, **options):
        return check_links.analyse(records, self.IMAGE, **options)

    def test_lists_the_image_files_in_path_order_and_not_the_driver(self):
        plain = self.record({"/work/libproject.a": {"lib.c.o": elf_object(NOP, defined=["f"], comment=True)}})
        result = self.analyse({"plain": plain})["plain"]
        self.assertEqual(result["uninstrumented"], [
            {"name": "crt1.o", "kind": "libc", "sha256": "1" * 64},
            {"name": "libc.a", "kind": "libc", "sha256": "c" * 64},
        ])
        self.assertEqual(result["instrumented"]["result"], "plain")

    def test_asan_wants_every_object_instrumented(self):
        bad = elf_object(NOP, defined=["g"], files=["other.c"], comment=True)
        result = self.analyse({"asan": self.record({"/work/libproject.a": {"lib.c.o": good()}},
                                                   runtimes=(self.LIBC, self.ASAN_RT))})["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass")
        self.assertIn({"name": "libclang_rt.asan.a", "kind": "sanitizer-runtime", "sha256": "a" * 64},
                      result["uninstrumented"])
        result = self.analyse({"asan": self.record({"/work/libproject.a": {"lib.c.o": good(), "other.c.o": bad}})})
        self.assertEqual(result["asan"]["instrumented"]["result"], "fail")
        self.assertIn("libproject.a(other.c.o)", result["asan"]["instrumented"]["detail"])

    def test_a_member_the_archive_does_not_hold(self):
        record = self.record({"/work/libproject.a": {"lib.c.o": good()}})
        record.taken.append(("/work/libproject.a", "gone.o", ".text", 4))
        result = self.analyse({"asan": record})["asan"]
        # The record names a member that is not there: the list may leave code out, so no list and an error.
        self.assertEqual(result["instrumented"]["result"], "error")
        self.assertIsNone(result["uninstrumented"])
        self.assertIn("libproject.a(gone.o)", result["instrumented"]["detail"])

    def test_a_file_the_record_does_not_describe_leaves_no_list_in_the_plain_build(self):
        record = self.record({"/work/libproject.a": {"lib.c.o": good()}})
        record.taken.append(("/opt/musl-sysroot/usr/lib/libmissing.a", "m.o", ".text", 4))
        result = self.analyse({"plain": record})["plain"]
        self.assertIsNone(result["uninstrumented"])
        self.assertEqual(result["instrumented"]["result"], "error", result)
        self.assertIn("which its record does not describe", result["instrumented"]["detail"])

    def test_asan_lists_hand_written_assembly_from_its_dwarf(self):
        asm = elf_object(NOP, defined=["memcpy_fast"])  # no STT_FILE, no compiler mark: clang's output for a .S
        record = self.record({"/work/libproject.a": {"lib.c.o": good(), "memcpy.S.o": asm}})
        units = lambda objects: [("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")] * len(objects)
        result = self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        self.assertIn({"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"},
                      result["uninstrumented"])
        # C with its marks stripped: its DWARF says C, so it is the project's code, uninstrumented.
        units = lambda objects: [("DW_LANG_C11", "src/arch/memcpy.c", "/src/lib")] * len(objects)
        result = self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        # No DWARF at all, or a source outside every checkout of the image.
        self.assertEqual(self.analyse({"asan": record}, dwarf_units=lambda objects: [None])["asan"]
                         ["instrumented"]["result"], "fail")
        units = lambda objects: [("DW_LANG_Mips_Assembler", "/tmp/x.S", "/")] * len(objects)
        self.assertEqual(self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
                         ["instrumented"]["result"], "fail")

    # libunwind's ported build: the release recipe copies the checkout into a build directory and assembles the copy,
    # so each object's DWARF names the copy, outside every checkout. Its C member has a UBSan trap, as libunwind's do.
    CHECKOUT = "/src/upstream/libunwind"
    COPY = "/work/build/lib/{flav}/libunwind-fuzz_libunwind/src/src"
    ASM = {"getcontext.o": ("getcontext", b"getcontext source\n"),
           "setcontext.o": ("setcontext", b"setcontext source\n"),
           "lt1-siglongjmp.o": ("siglongjmp", b"siglongjmp source\n")}

    def copied(self, build, flags=None, sources=None, members=None, checkout=None):
        """The analysis of a libunwind-like link in `build`: its three assembly members compiled in the build
        directory's copy, with `flags` (the build's own by default) and the recorded SHA-256 of `sources` ({name:
        bytes}, the checkout's by default; None in it: no source_sha256); `members` the names that have a record
        (all by default); `checkout` the checkout's files ({relative path: bytes})."""
        flav = {"asan": "asan", "asan-ubsan": "asanubsan"}[build]
        own = ["-fsanitize=address"] + (UBSAN_FLAGS if build == "asan-ubsan" else [])
        flags = own if flags is None else flags
        checkout = ({f"src/riscv/{stem}.S": text for stem, text in self.ASM.values()} if checkout is None
                    else checkout)
        objects = {name: elf_object(NOP, defined=[stem]) for name, (stem, _) in self.ASM.items()}
        compiled = []
        for name, (stem, text) in self.ASM.items():
            if members is not None and name not in members:
                continue
            source = (sources or {}).get(name, text)
            compiled.append((objects[name], f"riscv/{stem}.S", "assembler-with-cpp",
                             BASE + list(flags) + ["-c", f"riscv/{stem}.S", "-o", f"riscv/{stem}.o"],
                             self.COPY.format(flav=flav),
                             None if source is None else hashlib.sha256(source).hexdigest()))
        checked = elf_object(LW + UNIMP + RET, defined=["unw_step"], undefined=ASAN, files=["lib.c"], comment=True)
        record = self.record({"/work/b/liboft.a": {"lib.c.o": checked, **objects}}, compiled=compiled, build=build)
        plain = self.record({"/work/b/liboft.a": {"lib.c.o": elf_object(LW + RET, defined=["unw_step"], comment=True),
                                                  **objects}}, build="plain")
        units = {hashlib.sha256(objects[name]).hexdigest():
                 ("DW_LANG_Mips_Assembler", f"riscv/{stem}.S", self.COPY.format(flav=flav))
                 for name, (stem, _) in self.ASM.items()}
        files = {f"{self.CHECKOUT}/{path}": hashlib.sha256(text).hexdigest() for path, text in checkout.items()}
        self.asked = []

        def checkout_files(paths):
            self.asked.append(sorted(paths))
            return {path: files[path] for path in paths if path in files}

        return self.analyse({"plain": plain, build: record},
                            dwarf_units=lambda data: [units.get(hashlib.sha256(d).hexdigest()) for d in data],
                            checkouts=[self.CHECKOUT], checkout_files=checkout_files)[build]

    def test_a_build_directory_copy_of_an_assembly_source_is_listed_by_its_checkout_path(self):
        for build in ("asan", "asan-ubsan"):
            result = self.copied(build)
            self.assertEqual(result["instrumented"]["result"], "pass", (build, result))
            for name, (stem, _) in self.ASM.items():
                self.assertIn({"name": name, "kind": "assembly", "source": f"src/riscv/{stem}.S"},
                              result["uninstrumented"])
            # One read of the project image for all three, of paths in the checkout only.
            self.assertEqual(len(self.asked), 1)
            self.assertTrue(all(path.startswith(self.CHECKOUT + "/") for path in self.asked[0]))

    def test_a_copy_with_no_record_or_other_bytes_fails_as_before(self):
        cases = {"no record": {"members": ()}, "other bytes": {"sources": {"getcontext.o": b"planted\n"}},
                 "no source sha256": {"sources": {"getcontext.o": None}},
                 "not in the checkout": {"checkout": {"src/riscv/setcontext.S": b"setcontext source\n",
                                                      "src/riscv/siglongjmp.S": b"siglongjmp source\n"}}}
        for case, options in cases.items():
            result = self.copied("asan", **options)["instrumented"]
            self.assertEqual(result["result"], "fail", (case, result))
            self.assertIn("liboft.a(getcontext.o): its assembly source riscv/getcontext.S is in no checkout of the "
                          "project image", result["detail"])
            if case != "no record":
                self.assertNotIn("setcontext.o", result["detail"], case)

    def test_a_copy_assembled_without_the_builds_sanitizer_flags_fails(self):
        """A planted assembly file built without -fsanitize: it fails, named, with the flags it lacks."""
        result = self.copied("asan", flags=[])["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("liboft.a(getcontext.o): assembled without the build's sanitizer flags (riscv/getcontext.S: "
                      "without -fsanitize=address)", result["detail"])
        result = self.copied("asan-ubsan", flags=["-fsanitize=address"])["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("(riscv/getcontext.S: without -fsanitize=undefined -fno-sanitize-recover=all "
                      "-fsanitize-trap=all)", result["detail"])

    def test_an_assembly_object_in_a_checkout_needs_the_flags_when_it_has_a_record(self):
        """An object whose DWARF names a checkout's file: recorded without the build's sanitizer flags it fails, named;
        recorded with them, or with no record, it passes as before. No checkout file is read for it."""
        asm = elf_object(NOP, defined=["memcpy_fast"])
        checked = elf_object(LW + UNIMP + RET, defined=["f"], undefined=ASAN, files=["lib.c"], comment=True)
        plain = self.record({"/work/libproject.a": {"lib.c.o": elf_object(LW + RET, defined=["f"], comment=True),
                                                    "memcpy.S.o": asm}}, build="plain")
        units = lambda objects: [("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")] * len(objects)
        for build, own in (("asan", ["-fsanitize=address"]), ("asan-ubsan", ["-fsanitize=address", *UBSAN_FLAGS])):
            for flags, compiled, verdict in (([], True, "fail"), (own, True, "pass"), ([], False, "pass")):
                record = self.record(
                    {"/work/libproject.a": {"lib.c.o": checked, "memcpy.S.o": asm}}, build=build,
                    compiled=[(asm, "src/arch/memcpy.S", "assembler-with-cpp", BASE + list(flags) + ["-c", "x.S"],
                               "/src/lib", None)] if compiled else [])
                result = self.analyse({"plain": plain, build: record}, dwarf_units=units, checkouts=["/src/lib"],
                                      checkout_files=lambda paths: self.fail("no checkout file is read"))[build]
                case = (build, flags, compiled, result)
                self.assertEqual(result["instrumented"]["result"], verdict, case)
                if verdict == "fail":
                    self.assertIn("libproject.a(memcpy.S.o): assembled without the build's sanitizer flags "
                                  "(src/arch/memcpy.S: without -fsanitize=address", result["instrumented"]["detail"])
                    self.assertIsNone(result["uninstrumented"], case)
                else:
                    self.assertIn({"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"},
                                  result["uninstrumented"])

    def test_a_file_of_the_image_with_no_kind_leaves_no_list(self):
        """A list that leaves a file out would say that the build links less uninstrumented code than it does."""
        unknown = "/opt/musl-sysroot/usr/lib64/libmystery.a"
        self.IMAGE[unknown] = "b" * 64
        try:
            for build in ("plain", "asan"):
                record = self.record({"/work/l.a": {"a.o": good()}}, runtimes=(self.LIBC, self.CRT1, unknown))
                result = self.analyse({build: record})[build]
                self.assertIsNone(result["uninstrumented"], build)
                self.assertEqual(result["instrumented"]["result"], "error", build)
                self.assertIn("libmystery.a", result["instrumented"]["detail"])
                # The report shows an error, so nobody reads the missing list as a clean one.
                block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                         "targets": {"t": {build: {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                                   "quiet_loud": {"result": "pass"},
                                                   "instrumented": result["instrumented"]}}}}
                text = check_binaries.report(block, {"t": {build: None}}, [build])
                self.assertIn("**not decided**", text)
                self.assertIn("not recorded", text)
        finally:
            del self.IMAGE[unknown]

    def test_a_link_that_took_no_file_of_the_image_leaves_no_list(self):
        """Every static link takes the C library, and the facts hold a list of at least one entry."""
        record = self.record({"/work/l.a": {"a.o": good()}}, runtimes=())
        result = self.analyse({"asan": record})["asan"]
        self.assertIsNone(result["uninstrumented"])
        self.assertEqual(result["instrumented"]["result"], "error")
        self.assertIn("C library", result["instrumented"]["detail"])

    def test_the_fortran_runtime_has_a_kind(self):
        for name in ("libFortranRuntime.a", "libgfortran.a", "libflang_rt.runtime.a"):
            self.assertEqual(check_links.runtime_kind("/opt/fortran/lib/" + name), "fortran-runtime", name)

    def test_one_rust_allocator_shim_is_exempt(self):
        shim = elf_object(NOP, defined=["__rust_alloc", "__rust_dealloc"], comment=True)
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim}})})["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass")
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim, "s2.o": shim}})})
        self.assertEqual(result["asan"]["instrumented"]["result"], "fail")

    def test_a_seal_compiled_from_the_driver_sources_is_the_drivers(self):
        seal = elf_object(NOP, defined=["__wrap_getenv"], comment=True, files=["wrap_getenv.c"])
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={"/work/b/wrap_getenv.o": seal})
        self.assertEqual(self.analyse({"asan": record})["asan"]["instrumented"]["result"], "pass")
        # The same name, with a function that is not a __wrap_ interposer: the project's code, uninstrumented.
        other = elf_object(NOP, defined=["__wrap_getenv", "helper"], comment=True, files=["wrap_getenv.c"])
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={"/work/b/wrap_getenv.o": other})
        self.assertEqual(self.analyse({"asan": record})["asan"]["instrumented"]["result"], "fail")

    def test_ubsan_wants_more_traps_than_plain_in_each_archive(self):
        def build(lib, dep):
            return self.record({"/work/b/libproject.a": {"lib.o": elf_object(lib, defined=["f"], comment=True)},
                                "/work/b/libdep.a": {"dep.o": elf_object(dep, defined=["g"], comment=True)}})
        plain = build(NOP * 4, NOP * 4)
        ubsan = build(NOP + UNIMP * 3, NOP + UNIMP)
        self.assertEqual(self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]["result"], "pass")
        # The dependency's flags lost the sanitizer: the library's traps must not hide it.
        partly = build(NOP + UNIMP * 3, NOP * 4)
        result = self.analyse({"plain": plain, "ubsan": partly})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail")
        self.assertIn("libdep.a: 0", result["detail"])

    def test_ubsan_compares_each_loose_object_too(self):
        def build(fuzzer, other):
            return self.record({"/work/l.a": {"a.o": elf_object(NOP * 4, defined=["f"], comment=True)}},
                               loose={"/work/b/fuzzer.o": elf_object(fuzzer, defined=["g"], comment=True),
                                      "/work/b/other.o": elf_object(other, defined=["h"], comment=True)})
        plain = build(NOP * 4, NOP * 4)
        # Only the fuzz target's own object got the sanitizer: its traps must not stand for the other object's.
        partly = build(NOP + UNIMP * 3, NOP * 4)
        result = self.analyse({"plain": plain, "ubsan": partly})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail")
        self.assertIn("other.o: 0", result["detail"])

    def test_ubsan_without_a_plain_build_decides_nothing(self):
        ubsan = self.record({"/work/l.a": {"a.o": elf_object(NOP + UNIMP, defined=["f"], comment=True)}})
        result = self.analyse({"ubsan": ubsan})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "error")
        self.assertIn("no plain build", result["detail"])

    def test_assembly_without_dwarf_is_named_by_its_source(self):
        """The toolchain assembles a .S without -g, so the object carries no DWARF and no other mark."""
        asm = elf_object(NOP, defined=["memcpy_fast"])
        record = self.record({"/work/l.a": {"a.o": good(), "memcpy.S.o": asm}})
        asked = []

        def sources(wanted):
            asked.extend(wanted)
            return ["src/arch/memcpy.S"] * len(wanted)

        result = self.analyse({"asan": record}, dwarf_units=lambda objects: [None], assembly_sources=sources)["asan"]
        self.assertEqual(asked, [("memcpy.S.o", ["memcpy_fast"])])
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        self.assertIn({"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"},
                      result["uninstrumented"])
        # No source of the project carries its name and its functions: the object is not shown to be assembly.
        result = self.analyse({"asan": record}, dwarf_units=lambda objects: [None],
                              assembly_sources=lambda wanted: [None] * len(wanted))["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        self.assertIn("no DWARF", result["instrumented"]["detail"])

    def test_an_allocation_failure_copy_stands_for_its_original(self):
        copy = "/tmp/ov/af.abc/3-libz.a"
        uninstrumented_zlib = archive({"adler32.o": elf_object(NOP, defined=["adler32"], comment=True)})
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={copy: uninstrumented_zlib},
                             renamed={copy: (self.ZLIB, self.IMAGE[self.ZLIB])})
        record.taken = [entry for entry in record.taken if entry[0] != copy] + [(copy, "adler32.o", ".text", 4)]
        result = self.analyse({"asan": record})["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        self.assertIn({"name": "libz.a", "kind": "image-library", "sha256": "f" * 64}, result["uninstrumented"])

    # The UBSan builds judge an object by the compile that wrote its bytes, when the build recorded one.

    def ubsan(self, build, plain_archives, archives, compiled):
        plain = self.record(plain_archives, build="plain")
        record = self.record(archives, compiled=compiled, build=build)
        return self.analyse({"plain": plain, build: record})[build]["instrumented"]

    def test_a_member_with_nothing_to_check_passes_by_its_recorded_compile(self):
        """libabsl_log_sink.a in curl_fuzzer_proto_file: its code is a `ret`, with no UBSan trap in either build."""
        sink = elf_object(RET, defined=["_ZN4absl7LogSinkD2Ev"], undefined=ASAN, comment=True)
        archives = {"/work/b/libabsl_log_sink.a": {"log_sink.cc.o": sink}}
        for build in ("ubsan", "asan-ubsan"):
            result = self.ubsan(build, archives, archives,
                                [(sink, "absl/log/log_sink.cc", "c++", compile_arguments("absl/log/log_sink.cc"))])
            self.assertEqual(result["result"], "pass", (build, result))
            self.assertIn("1 of them by the compile that wrote them", result["detail"])
            # With no compile record, the traps decide, and there are none.
            result = self.ubsan(build, archives, archives, None)
            self.assertEqual(result["result"], "fail", (build, result))
            self.assertIn("libabsl_log_sink.a: 0 UBSan traps and UB checks, the plain build's 0", result["detail"])

    def test_a_planted_member_compiled_without_the_flags_fails(self):
        """A load UBSan would check, no trap, and a compile without -fsanitize: the archive's other member has traps,
        which would pass the archive by its count; the record fails the member, and names it."""
        planted = elf_object(LW + RET, defined=["planted"], comment=True)
        checked = elf_object(LW + UNIMP + RET, defined=["checked"], comment=True)
        plain = {"/work/b/libplanted.a": {"checked.c.o": elf_object(LW + RET, defined=["checked"], comment=True),
                                          "planted.c.o": planted}}
        archives = {"/work/b/libplanted.a": {"checked.c.o": checked, "planted.c.o": planted}}
        result = self.ubsan("ubsan", plain, archives, [
            (checked, "src/checked.c", "c", compile_arguments("src/checked.c")),
            (planted, "src/planted.c", "c", compile_arguments("src/planted.c", flags=()))])
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("1 objects were compiled without the build's UndefinedBehaviorSanitizer flags: "
                      "libplanted.a(planted.c.o) (src/planted.c: without -fsanitize=undefined "
                      "-fno-sanitize-recover=all -fsanitize-trap=all)", result["detail"])

    def test_a_planted_member_with_no_compile_record_fails_by_its_traps(self):
        planted = elf_object(LW + RET, defined=["planted"], comment=True)
        archives = {"/work/b/libplanted.a": {"planted.c.o": planted}}
        # A build with records that has none for these bytes (a compile that ran no shim), and one with no records.
        for compiled in ([], None):
            result = self.ubsan("ubsan", archives, archives, compiled)
            self.assertEqual(result["result"], "fail", (compiled, result))
            self.assertIn("libplanted.a: 0 UBSan traps and UB checks, the plain build's 0", result["detail"])
            self.assertNotIn("compiled without", result["detail"])

    def test_a_member_with_traps_compiled_without_the_flags_fails(self):
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": trapped}},
                            [(trapped, "x.c", "c", compile_arguments("x.c", flags=()))])
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("libx.a(x.c.o) (x.c: without", result["detail"])

    def test_a_compile_that_turns_the_sanitizer_off_after_its_flags_fails(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        result = self.ubsan("ubsan", archives, archives,
                            [(sink, "x.c", "c", compile_arguments("x.c", after=["-fno-sanitize=undefined"]))])
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("libx.a(x.c.o) (x.c: with -fno-sanitize=undefined)", result["detail"])

    UNDOING = ["-fsanitize-ignorelist=/src/ignore.txt", "-fsanitize-blacklist=/src/ignore.txt",
               "-fsanitize-system-ignorelist=/src/sys.txt", "-fsanitize-system-blacklist=/src/sys.txt",
               "-fno-sanitize-trap=null", "-fno-sanitize-trap=all", "-fno-sanitize-trap",
               "-fsanitize-recover=undefined", "-fsanitize-recover=all", "-fsanitize-recover",
               "-fno-sanitize-undefined-trap-on-error", "-ftrap-function=nothing"]

    def test_a_compile_with_the_flags_that_takes_checks_away_fails(self):
        """An ignorelist takes checks away and -fno-sanitize-trap / -fsanitize-recover turn traps into handler calls,
        while every -fsanitize= word is there: such a compile did not carry the build's flags, and the word is named."""
        sink = elf_object(LW + UNIMP + RET, defined=["f"], undefined=ASAN, comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        for word in self.UNDOING:
            for build in ("ubsan", "asan-ubsan"):
                compiled = [(sink, "x.c", "c", compile_arguments("x.c", after=[word]))]
                result = self.ubsan(build, plain, archives, compiled)
                self.assertEqual(result["result"], "fail", (word, build, result))
                self.assertIn(f"libx.a(x.c.o) (x.c: with {word})", result["detail"])
                self.assertNotIn("AddressSanitizer constructor", result["detail"])

    def test_a_word_given_through_xclang_counts_as_the_bare_word(self):
        sink = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        for after, word in ((["-Xclang=-fsanitize-ignorelist=ign.txt"], "-fsanitize-ignorelist=ign.txt"),
                            (["-Xclang", "-fsanitize-ignorelist=ign.txt"], "-fsanitize-ignorelist=ign.txt"),
                            (["-Xclang=-fno-sanitize=undefined"], "-fno-sanitize=undefined"),
                            (["-Xclang=-fno-sanitize-trap=null"], "-fno-sanitize-trap=null"),
                            (["-Xclang", "-ftrap-function=nothing"], "-ftrap-function=nothing"),
                            (["-Xclang=-ftrap-function=nothing"], "-ftrap-function=nothing"),
                            (["-Wp,-ftrap-function=nothing"], "-ftrap-function=nothing")):
            result = self.ubsan("ubsan", plain, archives, [(sink, "x.c", "c", compile_arguments("x.c", after=after))])
            self.assertEqual(result["result"], "fail", (after, result))
            self.assertIn(f"libx.a(x.c.o) (x.c: with {word})", result["detail"])

    def test_a_compile_with_an_llvm_option_decides_nothing(self):
        """LLVM's own options can take every check away (-ubsan-guard-checks with -lower-allow-check-random-rate=0):
        a compile with one that the build's own flags do not have leaves its object to the trap count."""
        sink = elf_object(RET, defined=["f"], comment=True)
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        for after in (["-mllvm", "-ubsan-guard-checks", "-mllvm", "-lower-allow-check-random-rate=0"],
                      ["-Xclang", "-mllvm", "-Xclang", "-lower-allow-check-random-rate=0"],
                      ["-Xclang=-mllvm", "-Xclang=-ubsan-guard-checks"], ["-mllvm=-ubsan-guard-checks"]):
            result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": sink}},
                                [(sink, "x.c", "c", compile_arguments("x.c", after=after))])
            self.assertEqual(result["result"], "fail", (after, result))
            self.assertIn("libx.a: 0 UBSan traps and UB checks, the plain build's 0", result["detail"])
            self.assertNotIn("1 of them by the compile", result["detail"])
            result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": trapped}},
                                [(trapped, "x.c", "c", compile_arguments("x.c", after=after))])
            self.assertEqual(result["result"], "pass", (after, result))
            self.assertNotIn("by the compile that wrote them", result["detail"])

    FROM_FILES = (["--config=/w/ign.cfg"], ["--config", "/w/ign.cfg"], ["--config-user-dir=/w/cfg"],
                  ["--config-user-dir", "/w/cfg"], ["--config-system-dir=/w/cfg"], ["--config-system-dir", "/w/cfg"],
                  ["-resource-dir=/w/rd"], ["-resource-dir", "/w/rd"], ["-Xclang", "-resource-dir", "-Xclang", "/w/rd"],
                  ["-Xclang=-resource-dir=/w/rd"], ["-Wp,-resource-dir,/w/rd"], ["-Xclang=--config=/w/ign.cfg"])

    def test_a_compile_that_reads_flags_from_a_file_decides_nothing(self):
        """A configuration file, a directory of default configuration files, or a resource directory can hold an
        ignorelist or LLVM options that take every check away, and the record shows only the option: such a compile
        leaves its object to the trap count."""
        sink = elf_object(RET, defined=["f"], comment=True)
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        for after in self.FROM_FILES:
            result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": sink}},
                                [(sink, "x.c", "c", compile_arguments("x.c", after=after))])
            self.assertEqual(result["result"], "fail", (after, result))
            self.assertIn("libx.a: 0 UBSan traps and UB checks, the plain build's 0", result["detail"])
            self.assertNotIn("by the compile", result["detail"])
            self.assertNotIn("compiled without", result["detail"])
            result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": trapped}},
                                [(trapped, "x.c", "c", compile_arguments("x.c", after=after))])
            self.assertEqual(result["result"], "pass", (after, result))
            self.assertNotIn("by the compile that wrote them", result["detail"])

    def test_a_file_option_the_build_gives_itself_decides(self):
        """The same option with the same value in the build's own flags is the build's: the compile decides. Another
        value decides nothing."""
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(sink, "x.c", "c", compile_arguments(
            "x.c", after=["--config", "/opt/build.cfg", "-mllvm", "-some-option"]))])
        record.compiles.sanitizer["c"] += ["--config=/opt/build.cfg", "-mllvm", "-some-option"]
        self.assertEqual(self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"], "pass")
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].arguments.append("--config=/w/other.cfg")
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("libx.a: 0 UBSan traps", result["detail"])

    def test_a_word_given_through_the_preprocessor_options_counts_as_the_bare_word(self):
        """-Wp, and -Xpreprocessor hand their words to clang's front end as -Xclang does."""
        sink = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        for after, word in ((["-Wp,-fsanitize-ignorelist=ign.txt"], "-fsanitize-ignorelist=ign.txt"),
                            (["-Xpreprocessor", "-fsanitize-ignorelist=ign.txt"], "-fsanitize-ignorelist=ign.txt"),
                            (["-Wp,-MD,x.d,-fno-sanitize=null"], "-fno-sanitize=null")):
            result = self.ubsan("ubsan", plain, archives, [(sink, "x.c", "c", compile_arguments("x.c", after=after))])
            self.assertEqual(result["result"], "fail", (after, result))
            self.assertIn(f"libx.a(x.c.o) (x.c: with {word})", result["detail"])
        sink = elf_object(RET, defined=["f"], comment=True)
        result = self.ubsan("ubsan", {"/work/b/libx.a": {"x.c.o": sink}}, {"/work/b/libx.a": {"x.c.o": sink}},
                            [(sink, "x.c", "c", compile_arguments(
                                "x.c", after=["-Wp,-mllvm,-ubsan-guard-checks"]))])
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("libx.a: 0 UBSan traps", result["detail"])

    def test_the_builds_own_trap_and_recover_words_and_coverage_words_are_not_taken_for_them(self):
        """The build's own -fsanitize-trap=all and -fno-sanitize-recover=all, -fsanitize-coverage=0 (which curl's seed
        gives its protobuf build), and a word the build's own flags have, do not fail a compile."""
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        result = self.ubsan("ubsan", archives, archives,
                            [(sink, "x.c", "c", compile_arguments("x.c", after=["-fsanitize-coverage=0"]))])
        self.assertEqual(result["result"], "pass", result)
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(sink, "x.c", "c", compile_arguments(
            "x.c", after=["-fsanitize-ignorelist=/src/ignore.txt"]))])
        record.compiles.sanitizer["c"].append("-fsanitize-ignorelist=/src/ignore.txt")
        self.assertEqual(self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"], "pass")
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].arguments[-1] = "-fsanitize-ignorelist=/src/b.txt"
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("with -fsanitize-ignorelist=/src/b.txt", result["detail"])

    def test_any_compile_of_the_same_bytes_with_the_flags_decides(self):
        """Two compiles that wrote the same bytes, one without the flags (a host tool's copy, say): the bytes are the
        same whichever made them, so the one with the flags makes the member instrumented."""
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        result = self.ubsan("ubsan", archives, archives, [(sink, "x.c", "c", compile_arguments("x.c", flags=())),
                                                          (sink, "x.c", "c", compile_arguments("x.c"))])
        self.assertEqual(result["result"], "pass", result)

    def test_a_compile_the_records_cannot_judge_falls_back_to_the_traps(self):
        """Assembly, which UBSan does not instrument, and arguments in a response file decide nothing."""
        code = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.o": code}}
        for language, arguments in (("assembler-with-cpp", compile_arguments("x.S", flags=())),
                                    ("c", ["@x.rsp", "-c", "x.c"])):
            result = self.ubsan("ubsan", archives, archives, [(code, "x", language, arguments)])
            self.assertEqual(result["result"], "fail", (language, result))
            self.assertIn("libx.a: 0 UBSan traps", result["detail"])
            self.assertNotIn("compiled without", result["detail"])

    def test_an_exclusion_counts_only_where_the_build_has_it(self):
        """compile leaves OV_UBSAN_C_EXCLUDE out of the C compiles only: a C++ compile with it adds an exclusion."""
        plain = self.record({}, build="plain")
        sink = elf_object(RET, defined=["f"], comment=True)
        record = self.record({"/work/b/libx.a": {"x.o": sink}},
                             compiled=[(sink, "x", "c", compile_arguments("x", after=["-fno-sanitize=vptr"]))])
        record.compiles.sanitizer["c"].append("-fno-sanitize=vptr")
        record.compiles.ubsan["c"].append("-fno-sanitize=vptr")
        self.assertEqual(self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"], "pass")
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].language = "c++"
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("with -fno-sanitize=vptr", result["detail"])
        # A C compile need not repeat the exclusion: with it off, the compile has more checks, not fewer.
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0] = check_links.Compile(
            "x.c", "c", compile_arguments("x.c"))
        self.assertEqual(self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"], "pass")

    def test_flags_that_turn_on_no_check_decide_nothing(self):
        """A build whose recorded UBSan flags hold no -fsanitize= word (none at all, or only words every compile
        carries): its records would call every compile instrumented, so they decide nothing, the trap rule refuses a
        member with no trap, and the cell says why."""
        sink = elf_object(RET, defined=["f"], undefined=ASAN, comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        for build in ("ubsan", "asan-ubsan"):
            for wanted in ([], ["-fno-sanitize-recover=all"], ["-fno-sanitize=vptr", "-fno-sanitize-recover=all"]):
                plain = self.record(archives, build="plain")
                record = self.record(archives, build=build,
                                     compiled=[(sink, "x.c", "c", compile_arguments("x.c", flags=wanted))])
                own = (["-fsanitize=address"] if build == "asan-ubsan" else []) + wanted
                record.compiles.ubsan = {"c": list(wanted), "c++": list(wanted)}
                record.compiles.sanitizer = {"c": own, "c++": own}
                result = self.analyse({"plain": plain, build: record})[build]["instrumented"]
                self.assertEqual(result["result"], "fail", (build, wanted, result))
                self.assertIn("libx.a: 0 UBSan traps and UB checks, the plain build's 0", result["detail"])
                self.assertNotIn("by the compile that wrote them", result["detail"])
                self.assertIn("the build's recorded UndefinedBehaviorSanitizer flags for C and C++ turn on no check",
                              result["detail"])

    def test_flags_that_turn_on_no_check_for_one_language_decide_nothing_there(self):
        """C++'s flags name checks, C's do not: the C++ member is decided by its record, the C member by its traps."""
        c_sink = elf_object(RET, defined=["f"], comment=True)
        cxx_sink = elf_object(RET, defined=["g"], comment=True)
        archives = {"/work/b/libc.a": {"c.o": c_sink}, "/work/b/libcxx.a": {"cxx.o": cxx_sink}}
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(c_sink, "c.c", "c", compile_arguments("c.c")),
                                                 (cxx_sink, "x.cc", "c++", compile_arguments("x.cc"))])
        record.compiles.ubsan["c"] = ["-fno-sanitize-recover=all"]
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("libc.a: 0 UBSan traps", result["detail"])
        self.assertNotIn("libcxx.a", result["detail"])
        self.assertIn("flags for C turn on no check", result["detail"])

    def test_a_build_with_no_compile_records_says_so(self):
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = self.record({"/work/b/libx.a": {"x.o": elf_object(LW + RET, defined=["f"], comment=True)}})
        ubsan = self.record({"/work/b/libx.a": {"x.o": trapped}})
        result = self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "pass", result)
        self.assertIn("the build has no compile records that this reads", result["detail"])

    def test_another_builds_compile_records_decide_nothing(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.o": sink}}
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(sink, "x.c", "c", compile_arguments("x.c"))], build="ubsan")
        record.compiles.build = "asan-ubsan"
        self.assertEqual(self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"], "fail")

    def test_a_loose_object_compiled_without_the_flags_fails(self):
        """With no record, a loose object with no check is only named; recorded without the flags, it fails."""
        fuzzer = elf_object(LW + RET, defined=["LLVMFuzzerTestOneInput"], comment=True)
        lib = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = self.record({"/work/b/l.a": {"a.o": elf_object(LW + RET, defined=["f"], comment=True)}},
                            loose={"/work/b/fuzzer.o": fuzzer}, build="plain")
        for compiled, verdict in ((None, "pass"), ([(lib, "a.c", "c", compile_arguments("a.c")),
                                                    (fuzzer, "fuzzer.c", "c", compile_arguments("fuzzer.c", ()))],
                                                   "fail")):
            ubsan = self.record({"/work/b/l.a": {"a.o": lib}}, loose={"/work/b/fuzzer.o": fuzzer}, compiled=compiled)
            result = self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]
            self.assertEqual(result["result"], verdict, result)
            self.assertIn("fuzzer.o", result["detail"])

    def test_an_archive_with_code_no_record_decides_is_judged_by_its_checks(self):
        """A member that no record decides (here, assembly) leaves its archive to the trap count, as before."""
        sink = elf_object(RET, defined=["f"], comment=True)
        asm = elf_object(RET, defined=["g"])
        archives = {"/work/b/libx.a": {"x.o": sink, "g.o": asm}}
        compiled = [(sink, "x.c", "c", compile_arguments("x.c")),
                    (asm, "g.S", "assembler-with-cpp", compile_arguments("g.S", ()))]
        result = self.ubsan("ubsan", archives, archives, compiled)
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("libx.a: 0 UBSan traps and UB checks, the plain build's 0", result["detail"])
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        result = self.ubsan("ubsan", {"/work/b/libx.a": {"x.o": elf_object(LW + RET, defined=["f"], comment=True),
                                                         "g.o": asm}},
                            {"/work/b/libx.a": {"x.o": trapped, "g.o": asm}},
                            [(trapped, "x.c", "c", compile_arguments("x.c")),
                             (asm, "g.S", "assembler-with-cpp", compile_arguments("g.S", ()))])
        self.assertEqual(result["result"], "pass", result)

    def test_the_plain_build_is_needed_only_for_code_no_record_decides(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.o": sink}}
        result = self.analyse({"ubsan": self.record(archives, compiled=[(sink, "x.c", "c",
                                                                         compile_arguments("x.c"))])})["ubsan"]
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        # With no records, as before: no plain build, no decision.
        result = self.analyse({"ubsan": self.record(archives)})["ubsan"]
        self.assertEqual(result["instrumented"]["result"], "error", result)
        self.assertIn("no plain build", result["instrumented"]["detail"])

    def test_an_exclusion_the_build_makes_is_allowed_by_check_name(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        plain = self.record({}, build="plain")
        record = self.record({"/work/b/libx.a": {"x.o": sink}},
                             compiled=[(sink, "x.cc", "c++", compile_arguments("x.cc", after=["-fno-sanitize=vptr"]))])
        record.compiles.sanitizer["c++"][-1] = "-fno-sanitize=function,vptr"
        self.assertEqual(self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"], "pass")
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].arguments.append("-fno-sanitize=vptr,null")
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail", result)
        self.assertIn("with -fno-sanitize=vptr,null", result["detail"])

    def test_compile_records_are_read_safely(self):
        good_line = json.dumps({"sha256": "a" * 64, "output": "x.o", "directory": "/w", "file": "x.c",
                                "language": "c", "shim": "s", "arguments": ["-c", "x.c"]})
        records = self.raw / ".records"
        (records / "flags.json").write_text(json.dumps({"build": "ubsan", "sanitizer": {"c": [], "c++": []},
                                                         "ubsan": {"c": [], "c++": []}}))
        (records / "compiles.jsonl").write_bytes(b"not json\n" + good_line.encode() + b"\n"
                                                 + b'{"sha256": "short", "file": "y.c", "language": "c", '
                                                   b'"arguments": []}\n' + b'{"sha256": "' + b"b" * 64
                                                 + b'", "file": "\xff.c", "language": "c", "arguments": ["\xfe"]}\n')
        compiles = check_links.read_compiles(self.raw)
        self.assertEqual(sorted(compiles.objects), ["a" * 64, "b" * 64])
        self.assertEqual(compiles.objects["a" * 64][0].arguments, ["-c", "x.c"])
        # No records, flags that are not the build's, or a link planted in their place: no records.
        (records / "compiles.jsonl").unlink()
        self.assertIsNone(check_links.read_compiles(self.raw))
        (records / "compiles.jsonl").symlink_to(records / "flags.json")
        self.assertIsNone(check_links.read_compiles(self.raw))
        (records / "compiles.jsonl").unlink()
        (records / "compiles.jsonl").write_text(good_line + "\n")
        (records / "flags.json").write_text('{"build": "ubsan", "sanitizer": {"c": []}}')
        self.assertIsNone(check_links.read_compiles(self.raw))

    def test_a_changed_image_file_is_examined_as_the_projects_code(self):
        changed = archive({"x.o": elf_object(NOP, defined=["x"], comment=True)})
        record = self.record({"/work/l.a": {"a.o": good()}, "/opt/musl-sysroot/usr/lib/libnew.a": {}},
                             loose={})
        record.inputs["/opt/musl-sysroot/usr/lib/libnew.a"] = ("/opt/musl-sysroot/usr/lib/libnew.a", self.keep(changed),
                                                              len(changed))
        record.taken.append(("/opt/musl-sysroot/usr/lib/libnew.a", "x.o", ".text", 4))
        result = self.analyse({"asan": record})["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        self.assertIn("libnew.a(x.o)", result["instrumented"]["detail"])

    def test_no_record(self):
        result = self.analyse({"asan": "compile recorded no link of it"})["asan"]
        self.assertIsNone(result["uninstrumented"])
        self.assertEqual(result["instrumented"]["result"], "error")
        # The plain build with no record is not decided either, whatever the cause, and the report says why.
        for why in ("compile recorded no link of it", "its link has no map, and it is not a Go program linked from "
                                                      "Go code only (0 .go.buildinfo sections, not one)"):
            result = self.analyse({"plain": why})["plain"]
            self.assertIsNone(result["uninstrumented"])
            self.assertEqual(result["instrumented"], {"result": "error", "detail": f"no link record: {why}"})
            block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                     "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                                 "quiet_loud": {"result": "pass"},
                                                 "instrumented": result["instrumented"]}}}}
            text = check_binaries.report(block, {"t": {"plain": None}}, ["plain"])
            self.assertIn("| `t.plain` | pass | pass | pass | **not decided** | not recorded |", text)
            self.assertIn(f"What each failure is:\n\n- `t.plain`, instrumented: `no link record: {why}`", text)

    def test_a_go_program_is_plain_from_its_build_information(self):
        """Go's linker writes no map; the program's own build information stands in for the record."""
        program = check_links.go_program(go_executable())
        self.assertIsInstance(program, check_links.GoProgram, program)
        self.assertEqual(program.version, "go1.27.1")
        result = self.analyse({"plain": program})["plain"]
        self.assertIsNone(result["uninstrumented"])
        self.assertEqual(result["instrumented"]["result"], "plain")
        self.assertIn("a Go program (go1.27.1)", result["instrumented"]["detail"])
        self.assertIn("CGO_ENABLED=0", result["instrumented"]["detail"])
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                             "quiet_loud": {"result": "pass"},
                                             "instrumented": result["instrumented"]}}}}
        text = check_binaries.report(block, {"t": {"plain": None}}, ["plain"])
        self.assertIn("| `t.plain` | pass | pass | pass | not instrumented (plain) | no list (Go code only) |", text)
        # No sanitizer instruments Go code, so a sanitizer build of a Go program decides nothing.
        self.assertEqual(self.analyse({"asan": program})["asan"]["instrumented"]["result"], "error")

    def test_a_go_program_that_may_link_c_is_not_plain(self):
        cases = {
            "CGO_ENABLED=1, not 0": go_executable(CGO_ENABLED="1"),
            "-compiler=gccgo, not gc": go_executable(**{"-compiler": "gccgo"}),
            "-buildmode=pie, not exe": go_executable(**{"-buildmode": "pie"}),
            "GOARCH=amd64, not riscv64": go_executable(GOARCH="amd64"),
            "CGO_ENABLED=(none), not 0": go_executable(CGO_ENABLED=None),
            "-race=true": go_executable(**{"-race": "true"}),
            "-asan=true": go_executable(**{"-asan": "true"}),
            "chooses the linker": go_executable(**{"-ldflags": '"-linkmode=external -s"'}),
            "0 .go.buildinfo sections": go_executable(section=b".data"),
            "cannot be read": go_executable(truncate=True),
            "not the build information of Go 1.18": go_executable(flags=0),
            "not a RISC-V ELF file": b"\x7fELF" + b"\0" * 60,
            # A .syso file's C code, which CGO_ENABLED=0 still links: it has no line table, whatever its name, also a
            # Go-like one from an asm label.
            "no line table, so code that Go did not compile (a .syso file, for one): $x, cfunc_c":
                go_executable(functions=GO_FUNCTIONS + (("cfunc_c", NOP16, False), ("$x", NOP16, False))),
            "no line table, so code that Go did not compile (a .syso file, for one): main.cfunc":
                go_executable(functions=GO_FUNCTIONS + (("main.cfunc", NOP16, False),)),
            # A trampoline is the linker's only with the linker's bytes; FIPS markers only when they are zero.
            "no line table, so code that Go did not compile (a .syso file, for one): main.f-tramp0":
                go_executable(functions=GO_FUNCTIONS + (("main.f-tramp0", NOP16, False),)),
            "no line table, so code that Go did not compile (a .syso file, for one): go:textfipsstart":
                go_executable(functions=GO_FUNCTIONS + (("go:textfipsstart", NOP16, False),)),
            "0 .gopclntab sections": go_executable(section=b".go.buildinfo").replace(b".gopclntab", b".gopclnta_"),
        }
        for expected, data in cases.items():
            why = check_links.go_program(data)
            self.assertIsInstance(why, str, expected)
            self.assertIn(expected, why)
        # Zero bytes after the last function are padding; any other byte there is code the table does not name.
        end = len(GO_FUNCTIONS) * 16
        padded = go_executable(text_size=end + 16)
        self.assertIsInstance(check_links.go_program(padded), check_links.GoProgram)
        code = bytearray(padded)
        code[64 + end] = 0x13
        self.assertIn("not zero padding", check_links.go_program(bytes(code)))
        # Go's own unqualified assembly (crypto/internal/fips140/bigmod's addMulVVWx) has a line table like any Go
        # code; the linker's trampolines and FIPS markers have none, and are recognised by their bytes.
        # Laid out after GO_FUNCTIONS (5 x 16 bytes): addMulVVWx at 80, its trampoline at 96, a 24-byte trampoline to
        # main.main (at 48) at 112, the FIPS markers at 136, and a trampoline to the first function at 144.
        stdlib = go_executable(functions=GO_FUNCTIONS + (
            "addMulVVWx", ("addMulVVWx-tramp0", trampoline(-16), False),
            ("crypto/rsa.f-tramp1", trampoline(48 - 112, 24), False),
            ("go:textfipsstart", bytes(0), False), ("go:textfipsend", bytes(8), False),
            # A trampoline to a generic function: its name is longer than the bytes of a name that are read.
            ("crypto/internal/fips140/hmac.New[go.shape." + "x" * 300 + "]-tramp2", trampoline(-144), False)))
        self.assertIsInstance(check_links.go_program(stdlib), check_links.GoProgram)
        # A stub of the trampoline's shape that jumps anywhere but a function's entry is not the linker's: entered at
        # +2, the other stub's auipc word decodes as a compressed instruction of the author's choice. Two stubs at 80
        # and 96, each jumping 2 bytes into the other; and one that jumps past every function.
        for stubs in ((18, -14), (0x1000,)):
            gadget = go_executable(functions=GO_FUNCTIONS + tuple(
                (f"q_tramp{n}", trampoline(jump), False) for n, jump in enumerate(stubs)))
            self.assertIn("no line table, so code that Go did not compile", check_links.go_program(gadget), stubs)

    def test_code_outside_the_function_table_is_not_go_code(self):
        # Go's linker lists no .L label or section container of a .syso file on riscv64, and lays host code out first:
        # code before the table's first function is code that no Go function owns.
        self.assertIn("does not start at .text's start", check_links.go_program(go_executable(skip=16)))
        # A .syso symbol that an empty Go assembly TEXT also defines takes that TEXT's line table, and is listed a
        # second time, out of address order: function 2 here starts before function 1.
        why = check_links.go_program(go_executable(entries={2: 8}))
        self.assertIn("not in address order", why)
        self.assertNotIn("runs past the end", why)
        # The last entry is the end of the code: one below the last function names no function past it.
        self.assertIn("the code ends before function 4", check_links.go_program(go_executable(entries={5: 0})))
        # A function's name must lie in funcnametab, also for a function with a line table, whose name is not read.
        self.assertIn("function 0 has no name", check_links.go_program(go_executable(name_offset=1 << 20)))
        # The machine's target is the jump's sum with bit 0 cleared (jalr): a jump of 17 from 80 lands at 96.
        self.assertTrue(check_links.linker_function(trampoline(17), 80, {96}))
        self.assertFalse(check_links.linker_function(trampoline(17), 80, {97}))
        # A function at an odd offset: Go starts every function at an even one, and a jump cannot land on it.
        self.assertIn("starts at the odd offset 0x51",
                      check_links.go_program(go_executable(functions=GO_FUNCTIONS + (
                          ("p", b"\0", False), ("s", trampoline(47), False)))))

    def test_a_crafted_function_table_is_read_in_linear_time(self):
        # Thousands of functions with no line table, all named by one long run of bytes: each name is read for at
        # most NAME_MAX_GO bytes, so the work stays linear, and the program is not Go-only.
        n = 20000
        functions = [("x" * 400000, NOP16, False)] + [("y", NOP16, False)] * (n - 1)
        data = go_executable(functions=functions, shared_name=True)
        start = time.monotonic()
        why = check_links.go_program(data)
        self.assertLess(time.monotonic() - start, 10)
        self.assertIn("x" * check_links.NAME_MAX_GO, why)
        self.assertNotIn("x" * (check_links.NAME_MAX_GO + 1), why)
        # Functions with a line table are not named at all: their names are never read.
        plain = go_executable()
        _, sections, _ = check_links.binary_isa.parse_elf(plain)
        self.assertEqual({f[2] for f in check_links.go_functions(plain, sections)}, {None})

    def test_a_go_program_that_cannot_be_read_fails_that_binary_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = pathlib.Path(tmp)
            (raw / "t").write_bytes(go_executable())
            saved = check_links.go_program

            def raises(data):
                raise MemoryError("a crafted table")

            check_links.go_program = raises
            try:
                record, _ = check_binaries.record_of(raw, "t")
            finally:
                check_links.go_program = saved
            self.assertIsInstance(record, str)
            self.assertIn("MemoryError: a crafted table", record)

    def test_record_of_reads_a_go_program_and_refuses_any_other_binary_without_a_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = pathlib.Path(tmp)
            go, other = go_executable(), go_executable(CGO_ENABLED="1")
            (raw / "go").write_bytes(go)
            (raw / "c").write_bytes(other)
            record, quiet = check_binaries.record_of(raw, "go")
            self.assertIsInstance(record, check_links.GoProgram)
            self.assertIsNone(quiet)
            # compile-go keeps the quiet program in a record with no map.
            kept = raw / ".records" / hashlib.sha256(go).hexdigest()
            kept.mkdir(parents=True)
            (kept / "quiet").write_bytes(b"quiet")
            record, quiet = check_binaries.record_of(raw, "go")
            self.assertIsInstance(record, check_links.GoProgram)
            self.assertEqual(quiet, b"quiet")
            record, quiet = check_binaries.record_of(raw, "c")
            self.assertIsInstance(record, str)
            self.assertIn("compile recorded no link of it", record)
            self.assertIn("CGO_ENABLED=1", record)
            self.assertEqual(check_links.analyse({"plain": record}, {})["plain"]["instrumented"]["result"], "error")

    def test_dwarfdump_output(self):
        text = "\n".join([
            "== /objects/0.o",
            "0x0000000b: DW_TAG_compile_unit",
            '              DW_AT_name\t("src/arch/memcpy.S")',
            '              DW_AT_comp_dir\t("/src/lib")',
            "              DW_AT_language\t(DW_LANG_Mips_Assembler)",
            "0x00000030:   DW_TAG_label",
            '                DW_AT_name\t("loop")',
            "== /objects/1.o",
        ])
        self.assertEqual(check_links.parse_dwarfdump(text),
                         {"/objects/0.o": ("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")})


BUILDER = pathlib.Path(__file__).resolve().parents[2] / "infra" / "base-builder"
RECORD_COMPILE = BUILDER / "record-compile"


class CompileRecords(unittest.TestCase):
    """infra/base-builder/record-compile, with a stand-in for a compiler shim; and the wrapper compile writes."""

    # The stand-in: it writes each object its arguments name (-o's or -o<file>'s, else <name>.o for each .c, .cc or
    # .S) unless SHIM_WRITE=0, writes its arguments to both streams (and to fd 3 with SHIM_FD3=1), and exits with
    # $SHIM_STATUS, or kills itself with SIGSEGV.
    SHIM = r"""#!/bin/sh
out=""; prev=""; sources=""
for a in "$@"; do
  case "$prev" in -o|--output) out=$a ;; esac
  case "$a" in --output=*) out=${a#--output=} ;; -o?*) out=${a#-o} ;; *.c|*.cc|*.S) sources="$sources ${a##*/}" ;; esac
  prev=$a
done
if [ "${SHIM_WRITE:-1}" = 1 ]; then
  if [ -n "$out" ]; then printf 'object of %s\n' "$*" > "$out"
  else for s in $sources; do printf 'object of %s\n' "$s" > "${s%.*}.o"; done; fi
fi
printf 'out: %s [%s] %s\n' "$#" "$PWD" "$*"; printf 'err: [%s]\n' "$@" >&2
[ "${SHIM_FD3:-0}" != 1 ] || printf 'fd3: %s\n' "$*" >&3 || exit 7
[ "${SHIM_STATUS:-0}" != segv ] || kill -SEGV $$
exit "${SHIM_STATUS:-0}"
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(os.path.realpath(self.tmp.name))
        self.records = self.dir / "records"
        self.shim = self.dir / "riscv64-linux-musl-clang-plain"
        self.shim.write_text(self.SHIM)
        self.shim.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_shim(self, *arguments, through=True, shim=None, status=0, fd3=None, **env):
        """The stand-in, through record-compile or not; with `fd3`, a file that the step gets open as fd 3."""
        command = [str(RECORD_COMPILE), str(self.records)] if through else []
        command += [str(shim or self.shim), *arguments]
        if fd3 is not None:
            command = ["bash", "-c", 'exec 3>>"$0"; exec "$@"', str(fd3), *command]
        return subprocess.run(command, cwd=self.dir, capture_output=True, timeout=60,
                              env={**os.environ, "SHIM_STATUS": str(status), **env})

    def lines(self):
        files = sorted((self.records / "compiles").glob("*")) if (self.records / "compiles").exists() else []
        return sorted((json.loads(path.read_text()) for path in files), key=lambda line: line["output"])

    def test_a_compile_runs_as_without_records_and_is_recorded(self):
        arguments = ["-Iinc", '-DQ="a \\ b"', "-DT=a\tb\x01", "-fsanitize=undefined", "-c", "src/x.c", "-o", "x.o"]
        (self.dir / "src").mkdir()
        (self.dir / "src" / "x.c").write_bytes(b"int x;\n")
        bare = self.run_shim(*arguments, through=False)
        made = (self.dir / "x.o").read_bytes()
        (self.dir / "x.o").unlink()
        done = self.run_shim(*arguments)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))
        self.assertEqual((self.dir / "x.o").read_bytes(), made)
        self.assertEqual(self.lines(), [{"sha256": hashlib.sha256(made).hexdigest(), "output": "x.o",
                                         "directory": str(self.dir), "file": "src/x.c",
                                         "source_sha256": hashlib.sha256(b"int x;\n").hexdigest(), "language": "c",
                                         "shim": str(self.shim), "arguments": arguments}])
        records = self.dir / "out" / ".records"
        records.mkdir(parents=True)
        (records / "flags.json").write_text('{"build": "ubsan", "sanitizer": {"c": [], "c++": []}, '
                                            '"ubsan": {"c": [], "c++": []}}')
        (records / "compiles.jsonl").write_text(next((self.records / "compiles").iterdir()).read_text())
        compiles = check_links.read_compiles(self.dir / "out")
        compile, = compiles.objects[hashlib.sha256(made).hexdigest()]
        self.assertEqual((compile.directory, compile.source_sha256),
                         (str(self.dir), hashlib.sha256(b"int x;\n").hexdigest()))

    def test_a_source_from_standard_input_has_no_source_sha256(self):
        self.assertEqual(self.run_shim("-x", "c", "-c", "-", "-o", "x.o").returncode, 0)
        self.assertEqual([(line["file"], line["source_sha256"]) for line in self.lines()], [("-", None)])

    def test_only_a_compile_that_succeeds_is_recorded(self):
        self.assertEqual(self.run_shim("-E", "-c", "x.c", "-o", "x.i").returncode, 0)
        self.assertEqual(self.run_shim("x.c", "-o", "x").returncode, 0)  # a link
        self.assertEqual(self.run_shim("-c", "x.c", "-o", "x.o", status=3).returncode, 3)
        # An object older than the step is not one it wrote.
        (self.dir / "y.o").write_text("stale")
        os.utime(self.dir / "y.o", (1, 1))
        self.assertEqual(self.run_shim("-c", "y.c", SHIM_WRITE="0").returncode, 0)
        self.assertEqual(self.lines(), [])

    def test_a_step_ends_as_the_shim_ends(self):
        """Killed by a signal, the step is killed by it too, with nothing more on standard error; and a BASH_ENV or
        SHELLOPTS that the build exports changes nothing the step writes."""
        for arguments in (["-c", "x.c", "-o", "x.o"], ["x.c", "-o", "x"]):
            bare = self.run_shim(*arguments, through=False, status="segv")
            done = self.run_shim(*arguments, status="segv")
            self.assertEqual(bare.returncode, -11)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))
        startup = self.dir / "startup.sh"
        startup.write_text("echo from BASH_ENV >&2\n")
        env = {"BASH_ENV": str(startup), "SHELLOPTS": "braceexpand:hashall:interactive-comments:xtrace"}
        for arguments in (["-c", "x.c", "-o", "x.o"], ["--version"]):
            bare = self.run_shim(*arguments, through=False, **env)
            done = self.run_shim(*arguments, **env)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))

    def test_a_shim_exit_status_that_names_a_stop_signal_is_the_steps(self):
        """A shim that exits with 147-150 (128 + SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU) or 145 (128 + SIGCHLD): the step
        exits with that status and does not stop itself."""
        for status in (145, 147, 148, 149, 150):
            bare = self.run_shim("-c", "x.c", "-o", "x.o", through=False, status=status)
            done = self.run_shim("-c", "x.c", "-o", "x.o", status=status)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))
            self.assertEqual(done.returncode, status)

    def test_every_open_file_reaches_the_shim(self):
        """A build that gives the compiler fd 3 open: the shim writes to it as it does without the front."""
        for arguments in (["-c", "x.c", "-o", "x.o"], ["x.c", "-o", "x"]):
            bare_file, done_file = self.dir / "bare3", self.dir / "done3"
            bare = self.run_shim(*arguments, through=False, fd3=bare_file, SHIM_FD3="1")
            done = self.run_shim(*arguments, fd3=done_file, SHIM_FD3="1")
            self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))
            self.assertEqual(done.returncode, 0)
            self.assertEqual(done_file.read_text(), bare_file.read_text())
            bare_file.unlink()
            done_file.unlink()

    def test_a_compile_whose_arguments_clang_edits_has_no_record(self):
        """CCC_OVERRIDE_OPTIONS edits the arguments inside clang's driver, after the record would take them."""
        env = {"CCC_OVERRIDE_OPTIONS": "+-fno-sanitize=undefined"}
        bare = self.run_shim("-fsanitize=undefined", "-c", "x.c", "-o", "x.o", through=False, **env)
        done = self.run_shim("-fsanitize=undefined", "-c", "x.c", "-o", "x.o", **env)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))
        self.assertEqual(self.lines(), [])
        self.assertEqual(self.run_shim("-c", "x.c", "-o", "x.o", CCC_OVERRIDE_OPTIONS="").returncode, 0)
        self.assertEqual(len(self.lines()), 1)

    def test_the_output_named_in_each_spelling(self):
        for arguments in (["-c", "a.c", "-oj.o"], ["-c", "a.c", "--output", "k.o"], ["-c", "--output=l.o", "a.c"]):
            self.assertEqual(self.run_shim(*arguments).returncode, 0)
        self.assertEqual([line["output"] for line in self.lines()], ["j.o", "k.o", "l.o"])

    def test_each_object_and_its_language(self):
        self.assertEqual(self.run_shim("-c", "a.c", "lib/b.cc", "-x", "c++", "e.S", "-I", "f.c").returncode, 0)
        self.assertEqual([(line["output"], line["file"], line["language"]) for line in self.lines()],
                         [("a.o", "a.c", "c"), ("b.o", "lib/b.cc", "c++"), ("e.o", "e.S", "c++")])
        # A C++ shim (clang++) takes C as C++.
        cxx = self.dir / "riscv64-linux-musl-clang++-plain"
        cxx.write_text(self.SHIM)
        cxx.chmod(0o755)
        (self.records / "compiles").rename(self.dir / "earlier")
        self.assertEqual(self.run_shim("-c", "a.c", "f.S", shim=cxx).returncode, 0)
        self.assertEqual([(line["output"], line["language"]) for line in self.lines()],
                         [("a.o", "c++"), ("f.o", "assembler-with-cpp")])

    def test_a_front_hands_the_shim_every_argument(self):
        original = self.shim.read_bytes()
        for _ in range(2):  # a shim that has a front keeps it
            subprocess.run([str(RECORD_COMPILE), "--front", str(self.records), str(self.shim)], check=True)
        aside = self.dir / ".recorded" / self.shim.name
        self.assertEqual(aside.read_bytes(), original)
        self.assertEqual(self.shim.read_text(), "#!/bin/sh\n# record-compile front\n"
                         f'exec {RECORD_COMPILE} {self.records} {aside} "$@"\n')
        # The build runs the shim by its path, and the front hands the shim what the shim itself got.
        arguments = ["-c", "a b.c", "-o", "a.o", "-DX=\"$HOME\"", "-D*", "", "--", "-x"]
        done = self.run_shim(*arguments, through=False)
        bare = self.run_shim(*arguments, through=False, shim=aside)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (bare.returncode, bare.stdout, bare.stderr))
        self.assertEqual([(line["shim"], line["arguments"]) for line in self.lines()], [(str(self.shim), arguments)])

    def test_compile_writes_the_wrapper_it_always_wrote(self):
        """compile's wrappers for $CC and $CXX are the text compile has always written, with records and without:
        the records come from a front before each shim, never from the wrappers."""
        script = ('eval "$(sed -n \'/^write_wrapper() {/,/^}/p\' "$1")"\n'
                  "LIB=/usr/local/lib/oss-verify LIB_FUZZING_ENGINE=/tmp/ov/libFuzzingEngine.a\n"
                  "LIB_ALLOCATION_FAILURE_ENGINE=/tmp/ov/libAllocationFailureEngine.a\n"
                  "LIB_ALLOCATION_COUNTING_ENGINE=/tmp/ov/libAllocationCountingEngine.a OV_RECORDS=$2\n"
                  'write_wrapper "$3" /tmp/shim/riscv64-linux-musl-clang-plain\n')
        shim = "/tmp/shim/riscv64-linux-musl-clang-plain"
        expected = (
            '#!/bin/sh\nfor a in "$@"; do\n'
            f'  case "$a" in -c|-E|-S|-fsyntax-only|-M|-MM|--version|-dumpmachine|-print-*) exec {shim} "$@" ;; esac\n'
            'done\nfor a in "$@"; do\n'
            '  case "$a" in "/tmp/ov/libFuzzingEngine.a"|"/tmp/ov/libAllocationFailureEngine.a"|'
            '"/tmp/ov/libAllocationCountingEngine.a")\n'
            f'    exec /usr/local/lib/oss-verify/link-fuzz-target {shim} "$@" ;; esac\n'
            f'done\nexec {shim} "$@"\n')
        for n, records in enumerate(("", "/tmp/ov/records")):
            out = self.dir / f"wrapper{n}"
            subprocess.run(["bash", "-c", script, "bash", str(BUILDER / "compile"), records, str(out)], check=True)
            self.assertEqual(out.read_text(), expected)


class ModelRelease(unittest.TestCase):
    RELEASE = ("schema: oss-fuzz-theorems/release/1\nrelease: 2026.10.0\nsemantics:\n"
               "  name: rocq-linux-process-semantics-core\n"
               "  repository: https://github.com/theorem-labs/rocq-linux-process-semantics\n"
               "  commit: f1006fe8178338a499b5e5c41be83006c4edd058\n")

    def test_reads_the_model_from_release_yaml(self):
        model = model_release.release_model(text=self.RELEASE)
        self.assertEqual((model["release"], model["commit"]), ("2026.10.0", "f1006fe8178338a499b5e5c41be83006c4edd058"))
        self.assertEqual(model["repository"], "https://github.com/theorem-labs/rocq-linux-process-semantics")

    def test_refuses_a_release_yaml_that_names_no_model(self):
        for text in ("release: x\n", self.RELEASE.replace("f1006fe8", "zz"),
                     self.RELEASE.replace("https://github.com", "file://"), "- a list\n"):
            with self.assertRaises(Failed):
                model_release.release_model(text=text)

    def test_code_without_comments(self):
        text = 'Definition a := 1. (* one (* nested *) *)\n\n  Definition   b := "(* not a comment *)".\n'
        self.assertEqual(model_release.rocq_code(text), ["Definition a := 1.",
                                                         'Definition b := "(* not a comment *)".'])
        self.assertEqual(model_release.code_sha256(text), model_release.code_sha256(text.replace("one", "uno")))
        self.assertNotEqual(model_release.code_sha256(text), model_release.code_sha256(text.replace("1.", "2.")))

    def test_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "A.v").write_text("Definition a := 1.\n")
            files = {"A.v": model_release.code_sha256("(* a comment *) Definition a := 1.")}
            self.assertEqual(model_release.stale(root, files), [])
            self.assertEqual(model_release.stale(root, {**files, "B.v": "0" * 64}), ["B.v"])
            (root / "A.v").write_text("Definition a := 2.\n")
            self.assertEqual(model_release.stale(root, files), ["A.v"])


class Runs(unittest.TestCase):
    """check_binaries' reading of the runs: quiet and loud, the system calls' floors, and the report."""

    QEMU = "qemu-riscv64 version 10.0.11 (Debian 1:10.0.11+ds-0+deb13u1)"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.results = pathlib.Path(self.tmp.name)
        self.inputs = [(check_binaries.EMPTY, check_binaries.HEADER), ("seed1", check_binaries.HEADER + b"x")]
        for kind in "lq":
            for n in range(2):
                self.write(f"{kind}{n}.calls", "exec")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, value):
        (self.results / name).write_text(f"{value}\n")

    def test_seed_inputs(self):
        corpus = self.results / "t_seed_corpus.zip"
        with zipfile.ZipFile(corpus, "w") as archive_file:
            for n in range(12):
                archive_file.writestr(f"s{n}", b"%d" % n)
        inputs = check_binaries.seed_inputs(self.results, "t")
        self.assertEqual(len(inputs), check_binaries.MAX_SEEDS + 1)
        self.assertEqual(inputs[0], (check_binaries.EMPTY, check_binaries.HEADER))
        self.assertEqual(inputs[1], ("s0", check_binaries.HEADER + b"0"))

    def test_quiet_and_loud(self):
        for n, (loud, quiet, written) in enumerate([(0, 0, 0), (2, 2, 0)]):
            self.write(f"l{n}.status", loud)
            self.write(f"q{n}.status", quiet)
            self.write(f"q{n}.out", written)
            self.write(f"q{n}.err", 0)
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"], "pass")
        self.write("q1.status", 0)
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results)
        self.assertEqual(result["result"], "fail")
        self.assertIn("exits 2, the quiet twin 0", result["detail"])
        self.write("q1.status", 2)
        self.write("q0.out", 5)
        self.assertIn("wrote 5 bytes", check_binaries.quiet_loud(True, "", self.inputs, self.results)["detail"])
        self.write("q0.out", 0)
        self.assertEqual(check_binaries.quiet_loud(False, "no adapter", self.inputs, self.results)["result"],
                         "not-run")
        # A check that did not run must not read as a clean one.
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                             "quiet_loud": {"result": "not-run", "detail": "no quiet twin: a Go "
                                                                                           "program"},
                                             "instrumented": {"result": "plain"}}}}}
        text = check_binaries.report(block, {"t": {"plain": [{"name": "libc.a", "kind": "libc"}]}}, ["plain"])
        self.assertIn("**not decided** (not run)", text)
        self.assertIn("quiet and loud: `no quiet twin: a Go program`", text)
        # A run that never started: its status is the tracer's, and decides nothing.
        self.write("l0.calls", "")
        self.write("l1.calls", "")
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"], "error")

    def test_a_missing_byte_count_is_not_silence(self):
        for n in range(2):
            self.write(f"l{n}.status", 0)
            self.write(f"q{n}.status", 0)
            self.write(f"q{n}.out", 0)
            self.write(f"q{n}.err", 0)
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"], "pass")
        for n in range(2):
            (self.results / f"q{n}.err").unlink()
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results)
        self.assertEqual(result["result"], "error", result)
        self.assertIn("count of what the quiet twin wrote is missing", result["detail"])

    def test_a_run_that_never_reached_its_input_decides_nothing(self):
        """Two binaries that both die before main agree on every status and write nothing."""
        for n in range(2):
            self.write(f"l{n}.status", 2)
            self.write(f"q{n}.status", 2)
            self.write(f"q{n}.out", 0)
            self.write(f"q{n}.err", 0)
        whole = {check_binaries.EMPTY, "seed1"}
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results, whole)["result"], "pass")
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results, set())
        self.assertEqual(result["result"], "error")
        self.assertIn("not a whole run of the input", result["detail"])
        # A difference still fails, whether or not the run reached its input.
        self.write("q0.status", 0)
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results, set())["result"], "fail")

    def test_a_linked_result_is_not_read(self):
        secret = self.results / "secret"
        secret.write_text("0\n")
        (self.results / "l0.status").symlink_to(secret)
        self.assertIsNone(check_binaries.read_number(self.results, "l0.status"))

    def test_system_calls_need_whole_runs(self):
        traces = {0: '7 openat(AT_FDCWD,"input.bin",O_RDONLY|O_LARGEFILE) = 3\n7 read(3,0x1,65536) = 6\n',
                  1: '7 openat(AT_FDCWD,"input.bin",O_RDONLY|O_LARGEFILE) = 3\n7 read(3,0x1,65536) = 7\n'}
        for n, text in traces.items():
            self.write(f"l{n}.status", 0)
            (self.results / f"l{n}.trace").write_text(text)
        verdicts = {"calls": 12, "names": ["openat", "read", "exit_group"], "unmodeled": [], "exited": True,
                    "verdict": "pass", "host_log": "present"}
        seen = {}

        def check_trace(model, text, *, stance, require_exit, binary, lengths, inputs):
            seen.update(stance=stance, lengths=lengths, inputs=inputs)
            return dict(verdicts)

        saved = check_binaries.syscall_shapes.check_trace
        check_binaries.syscall_shapes.check_trace = check_trace
        run = lambda stale="", qemu=self.QEMU: check_binaries.system_calls(object(), stale, qemu, "bin", self.inputs,
                                                                           self.results)
        try:
            self.assertEqual(run()["result"], "pass")
            # Each run's input.bin holds that run's input, header and all.
            self.assertEqual(seen, {"stance": "off", "lengths": "exec\n",
                                    "inputs": {"input.bin": check_binaries.HEADER + b"x"}})
            self.assertEqual(run(qemu="qemu-riscv64 version 9.1.0")["result"], "error")
            # 10.0.0 prints read's and write's buffer in 32 bits, which the checker does not read so.
            self.assertEqual(run(qemu="qemu-riscv64 version 10.0.0 (Debian 1:10.0.0+ds-1)")["result"], "error")
            self.assertEqual(run(qemu="qemu-riscv64 version 10.0.110")["result"], "error")
            # qemu 8.2 hands the host 0 for every anonymous mmap's offset: its runs decide nothing.
            result = run(qemu="qemu-riscv64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)")
            self.assertEqual(result["result"], "error")
            self.assertIn("qemu 10.0.11 only", result["detail"])
            self.assertIn("docs/build-contract.md", result["detail"])
            verdicts["calls"] = 3
            self.assertEqual(run()["result"], "error")
            verdicts["calls"] = 12
            # A call the trace cannot decide is reported with its own reason, and a failure is still a failure when
            # the host-side log is missing.
            verdicts.update(verdict="undecided", undecided=[{"call": "connect", "why": "the address is not printed"}])
            self.assertIn("connect: the address is not printed", run()["detail"])
            verdicts.update(host_log="missing")
            self.assertIn("host-side log", run()["detail"])
            verdicts.update(unmodeled=[{"call": "uname", "why": "not in the model's table"}])
            self.assertEqual(run()["result"], "fail")
            verdicts.update(host_log="present", verdict="pass", undecided=[], unmodeled=[])
            (self.results / "l1.trace").write_text("7 read(3,0x1,65536) = 7\n")
            result = run()
            self.assertEqual(result["result"], "error")
            self.assertIn("does not open and read input.bin", result["detail"])
            verdicts["unmodeled"] = [{"call": "uname", "why": "not in the model's table"}]
            result = run()
            self.assertEqual(result["result"], "fail")
            self.assertEqual(result["unmodeled"][0]["inputs"], [check_binaries.EMPTY, "seed1"])
            self.assertEqual(run(stale="the rules are old")["result"], "stale")
        finally:
            check_binaries.syscall_shapes.check_trace = saved

    def test_a_trace_that_cannot_be_read_fails_one_binary_only(self):
        self.write("l0.status", 0)
        (self.results / "l0.trace").write_text("7 exit_group(0)\n")
        saved = check_binaries.syscall_shapes.check_trace

        def raises(*arguments, **options):
            raise TypeError("kind_reason() missing 2 required positional arguments")

        check_binaries.syscall_shapes.check_trace = raises
        try:
            result = check_binaries.system_calls(object(), "", self.QEMU, "bin", self.inputs, self.results)
        finally:
            check_binaries.syscall_shapes.check_trace = saved
        self.assertEqual(result["result"], "error")
        self.assertIn("kind_reason", result["detail"])
        # And a check that raises anywhere gives that binary an error, not the step.
        def fails(binary, stale):
            raise ValueError("not a RISC-V program")
        self.assertEqual(check_binaries.guarded(fails, "bin", ""),
                         {"result": "error", "detail": "fails: ValueError: not a RISC-V program"})

    def test_report_names_the_four_checks_per_binary(self):
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "2026.10.0"}, "inputs": {"t": ["a", "b"]},
                 "targets": {"t": {
                     "plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                               "quiet_loud": {"result": "pass"}, "instrumented": {"result": "plain"}},
                     "asan": {"elf": {"result": "pass"},
                              "system_calls": {"result": "fail", "detail": "uname: not in the table"},
                              "quiet_loud": {"result": "pass"}, "instrumented": {"result": "pass"}}}}}
        listing = {"t": {"plain": [{"name": "libc.a", "kind": "libc"}], "asan": None}}
        text = check_binaries.report(block, listing, ["plain", "asan"])
        self.assertIn("| ELF and instructions | system calls | quiet and loud | instrumented |", text)
        self.assertIn("| `t.plain` | pass | pass | pass | not instrumented (plain) | 1 files |", text)
        self.assertIn("| `t.asan` | pass | **fail** | pass | pass | not recorded |", text)
        self.assertIn("`t.asan`, system calls: `uname: not in the table`", text)


if __name__ == "__main__":
    unittest.main()
