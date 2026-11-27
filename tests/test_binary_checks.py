# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checks of the binaries that need no Docker: src/oss_verify/check_links.py,
src/oss_verify/model_release.py and src/oss_verify/check_binaries.py. uv run pytest"""
import gzip
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import tempfile
import time
import types
import zipfile

import pytest
import yaml

from oss_verify import check_binaries
from oss_verify import check_links
from oss_verify import model_release
from oss_verify.check_build import Failed
from test_manifest import elf

UNIMP = struct.pack("<I", check_links.TRAP)
NOP = struct.pack("<I", 0x00000013)  # addi x0, x0, 0
RET = struct.pack("<I", 0x00008067)  # jalr x0, 0(ra): a function with nothing for UBSan to check
LW = struct.pack("<I", 0x00052503)  # lw a0, 0(a0): a load UBSan checks (null, alignment)
ASAN = ["__asan_init", "__asan_version_mismatch_check_v8", "__asan_load4"]
# The release's fixed UBSan flags (infra/base-builder/toolchain.sh), and a compile's arguments with and without them.
UBSAN_FLAGS = ["-fsanitize=undefined", "-fno-sanitize-recover=all", "-fsanitize-trap=all", "-fno-sanitize=function"]
BASE = ["-march=rv64g", "-mabi=lp64d", "-Os", "-g", "-ffunction-sections", "-fdata-sections"]
# Each line end that str.splitlines() knows but "\n" (TestMapParsing.test_other_line_ends checks the tuple is whole).
OTHER_LINE_ENDS = ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def code_point(character):
    """The test id of a character, such as a line end of OTHER_LINE_ENDS: its code point, as U+000D for "\\r"."""
    return f"U+{ord(character):04X}"


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
    """A line of a link's record: an input section of the linker's map, or with more indent a symbol. A record
    holds these lines alone (infra/base-builder/link-fuzz-target), never one that starts an output section."""
    return f"{address:>16x} {address:>16x} {size:>8x} {4:>5}         {text}"


def good(name="f"):
    """An object instrumented by AddressSanitizer, compiled from C."""
    return elf_object(NOP, defined=[name], undefined=ASAN, files=["lib.c"], comment=True)


class TestMapParsing:
    def test_input_sections_and_members(self):
        text = "\n".join([
            map_line(0x10000, 0x10, "/opt/musl-sysroot/usr/lib/crt1.o:(.text)"),
            map_line(0x10010, 0x20, "/work/build/libfoo.a(foo.c.o):(.text.foo)"),
            map_line(0x10010, 0, "        foo"),  # a symbol line, indented further
            map_line(0x10030, 0x8, "<internal>:(.rodata.str1.1)"),
            # a section that is not loaded: lld gives it and its input sections their offsets in it, from 0
            map_line(0, 0x2b, "/opt/rt/libclang_rt.asan_static.a(asan_rtl_static.cpp.o):(.debug_info)"),
            map_line(0x2b, 0x15, "/work/build/libfoo.a(bar.c.o):(.debug_info)"),
        ])
        assert check_links.parse_map(text) == ([
            ("/opt/musl-sysroot/usr/lib/crt1.o", None, ".text", 0x10),
            ("/work/build/libfoo.a", "foo.c.o", ".text.foo", 0x20),
        ], 5)

    def test_a_tbss_overlap_does_not_end_the_loaded_part(self):
        """lld overlaps a .tbss input section with what follows it, so the address falls between two sections the
        linker loads. The line after it begins another output section, which its address, not 0, says is loaded."""
        text = "\n".join([
            map_line(0x45522c, 0x10, "/work/build/liboft.a(shim.o):(.tbss.state)"),
            map_line(0x4551b0, 0x8, "/opt/musl-sysroot/usr/lib/libc++.a(iostream.cpp.o):(.init_array.100)"),
            map_line(0, 0x20, "/opt/musl-sysroot/usr/lib/libc++.a(iostream.cpp.o):(.debug_info)"),
        ])
        assert check_links.parse_map(text) == ([
            ("/work/build/liboft.a", "shim.o", ".tbss.state", 0x10),
            ("/opt/musl-sysroot/usr/lib/libc++.a", "iostream.cpp.o", ".init_array.100", 0x8),
        ], 3)

    def test_read_counts_the_shape_and_not_the_loading(self):
        """`read` counts the lines in the shape of an input section, loaded or not, and <internal> ones too. A line
        that is not in that shape is not counted, but its address still decides where the loaded part ends."""
        text = "\n".join([
            map_line(0x10000, 0x10, "/opt/musl-sysroot/usr/lib/crt1.o:(.text)"),
            map_line(0x10010, 0x8, "/work/build/libfoo.a(foo.c.o).text.foo"),  # no ":("
            map_line(0x10018, 0x8, "/work/build/libfoo.a(foo.c.o):(.text.foo"),  # no ")" at the end
            map_line(0x10020, 0x8, ":(.text.bar)"),  # ":(" is its first character
            map_line(0x10028, 0x8, "<internal>:(.rodata.str1.1)"),
            # Not in the shape, at the address 0: the output section it begins is not loaded.
            map_line(0, 0x10, "/work/build/libfoo.a(bar.c.o)"),
            map_line(0x10, 0x10, "/work/build/libfoo.a(bar.c.o):(.debug_info)"),
        ])
        assert check_links.parse_map(text) == ([
            ("/opt/musl-sysroot/usr/lib/crt1.o", None, ".text", 0x10),
        ], 3)

    def test_other_line_ends(self):
        """OTHER_LINE_ENDS holds each character at which str.splitlines() splits, but "\\n", and each of them once."""
        every = "".join(map(chr, range(0x110000)))
        assert [line[-1] for line in every.splitlines(keepends=True)[:-1]] == sorted(("\n",) + OTHER_LINE_ENDS)

    @pytest.mark.parametrize("separator", OTHER_LINE_ENDS, ids=code_point)
    def test_a_path_that_holds_another_line_end_is_kept(self, separator):
        """str.splitlines() splits at each line end that it knows but "\\n" (OTHER_LINE_ENDS), and nothing refuses these
        characters in a path of the map. The map is split at "\\n" only, so the input section of a path that holds one
        of them is kept and counted in `read`."""
        text = "\n".join([
            map_line(0x10000, 0x10, f"/work/obj/a{separator}b.o:(.text.f)"),
            map_line(0x10010, 0x20, f"/work/obj/lib{separator}x.a(m{separator}.o):(.text.g)"),
        ]) + "\n"
        assert check_links.parse_map(text) == ([
            (f"/work/obj/a{separator}b.o", None, ".text.f", 0x10),
            (f"/work/obj/lib{separator}x.a", f"m{separator}.o", ".text.g", 0x20),
        ], 2)


class TestRealRecord:
    """The reading of a record that a build wrote, not one written here: tests/fixtures/link-record/.

    The record is the plain build's link of curl's fuzz_bufq, from the enrollment build of projects/curl at
    908bbe80c3ccfbb3251ac204892b83d6635fc327 on the oss-fuzz-theorems-2026.10 toolchain (infra/toolchains.tsv),
    as the build wrote it, with its map gzipped. A map written here says what its writer believes a link records;
    a reading that no record carries passed on such a map and emptied the list of every binary of every build
    (dispatch://OSSV-395), so the reading is held against a record a build wrote.
    """

    RECORD = pathlib.Path(__file__).resolve().parent / "fixtures/link-record/curl-fuzz_bufq.plain"
    DIGEST = "a" * 64
    # The files of the toolchain image this link took whose code --gc-sections left in the binary, ...
    IN_BINARY = ["clang_rt.crtbegin.o", "crt1.o", "libc++.a", "libc.a", "libclang_rt.builtins.a"]
    # ... and the image archives it took a member of and left no code of: not listed (dispatch://OSSV-332).
    EMPTIED = ["libbrotlicommon.a", "libbrotlidec.a", "libcrypto.a", "libnghttp2.a", "libssl.a", "libz.a",
               "libzstd.a"]

    @pytest.fixture(autouse=True)
    def set_up(self):
        self.map, self.inputs = self.fixture()

    @classmethod
    def fixture(cls):
        """The record's map, and the rows of its inputs.tsv."""
        with gzip.open(cls.RECORD / "map.gz", "rt") as stream:
            mapping = stream.read()
        return mapping, (cls.RECORD / "inputs.tsv").read_text().splitlines()

    @staticmethod
    def unloaded(lines):
        """Where the part of a map's lines that the linker does not load starts: the first line at the address 0,
        after the map's first line."""
        return min(n for n, line in enumerate(lines)
                   if n and check_links.MAP_COLUMNS.match(line)
                   and int(check_links.MAP_COLUMNS.match(line).group(1), 16) == 0)

    @staticmethod
    def split(inputs):
        """The rows of an inputs.tsv: the toolchain image's files as {real path: sha256}, and the other real paths."""
        image, other = {}, []
        for row in inputs:
            _path, real, sha256, _size = row.split("\t")
            if real.startswith("/opt/"):
                image[real] = sha256
            else:
                other.append(real)
        return image, other

    @classmethod
    def written(cls, raw, mapping, inputs, skipped=(), drop=None):
        """read_record on a record written in the $OUT `raw`: this map, these inputs.tsv rows, and the fixture's
        driver with the paths `skipped` after it. `drop` is a file of the record to leave out."""
        directory = raw / ".records" / cls.DIGEST
        directory.mkdir(parents=True)
        files = {"map": mapping, "inputs.tsv": "\n".join(inputs) + "\n",
                 "driver": (cls.RECORD / "driver").read_text() + "".join(f"{path}\n" for path in skipped)}
        for file, text in files.items():
            if file != drop:
                (directory / file).write_text(text)
        return check_links.read_record(raw, cls.DIGEST)

    def names(self, taken):
        """The names of the toolchain image's files among some input sections."""
        return sorted({pathlib.PurePosixPath(f).name for f, _m, _s, _z in taken if f.startswith("/opt/")})

    def test_the_sections_that_reach_the_binary(self):
        taken, read = check_links.parse_map(self.map)
        assert len(taken) == 224
        assert self.names(taken) == self.IN_BINARY
        assert read == 7865

    def test_the_sections_that_are_not_loaded_are_read_and_dropped(self):
        """The control: the part of the same record that the linker does not load, from the first line at the
        address 0, is 7,632 real lines naming the seven archives, and not one of them is taken."""
        lines = self.map.splitlines()
        tail = "\n".join(lines[self.unloaded(lines):])
        assert len(tail.splitlines()) == 7632
        assert all(any(f"/{name}(" in line for line in tail.splitlines()) for name in self.EMPTIED)
        assert check_links.parse_map(tail) == ([], 7632)

    def test_the_list_of_the_toolchain_image_s_files(self, tmp_path):
        """The uninstrumented list this record gives: the five files of the image whose code is in the binary,
        with the bytes the build recorded, and none of the seven archives it took and left no code of."""
        image, _other = self.split(self.inputs)
        took = {pathlib.PurePosixPath(row.split("\t")[0]).name for row in self.inputs}
        assert set(self.EMPTIED) <= took, "the link took the archives the list must leave out"
        record = self.written(tmp_path, self.map, self.inputs)
        _code, provided, _problems = check_links.project_code(record, image)
        assert sorted((pathlib.PurePosixPath(p).name, s) for p, s in provided) == \
            sorted((pathlib.PurePosixPath(p).name, s) for p, s in image.items()
                   if pathlib.PurePosixPath(p).name in self.IN_BINARY)
        assert sorted(pathlib.PurePosixPath(p).name for p, _s in provided) == self.IN_BINARY
        assert all(check_links.runtime_kind(p) for p, _s in provided)


class TestRealRecordWithLibc:
    """The reading of a record whose build declares its own C library (OV_LIBC): tests/fixtures/link-record/.

    The record is the asan build's link of libc_fuzzer, a fuzz target of the test project
    tests/fixtures/target-settings/. The build cluster wrote it when it built that project with the tools of pull
    request #275 (dispatch://OSSV-866), in the farm job farm/20261121t204015z-09eeff. The fixture keeps the record's
    map, inputs.tsv, driver and libc as the build wrote them, with the map gzipped (gzip -n -9). It leaves out the
    quiet twin, which no test here reads. The record's libc file declares a copy of the toolchain image's C library,
    whose libc.a has one more member, marker.o. A record written here says what its writer believes a link records,
    so the reading of the libc file is held against a record a build wrote, for the reason that TestRealRecord gives.
    """

    RECORD = pathlib.Path(__file__).resolve().parent / "fixtures/link-record/fxs-libc_fuzzer.asan"
    # The rows of the record's libc file: {file name: (real path, sha256)}.
    LIBC = {
        "libc.a": ("/work/build/lib/asan/fxs-libc.libc/lib/libc.a",
                   "9a6179f160c2b0666befdab91bddb9dfba39800c9b4a177ffd5aa3e7ab306eb2"),
        "crt1.o": ("/work/build/lib/asan/fxs-libc.libc/lib/crt1.o",
                   "111e0dda16a02983fee66cc70e332b41860dccad42d8fb0990776814ef70930a"),
        "crti.o": ("/work/build/lib/asan/fxs-libc.libc/lib/crti.o",
                   "a6e2f8732e64c9664569346d4e5b8937e8c560beca9122a4dbeaf89e9cd37e4b"),
        "crtn.o": ("/work/build/lib/asan/fxs-libc.libc/lib/crtn.o",
                   "3a7c0db23f66cca64d8f40be4ffc5c26a1371a0f0291e5a161c2dac2f66a6a47"),
    }
    # The files of the declared C library that the link took. It took no crti.o and no crtn.o.
    TOOK = ["crt1.o", "libc.a"]
    # The files of the toolchain image that this link took and whose code --gc-sections left in the binary. The
    # image's libc.a and crt1.o are not among them: the record has no row for them.
    IN_BINARY = ["clang_rt.crtbegin.o", "libclang_rt.asan.a", "libclang_rt.builtins.a", "libunwind.a"]

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.tmp = tmp_path
        self.image, self.other = TestRealRecord.split((self.RECORD / "inputs.tsv").read_text().splitlines())

    def written(self, skipped=()):
        """read_record on the fixture's record, written in its own $OUT: each file of the fixture, with the map
        decompressed and the paths `skipped` after the driver's paths."""
        directory = self.tmp / ".records" / TestRealRecord.DIGEST
        directory.mkdir(parents=True)
        for path in self.RECORD.iterdir():
            if path.name == "map.gz":
                (directory / "map").write_bytes(gzip.decompress(path.read_bytes()))
            else:
                (directory / path.name).write_bytes(path.read_bytes())
        with open(directory / "driver", "a") as stream:
            stream.write("".join(f"{path}\n" for path in skipped))
        return check_links.read_record(self.tmp, TestRealRecord.DIGEST)

    def test_the_libc_file_is_read(self):
        """read_record reads the four rows of the libc file that the build wrote."""
        assert self.written().libc == self.LIBC

    def test_the_declared_libc_is_provided(self):
        """project_code, with the record's files under /opt as the image. The declared libc.a and crt1.o are among the
        provided files, with their real paths and sha256, beside the image's files whose code is in the binary. No
        problem names OV_LIBC. The other problems are about the project's files, whose bytes the fixture does not
        keep, and this test does not examine them."""
        names = {pathlib.PurePosixPath(real).name for real in self.image}
        assert not names & {"libc.a", "crt1.o"}, "the record has no row for the image's libc.a or crt1.o"
        _code, provided, problems = check_links.project_code(self.written(), self.image)
        assert sorted(provided) == \
            sorted([(real, sha256) for real, sha256 in self.image.items()
                    if pathlib.PurePosixPath(real).name in self.IN_BINARY]
                   + [self.LIBC[name] for name in self.TOOK])
        assert [problem for problem in problems if "OV_LIBC" in problem] == []

    def test_the_list_names_the_declared_libc(self):
        """analyse with this record as the record of a plain build. The plain build examines none of the project's
        code. The driver file names the project's files that are not of the declared C library, so the reader skips
        them, as in TestReaderKeptNothing, and needs none of their bytes. The list names the image's files whose code is
        in the binary, and the declared crt1.o and libc.a, with the kind libc and the sha256 of the libc file."""
        declared = {real for real, _sha256 in self.LIBC.values()}
        record = self.written([real for real in self.other if real not in declared])
        result = check_links.analyse({"plain": record}, self.image)["plain"]
        assert result["instrumented"]["result"] == "plain", result["instrumented"]["detail"]
        listing = result["uninstrumented"]
        assert [entry["name"] for entry in listing if entry["kind"] != "libc"] == self.IN_BINARY
        assert [entry for entry in listing if entry["kind"] == "libc"] == \
            [{"name": name, "kind": "libc", "sha256": self.LIBC[name][1]} for name in self.TOOK]


class TestReaderKeptNothing:
    """A map with non-blank lines of which the reader keeps no input section: the record a build wrote, or its parts.

    read_record puts the problem on the Record, with the counts and the map's first line. analyse then gives that
    build no list and the problem as its whole detail, and a plain build with it is no baseline for ubsan. The
    record's files that are not under /opt are named in its driver file, so the reader skips them; the toolchain
    image is the record's files under /opt.
    """

    RECORD = TestRealRecord.RECORD
    PLAIN = "the plain build instruments nothing, by design"
    FIRST = "10270            10270       24     4         <internal>:(.note.gnu.build-id)"  # the map's first line
    TAIL_FIRST = "0                0       30     1         <internal>:(.comment)"  # the unloaded part's first line

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.map, self.inputs = TestRealRecord.fixture()
        self.image, self.other = TestRealRecord.split(self.inputs)
        # The part of the map that the linker does not load.
        lines = self.map.splitlines()
        at = TestRealRecord.unloaded(lines)
        self.tail = "\n".join(lines[at:])
        # The <internal> lines of the loaded part.
        self.internal = [line for line in lines[:at]
                         if line[check_links.MAP_COLUMNS.match(line).end():].lstrip(" ").startswith("<internal>")]
        self.tmp = tmp_path

    def read(self, mapping, name="plain", drop=None):
        """read_record on a record with this map and the fixture's inputs and driver, in its own $OUT `name`.
        `drop` is a file of the record to leave out."""
        return TestRealRecord.written(self.tmp / name, mapping, self.inputs, self.other, drop)

    def analyse(self, records):
        return check_links.analyse(records, self.image)

    def problem(self, lines, read, first):
        return (f"the reader kept no input section of the link's map: {lines} non-blank lines, {read} read as input "
                f"sections, 0 kept; the first line: {first}")

    def error(self, build, problem):
        """The result of a build whose record has this problem."""
        detail = f"{self.PLAIN}; {problem}" if build == "plain" else problem
        return {"uninstrumented": None, "instrumented": {"result": "error", "detail": detail}}

    @pytest.mark.parametrize("build", ("plain", "ubsan", "asan", "asan-ubsan"))
    def test_the_unloaded_part_alone(self, build):
        assert self.tail.splitlines()[0].strip(" \t") == self.TAIL_FIRST
        result = self.analyse({build: self.read(self.tail, build)})[build]
        assert result == self.error(build, self.problem(7632, 7632, self.TAIL_FIRST))

    @pytest.mark.parametrize("build", ("plain", "ubsan", "asan", "asan-ubsan"))
    def test_a_parse_map_that_keeps_nothing(self, build, monkeypatch):
        """The check is outside parse_map: a parse_map that keeps nothing, for any reason, is reported too."""
        assert self.map.splitlines()[0].strip(" \t") == self.FIRST
        monkeypatch.setattr(check_links, "parse_map", lambda *args, **kwargs: ([], 0))
        result = self.analyse({build: self.read(self.map, build)})[build]
        assert result == self.error(build, self.problem(7865, 0, self.FIRST))

    @pytest.mark.parametrize("build", ("plain", "ubsan", "asan", "asan-ubsan"))
    def test_a_map_of_internal_lines_alone(self, build):
        """A map whose loaded lines are all of <internal>: the reader keeps none of them."""
        assert len(self.internal) == 9
        assert self.internal[0].strip(" \t") == self.FIRST
        result = self.analyse({build: self.read("\n".join(self.internal) + "\n", build)})[build]
        assert result == self.error(build, self.problem(9, 9, self.FIRST))

    def test_a_ubsan_build_beside_a_plain_build_with_the_problem(self):
        """A plain build with the problem is no baseline: the ubsan build reads as it does with no plain build."""
        plain, ubsan = self.read(self.tail, "plain"), self.read(self.map, "ubsan")
        beside = self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]
        assert beside == self.analyse({"ubsan": ubsan})["ubsan"]
        assert "no plain build to compare the UndefinedBehaviorSanitizer's checks with" in \
            beside["instrumented"]["detail"]

    def test_the_first_line_is_the_first_non_blank_line(self):
        """A map that starts with blank lines: the problem names its first non-blank line, not its first line, without
        its leading and trailing blanks. With those blanks after it, that line does not read as an input section."""
        record = self.read("\n  \n\t\n" + self.tail.replace("\n", " \t\n", 1))
        assert record.problem == self.problem(7632, 7631, self.TAIL_FIRST)

    @pytest.mark.parametrize("mapping", ("", "\n  \n\t\n"), ids=("empty", "blank"))
    def test_an_empty_map_and_a_blank_map(self, mapping):
        """A map with no non-blank line has no problem: the detail is the one it had before."""
        record = self.read(mapping, name=f"map{len(mapping)}")
        assert record.problem is None
        assert self.analyse({"plain": record})["plain"]["instrumented"] == {
            "result": "error", "detail": f"{self.PLAIN}; the link took no file of the toolchain image, and "
                                         "every static link takes its C library"}

    @pytest.mark.parametrize("drop", ("driver", "inputs.tsv"))
    def test_an_incomplete_record(self, drop):
        with pytest.raises(check_links.RecordError) as caught:
            self.read(self.map, name=drop, drop=drop)
        assert str(caught.value) == f"the link record is incomplete: {drop} is not there"

    def test_a_link_with_no_map_file(self):
        """A record with no map, as check_binaries.record_of reads it: no link record, as before."""
        body = b"not an executable"
        raw = self.tmp / "out"
        directory = raw / ".records" / hashlib.sha256(body).hexdigest()
        directory.mkdir(parents=True)
        (raw / "t").write_bytes(body)
        (raw / "t").chmod(0o755)
        (directory / "inputs.tsv").write_text("\n".join(self.inputs) + "\n")
        (directory / "driver").write_text((self.RECORD / "driver").read_text())
        reason, _quiet = check_binaries.record_of(raw, "t")
        result = self.analyse({"plain": reason})["plain"]["instrumented"]
        assert result["result"] == "error"
        assert result["detail"].startswith("no link record: its link has no map, and it is not a Go program"), \
            result["detail"]

    def test_the_real_record_is_plain(self):
        record = self.read(self.map)
        assert record.problem is None
        result = self.analyse({"plain": record})["plain"]
        assert sorted(entry["name"] for entry in result["uninstrumented"]) == TestRealRecord.IN_BINARY
        assert result["instrumented"] == {"result": "plain", "detail": self.PLAIN}


class TestArchives:
    def test_members_with_long_names(self):
        a, b = elf_object(NOP), elf_object(NOP * 2)
        members = check_links.ar_members(archive({"a.o": a, "a_very_long_member_name.c.o": b}))
        assert members == [("a.o", a), ("a_very_long_member_name.c.o", b)]

    def test_not_an_archive(self):
        assert check_links.ar_members(b"\x7fELF") == []

    def test_a_long_name_offset_that_is_not_ascii_digits_is_kept_as_written(self):
        """A GNU member name `/<digits>` is an offset into the long-name table. The pull request's build writes the
        archives that the record keeps, and "/²" (the byte 0xB2) passes str.isdigit(), which int() refuses: it is
        a name, not an offset, and the walk goes on, rather than end the checks of the binaries with an error."""
        def member(name, body):
            return (name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8)
                    + str(len(body)).encode().ljust(10) + b"`\n" + body + b"\n" * (len(body) % 2))

        a = elf_object(NOP)
        data = b"!<arch>\n" + member(b"//", b"long_name.o/\n") + member(b"/\xb2", a) + member(b"/0", a)
        assert check_links.ar_members(data) == [("/\xb2", a), ("long_name.o", a)]


class TestObjects:
    def test_facts(self):
        facts = check_links.object_facts(elf_object(NOP + UNIMP + UNIMP, defined=["f"], undefined=ASAN,
                                                    files=["lib.c"], local=["core::ub_checks::precondition_check"],
                                                    comment=True))
        assert (facts.code, facts.traps, facts.asan, facts.ub_checks) == (12, 2, True, 1)
        assert (facts.defined, facts.files, facts.compiled) == (["f"], ["lib.c"], True)

    def test_only_the_constructor_symbols_mark_asan(self):
        # An uninstrumented object may still declare a public AddressSanitizer function.
        facts = check_links.object_facts(elf_object(NOP, defined=["f"], undefined=["__asan_poison_memory_region"]))
        assert not facts.asan

    def test_extended_section_numbering(self):
        data = bytearray(elf_object(NOP, defined=["f"], undefined=ASAN, comment=True))
        shoff, = struct.unpack_from("<Q", data, 40)
        shnum, = struct.unpack_from("<H", data, 60)
        struct.pack_into("<Q", data, shoff + 32, shnum)  # section 0's sh_size holds the count
        struct.pack_into("<H", data, 60, 0)
        facts = check_links.object_facts(bytes(data))
        assert (facts.code, facts.asan) == (4, True)

    def test_not_elf(self):
        assert check_links.object_facts(b"not an object") is None
        assert check_links.object_facts(b"BC\xc0\xde....").bitcode

    def test_touches_memory_reads_each_instruction(self):
        """The exemption of rustc's allocator shim rests on its code making no memory access, so the check reads
        the code. A compressed instruction is 16 bits and the rest are 32, so the words cannot simply be counted."""
        def word(value):
            return struct.pack("<I", value)

        def half(value):
            return struct.pack("<H", value)

        # addi x0, x0, 0; jalr x0, 0(ra); auipc; c.nop; c.addi4spn: no access.
        for name, body in (("empty", b""),
                           ("nop", NOP),
                           ("ret", word(0x00008067)),
                           ("auipc and jalr, a tail call", word(0x00000017) + word(0x00000067)),
                           ("the UBSan trap", UNIMP),
                           ("c.nop", half(0x0001)),
                           ("c.addi4spn", half(0x0040)),
                           ("a compressed and a full instruction", half(0x0001) + NOP)):
            assert not check_links.touches_memory(body), name
        # One of each kind of access, by its major opcode, and the compressed loads and stores of quadrants 0 and 2.
        for name, body in (("load", word(0x00000003)),
                           ("floating-point load", word(0x00000007)),
                           ("store", word(0x00000023)),
                           ("floating-point store", word(0x00000027)),
                           ("atomic", word(0x0000002F)),
                           ("lw a0, 0(a0)", LW),
                           ("c.lw", half(0x4000)),
                           ("c.sw", half(0xC000)),
                           ("c.ldsp", half(0x6002)),
                           ("c.sdsp", half(0xE002)),
                           ("c.lbu (Zcb), and the reserved funct3 beside it", half(0x8000)),
                           ("an access after a compressed instruction", half(0x0001) + LW)):
            assert check_links.touches_memory(body), name
        # Bytes this cannot read as instructions do not pass: an instruction of 48 bits or more, a 32-bit
        # instruction cut short, and a byte left over.
        for name, body in (("a 48-bit instruction", word(0x0000001F)),
                           ("a 32-bit instruction cut short", NOP + half(0x0013)),
                           ("one byte left over", NOP + b"\x13")):
            assert check_links.touches_memory(body), name


class TestKinds:
    def test_runtime_kinds(self):
        lib = "/opt/musl-sysroot/usr/lib/"
        rt = "/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/"
        assert check_links.runtime_kind(lib + "crt1.o") == "libc"
        assert check_links.runtime_kind(lib + "libc.a") == "libc"
        assert check_links.runtime_kind(lib + "libm.a") == "libc"
        assert check_links.runtime_kind(lib + "libc++.a") == "cxx-runtime"
        assert check_links.runtime_kind(lib + "libunwind.a") == "cxx-runtime"
        assert check_links.runtime_kind(rt + "libclang_rt.builtins.a") == "compiler-rt"
        assert check_links.runtime_kind(rt + "clang_rt.crtbegin.o") == "compiler-rt"
        assert check_links.runtime_kind(rt + "libclang_rt.asan.a") == "sanitizer-runtime"
        assert check_links.runtime_kind(lib + "libz.a") == "image-library"
        assert check_links.runtime_kind("/opt/other/thing.o") is None


def bad_libc_files(good):
    """Libc files made from the four rows `good` that do not name each of the four files once, with an absolute path
    and a sha256 in three fields, each by what is wrong with it."""
    rows, last = good[:3], good[3]
    return {
        "a missing name": rows,
        "a repeated name": rows + [last, rows[0]],
        "a name in place of another": rows + [("crti.o",) + last[1:]],
        "an unknown name": rows + [("libm.a",) + last[1:]],
        "a relative path": rows + [(last[0], "musl/lib/crtn.o", last[2])],
        "an empty path": rows + [(last[0], "", last[2])],
        "a sha256 that is not hex": rows + [last[:2] + ("g" * 64,)],
        "a short sha256": rows + [last[:2] + ("4" * 63,)],
        "a row with two fields": rows + [last[:2]],
        "a row with four fields": rows + [last + ("1",)],
        "an empty file": [],
    }


class TestRecords:
    """Reading a record that a build wrote: never through a symbolic link, and the kept bytes checked."""

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.raw = tmp_path
        self.directory = self.raw / ".records" / ("a" * 64)
        self.directory.mkdir(parents=True)
        (self.raw / ".records" / "store").mkdir()
        for name, text in (("map", ""), ("inputs.tsv", ""), ("driver", "/tmp/ov/cli.o\n")):
            (self.directory / name).write_text(text)

    def test_a_complete_record(self):
        record = check_links.read_record(self.raw, "a" * 64)
        assert record.driver == {"/tmp/ov/cli.o"}
        assert record.quiet is None

    def test_a_size_that_is_not_ascii_digits_leaves_its_row_out(self):
        """inputs.tsv is the build's, so its size field may be anything: "²" passes str.isdigit() and 5,000 digits
        are more than int() reads. Each such row is left out, as a row that is not a record, rather than end the
        checks of the binaries with an error."""
        rows = ["/work/a.o\t/work/a.o\t" + "b" * 64 + "\t12", "/work/b.o\t/work/b.o\t" + "c" * 64 + "\t²",
                "/work/c.o\t/work/c.o\t" + "d" * 64 + "\t" + "1" * 5000]
        (self.directory / "inputs.tsv").write_text("\n".join(rows) + "\n")
        assert check_links.read_record(self.raw, "a" * 64).inputs == {"/work/a.o": ("/work/a.o", "b" * 64, 12)}

    def test_links_are_refused(self):
        secret = self.raw / "secret"
        secret.write_text("x")
        (self.directory / "map").unlink()
        (self.directory / "map").symlink_to(secret)
        with pytest.raises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)
        (self.directory / "map").unlink()
        (self.directory / "map").write_text("")
        (self.directory / "quiet").symlink_to(secret)
        assert check_links.read_record(self.raw, "a" * 64).quiet is None
        os.rename(self.raw / ".records", self.raw / "elsewhere")
        (self.raw / ".records").symlink_to(self.raw / "elsewhere")
        with pytest.raises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_a_fifo_is_not_read(self):
        (self.directory / "map").unlink()
        os.mkfifo(self.directory / "map")
        with pytest.raises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_the_kept_bytes_are_checked(self):
        record = check_links.read_record(self.raw, "a" * 64)
        body = b"object"
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        assert record.store(digest) == body
        (self.raw / ".records" / "store" / digest).write_bytes(b"other")
        with pytest.raises(check_links.RecordError):
            record.store(digest)

    # The libc file of a link whose build declares its C library (link-fuzz-target, OV_LIBC).
    LIBC_ROWS = [("libc.a", "/work/b/musl/lib/libc.a", "1" * 64), ("crt1.o", "/work/b/musl/lib/crt1.o", "2" * 64),
                 ("crti.o", "/work/b/musl/lib/crti.o", "3" * 64), ("crtn.o", "/work/b/musl/lib/crtn.o", "4" * 64)]
    BAD_LIBC_FILES = bad_libc_files(LIBC_ROWS)

    def write_libc(self, rows):
        (self.directory / "libc").write_text("".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")

    def test_a_libc_file_is_read(self):
        self.write_libc(self.LIBC_ROWS)
        record = check_links.read_record(self.raw, "a" * 64)
        assert record.libc == {name: (path, sha256) for name, path, sha256 in self.LIBC_ROWS}
        # The rows in another order say the same.
        self.write_libc(self.LIBC_ROWS[::-1])
        assert check_links.read_record(self.raw, "a" * 64).libc == record.libc

    @pytest.mark.parametrize("separator", OTHER_LINE_ENDS, ids=code_point)
    def test_a_libc_path_that_holds_another_line_end_is_read(self, separator):
        """A libc file whose four real paths each hold a line end that str.splitlines() knows but "\\n"
        (OTHER_LINE_ENDS) is read whole, because the libc file is split at "\\n" only. link-fuzz-target refuses
        [[:cntrl:]] in these real paths, so in the C locale only \\x85, U+2028 and U+2029 get to the libc file. The
        test uses each line end all the same."""
        rows = [(name, path + separator + "x", sha256) for name, path, sha256 in self.LIBC_ROWS]
        self.write_libc(rows)
        assert check_links.read_record(self.raw, "a" * 64).libc == \
            {name: (path, sha256) for name, path, sha256 in rows}

    @pytest.mark.parametrize("separator", OTHER_LINE_ENDS, ids=code_point)
    def test_an_object_whose_path_holds_another_line_end_is_examined(self, separator):
        """A map line and an inputs.tsv row that name an object whose real path holds a line end that str.splitlines()
        knows but "\\n" (OTHER_LINE_ENDS) are read whole, so the record has the object, and project_code examines it
        and does not leave it out."""
        body = elf_object(NOP, defined=["f"], comment=True)
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        path = f"/work/obj/a{separator}b.o"
        (self.directory / "map").write_text(map_line(0x10000, 4, f"{path}:(.text.f)") + "\n", encoding="utf-8")
        (self.directory / "inputs.tsv").write_text(f"{path}\t{path}\t{digest}\t{len(body)}\n", encoding="utf-8")
        record = check_links.read_record(self.raw, "a" * 64)
        assert record.taken == [(path, None, ".text.f", 4)]
        assert record.inputs == {path: (path, digest, len(body))}
        assert record.problem is None
        code, provided, problems = check_links.project_code(record, {})
        assert ([c.label for c in code], provided, problems) == ([f"a{separator}b.o"], [], [])

    def test_a_renamed_path_that_holds_another_line_end_is_read(self):
        """A row of the renamed file whose real paths hold a line end that str.splitlines() knows but "\\n"
        (OTHER_LINE_ENDS) is read whole."""
        rows = [(f"/tmp/copies/{n}-a{separator}b.o", f"/work/obj/a{separator}b.o", str(n) * 64)
                for n, separator in enumerate(OTHER_LINE_ENDS, 1)]
        (self.directory / "renamed").write_text("".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")
        assert check_links.read_record(self.raw, "a" * 64).renamed == \
            {copy: (original, sha256) for copy, original, sha256 in rows}

    def test_a_record_with_no_libc_file_declares_no_libc(self):
        assert check_links.read_record(self.raw, "a" * 64).libc == {}

    @pytest.mark.parametrize("rows", BAD_LIBC_FILES.values(), ids=list(BAD_LIBC_FILES))
    def test_a_bad_libc_file_makes_the_record_incomplete(self, rows):
        """A libc file that does not name each of the four files once, with an absolute path and a sha256 in three
        fields, does not say which C library the link declared."""
        self.write_libc(rows)
        with pytest.raises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_a_libc_link_is_refused(self):
        secret = self.raw / "secret"
        secret.write_text("".join("\t".join(row) + "\n" for row in self.LIBC_ROWS))
        (self.directory / "libc").symlink_to(secret)
        with pytest.raises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)


class TestAnalyse:
    """check_links.analyse on records made by hand: the uninstrumented lists and the instrumentation verdicts."""

    LIBC = "/opt/musl-sysroot/usr/lib/libc.a"
    CRT1 = "/opt/musl-sysroot/usr/lib/crt1.o"
    ASAN_RT = "/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/libclang_rt.asan.a"
    ZLIB = "/opt/musl-sysroot/usr/lib/libz.a"
    IMAGE = {LIBC: "c" * 64, CRT1: "1" * 64, ASAN_RT: "a" * 64, ZLIB: "f" * 64}

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.raw = tmp_path
        (self.raw / ".records" / "store").mkdir(parents=True)

    def keep(self, body):
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        return digest

    def record(self, archives, runtimes=(LIBC, CRT1), driver=("/tmp/ov/cli.o",), loose=None, renamed=None,
               compiled=None, build="ubsan"):
        """A Record whose link took `runtimes` from the image, the members of `archives` ({archive path: {member:
        bytes}}), the objects `loose` ({path: bytes}) and the driver. With `compiled` ([(object bytes, source,
        language, arguments[, directory, source's sha256[, no_sanitize[, bytes of the object without them]]])]), the
        build has compile records: the flags.json compile writes for `build`, with the toolchain's fixed UBSan flags,
        and a line of compiles.jsonl as record-compile writes it for each compile (in /work/b, with no source_sha256
        and a source with no no_sanitize attribute, unless given), read back with check_links.read_compiles."""
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
                directory, source_sha256, no_sanitize, stripped = (list(more) + ["/work/b", None, [], None][len(more):])
                line = {"sha256": hashlib.sha256(body).hexdigest(), "output": "x.o", "directory": directory,
                        "file": source, "language": language, "no_sanitize": no_sanitize, "no_sanitize_object": None,
                        "shim": "/tmp/shim/riscv64-linux-musl-clang-plain", "arguments": arguments}
                if stripped is not None:
                    line["no_sanitize_object"] = hashlib.sha256(stripped).hexdigest()
                    (raw / ".records" / "nosan").mkdir(exist_ok=True)
                    (raw / ".records" / "nosan" / line["no_sanitize_object"]).write_bytes(stripped)
                if source_sha256 is not None:
                    line["source_sha256"] = source_sha256
                lines.append(json.dumps(line) + "\n")
            (raw / ".records" / "compiles.jsonl").write_text("".join(lines))
            compiles = check_links.read_compiles(raw)
            assert compiles is not None
        return check_links.Record(taken, inputs, set(driver), renamed or {}, self.raw, None, compiles)

    def analyse(self, records, **options):
        return check_links.analyse(records, self.IMAGE, **options)

    def test_lists_the_image_files_in_path_order_and_not_the_driver(self):
        plain = self.record({"/work/libproject.a": {"lib.c.o": elf_object(NOP, defined=["f"], comment=True)}})
        result = self.analyse({"plain": plain})["plain"]
        assert result["uninstrumented"] == [
            {"name": "crt1.o", "kind": "libc", "sha256": "1" * 64},
            {"name": "libc.a", "kind": "libc", "sha256": "c" * 64},
        ]
        assert result["instrumented"]["result"] == "plain"

    def test_an_archive_that_gc_sections_removed_is_not_listed(self):
        """Two image archives that the link took members of: --gc-sections kept code of libz's and removed all of
        libcrypto's, whose debug information alone is left in the map (OSSV-332). Only libz is listed, read from
        the record a build writes; a record with no map gives no list."""
        crypto = "/opt/musl-sysroot/usr/lib/libcrypto.a"
        image = dict(self.IMAGE, **{crypto: "b" * 64})
        digest = "a" * 64
        directory = self.raw / ".records" / digest
        directory.mkdir()
        (directory / "map").write_text("\n".join([
            map_line(0x10000, 0x10, f"{self.CRT1}:(.text)"),
            map_line(0x10010, 0x10, f"{self.LIBC}(memcpy.lo):(.text.memcpy)"),
            map_line(0x10020, 0x20, f"{self.ZLIB}(inflate.o):(.text.inflate)"),
            # the sections the linker does not load, each from the offset 0: all libcrypto has left
            map_line(0, 0x100, f"{self.ZLIB}(inflate.o):(.debug_info)"),
            map_line(0x100, 0x100, f"{crypto}(libcrypto-lib-init.o):(.debug_info)"),
            map_line(0x200, 0x100, f"{crypto}(libcrypto-lib-err.o):(.debug_info)"),
            map_line(0, 0x18, f"{self.ZLIB}(inflate.o):(.comment)"),
            map_line(0x18, 0x18, f"{crypto}(libcrypto-lib-init.o):(.comment)"),
        ]) + "\n")
        (directory / "inputs.tsv").write_text("".join(
            f"{path}\t{path}\t{image[path]}\t1\n" for path in (self.CRT1, self.LIBC, self.ZLIB, crypto)))
        (directory / "driver").write_text("/tmp/ov/cli.o\n")
        record = check_links.read_record(self.raw, digest)
        result = check_links.analyse({"plain": record}, image)["plain"]
        assert result["uninstrumented"] == [
            {"name": "crt1.o", "kind": "libc", "sha256": "1" * 64},
            {"name": "libc.a", "kind": "libc", "sha256": "c" * 64},
            {"name": "libz.a", "kind": "image-library", "sha256": "f" * 64},
        ]
        assert result["instrumented"]["result"] == "plain"
        # With no map, the step fails: no list at all, never the files the link took.
        (directory / "map").unlink()
        with pytest.raises(check_links.RecordError):
            check_links.read_record(self.raw, digest)
        executable = elf_object(NOP)
        (self.raw / "fuzzer").write_bytes(executable)
        kept = self.raw / ".records" / hashlib.sha256(executable).hexdigest()
        kept.mkdir()
        (kept / "inputs.tsv").write_text((directory / "inputs.tsv").read_text())
        (kept / "driver").write_text("/tmp/ov/cli.o\n")
        reason, _ = check_binaries.record_of(self.raw, "fuzzer")
        assert isinstance(reason, str)
        result = check_links.analyse({"plain": reason}, image)["plain"]
        assert result["uninstrumented"] is None
        assert result["instrumented"]["result"] == "error"

    def test_asan_wants_every_object_instrumented(self):
        bad = elf_object(NOP, defined=["g"], files=["other.c"], comment=True)
        result = self.analyse({"asan": self.record({"/work/libproject.a": {"lib.c.o": good()}},
                                                   runtimes=(self.LIBC, self.ASAN_RT))})["asan"]
        assert result["instrumented"]["result"] == "pass"
        assert {"name": "libclang_rt.asan.a", "kind": "sanitizer-runtime", "sha256": "a" * 64} in \
            result["uninstrumented"]
        result = self.analyse({"asan": self.record({"/work/libproject.a": {"lib.c.o": good(), "other.c.o": bad}})})
        assert result["asan"]["instrumented"]["result"] == "fail"
        assert "libproject.a(other.c.o)" in result["asan"]["instrumented"]["detail"]

    def test_a_member_the_archive_does_not_hold(self):
        record = self.record({"/work/libproject.a": {"lib.c.o": good()}})
        record.taken.append(("/work/libproject.a", "gone.o", ".text", 4))
        result = self.analyse({"asan": record})["asan"]
        # The record names a member that is not there: the list may leave code out, so no list and an error.
        assert result["instrumented"]["result"] == "error"
        assert result["uninstrumented"] is None
        assert "libproject.a(gone.o)" in result["instrumented"]["detail"]

    def test_a_file_the_record_does_not_describe_leaves_no_list_in_the_plain_build(self):
        record = self.record({"/work/libproject.a": {"lib.c.o": good()}})
        record.taken.append(("/opt/musl-sysroot/usr/lib/libmissing.a", "m.o", ".text", 4))
        result = self.analyse({"plain": record})["plain"]
        assert result["uninstrumented"] is None
        assert result["instrumented"]["result"] == "error", result
        assert "which its record does not describe" in result["instrumented"]["detail"]

    def test_asan_lists_hand_written_assembly_from_its_dwarf(self):
        asm = elf_object(NOP, defined=["memcpy_fast"])  # no STT_FILE, no compiler mark: clang's output for a .S
        record = self.record({"/work/libproject.a": {"lib.c.o": good(), "memcpy.S.o": asm}})
        units = lambda objects: [("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")] * len(objects)
        result = self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
        assert result["instrumented"]["result"] == "pass", result
        assert {"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"} in result["uninstrumented"]
        # C with its marks stripped: its DWARF says C, so it is the project's code, uninstrumented.
        units = lambda objects: [("DW_LANG_C11", "src/arch/memcpy.c", "/src/lib")] * len(objects)
        result = self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
        assert result["instrumented"]["result"] == "fail"
        # No DWARF at all, or a source outside every checkout of the image.
        assert self.analyse({"asan": record}, dwarf_units=lambda objects: [None])["asan"] \
            ["instrumented"]["result"] == "fail"
        units = lambda objects: [("DW_LANG_Mips_Assembler", "/tmp/x.S", "/")] * len(objects)
        assert self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"] \
            ["instrumented"]["result"] == "fail"

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
            assert result["instrumented"]["result"] == "pass", (build, result)
            for name, (stem, _) in self.ASM.items():
                assert {"name": name, "kind": "assembly", "source": f"src/riscv/{stem}.S"} in result["uninstrumented"]
            # One read of the project image for all three, of paths in the checkout only.
            assert len(self.asked) == 1
            assert all(path.startswith(self.CHECKOUT + "/") for path in self.asked[0])

    def test_a_copy_with_no_record_or_other_bytes_fails_as_before(self):
        cases = {"no record": {"members": ()}, "other bytes": {"sources": {"getcontext.o": b"planted\n"}},
                 "no source sha256": {"sources": {"getcontext.o": None}},
                 "not in the checkout": {"checkout": {"src/riscv/setcontext.S": b"setcontext source\n",
                                                      "src/riscv/siglongjmp.S": b"siglongjmp source\n"}}}
        for case, options in cases.items():
            result = self.copied("asan", **options)["instrumented"]
            assert result["result"] == "fail", (case, result)
            assert "liboft.a(getcontext.o): its assembly source riscv/getcontext.S is in no checkout of the " \
                "project image" in result["detail"]
            if case != "no record":
                assert "setcontext.o" not in result["detail"], case

    def test_a_copy_assembled_without_the_builds_sanitizer_flags_fails(self):
        """A planted assembly file built without -fsanitize: it fails, named, with the flags it lacks."""
        result = self.copied("asan", flags=[])["instrumented"]
        assert result["result"] == "fail", result
        assert "liboft.a(getcontext.o): assembled without the build's sanitizer flags (riscv/getcontext.S: " \
            "without -fsanitize=address)" in result["detail"]
        result = self.copied("asan-ubsan", flags=["-fsanitize=address"])["instrumented"]
        assert result["result"] == "fail", result
        assert "(riscv/getcontext.S: without -fsanitize=undefined -fno-sanitize-recover=all " \
            "-fsanitize-trap=all)" in result["detail"]

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
                                      checkout_files=lambda paths: pytest.fail("no checkout file is read"))[build]
                case = (build, flags, compiled, result)
                assert result["instrumented"]["result"] == verdict, case
                if verdict == "fail":
                    assert "libproject.a(memcpy.S.o): assembled without the build's sanitizer flags " \
                        "(src/arch/memcpy.S: without -fsanitize=address" in result["instrumented"]["detail"]
                    assert result["uninstrumented"] is None, case
                else:
                    assert {"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"} in \
                        result["uninstrumented"]

    def test_a_file_of_the_image_with_no_kind_leaves_no_list(self):
        """A list that leaves a file out would say that the build links less uninstrumented code than it does."""
        unknown = "/opt/musl-sysroot/usr/lib64/libmystery.a"
        self.IMAGE[unknown] = "b" * 64
        try:
            for build in ("plain", "asan"):
                record = self.record({"/work/l.a": {"a.o": good()}}, runtimes=(self.LIBC, self.CRT1, unknown))
                result = self.analyse({build: record})[build]
                assert result["uninstrumented"] is None, build
                assert result["instrumented"]["result"] == "error", build
                assert "libmystery.a" in result["instrumented"]["detail"]
                # The report shows an error, so nobody reads the missing list as a clean one.
                block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                         "targets": {"t": {build: {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                                   "quiet_loud": {"result": "pass"},
                                                   "instrumented": result["instrumented"]}}}}
                text = check_binaries.report(block, {"t": {build: None}}, [build], {"t": {build: None}})
                assert "**not decided**" in text
                assert "not recorded" in text
        finally:
            del self.IMAGE[unknown]

    def test_a_link_that_took_no_file_of_the_image_leaves_no_list(self):
        """Every static link takes the C library, and the facts hold a list of at least one entry."""
        record = self.record({"/work/l.a": {"a.o": good()}}, runtimes=())
        result = self.analyse({"asan": record})["asan"]
        assert result["uninstrumented"] is None
        assert result["instrumented"]["result"] == "error"
        assert "C library" in result["instrumented"]["detail"]

    def test_the_fortran_runtime_has_a_kind(self):
        for name in ("libFortranRuntime.a", "libgfortran.a", "libflang_rt.runtime.a"):
            assert check_links.runtime_kind("/opt/fortran/lib/" + name) == "fortran-runtime", name

    # The v0 names are from the allocator shim of tessera-sort's enrollment
    # with the pinned Rust toolchain (nightly-2025-07-16).
    @pytest.mark.parametrize("names", (
        ["__rust_alloc", "__rust_dealloc"],
        ["_RNvC7___rustc12___rust_alloc", "_RNvC7___rustc14___rust_dealloc"],
        ["_RNvCs6UdHf40Qw6p_7___rustc12___rust_alloc",
         "_RNvCs6UdHf40Qw6p_7___rustc14___rust_dealloc",
         "_RNvCs6UdHf40Qw6p_7___rustc14___rust_realloc",
         "_RNvCs6UdHf40Qw6p_7___rustc19___rust_alloc_zeroed",
         "_RNvCs6UdHf40Qw6p_7___rustc26___rust_alloc_error_handler",
         "_RNvCs6UdHf40Qw6p_7___rustc35___rust_no_alloc_shim_is_unstable_v2",
         "_RNvCs6UdHf40Qw6p_7___rustc42___rust_alloc_error_handler_should_panic_v2"],
    ), ids=lambda names: names[0])
    def test_one_rust_allocator_shim_is_exempt(self, names):
        shim = elf_object(NOP, defined=names, comment=True)
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim}})})["asan"]
        assert result["instrumented"]["result"] == "pass"
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim,
                                                                  "s2.o": shim}})})
        assert result["asan"]["instrumented"]["result"] == "fail"

    ALLOCATOR = "_RNvCs6UdHf40Qw6p_7___rustc12___rust_alloc"

    @pytest.mark.parametrize("other", (
        "helper", ALLOCATOR.replace("7___rustc", "7___other"), ALLOCATOR.replace("12___rust_alloc", "13___rust_alloc"),
        ALLOCATOR + "extra", "_RNvCs6UdHf40Qw6p_7___rustc18___rust_alloc_extra"))
    def test_allocator_names_do_not_exempt_other_functions(self, other):
        shim = elf_object(NOP, defined=[self.ALLOCATOR, other], comment=True)
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim}})})
        assert result["asan"]["instrumented"]["result"] == "fail", other

    SHIMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "allocator-shim"

    def shim_link(self, name):
        """(the asan result, the fixture's bytes) for a link of one instrumented object and the fixture `name`,
        a real riscv64 object (fixtures/allocator-shim/README.md)."""
        body = (self.SHIMS / name).read_bytes()
        record = self.record({"/work/l.a": {"a.o": good(), "shim.o": body}},
                             runtimes=(self.LIBC, self.ASAN_RT), build="asan")
        return self.analyse({"asan": record})["asan"], body

    def test_the_exempt_shim_makes_no_memory_access_and_is_listed(self):
        """A real shim object whose six functions are tail forwards: exempt, named in the uninstrumented list, and
        counted out of "all instrumented", because it is an object with code that nothing instruments."""
        result, body = self.shim_link("shim-forwards.o")
        assert result["instrumented"]["result"] == "pass", result
        assert {"name": "shim.o", "kind": "rust-allocator-shim",
                "sha256": hashlib.sha256(body).hexdigest()} in result["uninstrumented"]
        assert "all instrumented but the one named below" in result["instrumented"]["detail"]
        assert "l.a(shim.o)" in result["instrumented"]["detail"]

    def test_a_shim_whose_own_code_stores_is_not_exempt(self):
        """The same names, and each function stores a byte. Before this check read the code, it was exempt."""
        result, body = self.shim_link("shim-stores.o")
        assert result["instrumented"]["result"] == "fail", result
        assert "l.a(shim.o)" in result["instrumented"]["detail"]
        assert check_links.object_facts(body).memory

    def test_a_shim_whose_local_function_makes_an_access_is_not_exempt(self):
        """One global, __rust_alloc; the loads and stores are in two local functions, which the symbol table of an
        object shows and which the rule about global functions alone did not reach."""
        result, body = self.shim_link("shim-local-access.o")
        assert result["instrumented"]["result"] == "fail", result
        facts = check_links.object_facts(body)
        assert facts.defined == ["__rust_alloc"]
        assert len(facts.functions) == 3

    def test_a_local_function_of_another_name_is_not_exempt_either(self):
        """No memory access at all: the rule that every function it defines, of any binding, is the shim's is what
        refuses this one. An object may not carry a function into the exemption by making it local."""
        result, body = self.shim_link("shim-local-call.o")
        assert result["instrumented"]["result"] == "fail", result
        assert not check_links.object_facts(body).memory

    def test_the_shim_of_the_pinned_rust_toolchain_is_exempt_and_listed(self):
        """The member of a real asan link (fixtures/allocator-shim/README.md): the names this change adds, and a
        code of 13 words with no load, store or atomic. It is the object the exemption is for, so it is exempt,
        and the list names it."""
        result, body = self.shim_link("shim-rustc-v0.o")
        assert result["instrumented"]["result"] == "pass", result
        assert {"name": "shim.o", "kind": "rust-allocator-shim",
                "sha256": hashlib.sha256(body).hexdigest()} in result["uninstrumented"]
        facts = check_links.object_facts(body)
        assert not facts.memory
        assert len(facts.functions) == 7

    def test_the_allocator_names_do_not_exempt_a_c_object_that_makes_an_access(self):
        """analyse reads no project.yaml: the exemption is not for Rust projects, it is for objects shaped like the
        shim. One that is not, is not exempt, whatever it is called."""
        body = elf_object(LW * 2, defined=["__rust_alloc"], files=["lib.c"], comment=True)
        record = self.record({"/work/l.a": {"a.o": good(), "lib.c.o": body}},
                             runtimes=(self.LIBC, self.ASAN_RT), build="asan")
        result = self.analyse({"asan": record})["asan"]
        assert result["instrumented"]["result"] == "fail", result
        assert "l.a(lib.c.o)" in result["instrumented"]["detail"]

    def test_a_seal_compiled_from_the_driver_sources_is_the_drivers(self):
        seal = elf_object(NOP, defined=["__wrap_getenv"], comment=True, files=["wrap_getenv.c"])
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={"/work/b/wrap_getenv.o": seal})
        assert self.analyse({"asan": record})["asan"]["instrumented"]["result"] == "pass"
        # The same name, with a function that is not a __wrap_ interposer: the project's code, uninstrumented.
        other = elf_object(NOP, defined=["__wrap_getenv", "helper"], comment=True, files=["wrap_getenv.c"])
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={"/work/b/wrap_getenv.o": other})
        assert self.analyse({"asan": record})["asan"]["instrumented"]["result"] == "fail"

    def test_ubsan_wants_more_traps_than_plain_in_each_archive(self):
        def build(lib, dep):
            return self.record({"/work/b/libproject.a": {"lib.o": elf_object(lib, defined=["f"], comment=True)},
                                "/work/b/libdep.a": {"dep.o": elf_object(dep, defined=["g"], comment=True)}})
        plain = build(NOP * 4, NOP * 4)
        ubsan = build(NOP + UNIMP * 3, NOP + UNIMP)
        assert self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]["result"] == "pass"
        # The dependency's flags lost the sanitizer: the library's traps must not hide it.
        partly = build(NOP + UNIMP * 3, NOP * 4)
        result = self.analyse({"plain": plain, "ubsan": partly})["ubsan"]["instrumented"]
        assert result["result"] == "fail"
        assert "libdep.a: 0" in result["detail"]

    def test_ubsan_compares_each_loose_object_too(self):
        def build(fuzzer, other):
            return self.record({"/work/l.a": {"a.o": elf_object(NOP * 4, defined=["f"], comment=True)}},
                               loose={"/work/b/fuzzer.o": elf_object(fuzzer, defined=["g"], comment=True),
                                      "/work/b/other.o": elf_object(other, defined=["h"], comment=True)})
        plain = build(NOP * 4, NOP * 4)
        # Only the fuzz target's own object got the sanitizer: its traps must not stand for the other object's.
        partly = build(NOP + UNIMP * 3, NOP * 4)
        result = self.analyse({"plain": plain, "ubsan": partly})["ubsan"]["instrumented"]
        assert result["result"] == "fail"
        assert "other.o: 0" in result["detail"]

    def test_ubsan_without_a_plain_build_decides_nothing(self):
        ubsan = self.record({"/work/l.a": {"a.o": elf_object(NOP + UNIMP, defined=["f"], comment=True)}})
        result = self.analyse({"ubsan": ubsan})["ubsan"]["instrumented"]
        assert result["result"] == "error"
        assert "no plain build" in result["detail"]

    def test_assembly_without_dwarf_is_named_by_its_source(self):
        """The toolchain assembles a .S without -g, so the object carries no DWARF and no other mark."""
        asm = elf_object(NOP, defined=["memcpy_fast"])
        record = self.record({"/work/l.a": {"a.o": good(), "memcpy.S.o": asm}})
        asked = []

        def sources(wanted):
            asked.extend(wanted)
            return ["src/arch/memcpy.S"] * len(wanted)

        result = self.analyse({"asan": record}, dwarf_units=lambda objects: [None], assembly_sources=sources)["asan"]
        assert asked == [("memcpy.S.o", ["memcpy_fast"])]
        assert result["instrumented"]["result"] == "pass", result
        assert {"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"} in result["uninstrumented"]
        # No source of the project carries its name and its functions: the object is not shown to be assembly.
        result = self.analyse({"asan": record}, dwarf_units=lambda objects: [None],
                              assembly_sources=lambda wanted: [None] * len(wanted))["asan"]
        assert result["instrumented"]["result"] == "fail"
        assert "no DWARF" in result["instrumented"]["detail"]

    def test_an_allocation_failure_copy_stands_for_its_original(self):
        copy = "/tmp/ov/af.abc/3-libz.a"
        uninstrumented_zlib = archive({"adler32.o": elf_object(NOP, defined=["adler32"], comment=True)})
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={copy: uninstrumented_zlib},
                             renamed={copy: (self.ZLIB, self.IMAGE[self.ZLIB])})
        record.taken = [entry for entry in record.taken if entry[0] != copy] + [(copy, "adler32.o", ".text", 4)]
        result = self.analyse({"asan": record})["asan"]
        assert result["instrumented"]["result"] == "pass", result
        assert {"name": "libz.a", "kind": "image-library", "sha256": "f" * 64} in result["uninstrumented"]

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
            assert result["result"] == "pass", (build, result)
            assert "1 of them by the compile that wrote them" in result["detail"]
            # With no compile record, the traps decide, and there are none.
            result = self.ubsan(build, archives, archives, None)
            assert result["result"] == "fail", (build, result)
            assert "libabsl_log_sink.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]

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
        assert result["result"] == "fail", result
        assert "1 objects were compiled without the build's UndefinedBehaviorSanitizer flags: " \
            "libplanted.a(planted.c.o) (src/planted.c: without -fsanitize=undefined " \
            "-fno-sanitize-recover=all -fsanitize-trap=all)" in result["detail"]

    def test_a_planted_member_whose_source_turns_ubsan_off_fails(self):
        """A load UBSan would check, compiled with the build's flags, no trap, and a source whose no_sanitize attribute
        took the check out (compiled again without it, the object has a trap): the archive's other member has traps,
        which would pass the archive by its count; the record fails the member."""
        planted = elf_object(LW + RET, defined=["planted"], undefined=ASAN, comment=True)
        without = elf_object(LW + UNIMP + RET, defined=["planted"], undefined=ASAN, comment=True)
        checked = elf_object(LW + UNIMP + RET, defined=["checked"], undefined=ASAN, comment=True)
        plain = {"/work/b/libplanted.a": {"checked.c.o": elf_object(LW + RET, defined=["checked"], comment=True),
                                          "planted.c.o": planted}}
        archives = {"/work/b/libplanted.a": {"checked.c.o": checked, "planted.c.o": planted}}
        for build in ("ubsan", "asan-ubsan"):
            for attribute in ('no_sanitize("undefined")', "no_sanitize_undefined",
                              'no_sanitize("signed-integer-overflow", "address")'):
                result = self.ubsan(build, plain, archives, [
                    (checked, "src/checked.c", "c", compile_arguments("src/checked.c")),
                    (planted, "src/planted.c", "c", compile_arguments("src/planted.c"), "/work/b", None,
                     [attribute], without)])
                assert result["result"] == "fail", (build, attribute, result)
                assert "1 objects have no UndefinedBehaviorSanitizer check because the no_sanitize attributes " \
                    "of their source took the checks out: libplanted.a(planted.c.o) (src/planted.c: no UBSan " \
                    "check, and its source's no_sanitize attributes took UBSan checks out of it (1 without " \
                    f"{attribute}))" in result["detail"]

    def test_a_member_with_nothing_to_check_still_passes_with_an_attribute(self):
        """Case 1 with attributes: a source whose attributes took nothing out of the object (compiled again without
        them, it still has no trap: an unused inline function of a header), or whose attributes name only other
        sanitizers, passes by its record; a member whose attribute left some checks in it (it has a trap) passes too."""
        sink = elf_object(RET, defined=["_ZN4absl7LogSinkD2Ev"], undefined=ASAN, comment=True)
        archives = {"/work/b/libabsl_log_sink.a": {"log_sink.cc.o": sink}}
        arguments = compile_arguments("absl/log/log_sink.cc")
        for build in ("ubsan", "asan-ubsan"):
            for more in ([['no_sanitize("pointer-overflow")'], sink], [["no_sanitize_address"]],
                         [['no_sanitize("address")', "no_sanitize"]], [[]]):
                result = self.ubsan(build, archives, archives,
                                    [(sink, "absl/log/log_sink.cc", "c++", arguments, "/work/b", None, *more)])
                assert result["result"] == "pass", (build, more, result)
                assert "1 of them by the compile that wrote them" in result["detail"]
            trapped = elf_object(LW + UNIMP + RET, defined=["f"], undefined=ASAN, comment=True)
            result = self.ubsan(build, {"/work/b/libf.a": {"f.c.o": elf_object(LW + RET, defined=["f"], comment=True)}},
                                {"/work/b/libf.a": {"f.c.o": trapped}},
                                [(trapped, "f.c", "c", compile_arguments("f.c"), "/work/b", None,
                                  ['no_sanitize("shift")'], None)])
            assert result["result"] == "pass", (build, result)

    def test_a_member_with_no_trap_whose_record_cannot_say_is_judged_by_traps(self):
        """A record that cannot say what the source's attributes took out (no_sanitize null: standard input, a response
        file, a precompiled header, a source that could not be preprocessed; or an attribute and no object compiled
        without it) does not decide a
        member with no trap: its archive is judged by its traps, and has none."""
        sink = elf_object(RET, defined=["_ZN4absl7LogSinkD2Ev"], undefined=ASAN, comment=True)
        archives = {"/work/b/libabsl_log_sink.a": {"log_sink.cc.o": sink}}
        for more in ([None], [['no_sanitize("undefined")'], None]):
            result = self.ubsan("ubsan", archives, archives, [
                (sink, "absl/log/log_sink.cc", "c++", compile_arguments("absl/log/log_sink.cc"), "/work/b", None,
                 *more)])
            assert result["result"] == "fail", (more, result)
            assert "libabsl_log_sink.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]

    def test_a_planted_member_with_no_compile_record_fails_by_its_traps(self):
        planted = elf_object(LW + RET, defined=["planted"], comment=True)
        archives = {"/work/b/libplanted.a": {"planted.c.o": planted}}
        # A build with records that has none for these bytes (a compile that ran no shim), and one with no records.
        for compiled in ([], None):
            result = self.ubsan("ubsan", archives, archives, compiled)
            assert result["result"] == "fail", (compiled, result)
            assert "libplanted.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]
            assert "compiled without" not in result["detail"]

    def test_a_member_with_traps_compiled_without_the_flags_fails(self):
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": trapped}},
                            [(trapped, "x.c", "c", compile_arguments("x.c", flags=()))])
        assert result["result"] == "fail", result
        assert "libx.a(x.c.o) (x.c: without" in result["detail"]

    def test_a_compile_that_turns_the_sanitizer_off_after_its_flags_fails(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        result = self.ubsan("ubsan", archives, archives,
                            [(sink, "x.c", "c", compile_arguments("x.c", after=["-fno-sanitize=undefined"]))])
        assert result["result"] == "fail", result
        assert "libx.a(x.c.o) (x.c: with -fno-sanitize=undefined)" in result["detail"]

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
                assert result["result"] == "fail", (word, build, result)
                assert f"libx.a(x.c.o) (x.c: with {word})" in result["detail"]
                assert "AddressSanitizer constructor" not in result["detail"]

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
            assert result["result"] == "fail", (after, result)
            assert f"libx.a(x.c.o) (x.c: with {word})" in result["detail"]

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
            assert result["result"] == "fail", (after, result)
            assert "libx.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]
            assert "1 of them by the compile" not in result["detail"]
            result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": trapped}},
                                [(trapped, "x.c", "c", compile_arguments("x.c", after=after))])
            assert result["result"] == "pass", (after, result)
            assert "by the compile that wrote them" not in result["detail"]

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
            assert result["result"] == "fail", (after, result)
            assert "libx.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]
            assert "by the compile" not in result["detail"]
            assert "compiled without" not in result["detail"]
            result = self.ubsan("ubsan", plain, {"/work/b/libx.a": {"x.c.o": trapped}},
                                [(trapped, "x.c", "c", compile_arguments("x.c", after=after))])
            assert result["result"] == "pass", (after, result)
            assert "by the compile that wrote them" not in result["detail"]

    def test_a_file_option_the_build_gives_itself_decides(self):
        """The same option with the same value in the build's own flags is the build's: the compile decides. Another
        value decides nothing."""
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(sink, "x.c", "c", compile_arguments(
            "x.c", after=["--config", "/opt/build.cfg", "-mllvm", "-some-option"]))])
        record.compiles.sanitizer["c"] += ["--config=/opt/build.cfg", "-mllvm", "-some-option"]
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "pass"
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].arguments.append("--config=/w/other.cfg")
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "libx.a: 0 UBSan traps" in result["detail"]

    def test_a_word_given_through_the_preprocessor_options_counts_as_the_bare_word(self):
        """-Wp, and -Xpreprocessor hand their words to clang's front end as -Xclang does."""
        sink = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = {"/work/b/libx.a": {"x.c.o": elf_object(LW + RET, defined=["f"], comment=True)}}
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        for after, word in ((["-Wp,-fsanitize-ignorelist=ign.txt"], "-fsanitize-ignorelist=ign.txt"),
                            (["-Xpreprocessor", "-fsanitize-ignorelist=ign.txt"], "-fsanitize-ignorelist=ign.txt"),
                            (["-Wp,-MD,x.d,-fno-sanitize=null"], "-fno-sanitize=null")):
            result = self.ubsan("ubsan", plain, archives, [(sink, "x.c", "c", compile_arguments("x.c", after=after))])
            assert result["result"] == "fail", (after, result)
            assert f"libx.a(x.c.o) (x.c: with {word})" in result["detail"]
        sink = elf_object(RET, defined=["f"], comment=True)
        result = self.ubsan("ubsan", {"/work/b/libx.a": {"x.c.o": sink}}, {"/work/b/libx.a": {"x.c.o": sink}},
                            [(sink, "x.c", "c", compile_arguments(
                                "x.c", after=["-Wp,-mllvm,-ubsan-guard-checks"]))])
        assert result["result"] == "fail", result
        assert "libx.a: 0 UBSan traps" in result["detail"]

    def test_the_builds_own_trap_and_recover_words_and_coverage_words_are_not_taken_for_them(self):
        """The build's own -fsanitize-trap=all and -fno-sanitize-recover=all, -fsanitize-coverage=0 (which curl's seed
        gives its protobuf build), and a word the build's own flags have, do not fail a compile."""
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        result = self.ubsan("ubsan", archives, archives,
                            [(sink, "x.c", "c", compile_arguments("x.c", after=["-fsanitize-coverage=0"]))])
        assert result["result"] == "pass", result
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(sink, "x.c", "c", compile_arguments(
            "x.c", after=["-fsanitize-ignorelist=/src/ignore.txt"]))])
        record.compiles.sanitizer["c"].append("-fsanitize-ignorelist=/src/ignore.txt")
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "pass"
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].arguments[-1] = "-fsanitize-ignorelist=/src/b.txt"
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "with -fsanitize-ignorelist=/src/b.txt" in result["detail"]

    def test_any_compile_of_the_same_bytes_with_the_flags_decides(self):
        """Two compiles that wrote the same bytes, one without the flags (a host tool's copy, say): the bytes are the
        same whichever made them, so the one with the flags makes the member instrumented."""
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.c.o": sink}}
        result = self.ubsan("ubsan", archives, archives, [(sink, "x.c", "c", compile_arguments("x.c", flags=())),
                                                          (sink, "x.c", "c", compile_arguments("x.c"))])
        assert result["result"] == "pass", result

    def test_a_compile_the_records_cannot_judge_falls_back_to_the_traps(self):
        """Assembly, which UBSan does not instrument, and arguments in a response file decide nothing."""
        code = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.o": code}}
        for language, arguments in (("assembler-with-cpp", compile_arguments("x.S", flags=())),
                                    ("c", ["@x.rsp", "-c", "x.c"])):
            result = self.ubsan("ubsan", archives, archives, [(code, "x", language, arguments)])
            assert result["result"] == "fail", (language, result)
            assert "libx.a: 0 UBSan traps" in result["detail"]
            assert "compiled without" not in result["detail"]

    def test_an_exclusion_counts_only_where_the_build_has_it(self):
        """compile leaves OV_UBSAN_C_EXCLUDE out of the C compiles only: a C++ compile with it adds an exclusion."""
        plain = self.record({}, build="plain")
        sink = elf_object(RET, defined=["f"], comment=True)
        record = self.record({"/work/b/libx.a": {"x.o": sink}},
                             compiled=[(sink, "x", "c", compile_arguments("x", after=["-fno-sanitize=vptr"]))])
        record.compiles.sanitizer["c"].append("-fno-sanitize=vptr")
        record.compiles.ubsan["c"].append("-fno-sanitize=vptr")
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "pass"
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].language = "c++"
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "with -fno-sanitize=vptr" in result["detail"]
        # A C compile need not repeat the exclusion: with it off, the compile has more checks, not fewer.
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0] = check_links.Compile(
            "x.c", "c", compile_arguments("x.c"), no_sanitize=[])
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "pass"

    def test_a_later_lower_strict_flex_arrays_level_takes_the_check_away(self):
        """clang keeps only the last -fstrict-flex-arrays= it is given: when the build's UBSan flags give level 1, a
        compile that gives 0 after them did not carry them; one that keeps 1 or gives a higher level did. A word handed
        on to the front end counts against the compile, never for it. A build without the flag holds no level."""
        plain = self.record({}, build="plain")
        sink = elf_object(RET, defined=["f"], undefined=ASAN, comment=True)
        flags = UBSAN_FLAGS + ["-fstrict-flex-arrays=1"]
        for after, word in ((["-fstrict-flex-arrays=0"], "-fstrict-flex-arrays=0"),
                            (["-fstrict-flex-arrays=3", "-fstrict-flex-arrays=0"], "-fstrict-flex-arrays=0"),
                            (["-Xclang", "-fstrict-flex-arrays=0"], "-fstrict-flex-arrays=0"),
                            (["-Xclang=-fstrict-flex-arrays=0", "-fstrict-flex-arrays=3"], "-fstrict-flex-arrays=0"),
                            (["-Wp,-fstrict-flex-arrays=0"], "-fstrict-flex-arrays=0"),
                            (["-fstrict-flex-arrays=x"], "-fstrict-flex-arrays=x"),
                            (["-fstrict-flex-arrays=²"], "-fstrict-flex-arrays=²"),
                            (["-fstrict-flex-arrays=0", "-fstrict-flex-arrays=2"], None),
                            ([], None), (["-fstrict-flex-arrays=1"], None), (["-fstrict-flex-arrays=3"], None),
                            (["-Xclang", "-fstrict-flex-arrays=2"], None)):
            for build in ("ubsan", "asan-ubsan"):
                record = self.record({"/work/b/libx.a": {"x.c.o": sink}}, build=build,
                                     compiled=[(sink, "x.c", "c", compile_arguments("x.c", flags=flags, after=after))])
                for language in ("c", "c++"):
                    record.compiles.ubsan[language].append("-fstrict-flex-arrays=1")
                    record.compiles.sanitizer[language].append("-fstrict-flex-arrays=1")
                result = self.analyse({"plain": plain, build: record})[build]["instrumented"]
                if word is None:
                    assert result["result"] == "pass", (after, build, result)
                else:
                    assert result["result"] == "fail", (after, build, result)
                    assert f"libx.a(x.c.o) (x.c: with {word})" in result["detail"]
        # Without the flag in the build's own UBSan flags, a level in the compile is the project's choice.
        record = self.record({"/work/b/libx.a": {"x.c.o": sink}}, compiled=[
            (sink, "x.c", "c", compile_arguments("x.c", after=["-fstrict-flex-arrays=0"]))])
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "pass"
        # A build level that is not decimal digits cannot be compared: a compile that then gives a decimal level fails,
        # and no traceback stops the check.
        record = self.record({"/work/b/libx.a": {"x.c.o": sink}}, compiled=[
            (sink, "x.c", "c", compile_arguments("x.c", flags=UBSAN_FLAGS + ["-fstrict-flex-arrays=²"],
                                                 after=["-fstrict-flex-arrays=1"]))])
        for language in ("c", "c++"):
            record.compiles.ubsan[language].append("-fstrict-flex-arrays=²")
            record.compiles.sanitizer[language].append("-fstrict-flex-arrays=²")
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "libx.a(x.c.o) (x.c: with -fstrict-flex-arrays=²)" in result["detail"]

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
                assert result["result"] == "fail", (build, wanted, result)
                assert "libx.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]
                assert "by the compile that wrote them" not in result["detail"]
                assert "the build's recorded UndefinedBehaviorSanitizer flags for C and C++ turn on no check" in \
                    result["detail"]

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
        assert result["result"] == "fail", result
        assert "libc.a: 0 UBSan traps" in result["detail"]
        assert "libcxx.a" not in result["detail"]
        assert "flags for C turn on no check" in result["detail"]

    def test_a_build_with_no_compile_records_says_so(self):
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        plain = self.record({"/work/b/libx.a": {"x.o": elf_object(LW + RET, defined=["f"], comment=True)}})
        ubsan = self.record({"/work/b/libx.a": {"x.o": trapped}})
        result = self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]
        assert result["result"] == "pass", result
        assert "the build has no compile records that this reads" in result["detail"]

    def test_another_builds_compile_records_decide_nothing(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.o": sink}}
        plain = self.record(archives, build="plain")
        record = self.record(archives, compiled=[(sink, "x.c", "c", compile_arguments("x.c"))], build="ubsan")
        record.compiles.build = "asan-ubsan"
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "fail"

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
            assert result["result"] == verdict, result
            assert "fuzzer.o" in result["detail"]

    def test_an_archive_with_code_no_record_decides_is_judged_by_its_checks(self):
        """A member that no record decides (here, assembly) leaves its archive to the trap count, as before."""
        sink = elf_object(RET, defined=["f"], comment=True)
        asm = elf_object(RET, defined=["g"])
        archives = {"/work/b/libx.a": {"x.o": sink, "g.o": asm}}
        compiled = [(sink, "x.c", "c", compile_arguments("x.c")),
                    (asm, "g.S", "assembler-with-cpp", compile_arguments("g.S", ()))]
        result = self.ubsan("ubsan", archives, archives, compiled)
        assert result["result"] == "fail", result
        assert "libx.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]
        trapped = elf_object(LW + UNIMP + RET, defined=["f"], comment=True)
        result = self.ubsan("ubsan", {"/work/b/libx.a": {"x.o": elf_object(LW + RET, defined=["f"], comment=True),
                                                         "g.o": asm}},
                            {"/work/b/libx.a": {"x.o": trapped, "g.o": asm}},
                            [(trapped, "x.c", "c", compile_arguments("x.c")),
                             (asm, "g.S", "assembler-with-cpp", compile_arguments("g.S", ()))])
        assert result["result"] == "pass", result

    def test_the_plain_build_is_needed_only_for_code_no_record_decides(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        archives = {"/work/b/libx.a": {"x.o": sink}}
        result = self.analyse({"ubsan": self.record(archives, compiled=[(sink, "x.c", "c",
                                                                         compile_arguments("x.c"))])})["ubsan"]
        assert result["instrumented"]["result"] == "pass", result
        # With no records, as before: no plain build, no decision.
        result = self.analyse({"ubsan": self.record(archives)})["ubsan"]
        assert result["instrumented"]["result"] == "error", result
        assert "no plain build" in result["instrumented"]["detail"]

    def test_an_exclusion_the_build_makes_is_allowed_by_check_name(self):
        sink = elf_object(RET, defined=["f"], comment=True)
        plain = self.record({}, build="plain")
        record = self.record({"/work/b/libx.a": {"x.o": sink}},
                             compiled=[(sink, "x.cc", "c++", compile_arguments("x.cc", after=["-fno-sanitize=vptr"]))])
        record.compiles.sanitizer["c++"][-1] = "-fno-sanitize=function,vptr"
        assert self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]["result"] == "pass"
        record.compiles.objects[hashlib.sha256(sink).hexdigest()][0].arguments.append("-fno-sanitize=vptr,null")
        result = self.analyse({"plain": plain, "ubsan": record})["ubsan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "with -fno-sanitize=vptr,null" in result["detail"]

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
        assert sorted(compiles.objects) == ["a" * 64, "b" * 64]
        assert compiles.objects["a" * 64][0].arguments == ["-c", "x.c"]
        # No records, flags that are not the build's, or a link planted in their place: no records.
        (records / "compiles.jsonl").unlink()
        assert check_links.read_compiles(self.raw) is None
        (records / "compiles.jsonl").symlink_to(records / "flags.json")
        assert check_links.read_compiles(self.raw) is None
        (records / "compiles.jsonl").unlink()
        (records / "compiles.jsonl").write_text(good_line + "\n")
        (records / "flags.json").write_text('{"build": "ubsan", "sanitizer": {"c": []}}')
        assert check_links.read_compiles(self.raw) is None

    def test_a_changed_image_file_is_examined_as_the_projects_code(self):
        changed = archive({"x.o": elf_object(NOP, defined=["x"], comment=True)})
        record = self.record({"/work/l.a": {"a.o": good()}, "/opt/musl-sysroot/usr/lib/libnew.a": {}},
                             loose={})
        record.inputs["/opt/musl-sysroot/usr/lib/libnew.a"] = ("/opt/musl-sysroot/usr/lib/libnew.a", self.keep(changed),
                                                              len(changed))
        record.taken.append(("/opt/musl-sysroot/usr/lib/libnew.a", "x.o", ".text", 4))
        result = self.analyse({"asan": record})["asan"]
        assert result["instrumented"]["result"] == "fail"
        assert "libnew.a(x.o)" in result["instrumented"]["detail"]

    # A C library that the build declares (link-fuzz-target, OV_LIBC), as musl's make install lays out its lib
    # directory, here in the build directory. No sanitizer instruments it: its code refers to no AddressSanitizer
    # constructor and holds no UBSan trap.
    MUSL = "/work/b/musl/lib/"
    MUSL_LIBC = {"memcpy.lo": elf_object(LW + RET, defined=["memcpy"], files=["memcpy.c"], comment=True)}
    MUSL_CRT1 = elf_object(NOP, defined=["_start"], files=["crt1.c"], comment=True)

    def declared_record(self, archives, runtimes=(ZLIB,), take=True, declare=True):
        """A Record (record) whose link also took the C library under MUSL: libc.a's member and crt1.o, with their
        bytes in the store. With `take` False, the link took neither. With `declare`, the build declares that C
        library: the record's libc field names the four files, libc.a and crt1.o with the sha256 of the bytes kept."""
        loose = {}
        if take:
            archives = {**archives, self.MUSL + "libc.a": self.MUSL_LIBC}
            loose = {self.MUSL + "crt1.o": self.MUSL_CRT1}
        record = self.record(archives, runtimes=runtimes, loose=loose)
        if declare:
            record.libc = {"libc.a": (self.MUSL + "libc.a", hashlib.sha256(archive(self.MUSL_LIBC)).hexdigest()),
                           "crt1.o": (self.MUSL + "crt1.o", hashlib.sha256(self.MUSL_CRT1).hexdigest()),
                           "crti.o": (self.MUSL + "crti.o", "3" * 64), "crtn.o": (self.MUSL + "crtn.o", "4" * 64)}
        return record

    def declared_builds(self, **options):
        """analyse of the four builds of a link that took the project's code, instrumented as each build wants it, an
        image library, and the C library under MUSL (declared_record, with `options`)."""
        project = {"plain": elf_object(LW + RET, defined=["f"], files=["lib.c"], comment=True),
                   "ubsan": elf_object(LW + UNIMP + RET, defined=["f"], files=["lib.c"], comment=True),
                   "asan": elf_object(LW + RET, defined=["f"], undefined=ASAN, files=["lib.c"], comment=True),
                   "asan-ubsan": elf_object(LW + UNIMP + RET, defined=["f"], undefined=ASAN, files=["lib.c"],
                                            comment=True)}
        return self.analyse({build: self.declared_record({"/work/b/libproject.a": {"lib.c.o": body}}, **options)
                             for build, body in project.items()})

    def declared_line(self, binary):
        """The line at the end of the report that names the C library of declared_record for `binary`."""
        return (f"- `{binary}`: "
                f"`libc.a` `{self.MUSL}libc.a` sha256 `{hashlib.sha256(archive(self.MUSL_LIBC)).hexdigest()}`, "
                f"`crt1.o` `{self.MUSL}crt1.o` sha256 `{hashlib.sha256(self.MUSL_CRT1).hexdigest()}`, "
                f"`crti.o` `{self.MUSL}crti.o` sha256 `{'3' * 64}`, `crtn.o` `{self.MUSL}crtn.o` sha256 `{'4' * 64}`")

    def test_a_declared_libc_is_listed_and_exempt_in_each_build(self):
        """The declared libc.a and crt1.o are listed by name, with kind libc and the sha256 of the declared bytes,
        after the image's files (path order). No build reads them as the project's code: the plain build is plain,
        and the three sanitizer builds pass. Each build's detail names the four declared files and their sha256."""
        libc_sha256 = hashlib.sha256(archive(self.MUSL_LIBC)).hexdigest()
        crt1_sha256 = hashlib.sha256(self.MUSL_CRT1).hexdigest()
        for build, result in self.declared_builds().items():
            assert result["uninstrumented"] == [
                {"name": "libz.a", "kind": "image-library", "sha256": "f" * 64},
                {"name": "crt1.o", "kind": "libc", "sha256": crt1_sha256},
                {"name": "libc.a", "kind": "libc", "sha256": libc_sha256},
            ], build
            assert result["instrumented"]["result"] == ("plain" if build == "plain" else "pass"), (build, result)
            detail = result["instrumented"]["detail"]
            if build == "plain":
                assert detail.startswith(check_links.PLAIN_DETAIL), detail
            for name, sha256 in (("libc.a", libc_sha256), ("crt1.o", crt1_sha256), ("crti.o", "3" * 64),
                                 ("crtn.o", "4" * 64)):
                assert f"{name} ({self.MUSL}{name}, sha256 {sha256})" in detail, build

    def test_the_report_names_a_declared_libc(self):
        """The report of the four builds of test_a_declared_libc_is_listed_and_exempt_in_each_build, whose results
        are pass, and plain in the plain build. The enrollment's review reads the report, which gives a detail only
        for the other results, so the report names the C library that each build's record declares (binary_checks
        gives the record's libc file): each build's cell of uninstrumented code says so, and a line at the end of the
        report gives the path and the sha256 of each of the four files, none cut. The same builds with no declared C
        library give the report that such a build always got, also when the note is in their detail: the report does
        not read the detail for it. With a failure, these lines come after "What each failure is", so a cut from the
        end takes them first."""
        builds = ["plain", "ubsan", "asan", "asan-ubsan"]
        results = self.declared_builds()
        libc = self.declared_record({}, take=False).libc
        libc_sha256 = hashlib.sha256(archive(self.MUSL_LIBC)).hexdigest()
        crt1_sha256 = hashlib.sha256(self.MUSL_CRT1).hexdigest()
        note = ("the build declares its own C library (OV_LIBC), whose files no sanitizer instruments: "
                + ", ".join(f"{name} ({self.MUSL}{name}, sha256 {sha256})"
                            for name, sha256 in (("libc.a", libc_sha256), ("crt1.o", crt1_sha256),
                                                 ("crti.o", "3" * 64), ("crtn.o", "4" * 64))))

        def report(instrumented, declared_libc):
            """The report of the four builds, with each one's instrumented result from `instrumented`, and
            `declared_libc` as the C library of each."""
            block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                     "targets": {"t": {build: {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                               "quiet_loud": {"result": "pass"}, "instrumented": instrumented[build]}
                                       for build in builds}}}
            return check_binaries.report(block, {"t": {build: results[build]["uninstrumented"] for build in builds}},
                                         builds, {"t": {build: declared_libc for build in builds}})

        head = ("### The checks of the binaries\n\n"
                "Against the process model the published proofs use: `m` at `ffffffffffff` (release `x`, from its "
                "release.yaml).\n"
                f"Each fuzz target ran on the empty input and up to {check_binaries.MAX_SEEDS} seed inputs (`t`: 1). "
                "docs/build-contract.md, \"The checks of the binaries\", says what each check proves.\n\n"
                "| binary | ELF and instructions | system calls | quiet and loud | instrumented | uninstrumented code "
                "|\n|---|---|---|---|---|---|\n")
        rows = ("| `t.plain` | pass | pass | pass | not instrumented (plain) | 3 files{} |\n"
                "| `t.ubsan` | pass | pass | pass | pass | 3 files{} |\n"
                "| `t.asan` | pass | pass | pass | pass | 3 files{} |\n"
                "| `t.asan-ubsan` | pass | pass | pass | pass | 3 files{} |\n")
        declared = {build: results[build]["instrumented"] for build in builds}
        for build in builds:
            assert "; " + note in declared[build]["detail"], build
        # With no declared C library, and so no note, the report is the one that the same results got before.
        undeclared = {build: {**declared[build], "detail": declared[build]["detail"].replace("; " + note, "")}
                      for build in builds}
        assert report(undeclared, None) == head + rows.format(*[""] * 4)
        assert report(declared, None) == head + rows.format(*[""] * 4)
        noted = rows.format(*[", a declared C library"] * 4)
        listing = ("These builds declare their own C library (OV_LIBC). Check C5 of review.md says what the review "
                   "checks:\n\n" + "".join(self.declared_line(f"t.{build}") + "\n" for build in builds))
        assert report(declared, libc) == head + noted + "\n" + listing
        failed = {**declared, "asan": {**declared["asan"], "result": "fail"}}
        assert report(failed, libc) == \
            head + noted.replace("| `t.asan` | pass | pass | pass | pass |",
                                 "| `t.asan` | pass | pass | pass | **fail** |") \
            + f"\nWhat each failure is:\n\n- `t.asan`, instrumented: `{declared['asan']['detail']}`\n\n" \
            + listing

    def test_the_report_names_a_declared_libc_of_a_record_with_a_problem(self):
        """A record of which the reader kept no input section of the map (Record.problem), in builds that declare a C
        library: the problem is each build's whole detail, with no note, and the result is error. read_record has
        read the record's libc file, so the report names the C library all the same, in the cell and in a line at the
        end, with the path and the sha256 of each of the four files."""
        problem = ("the reader kept no input section of the link's map: 3 non-blank lines, 3 read as input sections, "
                   "0 kept; the first line: <internal>:(.comment)")
        records = {}
        for build in ("plain", "asan"):
            records[build] = self.declared_record({"/work/b/libproject.a": {"lib.c.o": good()}})
            records[build].problem = problem
        results = self.analyse(records)
        assert results["asan"] == {"uninstrumented": None, "instrumented": {"result": "error", "detail": problem}}
        assert results["plain"]["instrumented"]["detail"] == f"{check_links.PLAIN_DETAIL}; {problem}"
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {build: {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                           "quiet_loud": {"result": "pass"}, "instrumented": result["instrumented"]}
                                   for build, result in results.items()}}}
        text = check_binaries.report(block, {"t": {"plain": None, "asan": None}}, ["plain", "asan"],
                                     {"t": {build: record.libc for build, record in records.items()}})
        for build in ("plain", "asan"):
            assert f"| `t.{build}` | pass | pass | pass | **not decided** | not recorded, a declared C " \
                "library |\n" in text
            assert f"- `t.{build}`, instrumented: " in text
        assert text.endswith("These builds declare their own C library (OV_LIBC). Check C5 of review.md says "
                             f"what the review checks:\n\n{self.declared_line('t.plain')}\n"
                             f"{self.declared_line('t.asan')}\n"), text

    def test_the_report_gives_each_declared_file_whole(self):
        """The paths of the test project's asan-ubsan build of libc_fuzzer: tests/fixtures/target-settings/ makes its C
        library under /work/build/lib/$FLAV, and FLAV is asanubsan in that build. The report gives each path and each
        sha256 whole. A path of more than 300 characters is cut, and the sha256 of its file is still whole."""
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"asan-ubsan": {
                     "elf": {"result": "pass"}, "system_calls": {"result": "pass"}, "quiet_loud": {"result": "pass"},
                     "instrumented": {"result": "pass", "detail": "1 objects with code, all instrumented"}}}}}
        long = "/work/" + "d" * 300 + "/lib/"
        for lib, shown in (("/work/build/lib/asanubsan/fxs-libc.libc/lib/", None),
                           (long, "/work/" + "d" * 293 + "…")):
            libc = {name: (lib + name, str(n) * 64) for n, name in enumerate(check_links.DECLARED_LIBC, 1)}
            text = check_binaries.report(block, {"t": {"asan-ubsan": []}}, ["asan-ubsan"], {"t": {"asan-ubsan": libc}})
            assert "| `t.asan-ubsan` | pass | pass | pass | pass | 0 files, a declared C library |\n" in text
            line = ", ".join(f"`{name}` `{shown or lib + name}` sha256 `{str(n) * 64}`"
                             for n, name in enumerate(check_links.DECLARED_LIBC, 1))
            assert text.endswith(f"\n\n- `t.asan-ubsan`: {line}\n"), text

    def test_a_declared_path_cannot_change_the_list(self):
        """link-fuzz-target takes any absolute path that ends in /libc.a. So a declared path can hold "; ", which also
        joins the parts of a detail, and text that reads as the crtn.o entry of the detail's note, with a sha256 that
        is not the file's. The report makes each line from the four files of the record, not from the detail: the
        line of a plain build with a problem after the note gives each path whole and the four real sha256 values."""
        lib = f"/work/a; b/crtn.o (x, sha256 {'9' * 64})/lib/"
        libc = {name: (lib + name, str(n) * 64) for n, name in enumerate(check_links.DECLARED_LIBC, 1)}
        note = check_links.libc_note(check_links.Record([], {}, set(), {}, self.raw, None, libc=libc))
        problem = ("/opt/musl-sysroot/usr/lib/libnew.a: a file of the toolchain image that no kind names "
                   "(src/oss_verify/check_links.py, runtime_kind)")
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"plain": {
                     "elf": {"result": "pass"}, "system_calls": {"result": "pass"}, "quiet_loud": {"result": "pass"},
                     "instrumented": {"result": "error", "detail": f"{check_links.PLAIN_DETAIL}; {note}; {problem}"}}}}}
        text = check_binaries.report(block, {"t": {"plain": None}}, ["plain"], {"t": {"plain": libc}})
        assert "| **not decided** | not recorded, a declared C library |\n" in text
        assert text.endswith(
            f"\n\n- `t.plain`: `libc.a` `{lib}libc.a` sha256 `{'1' * 64}`, `crt1.o` `{lib}crt1.o` sha256 `{'2' * 64}`, "
            f"`crti.o` `{lib}crti.o` sha256 `{'3' * 64}`, `crtn.o` `{lib}crtn.o` sha256 `{'4' * 64}`\n"), text

    def test_the_same_libc_undeclared_fails_the_asan_builds(self):
        """The control: the same C library with no declaration is the project's code, uninstrumented, as before."""
        results = self.declared_builds(declare=False)
        for build in ("asan", "asan-ubsan"):
            result = results[build]["instrumented"]
            assert result["result"] == "fail", (build, result)
            assert "2 of 3 objects with code refer to no AddressSanitizer constructor" in result["detail"]
            assert "libc.a(memcpy.lo)" in result["detail"]
        assert results["plain"]["uninstrumented"] == [{"name": "libz.a", "kind": "image-library", "sha256": "f" * 64}]

    def test_an_undeclared_archive_beside_a_declared_libc_is_judged_as_before(self):
        """An uninstrumented archive that the build does not declare fails AddressSanitizer's check. The plain
        build's counts, the UndefinedBehaviorSanitizer's baseline, hold no declared file."""
        other = {"o.c.o": elf_object(LW + RET, defined=["g"], files=["o.c"], comment=True)}
        asan = self.declared_record({"/work/b/libproject.a": {"lib.c.o": good()}, "/work/b/libother.a": other})
        result = self.analyse({"asan": asan})["asan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "1 of 2 objects with code refer to no AddressSanitizer constructor: libother.a(o.c.o)" in \
            result["detail"]
        plain = self.declared_record({"/work/b/libproject.a": {"lib.c.o": elf_object(LW + RET, defined=["f"],
                                                                                      comment=True)},
                                      "/work/b/libother.a": other})
        code, _provided, problems = check_links.project_code(plain, self.IMAGE)
        assert problems == []
        assert check_links.ub_count(code) == {"libproject.a": 0, "libother.a": 0}
        ubsan = self.declared_record({"/work/b/libproject.a": {"lib.c.o": elf_object(LW + UNIMP + RET, defined=["f"],
                                                                                      comment=True)},
                                      "/work/b/libother.a": other})
        result = self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]
        assert result["result"] == "fail", result
        assert "libother.a: 0 UBSan traps and UB checks, the plain build's 0" in result["detail"]
        assert "libc.a: " not in result["detail"]

    def test_a_declared_libc_the_link_did_not_take_is_an_error(self):
        """A declaration that the link ignored: the list would name a C library that the binary does not hold, so
        each build has no list and the result error."""
        for build, result in self.declared_builds(take=False).items():
            assert result["uninstrumented"] is None, build
            assert result["instrumented"]["result"] == "error", (build, result)
            assert f"the link did not take the C library that the build declares (OV_LIBC): {self.MUSL}libc.a" in \
                result["instrumented"]["detail"]

    def test_an_image_libc_file_beside_a_declared_libc_is_an_error(self):
        """The image's libc.a, or the image's crt1.o, beside a declared C library: the link took two C libraries, so
        each build has no list and the result error."""
        for path in (self.LIBC, self.CRT1):
            for build, result in self.declared_builds(runtimes=(path, self.ZLIB)).items():
                assert result["uninstrumented"] is None, (path, build)
                assert result["instrumented"]["result"] == "error", (path, build, result)
                assert f"the link took {path}, the toolchain image's {path.rsplit('/', 1)[-1]}, beside the C " \
                    "library that the build declares (OV_LIBC)" in result["instrumented"]["detail"]

    def test_other_bytes_at_the_declared_path_are_the_projects_code(self):
        """A libc.a at the declared path whose bytes are not the declared ones is the project's code, judged as any
        other archive, and the declared libc.a counts as not taken."""
        record = self.declared_record({"/work/b/libproject.a": {"lib.c.o": good()}})
        record.libc["libc.a"] = (self.MUSL + "libc.a", "9" * 64)
        result = self.analyse({"asan": record})["asan"]
        assert result["uninstrumented"] is None
        assert result["instrumented"]["result"] == "error", result
        detail = result["instrumented"]["detail"]
        assert "1 of 2 objects with code refer to no AddressSanitizer constructor: libc.a(memcpy.lo)" in detail
        assert f"the link did not take the C library that the build declares (OV_LIBC): {self.MUSL}libc.a" in detail

    def test_no_record(self):
        result = self.analyse({"asan": "compile recorded no link of it"})["asan"]
        assert result["uninstrumented"] is None
        assert result["instrumented"]["result"] == "error"
        # The plain build with no record is not decided either, whatever the cause, and the report says why.
        for why in ("compile recorded no link of it", "its link has no map, and it is not a Go program linked from "
                                                      "Go code only (0 .go.buildinfo sections, not one)"):
            result = self.analyse({"plain": why})["plain"]
            assert result["uninstrumented"] is None
            assert result["instrumented"] == {"result": "error", "detail": f"no link record: {why}"}
            block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                     "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                                 "quiet_loud": {"result": "pass"},
                                                 "instrumented": result["instrumented"]}}}}
            text = check_binaries.report(block, {"t": {"plain": None}}, ["plain"], {"t": {"plain": None}})
            assert "| `t.plain` | pass | pass | pass | **not decided** | not recorded |" in text
            assert f"What each failure is:\n\n- `t.plain`, instrumented: `no link record: {why}`" in text

    def test_a_go_program_is_plain_from_its_build_information(self):
        """Go's linker writes no map; the program's own build information stands in for the record."""
        program = check_links.go_program(go_executable())
        assert isinstance(program, check_links.GoProgram), program
        assert program.version == "go1.27.1"
        result = self.analyse({"plain": program})["plain"]
        assert result["uninstrumented"] is None
        assert result["instrumented"]["result"] == "plain"
        assert "a Go program (go1.27.1)" in result["instrumented"]["detail"]
        assert "CGO_ENABLED=0" in result["instrumented"]["detail"]
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                             "quiet_loud": {"result": "pass"},
                                             "instrumented": result["instrumented"]}}}}
        text = check_binaries.report(block, {"t": {"plain": None}}, ["plain"], {"t": {"plain": None}})
        assert "| `t.plain` | pass | pass | pass | not instrumented (plain) | no list (Go code only) |" in text
        # No sanitizer instruments Go code, so a sanitizer build of a Go program decides nothing.
        assert self.analyse({"asan": program})["asan"]["instrumented"]["result"] == "error"

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
            assert isinstance(why, str), expected
            assert expected in why
        # Zero bytes after the last function are padding; any other byte there is code the table does not name.
        end = len(GO_FUNCTIONS) * 16
        padded = go_executable(text_size=end + 16)
        assert isinstance(check_links.go_program(padded), check_links.GoProgram)
        code = bytearray(padded)
        code[64 + end] = 0x13
        assert "not zero padding" in check_links.go_program(bytes(code))
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
        assert isinstance(check_links.go_program(stdlib), check_links.GoProgram)
        # A stub of the trampoline's shape that jumps anywhere but a function's entry is not the linker's: entered at
        # +2, the other stub's auipc word decodes as a compressed instruction of the author's choice. Two stubs at 80
        # and 96, each jumping 2 bytes into the other; and one that jumps past every function.
        for stubs in ((18, -14), (0x1000,)):
            gadget = go_executable(functions=GO_FUNCTIONS + tuple(
                (f"q_tramp{n}", trampoline(jump), False) for n, jump in enumerate(stubs)))
            assert "no line table, so code that Go did not compile" in check_links.go_program(gadget), stubs

    def test_code_outside_the_function_table_is_not_go_code(self):
        # Go's linker lists no .L label or section container of a .syso file on riscv64, and lays host code out first:
        # code before the table's first function is code that no Go function owns.
        assert "does not start at .text's start" in check_links.go_program(go_executable(skip=16))
        # A .syso symbol that an empty Go assembly TEXT also defines takes that TEXT's line table, and is listed a
        # second time, out of address order: function 2 here starts before function 1.
        why = check_links.go_program(go_executable(entries={2: 8}))
        assert "not in address order" in why
        assert "runs past the end" not in why
        # The last entry is the end of the code: one below the last function names no function past it.
        assert "the code ends before function 4" in check_links.go_program(go_executable(entries={5: 0}))
        # A function's name must lie in funcnametab, also for a function with a line table, whose name is not read.
        assert "function 0 has no name" in check_links.go_program(go_executable(name_offset=1 << 20))
        # The machine's target is the jump's sum with bit 0 cleared (jalr): a jump of 17 from 80 lands at 96.
        assert check_links.linker_function(trampoline(17), 80, {96})
        assert not check_links.linker_function(trampoline(17), 80, {97})
        # A function at an odd offset: Go starts every function at an even one, and a jump cannot land on it.
        assert "starts at the odd offset 0x51" in \
            check_links.go_program(go_executable(functions=GO_FUNCTIONS + (
                ("p", b"\0", False), ("s", trampoline(47), False))))

    def test_a_crafted_function_table_is_read_in_linear_time(self):
        # Thousands of functions with no line table, all named by one long run of bytes: each name is read for at
        # most NAME_MAX_GO bytes, so the work stays linear, and the program is not Go-only.
        n = 20000
        functions = [("x" * 400000, NOP16, False)] + [("y", NOP16, False)] * (n - 1)
        data = go_executable(functions=functions, shared_name=True)
        start = time.monotonic()
        why = check_links.go_program(data)
        assert time.monotonic() - start < 10
        assert "x" * check_links.NAME_MAX_GO in why
        assert "x" * (check_links.NAME_MAX_GO + 1) not in why
        # Functions with a line table are not named at all: their names are never read.
        plain = go_executable()
        _, sections, _ = check_links.binary_isa.parse_elf(plain)
        assert {f[2] for f in check_links.go_functions(plain, sections)} == {None}

    def test_a_go_program_that_cannot_be_read_fails_that_binary_only(self, tmp_path):
        raw = tmp_path / "out"
        raw.mkdir()
        (raw / "t").write_bytes(go_executable())
        saved = check_links.go_program

        def raises(data):
            raise MemoryError("a crafted table")

        check_links.go_program = raises
        try:
            record, _ = check_binaries.record_of(raw, "t")
        finally:
            check_links.go_program = saved
        assert isinstance(record, str)
        assert "MemoryError: a crafted table" in record

    def test_record_of_reads_a_go_program_and_refuses_any_other_binary_without_a_map(self, tmp_path):
        raw = tmp_path / "out"
        raw.mkdir()
        go, other = go_executable(), go_executable(CGO_ENABLED="1")
        (raw / "go").write_bytes(go)
        (raw / "c").write_bytes(other)
        record, quiet = check_binaries.record_of(raw, "go")
        assert isinstance(record, check_links.GoProgram)
        assert quiet is None
        # compile-go keeps the quiet program in a record with no map.
        kept = raw / ".records" / hashlib.sha256(go).hexdigest()
        kept.mkdir(parents=True)
        (kept / "quiet").write_bytes(b"quiet")
        record, quiet = check_binaries.record_of(raw, "go")
        assert isinstance(record, check_links.GoProgram)
        assert quiet == b"quiet"
        record, quiet = check_binaries.record_of(raw, "c")
        assert isinstance(record, str)
        assert "compile recorded no link of it" in record
        assert "CGO_ENABLED=1" in record
        assert check_links.analyse({"plain": record}, {})["plain"]["instrumented"]["result"] == "error"

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
        assert check_links.parse_dwarfdump(text) == \
            {"/objects/0.o": ("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")}


BUILDER = pathlib.Path(__file__).resolve().parents[1] / "infra" / "base-builder"
RECORD_COMPILE = BUILDER / "record-compile"


class TestCompileRecords:
    """infra/base-builder/record-compile, with a stand-in for a compiler shim; the wrapper compile writes; and the
    record code of compile and release-target.sh."""

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

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.dir = pathlib.Path(os.path.realpath(tmp_path))
        self.records = self.dir / "records"
        self.shim = self.dir / "riscv64-linux-musl-clang-plain"
        self.shim.write_text(self.SHIM)
        self.shim.chmod(0o755)

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
        assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)
        assert (self.dir / "x.o").read_bytes() == made
        assert self.lines() == [{"sha256": hashlib.sha256(made).hexdigest(), "output": "x.o",
                                 "directory": str(self.dir), "file": "src/x.c",
                                 "source_sha256": hashlib.sha256(b"int x;\n").hexdigest(), "language": "c",
                                 "no_sanitize": [], "no_sanitize_object": None, "shim": str(self.shim),
                                 "arguments": arguments}]
        records = self.dir / "out" / ".records"
        records.mkdir(parents=True)
        (records / "flags.json").write_text('{"build": "ubsan", "sanitizer": {"c": [], "c++": []}, '
                                            '"ubsan": {"c": [], "c++": []}}')
        (records / "compiles.jsonl").write_text(next((self.records / "compiles").iterdir()).read_text())
        compiles = check_links.read_compiles(self.dir / "out")
        compile, = compiles.objects[hashlib.sha256(made).hexdigest()]
        assert (compile.directory, compile.source_sha256) == (str(self.dir), hashlib.sha256(b"int x;\n").hexdigest())

    def test_a_source_from_standard_input_has_no_source_sha256(self):
        assert self.run_shim("-x", "c", "-c", "-", "-o", "x.o").returncode == 0
        assert [(line["file"], line["source_sha256"]) for line in self.lines()] == [("-", None)]

    def test_a_compile_records_the_no_sanitize_attributes_of_its_preprocessed_source(self):
        """record-compile preprocesses the source again, with no output or dependency file of the step's, and records
        each no_sanitize attribute of the result once; it compiles the result with every attribute taken out, without
        the step's -include, and saves that object by its SHA-256. Each source of a step of two is read on its own."""
        shim = self.dir / "riscv64-linux-musl-clang-pre"
        shim.write_text(self.SHIM.replace(
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then',
            'case " $* " in *" -E "*)\n'
            '  case " $* " in *" -MD "*|*" -MF "*|*" -c "*|*" x.o "*|*" x.c "*" y.c "*) exit 9 ;; esac\n'
            "  printf '%s\\n' 'int a __attribute__((no_sanitize(\"undefined\")));' "
            "'int b __attribute__((no_sanitize_address)); int c __attribute__((no_sanitize(' "
            "'\"undefined\"))); int no_sanitize_count;' "
            "'int no_sanitize; int d [[clang::no_sanitize(\"shift\", \"address\")]];' > \"$out\"; exit 0 ;;\n"
            '*" -x cpp-output "*)\n'
            '  case " $* " in *" -include "*|*" x.c "*|*" y.c "*|*" -MD "*) exit 9 ;; esac\n'
            '  for a in "$@"; do case "$a" in *.i) cat "$a" > "$out" ;; esac; done; exit 0 ;;\n'
            "esac\n"
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then'))
        shim.chmod(0o755)
        assert self.run_shim("-include", "h.h", "-MD", "-MF", "x.d", "-c", "x.c", "-o", "x.o",
                             shim=shim).returncode == 0
        assert not (self.dir / "x.d").exists()
        [line] = self.lines()
        # The attribute of c runs onto the next line, as a source's own line break stays in the preprocessed text.
        assert line["no_sanitize"] == ["no_sanitize", 'no_sanitize( "undefined")',
                                       'no_sanitize("shift", "address")', 'no_sanitize("undefined")',
                                       "no_sanitize_address"]
        assert [check_links.turns_ubsan_off(a) for a in line["no_sanitize"]] == [False, True, True, True, False]
        stripped = (self.records / "nosan" / line["no_sanitize_object"]).read_bytes()
        assert hashlib.sha256(stripped).hexdigest() == line["no_sanitize_object"]
        assert stripped.decode() == "int a __attribute__(());\nint b __attribute__(()); " \
            "int c __attribute__(()); int no_sanitize_count;\n" \
            "int no_sanitize; int d [[]];\n"
        assert sorted(p.name for p in self.records.iterdir() if p.name.startswith("pre.")) == []
        (self.records / "compiles").rename(self.dir / "earlier")
        assert self.run_shim("-c", "x.c", "y.c", shim=shim).returncode == 0
        # Each source is preprocessed and compiled again without the other (the stand-in exits 9 if it sees both).
        assert [(other["file"], other["no_sanitize"], other["no_sanitize_object"]) for other in self.lines()] == \
            [("x.c", line["no_sanitize"], line["no_sanitize_object"]),
             ("y.c", line["no_sanitize"], line["no_sanitize_object"])]
        # A preprocessed text of one line (a step with -P, a source of one line): its attribute goes too.
        one = self.dir / "riscv64-linux-musl-clang-one"
        one.write_text(self.SHIM.replace(
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then',
            'case " $* " in *" -E "*)\n'
            "  printf '%s' 'int a __attribute__((no_sanitize(\"undefined\")));' > \"$out\"; exit 0 ;;\n"
            '*" -x cpp-output "*)\n'
            '  for a in "$@"; do case "$a" in *.i) cat "$a" > "$out" ;; esac; done; exit 0 ;;\n'
            "esac\n"
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then'))
        one.chmod(0o755)
        (self.records / "compiles").rename(self.dir / "earlier2")
        assert self.run_shim("-P", "-c", "x.c", "-o", "x.o", shim=one).returncode == 0
        [line] = self.lines()
        assert line["no_sanitize"] == ['no_sanitize("undefined")']
        assert (self.records / "nosan" / line["no_sanitize_object"]).read_text() == "int a __attribute__(());"
        # A step with arguments in a response file: the second runs could not filter them, and nothing is read.
        (self.records / "compiles").rename(self.dir / "earlier3")
        assert self.run_shim("@args", "-c", "x.c", "-o", "x.o", shim=one).returncode == 0
        assert [(line["no_sanitize"], line["no_sanitize_object"]) for line in self.lines()] == [(None, None)]
        # A step that takes a precompiled header or clang modules: -E does not print their text, and nothing is read.
        # That holds for the precompiled header that clang finds by itself beside a header given with -include.
        (self.dir / "p.h.gch").mkdir()
        (self.dir / "q.h.pch").write_text("pch")
        for n, arguments in enumerate((["-include-pch", "h.pch"], ["-Xclang", "-include-pch", "-Xclang", "h.pch"],
                                       ["-fmodules"], ["-fprebuilt-module-path=m"], ["-include", "p.h"],
                                       ["-includeq.h"], ["--include=q.h"])):
            (self.records / "compiles").rename(self.dir / f"earlier-pch-{n}")
            assert self.run_shim(*arguments, "-c", "x.c", "-o", "x.o", shim=one).returncode == 0
            assert [(line["no_sanitize"], line["no_sanitize_object"]) for line in self.lines()] == \
                [(None, None)], arguments
        # A header with no precompiled one beside it is read as before.
        (self.records / "compiles").rename(self.dir / "earlier-h")
        assert self.run_shim("-include", "h.h", "-c", "x.c", "-o", "x.o", shim=one).returncode == 0
        assert [line["no_sanitize"] for line in self.lines()] == [['no_sanitize("undefined")']]
        # A source preprocessed already (.i) is read as it is, as clang's -E skips it; a -E that writes nothing says
        # nothing.
        silent = self.dir / "riscv64-linux-musl-clang-silent"
        silent.write_text(self.SHIM.replace(
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then',
            'case " $* " in *" -E "*) exit 0 ;;\n'
            '*" -x cpp-output "*) printf \'stripped\\n\' > "$out"; exit 0 ;;\nesac\n'
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then'))
        silent.chmod(0o755)
        (self.dir / "z.i").write_text('int z __attribute__((no_sanitize("undefined")));\n')
        (self.records / "compiles").rename(self.dir / "earlier-i")
        assert self.run_shim("-c", "z.i", "-o", "z.o", shim=silent).returncode == 0
        assert self.run_shim("-c", "x.c", "-o", "x.o", shim=silent).returncode == 0
        assert [(line["file"], line["no_sanitize"]) for line in self.lines()] == \
            [("x.c", None), ("z.i", ['no_sanitize("undefined")'])]

    def test_only_a_compile_that_succeeds_is_recorded(self):
        assert self.run_shim("-E", "-c", "x.c", "-o", "x.i").returncode == 0
        assert self.run_shim("x.c", "-o", "x").returncode == 0  # a link
        assert self.run_shim("-c", "x.c", "-o", "x.o", status=3).returncode == 3
        # An object older than the step is not one it wrote.
        (self.dir / "y.o").write_text("stale")
        os.utime(self.dir / "y.o", (1, 1))
        assert self.run_shim("-c", "y.c", SHIM_WRITE="0").returncode == 0
        assert self.lines() == []

    def test_a_step_ends_as_the_shim_ends(self):
        """Killed by a signal, the step is killed by it too, with nothing more on standard error; and a BASH_ENV or
        SHELLOPTS that the build exports changes nothing the step writes."""
        for arguments in (["-c", "x.c", "-o", "x.o"], ["x.c", "-o", "x"]):
            bare = self.run_shim(*arguments, through=False, status="segv")
            done = self.run_shim(*arguments, status="segv")
            assert bare.returncode == -11
            assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)
        startup = self.dir / "startup.sh"
        startup.write_text("echo from BASH_ENV >&2\n")
        env = {"BASH_ENV": str(startup), "SHELLOPTS": "braceexpand:hashall:interactive-comments:xtrace"}
        for arguments in (["-c", "x.c", "-o", "x.o"], ["--version"]):
            bare = self.run_shim(*arguments, through=False, **env)
            done = self.run_shim(*arguments, **env)
            assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)

    def test_a_shim_exit_status_that_names_a_stop_signal_is_the_steps(self):
        """A shim that exits with 147-150 (128 + SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU) or 145 (128 + SIGCHLD): the step
        exits with that status and does not stop itself."""
        for status in (145, 147, 148, 149, 150):
            bare = self.run_shim("-c", "x.c", "-o", "x.o", through=False, status=status)
            done = self.run_shim("-c", "x.c", "-o", "x.o", status=status)
            assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)
            assert done.returncode == status

    def test_every_open_file_reaches_the_shim(self):
        """A build that gives the compiler fd 3 open: the shim writes to it as it does without the front."""
        for arguments in (["-c", "x.c", "-o", "x.o"], ["x.c", "-o", "x"]):
            bare_file, done_file = self.dir / "bare3", self.dir / "done3"
            bare = self.run_shim(*arguments, through=False, fd3=bare_file, SHIM_FD3="1")
            done = self.run_shim(*arguments, fd3=done_file, SHIM_FD3="1")
            assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)
            assert done.returncode == 0
            assert done_file.read_text() == bare_file.read_text()
            bare_file.unlink()
            done_file.unlink()

    def test_a_compile_whose_arguments_clang_edits_has_no_record(self):
        """CCC_OVERRIDE_OPTIONS edits the arguments inside clang's driver, after the record would take them."""
        env = {"CCC_OVERRIDE_OPTIONS": "+-fno-sanitize=undefined"}
        bare = self.run_shim("-fsanitize=undefined", "-c", "x.c", "-o", "x.o", through=False, **env)
        done = self.run_shim("-fsanitize=undefined", "-c", "x.c", "-o", "x.o", **env)
        assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)
        assert self.lines() == []
        assert self.run_shim("-c", "x.c", "-o", "x.o", CCC_OVERRIDE_OPTIONS="").returncode == 0
        assert len(self.lines()) == 1

    def test_the_output_named_in_each_spelling(self):
        for arguments in (["-c", "a.c", "-oj.o"], ["-c", "a.c", "--output", "k.o"], ["-c", "--output=l.o", "a.c"]):
            assert self.run_shim(*arguments).returncode == 0
        assert [line["output"] for line in self.lines()] == ["j.o", "k.o", "l.o"]

    def test_each_object_and_its_language(self):
        assert self.run_shim("-c", "a.c", "lib/b.cc", "-x", "c++", "e.S", "-I", "f.c").returncode == 0
        assert [(line["output"], line["file"], line["language"]) for line in self.lines()] == \
            [("a.o", "a.c", "c"), ("b.o", "lib/b.cc", "c++"), ("e.o", "e.S", "c++")]
        # A C++ shim (clang++) takes C as C++.
        cxx = self.dir / "riscv64-linux-musl-clang++-plain"
        cxx.write_text(self.SHIM)
        cxx.chmod(0o755)
        (self.records / "compiles").rename(self.dir / "earlier")
        assert self.run_shim("-c", "a.c", "f.S", shim=cxx).returncode == 0
        assert [(line["output"], line["language"]) for line in self.lines()] == \
            [("a.o", "c++"), ("f.o", "assembler-with-cpp")]

    def test_a_front_hands_the_shim_every_argument(self):
        original = self.shim.read_bytes()
        for _ in range(2):  # a shim that has a front keeps it
            subprocess.run([str(RECORD_COMPILE), "--front", str(self.records), str(self.shim)], check=True)
        aside = self.dir / ".recorded" / self.shim.name
        assert aside.read_bytes() == original
        assert self.shim.read_text() == "#!/bin/sh\n# record-compile front\n" \
            f'exec {RECORD_COMPILE} {self.records} {aside} "$@"\n'
        # The build runs the shim by its path, and the front hands the shim what the shim itself got.
        arguments = ["-c", "a b.c", "-o", "a.o", "-DX=\"$HOME\"", "-D*", "", "--", "-x"]
        done = self.run_shim(*arguments, through=False)
        bare = self.run_shim(*arguments, through=False, shim=aside)
        assert (done.returncode, done.stdout, done.stderr) == (bare.returncode, bare.stdout, bare.stderr)
        assert [(line["shim"], line["arguments"]) for line in self.lines()] == [(str(self.shim), arguments)]

    def test_compile_writes_the_wrapper_it_always_wrote(self):
        """compile's wrappers for $CC and $CXX are the text compile has always written, with records and without:
        the records come from a front before each shim, never from the wrappers."""
        script = ('eval "$(sed -n \'/^write_wrapper() {/,/^}/p\' "$1")"\n'
                  "LIB=/usr/local/lib/oss-verify LIB_FUZZING_ENGINE=/tmp/ov/libFuzzingEngine.a\n"
                  "LIB_ALLOCATION_FAILURE_ENGINE=/tmp/ov/libAllocationFailureEngine.a\n"
                  "LIB_ALLOCATION_COUNTING_ENGINE=/tmp/ov/libAllocationCountingEngine.a OV_RECORDS=$2\n"
                  "LIB_DSL_ENGINE=/tmp/ov/libDslEngine.a\n"
                  'write_wrapper "$3" /tmp/shim/riscv64-linux-musl-clang-plain\n')
        shim = "/tmp/shim/riscv64-linux-musl-clang-plain"
        expected = (
            '#!/bin/sh\nfor a in "$@"; do\n'
            f'  case "$a" in -c|-E|-S|-fsyntax-only|-M|-MM|--version|-dumpmachine|-print-*) exec {shim} "$@" ;; esac\n'
            'done\nfor a in "$@"; do\n'
            '  case "$a" in "/tmp/ov/libFuzzingEngine.a"|"/tmp/ov/libAllocationFailureEngine.a"|'
            '"/tmp/ov/libAllocationCountingEngine.a"|"/tmp/ov/libDslEngine.a")\n'
            f'    exec /usr/local/lib/oss-verify/link-fuzz-target {shim} "$@" ;; esac\n'
            f'done\nexec {shim} "$@"\n')
        for n, records in enumerate(("", "/tmp/ov/records")):
            out = self.dir / f"wrapper{n}"
            subprocess.run(["bash", "-c", script, "bash", str(BUILDER / "compile"), records, str(out)], check=True)
            assert out.read_text() == expected

    def test_compile_writes_records_that_check_links_reads(self):
        """compile's own record code: the build's flags.json and compiles.jsonl, the records of every compile in byte
        order, and the objects compiled without a source's no_sanitize attributes, which it copies to $OUT/.records,
        read back by check_links.read_compiles. A word with a quote or a backslash survives, and C gets the C exclusion
        that C++ does not."""
        script = ('set -euo pipefail\n'
                  'eval "$(sed -n \'/^c_exclude=""/,/^\\[ -z "\\$c_exclude" \\]/p\' "$1")"\n'
                  'eval "$(sed -n \'/^  json_words() {/,/> "\\$OV_RECORDS\\/flags.json"/p\' "$1")"\n'
                  'eval "$(sed -n \'/^# The compile records (record-compile), one line each/,/^fi/p\' "$1")"\n')
        san = '-fsanitize=address -fsanitize=undefined -DQ="a\\b"'
        ubsan = "-fsanitize=undefined -fsanitize-trap=all"
        (self.dir / "src").mkdir()
        names = ["x", "a", "q", "c", "m"]
        # m's source has an attribute (a stand-in whose -E output holds one), so record-compile saves an object of it.
        attributed = self.dir / "riscv64-linux-musl-clang-attr"
        attributed.write_text(self.SHIM.replace(
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then',
            'case " $* " in *" -E "*) printf \'%s\\n\' \'int m __attribute__((no_sanitize_undefined));\' > "$out"; '
            'exit 0 ;;\n*" -x cpp-output "*) printf \'stripped m\\n\' > "$out"; exit 0 ;;\nesac\n'
            'if [ "${SHIM_WRITE:-1}" = 1 ]; then'))
        attributed.chmod(0o755)
        for name in names:
            (self.dir / "src" / f"{name}.c").write_text(f"int {name};\n")
            assert self.run_shim("-c", f"src/{name}.c", "-o", f"{name}.o",
                                 shim=attributed if name == "m" else None).returncode == 0
        stripped = hashlib.sha256(b"stripped m\n").hexdigest()
        out = self.dir / "out"
        for flav, build, wanted_ubsan in (("asanubsan", "asan-ubsan", ubsan.split()), ("asan", "asan", [])):
            subprocess.run(["bash", "-c", script, "bash", str(BUILDER / "compile")], check=True, cwd=self.dir,
                           env={**os.environ, "FLAV": flav, "BUILD": build, "SAN": san, "UBSAN": ubsan, "CFLAGS": "",
                                "OV_UBSAN_C_EXCLUDE": "function", "OV_UBSAN_CHECKS": "undefined",
                                "OV_RECORDS": str(self.records), "OUT": str(out)})
            compiles = check_links.read_compiles(out)
            assert compiles is not None, build
            assert compiles.build == build
            words = ["-fsanitize=address", "-fsanitize=undefined", '-DQ="a\\b"']
            exclude = ["-fno-sanitize=function"] if wanted_ubsan else []
            assert compiles.sanitizer == {"c": words + exclude, "c++": words}
            assert compiles.ubsan == {"c": wanted_ubsan + exclude, "c++": wanted_ubsan}
            lines = (out / ".records" / "compiles.jsonl").read_bytes().splitlines()
            assert (len(lines), lines) == (len(names), sorted(lines))
            digests = {hashlib.sha256((self.dir / f"{name}.o").read_bytes()).hexdigest(): name for name in names}
            assert set(compiles.objects) == set(digests)
            for digest, name in digests.items():
                compile, = compiles.objects[digest]
                assert (compile.file, compile.language) == (f"src/{name}.c", "c")
                assert compile.no_sanitize == (["no_sanitize_undefined"] if name == "m" else [])
            assert [p.name for p in (out / ".records" / "nosan").iterdir()] == [stripped]
            assert (out / ".records" / "nosan" / stripped).read_bytes() == b"stripped m\n"

    def test_release_target_puts_a_front_before_each_shim_it_writes(self):
        """release-target.sh's record code: with OV_RECORDS, a front before each of the four shims it wrote, which
        records each compile; without it, the shims stay as written."""
        block = subprocess.run(["sed", "-n", '/^  if \\[ -n "${OV_RECORDS:-}" \\]; then/,/^  fi/p',
                                str(BUILDER / "release-target.sh")], capture_output=True, text=True, check=True).stdout
        assert "record-compile --front" in block
        block = block.replace("/usr/local/lib/oss-verify/record-compile", str(RECORD_COMPILE))
        names = [f"riscv64-linux-musl-{n}" for n in ("clang-plain", "clang++-plain", "clang-sealed", "clang++-sealed")]
        shims = self.dir / "shim"
        shims.mkdir()
        for name in names:
            (shims / name).write_text(self.SHIM)
            (shims / name).chmod(0o755)
        for records in ("", str(self.records)):
            subprocess.run(["bash", "-euc", block], check=True, cwd=self.dir,
                           env={**os.environ, "SHIM": str(shims), "CHOST": "riscv64-linux-musl", "OV_RECORDS": records})
            fronted = [name for name in names if "# record-compile front" in (shims / name).read_text()]
            assert fronted == (names if records else [])
        (self.dir / "y.c").write_text("int y;\n")
        assert subprocess.run([str(shims / names[2]), "-c", "y.c", "-o", "y.o"], cwd=self.dir,
                              capture_output=True).returncode == 0
        assert [(line["output"], line["shim"]) for line in self.lines()] == [("y.o", str(shims / names[2]))]


class TestModelRelease:
    RELEASE = ("schema: oss-fuzz-theorems/release/1\nrelease: 2026.10.0\nsemantics:\n"
               "  name: rocq-linux-process-semantics-core\n"
               "  repository: https://github.com/theorem-labs/rocq-linux-process-semantics\n"
               "  commit: f1006fe8178338a499b5e5c41be83006c4edd058\n")

    def test_reads_the_model_from_release_yaml(self):
        model = model_release.release_model(text=self.RELEASE)
        assert (model["release"], model["commit"]) == ("2026.10.0", "f1006fe8178338a499b5e5c41be83006c4edd058")
        assert model["repository"] == "https://github.com/theorem-labs/rocq-linux-process-semantics"

    def test_refuses_a_release_yaml_that_names_no_model(self):
        for text in ("release: x\n", self.RELEASE.replace("f1006fe8", "zz"),
                     self.RELEASE.replace("https://github.com", "file://"), "- a list\n",
                     "release: 2024-13-45\n", "created: 2024-01-01T25:00:00\n"):
            with pytest.raises(Failed):
                model_release.release_model(text=text)

    def test_code_without_comments(self):
        text = 'Definition a := 1. (* one (* nested *) *)\n\n  Definition   b := "(* not a comment *)".\n'
        assert model_release.rocq_code(text) == ["Definition a := 1.", 'Definition b := "(* not a comment *)".']
        assert model_release.code_sha256(text) == model_release.code_sha256(text.replace("one", "uno"))
        assert model_release.code_sha256(text) != model_release.code_sha256(text.replace("1.", "2."))

    def test_stale(self, tmp_path):
        root = tmp_path
        (root / "A.v").write_text("Definition a := 1.\n")
        files = {"A.v": model_release.code_sha256("(* a comment *) Definition a := 1.")}
        assert model_release.stale(root, files) == []
        assert model_release.stale(root, {**files, "B.v": "0" * 64}) == ["B.v"]
        (root / "A.v").write_text("Definition a := 2.\n")
        assert model_release.stale(root, files) == ["A.v"]


class TestRuns:
    """check_binaries' reading of the runs: quiet and loud, the system calls' floors, and the report."""

    QEMU = "qemu-riscv64 version 10.0.11 (Debian 1:10.0.11+ds-0+deb13u1)"

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.results = tmp_path
        self.inputs = [(check_binaries.EMPTY, check_binaries.HEADER), ("seed1", check_binaries.HEADER + b"x")]
        for kind in "lq":
            for n in range(2):
                self.write(f"{kind}{n}.calls", "exec")

    def write(self, name, value):
        (self.results / name).write_text(f"{value}\n")

    def test_seed_inputs(self):
        corpus = self.results / "t_seed_corpus.zip"
        with zipfile.ZipFile(corpus, "w") as archive_file:
            for n in range(12):
                archive_file.writestr(f"s{n}", b"%d" % n)
        inputs = check_binaries.seed_inputs(self.results, "t")
        assert len(inputs) == check_binaries.MAX_SEEDS + 1
        assert inputs[0] == (check_binaries.EMPTY, check_binaries.HEADER)
        assert inputs[1] == ("s0", check_binaries.HEADER + b"0")

    def test_quiet_and_loud(self):
        for n, (loud, quiet, written) in enumerate([(0, 0, 0), (2, 2, 0)]):
            self.write(f"l{n}.status", loud)
            self.write(f"q{n}.status", quiet)
            self.write(f"q{n}.out", written)
            self.write(f"q{n}.err", 0)
        assert check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"] == "pass"
        self.write("q1.status", 0)
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results)
        assert result["result"] == "fail"
        assert "exits 2, the quiet twin 0" in result["detail"]
        self.write("q1.status", 2)
        self.write("q0.out", 5)
        assert "wrote 5 bytes" in check_binaries.quiet_loud(True, "", self.inputs, self.results)["detail"]
        self.write("q0.out", 0)
        assert check_binaries.quiet_loud(False, "no adapter", self.inputs, self.results)["result"] == "not-run"
        # A check that did not run must not read as a clean one.
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                             "quiet_loud": {"result": "not-run", "detail": "no quiet twin: a Go "
                                                                                           "program"},
                                             "instrumented": {"result": "plain"}}}}}
        text = check_binaries.report(block, {"t": {"plain": [{"name": "libc.a", "kind": "libc"}]}}, ["plain"],
                                     {"t": {"plain": None}})
        assert "**not decided** (not run)" in text
        assert "quiet and loud: `no quiet twin: a Go program`" in text
        # A run that never started: its status is the tracer's, and decides nothing.
        self.write("l0.calls", "")
        self.write("l1.calls", "")
        assert check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"] == "error"

    def test_a_missing_byte_count_is_not_silence(self):
        for n in range(2):
            self.write(f"l{n}.status", 0)
            self.write(f"q{n}.status", 0)
            self.write(f"q{n}.out", 0)
            self.write(f"q{n}.err", 0)
        assert check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"] == "pass"
        for n in range(2):
            (self.results / f"q{n}.err").unlink()
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results)
        assert result["result"] == "error", result
        assert "count of what the quiet twin wrote is missing" in result["detail"]

    def test_a_run_that_never_reached_its_input_decides_nothing(self):
        """Two binaries that both die before main agree on every status and write nothing."""
        for n in range(2):
            self.write(f"l{n}.status", 2)
            self.write(f"q{n}.status", 2)
            self.write(f"q{n}.out", 0)
            self.write(f"q{n}.err", 0)
        whole = {check_binaries.EMPTY, "seed1"}
        assert check_binaries.quiet_loud(True, "", self.inputs, self.results, whole)["result"] == "pass"
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results, set())
        assert result["result"] == "error"
        assert "not a whole run of the input" in result["detail"]
        # A difference still fails, whether or not the run reached its input.
        self.write("q0.status", 0)
        assert check_binaries.quiet_loud(True, "", self.inputs, self.results, set())["result"] == "fail"

    def test_check_2_without_a_verdict_is_named_as_the_reason(self):
        """When check 2 could not read the runs at all (no model, another qemu), it lists no whole run, and check 3
        says that check 2 could not tell, with check 2's reason, not that each run fell short of its input."""
        for n in range(2):
            self.write(f"l{n}.status", 0)
            self.write(f"q{n}.status", 0)
            self.write(f"q{n}.out", 0)
            self.write(f"q{n}.err", 0)
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results, set(), "qemu 8.2.2: not 10.0.11")
        assert result["result"] == "error"
        assert "check 2 could not tell whether the binary's run reached its input" in result["detail"]
        assert "(check 2: qemu 8.2.2: not 10.0.11)" in result["detail"]
        assert "not a whole run" not in result["detail"]
        # A difference still fails.
        self.write("q1.status", 3)
        assert check_binaries.quiet_loud(True, "", self.inputs, self.results, set(), "x")["result"] == "fail"

    def test_a_linked_result_is_not_read(self):
        secret = self.results / "secret"
        secret.write_text("0\n")
        (self.results / "l0.status").symlink_to(secret)
        assert check_binaries.read_number(self.results, "l0.status") is None

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
            assert run()["result"] == "pass"
            # Each run's input.bin holds that run's input, header and all.
            assert seen == {"stance": "off", "lengths": "exec\n", "inputs": {"input.bin": check_binaries.HEADER + b"x"}}
            assert run(qemu="qemu-riscv64 version 9.1.0")["result"] == "error"
            # 10.0.0 prints read's and write's buffer in 32 bits, which the checker does not read so.
            assert run(qemu="qemu-riscv64 version 10.0.0 (Debian 1:10.0.0+ds-1)")["result"] == "error"
            assert run(qemu="qemu-riscv64 version 10.0.110")["result"] == "error"
            # qemu 8.2 hands the host 0 for every anonymous mmap's offset: its runs decide nothing.
            result = run(qemu="qemu-riscv64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)")
            assert result["result"] == "error"
            assert "qemu 10.0.11 only" in result["detail"]
            assert "docs/build-contract.md" in result["detail"]
            verdicts["calls"] = 3
            assert run()["result"] == "error"
            verdicts["calls"] = 12
            # A call the trace cannot decide is reported with its own reason, and a failure is still a failure when
            # the host-side log is missing.
            verdicts.update(verdict="undecided", undecided=[{"call": "connect", "why": "the address is not printed"}])
            assert "connect: the address is not printed" in run()["detail"]
            verdicts.update(host_log="missing")
            assert "host-side log" in run()["detail"]
            verdicts.update(unmodeled=[{"call": "uname", "why": "not in the model's table"}])
            assert run()["result"] == "fail"
            verdicts.update(host_log="present", verdict="pass", undecided=[], unmodeled=[])
            (self.results / "l1.trace").write_text("7 read(3,0x1,65536) = 7\n")
            result = run()
            assert result["result"] == "error"
            assert "does not open and read input.bin" in result["detail"]
            verdicts["unmodeled"] = [{"call": "uname", "why": "not in the model's table"}]
            result = run()
            assert result["result"] == "fail"
            assert result["unmodeled"][0]["inputs"] == [check_binaries.EMPTY, "seed1"]
            assert run(stale="the rules are old")["result"] == "stale"
        finally:
            check_binaries.syscall_shapes.check_trace = saved

    def test_check_3_reads_each_result_of_check_2(self):
        """whole_runs() on each result system_calls() can give: the whole runs, and no reason, when check 2 read the
        runs; none, and check 2's reason, when it could not read them or raised. Check 3 then says which."""
        opened = '7 openat(AT_FDCWD,"input.bin",O_RDONLY|O_LARGEFILE) = 3\n'
        for n, text in {0: opened + "7 read(3,0x1,65536) = 6\n", 1: opened + "7 read(3,0x1,65536) = 7\n"}.items():
            for name, value in ((f"l{n}.status", 0), (f"q{n}.status", 0), (f"q{n}.out", 0), (f"q{n}.err", 0)):
                self.write(name, value)
            (self.results / f"l{n}.trace").write_text(text)
        verdict = {"calls": 12, "names": ["openat", "read", "exit_group"], "unmodeled": [], "exited": True,
                   "verdict": "pass", "host_log": "present"}

        def check_trace(model, text, **options):
            if verdict.get("raises"):
                raise TypeError("the trace is cut short")
            return dict(verdict)

        def check_2(model=object(), stale="", qemu=self.QEMU, results=self.results):
            return check_binaries.guarded(check_binaries.system_calls, model, stale, qemu, "bin", self.inputs, results)

        def check_3(calls):
            return check_binaries.quiet_loud(True, "", self.inputs, self.results, *check_binaries.whole_runs(calls))

        both = {check_binaries.EMPTY, "seed1"}
        saved = check_binaries.syscall_shapes.check_trace
        check_binaries.syscall_shapes.check_trace = check_trace
        try:
            # Check 2 read the runs: its list of whole runs, and no reason, whatever its result.
            for result, change in (("pass", {}), ("stale", {"stale": "the rules are old"})):
                calls = check_2(**change)
                assert (calls["result"], check_binaries.whole_runs(calls)) == (result, (both, None))
            assert check_3(check_2())["result"] == "pass"
            verdict["unmodeled"] = [{"call": "uname", "why": "not in the model's table"}]
            assert (check_2()["result"], check_binaries.whole_runs(check_2())) == ("fail", (both, None))
            verdict.update(unmodeled=[], exited=False)
            calls = check_2()  # runs that decide nothing: a list, empty, and still no reason
            assert (calls["result"], check_binaries.whole_runs(calls)) == ("error", (set(), None))
            assert "not a whole run of the input" in check_3(calls)["detail"]
            verdict.update(exited=True, raises=True)
            # Check 2 could not read the runs, or raised: no list, and its detail as the reason.
            unread = {"model": check_2(model="the model could not be read: no release.yaml"),
                      "qemu": check_2(qemu="qemu-riscv64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)"),
                      "trace": check_2(), "raised": check_2(results=None)}
            for why, calls in unread.items():
                assert "whole" not in calls, why
                assert check_binaries.whole_runs(calls) == (set(), calls["detail"]), why
                assert f"(check 2: {calls['detail'][:40]}" in check_3(calls)["detail"], why
                assert "not a whole run" not in check_3(calls)["detail"], why
            assert "the trace could not be read" in unread["trace"]["detail"]
            assert unread["raised"]["detail"].startswith("system_calls: TypeError")
            assert check_binaries.whole_runs({"result": "error"}) == (set(), "it gave no reason")
        finally:
            check_binaries.syscall_shapes.check_trace = saved

    def test_binary_checks_gives_check_3_the_reason_of_check_2(self):
        """binary_checks() itself, with its docker and model steps replaced: with no model, check 2 reads no run, and
        check 3 names check 2's reason, not that each run fell short of its input. The third value is the C library
        that the record of each binary declares: the record's libc file, or None for a record that declares none, for
        a Go program and for a binary with no record."""
        import types
        work = self.results / "work"
        declared = {name: (f"/work/b/musl/lib/{name}", str(n) * 64)
                    for n, name in enumerate(check_links.DECLARED_LIBC, 1)}
        records = {"t": "no record", "u": check_links.Record([], {}, set(), {}, work, None, libc=declared),
                   "v": check_links.Record([], {}, set(), {}, work, None),
                   "w": check_links.GoProgram("go1.27.1", {})}
        for target in records:
            (work / "out" / target).mkdir(parents=True)
            (work / "out" / target / f"{target}.plain").write_bytes(b"\x7fELF")

        def release_model():
            raise Failed("no release.yaml")

        def run_job(job_dir, image, qemu, labels, seconds):  # one whole run of each binary, quiet and loud alike
            results = job_dir / "results"
            results.mkdir()
            for kind in "lq":
                (results / f"{kind}0.calls").write_text("exec\n")
                (results / f"{kind}0.status").write_text("0\n")
            for name in ("q0.out", "q0.err"):
                (results / name).write_text("0\n")
            return results

        link = {"plain": {"uninstrumented": None, "instrumented": {"result": "plain"}}}
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(model_release, "release_model", release_model)
            patch.setattr(check_links, "read_compiles", lambda raw: {})
            patch.setattr(check_links, "analyse", lambda *arguments: link)
            patch.setattr(check_binaries, "record_of", lambda raw, target, compiles: (records[target], b"quiet"))
            patch.setattr(check_binaries, "image_hashes", lambda *arguments, **options: {})
            patch.setattr(check_binaries, "dwarf_reader", lambda *arguments: None)
            patch.setattr(check_binaries, "assembly_reader", lambda *arguments: None)
            patch.setattr(check_binaries, "seed_inputs",
                          lambda directory, target: [(check_binaries.EMPTY, check_binaries.HEADER)])
            patch.setattr(check_binaries, "qemu_version", lambda qemu: self.QEMU)
            patch.setattr(check_binaries, "run_job", run_job)
            patch.setattr(check_binaries.check_checks, "qemu", lambda: "/bin/true")
            block, _, libc = check_binaries.binary_checks(
                types.SimpleNamespace(builds=["plain"], directory=work), "tag", "toolchain", list(records),
                {target: {"plain": {"file": f"{target}.plain"}} for target in records}, {}, work, labels=[])
        assert libc == {"t": {"plain": None}, "u": {"plain": declared}, "v": {"plain": None}, "w": {"plain": None}}
        checks = block["targets"]["t"]["plain"]
        assert checks["system_calls"] == {"result": "error", "detail": "the model could not be read: no release.yaml"}
        agreement = checks["quiet_loud"]
        assert agreement["result"] == "error"
        assert "check 2 could not tell whether the binary's run reached its input" in agreement["detail"]
        assert "(check 2: the model could not be read: no release.yaml)" in agreement["detail"]

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
        assert result["result"] == "error"
        assert "kind_reason" in result["detail"]
        # And a check that raises anywhere gives that binary an error, not the step.
        def fails(binary, stale):
            raise ValueError("not a RISC-V program")
        assert check_binaries.guarded(fails, "bin", "") == \
            {"result": "error", "detail": "fails: ValueError: not a RISC-V program"}

    def test_report_names_the_four_checks_per_binary(self):
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "2026.10.0"}, "inputs": {"t": ["a", "b"]},
                 "targets": {"t": {
                     "plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                               "quiet_loud": {"result": "pass"}, "instrumented": {"result": "plain"}},
                     "asan": {"elf": {"result": "pass"},
                              "system_calls": {"result": "fail", "detail": "uname: not in the table"},
                              "quiet_loud": {"result": "pass"}, "instrumented": {"result": "pass"}}}}}
        listing = {"t": {"plain": [{"name": "libc.a", "kind": "libc"}], "asan": None}}
        text = check_binaries.report(block, listing, ["plain", "asan"], {"t": {"plain": None, "asan": None}})
        assert "| ELF and instructions | system calls | quiet and loud | instrumented |" in text
        assert "| `t.plain` | pass | pass | pass | not instrumented (plain) | 1 files |" in text
        assert "| `t.asan` | pass | **fail** | pass | pass | not recorded |" in text
        assert "`t.asan`, system calls: `uname: not in the table`" in text


class TestProgramChecks:
    """check_binaries.program_checks: the checks that apply to a whole program. It has no fuzz entry, so no fuzz driver
    runs it, and it has no quiet twin and no link record: only the ELF check applies, and each other check of a binary
    has a result of its own for a program."""

    # The same bytes at the path of a fuzz target's build and at the path of a program: one ELF check, one result.
    ELF = elf(sections=[(".text", 1234)], segments=[1])
    # What a program's build has for each check that does not run (docs/build-contract.md, "The checks of the
    # binaries").
    NOT_RUN = {"system_calls": "not-run", "quiet_loud": "not-run", "instrumented": "plain"}

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.work = tmp_path / "work"
        for target, name in (("p", "p"), ("q", "q"), ("t", "t.plain")):
            (self.work / "out" / target).mkdir(parents=True)
            (self.work / "out" / target / name).write_bytes(self.ELF)
        self.job = types.SimpleNamespace(builds=["plain"], directory=self.work)

    @staticmethod
    def no_model(patch):
        """Replace the model step, so that no network is reached: the release's model cannot be read."""
        def release_model():
            raise Failed("no release.yaml")

        def fetch(*arguments):
            pytest.fail("the model was fetched")

        patch.setattr(model_release, "release_model", release_model)
        patch.setattr(model_release, "fetch", fetch)

    def programs(self, targets=("p",)):
        """program_checks of these programs, whose plain build is out/<name>/<name>, with no model."""
        with pytest.MonkeyPatch.context() as patch:
            self.no_model(patch)
            return check_binaries.program_checks(self.job, list(targets), {t: {"plain": {"file": t}} for t in targets},
                                                 self.work)

    def fuzz_target(self):
        """The checks of one fuzz target's plain build, `t`, as binary_checks gives them, run as
        TestRuns::test_binary_checks_gives_check_3_the_reason_of_check_2 runs it."""
        def run_job(job_dir, image, qemu, labels, seconds):  # one whole run, quiet and loud alike
            results = job_dir / "results"
            results.mkdir()
            for kind in "lq":
                (results / f"{kind}0.calls").write_text("exec\n")
                (results / f"{kind}0.status").write_text("0\n")
            for name in ("q0.out", "q0.err"):
                (results / name).write_text("0\n")
            return results

        link = {"plain": {"uninstrumented": None, "instrumented": {"result": "plain"}}}
        with pytest.MonkeyPatch.context() as patch:
            self.no_model(patch)
            patch.setattr(check_links, "read_compiles", lambda raw: {})
            patch.setattr(check_links, "analyse", lambda *arguments: link)
            patch.setattr(check_binaries, "record_of", lambda raw, target, compiles: ("no record", b"quiet"))
            patch.setattr(check_binaries, "image_hashes", lambda *arguments, **options: {})
            patch.setattr(check_binaries, "dwarf_reader", lambda *arguments: None)
            patch.setattr(check_binaries, "assembly_reader", lambda *arguments: None)
            patch.setattr(check_binaries, "seed_inputs",
                          lambda directory, target: [(check_binaries.EMPTY, check_binaries.HEADER)])
            patch.setattr(check_binaries, "qemu_version", lambda qemu: TestRuns.QEMU)
            patch.setattr(check_binaries, "run_job", run_job)
            patch.setattr(check_binaries.check_checks, "qemu", lambda: "/bin/true")
            block, _, _ = check_binaries.binary_checks(self.job, "tag", "toolchain", ["t"],
                                                       {"t": {"plain": {"file": "t.plain"}}}, {}, self.work,
                                                       labels=[])
        return block["targets"]["t"]["plain"]

    def test_every_check_of_a_binary_has_a_program_result(self):
        """The inventory of the checks: each key that a fuzz target's build has in the block of binary_checks is a key
        of a program's build in the block of program_checks, with the result that a program has. A check added to
        binary_checks fails this test until program_checks gives it a result too."""
        fuzz = self.fuzz_target()
        assert set(fuzz) == {"elf", "system_calls", "quiet_loud", "instrumented"}
        program = self.programs()["targets"]["p"]["plain"]
        assert list(program) == list(fuzz)
        # The ELF check reads the same bytes, so it gives the same result.
        assert program["elf"] == fuzz["elf"]
        for key, result in self.NOT_RUN.items():
            assert program[key]["result"] == result, key
            assert program[key]["detail"].startswith("a program: "), key

    def test_program_checks_run_no_binary(self):
        def fails(name):
            def call(*arguments, **options):
                pytest.fail(f"program_checks called {name}")
            return call

        def isa(path):
            return {"result": "pass", "detail": "isa ok"}

        with pytest.MonkeyPatch.context() as patch:
            self.no_model(patch)
            for name in ("run_job", "record_of", "image_hashes", "seed_inputs", "qemu_version"):
                patch.setattr(check_binaries, name, fails(name))
            patch.setattr(check_binaries.check_checks, "qemu", fails("check_checks.qemu"))
            patch.setattr(check_binaries.check_links, "read_compiles", fails("read_compiles"))
            # No container: no docker command runs.
            patch.setattr(check_binaries.check_build, "run", fails("check_build.run"))
            patch.setattr(check_binaries.check_build, "output", fails("check_build.output"))
            patch.setattr(check_binaries.binary_isa, "check", isa)
            block = check_binaries.program_checks(self.job, ["p", "q"],
                                                  {name: {"plain": {"file": name}} for name in "pq"}, self.work)
        assert block["qemu"] == ""
        assert block["inputs"] == {"p": [], "q": []}
        assert block["model"] == {"error": "the model could not be read: no release.yaml"}
        assert list(block["targets"]) == ["p", "q"]
        for target, by_build in block["targets"].items():
            assert list(by_build) == ["plain"]
            # With a model that cannot be read, the ELF check has no verdict either way.
            assert by_build["plain"]["elf"]["result"] == "stale"
            assert by_build["plain"]["elf"]["detail"].startswith("isa ok; ")
            assert "could not be read" in by_build["plain"]["elf"]["detail"]
        # Each program has results of its own: the block, written as YAML, has no alias between two programs.
        assert "&id" not in yaml.safe_dump(block)

    def test_the_report_of_a_program(self):
        model = {"name": "m", "commit": "f" * 40, "release": "2026.10.0"}
        about = "a program: nothing runs it"

        def block(elf_result, *targets):
            inputs = {name: [] if name == "hello" else ["a", "b"] for name in targets}
            return {"model": model, "qemu": "", "inputs": inputs,
                    "targets": {name: {"plain": {
                        "elf": elf_result,
                        "system_calls": {"result": "not-run", "detail": about},
                        "quiet_loud": {"result": "not-run", "detail": about},
                        "instrumented": {"result": "plain", "detail": about}}} for name in targets}}

        text = check_binaries.report(block({"result": "pass"}, "hello"), {}, ["plain"], {}, programs=["hello"])
        assert ("| `hello.plain` | pass | not run (a program) | not run (a program) | not instrumented (plain) | "
                "no list (a program) |") in text
        assert text.count("not run (a program)") == 2
        assert "**not decided**" not in text
        # Nothing to say about the two checks that no program runs, and no fuzz target ran on any input.
        assert "What each failure is" not in text
        assert "Each fuzz target ran" not in text
        # A result of the ELF check that is not a pass is listed, and the two that did not run are not.
        stale = {"result": "stale", "detail": "isa ok; the model is not the release's"}
        text = check_binaries.report(block(stale, "hello"), {}, ["plain"], {}, programs=["hello"])
        assert "| `hello.plain` | **stale model** | not run (a program) |" in text
        assert "What each failure is" in text
        assert "- `hello.plain`, ELF and instructions: `isa ok; the model is not the release's`" in text
        assert "system calls:" not in text and "quiet and loud:" not in text
        # A fuzz target beside it reads as it does without the program, and is the only one that the line names.
        mixed = block({"result": "pass"}, "hello", "t")
        mixed["targets"]["t"]["plain"].update(system_calls={"result": "pass"}, quiet_loud={"result": "pass"})
        text = check_binaries.report(mixed, {"t": {"plain": [{"name": "libc.a", "kind": "libc"}]}}, ["plain"],
                                     {"t": {"plain": None}}, programs=["hello"])
        assert "Each fuzz target ran on the empty input and up to 8 seed inputs (`t`: 2)." in text
        assert "`hello`: 0" not in text
        assert "| `t.plain` | pass | pass | pass | not instrumented (plain) | 1 files |" in text
        assert "| `hello.plain` | pass | not run (a program) | not run (a program) |" in text
