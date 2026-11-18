# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""infra/base-builder/layout.py, the layout of a fuzz target's link and the check that a development build kept the
addresses of its unchanged functions: uv run pytest tests/test_layout.py

No linker runs here. The objects are the riscv64 relocatable objects of tests/fixtures/allocator-shim/, which the tests
also read with a reader of their own; the map is the one of tests/fixtures/link-record/; the records and the layout
trees are small files that each test writes."""
import collections
import gzip
import hashlib
import importlib.util
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys

import pytest

from oss_verify import check_links

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra/base-builder/layout.py"
SPEC = importlib.util.spec_from_file_location("layout", SCRIPT)
layout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(layout)

SHIMS = ROOT / "tests/fixtures/allocator-shim"
MAP = ROOT / "tests/fixtures/link-record/curl-fuzz_bufq.plain/map.gz"
FORWARDS = (SHIMS / "shim-forwards.o").read_bytes()
STORES = (SHIMS / "shim-stores.o").read_bytes()
LOCAL_ACCESS = (SHIMS / "shim-local-access.o").read_bytes()
LOCAL_CALL = (SHIMS / "shim-local-call.o").read_bytes()
V0 = (SHIMS / "shim-rustc-v0.o").read_bytes()
# shim-forwards.o's __rust_realloc calls __rdl_realloc. This copy names that symbol __real_dalloc (as long a name), so
# that in a link that wraps dalloc the call reaches dalloc itself.
REAL = FORWARDS.replace(b"\0__rdl_realloc\0", b"\0__real_dalloc\0")
WRAPS = ("_RNvCs6UdHf40Qw6p_7___rustc11___rdl_alloc", "dalloc")
ORIGINAL = "/work/obj/shim-local-call.o"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def map_line(address, size, align, text):
    """A line of a link's record, as record_link keeps it from lld's map."""
    return f"{address:>16x} {address:>16x} {size:>8x} {align:>5}         {text}\n"


def archive(members):
    """A GNU ar archive of [(name, bytes)], in order, after a symbol index and a // table for the names longer than
    15 bytes."""
    table, entries = b"", []
    for name, body in members:
        if len(name) > 15:
            entries.append((f"/{len(table)}", body))
            table += name.encode() + b"/\n"
        else:
            entries.append((name + "/", body))
    entries = [("/", bytes(4))] + ([("//", table)] if table else []) + entries
    out = [b"!<arch>\n"]
    for name, body in entries:
        out.append(f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(body):<10}`\n".encode())
        out.append(body + (b"\n" if len(body) % 2 else b""))
    return b"".join(out)


# Two members named a.o, both with a .text.__rust_alloc and a .text.__rust_dealloc, an odd-sized member before them,
# and a member whose name is in the // table.
MEMBERS = [("notes.txt", b"odd"), ("a.o", REAL), ("a.o", STORES), ("shim-local-access.o", LOCAL_ACCESS)]
ARCHIVE = archive(MEMBERS)


def read_object(data):
    """The test's own reading of a relocatable ELF64 little-endian object: ({section index: (name, type, bytes or
    None for SHT_NOBITS, size, alignment)}, [symbol: (name, value, info, shndx)], {section index: [(offset, info,
    addend)] of its SHT_RELA relocations})."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shnum, shstrndx = struct.unpack_from("<HH", data, 0x3C)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + 64 * i) for i in range(shnum)]

    def body(index):
        offset, size = headers[index][4], headers[index][5]
        return data[offset:offset + size]

    def string(table, at):
        return table[at:table.index(b"\0", at)].decode()

    names = body(shstrndx)
    sections = {i: (string(names, h[0]), h[1], None if h[1] == 8 else body(i), h[5], h[8])
                for i, h in enumerate(headers)}
    symtab = next(i for i, h in enumerate(headers) if h[1] == 2)
    strings, table = body(headers[symtab][6]), body(symtab)
    symbols = []
    for at in range(0, len(table), 24):
        name, info, _, shndx, value, _ = struct.unpack_from("<IBBHQQ", table, at)
        symbols.append((string(strings, name), value, info, shndx))
    relocations = {h[7]: [struct.unpack_from("<QQq", body(i), at) for at in range(0, h[5], 24)]
                   for i, h in enumerate(headers) if h[1] == 4}
    return sections, symbols, relocations


def section_offset(data, name):
    """The file offset of the bytes of the section `name` of an object, from its section header."""
    sections, _, _ = read_object(data)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    index = next(i for i, s in sections.items() if s[0] == name)
    return struct.unpack_from("<Q", data, shoff + 64 * index + 24)[0]


def executable():
    """(bytes, output.tsv) of a small riscv64 ELF64 executable: .rodata, .text and .data, a .comment that is not
    loaded, three PT_LOAD segments and a PT_GNU_STACK, and a symbol table with a local, a global, a weak, an
    undefined, an absolute symbol and a second global of the first global's name."""
    bodies = {".rodata": bytes(32), ".text": bytes(64), ".data": bytes(8), ".comment": b"clang version 20.1.8\0"}
    symbols = [("", 0, 0, 0), ("local_fn", 0x11010, 0x02, 2), ("LLVMFuzzerTestOneInput", 0x11000, 0x12, 2),
               ("weak_fn", 0x11020, 0x22, 2), ("undefined_fn", 0, 0x10, 0),
               ("LLVMFuzzerTestOneInput", 0x11030, 0x12, 2), ("abs_sym", 0x1234, 0x10, 0xFFF1)]
    strtab, entries = b"\0", []
    for name, value, info, shndx in symbols:
        entries.append(struct.pack("<IBBHQQ", len(strtab) if name else 0, info, 0, shndx, value, 0))
        strtab += name.encode() + b"\0" if name else b""
    bodies[".symtab"], bodies[".strtab"] = b"".join(entries), strtab
    # name, type, flags, address, link, info, alignment, entry size
    sections = [(".rodata", 1, 0x2, 0x10200, 0, 0, 8, 0), (".text", 1, 0x6, 0x11000, 0, 0, 4, 0),
                (".data", 1, 0x3, 0x12000, 0, 0, 8, 0), (".comment", 1, 0x30, 0, 0, 0, 1, 1),
                (".symtab", 2, 0, 0, 6, 2, 8, 24), (".strtab", 3, 0, 0, 0, 0, 1, 0), (".shstrtab", 3, 0, 0, 0, 0, 1, 0)]
    shstrtab = b"\0" + b"".join(s[0].encode() + b"\0" for s in sections)
    bodies[".shstrtab"] = shstrtab
    loads = [(1, 4, 0x10000, 0x220, 0x220), (1, 5, 0x11000, 0x40, 0x40), (0x6474E551, 6, 0, 0, 0),
             (1, 6, 0x12000, 0x8, 0x10)]
    data = bytearray(64 + 56 * len(loads))
    for k, (kind, flags, vaddr, filesz, memsz) in enumerate(loads):
        struct.pack_into("<IIQQQQQQ", data, 64 + 56 * k, kind, flags, 0, vaddr, vaddr, filesz, memsz, 0x1000)
    headers = [bytes(64)]
    for name, kind, flags, address, link, info, align, entsize in sections:
        headers.append(struct.pack("<IIQQQQIIQQ", shstrtab.index(b"\0" + name.encode() + b"\0") + 1, kind, flags,
                                   address, len(data), len(bodies[name]), link, info, align, entsize))
        data += bodies[name]
    shoff = len(data)
    data += b"".join(headers)
    data[:64] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0xF3, 1, 0x11000, 64, shoff, 0, 64, 56, len(loads), 64, len(headers), 7)
    output = "".join(f"section\t{name}\t0x{address:x}\t{len(bodies[name])}\t0x{flags:x}\n"
                     for name, _, flags, address, *_ in sections)
    output += ("load\t0x10000\t544\t544\t0x4\nload\t0x11000\t64\t64\t0x5\nload\t0x12000\t8\t16\t0x6\n"
               "symbol\tLLVMFuzzerTestOneInput\t0x11000\nsymbol\tweak_fn\t0x11020\nsymbol\tabs_sym\t0x1234\n")
    return bytes(data), output


def map_lines(copies):
    """The record's map of out_tree: (address, linked size, alignment, text)."""
    copy = f"{copies}/2-shim-local-call.o"
    return [
        (0x10200, 0x24, 4, "<internal>:(.note.gnu.build-id)"),
        (0x10224, 0x10, 8, "/work/lib/libshim.a(a.o):(.eh_frame)"),
        (0x11000, 0x4, 4, "/work/lib/libshim.a(a.o):(.text.__rust_alloc)"),
        (0x11004, 0x1a, 2, "/work/lib/libshim.a(a.o):(.text.__rust_alloc)"),
        (0x11020, 0x8, 2, "/work/lib/libshim.a(a.o):(.text.__rust_dealloc)"),
        # Smaller than its section, as lld's relaxation makes a line: sections.tsv gives the object's input size.
        (0x11028, 0x4, 2, "/work/lib/libshim.a(a.o):(.text.__rust_realloc)"),
        (0x11030, 0x2e, 2, "/work/lib/libshim.a(shim-local-access.o):(.text.__rust_alloc)"),
        (0x11060, 0x20, 2,
         "/work/lib/libshim.a(shim-local-access.o):(.text._RNvCsdMW3fuGnryS_17shim_local_access5parse)"),
        (0x11080, 0x8, 2, f"{copy}:(.text.__rust_alloc)"),
        (0x11088, 0xc, 2, f"{copy}:(.text._RNvCsgdEkaKC4q9e_15shim_local_call7rounded)"),
        (0x11094, 0x8, 4, "/work/obj/shim-rustc-v0.o:(.text._RNvCs6UdHf40Qw6p_7___rustc12___rust_alloc)"),
        (0x1109c, 0x8, 4, "/work/obj/shim-rustc-v0.o:(.text._RNvCs6UdHf40Qw6p_7___rustc14___rust_dealloc)"),
        (0x12000, 0x40, 1,
         "/work/lib/libshim.a(shim-local-access.o):(.bss._RNvCsdMW3fuGnryS_17shim_local_access4POOL)"),
        (0x12040, 0x10, 8, "/work/obj/shim-rustc-v0.o:(COMMON)"),
        (0, 0x36, 1, "/work/lib/libshim.a(a.o):(.comment)"),
    ]


def out_tree(builds, copies="/tmp/ov/af.AAAAAA", local_call=LOCAL_CALL, placement=None):
    """builds/plain/, the $OUT of a build as compile leaves it with link records: the fuzz target fuzz_shim
    (executable()) with its stripped twin and its record, an ELF file whose link has no record, and a seed corpus.
    The link took the archive ARCHIVE, an object, and an allocation-failure copy of shim-local-call.o in `copies`
    with the bytes `local_call`. Returns the record's directory."""
    raw = builds / "plain"
    binary, _ = executable()
    record = raw / ".records" / sha(binary)
    store = raw / ".records" / "store"
    for directory in (raw / ".stripped", record, store):
        directory.mkdir(parents=True)
    (raw / "fuzz_shim").write_bytes(binary)
    (raw / ".stripped" / sha(binary)).write_bytes(binary[:300])
    (raw / "other_fuzzer").write_bytes(binary + b"\0")
    (raw / "fuzz_shim_seed_corpus.zip").write_bytes(b"PK\5\6" + bytes(18))
    inputs = {"/work/lib/libshim.a": ARCHIVE, f"{copies}/2-shim-local-call.o": local_call,
              "/work/obj/shim-rustc-v0.o": V0}
    (record / "inputs.tsv").write_text("".join(f"{f}\t{f}\t{sha(d)}\t{len(d)}\n" for f, d in inputs.items()))
    for data in inputs.values():
        (store / sha(data)).write_bytes(data)
    (record / "map").write_text("".join(map_line(*line) for line in map_lines(copies)))
    (record / "driver").write_text("/tmp/ov/cli.o\n/tmp/ov/adapter.o\n")
    (record / "renamed").write_text(f"{copies}/2-shim-local-call.o\t{ORIGINAL}\t{sha(LOCAL_CALL)}\n")
    (record / "wraps").write_text("".join(f"{name}\n" for name in WRAPS))
    if placement is not None:
        (record / "placement.tsv").write_text(placement)
    return record


def expected_tables(copies, local_call=LOCAL_CALL):
    """sections.tsv and calls.tsv of out_tree's record, from the test's own reading of its objects. A map line takes
    the k-th section of its name in the objects of its file and member when they lie in one object, are as many as
    the map's lines of that name, and the line's linked size is not larger; any other line has no sha256, the map's
    size and alignment, and no calls. calls.tsv has each call and each R_RISCV_TPREL_HI20, and for a global, the
    global (else the first weak) symbol of its name that an object the map took defines in a section the map took."""
    objects = {("/work/lib/libshim.a", "a.o"): [REAL, STORES],
               ("/work/lib/libshim.a", "shim-local-access.o"): [LOCAL_ACCESS],
               (f"{copies}/2-shim-local-call.o", None): [local_call], ("/work/obj/shim-rustc-v0.o", None): [V0]}
    readings = {(where, i): read_object(data) for where, datas in objects.items() for i, data in enumerate(datas)}
    named = []
    for _, linked, map_align, text in map_lines(copies):
        if text.startswith("<internal>"):
            continue
        at = text.rindex(":(")
        where, section = text[:at], text[at + 2:-1]
        file, member = (where[:where.index("(")], where[where.index("(") + 1:-1]) if where.endswith(")") else (
            where, None)
        named.append((file, member, section, linked, map_align))
    counts = collections.Counter(n[:3] for n in named)
    sections, located, rows, seen = [], {}, {}, collections.Counter()
    for file, member, section, linked, map_align in named:
        k = seen[(file, member, section)]
        seen[(file, member, section)] += 1
        found = [(i, index) for i in range(len(objects[(file, member)]))
                 for index, s in readings[((file, member), i)][0].items() if s[0] == section]
        digest, size, align = "", linked, map_align
        if len(found) == counts[(file, member, section)] and len({i for i, _ in found}) == 1 \
                and linked <= readings[((file, member), found[k][0])][0][found[k][1]][3]:
            i, index = found[k]
            _, _, body, size, align = readings[((file, member), i)][0][index]
            digest = "" if body is None else sha(body)
            located[len(sections)] = ((file, member), i, index, section)
            rows[((file, member), i, index)] = len(sections)
        key_file = ORIGINAL if file.endswith("/2-shim-local-call.o") else file
        sections.append(f"{file}\t{key_file}\t{member or '-'}\t{section}\t{digest}\t{size}\t{align}\n")
    # The definitions: a global symbol first, then the first in map order.
    defined = {}
    for where, i, index, section in located.values():
        for name, value, symbol_info, shndx in readings[(where, i)][1]:
            row = rows.get((where, i, shndx))
            if symbol_info >> 4 in (1, 2) and row is not None and name:
                assert symbol_info & 0xF != 10  # no ifunc
                rank = (symbol_info >> 4 != 1, row)
                if name not in defined or rank < defined[name][0]:
                    defined[name] = (rank, f"{row}\t0x{value:x}")
    calls = []
    for row, (where, i, index, section) in sorted(located.items()):
        if not section.startswith(".text"):
            continue
        _, symbols, relocations = readings[(where, i)]
        found = sorted(relocations.get(index, []), key=lambda r: r[0])
        # These objects hold no R_RISCV_ALIGN and no R_RISCV_RELAX: no relocation of theirs removes bytes, so each line
        # has relax 0 and delta 0.
        assert not [r for r in found if r[1] & 0xFFFFFFFF in (43, 51)]
        for offset, info, addend in found:
            kind = {18: "call", 19: "call", 29: "tprel"}.get(info & 0xFFFFFFFF)
            if kind is None:
                continue
            name, value, symbol_info, shndx = symbols[info >> 32]
            if symbol_info >> 4 == 0 or symbol_info & 0xF == 3:
                calls.append(f"{row}\t0x{offset:x}\t{kind}\t0\t0x0\tlocal\t{rows.get((where, i, shndx), '-')}\t"
                             f"0x{value + addend:x}\t-\t-\n")
            else:
                if name in WRAPS:
                    name = "__wrap_" + name
                elif name.startswith("__real_") and name[7:] in WRAPS:
                    name = name[7:]
                weak = symbol_info >> 4 == 2 and shndx == 0 and name not in defined
                definition = defined[name][1] if name in defined else "-\t-"
                calls.append(f"{row}\t0x{offset:x}\t{kind}\t0\t0x0\t{'weak' if weak else 'global'}\t{name}\t"
                             f"0x{addend:x}\t{definition}\n")
    return "".join(sections), "".join(calls)


# ── the map ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_the_map_reader_agrees_with_parse_map():
    text = gzip.decompress(MAP.read_bytes()).decode()
    taken, read = check_links.parse_map(text)
    lines = layout.read_map(text)
    assert [(line.file, line.member, line.section, line.size) for line in lines[:len(taken)]] == taken
    # lld writes the output sections it does not load last, each from the address 0. The reader's other lines are
    # those of that tail, which parse_map reads as input sections and leaves out as not loaded.
    raw = text.split("\n")
    addresses = [int(line.split()[0], 16) for line in raw if line]
    start = next(k for k in range(1, len(addresses)) if addresses[k] < addresses[k - 1] and addresses[k] == 0)
    head, tail = "\n".join(raw[:start]), "\n".join(raw[start:])
    assert check_links.parse_map(head)[0] == taken and layout.read_map(head) == lines[:len(taken)]
    assert check_links.parse_map(tail)[0] == [] and layout.read_map(tail) == lines[len(taken):]
    assert len(lines) > len(taken)
    assert read == len(lines) + text.count("<internal>:(")
    # A line is loaded when parse_map keeps it: the lines it takes, which come first, and none of the tail.
    assert [line.loaded for line in lines] == [k < len(taken) for k in range(len(lines))]
    # Every line's address, and the alignment in decimal.
    assert lines[0] == layout.MapLine(0x10824, 0x24, 4, "/work/build/lib/plain/curl-fuzz_bufq/lib/liboft.a",
                                      "harness.o", ".rodata._Z16fuzz_handle_bufqP18FuzzedDataProvider", True)
    assert layout.MapLine(0x704E0, 0x30, 16, "/tmp/ov/adapter.o", None, ".bss..L_MergedGlobals.2", True) in lines
    assert [line.address for line in lines if line.section == ".debug_info"][0] == 0


# ── ELF files and archives ───────────────────────────────────────────────────────────────────────────────────────────

def test_the_archive_reader_reads_long_names_and_members_of_one_name():
    members = [(name, bytes(body)) for name, body in layout.ar_members(ARCHIVE, "libshim.a")]
    assert members == MEMBERS
    assert members == check_links.ar_members(ARCHIVE)


@pytest.mark.parametrize("data", [
    b"!<thin>\n" + ARCHIVE[8:],
    b"!<arch>\n" + f"{'#1/8':<16}{0:<12}{0:<6}{0:<6}{644:<8}{8:<10}`\n".encode() + b"a.o\0\0\0\0\0",
    ARCHIVE[:-100],
    ARCHIVE.replace(b"`\n", b"!\n", 1),
    FORWARDS,
], ids=["thin", "bsd", "truncated", "header", "object"])
def test_the_archive_reader_refuses_anything_else(data):
    with pytest.raises(layout.LayoutError):
        layout.ar_members(data, "x.a")


@pytest.mark.parametrize("data", [
    FORWARDS[:4] + b"\x01" + FORWARDS[5:],
    FORWARDS[:5] + b"\x02" + FORWARDS[6:],
    b"BC\xc0\xde" + bytes(60),
    FORWARDS[:0x740],
], ids=["32-bit", "big-endian", "bitcode", "truncated"])
def test_the_elf_reader_refuses_anything_else(data):
    with pytest.raises(layout.LayoutError):
        layout.Elf(data, "x.o").sections[-1]


def test_the_elf_reader_refuses_sht_rel_relocations():
    sections, _, _ = read_object(FORWARDS)
    shoff, = struct.unpack_from("<Q", FORWARDS, 0x28)
    index = next(i for i, s in sections.items() if s[0] == ".rela.text.__rust_alloc")
    data = bytearray(FORWARDS)
    struct.pack_into("<I", data, shoff + 64 * index + 4, 9)
    elf = layout.Elf(bytes(data), "x.o")
    with pytest.raises(layout.LayoutError):
        elf.relocations(elf.named(".text.__rust_alloc")[0].index)


# ── collect ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_sections_and_calls_agree_with_an_independent_reading(tmp_path):
    assert REAL.count(b"\0__real_dalloc\0") == 1
    out_tree(tmp_path / "builds")
    assert layout.main(["collect", str(tmp_path / "builds"), str(tmp_path / "layout")]) == 0
    entry = tmp_path / "layout" / "plain" / "fuzz_shim"
    sections, calls = expected_tables("/tmp/ov/af.AAAAAA")
    assert (entry / "sections.tsv").read_text() == sections
    assert (entry / "calls.tsv").read_text() == calls


def test_collect_writes_the_layout_tree(tmp_path):
    record = out_tree(tmp_path / "builds", placement="placed\n")
    assert layout.main(["collect", str(tmp_path / "builds"), str(tmp_path / "layout")]) == 0
    # Only the fuzz target with a record has an entry.
    assert [p.relative_to(tmp_path / "layout").as_posix() for p in sorted((tmp_path / "layout").glob("*/*"))] == [
        "plain/fuzz_shim"]
    entry = tmp_path / "layout" / "plain" / "fuzz_shim"
    assert sorted(p.name for p in entry.iterdir()) == ["binary.sha256", "calls.tsv", "map", "output.tsv",
                                                        "placement.tsv", "sections.tsv", "wraps"]
    for name in ("map", "wraps", "placement.tsv"):
        assert (entry / name).read_bytes() == (record / name).read_bytes()
    binary, output = executable()
    assert (entry / "output.tsv").read_text() == output
    assert (entry / "binary.sha256").read_text() == f"{sha(binary)}  unstripped\n{sha(binary[:300])}  stripped\n"
    rows = [line.split("\t") for line in (entry / "sections.tsv").read_text().splitlines()]
    # Both members named a.o have a .text.__rust_alloc and a .text.__rust_dealloc, and lld's map lists the members it
    # took in the order it took them: no line of those names can be told, so each has no sha256 and the map's size
    # and alignment. The one member's __rust_realloc has the object's input size and alignment, not the map's.
    assert [r[4:] for r in rows[1:4]] == [["", "4", "4"], ["", "26", "2"], ["", "8", "2"]]
    realloc = next(s[2] for s in read_object(REAL)[0].values() if s[0] == ".text.__rust_realloc")
    assert rows[4][4:] == [sha(realloc), "8", "2"]
    assert rows[11][4:] == ["", "64", "1"]  # .bss: SHT_NOBITS
    assert rows[12][4:] == ["", "16", "8"]  # COMMON: no such section; the map's size and alignment
    assert [r[1] for r in rows[7:9]] == [ORIGINAL, ORIGINAL]  # the allocation-failure copy, by its original
    assert [r[1] for r in rows[:7]] == [r[0] for r in rows[:7]]
    calls = [line.split("\t") for line in (entry / "calls.tsv").read_text().splitlines()]
    assert ["9", "0x0", "call", "0", "0x0", "global", "__wrap__RNvCs6UdHf40Qw6p_7___rustc11___rdl_alloc", "0x0", "-",
            "-"] in calls  # a wrapped function
    assert ["4", "0x0", "call", "0", "0x0", "global", "dalloc", "0x0", "-", "-"] in calls  # __real_dalloc
    assert ["10", "0x0", "call", "0", "0x0", "global", "_RNvCs6UdHf40Qw6p_7___rustc13___rdl_dealloc", "0x0", "-",
            "-"] in calls
    assert ["5", "0x8", "call", "0", "0x0", "local", "6", "0x0", "-", "-"] in calls
    assert ["5", "0x16", "call", "0", "0x0", "local", "-", "0x0", "-", "-"] in calls
    assert ["7", "0x0", "call", "0", "0x0", "local", "8", "0x0", "-", "-"] in calls
    assert not [c for c in calls if c[0] in ("1", "2", "3")]


def test_collect_runs_as_a_command(tmp_path):
    out_tree(tmp_path / "builds")
    done = subprocess.run([sys.executable, str(SCRIPT), "collect", str(tmp_path / "builds"), str(tmp_path / "out")],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "out" / "plain" / "fuzz_shim" / "sections.tsv").is_file()


def test_collect_replaces_a_placement_the_record_no_longer_has(tmp_path):
    record = out_tree(tmp_path / "builds", placement="placed\n")
    assert layout.main(["collect", str(tmp_path / "builds"), str(tmp_path / "layout")]) == 0
    (record / "placement.tsv").unlink()
    assert layout.main(["collect", str(tmp_path / "builds"), str(tmp_path / "layout")]) == 0
    assert not (tmp_path / "layout" / "plain" / "fuzz_shim" / "placement.tsv").exists()


def break_store(record):
    (record.parent / "store" / sha(ARCHIVE)).unlink()


def break_wraps(record):
    (record / "wraps").unlink()


def link_wraps(record):
    (record / "wraps").rename(record.parent / "wraps")
    (record / "wraps").symlink_to(record.parent / "wraps")


def no_record(record):
    shutil.rmtree(record.parent)


@pytest.mark.parametrize("damage, named", [
    (break_store, "/work/lib/libshim.a"),
    (break_wraps, "wraps"),
    (link_wraps, "wraps"),
    (no_record, "builds"),
], ids=["store", "no-wraps", "linked-wraps", "no-record"])
def test_collect_exits_2_for_a_record_it_cannot_use(tmp_path, capsys, damage, named):
    damage(out_tree(tmp_path / "builds"))
    assert layout.main(["collect", str(tmp_path / "builds"), str(tmp_path / "layout")]) == 2
    error = capsys.readouterr().err
    assert len(error.splitlines()) == 1 and named in error
    assert not (tmp_path / "layout").exists()


def test_collect_of_named_builds_reads_no_other_build_directory(tmp_path):
    builds = tmp_path / "builds"
    out_tree(builds)
    # Another run's build beside it, whose record has no wraps: a collect of each build directory stops on it.
    shutil.copytree(builds / "plain", builds / "asan", symlinks=True)
    for wraps in (builds / "asan" / ".records").glob("*/wraps"):
        wraps.unlink()
    with pytest.raises(layout.LayoutError, match="asan/fuzz_shim: the record has no wraps"):
        layout.collect(str(builds), str(tmp_path / "every"))
    layout.collect(str(builds), str(tmp_path / "layout"), ["plain"])
    assert [p.relative_to(tmp_path / "layout").as_posix() for p in sorted((tmp_path / "layout").glob("*/*"))] == [
        "plain/fuzz_shim"]
    assert sorted(p.name for p in (tmp_path / "layout" / "plain" / "fuzz_shim").iterdir()) == [
        "binary.sha256", "calls.tsv", "map", "output.tsv", "sections.tsv", "wraps"]


@pytest.mark.parametrize("name, made", [("ubsan", True), ("asan", False)], ids=["no-records", "no-directory"])
def test_collect_refuses_a_named_build_with_no_records(tmp_path, name, made):
    out_tree(tmp_path / "builds")
    if made:
        (tmp_path / "builds" / name).mkdir()
    with pytest.raises(layout.LayoutError, match=f"^{name}: .* holds no link records"):
        layout.collect(str(tmp_path / "builds"), str(tmp_path / "layout"), ["plain", name])
    assert not (tmp_path / "layout").exists()


# ── pairing ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def inputs(*specs):
    """[Input] of (file, member, section, content, size): the sha256 is that of `content`."""
    return [layout.Input(row, 0x11000 + 0x100 * row, size, file, (file, member or "-", section), member, section,
                         sha(content.encode()) if content else "", size, 4)
            for row, (file, member, section, content, size) in enumerate(specs)]


def test_pairing_by_key():
    base = inputs(("a.o", None, ".text.f", "f", 8), ("a.o", None, ".text.g", "g", 12),
                  ("a.o", None, ".rodata.r", "r", 4))
    new = inputs(("a.o", None, ".rodata.r", "r", 4), ("a.o", None, ".text.g", "g", 12),
                 ("a.o", None, ".text.f", "F", 8), ("a.o", None, ".text.h", "h", 4))
    pairing = layout.pair(base, new)
    assert pairing.partner == {1: 1, 2: 0, 3: None}
    assert pairing.same == {1: True, 2: False, 3: False}
    assert pairing.repeated == set()


def test_pairing_a_comdat_section_from_another_object():
    base = inputs(("a.o", None, ".text._Z3foov", "foo", 16), ("a.o", None, ".text._Z3barv", "bar", 16))
    new = inputs(("b.o", None, ".text._Z3foov", "foo", 16), ("b.o", None, ".text._Z3barv", "bar 2", 16))
    pairing = layout.pair(base, new)
    assert pairing.partner == {0: 0, 1: None} and pairing.same == {0: True, 1: False}
    # Two sections with the same name, bytes and size on one side: neither is paired by them.
    base = inputs(("a.o", None, ".text._Z3foov", "foo", 16), ("c.o", None, ".text._Z3foov", "foo", 16))
    assert layout.pair(base, new).partner == {0: None, 1: None}


def test_pairing_a_repeated_key_member_by_member():
    key = ("lib.a", "x.o", ".text.helper")
    base = inputs(key + ("x", 8), ("lib.a", "y.o", ".text.other", "o", 8), key + ("x", 8))
    new = inputs(key + ("x", 8), key + ("z", 8))
    pairing = layout.pair(base, new)
    assert pairing.partner == {0: 0, 1: 2} and pairing.same == {0: True, 1: False}
    assert pairing.repeated == {("lib.a", "x.o", ".text.helper")}
    # Members whose bytes and size are unique on each side are paired by them first, whatever their order.
    base = inputs(key + ("x", 8), key + ("y", 8))
    new = inputs(key + ("y", 8), key + ("x", 8))
    pairing = layout.pair(base, new)
    assert pairing.partner == {0: 1, 1: 0} and pairing.same == {0: True, 1: True}


def test_pairing_keys_a_copy_by_its_original(tmp_path):
    # The append build's copy is at another path, and one of its functions changed: it is paired by its original.
    changed = bytearray(LOCAL_CALL)
    changed[section_offset(LOCAL_CALL, ".text._RNvCsgdEkaKC4q9e_15shim_local_call7rounded")] ^= 0xFF
    for name, copies, data in (("base", "/tmp/ov/af.AAAAAA", LOCAL_CALL), ("new", "/tmp/ov/af.BBBBBB", changed)):
        out_tree(tmp_path / name, copies=copies, local_call=bytes(data))
        assert layout.main(["collect", str(tmp_path / name), str(tmp_path / f"{name}-layout")]) == 0
    base, new = (layout.read_layout(str(tmp_path / f"{name}-layout" / "plain" / "fuzz_shim"))
                 for name in ("base", "new"))
    assert base.inputs[8].file != new.inputs[8].file and base.inputs[8].key == new.inputs[8].key
    pairing = layout.pair(base.inputs, new.inputs)
    assert (pairing.partner[7], pairing.same[7]) == (7, True)
    assert (pairing.partner[8], pairing.same[8]) == (8, False)


# ── check ────────────────────────────────────────────────────────────────────────────────────────────────────────────

def row(section, address, size, file="/work/a.o", member=None, align=4, content=None):
    """An input section of a layout tree's entry: its map line and its sections.tsv line."""
    return {"file": file, "member": member, "section": section, "address": address, "linked": size,
            "sha256": sha((content or section).encode()), "size": size, "align": align}


TABLE = row(".rodata.table", 0x10200, 0x20, align=8)
ALPHA = row(".text.alpha", 0x11000, 0x20)
BETA = row(".text.beta", 0x11020, 0x10)
GAMMA = row(".text.gamma", 0x11030, 0x40, file="/work/b.o")
COMMENT = row(".comment", 0, 0x10, align=1)
DUP0 = row(".text.dup", 0x11070, 0x10, file="/work/lib.a", member="dup.o")
OTHER = row(".text.other", 0x11080, 0x10, file="/work/c.o")
DUP1 = row(".text.dup", 0x11090, 0x10, file="/work/lib.a", member="dup.o", content="dup 1")
# beta (row 2) calls alpha, a local symbol of a.o (row 1), at 0x4, and gamma, a global that only the binary's symbol
# gives (no definition), at 0xc. Each line has R_RISCV_RELAX (relax 1), and no byte in front of it was removed.
CALLS = [("2", "0x4", "call", "1", "0x0", "local", "1", "0x0", "-", "-"),
         ("2", "0xc", "call", "1", "0x0", "global", "gamma", "0x0", "-", "-")]
# tv, a thread-local variable of b.o, lies in the TLS segment that starts at 0x12000. beta also reads it, with a lui at
# 0x8 whose line names tv's definition, row 4.
TV = dict(row(".tbss.tv", 0x12000, 4, file="/work/b.o"), sha256="")
TLS_CALLS = CALLS + [("2", "0x8", "tprel", "1", "0x0", "global", "tv", "0x0", "4", "0x0")]


def output(text=0x11000, text_size=0x100, front=0x300, gamma=0x11030, tls=False):
    """output.tsv: .rodata in a read-only PT_LOAD at 0x10000 of `front` bytes, .text in the next one; with `tls`, a
    .tbss at 0x12000, the start of the TLS segment."""
    return (f"section\t.rodata\t0x10200\t256\t0x2\nsection\t.text\t0x{text:x}\t{text_size}\t0x6\n"
            + ("section\t.tbss\t0x12000\t8192\t0x403\n" if tls else "")
            + f"section\t.comment\t0x0\t16\t0x30\nload\t0x10000\t{front}\t{front}\t0x4\n"
            f"load\t0x{text:x}\t{text_size}\t{text_size}\t0x5\nsymbol\tgamma\t0x{gamma:x}\n")


def placed(r, occurrence=0, cause="-", detail="-", place="hole"):
    """A line of placement.tsv for the section `r`, paired with the base section of the same key."""
    key = [r["file"], r["member"] or "-", r["section"], str(occurrence)]
    return "\t".join(key + key + [place, f"0x{r['address']:x}", cause, detail]) + "\n"


def write_entry(root, rows, calls=CALLS, out=None, placement=None, build="plain", target="fuzz"):
    """root/<build>/<target>/ of a layout tree. A row of the file <internal> is a line of the map alone, as the
    linker's own sections are: sections.tsv has no line for it."""
    entry = root / build / target
    entry.mkdir(parents=True)
    where = [r["file"] if r["member"] is None else f"{r['file']}({r['member']})" for r in rows]
    (entry / "map").write_text("".join(map_line(r["address"], r["linked"], r["align"], f"{w}:({r['section']})")
                                       for r, w in zip(rows, where)))
    (entry / "sections.tsv").write_text("".join(
        f"{r['file']}\t{r['file']}\t{r['member'] or '-'}\t{r['section']}\t{r['sha256']}\t{r['size']}\t{r['align']}\n"
        for r in rows if r["file"] != "<internal>"))
    (entry / "calls.tsv").write_text("".join("\t".join(c) + "\n" for c in calls))
    (entry / "output.tsv").write_text(out or output())
    if placement is not None:
        (entry / "placement.tsv").write_text("".join(placement))
    return entry


BASE_ROWS = [TABLE, ALPHA, BETA, GAMMA, COMMENT]


def run_check(tmp_path, capsys, new, base=None):
    """layout.py check on a BASE of `base` (write_entry's arguments, by default BASE_ROWS) and a NEW of `new`: (exit
    status, the lines it prints)."""
    write_entry(tmp_path / "base", **(base or {"rows": BASE_ROWS}))
    write_entry(tmp_path / "new", **new)
    status = layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")])
    return status, capsys.readouterr().out.splitlines()


def lines_with(lines, *words):
    return [line for line in lines if all(word in line for word in words)]


def test_check_passes_for_the_same_layout(tmp_path, capsys):
    status, lines = run_check(tmp_path, capsys, {"rows": BASE_ROWS})
    assert status == 0
    assert lines_with(lines, "plain/fuzz", "3 kept")
    assert not lines_with(lines, "FAIL")


@pytest.mark.parametrize("moved", [dict(BETA, address=BETA["address"] + 0x10), dict(BETA, linked=BETA["linked"] + 4)],
                         ids=["address", "size"])
def test_check_fails_for_a_kept_function_that_moved_or_changed_size(tmp_path, capsys, moved):
    status, lines = run_check(tmp_path, capsys, {"rows": [TABLE, ALPHA, moved, GAMMA, COMMENT]})
    assert status == 1
    assert lines_with(lines, "FAIL", "plain/fuzz", "beta", hex(BETA["address"]), hex(moved["address"]),
                      str(BETA["linked"]), str(moved["linked"]))
    assert not lines_with(lines, "FAIL", "alpha") and not lines_with(lines, "FAIL", "gamma")


def test_check_lists_changed_new_and_moved_data(tmp_path, capsys):
    gamma = dict(GAMMA, address=0x11100, sha256=sha(b"gamma 2"))
    delta = row(".text.delta", 0x11140, 0x10, file="/work/b.o")
    table = dict(TABLE, address=0x10240)
    # A section whose name starts with .text but not with .text. holds no function: it is listed as data.
    textfoo = row(".textfoo", 0x10280, 0x10, file="/work/c.o")
    # A section that the binary does not load has offsets from 0, which can fall in the range of one it loads (.text
    # here): it moved with the same bytes, and is not listed.
    debug = row(".debug_info", 0x11010, 0x10)
    status, lines = run_check(tmp_path, capsys,
                              {"rows": [table, ALPHA, BETA, gamma, delta, dict(textfoo, address=0x102a0), COMMENT,
                                        dict(debug, address=0x11050)],
                               "out": output(text_size=0x200)},
                              {"rows": BASE_ROWS[:-1] + [textfoo, COMMENT, debug]})
    assert status == 0
    assert lines_with(lines, "gamma", "0x11030", "0x11100")
    assert lines_with(lines, "delta", "- -> 0x11140")
    assert lines_with(lines, ".text", "0x11000", "256", "512")
    assert lines_with(lines, ".rodata.table", "0x10200", "0x10240")
    assert lines_with(lines, "moved, same bytes: .textfoo (/work/c.o): 0x10280 -> 0x102a0")
    assert not lines_with(lines, ".debug_info")  # not loaded


def test_check_does_not_list_a_section_the_binary_does_not_load_that_begins_with_an_internal_line(tmp_path, capsys):
    # OSSV-675. An output section that the binary does not load can begin with a line of the linker's own at 0, and
    # go on with an object's line at an offset that is not 0. As parse_map reads the map, the address falls to 0 on
    # the <internal> line, so the object's .comment is not loaded: its offset changed with the same bytes, and it is
    # not listed. The table, which the binary loads, is.
    internal = row(".comment", 0, 0x13, file="<internal>", align=1)
    status, lines = run_check(tmp_path, capsys,
                              {"rows": [dict(TABLE, address=0x10240), ALPHA, BETA, GAMMA, internal,
                                        dict(COMMENT, address=0x26)]},
                              {"rows": BASE_ROWS[:-1] + [internal, dict(COMMENT, address=0x13)]})
    assert status == 0
    assert lines_with(lines, "moved, same bytes:") == [
        "  moved, same bytes: .rodata.table (/work/a.o): 0x10200 -> 0x10240"]


def jal_lost():
    alpha = dict(ALPHA, address=0x211000, sha256=sha(b"alpha 2"))
    beta = dict(BETA, address=0x11100)
    return None, {"rows": [TABLE, alpha, beta, GAMMA, COMMENT],
                  "placement": [placed(alpha, place="end"), placed(beta, cause="jal_reach",
                                                                   detail="offset=0x4;target=row:1+0x0;lost")]}, beta


def jal_gained():
    far = dict(GAMMA, address=0x300000)
    gamma = dict(GAMMA, address=0x11100, sha256=sha(b"gamma 2"))
    beta = dict(BETA, address=0x11200)
    return ({"rows": [TABLE, ALPHA, BETA, far, COMMENT], "out": output(gamma=0x300000)},
            {"rows": [TABLE, ALPHA, beta, gamma, COMMENT], "out": output(gamma=0x11100),
             "placement": [placed(beta, cause="jal_reach", detail="offset=0xc;target=gamma;gained")]}, beta)


# As CALLS, but lld relaxed beta's call of alpha at 0x4 at the base, so its call of gamma at 0xc is at 0x11020 + 0xc -
# 4 = 0x11028 (delta 0x4).
DELTA_CALLS = [CALLS[0], ("2", "0xc", "call", "1", "0x4", "global", "gamma", "0x0", "-", "-")]


def jal_gained_past_a_relaxed_call():
    # OSSV-675 review. At the base gamma lies 0x100000 bytes from beta's call site 0x11028, one past jal's reach: lld
    # kept that call. From 0x1102c, the section's address plus the offset alone, gamma would lie in reach. In NEW,
    # gamma lies in reach, so the call gained it.
    far = dict(GAMMA, address=0x111028)
    gamma = dict(GAMMA, address=0x11100, sha256=sha(b"gamma 2"))
    beta = dict(BETA, address=0x11200)
    return ({"rows": [TABLE, ALPHA, BETA, far, COMMENT], "calls": DELTA_CALLS, "out": output(gamma=0x111028)},
            {"rows": [TABLE, ALPHA, beta, gamma, COMMENT], "calls": DELTA_CALLS, "out": output(gamma=0x11100),
             "placement": [placed(beta, cause="jal_reach", detail="offset=0xc;target=gamma;gained")]}, beta)


def repeated_key():
    dup0, dup1 = dict(DUP0, address=0x11300), dict(DUP1, address=0x11310)
    return ({"rows": BASE_ROWS + [DUP0, OTHER, DUP1]},
            {"rows": BASE_ROWS + [dup0, OTHER, dup1],
             "placement": [placed(dup0, 0, "repeated_key"), placed(dup1, 1, "repeated_key")]}, dup1)


def alignment():
    beta = dict(BETA, address=0x11100, align=64)
    return None, {"rows": [TABLE, ALPHA, beta, GAMMA, COMMENT],
                  "placement": [placed(beta, cause="alignment", detail="align=64")]}, beta


def readonly_growth():
    moved = [dict(r, address=r["address"] + 0x1000) for r in (ALPHA, BETA, GAMMA)]
    # The segment in front of .text ends at 0x11100, past page_floor(0x11000): it grew by 0x11100 - 0x10300 = 3584
    # bytes, and its room was 0x11000 - 0x10300 = 3328.
    return None, {"rows": [TABLE] + moved + [COMMENT], "out": output(text=0x12000, front=0x1100, gamma=0x12030),
                  "placement": [placed(r, cause="readonly_growth", detail="growth=3584;room=3328", place="normal")
                                for r in moved]}, moved[1]


def repeated_run_dragged():
    # One pattern would keep the run, but one member moved for a cause of its own (alignment): the other moves with it.
    dup1 = dict(DUP1, address=0x11080)
    moved0, moved1 = dict(DUP0, address=0x11300, align=64), dict(dup1, address=0x11310)
    return ({"rows": BASE_ROWS + [DUP0, dup1]},
            {"rows": BASE_ROWS + [moved0, moved1],
             "placement": [placed(moved0, 0, "alignment", "align=64"), placed(moved1, 1, "repeated_key")]}, moved1)


def tls_reach(base_offset, new_offset, way):
    """beta reads tv (TLS_CALLS), which lies `base_offset` bytes into the TLS segment at the base and `new_offset`
    bytes into it in NEW, and moved with tls_reach, `way`: lld keeps or removes 8 of its bytes wherever it goes."""
    beta = dict(BETA, address=0x11100, linked=BETA["linked"] + (8 if way == "lost" else -8))
    return ({"rows": [TABLE, ALPHA, BETA, GAMMA, dict(TV, address=0x12000 + base_offset), COMMENT],
             "calls": TLS_CALLS, "out": output(tls=True)},
            {"rows": [TABLE, ALPHA, beta, GAMMA, dict(TV, address=0x12000 + new_offset), COMMENT],
             "calls": TLS_CALLS, "out": output(tls=True),
             "placement": [placed(beta, cause="tls_reach", detail=f"offset=0x8;target=tv;{way}")]}, beta)


def tls_lost():
    # 0x7ff is the largest offset whose access lld relaxes.
    return tls_reach(0x7FF, 0x800, "lost")


def tls_gained():
    return tls_reach(0x2000, 0x10, "gained")


@pytest.mark.parametrize("scenario", [jal_lost, jal_gained, jal_gained_past_a_relaxed_call, tls_lost, tls_gained,
                                      repeated_key, repeated_run_dragged, alignment, readonly_growth])
def test_check_lists_a_function_that_moved_for_a_cause_the_trees_show(tmp_path, capsys, scenario):
    base, new, moved = scenario()
    status, lines = run_check(tmp_path, capsys, new, base)
    assert status == 0, lines
    old = next(r for r in (base or {"rows": BASE_ROWS})["rows"] if r["section"] == moved["section"]
               and r.get("sha256") == moved["sha256"])
    cause = new["placement"][-1].split("\t")[10]
    assert lines_with(lines, moved["section"][len(".text."):], cause, hex(old["address"]), hex(moved["address"]))


def jal_in_reach():
    beta = dict(BETA, address=0x11100)
    return None, {"rows": [TABLE, ALPHA, beta, GAMMA, COMMENT],
                  "placement": [placed(beta, cause="jal_reach", detail="offset=0x4;target=row:1+0x0;lost")]}, "beta"


def jal_no_such_call():
    base, new, _ = jal_lost()
    new["placement"][1] = new["placement"][1].replace("offset=0x4", "offset=0x6")
    return base, new, "beta"


def repeated_once():
    beta = dict(BETA, address=0x11100)
    return None, {"rows": [TABLE, ALPHA, beta, GAMMA, COMMENT],
                  "placement": [placed(beta, cause="repeated_key")]}, "beta"


def repeated_run():
    # Side by side at the base, the same bytes, and in the same order: one pattern keeps them.
    dup1 = dict(DUP1, address=0x11080)
    moved0, moved1 = dict(DUP0, address=0x11300), dict(dup1, address=0x11310)
    return ({"rows": BASE_ROWS + [DUP0, dup1]},
            {"rows": BASE_ROWS + [moved0, moved1],
             "placement": [placed(moved0, 0, "repeated_key"), placed(moved1, 1, "repeated_key")]}, "dup")


def repeated_run_unshown_drag():
    # The member that would drag the other claims alignment, but its base address meets its alignment.
    dup1 = dict(DUP1, address=0x11080)
    moved0, moved1 = dict(DUP0, address=0x11300, align=16), dict(dup1, address=0x11310)
    return ({"rows": BASE_ROWS + [DUP0, dup1]},
            {"rows": BASE_ROWS + [moved0, moved1],
             "placement": [placed(moved0, 0, "alignment", "align=16"), placed(moved1, 1, "repeated_key")]}, "dup")


def aligned():
    alpha = dict(ALPHA, address=0x11100, align=64)
    return None, {"rows": [TABLE, alpha, BETA, GAMMA, COMMENT],
                  "placement": [placed(alpha, cause="alignment", detail="align=64")]}, "alpha"


def within_room():
    moved = [dict(r, address=r["address"] + 0x1000) for r in (ALPHA, BETA, GAMMA)]
    return None, {"rows": [TABLE] + moved + [COMMENT], "out": output(text=0x12000, front=0x400, gamma=0x12030),
                  "placement": [placed(r, cause="readonly_growth", detail="growth=256;room=3328", place="normal")
                                for r in moved]}, "alpha"


def wrong_growth():
    base, new, _ = readonly_growth()
    new["placement"] = [line.replace("growth=3584", "growth=3585") for line in new["placement"]]
    return base, new, "gamma"


def tls_within():
    # tv moved, but stayed within the reach of a relaxed access.
    base, new, _ = tls_reach(0, 0x7FF, "lost")
    return base, new, "beta"


def tls_wrong_way():
    base, new, _ = tls_reach(0x7FF, 0x800, "gained")
    return base, new, "beta"


def jal_unrelaxable():
    # OSSV-675 review. beta's call of alpha has no R_RISCV_RELAX (relax 0), so lld never relaxes it, wherever alpha
    # goes: no cause rests on it.
    _, new, _ = jal_lost()
    calls = [("2", "0x4", "call", "0", "0x0", "local", "1", "0x0", "-", "-"), CALLS[1]]
    return {"rows": BASE_ROWS, "calls": calls}, dict(new, calls=calls), "beta"


def jal_no_delta():
    # BASE's calls.tsv does not know the bytes that relaxation removed in front of the call: its base call site is
    # not known.
    _, new, _ = jal_lost()
    calls = [("2", "0x4", "call", "1", "-", "local", "1", "0x0", "-", "-"),
             ("2", "0xc", "call", "1", "-", "global", "gamma", "0x0", "-", "-")]
    return {"rows": BASE_ROWS, "calls": calls}, dict(new, calls=calls), "beta"


def tls_unrelaxable():
    # The access to tv has no R_RISCV_RELAX: lld never relaxes it, wherever tv lies.
    base, new, _ = tls_reach(0x7FF, 0x800, "lost")
    calls = CALLS + [("2", "0x8", "tprel", "0", "0x0", "global", "tv", "0x0", "4", "0x0")]
    return dict(base, calls=calls), dict(new, calls=calls), "beta"


def no_cause():
    beta = dict(BETA, address=0x11100)
    return None, {"rows": [TABLE, ALPHA, beta, GAMMA, COMMENT], "placement": [placed(beta)]}, "beta"


def no_placement():
    return None, {"rows": [TABLE, ALPHA, dict(BETA, address=0x11100), GAMMA, COMMENT]}, "beta"


@pytest.mark.parametrize("scenario", [jal_in_reach, jal_no_such_call, jal_unrelaxable, jal_no_delta, tls_within,
                                      tls_wrong_way, tls_unrelaxable, repeated_once, repeated_run,
                                      repeated_run_unshown_drag, aligned, within_room, wrong_growth, no_cause,
                                      no_placement])
def test_check_fails_for_a_cause_the_trees_do_not_show(tmp_path, capsys, scenario):
    base, new, name = scenario()
    status, lines = run_check(tmp_path, capsys, new, base)
    assert status == 1
    assert lines_with(lines, "FAIL", "plain/fuzz", name)


def test_check_exits_2_for_a_missing_file(tmp_path, capsys):
    write_entry(tmp_path / "base", BASE_ROWS)
    os.unlink(write_entry(tmp_path / "new", BASE_ROWS) / "calls.tsv")
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 2
    assert "calls.tsv" in capsys.readouterr().err


@pytest.mark.parametrize("line", [
    "2\t0x4\tlocal\t1\t0x0",
    "2\t0x4\tcall\tlocal\t1\t0x0\t-\t-",
    "2\t0x4\tjump\t1\t0x0\tlocal\t1\t0x0\t-\t-",
    "2\t0x4\tcall\t2\t0x0\tlocal\t1\t0x0\t-\t-",
    "2\t0x4\tcall\t1\t4\tlocal\t1\t0x0\t-\t-",
    "2\t0x4\tcall\t1\t-0x4\tlocal\t1\t0x0\t-\t-",
    "2\t0x4\tcall\t1\t0x0\textern\tgamma\t0x0\t-\t-",
    "2\t0x4\tcall\t1\t0x0\tlocal\t1\t0x0\t3\t0x0",
    "2\t0x4\tcall\t1\t0x0\tweak\tgamma\t0x0\t3\t0x0",
    "2\t0x4\tcall\t1\t0x0\tglobal\tgamma\t0x0\t5\t0x0",
    "2\t0x4\tcall\t1\t0x0\tglobal\tgamma\t0x0\t3\t-",
], ids=["old-columns", "eight-columns", "type", "relax", "delta", "negative-delta", "kind", "local-definition",
        "weak-definition", "definition-past-the-rows", "half-a-definition"])
def test_check_exits_2_for_a_line_of_calls_that_does_not_read(tmp_path, capsys, line):
    write_entry(tmp_path / "base", BASE_ROWS, calls=[])
    entry = write_entry(tmp_path / "new", BASE_ROWS, calls=[line.split("\t")])
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 2
    assert f"{entry / 'calls.tsv'}: line 1 does not read" in capsys.readouterr().err


def test_calls_lines_of_each_kind_read_and_write_back(tmp_path):
    # OSSV-675 review: relax and delta, and the kinds weak and ifunc.
    lines = ["2\t0x4\tcall\t1\t0x0\tlocal\t1\t0x0\t-\t-", "2\t0x8\ttprel\t1\t0x4\tglobal\ttv\t0x0\t4\t0x0",
             "2\t0xc\tcall\t0\t0x4\tglobal\tgamma\t-0x2\t-\t-", "2\t0x10\tcall\t1\t0x8\tweak\tw\t0x0\t-\t-",
             "2\t0x14\tcall\t1\t-\tifunc\ti\t0x0\t-\t-", "2\t0x18\tcall\t1\t-\tlocal\t-\t0x10\t-\t-"]
    (tmp_path / "calls.tsv").write_text("".join(line + "\n" for line in lines))
    calls = layout.read_calls(str(tmp_path / "calls.tsv"), 5)
    assert calls[2] == [layout.Call(2, 0x4, "call", True, 0, "local", 1, 0, None),
                        layout.Call(2, 0x8, "tprel", True, 4, "global", "tv", 0, (4, 0)),
                        layout.Call(2, 0xC, "call", False, 4, "global", "gamma", -2, None),
                        layout.Call(2, 0x10, "call", True, 8, "weak", "w", 0, None),
                        layout.Call(2, 0x14, "call", True, None, "ifunc", "i", 0, None),
                        layout.Call(2, 0x18, "call", True, None, "local", None, 0x10, None)]
    assert layout.calls_rows(calls[2]) == [line.split("\t") for line in lines]


def test_check_exits_2_for_sections_that_do_not_match_the_map(tmp_path):
    write_entry(tmp_path / "base", BASE_ROWS)
    entry = write_entry(tmp_path / "new", BASE_ROWS)
    (entry / "sections.tsv").write_text("".join((entry / "sections.tsv").read_text().splitlines(True)[:-1]))
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 2


def test_check_exits_2_when_the_trees_share_no_build_and_target(tmp_path):
    write_entry(tmp_path / "base", BASE_ROWS)
    write_entry(tmp_path / "new", BASE_ROWS, build="ubsan")
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 2


# ── wraps ────────────────────────────────────────────────────────────────────────────────────────────────────────────

def fake_driver(tmp_path, status=0, linker=True, loop=False):
    """A compiler driver that answers -### as clang does, on its standard error, and exits with `status`: a linker
    line that a later one replaces, a compile line, the linker's line (with --wrap=a, --wrap b and an @file that
    holds --wrap=c and a nested @file that holds --wrap=d), and then a line of another tool. With `linker` false, no
    linker line; with `loop`, the nested @file names the first. Returns its path."""
    (tmp_path / "two.rsp").write_text(f"--wrap=d --wrap=a{f' @{tmp_path}/one.rsp' if loop else ''}\n")
    (tmp_path / "one.rsp").write_text(f'--wrap=c\n"@{tmp_path}/two.rsp" x.o\n')
    earlier = ' "/usr/bin/ld" "--wrap=earlier"\n'
    linker_line = f' "/usr/bin/ld.lld" "-o" "a.out" "--wrap=a" "--wrap" "b" "@{tmp_path}/one.rsp" "main.o"\n'
    driver = tmp_path / "driver"
    driver.write_text("#!/bin/sh\n"
                      "case \" $* \" in *' -### '*) ;; *) exit 9 ;; esac\n"
                      "cat >&2 <<'EOF'\n"
                      "clang version 20.1.8\n"
                      + (earlier if linker else "")
                      + ' "/usr/bin/clang-20" "-cc1" "--wrap=compiled"\n'
                      + (linker_line if linker else "")
                      + ' "/usr/bin/llvm-objcopy" "--wrap=other"\n'
                      f"EOF\nexit {status}\n")
    driver.chmod(0o755)
    return driver


def test_wraps_of_reads_the_linkers_command_and_its_at_files(tmp_path):
    wraps = layout.wraps_of([str(fake_driver(tmp_path)), "main.o"])
    assert wraps == ["a", "b", "c", "d"]
    # A call of a wrapped function reaches its wrapper, and a call of __real_<f> the function itself.
    assert layout.resolve("c", wraps) == "__wrap_c"
    assert layout.resolve("__real_d", wraps) == "d"
    assert layout.resolve("other", wraps) == "other"


def test_wraps_runs_as_a_command(tmp_path):
    done = subprocess.run([sys.executable, str(SCRIPT), "wraps", "--", str(fake_driver(tmp_path)), "main.o"],
                          capture_output=True, text=True)
    assert (done.returncode, done.stdout) == (0, "a\nb\nc\nd\n"), done.stderr


@pytest.mark.parametrize("driver", [{"status": 1}, {"linker": False}, {"loop": True}],
                         ids=["fails", "no-linker-line", "at-file-loop"])
def test_wraps_exits_2_without_a_linker_command_it_can_read(tmp_path, capsys, driver):
    assert layout.main(["wraps", "--", str(fake_driver(tmp_path, **driver)), "main.o"]) == 2
    assert len(capsys.readouterr().err.splitlines()) == 1


# ── the append mode: the plan ────────────────────────────────────────────────────────────────────────────────────────

def text_input(row, name, address, size, file="/work/a.o", member=None, content=None, align=4, section=None):
    """A .text input section of a link (Input): .text.<name> of `file`, `size` bytes (input and linked) at
    `address`, with the bytes that `content` names (by default the name)."""
    section = section or f".text.{name}"
    return layout.Input(row, address, size, file, (file, member or "-", section), member, section,
                        sha((content or name).encode()), size, align)


def laid_out(specs, start=0x11000):
    """The .text input sections of a link with no script: [(name, size, text_input's other arguments)], one after
    another from `start`, each at its alignment."""
    found, at = [], start
    for row, (name, size, extra) in enumerate(specs):
        align = extra.get("align", 4)
        at = (at + align - 1) // align * align
        found.append(text_input(row, name, at, size, **extra))
        at += size
    return found


def link(found, calls=(), symbols=None, front=0x10400, tls=(), deltas=None, norelax=(), tail=(), defined=None):
    """A Layout of the .text input sections `found` and their calls [(row, offset, called global)]. Its output:
    .eh_frame in a read-only PT_LOAD from 0x10000 to `front`, .text over the sections in the next PT_LOAD, and
    .init_array and .fini_array in the PT_LOAD after it, where lld puts it (the next page, at the same offset), and
    the global symbols `symbols`. With `tls` [(section, address, size)], the link also takes these thread-local data
    sections of /work/t.o, rows after `found`, and its TLS segment is a .tdata over them; a call (row, offset,
    variable, (row, value)) is then a thread-local access of the variable that row and value define. With `tail`
    [(section, size, alignment)], it also takes these sections of /opt/lib/libc++.a(new.o), rows after those, which
    lld puts after .text in the same PT_LOAD, one after another, each at its alignment and in an output section of
    its name (libc++'s __lcxx_override, for one). `defined` ({global: (row, value)}) gives the definition in the
    link's objects of a global that calls name. The binary loads each input. Each call has R_RISCV_RELAX (relax 1),
    but those (row, offset) that `norelax` names, and lld removed `deltas` {(row, offset): bytes} in front of it (by
    default none)."""
    by_row = collections.defaultdict(list)
    for row, offset, name, *defined_at in calls:
        line_type, definition = ("tprel", defined_at[0]) if defined_at else ("call", (defined or {}).get(name))
        by_row[row].append(layout.Call(row, offset, line_type, (row, offset) not in norelax,
                                       (deltas or {}).get((row, offset), 0), "global", name, 0, definition))
    start, end = min(i.address for i in found), max(i.address + i.linked for i in found)
    after, more = end, []
    for k, (section, size, align) in enumerate(tail):
        after = (after + align - 1) // align * align
        more.append(layout.Input(len(found) + len(tls) + k, after, size, "/opt/lib/libc++.a",
                                 ("/opt/lib/libc++.a", "new.o", section), "new.o", section, sha(section.encode()),
                                 size, align))
        after += size
    rw = (after + 0xFFF) // 0x1000 * 0x1000 + after % 0x1000
    sections = [layout.OutputSection(".eh_frame", 0x10300, front - 0x10300, 0x2),
                layout.OutputSection(".text", start, end - start, 0x6)]
    sections += [layout.OutputSection(i.section, i.address, i.size, 0x6) for i in more]
    sections += [layout.OutputSection(".init_array", rw, 8, 0x3), layout.OutputSection(".fini_array", rw + 8, 8, 0x3),
                 layout.OutputSection(".comment", 0, 0x10, 0x30)]
    data = [layout.Input(len(found) + k, address, size, "/work/t.o", ("/work/t.o", "-", section), None, section,
                         sha(section.encode()), size, 8) for k, (section, address, size) in enumerate(tls)]
    if data:
        sections.append(layout.OutputSection(".tdata", data[0].address, data[-1].address + data[-1].size
                                             - data[0].address, 0x403))
    loads = [layout.Load(0x10000, front - 0x10000, front - 0x10000, 0x4),
             layout.Load(start, after - start, after - start, 0x5), layout.Load(rw, 16, 16, 0x6)]
    inputs = found + data + more
    return layout.Layout(inputs, by_row, layout.Output(sections, loads, dict(symbols or {})), {},
                         {i.row for i in inputs})


def planned(base, probe):
    return layout.plan(base, probe, layout.pair(base.inputs, probe.inputs))


def where(plan, probe):
    """{function: (place, address, cause, detail)} of a plan."""
    return {probe.inputs[row].section[len(".text."):]: tuple(place) for row, place in plan.places.items()}


def unverified(base, probe, plan, moved=None):
    """{function: why} for each same-bytes section that `plan` moves with a cause that layout.py check does not verify
    (unshown) in a link that puts each .text input section where the plan puts it, and each other input section that
    `moved` ({row: address}) names at that address: each symbol of the probe link that lies in one of these sections
    moves with it."""
    pairing = layout.pair(base.inputs, probe.inputs)
    at = {**(moved or {}), **{row: place.address for row, place in plan.places.items()}}
    inputs = [i._replace(address=at.get(i.row, i.address)) for i in probe.inputs]
    symbols = {}
    for name, address in probe.output.symbols.items():
        holder = next((i for i in probe.inputs if i.row in at and i.address <= address < i.address + i.linked), None)
        symbols[name] = address if holder is None else at[holder.row] + address - holder.address
    occurrence = layout.occurrences(inputs)
    placement = {inputs[row].key + (occurrence[row],): layout.Placement(None, *place)
                 for row, place in plan.places.items()}
    new = probe._replace(inputs=inputs, placement=placement, output=probe.output._replace(symbols=symbols))
    found = {}
    for row, place in plan.places.items():
        if place.cause != "-":
            fn = inputs[row]
            why = layout.unshown(placement[fn.key + (occurrence[row],)], fn, base.inputs[pairing.partner[row]], base,
                                 new, pairing)
            if why is not None:
                found[fn.section[len(".text."):]] = why
    return found


def test_the_plan_fills_the_holes_largest_first_never_at_a_sections_own_address():
    base = link([text_input(0, "k0", 0x11000, 0x10), text_input(1, "changed", 0x11010, 0x40),
                 text_input(2, "k1", 0x11050, 0x10), text_input(3, "gone", 0x11060, 0x20),
                 text_input(4, "k2", 0x11080, 0x10)])
    probe = link(laid_out([("k0", 0x10, {}), ("changed", 0x40, {"content": "changed 2"}), ("k1", 0x10, {}),
                           ("k2", 0x10, {}), ("big", 0x60, {}), ("mid", 0x30, {}), ("zeta", 0x20, {}),
                           ("alpha", 0x20, {})]))
    # The holes are [0x11010, 0x11050) and [0x11060, 0x11080); the end starts at 0x11090.
    assert where(planned(base, probe), probe) == {
        "k0": ("kept", 0x11000, "-", "-"), "k1": ("kept", 0x11050, "-", "-"), "k2": ("kept", 0x11080, "-", "-"),
        "big": ("end", 0x11090, "-", "-"),  # first, and too large for each hole
        "changed": ("end", 0x110F0, "-", "-"),  # it fits the first hole only at its own base address
        "mid": ("hole", 0x11010, "-", "-"),
        "zeta": ("hole", 0x11060, "-", "-"),  # as large as alpha, and before it in the probe's map
        "alpha": ("end", 0x11130, "-", "-"),
    }


@pytest.mark.parametrize("size, fits", [(0xFE0, True), (0xFE4, False)], ids=["fits", "past"])
def test_the_script_keeps_the_next_segment_when_the_code_ends_below_its_page(size, fits):
    base = link([text_input(0, "grown", 0x11000, 0x10), text_input(1, "kept", 0x11010, 0x10)])
    probe = link(laid_out([("grown", size, {"content": "grown 2"}), ("kept", 0x10, {})]))
    plan = planned(base, probe)
    # BASE's next PT_LOAD starts at 0x12020, so .text may end at page_floor(0x12020) = 0x12000.
    assert plan.places[0][:2] == ("end", 0x11020)
    assert plan.places[0].address + size == (0x12000 if fits else 0x12004)
    pinned = "SECTIONS { .init_array 0x12020 : { } } INSERT BEFORE .fini_array;\n"
    assert plan.script.endswith("}\nINSERT AFTER .eh_frame;\n" + (pinned if fits else ""))
    assert plan.next_start == (0x12020 if fits else None)


@pytest.mark.parametrize("tail, fits", [(0x10, True), (0x30, False)], ids=["fits", "past"])
def test_what_follows_text_in_its_segment_counts_against_the_room_of_the_next_segment(tail, fits):
    # libc++'s __lcxx_override is an output section of code that lld puts after .text in the same PT_LOAD, wherever
    # .text ends: an example_fuzzer_cc_af whose .text fitted the room, and whose overrides did not, linked its code and
    # its data on one page.
    base = link([text_input(0, "grown", 0x11000, 0x10), text_input(1, "kept", 0x11010, 0x10)])
    probe = link(laid_out([("grown", 0xFC0, {"content": "grown 2"}), ("kept", 0x10, {})]))
    end = 0x11FD0  # the end of the probe's .text
    override = layout.Input(2, end, tail, "/opt/lib/libc++.a", ("/opt/lib/libc++.a", "new.o", "__lcxx_override"),
                            "new.o", "__lcxx_override", sha(b"override"), tail, 4)
    sections = probe.output.sections[:2] + [layout.OutputSection("__lcxx_override", end, tail, 0x6)] + \
        probe.output.sections[2:]
    loads = list(probe.output.loads)
    loads[1] = loads[1]._replace(filesz=loads[1].filesz + tail, memsz=loads[1].memsz + tail)
    probe = probe._replace(inputs=probe.inputs + [override],
                           output=layout.Output(sections, loads, probe.output.symbols))
    plan = planned(base, probe)
    # .text ends at 0x11020 + 0xfc0 = 0x11fe0, below page_floor(0x12020) = 0x12000, a multiple of the overrides'
    # alignment of 4 from the probe's end of .text, 0x11fd0: the overrides after it end at 0x11ff0 or 0x12010.
    assert plan.places[0].address + 0xFC0 == 0x11FE0
    assert plan.next_start == (0x12020 if fits else None)
    assert ("INSERT BEFORE .fini_array;" in plan.script) == fits


@pytest.mark.parametrize("size, text_end, fits", [(0xFC8, 0x11FE8, True), (0xFD8, 0x11FF8, False)],
                         ids=["fits", "past"])
def test_the_script_ends_text_where_the_tail_after_it_keeps_its_alignment(size, text_end, fits):
    # OSSV-675 review. The overrides after .text need an alignment of 16. In the probe link .text ends at P = 0x11010
    # + size, 8 bytes past a multiple of 16, and the overrides start 8 bytes later. The plan puts grown at the end,
    # from 0x11018: its planned end, 0x11018 + size, is a multiple of 16, so .text ends 8 bytes later, at E, a
    # multiple of 16 from P, and the overrides lie E - P bytes from where the probe link put them. The code then ends
    # at E plus the tail's 0x18 bytes: at page_floor(0x12030) = 0x12000, or 0x10 bytes past it.
    tail = [("__lcxx_override", 0x10, 16)]
    base = link([text_input(0, "grown", 0x11000, 0x8), text_input(1, "kept", 0x11008, 0x10)], tail=tail)
    probe = link(laid_out([("grown", size, {"content": "grown 2"}), ("kept", 0x10, {})]), tail=tail)
    text = next(s for s in probe.output.sections if s.name == ".text")
    plan = planned(base, probe)
    assert plan.places[0][:2] == ("end", 0x11018)
    assert (text_end - (text.addr + text.size)) % 16 == 0 and text_end == 0x11018 + size + 8
    assert f"    . = {hex(text_end)};\n  }}\n}}\nINSERT AFTER .eh_frame;\n" in plan.script
    assert plan.next_start == (0x12030 if fits else None)


@pytest.mark.parametrize("by_symbol", [False, True], ids=["definition", "symbol"])
def test_a_call_into_the_tail_after_text_is_tested_where_the_planned_end_puts_the_tail(by_symbol):
    # OSSV-675 review. k calls _Znwm, libc++'s operator new, which lld puts after .text in the output section
    # __lcxx_override, wherever .text ends; the link's objects define it, or the binary's symbol gives it. f grows by
    # 8 bytes, so in the probe link the tail lies at 0x111018, in reach of k's base call site 0x11024, as at the base
    # (0x111010). But the plan puts f at the end, from 0x111010 to 0x111038: .text ends there, and the tail then lies
    # at 0x111038, out of reach. k moves (lost), into the hole in front of its own base range.
    tail = [("__lcxx_override", 0x10, 4)]
    calls = [(1, 4, "_Znwm")]
    old = [text_input(0, "f", 0x11000, 0x20), text_input(1, "k", 0x11020, 0x10),
           text_input(2, "filler", 0x11030, 0xFFFE0)]
    new = laid_out([("f", 0x28, {"content": "f 2"}), ("k", 0x10, {}), ("filler", 0xFFFE0, {})])
    if by_symbol:
        base = link(old, calls, {"_Znwm": 0x111010}, tail=tail)
        probe = link(new, calls, {"_Znwm": 0x111018}, tail=tail)
    else:
        base, probe = (link(found, calls, tail=tail, defined={"_Znwm": (3, 0)}) for found in (old, new))
    assert (base.inputs[3].address, probe.inputs[3].address) == (0x111010, 0x111018)
    plan = planned(base, probe)
    assert where(plan, probe) == {"f": ("end", 0x111010, "-", "-"),
                                  "k": ("hole", 0x11000, "jal_reach", "offset=0x4;target=_Znwm;lost"),
                                  "filler": ("kept", 0x11030, "-", "-")}
    assert "    . = 0x111038;\n  }\n" in plan.script
    # layout.py check shows the cause in a link that puts the tail there.
    assert unverified(base, probe, plan, {3: 0x111038}) == {}


def test_a_plan_whose_read_only_data_grew_past_its_room_is_a_normal_link():
    base = link([text_input(0, "same", 0x11000, 0x10), text_input(1, "changed", 0x11010, 0x10)])
    probe = link(laid_out([("same", 0x10, {}), ("changed", 0x10, {"content": "changed 2"}), ("new", 0x8, {})],
                          start=0x12100), front=0x11100)
    plan = planned(base, probe)
    # The segment in front of .text now ends at 0x11100, 0xd00 bytes past BASE's 0x10400, whose room up to
    # page_floor(0x11000) was 0xc00.
    assert (plan.script, plan.growth, plan.next_start) == (None, (0xD00, 0xC00), None)
    assert where(plan, probe) == {"same": ("normal", 0x12100, "readonly_growth", "growth=3328;room=3072"),
                                  "changed": ("normal", 0x12110, "-", "-"), "new": ("normal", 0x12120, "-", "-")}


FILLER = 0x180000  # 1.5 MiB: past the reach of jal


def test_a_kept_caller_whose_relaxation_a_moved_target_would_change_moves_with_jal_reach():
    # c1 calls f in reach; c2, after the filler, calls g out of reach. f and g grow past their holes.
    calls = [(0, 4, "f"), (5, 4, "g")]
    base = link([text_input(0, "c1", 0x11000, 0x10), text_input(1, "f", 0x11010, 0x20),
                 text_input(2, "pad", 0x11030, 0x10), text_input(3, "g", 0x11040, 0x20),
                 text_input(4, "filler", 0x11060, FILLER), text_input(5, "c2", 0x11060 + FILLER, 0x10)],
                calls, {"f": 0x11010, "g": 0x11040})
    found = laid_out([("c1", 0x10, {}), ("f", 0x50, {"content": "f 2"}), ("pad", 0x10, {}),
                      ("g", 0x50, {"content": "g 2"}), ("filler", FILLER, {}), ("c2", 0x10, {})])
    probe = link(found, calls, {"f": found[1].address, "g": found[3].address})
    # At the end, after c2, f is out of c1's reach (lost) and g in c2's (gained): both callers move. The next round
    # keeps their base ranges free, for them to return, and puts them into the hole that f left; f and g go to the end
    # again, past c2's base range, where the callers' causes hold.
    assert where(planned(base, probe), probe) == {
        "c1": ("hole", 0x11010, "jal_reach", "offset=0x4;target=f;lost"),
        "f": ("end", 0x11070 + FILLER, "-", "-"),
        "pad": ("kept", 0x11030, "-", "-"),
        "g": ("end", 0x110C0 + FILLER, "-", "-"),
        "filler": ("kept", 0x11060, "-", "-"),
        "c2": ("hole", 0x11020, "jal_reach", "offset=0x4;target=g;gained"),
    }


def test_a_kept_function_whose_call_target_changed_address_moves_with_jal_reach():
    base = link([text_input(0, "caller", 0x11000, 0x10), text_input(1, "t", 0x11010, 0x10)], [(0, 8, "t")],
                {"t": 0x11010})
    # The link now resolves t to a definition outside .text, 4 MiB away.
    probe = link(laid_out([("caller", 0x10, {}), ("t", 0x10, {})]), [(0, 8, "t")], {"t": 0x400000})
    assert where(planned(base, probe), probe) == {"caller": ("end", 0x11020, "jal_reach", "offset=0x8;target=t;lost"),
                                                  "t": ("kept", 0x11010, "-", "-")}


def test_a_kept_callers_site_is_its_offset_less_the_bytes_relaxation_removed_in_front_of_it():
    # OSSV-675 review. lld relaxes c's call of k at 0x4 and removes 4 bytes, so c's call of t at 0x10 is at 0x11000 +
    # 0x10 - 4 = 0x1100c (BASE's delta 0x4). t, at 0x11100c at the base, lies 0x100000 bytes from there, one past
    # jal's reach, and lld keeps that call. In the new link t changed: in the hole that gone left, at 0x11030, t would
    # be in reach of 0x1100c, and lld would relax the call and shrink c, which the plan keeps. With the input offset
    # alone the site is 0x11010, from which t lies in reach at the base and in the hole: the plan put t there. From
    # the site lld uses, t goes to the end, out of reach as at the base.
    base = link([text_input(0, "c", 0x11000, 0x20), text_input(1, "k", 0x11020, 0x10),
                 text_input(2, "gone", 0x11030, 0x40), text_input(3, "filler", 0x11070, 0xFFF9C),
                 text_input(4, "t", 0x11100C, 0x10)], [(0, 4, "k"), (0, 0x10, "t")],
                {"k": 0x11020, "t": 0x11100C}, deltas={(0, 0x10): 4})
    found = laid_out([("c", 0x20, {}), ("k", 0x10, {}), ("filler", 0xFFF9C, {}), ("t", 0x10, {"content": "t 2"})])
    probe = link(found, [(0, 4, "k"), (0, 0x10, "t")], {"k": found[1].address, "t": found[3].address})
    assert where(planned(base, probe), probe) == {
        "c": ("kept", 0x11000, "-", "-"), "k": ("kept", 0x11020, "-", "-"), "filler": ("kept", 0x11070, "-", "-"),
        "t": ("end", 0x111010, "-", "-")}


def test_a_call_with_no_relax_relocation_or_no_known_site_is_not_tested():
    # OSSV-675 review. As in the test before, the link resolves t to a definition 4 MiB away. caller's call of t has
    # no R_RISCV_RELAX: lld never relaxes it, so caller does not change, and keeps its base address.
    base = link([text_input(0, "caller", 0x11000, 0x10), text_input(1, "t", 0x11010, 0x10)], [(0, 8, "t")],
                {"t": 0x11010}, norelax={(0, 8)})
    probe = link(laid_out([("caller", 0x10, {}), ("t", 0x10, {})]), [(0, 8, "t")], {"t": 0x400000},
                 norelax={(0, 8)})
    assert layout.call_tests(base, probe, layout.pair(base.inputs, probe.inputs)) == {}
    assert where(planned(base, probe), probe) == {"caller": ("kept", 0x11000, "-", "-"),
                                                  "t": ("kept", 0x11010, "-", "-")}
    # A call whose BASE line has no delta has no known base call site.
    base = link(base.inputs, [(0, 8, "t")], {"t": 0x11010}, deltas={(0, 8): None})
    probe = link(probe.inputs, [(0, 8, "t")], {"t": 0x400000})
    assert layout.call_tests(base, probe, layout.pair(base.inputs, probe.inputs)) == {}


def test_a_kept_section_whose_thread_local_access_is_relaxed_otherwise_moves_with_tls_reach():
    # near reads tw and far reads tv, thread-local variables of t.o. In the probe link 0x7f0 bytes of new thread-local
    # data lie in front of them: tw now lies 0x7ff bytes into the TLS segment, the most whose access lld relaxes, and
    # tv 0x800 bytes, one past it. far changes size wherever it goes, so it moves; near keeps its base address.
    base = link([text_input(0, "near", 0x11000, 0x10), text_input(1, "far", 0x11010, 0x10),
                 text_input(2, "k", 0x11020, 0x10)], [(0, 4, "tw", (3, 0xF)), (1, 4, "tv", (4, 0))],
                tls=[(".tdata.tw", 0x20000, 0x10), (".tdata.tv", 0x20010, 0x10)])
    probe = link(laid_out([("near", 0x10, {}), ("far", 0x10, {}), ("k", 0x10, {})]),
                 [(0, 4, "tw", (4, 0xF)), (1, 4, "tv", (5, 0))],
                 tls=[(".tdata.new", 0x20000, 0x7F0), (".tdata.tw", 0x207F0, 0x10), (".tdata.tv", 0x20800, 0x10)])
    assert where(planned(base, probe), probe) == {
        "near": ("kept", 0x11000, "-", "-"), "far": ("end", 0x11030, "tls_reach", "offset=0x4;target=tv;lost"),
        "k": ("kept", 0x11020, "-", "-")}


def test_the_placement_ends_when_each_round_moves_another_caller():
    # c3 calls c2, which calls c1, which calls f; kept pads keep their holes apart, and f grows to the end.
    names = ["c3", "p0", "c2", "p1", "c1", "p2", "f", "p3", "filler"]
    sizes = [0x40, 0x10, 0x30, 0x10, 0x20, 0x10, 0x10, 0x10, FILLER]
    calls = [(0, 4, "c2"), (2, 4, "c1"), (4, 4, "f")]
    rows = {"c2": 2, "c1": 4, "f": 6}
    old = laid_out([(name, size, {}) for name, size in zip(names, sizes)])
    new = laid_out([(name, 0x100, {"content": "f 2"}) if name == "f" else (name, size, {})
                    for name, size in zip(names, sizes)])
    base = link(old, calls, {name: old[row].address for name, row in rows.items()})
    probe = link(new, calls, {name: new[row].address for name, row in rows.items()})
    found = where(planned(base, probe), probe)
    # Each round moves the caller of the last mover: c1 loses f's reach, then c2 loses c1's, then c3 c2's.
    assert {name: found[name][2:] for name in ("c1", "c2", "c3", "f")} == {
        "c1": ("jal_reach", "offset=0x4;target=f;lost"), "c2": ("jal_reach", "offset=0x4;target=c1;lost"),
        "c3": ("jal_reach", "offset=0x4;target=c2;lost"), "f": ("-", "-")}
    assert all(found[name][0] == "end" for name in ("c1", "c2", "c3", "f"))
    assert all(found[name] == ("kept", old[k].address, "-", "-") for k, name in enumerate(names)
               if name in ("p0", "p1", "p2", "p3", "filler"))


def reach_case():
    """(base, probe) of the OSSV-675 review's case of a cause that a later round takes away: T at 0x11000, a filler,
    k at 0x111010 with a call of T at 0x4 (rows 0 to 2), and a second filler to 0x210f24; from k's base call site
    0x111014, T lies out of reach. In the probe link T grows to 0x40 bytes, and V, a new function of 0xd0 bytes,
    comes last."""
    old = [text_input(0, "T", 0x11000, 0x10), text_input(1, "filler", 0x11010, 0x100000),
           text_input(2, "k", 0x111010, 0x100), text_input(3, "filler2", 0x111110, 0xFFE14)]
    new = laid_out([("T", 0x40, {"content": "T 2"}), ("filler", 0x100000, {}), ("k", 0x100, {}),
                    ("filler2", 0xFFE14, {}), ("V", 0xD0, {})])
    return link(old, [(2, 4, "T")], {"T": 0x11000}), link(new, [(2, 4, "T")], {"T": 0x11000})


def test_a_section_that_a_round_moved_returns_when_its_cause_no_longer_holds():
    # OSSV-675 review. The first round puts V and then T at the end, where T, at 0x210ff4, lies in reach of k's base
    # call site: k moves (gained). The next round keeps k's base range free, and puts k at the end first, the
    # largest, and V and T after it: T, at 0x2110f4, lies out of reach again, as at the base, so k's cause no longer
    # holds. k returns to its base address, and nothing else moves.
    base, probe = reach_case()
    plan = planned(base, probe)
    # Each cause holds, and no section that moves lies in k's base range.
    assert unverified(base, probe, plan) == {}
    assert all(place.address + layout.taken(probe.inputs[row]) <= 0x111010 or place.address >= 0x111110
               for row, place in plan.places.items() if place.place != "kept")
    assert where(plan, probe) == {
        "T": ("end", 0x2110F4, "-", "-"), "filler": ("kept", 0x11010, "-", "-"), "k": ("kept", 0x111010, "-", "-"),
        "filler2": ("kept", 0x111110, "-", "-"), "V": ("end", 0x211024, "-", "-")}


def test_a_return_takes_the_cause_of_a_section_that_rested_on_a_call_into_it():
    # As in reach_case, but k2, with a call of k at 0x4, and a pad lie in front of k, in the first filler's place:
    # from k2's base call site 0x110e14, k lies in reach. The first round moves k (gained). The second puts k at the
    # end, out of k2's reach, so k2 moves (lost). The third puts k at the end again, and T after it, out of k's
    # reach: k's cause no longer holds, and k returns. Then k2's call of k is relaxed as at the base, and k2 returns.
    old = [text_input(0, "T", 0x11000, 0x10), text_input(1, "filler", 0x11010, 0xFFE00),
           text_input(2, "k2", 0x110E10, 0x10), text_input(3, "pad", 0x110E20, 0x1F0),
           text_input(4, "k", 0x111010, 0x100), text_input(5, "filler2", 0x111110, 0xFFE14)]
    new = laid_out([("T", 0x40, {"content": "T 2"}), ("filler", 0xFFE00, {}), ("k2", 0x10, {}), ("pad", 0x1F0, {}),
                    ("k", 0x100, {}), ("filler2", 0xFFE14, {}), ("V", 0xD0, {})])
    calls = [(2, 4, "k"), (4, 4, "T")]
    base = link(old, calls, {"T": 0x11000, "k": 0x111010})
    probe = link(new, calls, {"T": 0x11000, "k": new[4].address})
    plan = planned(base, probe)
    assert unverified(base, probe, plan) == {}
    assert where(plan, probe) == {
        "T": ("end", 0x2110F4, "-", "-"), "filler": ("kept", 0x11010, "-", "-"), "k2": ("kept", 0x110E10, "-", "-"),
        "pad": ("kept", 0x110E20, "-", "-"), "k": ("kept", 0x111010, "-", "-"),
        "filler2": ("kept", 0x111110, "-", "-"), "V": ("end", 0x211024, "-", "-")}


def test_a_section_that_the_check_link_moved_never_returns():
    # In reach_case, the check after a link moved k (append's forced). Were the plan to give k back its base address,
    # the check link would move it again, and the links would not end: k stays moved with that cause, although the
    # plan alone returns it, and its base range is free for other sections.
    base, probe = reach_case()
    pairing = layout.pair(base.inputs, probe.inputs)
    test, = layout.call_tests(base, probe, pairing)[2]
    assert where(layout.plan(base, probe, pairing, {2: test}), probe) == {
        "T": ("end", 0x211024, "-", "-"), "filler": ("kept", 0x11010, "-", "-"),
        "k": ("end", 0x210F24, "jal_reach", "offset=0x4;target=T;gained"), "filler2": ("kept", 0x111110, "-", "-"),
        "V": ("hole", 0x111010, "-", "-")}
    assert where(layout.plan(base, probe, pairing), probe)["k"] == ("kept", 0x111010, "-", "-")


LIB = {"file": "/work/lib.a", "member": "dup.o"}


@pytest.mark.parametrize("filler2, places", [
    (0xFFE14, [("end", 0x2110F4, "-", "-"), ("kept", 0x11010, "-", "-"), ("kept", 0x111010, "-", "-"),
               ("kept", 0x111090, "-", "-"), ("kept", 0x111110, "-", "-"), ("end", 0x211024, "-", "-")]),
    (0xFFD00, [("end", 0x210FE0, "-", "-"), ("kept", 0x11010, "-", "-"),
               ("end", 0x210E10, "jal_reach", "offset=0x4;target=T;gained"), ("end", 0x210E90, "repeated_key", "-"),
               ("kept", 0x111110, "-", "-"), ("end", 0x210F10, "-", "-")]),
], ids=["returns", "stays"])
def test_a_repeated_key_returns_whole_when_no_call_of_its_members_is_relaxed_otherwise(filler2, places):
    # As in reach_case, but k is two members of one key, side by side, and the first calls T. The first round moves
    # that member (gained), and the next moves the key as one block to the end, with V and T after it. With the first
    # filler2, T lies out of reach again: the member's cause no longer holds, and neither member has a call relaxed
    # otherwise, so the key returns whole, and one pattern keeps it. With the second, 0x114 bytes shorter, T lies in
    # reach: the member keeps its cause, and the other moves with it (repeated_key).
    old = [text_input(0, "T", 0x11000, 0x10), text_input(1, "filler", 0x11010, 0x100000),
           text_input(2, "dup", 0x111010, 0x80, **LIB), text_input(3, "dup", 0x111090, 0x80, content="dup 1", **LIB),
           text_input(4, "filler2", 0x111110, filler2)]
    new = laid_out([("T", 0x40, {"content": "T 2"}), ("filler", 0x100000, {}), ("dup", 0x80, LIB),
                    ("dup", 0x80, {"content": "dup 1", **LIB}), ("filler2", filler2, {}), ("V", 0xD0, {})])
    base, probe = link(old, [(2, 4, "T")], {"T": 0x11000}), link(new, [(2, 4, "T")], {"T": 0x11000})
    plan = planned(base, probe)
    assert unverified(base, probe, plan) == {}
    assert [tuple(plan.places[row]) for row in range(6)] == places
    assert plan.script.count('"/work/lib.a:dup.o"(.text.dup)') == 1
    # No other section lies in the key's base range.
    assert all(place.address + layout.taken(probe.inputs[row]) <= 0x111010 or place.address >= 0x111110
               for row, place in plan.places.items() if row not in (2, 3))


def test_a_repeated_key_that_did_not_sit_side_by_side_moves_as_one_block():
    base = link([text_input(0, "k0", 0x11000, 0x102, align=2), text_input(1, "gone", 0x11102, 0x1C, align=2),
                 text_input(2, "k1", 0x1111E, 0x22, align=2), text_input(3, "dup", 0x11140, 0xA, align=2, **LIB),
                 text_input(4, "k2", 0x1114A, 0x6, align=2),
                 text_input(5, "dup", 0x11150, 0x10, align=8, content="dup 1", **LIB),
                 text_input(6, "k3", 0x11160, 0x20)])
    probe = link(laid_out([("k0", 0x102, {"align": 2}), ("k1", 0x22, {"align": 2}), ("dup", 0xA, {"align": 2, **LIB}),
                           ("k2", 0x6, {"align": 2}), ("dup", 0x10, {"align": 8, "content": "dup 1", **LIB}),
                           ("k3", 0x20, {})]))
    plan = planned(base, probe)
    # The first hole, [0x11102, 0x1111e), holds the two members' 0x1a bytes, but not the 4 bytes of padding that
    # the second one's alignment needs after the first: the block goes to the end, 0x11180, with that padding.
    assert [tuple(plan.places[row]) for row in (2, 4)] == [("end", 0x11180, "repeated_key", "-"),
                                                          ("end", 0x11190, "repeated_key", "-")]
    assert [tuple(plan.places[row]) for row in (0, 1, 3, 5)] == [
        ("kept", 0x11000, "-", "-"), ("kept", 0x1111E, "-", "-"), ("kept", 0x1114A, "-", "-"),
        ("kept", 0x11160, "-", "-")]
    # One pattern names both members.
    assert plan.script.count('"/work/lib.a:dup.o"(.text.dup)') == 1
    assert '    . = 0x11180;\n    "/work/lib.a:dup.o"(.text.dup)\n    . = 0x111a0;\n  }\n' in plan.script


def test_a_repeated_key_that_sat_side_by_side_is_kept_with_one_pattern():
    base = link([text_input(0, "dup", 0x11000, 0x10, **LIB),
                 text_input(1, "dup", 0x11010, 0x10, content="dup 1", **LIB), text_input(2, "k", 0x11020, 0x10)])
    probe = link(laid_out([("dup", 0x10, LIB), ("dup", 0x10, {"content": "dup 1", **LIB}), ("k", 0x10, {})]))
    plan = planned(base, probe)
    assert [tuple(plan.places[row]) for row in range(3)] == [("kept", 0x11000, "-", "-"), ("kept", 0x11010, "-", "-"),
                                                            ("kept", 0x11020, "-", "-")]
    assert ('  {\n    . = 0x11000;\n    "/work/lib.a:dup.o"(.text.dup)\n    . = 0x11020;\n    "/work/a.o"(.text.k)\n'
            '    . = 0x11030;\n  }\n') in plan.script


def test_a_same_bytes_section_moves_when_its_base_address_does_not_meet_its_new_alignment():
    base = link([text_input(0, "meets", 0x11000, 0x10), text_input(1, "misses", 0x11010, 0x10)])
    probe = link(laid_out([("meets", 0x10, {"align": 16}), ("misses", 0x10, {"align": 32})]))
    assert where(planned(base, probe), probe) == {"meets": ("kept", 0x11000, "-", "-"),
                                                  "misses": ("end", 0x11020, "alignment", "align=32")}


def test_the_script_of_a_small_plan():
    base = link([text_input(0, "main", 0x11000, 0x20), text_input(1, "helper", 0x11020, 0x10, "/work/lib.a", "m.o"),
                 text_input(2, "odd", 0x11030, 0x8, section=".text.odd-name"), text_input(3, "grow", 0x11038, 0x8)])
    probe = link(laid_out([("main", 0x20, {}), ("helper", 0x10, {"file": "/work/lib.a", "member": "m.o"}),
                           ("odd", 0x8, {"section": ".text.odd-name"}), ("grow", 0x10, {"content": "grow 2"})]))
    plan = planned(base, probe)
    assert plan.script == (
        "SECTIONS\n"
        "{\n"
        "  .text 0x11000 :\n"
        "  {\n"
        "    . = 0x11000;\n"
        '    "/work/a.o"(.text.main)\n'
        "    . = 0x11020;\n"
        '    "/work/lib.a:m.o"(.text.helper)\n'
        "    . = 0x11030;\n"
        '    "/work/a.o"(".text.odd-name")\n'
        # The end starts at grow's own base address, 0x11038: it goes to the next address of its alignment.
        "    . = 0x1103c;\n"
        '    "/work/a.o"(.text.grow)\n'
        # .text ends where grow does: the probe link has nothing after .text in its PT_LOAD.
        "    . = 0x1104c;\n"
        "  }\n"
        "}\n"
        "INSERT AFTER .eh_frame;\n"
        "SECTIONS { .init_array 0x12040 : { } } INSERT BEFORE .fini_array;\n")
    assert plan.lines == {6: 0, 8: 1, 10: 2, 12: 3}


def test_the_script_refuses_a_file_name_it_cannot_quote():
    base = link([text_input(0, "f", 0x11000, 0x10, file='/work/we"ird.o')])
    probe = link(laid_out([("f", 0x10, {"file": '/work/we"ird.o'})]))
    with pytest.raises(layout.AppendError, match='we"ird'):
        planned(base, probe)


# ── the append mode: the links ───────────────────────────────────────────────────────────────────────────────────────

def relocatable(functions, variables=(), weak=(), ifunc=()):
    """A riscv64 relocatable ELF64 object of [(name, bytes, alignment, [(offset, called function)])]: a section
    .text.<name> for each, a global function <name> at its start, and for each call an R_RISCV_CALL_PLT relocation and
    an R_RISCV_RELAX at its offset, as clang writes a call that lld may relax, against a symbol of this object or an
    undefined one. A call (offset, symbol, type) gives that one relocation of that type instead, with no
    R_RISCV_RELAX, and (offset, symbol, type, addend) that addend too; a symbol of None is the symbol 0, which
    R_RISCV_RELAX and R_RISCV_ALIGN name. `variables` [(section, bytes, alignment, name)] adds a data section for
    each, with a global object <name> at its start: one whose name starts with .tdata or .tbss is thread-local
    (SHF_TLS, STT_TLS), and a .tbss one holds no bytes (SHT_NOBITS, of the size of `bytes`). The symbols that `weak`
    names are weak ones, defined or undefined, and the functions that `ifunc` names are of type STT_GNU_IFUNC."""
    defined = [name for name, _, _, _ in functions] + [name for _, _, _, name in variables]
    names = defined + sorted({call[1] for _, _, _, calls in functions for call in calls if call[1] is not None}
                             - set(defined))
    # name, type, flags, bytes, link, info, alignment, entry size
    sections = [(f".text.{name}", 1, 0x6, body, 0, 0, align, 0) for name, body, align, _ in functions]
    sections += [(section, 8 if section.startswith(".tbss") else 1,
                  0x403 if section.startswith((".tdata", ".tbss")) else 0x3, body, 0, 0, align, 0)
                 for section, body, align, _ in variables]
    strtab, symtab = b"\0", [bytes(24)]
    for k, name in enumerate(names):
        if k < len(defined):
            kind = (0xA if name in ifunc else 0x2) if k < len(functions) else 0x6 if sections[k][2] & 0x400 else 0x1
            symtab.append(struct.pack("<IBBHQQ", len(strtab), (2 if name in weak else 1) << 4 | kind, 0, k + 1, 0,
                                      len(sections[k][3])))
        else:
            symtab.append(struct.pack("<IBBHQQ", len(strtab), (2 if name in weak else 1) << 4, 0, 0, 0, 0))
        strtab += name.encode() + b"\0"
    symbols = len(sections) + sum(1 for *_, calls in functions if calls) + 1
    for k, (name, _, _, calls) in enumerate(functions):
        if calls:
            relocations = []
            for call in calls:
                symbol = 0 if call[1] is None else names.index(call[1]) + 1
                if len(call) == 2:
                    relocations += [(call[0], symbol, 19, 0), (call[0], 0, 51, 0)]
                else:
                    relocations.append((call[0], symbol, call[2], call[3] if len(call) > 3 else 0))
            body = b"".join(struct.pack("<QQq", offset, symbol << 32 | kind, addend)
                            for offset, symbol, kind, addend in relocations)
            sections.append((f".rela.text.{name}", 4, 0x40, body, symbols, k + 1, 8, 24))
    sections += [(".symtab", 2, 0, b"".join(symtab), symbols + 1, 1, 8, 24), (".strtab", 3, 0, strtab, 0, 0, 1, 0)]
    shstrtab = b"\0" + b"".join(s[0].encode() + b"\0" for s in sections) + b".shstrtab\0"
    sections.append((".shstrtab", 3, 0, shstrtab, 0, 0, 1, 0))
    data, headers = bytearray(64), [bytes(64)]
    for name, kind, flags, body, link_to, info, align, entsize in sections:
        headers.append(struct.pack("<IIQQQQIIQQ", shstrtab.index(b"\0" + name.encode() + b"\0") + 1, kind, flags, 0,
                                   len(data), len(body), link_to, info, align, entsize))
        data += body
    shoff = len(data)
    data += b"".join(headers)
    data[:64] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + struct.pack(
        "<HHIQQQIHHHHHH", 1, 0xF3, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), len(headers) - 1)
    return bytes(data)


def executable_of(sections, loads, symbols):
    """A riscv64 ELF64 executable of the output sections [(name, address, size, flags)] (SHT_NOBITS, with no bytes
    in the file), the PT_LOAD segments [(address, size, flags)] and the global functions {name: address}."""
    strtab, symtab = b"\0", [bytes(24)]
    for name, address in sorted(symbols.items()):
        symtab.append(struct.pack("<IBBHQQ", len(strtab), 0x12, 0, 2, address, 0))
        strtab += name.encode() + b"\0"
    # name, type, flags, address, bytes, size (None: that of the bytes), link, info, alignment, entry size
    entries = [(name, 8, flags, address, b"", size, 0, 0, 4, 0) for name, address, size, flags in sections]
    entries += [(".symtab", 2, 0, 0, b"".join(symtab), None, len(entries) + 2, 1, 8, 24),
                (".strtab", 3, 0, 0, strtab, None, 0, 0, 1, 0)]
    shstrtab = b"\0" + b"".join(e[0].encode() + b"\0" for e in entries) + b".shstrtab\0"
    entries.append((".shstrtab", 3, 0, 0, shstrtab, None, 0, 0, 1, 0))
    data = bytearray(64 + 56 * len(loads))
    for k, (vaddr, size, flags) in enumerate(loads):
        struct.pack_into("<IIQQQQQQ", data, 64 + 56 * k, 1, flags, 0, vaddr, vaddr, size, size, 0x1000)
    headers = [bytes(64)]
    for name, kind, flags, address, body, size, link_to, info, align, entsize in entries:
        headers.append(struct.pack("<IIQQQQIIQQ", shstrtab.index(b"\0" + name.encode() + b"\0") + 1, kind, flags,
                                   address, len(data), len(body) if size is None else size, link_to, info, align,
                                   entsize))
        data += body
    shoff = len(data)
    data += b"".join(headers)
    data[:64] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0xF3, 1, 0, 64, shoff, 0, 64, 56, len(loads), 64, len(headers), len(headers) - 1)
    return bytes(data)


def fake_linker(cwd, ro_end=0x10300, misplace=None, extra_load=False, backward=None, far=None, grown=None,
                far_once=None, unrelaxed=None, hidden=(), made=None, relaxed=None):
    """The commands of the append mode (layout.run), with a stand-in for the compiler driver and lld, in `cwd`. For
    -###, the linker's line. Else a link of the objects and archives the command names: it lays out their .text
    sections one after another in input order, or as an append script puts them (each pattern's sections from the
    address before it, .text up to at least the address the script gives last, and the next PT_LOAD at the address
    the script gives), then their thread-local data sections (SHF_TLS: the .tdata ones before the .tbss ones, each in
    input order) in the output sections .tdata and .tbss, and writes lld's map (-Wl,-Map=) and an executable (-o).
    The read-only segment in front of .text ends at `ro_end`. Each function takes its input size, less the bytes that
    `relaxed` ({function: bytes}) names, which lld's relaxation removes in every link. In a link with a script:
    `misplace` names a function whose map line it puts 0x10 bytes further, `extra_load` adds a PT_LOAD, `backward`
    makes it fail as lld does when the script's line `backward` moves the location counter backward, `far`
    ({function: address}) puts symbols elsewhere, `far_once` the same in the first such link only, and `grown`
    ({function: bytes}) gives functions more linked bytes in the map. In every link, `unrelaxed` ({function: bytes})
    gives functions more linked bytes, in the map and before what follows them, as lld does for an access it no
    longer relaxes wherever .text puts the function; a script's address below the end of what came before it then
    fails as lld fails. The executable has no global symbol for the functions `hidden` names, as lld writes a symbol
    of hidden visibility as a local one, and it has the symbols `made` ({name: address}) that the linker makes, which
    no object defines."""
    extra = unrelaxed or {}
    scripted = []

    def run(words):
        if "-###" in words:
            return 0, ' "/usr/bin/clang-20" "-cc1"\n "/usr/bin/ld.lld" "-o" "a.out" "--wrap=getenv" "main.o"\n'
        found = []  # (pattern's file, the map's name, section, size, alignment)
        tls = []  # (the map's name, section, size, alignment)
        for word in words[1:]:
            if word.endswith(".o"):
                members = [(word, word, (cwd / word).read_bytes())]
            elif word.endswith(".a"):
                members = [(f"{word}:{name}", f"{word}({name})", bytes(body))
                           for name, body in layout.ar_members((cwd / word).read_bytes(), word)]
            else:
                continue
            for file, named, data in members:
                sections = layout.Elf(data, word).sections
                found += [(file, named, s.name, s.size, s.align) for s in sections if layout.is_text(s.name)]
                tls += [(named, s.name, s.size, s.align) for s in sections if s.flags & 0x400]

        def linked(k):
            name = found[k][2][len(".text."):]
            return found[k][3] - (relaxed or {}).get(name, 0) + extra.get(name, 0)
        script = next((w[len("-Wl,-T,"):] for w in words if w.startswith("-Wl,-T,")), None)
        text = (ro_end + 0xFFF) // 0x1000 * 0x1000 + ro_end % 0x1000
        addresses, rw, closing = {}, None, None
        if script:
            scripted.append(script)
            lines = pathlib.Path(script).read_text()
            if backward:
                return 1, (f"ld.lld: error: {script}:{backward}: unable to move location counter (0x11400) backward "
                           "to 0x11340 for section '.text'\nclang: error: linker command failed with exit code 1\n")
            text = int(re.search(r"\.text (0x[0-9a-f]+) :", lines).group(1), 16)
            counter = None
            for match in re.finditer(r'\. = (0x[0-9a-f]+);\n +"([^"]*)"\(("?)([^")]*)\3\)', lines):
                address, file, _, section = match.groups()
                at = int(address, 16)
                if extra and counter is not None and at < counter:
                    number = lines.count("\n", 0, match.start()) + 1
                    return 1, (f"ld.lld: error: {script}:{number}: unable to move location counter ({hex(counter)}) "
                               f"backward to {hex(at)} for section '.text'\nclang: error: linker command failed "
                               "with exit code 1\n")
                for k, (pattern_file, _, name, _, align) in enumerate(found):
                    if (pattern_file, name) == (file, section):
                        at = (at + align - 1) // align * align
                        addresses[k], at = at, at + linked(k)
                counter = at
            pinned = re.search(r"\.init_array (0x[0-9a-f]+) :", lines)
            rw = int(pinned.group(1), 16) if pinned else None
            last = re.search(r"\. = (0x[0-9a-f]+);\n  }", lines)
            closing = int(last.group(1), 16) if last else None
        at = max([addresses[k] + linked(k) for k in addresses], default=text)
        for k, (_, _, _, _, align) in enumerate(found):
            if k not in addresses:
                at = (at + align - 1) // align * align
                addresses[k], at = at, at + linked(k)
        end = max([addresses[k] + linked(k) for k in addresses] + ([closing] if closing else []))
        thread_local, at = [], end  # (address, the map's name, section, size, alignment)
        for named, section, size, align in sorted(tls, key=lambda t: t[1].startswith(".tbss")):
            at = (at + align - 1) // align * align
            thread_local.append((at, named, section, size, align))
            at += size
        rw = rw or (at + 0xFFF) // 0x1000 * 0x1000 + at % 0x1000
        lines = [f"{text:>16x} {text:>16x} {end - text:>8x} {4:>5} .text\n"]
        for k in sorted(addresses, key=lambda k: (addresses[k], k)):
            _, named, section, _, align = found[k]
            shift = 0x10 if script and section == f".text.{misplace}" else 0
            more = (grown or {}).get(section[len(".text."):], 0) if script else 0
            lines.append(map_line(addresses[k] + shift, linked(k) + more, align, f"{named}:({section})"))
        lines += [map_line(address, size, align, f"{named}:({section})")
                  for address, named, section, size, align in thread_local]
        mapping = next(w[len("-Wl,-Map="):] for w in words if w.startswith("-Wl,-Map="))
        pathlib.Path(mapping).write_text("".join(lines))
        loads = [(0x10000, ro_end - 0x10000, 4), (text, end - text, 5), (rw, 16, 6)]
        if script and extra_load:
            loads.append((rw + 0x1000, 16, 6))
        outputs = [(".eh_frame", 0x10200, ro_end - 0x10200, 0x2), (".text", text, end - text, 0x6)]
        for name in (".tdata", ".tbss"):
            held = [t for t in thread_local if t[2].startswith(name)]
            if held:
                outputs.append((name, held[0][0], held[-1][0] + held[-1][3] - held[0][0], 0x403))
        pathlib.Path(words[words.index("-o") + 1]).write_bytes(executable_of(
            outputs + [(".init_array", rw, 8, 0x3), (".fini_array", rw + 8, 8, 0x3)], loads,
            {**(made or {}), **{found[k][2][len(".text."):]: addresses[k] for k in addresses
                                if found[k][2][len(".text."):] not in hidden}, **((far or {}) if script else {}),
             **((far_once or {}) if len(scripted) == 1 and script else {})}))
        return 0, ""
    return run


# R_RISCV_TPREL_HI20, R_RISCV_TPREL_ADD and R_RISCV_TPREL_LO12_I, each with R_RISCV_RELAX: a local-exec read of the
# thread-local variable tv, as clang compiles `return tv;`. lld relaxes it (removes the lui and the add, 8 bytes) when
# tv lies within 2 KiB of the start of the TLS segment, wherever .text puts the function.
TLS_READ = [(0x0, "tv", 29), (0x0, None, 51), (0x4, "tv", 32), (0x4, None, 51), (0x8, "tv", 30), (0x8, None, 51)]


def sources(new, tls=False, made=()):
    """The files of the link of the append tests: main.o (entry, which calls helper and grow, grow and tail), b.o
    (other) and lib.a, whose member m.o holds helper and small. In the new source, grow has other bytes and more of
    them, and small the same bytes at an alignment of 16. With `tls`, tail reads a thread-local variable (TLS_READ),
    in both sources: tv, which b.o defines in .tbss.tv, at the start of the TLS segment in the old source and after
    8 KiB of .tdata in the new one. entry also calls each function that `made` names, which no object defines: the
    first at 0x18, the next 8 bytes further. lld's relaxation removes bytes of entry and of tail (RELAXED)."""
    main = relocatable([("entry", b"\1" * (0x40 + RELAXED["entry"]), 4,
                         [(0x8, "helper"), (0x10, "grow")] + [(0x18 + 8 * k, name) for k, name in enumerate(made)]),
                        ("grow", b"\x99" * 0x50 if new else b"\2" * 0x30, 4, []),
                        ("tail", b"\3" * (0x20 + (RELAXED["tail"] if tls else 0)), 4, TLS_READ if tls else [])])
    member = relocatable([("helper", b"\5" * 0x18, 4, []), ("small", b"\6" * 0x8, 16 if new else 4, [])])
    variables = []
    if tls:
        variables = ([(".tdata.table", bytes(0x2000), 8, "table")] if new else []) + [(".tbss.tv", bytes(4), 4, "tv")]
    return {"main.o": main, "b.o": relocatable([("other", b"\4" * 0x60, 4, [])], variables),
            "lib.a": archive([("m.o", member)])}


# The bytes that lld's relaxation removes of entry (of its relaxed calls), and of tail with `tls` (TLS_READ, relaxed
# at the base), in every link of sources(): each takes 0x40 and 0x20 bytes there, and a link that no longer relaxes
# them gives them back (fake_linker's grown and unrelaxed), up to the input size, as lld does.
RELAXED = {"entry": 4, "tail": 8}


COMMAND = ["clang", "main.o", "b.o", "lib.a"]


def tree_entry(root, directory, map_text, binary, placement=None):
    """root/plain/fuzz/, the layout tree's entry of a link of the files in `directory`, as collect writes it."""
    entry = root / "plain" / "fuzz"
    entry.mkdir(parents=True)
    output = layout.output_rows(layout.Elf(binary, "fuzz"))
    found, calls = layout.describe(layout.read_map(map_text), layout.Objects(lambda f: (directory / f).read_bytes()),
                                   lambda f: f, {"getenv"}, layout.output_of(output, "fuzz"))
    (entry / "map").write_text(map_text)
    (entry / "sections.tsv").write_bytes(layout.tsv(layout.sections_rows(found)))
    (entry / "calls.tsv").write_bytes(layout.tsv(layout.calls_rows(calls)))
    (entry / "output.tsv").write_bytes(layout.tsv(output))
    (entry / "wraps").write_text("getenv\n")
    if placement is not None:
        (entry / "placement.tsv").write_bytes(placement)
    return entry


def append_setup(tmp_path, monkeypatch, tls=False, made=None, **fake):
    """The base layout tree tmp_path/base of a link of the old sources in tmp_path/old, and the new sources in
    tmp_path/work, the working directory, with fake_linker(**fake) in place of the commands (sources(new, tls,
    made)). The linker makes the symbols `made` ({name: address}) in every link, and its relaxation removes the bytes
    of RELAXED. Returns the base entry."""
    for name, new in (("old", False), ("work", True)):
        (tmp_path / name).mkdir()
        for file, data in sources(new, tls, made or {}).items():
            (tmp_path / name / file).write_bytes(data)
    relaxed = {name: n for name, n in RELAXED.items() if name != "tail" or tls}
    old = tmp_path / "old"
    assert fake_linker(old, made=made, relaxed=relaxed)(COMMAND + [f"-Wl,-Map={old / 'map'}", "-o",
                                                                   str(old / "fuzz")]) == (0, "")
    entry = tree_entry(tmp_path / "base", old, (old / "map").read_text(), (old / "fuzz").read_bytes())
    monkeypatch.chdir(tmp_path / "work")
    monkeypatch.setattr(layout, "run", fake_linker(tmp_path / "work", made=made, relaxed=relaxed, **fake))
    (tmp_path / "links").mkdir()
    return entry


def run_append(tmp_path, entry):
    return layout.main(["append", "--base", str(entry), "--work", str(tmp_path / "links"), "--script",
                        str(tmp_path / "script.ld"), "--placement", str(tmp_path / "placement.tsv"), "--wraps",
                        str(tmp_path / "wraps"), "--"] + COMMAND)


# The base link lays .text out from 0x11300: entry, grow, tail, other, helper and small, to 0x11410; its next PT_LOAD
# starts at 0x12410. grow, at 0x11340, now takes 0x50 bytes; small, at 0x11408, needs an alignment of 16. .text ends
# where grow, at the end, does: 0x11458.
SCRIPT_TEXT = """SECTIONS
{
  .text 0x11300 :
  {
    . = 0x11300;
    "main.o"(.text.entry)
    . = 0x11340;
    "lib.a:m.o"(.text.small)
    . = 0x11370;
    "main.o"(.text.tail)
    . = 0x11390;
    "b.o"(.text.other)
    . = 0x113f0;
    "lib.a:m.o"(.text.helper)
    . = 0x11408;
    "main.o"(.text.grow)
    . = 0x11458;
  }
}
INSERT AFTER .eh_frame;
SECTIONS { .init_array 0x12410 : { } } INSERT BEFORE .fini_array;
"""


def test_append_writes_the_script_the_placement_and_the_wraps(tmp_path, monkeypatch, capsys):
    entry = append_setup(tmp_path, monkeypatch)
    assert run_append(tmp_path, entry) == 0
    assert (tmp_path / "script.ld").read_text() == SCRIPT_TEXT
    assert (tmp_path / "wraps").read_text() == "getenv\n"
    assert [line.split("\t") for line in (tmp_path / "placement.tsv").read_text().splitlines()] == [
        ["main.o", "-", ".text.entry", "0", "main.o", "-", ".text.entry", "0", "kept", "0x11300", "-", "-"],
        ["lib.a", "m.o", ".text.small", "0", "lib.a", "m.o", ".text.small", "0", "hole", "0x11340", "alignment",
         "align=16"],
        ["main.o", "-", ".text.tail", "0", "main.o", "-", ".text.tail", "0", "kept", "0x11370", "-", "-"],
        ["b.o", "-", ".text.other", "0", "b.o", "-", ".text.other", "0", "kept", "0x11390", "-", "-"],
        ["lib.a", "m.o", ".text.helper", "0", "lib.a", "m.o", ".text.helper", "0", "kept", "0x113f0", "-", "-"],
        ["main.o", "-", ".text.grow", "0", "main.o", "-", ".text.grow", "0", "end", "0x11408", "-", "-"],
    ]
    assert capsys.readouterr().err == ("layout.py append: fuzz (plain): 4 kept, 1 moved (alignment: 1), 1 changed "
                                       "or new; the next segment stays at 0x12410\n")
    # The same inputs make the same script, byte for byte.
    assert run_append(tmp_path, entry) == 0
    assert (tmp_path / "script.ld").read_text() == SCRIPT_TEXT


def test_layout_check_verifies_what_append_writes(tmp_path, monkeypatch, capsys):
    entry = append_setup(tmp_path, monkeypatch)
    assert run_append(tmp_path, entry) == 0
    links = tmp_path / "links"
    tree_entry(tmp_path / "new", tmp_path / "work", (links / "check.map").read_text(), (links / "check").read_bytes(),
               (tmp_path / "placement.tsv").read_bytes())
    capsys.readouterr()
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines_with(lines, "plain/fuzz: 4 kept, 1 moved with a cause, 1 changed or new, 0 failed")
    assert lines_with(lines, "moved with a cause: small", "alignment (align=16)", "0x11408 -> 0x11340")
    assert lines_with(lines, "changed: grow", "0x11340 -> 0x11408")


def test_a_global_target_resolves_to_its_definition_in_the_links_objects(tmp_path):
    # caller calls f, which the member m.o of lib.a defines and the binary has no symbol for (a hidden one, which lld
    # writes as a local one); g, weak in w.o and global in s.o after it; h, weak in both; and stub, which no object
    # defines and the linker makes. The link lays them out in input order from 0x11300: caller (row 0), w.o's g and h
    # (1, 2), s.o's g and h (3, 4), and f (5).
    calls = [(0x0, "f"), (0x8, "g"), (0x10, "h"), (0x18, "stub")]
    files = {"main.o": relocatable([("caller", b"\1" * 0x20, 4, calls)]),
             "w.o": relocatable([("g", b"\2" * 0x8, 4, []), ("h", b"\3" * 0x8, 4, [])], weak={"g", "h"}),
             "s.o": relocatable([("g", b"\4" * 0x8, 4, []), ("h", b"\5" * 0x8, 4, [])], weak={"h"}),
             "lib.a": archive([("m.o", relocatable([("f", b"\6" * 0x8, 4, [])]))])}
    for file, data in files.items():
        (tmp_path / file).write_bytes(data)
    words = ["clang", *files, f"-Wl,-Map={tmp_path / 'map'}", "-o", str(tmp_path / "fuzz")]
    assert fake_linker(tmp_path, hidden={"f"}, made={"stub": 0x12000})(words) == (0, "")
    entry = tree_entry(tmp_path / "tree", tmp_path, (tmp_path / "map").read_text(), (tmp_path / "fuzz").read_bytes())
    # The global g wins over the weak one before it, and of two weak h the first in the map's order. Each call has
    # R_RISCV_RELAX, and lld relaxes each, all in jal's reach: 4 bytes more lie in front of each call than of the one
    # before it.
    assert [line.split("\t") for line in (entry / "calls.tsv").read_text().splitlines()] == [
        ["0", "0x0", "call", "1", "0x0", "global", "f", "0x0", "5", "0x0"],
        ["0", "0x8", "call", "1", "0x4", "global", "g", "0x0", "3", "0x0"],
        ["0", "0x10", "call", "1", "0x8", "global", "h", "0x0", "2", "0x0"],
        ["0", "0x18", "call", "1", "0xc", "global", "stub", "0x0", "-", "-"]]
    tree = layout.read_layout(str(entry))
    assert "f" not in tree.output.symbols
    assert [layout.target_address(call, tree) for call in tree.calls[0]] == [0x11340, 0x11330, 0x11328, 0x12000]


def test_each_line_gives_the_bytes_that_relaxation_removed_in_front_of_it():
    # OSSV-675 review. lld 20's relax() walks the relocations of a section in offset order, and each is at the
    # section's address plus its offset, less the bytes removed in front of it (delta). c is at 0x11000. Its call of k
    # at 0x0 is in jal's reach: lld removes 4 bytes. Its R_RISCV_ALIGN at 0xc has 12 bytes of nops for an alignment
    # of 16 (the next power of two at or above 12 + 2) and is at 0x11008: the 4 nops past 0x11010 go. Its call of t at
    # 0x20, at 0x11018, is in reach and goes too. Its call of t at 0x30 has no R_RISCV_RELAX (relax 0). lld removes
    # 12 bytes of c in all, whose 0x40 bytes take 0x34. In k, nothing lies in front of its call.
    objects = {"main.o": relocatable([("c", bytes(0x40), 4, [(0x0, "k"), (0xC, None, 43, 12), (0x20, "t"),
                                                            (0x30, "t", 19)]),
                                      ("k", bytes(0x10), 4, [(0x4, "t")])])}
    text = map_line(0x11000, 0x34, 4, "main.o:(.text.c)") + map_line(0x11034, 0xC, 4, "main.o:(.text.k)")
    _, calls = layout.describe(layout.read_map(text), layout.Objects(objects.__getitem__), lambda f: f, set(),
                               layout.Output([], [], {"t": 0x11100}))
    assert [(c.row, c.offset, c.relax, c.delta) for c in calls] == [(0, 0x0, True, 0), (0, 0x20, True, 8),
                                                                   (0, 0x30, False, 12), (1, 0x4, True, 0)]
    # With t 1 MiB further, c's call of t at 0x20 keeps its 8 bytes: 4 bytes fewer lie in front of the next call.
    _, calls = layout.describe(layout.read_map(text), layout.Objects(objects.__getitem__), lambda f: f, set(),
                               layout.Output([], [], {"t": 0x211100}))
    assert [c.delta for c in calls] == [0, 8, 8, 0]


def test_an_undefined_weak_target_is_at_0_and_an_ifunc_has_no_address(tmp_path):
    # OSSV-675 review. caller calls w, a weak function that no object defines and the binary does not name: lld gives
    # it the value 0 in a static link, in jal's reach of 0x11300. It calls k, and i, an ifunc of i.o (STT_GNU_IFUNC),
    # whose call goes through lld's PLT entry, which no tree holds: from that call on, the bytes that relaxation
    # removed in front of each line are not known.
    calls = [(0x0, "w"), (0x8, "k"), (0x10, "i"), (0x18, "k")]
    files = {"main.o": relocatable([("caller", b"\1" * 0x20, 4, calls), ("k", b"\2" * 0x8, 4, [])], weak={"w"}),
             "i.o": relocatable([("i", b"\3" * 0x8, 4, [])], ifunc={"i"})}
    for file, data in files.items():
        (tmp_path / file).write_bytes(data)
    words = ["clang", *files, f"-Wl,-Map={tmp_path / 'map'}", "-o", str(tmp_path / "fuzz")]
    assert fake_linker(tmp_path)(words) == (0, "")
    entry = tree_entry(tmp_path / "tree", tmp_path, (tmp_path / "map").read_text(), (tmp_path / "fuzz").read_bytes())
    assert [line.split("\t") for line in (entry / "calls.tsv").read_text().splitlines()] == [
        ["0", "0x0", "call", "1", "0x0", "weak", "w", "0x0", "-", "-"],
        ["0", "0x8", "call", "1", "0x4", "global", "k", "0x0", "1", "0x0"],
        ["0", "0x10", "call", "1", "-", "ifunc", "i", "0x0", "-", "-"],
        ["0", "0x18", "call", "1", "-", "global", "k", "0x0", "1", "0x0"]]
    tree = layout.read_layout(str(entry))
    assert "i" in tree.output.symbols
    assert [layout.target_address(call, tree) for call in tree.calls[0]] == [0, 0x11320, None, 0x11320]
    # A weak symbol that the binary names (one the linker makes) is where the binary puts it.
    named = tree._replace(output=tree.output._replace(symbols={**tree.output.symbols, "w": 0x12000}))
    assert layout.target_address(tree.calls[0][0], named) == 0x12000


def test_a_map_line_whose_section_the_objects_do_not_tell_has_no_bytes_and_no_calls():
    # OSSV-675 review. An archive of two members named a.o, REAL and STORES, whose .text.__rust_alloc sections take 8
    # and 26 bytes, and a map that holds the second one's alone, a line of 0x1a bytes: lld's map lists the members it
    # took in the order it took them, so the line could be either member's. It gets no sha256 (it moves as a changed
    # function), the map's size and alignment, and none of REAL's calls.
    lib = archive([("a.o", REAL), ("a.o", STORES)])
    text = map_line(0x11000, 0x1A, 2, "/work/lib.a(a.o):(.text.__rust_alloc)")
    inputs, calls = layout.describe(layout.read_map(text), layout.Objects({"/work/lib.a": lib}.__getitem__),
                                    lambda f: f, set(), layout.Output([], [], {}))
    assert [(i.sha256, i.size, i.align) for i in inputs] == [("", 0x1A, 2)] and calls == []
    # An object with two sections .text.f, the first with a call.
    two = {"/work/two.o": relocatable([("f", b"\1" * 8, 4, [(0x0, "g")]), ("f", b"\2" * 0x10, 4, [])])}

    def described(*lines):
        text = "".join(map_line(address, size, 4, "/work/two.o:(.text.f)") for address, size in lines)
        return layout.describe(layout.read_map(text), layout.Objects(two.__getitem__), lambda f: f, set(),
                               layout.Output([], [], {}))

    # The map takes one of them (--gc-sections took the other): it could be either.
    inputs, calls = described((0x11000, 8))
    assert [(i.sha256, i.size) for i in inputs] == [("", 8)] and calls == []
    # It takes both: the k-th line is the k-th section, as before.
    inputs, calls = described((0x11000, 8), (0x11008, 0x10))
    assert [(i.sha256, i.size) for i in inputs] == [(sha(b"\1" * 8), 8), (sha(b"\2" * 0x10), 0x10)]
    assert [(c.row, c.offset, c.target) for c in calls] == [(0, 0x0, "g")]
    # A line longer than its section is not that section (lld only removes bytes): the first one can be told no more.
    inputs, calls = described((0x11000, 0x10), (0x11010, 8))
    assert [(i.sha256, i.size) for i in inputs] == [("", 0x10), (sha(b"\2" * 0x10), 0x10)] and calls == []


def test_append_links_normally_when_the_read_only_data_grew_past_its_room(tmp_path, monkeypatch, capsys):
    # The new link's read-only segment ends at 0x11100: 0xe00 bytes past the base's 0x10300, whose room up to
    # page_floor(0x11300) was 0xd00.
    entry = append_setup(tmp_path, monkeypatch, ro_end=0x11100)
    (tmp_path / "script.ld").write_text("an old script\n")
    assert run_append(tmp_path, entry) == 0
    assert not (tmp_path / "script.ld").exists()
    assert capsys.readouterr().err == (
        "layout.py append: fuzz (plain): the read-only data in front of .text grew by 3584 bytes, past its room of "
        "3328 bytes, so this is a normal link, and every function whose code did not change moves (readonly_growth)\n")
    rows = [line.split("\t") for line in (tmp_path / "placement.tsv").read_text().splitlines()]
    assert [row[2] for row in rows] == [".text.entry", ".text.grow", ".text.tail", ".text.other", ".text.helper",
                                        ".text.small"]
    assert {row[8] for row in rows} == {"normal"} and rows[0][9] == "0x12100"
    assert [row[10:] for row in rows] == [["readonly_growth", "growth=3584;room=3328"]] + [["-", "-"]] + [
        ["readonly_growth", "growth=3584;room=3328"]] * 4
    # layout check verifies the cause on the normal link's tree.
    links = tmp_path / "links"
    tree_entry(tmp_path / "new", tmp_path / "work", (links / "probe.map").read_text(), (links / "probe").read_bytes(),
               (tmp_path / "placement.tsv").read_bytes())
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 0
    assert lines_with(capsys.readouterr().out.splitlines(), "plain/fuzz: 0 kept, 5 moved with a cause")


@pytest.mark.parametrize("fake, named", [
    ({"misplace": "tail"}, ["tail (main.o)", "0x11370", "0x11380", "defect"]),
    ({"extra_load": True}, ["PT_LOAD 3", "0x13410"]),
    # Line 7 of SCRIPT_TEXT is the address of small: entry, on the line before, took more room than it had.
    ({"backward": 7}, ["unable to move location counter", "line 7", "entry (main.o)"]),
], ids=["kept-elsewhere", "pt-load-count", "backward"])
def test_append_exits_1_when_the_check_link_is_not_what_the_plan_asks(tmp_path, monkeypatch, capsys, fake, named):
    entry = append_setup(tmp_path, monkeypatch, **fake)
    assert run_append(tmp_path, entry) == 1
    error = capsys.readouterr().err
    assert error.splitlines()[-1].startswith("layout.py append: fuzz (plain): ")
    assert all(word in error for word in named), error
    assert not (tmp_path / "placement.tsv").exists()


# A call of a function that an object defines reaches it where the check link's map puts it, so a check link can
# relax such a call otherwise than the plan only when the call names a symbol that the linker makes (as --defsym=
# stub=grow does): stub, at grow's address in the base and the probe links, and once, at helper's.
@pytest.mark.parametrize("fake, placed_rows", [
    # In the check link, entry takes 4 bytes more, because its call of stub, which the link puts 4 MiB away, is no
    # longer in jal's reach: entry moves with jal_reach, and the plan runs again. grow, where the probe link has stub,
    # keeps away from entry's base call site, so that entry's cause holds.
    ({"made": {"stub": 0x11340}, "far": {"stub": 0x400000}, "grown": {"entry": 4}},
     [[".text.small", "hole", "0x11300", "alignment", "align=16"], [".text.tail", "kept", "0x11370", "-", "-"],
      [".text.other", "kept", "0x11390", "-", "-"], [".text.helper", "kept", "0x113f0", "-", "-"],
      [".text.grow", "end", "0x11408", "-", "-"],
      [".text.entry", "end", "0x11458", "jal_reach", "offset=0x18;target=stub;lost"]]),
    # The first check link also puts once far, and entry moves for its call of once; in the second, only the call of
    # stub is relaxed otherwise, and placement.tsv gives that one.
    ({"made": {"once": 0x113F0, "stub": 0x11340}, "far": {"stub": 0x400000}, "far_once": {"once": 0x400000},
      "grown": {"entry": 4}},
     [[".text.grow", "hole", "0x11300", "-", "-"], [".text.small", "hole", "0x11350", "alignment", "align=16"],
      [".text.tail", "kept", "0x11370", "-", "-"], [".text.other", "kept", "0x11390", "-", "-"],
      [".text.helper", "kept", "0x113f0", "-", "-"],
      [".text.entry", "end", "0x11408", "jal_reach", "offset=0x20;target=stub;lost"]]),
], ids=["lost", "another-call"])
def test_append_moves_a_kept_section_whose_call_the_check_link_relaxes_otherwise(tmp_path, monkeypatch, capsys, fake,
                                                                                 placed_rows):
    entry = append_setup(tmp_path, monkeypatch, **fake)
    assert run_append(tmp_path, entry) == 0
    rows = [line.split("\t") for line in (tmp_path / "placement.tsv").read_text().splitlines()]
    assert [[row[2]] + row[8:] for row in rows] == placed_rows
    assert capsys.readouterr().err.endswith("fuzz (plain): 3 kept, 2 moved (jal_reach: 1, alignment: 1), 1 changed "
                                            "or new; the next segment stays at 0x12410\n")
    links = tmp_path / "links"
    tree_entry(tmp_path / "new", tmp_path / "work", (links / "check.map").read_text(), (links / "check").read_bytes(),
               (tmp_path / "placement.tsv").read_bytes())
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 0
    assert lines_with(capsys.readouterr().out.splitlines(), "moved with a cause: entry", "jal_reach")


def test_append_links_when_a_kept_functions_thread_local_read_is_no_longer_relaxed(tmp_path, monkeypatch, capsys):
    # OSSV-675 testing. tail has the same bytes in both links and reads a thread-local variable. At the base lld
    # relaxed that read; in the new link, new thread-local data in front of the variable puts it more than 2 KiB into
    # the TLS segment, so lld keeps the lui and the add, and tail takes 8 bytes more in every link of the new inputs,
    # the probe link's included, wherever .text puts it. That is a change of the code, which the append mode must not
    # stop a link for (docs/build-contract.md: "The mode never stops a link for a change of the code"). On the real
    # toolchain at 76d299e2 the link stops: "unable to move location counter ... backward", "the check link cannot
    # move the location counter backward ... at ov_tls_get" (tests/fixtures/example with a __thread variable, farm
    # job farm/20261117t173804z-7d787b). tail must move, the functions around it keep their base addresses, and
    # layout check accepts the tree. The helpers may grow (tree_entry may have to write more of the tree); these
    # assertions are the contract.
    entry = append_setup(tmp_path, monkeypatch, tls=True, unrelaxed={"tail": 8})
    assert run_append(tmp_path, entry) == 0, capsys.readouterr().err
    rows = {row[2]: row[8:] for row in (line.split("\t") for line in
                                        (tmp_path / "placement.tsv").read_text().splitlines())}
    # At the base: entry 0x11300, tail 0x11370, other 0x11390, helper 0x113f0.
    assert rows[".text.entry"][:2] == ["kept", "0x11300"]
    assert rows[".text.other"][:2] == ["kept", "0x11390"]
    assert rows[".text.helper"][:2] == ["kept", "0x113f0"]
    assert rows[".text.tail"][0] != "kept"
    links = tmp_path / "links"
    tree_entry(tmp_path / "new", tmp_path / "work", (links / "check.map").read_text(), (links / "check").read_bytes(),
               (tmp_path / "placement.tsv").read_bytes())
    capsys.readouterr()
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 0
    assert lines_with(capsys.readouterr().out.splitlines(), "moved with a cause: tail")


def test_append_moves_a_kept_caller_whose_call_of_a_hidden_function_is_relaxed_otherwise(tmp_path, monkeypatch,
                                                                                         capsys):
    # OSSV-675 testing. f has hidden visibility (a library built with -fvisibility=hidden, or a function declared
    # hidden, as musl's internal functions are), so the output's symbol table, and so output.tsv, has no global symbol
    # for it: lld writes a hidden symbol as a local one. At the base, 1.25 MiB of filler lies between f and its caller
    # in c.o, so the call is out of jal's reach. In the new source f changes and grows, and goes to the end of .text,
    # right after caller: from caller's base call site, f is now in reach, lld relaxes the call, and caller takes 4
    # bytes less. caller must move with jal_reach, as it does when f is a global symbol (case (b) of c1), and layout
    # check must verify that cause. On the real toolchain at 76d299e2 the link stops instead: "LLVMFuzzerTestOneInput
    # (/work/example_fuzzer.o): the script keeps it at 0x12c4c with 128 bytes, and the check link puts it at 0x12c4c
    # with 132 bytes, and no call of it is relaxed otherwise: a defect of the append mode" (case (b) of c1 with ov_f
    # declared hidden, farm job farm/20261117t181743z-173fb2).
    def files(new):
        return {"main.o": relocatable([("f", b"\x99" * 0x50 if new else b"\2" * 0x30, 4, [])]),
                "filler.o": relocatable([("filler", b"\4" * 0x140000, 4, [])]),
                "c.o": relocatable([("caller", b"\3" * 0x20, 4, [(0x8, "f")])])}
    command = ["clang", "main.o", "filler.o", "c.o"]
    for name, new in (("old", False), ("work", True)):
        (tmp_path / name).mkdir()
        for file, data in files(new).items():
            (tmp_path / name / file).write_bytes(data)
    old = tmp_path / "old"
    assert fake_linker(old, hidden={"f"})(command + [f"-Wl,-Map={old / 'map'}", "-o", str(old / "fuzz")]) == (0, "")
    entry = tree_entry(tmp_path / "base", old, (old / "map").read_text(), (old / "fuzz").read_bytes())
    monkeypatch.chdir(tmp_path / "work")
    monkeypatch.setattr(layout, "run", fake_linker(tmp_path / "work", hidden={"f"}, grown={"caller": -4}))
    (tmp_path / "links").mkdir()
    code = layout.main(["append", "--base", str(entry), "--work", str(tmp_path / "links"), "--script",
                        str(tmp_path / "script.ld"), "--placement", str(tmp_path / "placement.tsv"), "--wraps",
                        str(tmp_path / "wraps"), "--"] + command)
    assert code == 0, capsys.readouterr().err
    rows = {row[2]: row[8:] for row in (line.split("\t") for line in
                                        (tmp_path / "placement.tsv").read_text().splitlines())}
    assert rows[".text.filler"][:2] == ["kept", "0x11330"]
    assert rows[".text.caller"][0] != "kept" and rows[".text.caller"][2:] == ["jal_reach",
                                                                              "offset=0x8;target=f;gained"]
    links = tmp_path / "links"
    tree_entry(tmp_path / "new", tmp_path / "work", (links / "check.map").read_text(), (links / "check").read_bytes(),
               (tmp_path / "placement.tsv").read_bytes())
    capsys.readouterr()
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 0
    assert lines_with(capsys.readouterr().out.splitlines(), "moved with a cause: caller", "jal_reach")


def test_append_names_the_call_it_cannot_test_when_the_check_link_changes_a_kept_section(tmp_path, monkeypatch,
                                                                                         capsys):
    # OSSV-675 review. caller calls i, an ifunc, whose call goes through lld's PLT entry, whose address no tree holds:
    # the append mode cannot test whether lld relaxes that call otherwise. When the check link gives caller 4 bytes
    # more (as when lld no longer relaxes the call), the link stops, and the error names that call, not a defect of
    # the mode.
    def files(new):
        return {"main.o": relocatable([("caller", b"\1" * 0x24, 4, [(0x8, "i")]),
                                       ("g", b"\x99" * 0x30 if new else b"\2" * 0x10, 4, [])]),
                "i.o": relocatable([("i", b"\3" * 0x8, 4, [])], ifunc={"i"})}
    command = ["clang", "main.o", "i.o"]
    for name, new in (("old", False), ("work", True)):
        (tmp_path / name).mkdir()
        for file, data in files(new).items():
            (tmp_path / name / file).write_bytes(data)
    old = tmp_path / "old"
    assert fake_linker(old, relaxed={"caller": 4})(command + [f"-Wl,-Map={old / 'map'}", "-o", str(old / "fuzz")]) \
        == (0, "")
    entry = tree_entry(tmp_path / "base", old, (old / "map").read_text(), (old / "fuzz").read_bytes())
    monkeypatch.chdir(tmp_path / "work")
    monkeypatch.setattr(layout, "run", fake_linker(tmp_path / "work", relaxed={"caller": 4}, grown={"caller": 4}))
    (tmp_path / "links").mkdir()
    code = layout.main(["append", "--base", str(entry), "--work", str(tmp_path / "links"), "--script",
                        str(tmp_path / "script.ld"), "--placement", str(tmp_path / "placement.tsv"), "--wraps",
                        str(tmp_path / "wraps"), "--"] + command)
    error = capsys.readouterr().err
    assert code == 1
    assert "caller (main.o)" in error and "offset 0x8 (i)" in error and "a defect of the append mode" not in error
    assert not (tmp_path / "placement.tsv").exists()


@pytest.mark.parametrize("words", [["--help"], ["collect", "--help"], ["check", "--help"], ["wraps", "--help"],
                                   ["append", "--help"]])
def test_each_command_has_help(words):
    assert subprocess.run([sys.executable, str(SCRIPT)] + words, capture_output=True).returncode == 0
