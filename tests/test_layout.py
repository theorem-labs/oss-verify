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
# shim-forwards.o's __rust_dealloc calls __rdl_dealloc. This copy names that symbol __real_dalloc (as long a name), so
# that in a link that wraps dalloc the call reaches dalloc itself.
REAL = FORWARDS.replace(b"\0__rdl_dealloc\0", b"\0__real_dalloc\0")
WRAPS = ("__rdl_alloc", "dalloc")
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


# Two members named a.o, an odd-sized member before them, and a member whose name is in the // table.
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
        (0x11028, 0x8, 2, "/work/lib/libshim.a(a.o):(.text.__rust_realloc)"),
        (0x11030, 0x2e, 2, "/work/lib/libshim.a(shim-local-access.o):(.text.__rust_alloc)"),
        (0x11060, 0x20, 2, "/work/lib/libshim.a(shim-local-access.o):(.text._RNvCsdMW3fuGnryS_17shim_local_access5parse)"),
        (0x11080, 0x8, 2, f"{copy}:(.text.__rust_alloc)"),
        (0x11088, 0xc, 2, f"{copy}:(.text._RNvCsgdEkaKC4q9e_15shim_local_call7rounded)"),
        (0x11094, 0x8, 4, "/work/obj/shim-rustc-v0.o:(.text._RNvCs6UdHf40Qw6p_7___rustc12___rust_alloc)"),
        (0x12000, 0x40, 1, "/work/lib/libshim.a(shim-local-access.o):(.bss._RNvCsdMW3fuGnryS_17shim_local_access4POOL)"),
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
    """sections.tsv and calls.tsv of out_tree's record, from the test's own reading of its objects."""
    objects = {("/work/lib/libshim.a", "a.o"): [REAL, STORES],
               ("/work/lib/libshim.a", "shim-local-access.o"): [LOCAL_ACCESS],
               (f"{copies}/2-shim-local-call.o", None): [local_call], ("/work/obj/shim-rustc-v0.o", None): [V0]}
    readings = {(where, i): read_object(data) for where, datas in objects.items() for i, data in enumerate(datas)}
    sections, located, rows, seen = [], {}, {}, collections.Counter()
    for _, size, align, text in map_lines(copies):
        if text.startswith("<internal>"):
            continue
        at = text.rindex(":(")
        where, section = text[:at], text[at + 2:-1]
        file, member = (where[:where.index("(")], where[where.index("(") + 1:-1]) if where.endswith(")") else (
            where, None)
        k = seen[(file, member, section)]
        seen[(file, member, section)] += 1
        found = [(i, index) for i in range(len(objects[(file, member)]))
                 for index, s in readings[((file, member), i)][0].items() if s[0] == section]
        digest = ""
        if k < len(found):
            i, index = found[k]
            _, _, body, size, align = readings[((file, member), i)][0][index]
            digest = "" if body is None else sha(body)
            located[len(sections)] = ((file, member), i, index, section)
            rows[((file, member), i, index)] = len(sections)
        key_file = ORIGINAL if file.endswith("/2-shim-local-call.o") else file
        sections.append(f"{file}\t{key_file}\t{member or '-'}\t{section}\t{digest}\t{size}\t{align}\n")
    calls = []
    for row, (where, i, index, section) in sorted(located.items()):
        if not section.startswith(".text"):
            continue
        _, symbols, relocations = readings[(where, i)]
        for offset, info, addend in relocations.get(index, []):
            if info & 0xFFFFFFFF not in (18, 19):
                continue
            name, value, symbol_info, shndx = symbols[info >> 32]
            if symbol_info >> 4 == 0 or symbol_info & 0xF == 3:
                calls.append(f"{row}\t0x{offset:x}\tlocal\t{rows.get((where, i, shndx), '-')}\t0x{value + addend:x}\n")
            else:
                if name in WRAPS:
                    name = "__wrap_" + name
                elif name.startswith("__real_") and name[7:] in WRAPS:
                    name = name[7:]
                calls.append(f"{row}\t0x{offset:x}\tglobal\t{name}\t0x{addend:x}\n")
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
    # Every line's address, and the alignment in decimal.
    assert lines[0] == layout.MapLine(0x10824, 0x24, 4, "/work/build/lib/plain/curl-fuzz_bufq/lib/liboft.a",
                                      "harness.o", ".rodata._Z16fuzz_handle_bufqP18FuzzedDataProvider")
    assert layout.MapLine(0x704E0, 0x30, 16, "/tmp/ov/adapter.o", None, ".bss..L_MergedGlobals.2") in lines
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
    # The k-th line of a (file, member, section) is the k-th such member's section: shim-forwards.o's 8-byte
    # __rust_alloc, then shim-stores.o's of 26 bytes. The input size and alignment are the object's, not the map's.
    assert [r[5:] for r in rows[1:3]] == [["8", "2"], ["26", "2"]]
    assert rows[10][4:] == ["", "64", "1"]  # .bss: SHT_NOBITS
    assert rows[11][4:] == ["", "16", "8"]  # COMMON: no such section; the map's size and alignment
    assert [r[1] for r in rows[7:9]] == [ORIGINAL, ORIGINAL]  # the allocation-failure copy, by its original
    assert [r[1] for r in rows[:7]] == [r[0] for r in rows[:7]]
    calls = [line.split("\t") for line in (entry / "calls.tsv").read_text().splitlines()]
    assert ["1", "0x0", "global", "__wrap___rdl_alloc", "0x0"] in calls  # a wrapped function
    assert ["3", "0x0", "global", "dalloc", "0x0"] in calls  # __real_dalloc
    assert ["4", "0x0", "global", "__rdl_realloc", "0x0"] in calls
    assert ["5", "0x8", "local", "6", "0x0"] in calls and ["5", "0x16", "local", "-", "0x0"] in calls
    assert ["7", "0x0", "local", "8", "0x0"] in calls
    assert not [c for c in calls if c[0] == "2"]


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
    for path in sorted(record.parent.rglob("*"), reverse=True):
        path.rmdir() if path.is_dir() else path.unlink()
    record.parent.rmdir()


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


# ── pairing ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def inputs(*specs):
    """[Input] of (file, member, section, content, size): the sha256 is that of `content`."""
    return [layout.Input(row, 0x11000 + 0x100 * row, size, file, (file, member or "-", section), member, section,
                         sha(content.encode()) if content else "", size, 4)
            for row, (file, member, section, content, size) in enumerate(specs)]


def test_pairing_by_key():
    base = inputs(("a.o", None, ".text.f", "f", 8), ("a.o", None, ".text.g", "g", 12), ("a.o", None, ".rodata.r", "r", 4))
    new = inputs(("a.o", None, ".rodata.r", "r", 4), ("a.o", None, ".text.g", "g", 12), ("a.o", None, ".text.f", "F", 8),
                 ("a.o", None, ".text.h", "h", 4))
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
    base, new = (layout.read_layout(str(tmp_path / f"{name}-layout" / "plain" / "fuzz_shim")) for name in ("base", "new"))
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
# beta (row 2) calls alpha, a local symbol of a.o (row 1), at 0x4, and gamma, a global, at 0xc.
CALLS = [("2", "0x4", "local", "1", "0x0"), ("2", "0xc", "global", "gamma", "0x0")]


def output(text=0x11000, text_size=0x100, front=0x300, gamma=0x11030):
    """output.tsv: .rodata in a read-only PT_LOAD at 0x10000 of `front` bytes, .text in the next one."""
    return (f"section\t.rodata\t0x10200\t256\t0x2\nsection\t.text\t0x{text:x}\t{text_size}\t0x6\n"
            f"section\t.comment\t0x0\t16\t0x30\nload\t0x10000\t{front}\t{front}\t0x4\n"
            f"load\t0x{text:x}\t{text_size}\t{text_size}\t0x5\nsymbol\tgamma\t0x{gamma:x}\n")


def placed(r, occurrence=0, cause="-", detail="-", place="hole"):
    """A line of placement.tsv for the section `r`, paired with the base section of the same key."""
    key = [r["file"], r["member"] or "-", r["section"], str(occurrence)]
    return "\t".join(key + key + [place, f"0x{r['address']:x}", cause, detail]) + "\n"


def write_entry(root, rows, calls=CALLS, out=None, placement=None, build="plain", target="fuzz"):
    """root/<build>/<target>/ of a layout tree."""
    entry = root / build / target
    entry.mkdir(parents=True)
    where = [r["file"] if r["member"] is None else f"{r['file']}({r['member']})" for r in rows]
    (entry / "map").write_text("".join(map_line(r["address"], r["linked"], r["align"], f"{w}:({r['section']})")
                                       for r, w in zip(rows, where)))
    (entry / "sections.tsv").write_text("".join(
        f"{r['file']}\t{r['file']}\t{r['member'] or '-'}\t{r['section']}\t{r['sha256']}\t{r['size']}\t{r['align']}\n"
        for r in rows))
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
    comment = dict(COMMENT, address=0x40)
    status, lines = run_check(tmp_path, capsys, {"rows": [table, ALPHA, BETA, gamma, delta, comment],
                                                 "out": output(text_size=0x200)})
    assert status == 0
    assert lines_with(lines, "gamma", "0x11030", "0x11100")
    assert lines_with(lines, "delta", "- -> 0x11140")
    assert lines_with(lines, ".text", "0x11000", "256", "512")
    assert lines_with(lines, ".rodata.table", "0x10200", "0x10240")
    assert not lines_with(lines, ".comment")  # not loaded


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


@pytest.mark.parametrize("scenario", [jal_lost, jal_gained, repeated_key, alignment, readonly_growth])
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


def no_cause():
    beta = dict(BETA, address=0x11100)
    return None, {"rows": [TABLE, ALPHA, beta, GAMMA, COMMENT], "placement": [placed(beta)]}, "beta"


def no_placement():
    return None, {"rows": [TABLE, ALPHA, dict(BETA, address=0x11100), GAMMA, COMMENT]}, "beta"


@pytest.mark.parametrize("scenario", [jal_in_reach, jal_no_such_call, repeated_once, repeated_run, aligned,
                                      within_room, wrong_growth, no_cause, no_placement])
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


def test_check_exits_2_for_sections_that_do_not_match_the_map(tmp_path):
    write_entry(tmp_path / "base", BASE_ROWS)
    entry = write_entry(tmp_path / "new", BASE_ROWS)
    (entry / "sections.tsv").write_text("".join((entry / "sections.tsv").read_text().splitlines(True)[:-1]))
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 2


def test_check_exits_2_when_the_trees_share_no_build_and_target(tmp_path):
    write_entry(tmp_path / "base", BASE_ROWS)
    write_entry(tmp_path / "new", BASE_ROWS, build="ubsan")
    assert layout.main(["check", str(tmp_path / "base"), str(tmp_path / "new")]) == 2


@pytest.mark.parametrize("words", [["--help"], ["collect", "--help"], ["check", "--help"]])
def test_each_command_has_help(words):
    assert subprocess.run([sys.executable, str(SCRIPT)] + words, capture_output=True).returncode == 0
