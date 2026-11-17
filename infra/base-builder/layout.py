#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The layout of a fuzz target's link, the append mode that keeps each function whose code did not change at the
address its base gave it, and the check that a development build did.

    python3 layout.py collect BUILDS DIR
    python3 layout.py check BASE NEW
    python3 layout.py wraps -- COMMAND...
    python3 layout.py append --base ENTRY --work DIR --script FILE --placement FILE --wraps FILE [--renamed FILE]
        -- COMMAND...

collect reads BUILDS/<build>/, the $OUT of one build of compile with link records (link-fuzz-target, "the record of
this link"): the fuzz targets at its top, the stripped twin of each in .stripped/<sha256 of the target>, the record of
each link in .records/<sha256 of the target>/, and every file a link took in .records/store/<its sha256>. For each fuzz
target with a record it writes the layout tree DIR/<build>/<target>/:

    map            the record's map, byte for byte: the input-section lines of the linker's map, in the map's order
    sections.tsv   one line for each line of map that names a file, in the same order: the file as the map names
                   it, key_file (the file the pairing keys on: for an allocation-failure link's copy, its original),
                   the member or -, the section, the sha256 of the section's bytes before relocation (empty for
                   SHT_NOBITS and for a section the object does not hold, such as COMMON), its input size and its
                   alignment
    calls.tsv      each call relocation of each .text input section: its row in sections.tsv, its offset, and
                   `local <row> <value>` for a symbol of the same object (the row of the section it is defined in,
                   or - when the map did not take it), else `global <name> <addend>`, with the name the link
                   resolves it to through its wraps
    output.tsv     the unstripped binary's section headers, PT_LOAD segments and defined global symbols
    binary.sha256  the sha256 of the unstripped binary and of its stripped twin
    wraps          the functions the link wraps (--wrap=<f>), one a line
    placement.tsv  for an append build only: where the append mode put each .text input section, and the cause for
                   which a same-bytes one moved

check compares two layout trees, a base and an append build, for each (build, target) that both hold. It pairs the
.text input sections (pair), and each function whose input section has the same bytes as at the base must have the
base's address and linked size, unless NEW's placement.tsv names a cause that the two trees show: jal_reach (a call
in it would be relaxed otherwise at its base address), repeated_key (lld's patterns cannot place it apart from another
section of its key), alignment (its base address does not meet its new alignment) or readonly_growth (the segment in
front of .text grew past the page that holds the base's first .text byte). It exits 1 when one does not, naming the
function; 2 when a tree cannot be read or the two share no (build, target); else 0.

wraps prints the functions that the link COMMAND wraps, one a line, sorted: each --wrap=<f> of the linker command
that the compiler driver gives for it with -###, with each @file expanded. It exits 2 when the command fails or gives
no linker command.

append is the append mode of link-fuzz-target, which runs it in the link's working directory with the link's whole
command (the compiler and every argument, the seals last; no -o, no map, no script). ENTRY is the base layout tree's
entry <tree>/<build>/<target>/, DIR an empty directory for its links, and --renamed an allocation-failure link's
renamed. It writes the link's wraps to --wraps, links once normally (the probe link, DIR/probe), and plans where
each .text input section goes: each same-bytes one at its base address, unless it moves for one of the causes above,
and every other one into a hole before or between them or at the end of .text. It writes the lld script of that
plan to --script, links with it (the check link, DIR/check), verifies that each kept section is at its base address
with its base linked size, that the PT_LOAD segments are the probe link's and that no two of them share a page, and
writes placement.tsv to --placement. When the read-only data in front of .text grew past its room, it writes no
script: the link is a normal one, and placement.tsv gives every same-bytes section readonly_growth. It exits 1 when a
link fails, when the check link is not what the plan asks, or when a file or section name holds a double quote or a
line break, which the script cannot quote; 2 when an input cannot be read; else 0.

The builder image runs this file with its own python3, and the host runs its commands: it takes the standard library
only, and the syntax of Python 3.9.
"""
import argparse
import bisect
import collections
import hashlib
import os
import re
import shlex
import stat
import struct
import subprocess
import sys

CAUSES = ("jal_reach", "repeated_key", "alignment", "readonly_growth")
PLACES = ("kept", "hole", "end", "normal")
# lld relaxes a call to one `jal` when the target is this many bytes from the call site, at most.
JAL_REACH = (-0x100000, 0xFFFFE)
PAGE = 0x1000
R_RISCV_CALL, R_RISCV_CALL_PLT = 18, 19
SHT_SYMTAB, SHT_RELA, SHT_NOBITS, SHT_REL, SHT_SYMTAB_SHNDX = 2, 4, 8, 9, 18
SHF_ALLOC = 0x2
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_SECTION = 3
SHN_UNDEF, SHN_LORESERVE, SHN_XINDEX = 0, 0xFF00, 0xFFFF
PT_LOAD = 1
PN_XNUM = 0xFFFF
# The most bytes read from one file: a map, or an archive the link took.
MAX_BYTES = 1 << 30
# The columns of a map line: address, load address, size (hexadecimal) and alignment (decimal, as lld writes it).
MAP_COLUMNS = re.compile(r" *([0-9a-f]+) +[0-9a-f]+ +([0-9a-f]+) +([0-9]+) ")
SHA256 = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"[0-9]{1,20}")
HEX = re.compile(r"-?0x[0-9a-f]{1,16}")
# The files of a layout tree's entry, as collect writes them.
TREE_FILES = ("map", "sections.tsv", "calls.tsv", "output.tsv", "binary.sha256", "wraps", "placement.tsv")


class LayoutError(Exception):
    """An input that is not there, cannot be read, or is not what a link or collect writes."""


# ── reading files that a build wrote ─────────────────────────────────────────────────────────────────────────────────

def below(base, *parts):
    """base/parts..., where no part is a symbolic link: a build writes these directories, and the host must never
    follow a link it planted. Raise LayoutError if a part is missing or is a link."""
    path = base
    for part in parts:
        if "/" in part or part in ("", ".", ".."):
            raise LayoutError(f"{part!r} is not a file name")
        path = os.path.join(path, part)
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            raise LayoutError(f"{path} is not there") from None
        if stat.S_ISLNK(mode):
            raise LayoutError(f"{path} is a symbolic link")
    return path


def read_regular(path, limit=MAX_BYTES):
    """The bytes of the regular file `path`, opened without following a link, without blocking on a FIFO, and at most
    `limit` bytes long. Raise LayoutError otherwise."""
    try:
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise LayoutError(f"{path}: {error.strerror}") from None
    try:
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode):
            raise LayoutError(f"{path} is not a regular file")
        if info.st_size > limit:
            raise LayoutError(f"{path} is larger than {limit} bytes")
        chunks, left = [], limit + 1
        while left > 0:
            chunk = os.read(handle, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise LayoutError(f"{path} is larger than {limit} bytes")
        return data
    except OSError as error:
        raise LayoutError(f"{path}: {error.strerror}") from None
    finally:
        os.close(handle)


def is_elf_file(path):
    """Whether `path` is a regular file, not a link, that starts as an ELF file does."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return os.read(handle, 4) == b"\x7fELF"
    except OSError:
        return False
    finally:
        os.close(handle)


def is_directory(path):
    """Whether `path` is a directory, not a link to one."""
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def text_of(data):
    """The text of a file's bytes: UTF-8, with any other byte kept as it was (surrogateescape), so that a path that is
    not UTF-8 is written back with the bytes it had."""
    return data.decode("utf-8", "surrogateescape")


def tsv_rows(path):
    """The fields of each line of the tab-separated file `path`."""
    return [line.split("\t") for line in text_of(read_regular(path)).split("\n") if line]


def tsv(rows):
    """The bytes of tab-separated lines. Raise LayoutError for a field that holds a tab or a line break, which would
    read back as other fields."""
    out = []
    for row in rows:
        for field in row:
            if "\t" in field or "\n" in field:
                raise LayoutError(f"{field!r} holds a tab or a line break")
        out.append("\t".join(row) + "\n")
    return "".join(out).encode("utf-8", "surrogateescape")


def write_new(path, data):
    """Write `data` to the file `path` anew: a file or a symbolic link that stands there is removed, never followed."""
    if os.path.lexists(path):
        os.unlink(path)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(handle, "wb") as stream:
        stream.write(data)


def hex_value(text):
    """The number of a field that `hex` wrote, or None."""
    return int(text, 16) if HEX.fullmatch(text) else None


# ── the map ──────────────────────────────────────────────────────────────────────────────────────────────────────────

MapLine = collections.namedtuple("MapLine", "address size align file member section")


def read_map(text):
    """The lines of a link record's map that name a file ([MapLine]), in the map's order. infra/base-builder/
    link-fuzz-target (record_link) keeps the input-section lines of lld's map alone, never sorted: four columns —
    address, load address and size in hexadecimal, alignment in decimal — then eight blanks and <file>:(<section>) or
    <archive>(<member>):(<section>). The linker's own sections (<internal>) are left out. Each line gives its address,
    its linked size, its alignment, the file, the member or None, and the section. Every line is read, loaded or not
    (src/oss_verify/check_links.py, parse_map, keeps the loaded ones only): a caller selects lines by their section
    names, never by the order of their addresses."""
    lines = []
    for line in text.split("\n"):
        found = MAP_COLUMNS.match(line)
        if not found:
            continue
        rest = line[found.end():]
        if not rest.startswith(" " * 8) or rest[8:9] in ("", " "):
            continue
        rest = rest[8:]
        at = rest.rfind(":(")
        if at <= 0 or not rest.endswith(")"):
            continue
        file, section = rest[:at], rest[at + 2:-1]
        if file == "<internal>":
            continue
        member = None
        if file.endswith(")") and "(" in file:
            open_at = file.rindex("(")
            file, member = file[:open_at], file[open_at + 1:-1]
        lines.append(MapLine(int(found.group(1), 16), int(found.group(2), 16), int(found.group(3)), file, member,
                             section))
    return lines


def is_text(section):
    """Whether an input section holds a function: its name is .text or starts with `.text.`."""
    return section == ".text" or section.startswith(".text.")


# ── ELF files and ar archives ────────────────────────────────────────────────────────────────────────────────────────

Section = collections.namedtuple("Section", "index name type flags addr offset size link info align entsize")
Symbol = collections.namedtuple("Symbol", "name value size bind type shndx")
Relocation = collections.namedtuple("Relocation", "offset type symbol addend")
Segment = collections.namedtuple("Segment", "type flags offset vaddr filesz memsz align")


class Elf:
    """A 64-bit little-endian ELF file: its section headers with their names, its symbols, its SHT_RELA relocations
    and its program headers. `what` names it in a message. Raise LayoutError for any other file, and for a header or
    a table that runs past the end of the file."""

    def __init__(self, data, what):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise LayoutError(f"{what} is not a 64-bit little-endian ELF file")
        self.data, self.what = data, what
        (_, _, _, _, self.phoff, shoff, _, _, self.phentsize, self.phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        headers = []
        if shoff:
            if shentsize != 64:
                raise LayoutError(f"{what}: section headers of {shentsize} bytes")
            self._fits(shoff, 64, "the section headers")
            first = struct.unpack_from("<IIQQQQIIQQ", data, shoff)
            # Extended numbering: with 0xff00 sections or more, the count is section 0's sh_size, and the index of
            # the section names is its sh_link.
            if shnum == 0:
                shnum = first[5]
            if shstrndx == SHN_XINDEX:
                shstrndx = first[6]
            self._fits(shoff, shnum * 64, "the section headers")
            headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + 64 * i) for i in range(shnum)]
        self.sections = [Section(i, "", *header[1:]) for i, header in enumerate(headers)]
        if 0 < shstrndx < len(self.sections):
            names = bytes(self.body(self.sections[shstrndx]))
            self.sections = [s._replace(name=self._string(names, header[0]))
                             for s, header in zip(self.sections, headers)]
        self._named = None
        self._symbols = {}
        self._relocations = None

    def _fits(self, offset, size, what):
        if offset + size > len(self.data):
            raise LayoutError(f"{self.what}: {what} run past the end of the file")

    @staticmethod
    def _string(table, offset):
        end = table.find(b"\0", offset)
        return text_of(table[offset:end if end >= 0 else len(table)])

    def body(self, section):
        """The bytes of a section in the file: none for SHT_NOBITS."""
        if section.type == SHT_NOBITS:
            return b""
        self._fits(section.offset, section.size, f"the bytes of {section.name}")
        return self.data[section.offset:section.offset + section.size]

    def named(self, name):
        """The sections of this name, in index order."""
        if self._named is None:
            self._named = collections.defaultdict(list)
            for section in self.sections:
                self._named[section.name].append(section)
        return self._named.get(name, [])

    def symbols(self, index=None):
        """The symbols of the symbol table at section `index`, or of the file's SHT_SYMTAB (none if it has none)."""
        if index is None:
            index = next((s.index for s in self.sections if s.type == SHT_SYMTAB), None)
            if index is None:
                return []
        if index not in self._symbols:
            if not 0 < index < len(self.sections):
                raise LayoutError(f"{self.what}: no section {index} for a symbol table")
            table = self.sections[index]
            if table.entsize != 24 or not 0 < table.link < len(self.sections):
                raise LayoutError(f"{self.what}: {table.name} does not read as a symbol table")
            data, strings = self.body(table), bytes(self.body(self.sections[table.link]))
            # Section indexes of 0xff00 and above are in an SHT_SYMTAB_SHNDX section, one word a symbol.
            extended = next((self.body(s) for s in self.sections if s.type == SHT_SYMTAB_SHNDX and s.link == index),
                            None)
            found = []
            for at in range(0, len(data) // 24 * 24, 24):
                name, info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", data, at)
                if shndx == SHN_XINDEX and extended is not None and at // 24 * 4 + 4 <= len(extended):
                    shndx, = struct.unpack_from("<I", extended, at // 24 * 4)
                found.append(Symbol(self._string(strings, name), value, size, info >> 4, info & 0xF, shndx))
            self._symbols[index] = found
        return self._symbols[index]

    def relocations(self, target):
        """The SHT_RELA relocations that apply to the section at index `target`: [(Relocation, the index of their
        symbol table)]. Raise LayoutError for SHT_REL relocations of it, which this does not read."""
        if self._relocations is None:
            self._relocations = collections.defaultdict(list)
            for section in self.sections:
                if section.type in (SHT_RELA, SHT_REL):
                    self._relocations[section.info].append(section)
        found = []
        for section in self._relocations.get(target, []):
            if section.type == SHT_REL:
                raise LayoutError(f"{self.what}: {section.name} holds SHT_REL relocations, which this does not read")
            if section.entsize != 24:
                raise LayoutError(f"{self.what}: {section.name} does not read as SHT_RELA relocations")
            data = self.body(section)
            for at in range(0, len(data) // 24 * 24, 24):
                offset, info, addend = struct.unpack_from("<QQq", data, at)
                found.append((Relocation(offset, info & 0xFFFFFFFF, info >> 32, addend), section.link))
        return found

    def symbol(self, table, index):
        symbols = self.symbols(table)
        if index >= len(symbols):
            raise LayoutError(f"{self.what}: a relocation names symbol {index}, which is not in its table")
        return symbols[index]

    def segments(self):
        """The program headers ([Segment]), in their order."""
        count = self.phnum
        if count == PN_XNUM and self.sections:
            count = self.sections[0].info
        if not count:
            return []
        if self.phentsize != 56:
            raise LayoutError(f"{self.what}: program headers of {self.phentsize} bytes")
        self._fits(self.phoff, count * 56, "the program headers")
        return [Segment(*struct.unpack_from("<IIQQ8xQQQ", self.data, self.phoff + 56 * i)) for i in range(count)]


def ar_members(data, what):
    """The members of a System V or GNU ar archive, in file order: [(name, bytes)], with a long name read through
    the archive's // member (as src/oss_verify/check_links.py, ar_members, reads them). `what` names it in a message.
    Raise LayoutError for anything else: a thin or BSD archive, or a member header that does not read."""
    if data.startswith(b"!<thin>\n"):
        raise LayoutError(f"{what} is a thin archive, which does not hold its members")
    if not data.startswith(b"!<arch>\n"):
        raise LayoutError(f"{what} is not a System V or GNU ar archive")
    view = memoryview(data)
    members, names, at = [], None, 8
    while at < len(data):
        header = data[at:at + 60]
        size_text = header[48:58].decode("latin-1").strip(" ")
        if len(header) < 60 or header[58:60] != b"`\n" or not re.fullmatch(r"[0-9]{1,10}", size_text):
            raise LayoutError(f"{what}: the member header at byte {at} does not read")
        size = int(size_text)
        if at + 60 + size > len(data):
            raise LayoutError(f"{what}: the member at byte {at} runs past the end of the archive")
        body = view[at + 60:at + 60 + size]
        at += 60 + size + (size & 1)
        name = header[:16].decode("latin-1").rstrip(" ")
        if name == "//":
            names = bytes(body)
            continue
        if name in ("/", "/SYM64/"):
            continue
        if name.startswith("#1/") or name.startswith("__.SYMDEF"):
            raise LayoutError(f"{what} is a BSD ar archive, which this does not read")
        if re.fullmatch(r"/[0-9]+", name):
            start = int(name[1:])
            if names is None or start >= len(names):
                raise LayoutError(f"{what}: the long member name {name} is not in the archive's // member")
            end = names.find(b"\n", start)
            name = text_of(names[start:end if end >= 0 else len(names)])
        members.append((name.rstrip("/"), body))
    return members


class Objects:
    """The object files of one link, by the name its map gives each; `read(file)` gives a file's bytes. Each file is
    read once, and each object in it parsed once."""

    def __init__(self, read):
        self.read = read
        self.files = {}  # {file: {member or None: [bytes or Elf]}}
        self.found = {}

    def objects(self, file, member):
        """The objects of `file`: the file itself, or each member of the archive `file` named `member`, in file
        order ([Elf])."""
        if file not in self.files:
            data = self.read(file)
            if data[:8] == b"!<arch>\n" or data[:8] == b"!<thin>\n":
                members = collections.defaultdict(list)
                for name, body in ar_members(data, file):
                    members[name].append(body)
                self.files[file] = members
            else:
                self.files[file] = {None: [data]}
        held = self.files[file]
        if member is None and None not in held:
            raise LayoutError(f"the map names the archive {file} without a member")
        if member is not None and None in held:
            raise LayoutError(f"the map names a member {member} of {file}, which is not an archive")
        if member not in held:
            raise LayoutError(f"the archive {file} holds no member {member}")
        objects = held[member]
        for i, body in enumerate(objects):
            if not isinstance(body, Elf):
                objects[i] = Elf(body, origin(file, member))
        return objects

    def sections(self, file, member, section):
        """The sections named `section` of the objects of `file` and `member` (objects), in file order:
        [(instance, Elf, Section)], where instance counts the archive's members of that name from 0."""
        key = (file, member, section)
        if key not in self.found:
            self.found[key] = [(instance, elf, s) for instance, elf in enumerate(self.objects(file, member))
                               for s in elf.named(section)]
        return self.found[key]


# ── the sections and calls of a link ─────────────────────────────────────────────────────────────────────────────────

# One line of a map that names a file, with its line of sections.tsv: `row` its index among those lines, `address`
# and `linked` (its linked size) from the map, `key` (key_file, member or "-", section), `sha256` of its bytes before
# relocation ("" for none), and its input size and alignment.
Input = collections.namedtuple("Input", "row address linked file key member section sha256 size align")
# A call relocation of a .text input section: kind "local", with `target` the row of the section its symbol is
# defined in (None when the map did not take it) and `value` the symbol's value plus the addend; or kind "global",
# with `target` the symbol's name as the link resolves it and `value` the addend.
Call = collections.namedtuple("Call", "row offset kind target value")


def member_text(member):
    return "-" if member is None else member


def origin(file, member):
    """Where an input section comes from, for a person: `file`, or `file(member)` for a member of an archive."""
    return file if member is None else f"{file}({member})"


def resolve(name, wraps):
    """The function a call of `name` reaches in a link that wraps `wraps` (--wrap=<f>): __wrap_<f> for a call of
    <f>, and <f> for a call of __real_<f>."""
    if name in wraps:
        return "__wrap_" + name
    if name.startswith("__real_") and name[len("__real_"):] in wraps:
        return name[len("__real_"):]
    return name


def describe(lines, objects, key_file, wraps):
    """The sections.tsv lines ([Input]) and the calls ([Call]) of a link: `lines` are its map's lines (read_map),
    `objects` its Objects, `key_file(file)` the file a section's key names, and `wraps` the functions it wraps.

    The bytes of a map line are those of the section of its name in the object the line names. When an archive holds
    several members of one name, or an object several sections of one name, the k-th map line of that (file,
    member, section) is the k-th such (member, section) in file order. A line with no such section (COMMON, or a
    piece of .eh_frame) gets no sha256, and the map's size and alignment."""
    inputs, located, rows, seen = [], {}, {}, collections.Counter()
    for row, line in enumerate(lines):
        name = (line.file, line.member, line.section)
        k = seen[name]
        seen[name] += 1
        found = objects.sections(*name)
        digest, size, align = "", line.size, line.align
        if k < len(found):
            instance, elf, section = found[k]
            if section.type != SHT_NOBITS:
                digest = hashlib.sha256(elf.body(section)).hexdigest()
            size, align = section.size, section.align
            located[row] = (instance, elf, section)
            rows[(line.file, line.member, instance, section.index)] = row
        inputs.append(Input(row, line.address, line.size, line.file,
                            (key_file(line.file), member_text(line.member), line.section), line.member, line.section,
                            digest, size, align))
    calls = []
    for row, (instance, elf, section) in sorted(located.items()):
        line = lines[row]
        if not is_text(line.section):
            continue
        for relocation, table in elf.relocations(section.index):
            if relocation.type not in (R_RISCV_CALL, R_RISCV_CALL_PLT):
                continue
            symbol = elf.symbol(table, relocation.symbol)
            if symbol.bind == STB_LOCAL or symbol.type == STT_SECTION:
                target = None
                if SHN_UNDEF < symbol.shndx < SHN_LORESERVE:
                    target = rows.get((line.file, line.member, instance, symbol.shndx))
                calls.append(Call(row, relocation.offset, "local", target, symbol.value + relocation.addend))
            else:
                calls.append(Call(row, relocation.offset, "global", resolve(symbol.name, wraps), relocation.addend))
    return inputs, calls


def occurrences(inputs):
    """{row: the input's index among the inputs of its key, from 0, in map order}."""
    seen, found = collections.Counter(), {}
    for i in inputs:
        found[i.row] = seen[i.key]
        seen[i.key] += 1
    return found


# ── the files of a layout tree ───────────────────────────────────────────────────────────────────────────────────────

OutputSection = collections.namedtuple("OutputSection", "name addr size flags")
Load = collections.namedtuple("Load", "vaddr filesz memsz flags")
Output = collections.namedtuple("Output", "sections loads symbols")
Placement = collections.namedtuple("Placement", "base place address cause detail")
Layout = collections.namedtuple("Layout", "inputs calls output placement")


def sections_rows(inputs):
    return [[i.file, i.key[0], i.key[1], i.section, i.sha256, str(i.size), str(i.align)] for i in inputs]


def calls_rows(calls):
    return [[str(c.row), hex(c.offset), c.kind,
             ("-" if c.target is None else str(c.target)) if c.kind == "local" else c.target, hex(c.value)]
            for c in calls]


def output_rows(elf):
    """output.tsv of an unstripped binary: each section header but the null one, in index order; each PT_LOAD; and
    each defined global or weak symbol, the first of each name."""
    rows = [["section", s.name, hex(s.addr), str(s.size), hex(s.flags)] for s in elf.sections[1:]]
    rows += [["load", hex(p.vaddr), str(p.filesz), str(p.memsz), hex(p.flags)]
             for p in elf.segments() if p.type == PT_LOAD]
    named = set()
    for symbol in elf.symbols():
        if symbol.bind in (STB_GLOBAL, STB_WEAK) and symbol.shndx != SHN_UNDEF and symbol.name \
                and symbol.name not in named:
            named.add(symbol.name)
            rows.append(["symbol", symbol.name, hex(symbol.value)])
    return rows


def read_sections(path, lines):
    """The inputs of a layout ([Input]) from its sections.tsv and its map's lines `lines`, which must agree."""
    rows = tsv_rows(path)
    if len(rows) != len(lines):
        raise LayoutError(f"{path}: {len(rows)} lines for the {len(lines)} lines of the map that name a file")
    inputs = []
    for row, (fields, line) in enumerate(zip(rows, lines)):
        if (len(fields) != 7 or fields[0] != line.file or fields[2] != member_text(line.member)
                or fields[3] != line.section or not (fields[4] == "" or SHA256.fullmatch(fields[4]))
                or not DECIMAL.fullmatch(fields[5]) or not DECIMAL.fullmatch(fields[6])):
            raise LayoutError(f"{path}: line {row + 1} does not read as the map's line {row + 1}")
        inputs.append(Input(row, line.address, line.size, line.file, (fields[1], fields[2], fields[3]), line.member,
                            line.section, fields[4], int(fields[5]), int(fields[6])))
    return inputs


def read_calls(path, count):
    """{row: [Call]} from calls.tsv, for a layout of `count` inputs."""
    calls = collections.defaultdict(list)
    for number, fields in enumerate(tsv_rows(path), 1):
        call = None
        if len(fields) == 5 and DECIMAL.fullmatch(fields[0]) and int(fields[0]) < count:
            row, offset, kind, target, value = int(fields[0]), hex_value(fields[1]), fields[2], fields[3], \
                hex_value(fields[4])
            known = offset is not None and offset >= 0 and value is not None
            if known and kind == "local" and target == "-":
                call = Call(row, offset, kind, None, value)
            elif known and kind == "local" and DECIMAL.fullmatch(target) and int(target) < count:
                call = Call(row, offset, kind, int(target), value)
            elif known and kind == "global" and target:
                call = Call(row, offset, kind, target, value)
        if call is None:
            raise LayoutError(f"{path}: line {number} does not read")
        calls[call.row].append(call)
    return calls


def read_output(path):
    """The output sections, PT_LOAD segments and global symbols of a layout's output.tsv (Output)."""
    return output_of(tsv_rows(path), path)


def output_of(rows, what):
    """The Output of the lines of an output.tsv (output_rows), as fields; `what` names them in a message."""
    sections, loads, symbols = [], [], {}
    for number, fields in enumerate(rows, 1):
        if fields[0] == "section" and len(fields) == 5 and DECIMAL.fullmatch(fields[3]):
            addr, flags = hex_value(fields[2]), hex_value(fields[4])
            if addr is not None and flags is not None:
                sections.append(OutputSection(fields[1], addr, int(fields[3]), flags))
                continue
        elif fields[0] == "load" and len(fields) == 5 and DECIMAL.fullmatch(fields[2]) \
                and DECIMAL.fullmatch(fields[3]):
            vaddr, flags = hex_value(fields[1]), hex_value(fields[4])
            if vaddr is not None and flags is not None:
                loads.append(Load(vaddr, int(fields[2]), int(fields[3]), flags))
                continue
        elif fields[0] == "symbol" and len(fields) == 3 and fields[1] not in symbols:
            addr = hex_value(fields[2])
            if addr is not None:
                symbols[fields[1]] = addr
                continue
        raise LayoutError(f"{what}: line {number} does not read")
    return Output(sections, loads, symbols)


def binary_output(path):
    """The Output of the binary at `path`, as its output.tsv gives it (output_rows)."""
    return output_of(output_rows(Elf(read_regular(path), path)), path)


def read_placement(path):
    """{(key_file, member, section, occurrence): Placement} from an append build's placement.tsv: one line for each
    .text input section of its link, tab-separated: the key and its occurrence (its index among the map lines of
    that key, from 0), the base key and occurrence it was paired with (four - when it was not), the place (kept,
    hole, end or normal), its address, its cause (- or one of CAUSES) and the cause's detail (- for none)."""
    found = {}
    unpaired = ("-",) * 4
    for number, fields in enumerate(tsv_rows(path), 1):
        if (len(fields) != 12 or not DECIMAL.fullmatch(fields[3]) or fields[8] not in PLACES
                or hex_value(fields[9]) is None or fields[10] not in ("-",) + CAUSES
                or tuple(fields[4:8]) != unpaired and not DECIMAL.fullmatch(fields[7])):
            raise LayoutError(f"{path}: line {number} does not read")
        key = (fields[0], fields[1], fields[2], int(fields[3]))
        if key in found:
            raise LayoutError(f"{path}: line {number} names a section that an earlier line names")
        base = None if tuple(fields[4:8]) == unpaired else (fields[4], fields[5], fields[6], int(fields[7]))
        found[key] = Placement(base, fields[8], hex_value(fields[9]), fields[10], fields[11])
    return found


def read_layout(directory):
    """The entry <build>/<target>/ of a layout tree (Layout). Its map, sections.tsv, calls.tsv and output.tsv are
    required; placement.tsv is read when it is there (an append build). Raise LayoutError if one cannot be read."""
    lines = read_map(text_of(read_regular(below(directory, "map"))))
    inputs = read_sections(below(directory, "sections.tsv"), lines)
    calls = read_calls(below(directory, "calls.tsv"), len(inputs))
    output = read_output(below(directory, "output.tsv"))
    placement = {}
    if os.path.lexists(os.path.join(directory, "placement.tsv")):
        placement = read_placement(below(directory, "placement.tsv"))
    return Layout(inputs, calls, output, placement)


# ── collect ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def read_inputs(path):
    """{file as the map names it: (real path, sha256)} from a record's inputs.tsv."""
    found = {}
    for number, fields in enumerate(tsv_rows(path), 1):
        if len(fields) != 4 or not SHA256.fullmatch(fields[2]) or not DECIMAL.fullmatch(fields[3]):
            raise LayoutError(f"{path}: line {number} does not read")
        found[fields[0]] = (fields[1], fields[2])
    return found


def read_renamed(path):
    """{copy: real path of its original} from an allocation-failure link's renamed."""
    found = {}
    for number, fields in enumerate(tsv_rows(path), 1):
        if len(fields) != 3 or not SHA256.fullmatch(fields[2]):
            raise LayoutError(f"{path}: line {number} does not read")
        found[fields[0]] = fields[1]
    return found


def store_reader(raw):
    """read(file, sha256): the bytes of `file`, a file that a record of the build $OUT `raw` names, from the build's
    store by its sha256, which they must have. Each store file is read and checked once for all the records of the
    build, so that a file many links took, such as libc, is read once. Raise LayoutError when the store lacks it or
    holds other bytes."""
    checked = {}

    def read(file, stored):
        if stored not in checked:
            try:
                data = read_regular(below(raw, ".records", "store", stored))
            except LayoutError as error:
                raise LayoutError(f"the record's store lacks {file}: {error}") from None
            if hashlib.sha256(data).hexdigest() != stored:
                raise LayoutError(f"the record's store holds other bytes for {file} than its sha256 {stored}")
            checked[stored] = data
        return checked[stored]

    return read


def collect_target(raw, name, binary, digest, store):
    """The files of the layout tree's entry of the fuzz target `name` of the build $OUT `raw`, whose bytes are
    `binary` and their sha256 `digest`, with `store` the build's store_reader: {file name: bytes}. Raise LayoutError
    when its record is incomplete, when it has no wraps, or when its store lacks a file its map names."""
    record = below(raw, ".records", digest)
    mapping = read_regular(below(record, "map"))
    inputs = read_inputs(below(record, "inputs.tsv"))
    try:
        wraps_data = read_regular(below(record, "wraps"))
    except LayoutError as error:
        raise LayoutError(f"the record has no wraps: {error}") from None
    renamed = {}
    if os.path.lexists(os.path.join(record, "renamed")):
        renamed = read_renamed(below(record, "renamed"))
    placement = None
    if os.path.lexists(os.path.join(record, "placement.tsv")):
        placement = read_regular(below(record, "placement.tsv"))
    twin = read_regular(below(raw, ".stripped", digest))
    wraps = {line for line in text_of(wraps_data).split("\n") if line}

    def read(file):
        if file not in inputs:
            raise LayoutError(f"the record's store lacks {file}: its inputs.tsv does not name it")
        return store(file, inputs[file][1])

    def key_file(file):
        # renamed names a copy by the path the link was given, which is the map's name for it; check_links reads it
        # by the real path, which is the same path unless a directory on the way is a link.
        if file in renamed:
            return renamed[file]
        return renamed.get(inputs[file][0], file)

    inputs_of, calls = describe(read_map(text_of(mapping)), Objects(read), key_file, wraps)
    files = {
        "map": mapping,
        "sections.tsv": tsv(sections_rows(inputs_of)),
        "calls.tsv": tsv(calls_rows(calls)),
        "output.tsv": tsv(output_rows(Elf(binary, name))),
        "binary.sha256": f"{digest}  unstripped\n{hashlib.sha256(twin).hexdigest()}  stripped\n".encode(),
        "wraps": wraps_data,
    }
    if placement is not None:
        files["placement.tsv"] = placement
    return files


def collect(builds, out, names=None):
    """Write the layout tree `out` of the builds in `builds` (module docstring): of each directory there, or, with
    `names`, of builds/<name>/ for each of those names alone, so that a build directory another run left there is not
    read. Nothing is written when one of them cannot be read. Raise LayoutError for that, for a name whose directory
    holds no .records, and when the builds hold no link record at all."""
    layouts = {}
    if names is None:
        try:
            listed = sorted(os.listdir(builds))
        except OSError as error:
            raise LayoutError(f"{builds}: {error.strerror}") from None
    else:
        listed = sorted(set(names))
    for build in listed:
        raw = os.path.join(builds, build)
        if not is_directory(raw) or not os.path.lexists(os.path.join(raw, ".records")):
            if names is not None:
                raise LayoutError(f"{build}: {raw} holds no link records (.records)")
            continue
        below(raw, ".records")
        try:
            targets = sorted(os.listdir(raw))
        except OSError as error:
            raise LayoutError(f"{raw}: {error.strerror}") from None
        store = store_reader(raw)
        for name in targets:
            path = os.path.join(raw, name)
            if not is_elf_file(path):
                continue
            binary = read_regular(path)
            digest = hashlib.sha256(binary).hexdigest()
            if not os.path.lexists(os.path.join(raw, ".records", digest)):
                continue
            try:
                layouts[(build, name)] = collect_target(raw, name, binary, digest, store)
            except LayoutError as error:
                raise LayoutError(f"{build}/{name}: {error}") from None
    if not layouts:
        raise LayoutError(f"{builds} holds no link record")
    for (build, name), files in sorted(layouts.items()):
        directory = os.path.join(out, build, name)
        os.makedirs(directory, exist_ok=True)
        for file in TREE_FILES:
            path = os.path.join(directory, file)
            if file in files:
                write_new(path, files[file])
            elif os.path.lexists(path):
                os.unlink(path)


# ── pairing ──────────────────────────────────────────────────────────────────────────────────────────────────────────

Pairing = collections.namedtuple("Pairing", "partner same repeated")


def same_bytes(a, b):
    """Whether two inputs have the same bytes before relocation: the same sha256, which is not empty, and the same
    input size."""
    return bool(a.sha256) and a.sha256 == b.sha256 and a.size == b.size


def content(i):
    return i.section, i.sha256, i.size


def pair(base, new, kind=is_text):
    """The pairs of the input sections of two links whose section names `kind` takes (by default those of .text):
    `base` the base layout's inputs, `new` the new link's ([Input]). In this order:

    1. by key (key_file, member, section), when the key occurs exactly once on each side;
    2. else by (section name, sha256, input size), when exactly one of the sections left on each side has all three:
       a C++ COMDAT section that now comes from another object;
    3. else, for a key that occurs more than once on a side, member by member in map order: the k-th left with the
       k-th left.

    Every other section is new, or gone. The check and the append mode pair the same way. The Pairing gives, for the
    row of each new section, the row of its base partner or None (`partner`) and whether the pair is same-bytes
    (`same`, same_bytes), and the keys that occur more than once on either side (`repeated`)."""
    base = [i for i in base if kind(i.section)]
    new = [i for i in new if kind(i.section)]
    base_count = collections.Counter(i.key for i in base)
    new_count = collections.Counter(i.key for i in new)
    by_key = {i.key: i for i in base if base_count[i.key] == 1}
    partner = {i.row: by_key[i.key] for i in new if new_count[i.key] == 1 and i.key in by_key}
    taken = {b.row for b in partner.values()}
    left_base = [i for i in base if i.row not in taken and i.sha256]
    left_new = [i for i in new if i.row not in partner and i.sha256]
    base_content = collections.Counter(content(i) for i in left_base)
    new_content = collections.Counter(content(i) for i in left_new)
    by_content = {content(i): i for i in left_base if base_content[content(i)] == 1}
    for i in left_new:
        if new_content[content(i)] == 1 and content(i) in by_content:
            partner[i.row] = by_content[content(i)]
            taken.add(partner[i.row].row)
    repeated = {key for key, n in base_count.items() if n > 1} | {key for key, n in new_count.items() if n > 1}
    base_members = collections.defaultdict(list)
    for i in base:
        if i.key in repeated and i.row not in taken:
            base_members[i.key].append(i)
    new_members = collections.defaultdict(list)
    for i in new:
        if i.key in repeated and i.row not in partner:
            new_members[i.key].append(i)
    for key, members in new_members.items():
        for i, b in zip(members, base_members.get(key, [])):
            partner[i.row] = b
    return Pairing({i.row: partner[i.row].row if i.row in partner else None for i in new},
                   {i.row: i.row in partner and same_bytes(partner[i.row], i) for i in new},
                   repeated)


def kept_run(key, base, new, pairing):
    """Whether the members of the repeated key `key` could all keep their base addresses under one lld pattern: as
    many on both sides, each same-bytes with its partner, side by side at the base (no other .text input section
    between them in BASE's address order), and in the same order in NEW's addresses."""
    olds = [i for i in base.inputs if is_text(i.section) and i.key == key]
    news = [i for i in new.inputs if is_text(i.section) and i.key == key]
    rows = {i.row for i in olds}
    if not olds or len(olds) != len(news) \
            or not all(pairing.same[i.row] and pairing.partner[i.row] in rows for i in news):
        return False
    order = sorted((i for i in base.inputs if is_text(i.section)), key=lambda i: (i.address, i.row))
    at = [k for k, i in enumerate(order) if i.key == key]
    if at != list(range(at[0], at[0] + len(at))):
        return False
    return [order[k].row for k in at] == [pairing.partner[i.row] for i in sorted(news, key=lambda i: (i.address,
                                                                                                       i.row))]


# ── the causes ───────────────────────────────────────────────────────────────────────────────────────────────────────

def page_floor(address):
    return address & ~(PAGE - 1)


def in_reach(site, target):
    return JAL_REACH[0] <= target - site <= JAL_REACH[1]


def text_load(output):
    """(.text, k) of an output.tsv reading (Output): its .text output section, and the index k of the PT_LOAD that
    holds the address of .text. .text is None when the output has no .text, and k is None when no PT_LOAD holds it."""
    text = next((s for s in output.sections if s.name == ".text"), None)
    holder = next((k for k, p in enumerate(output.loads) if text and p.vaddr <= text.addr < p.vaddr + p.memsz), None)
    return text, holder


def readonly_growth(base, new):
    """(N, M) for two output.tsv readings (Output): N, the growth of the PT_LOAD in front of the one that holds .text
    (NEW's end, vaddr + memsz, less BASE's); M, its room (page_floor of BASE's .text address less BASE's end). When N
    exceeds M, NEW's segment ends past that page, and .text cannot start where it did. None when a side has no .text
    or no PT_LOAD in front of it."""
    ends = []
    for output in (base, new):
        text, holder = text_load(output)
        if not holder:  # no PT_LOAD holds .text, or the first one does, with none in front of it
            return None
        front = output.loads[holder - 1]
        ends.append((text.addr, front.vaddr + front.memsz))
    (base_text, base_end), (_, new_end) = ends
    return new_end - base_end, page_floor(base_text) - base_end


def call_target(call):
    """A call's target as calls.tsv and the detail of jal_reach name it: row:<row>+<value>, or the global's name."""
    if call.kind == "local":
        return f"row:{'-' if call.target is None else call.target}+{hex(call.value)}"
    return call.target


def target_address(call, layout):
    """The address a call reaches in a layout, or None: its section's address plus the value, or its symbol's address
    plus the addend."""
    if call.kind == "local":
        return None if call.target is None else layout.inputs[call.target].address + call.value
    address = layout.output.symbols.get(call.target)
    return None if address is None else address + call.value


def dragged(fn, base, new, pairing):
    """Whether another same-bytes member of the repeated key of `fn` (of NEW) moved for a cause of its own that the
    two layouts show: one pattern places every member of a key, so the others move with it, with repeated_key."""
    occurrence = occurrences(new.inputs)
    for i in new.inputs:
        if i.row == fn.row or i.key != fn.key or not pairing.same.get(i.row):
            continue
        placement = new.placement.get(i.key + (occurrence[i.row],))
        if placement is not None and placement.cause not in ("-", "repeated_key") \
                and unshown(placement, i, base.inputs[pairing.partner[i.row]], base, new, pairing) is None:
            return True
    return False


def unshown(placement, fn, old, base, new, pairing):
    """Why the two layouts do not show the cause that NEW's placement gives for the same-bytes function `fn` (of NEW,
    paired with `old` of BASE) to move, or None when they show it."""
    cause, detail = placement.cause, placement.detail
    if cause == "jal_reach":
        found = re.fullmatch(r"offset=(0x[0-9a-f]+);target=(.+);(lost|gained)", detail)
        if not found:
            return "the detail does not read as offset=0x<offset>;target=<target>;lost or gained"
        offset, named, way = int(found.group(1), 16), found.group(2), found.group(3)
        call = next((c for c in base.calls.get(old.row, []) if c.offset == offset and call_target(c) == named), None)
        if call is None:
            return "BASE's calls.tsv gives the function no such call"
        now = next((c for c in new.calls.get(fn.row, []) if c.offset == offset), None)
        if now is None:
            return "NEW's calls.tsv gives the function no call at that offset"
        site, before, after = old.address + offset, target_address(call, base), target_address(now, new)
        if before is None or after is None:
            return "a target of the call has no address in its tree"
        reach = (in_reach(site, before), in_reach(site, after))
        if reach != ((True, False) if way == "lost" else (False, True)):
            return (f"from the base call site {hex(site)}, the base target {hex(before)} is "
                    f"{'in' if reach[0] else 'out of'} reach and the new target {hex(after)} "
                    f"{'in' if reach[1] else 'out of'} reach")
        return None
    if cause == "repeated_key":
        if fn.key not in pairing.repeated:
            return "its key occurs once on each side"
        if kept_run(fn.key, base, new, pairing) and not dragged(fn, base, new, pairing):
            return ("its key's members are as many on both sides, same-bytes, side by side at the base and in the "
                    "same order in NEW, and none moved for a cause of its own: one pattern keeps them")
        return None
    if cause == "alignment":
        if fn.align <= 1 or old.address % fn.align == 0:
            return f"its base address {hex(old.address)} is a multiple of its alignment {fn.align} in NEW"
        if detail != f"align={fn.align}":
            return f"its alignment in NEW's sections.tsv is {fn.align}"
        return None
    if cause != "readonly_growth":
        return f"{cause} is not a cause"
    figures = readonly_growth(base.output, new.output)
    if figures is None:
        return "an output.tsv has no .text, or no PT_LOAD in front of the one that holds it"
    growth, room = figures
    if growth <= room:
        return f"the segment in front of .text grew by {growth} bytes, within its room of {room}"
    if detail != f"growth={growth};room={room}":
        return f"the trees give growth={growth};room={room}"
    return None


# ── check ────────────────────────────────────────────────────────────────────────────────────────────────────────────

def function(i):
    """A .text input section's name for a person: the function (the section name without .text.) and where it comes
    from, or the key of a section named .text."""
    where = origin(i.key[0], i.member)
    if i.section.startswith(".text."):
        return f"{i.section[len('.text.'):]} ({where})"
    return f"{where}:({i.section})"


def loaded_rows(inputs):
    """The rows of the map lines whose output section the binary loads. An address cannot say it alone: lld gives each
    section it does not load (.debug_*, .comment) and its input sections their offsets from 0, which can fall in the
    range of a section it loads. So the map's order says it, as src/oss_verify/check_links.py, parse_map, reads it:
    within one output section the addresses do not fall, so a line whose address is below the line before it begins
    another output section, and that one is loaded when the address of its first line is not 0 (the link is -static
    -no-pie, so no loaded section is at 0, and lld writes the sections it does not load last)."""
    rows, is_loaded, previous = set(), False, None
    for i in inputs:
        if previous is None or i.address < previous:
            is_loaded = i.address != 0
        previous = i.address
        if is_loaded:
            rows.add(i.row)
    return rows


def compare(label, base, new):
    """The comparison of one (build, target) of two layouts: (failures, information), each a list of lines."""
    pairing = pair(base.inputs, new.inputs)
    occurrence = occurrences(new.inputs)
    failures, moved, changed = [], [], []
    kept = 0
    for i in new.inputs:
        if i.row not in pairing.partner:
            continue
        partner = pairing.partner[i.row]
        if partner is None:
            changed.append(f"  new: {function(i)}: - -> {hex(i.address)}")
            continue
        old = base.inputs[partner]
        if not pairing.same[i.row]:
            changed.append(f"  changed: {function(i)}: {hex(old.address)} -> {hex(i.address)}")
            continue
        if (old.address, old.linked) == (i.address, i.linked):
            kept += 1
            continue
        values = f"address {hex(old.address)} -> {hex(i.address)}, linked size {old.linked} -> {i.linked}"
        placement = new.placement.get(i.key + (occurrence[i.row],))
        if placement is None or placement.cause == "-":
            failures.append(f"FAIL {label}: {function(i)}: {values}: it has the same bytes, and NEW's placement.tsv "
                            "gives no cause for it to move")
            continue
        why = unshown(placement, i, old, base, new, pairing)
        if why:
            failures.append(f"FAIL {label}: {function(i)}: {values}: the cause {placement.cause} "
                            f"({placement.detail}) does not hold: {why}")
        else:
            moved.append(f"  moved with a cause: {function(i)}: {placement.cause} ({placement.detail}): {values}")
    lines = [f"{label}: {kept} kept, {len(moved)} moved with a cause, {len(changed)} changed or new, "
             f"{len(failures)} failed"]
    lines += moved + changed
    text = [text_load(layout.output)[0] for layout in (base, new)]
    lines.append("  .text: start {} -> {}, size {} -> {}".format(
        *[hex(s.addr) if s else "-" for s in text], *[s.size if s else "-" for s in text]))
    others = pair(base.inputs, new.inputs, kind=lambda name: not is_text(name))
    base_loaded, new_loaded = loaded_rows(base.inputs), loaded_rows(new.inputs)
    for i in new.inputs:
        partner = others.partner.get(i.row)
        if partner is None or not others.same[i.row]:
            continue
        old = base.inputs[partner]
        if old.address != i.address and old.row in base_loaded and i.row in new_loaded:
            lines.append(f"  moved, same bytes: {i.section} ({origin(i.key[0], i.member)}): {hex(old.address)} -> "
                         f"{hex(i.address)}")
    return failures, lines


def entries(tree):
    """The (build, target) pairs of a layout tree: its directories <build>/<target>/."""
    try:
        builds = sorted(os.listdir(tree))
    except OSError as error:
        raise LayoutError(f"{tree}: {error.strerror}") from None
    found = []
    for build in builds:
        if is_directory(os.path.join(tree, build)):
            found += [(build, target) for target in sorted(os.listdir(os.path.join(tree, build)))
                      if is_directory(os.path.join(tree, build, target))]
    return found


def check(base_tree, new_tree):
    """Compare the layout trees `base_tree` and `new_tree` (module docstring), printing what it finds: 1 when a
    (build, target) fails, else 0. Raise LayoutError when a tree cannot be read, or the two share no (build,
    target)."""
    base_entries, new_entries = entries(base_tree), entries(new_tree)
    shared = [entry for entry in base_entries if entry in new_entries]
    if not shared:
        raise LayoutError(f"{base_tree} and {new_tree} share no (build, target)")
    # One (build, target) at a time, whose two layouts are dropped once compared; the lines are printed after the
    # last, so that a tree that cannot be read stops the check before it prints anything.
    lines, failed = [], 0
    for build, target in shared:
        failures, found = compare(f"{build}/{target}", read_layout(below(base_tree, build, target)),
                                  read_layout(below(new_tree, build, target)))
        failed += bool(failures)
        lines += found[:1] + failures + found[1:]
    for line in lines:
        print(line)
    for entry in base_entries:
        if entry not in new_entries:
            print(f"only in BASE: {entry[0]}/{entry[1]}")
    for entry in new_entries:
        if entry not in base_entries:
            print(f"only in NEW: {entry[0]}/{entry[1]}")
    print(f"layout check: {len(shared) - failed} of {len(shared)} (build, target) pass")
    return 1 if failed else 0


# ── the linker's command ─────────────────────────────────────────────────────────────────────────────────────────────

# The first word of the linker's line in the compiler driver's account of a link (-###): a path to ld.lld or ld.
LINKER = re.compile(r"(.*/)?([^/]*-)?ld(\.lld)?")
# An option that wraps a function: --wrap=<f>, or --wrap and <f> in the next word. lld takes one dash as well.
WRAP = re.compile(r"--?wrap(=(.*))?")


def run(words):
    """Run the command `words` in the working directory, with no input: (its exit status, its standard output and
    standard error as one text). Each command that wraps and append run goes through here; the tests replace it."""
    done = subprocess.run(words, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return done.returncode, text_of(done.stdout)


def read_linked(path):
    """The bytes of a file that a link reads, by the name the link gives it. wraps and append run where the link
    runs, in the build's own container, and read what the linker reads: through a symbolic link too."""
    return read_regular(os.path.realpath(path))


def split_words(text, what):
    """The words of `text`, split as a shell would. Raise LayoutError for a quote that does not close."""
    try:
        return shlex.split(text)
    except ValueError as error:
        raise LayoutError(f"{what} does not split into words: {error}") from None


def expand(words, opened=()):
    """`words`, with each @file word replaced by the words of that file, split as a shell would and expanded the
    same way. Raise LayoutError for a file that cannot be read, or that names itself through its @file words."""
    out = []
    for word in words:
        if not word.startswith("@") or word == "@":
            out.append(word)
            continue
        path = word[1:]
        real = os.path.realpath(path)
        if real in opened:
            raise LayoutError(f"{path} names itself through its @file words")
        out += expand(split_words(text_of(read_linked(path)), path), opened + (real,))
    return out


def wraps_of(command):
    """The functions that the link `command` (the compiler driver and its arguments) wraps, sorted, each once. With
    -###, the driver prints the commands it would run on its standard error, and runs none. The linker's is the last
    line that starts with a blank and a double quote and whose first word is ld.lld or ld. Each --wrap=<f> and
    --wrap <f> of its words counts, with each @file word expanded. Raise LayoutError when the command fails or
    prints no linker command."""
    status, output = run(command + ["-###"])
    if status:
        raise LayoutError(f"{command[0]} -### exits with status {status}")
    words = None
    for line in reversed(output.split("\n")):
        if not line.startswith(' "'):
            continue
        try:
            found = shlex.split(line)
        except ValueError:
            continue
        if found and LINKER.fullmatch(found[0]):
            words = found
            break
    if words is None:
        raise LayoutError(f"{command[0]} -### prints no linker command")
    words = expand(words[1:])
    wrapped = set()
    for k, word in enumerate(words):
        found = WRAP.fullmatch(word)
        if found is None:
            continue
        name = found.group(2) if found.group(1) else (words[k + 1] if k + 1 < len(words) else "")
        if name:
            wrapped.add(name)
    return sorted(wrapped)


# ── the append mode ──────────────────────────────────────────────────────────────────────────────────────────────────

class AppendError(Exception):
    """A link of the append mode that fails, a check link that is not what the plan asks, or a file or section name
    that the script cannot quote (it holds a double quote or a line break): append exits 1."""


# Where the append mode puts a .text input section of the link: `place` (kept, hole, end, or normal for a normal
# link), its address, and for a same-bytes section that moves, the cause and its detail (- for none).
Place = collections.namedtuple("Place", "place address cause detail")
# A call of a same-bytes .text input section, as the append mode tests it at the section's base address: its offset,
# its target as BASE's call at that offset names it (call_target), the base call site and the base target's address,
# the link's own call, and where the link's target is: in the .text input section `row`, `value` bytes into it, or,
# with row None, at the address `value`.
CallTest = collections.namedtuple("CallTest", "offset target site before call row value")
# The plan of an append link (plan): `places` {row: Place} for each .text input section of the link, `script` the
# text of the linker script (None for a normal link), `lines` {line of the script: the row whose pattern is on it},
# `next_start` the address at which the script keeps the next PT_LOAD (None when it does not), and `growth` (N, M)
# of readonly_growth for a normal link (else None).
Plan = collections.namedtuple("Plan", "places script lines next_start growth")
# A check link: its map's lines, {row of the probe link: index of its line in that map}, and its Output.
Link = collections.namedtuple("Link", "lines match output")
# A section name that lld's script reads bare, as the exact name.
BARE = re.compile(r"[A-Za-z0-9._$]+")
# lld's error when an address of the script lies below the end of what the script put before it.
BACKWARD = re.compile(r":([0-9]+): unable to move location counter[^\n]*backward")


def align_up(address, align):
    align = max(align, 1)
    return (address + align - 1) // align * align


def relaxed_otherwise(test, after):
    """Whether the call `test`, at its base call site, is in jal's reach of the address `after` and not of its base
    target, or the other way round. False when `after` is None."""
    return after is not None and in_reach(test.site, test.before) != in_reach(test.site, after)


def jal_detail(test):
    """The detail of jal_reach for the call `test`, as unshown reads it."""
    way = "lost" if in_reach(test.site, test.before) else "gained"
    return f"offset={hex(test.offset)};target={test.target};{way}"


def call_tests(base, probe, pairing):
    """{row: [CallTest], in offset order} for each same-bytes .text input section of the link `probe` (Layout). A
    call is tested when BASE's partner has a call at the same offset and both targets have an address. The link's
    target is in the .text input section that holds it: a local symbol's section, or the section at the address of a
    global symbol in the link's output. A target in no .text input section keeps the link's address."""
    text = sorted((i for i in probe.inputs if is_text(i.section) and i.linked), key=lambda i: (i.address, i.row))
    starts = [i.address for i in text]

    def where(call):
        if call.kind == "local":
            if call.target is None:
                return None
            target = probe.inputs[call.target]
            return (target.row, call.value) if is_text(target.section) else (None, target.address + call.value)
        address = probe.output.symbols.get(call.target)
        if address is None:
            return None
        k = bisect.bisect_right(starts, address) - 1
        if k >= 0 and address < text[k].address + text[k].linked:
            return text[k].row, address - text[k].address + call.value
        return None, address + call.value

    tests = {}
    for i in probe.inputs:
        if not (is_text(i.section) and pairing.same[i.row]):
            continue
        old = base.inputs[pairing.partner[i.row]]
        then = {}
        for call in base.calls.get(old.row, []):
            then.setdefault(call.offset, call)
        found = []
        for call in sorted(probe.calls.get(i.row, []), key=lambda c: c.offset):
            before = then.get(call.offset)
            before_address = None if before is None else target_address(before, base)
            now = where(call)
            if before_address is not None and now is not None:
                found.append(CallTest(call.offset, call_target(before), old.address + call.offset, before_address,
                                      call, *now))
        if found:
            tests[i.row] = found
    return tests


def kept_set(base, probe, pairing, forced):
    """The .text input sections of the link `probe` that keep their base addresses ({row: BASE's partner}), and the
    cause of each same-bytes one that moves ({row: (cause, detail)}). A same-bytes section is kept, unless: `forced`
    ({row: CallTest}) names it (jal_reach); its base address does not meet its alignment now (alignment); or its key
    repeats (pairing.repeated). The members of such a key are kept, each at its base address, when one pattern keeps
    them all (kept_run) and none moves for a cause of its own; else the same-bytes ones move with repeated_key."""
    text = [i for i in probe.inputs if is_text(i.section)]
    kept, causes = {}, {}
    for i in text:
        if not pairing.same[i.row]:
            continue
        old = base.inputs[pairing.partner[i.row]]
        if i.row in forced:
            causes[i.row] = ("jal_reach", jal_detail(forced[i.row]))
        elif i.align > 1 and old.address % i.align:
            causes[i.row] = ("alignment", f"align={i.align}")
        elif i.key not in pairing.repeated:
            kept[i.row] = old
    for key in sorted(pairing.repeated):
        members = [i for i in text if i.key == key]
        if members and kept_run(key, base, probe, pairing) and not any(i.row in causes for i in members):
            kept.update((i.row, base.inputs[pairing.partner[i.row]]) for i in members)
            continue
        for i in members:
            if pairing.same[i.row] and i.row not in causes:
                causes[i.row] = ("repeated_key", "-")
    return kept, causes


def lay(unit, start):
    """The address of each input section of `unit` laid out from `start` in order, each at its alignment and with
    its input size, and the address after the last."""
    at, addresses = start, []
    for i in unit:
        at = align_up(at, i.align)
        addresses.append(at)
        at += i.size
    return addresses, at


def allowed(unit, addresses, own, wanted):
    """Whether the input sections of `unit` may go to `addresses`: none at its own base address (`own`), and each
    call into one that `wanted` names ({row: [(CallTest, whether it must be relaxed otherwise)]}) relaxed so."""
    for i, at in zip(unit, addresses):
        if own.get(i.row) == at:
            return False
        for test, change in wanted.get(i.row, ()):
            if relaxed_otherwise(test, at + test.value) != change:
                return False
    return True


def planned_target(test, planned):
    """The address of the target of the call `test` when each .text input section is at its address in `planned`."""
    return test.value if test.row is None else planned[test.row] + test.value


def alloc_order(output):
    """The SHF_ALLOC output sections of a link, in address order (then header order): [(address, index, name)]."""
    return sorted((s.addr, k, s.name) for k, s in enumerate(output.sections) if s.flags & SHF_ALLOC)


def next_segment(base, probe):
    """(S, first, after): S the start of BASE's PT_LOAD after the one that holds .text; `first` the SHF_ALLOC section
    of the probe link with the lowest address in the probe's PT_LOAD after the one that holds .text, and `after` the
    SHF_ALLOC section that follows it in the probe's address order. None when one of them is not there."""
    loads = []
    for output in (base, probe):
        _, holder = text_load(output)
        if holder is None or holder + 1 >= len(output.loads):
            return None
        loads.append(output.loads[holder + 1])
    order = alloc_order(probe)
    first = next((k for k, (address, _, _) in enumerate(order)
                  if loads[1].vaddr <= address < loads[1].vaddr + loads[1].memsz), None)
    if first is None or first + 1 >= len(order):
        return None
    return loads[0].vaddr, order[first][2], order[first + 1][2]


def segment_tail(probe):
    """The bytes that the probe link puts after .text in the PT_LOAD that holds .text (an output section of libc++'s
    overrides, __lcxx_override, for one), with room for their alignment: lld puts them after .text wherever .text
    ends, so the code ends that much after .text. 0 when the probe has no such PT_LOAD."""
    text, holder = text_load(probe.output)
    if holder is None:
        return 0
    load = probe.output.loads[holder]
    start, end = text.addr + text.size, load.vaddr + load.memsz
    if end <= start:
        return 0
    aligns = [i.align for i in probe.inputs if start <= i.address < end]
    return end - start + max(aligns + [1]) - 1


def quotable(name):
    """`name`, which the script quotes. Raise AppendError for a quote or a line break, which a quoted name cannot
    hold."""
    if '"' in name or "\n" in name:
        raise AppendError(f"{name!r} holds a double quote or a line break, which a linker script cannot name")
    return name


def script_name(name):
    """A section's name in the script: bare when lld reads it bare as the exact name, else quoted."""
    return name if BARE.fullmatch(name) else f'"{quotable(name)}"'


def pattern(i):
    """The script's pattern of the input section `i`: the file as the map names it (<archive>:<member> for a member
    of an archive), quoted, which lld reads as the exact name with no wildcard, and the section."""
    file = i.file if i.member is None else f"{i.file}:{i.member}"
    return f'"{quotable(file)}"({script_name(i.section)})'


def plan(base, probe, pairing, forced=None):
    """The plan (Plan) of an append link: where each .text input section of the probe link `probe` (Layout, with no
    placement) goes against the base layout `base`, with the pairing `pairing` (pair). It reads no file and runs
    nothing. `forced` ({row: CallTest}) names kept sections that the check after the link moves with jal_reach.

    When the read-only data in front of .text grew past its room (readonly_growth), the link is a normal one: no
    script, each section at the probe's address. Else each same-bytes section that kept_set keeps occupies its base
    address and base linked size, and the holes are the gaps between them from the base's .text address. Each other
    section moves: largest input size first (ties: the probe map's order), into the first hole in address order
    where it fits at its alignment (its input size: relaxation only removes bytes), never at its own base address,
    and where each call from a kept section into it is relaxed as at the base; else to the end of .text, one after
    another. The members of a repeated key that move are one block: one pattern places them all, in input order.
    Then each call of each kept section is tested at its base call site against its planned target: a kept section
    with a call relaxed otherwise moves with jal_reach, and the placement runs again with the larger set of moved
    sections. Each round moves one section more, so it ends.

    The script puts .text at the base's address, and each section, a kept run or a moved block once, at its address
    in address order. When the planned end of .text, with what the probe link puts after .text in its PT_LOAD
    (segment_tail), is at or below page_floor of the start S of BASE's next PT_LOAD, the script keeps that PT_LOAD at
    S: the first section of the probe's next PT_LOAD at S with an empty body, which lld fills in its own order
    (next_segment)."""
    text = [i for i in probe.inputs if is_text(i.section)]
    figures = readonly_growth(base.output, probe.output)
    if figures is not None and figures[0] > figures[1]:
        cause = ("readonly_growth", "growth={};room={}".format(*figures))
        places = {i.row: Place("normal", i.address, *(cause if pairing.same[i.row] else ("-", "-"))) for i in text}
        return Plan(places, None, {}, None, figures)
    base_text, _ = text_load(base.output)
    if base_text is None:
        raise LayoutError("BASE's output.tsv has no .text")
    start = base_text.addr
    tests = call_tests(base, probe, pairing)
    forced = dict(forced or {})
    while True:
        kept, causes = kept_set(base, probe, pairing, forced)
        movers = [i for i in text if i.row not in kept]
        units, blocks = [], {}
        for i in movers:
            if i.key not in pairing.repeated:
                units.append([i])
                continue
            if i.key not in blocks:
                blocks[i.key] = []
                units.append(blocks[i.key])
            blocks[i.key].append(i)
        units.sort(key=lambda unit: (-sum(i.size for i in unit), unit[0].row))
        own = {i.row: base.inputs[pairing.partner[i.row]].address for i in movers
               if pairing.partner[i.row] is not None}
        # A call from a kept section must be relaxed as at the base; the call that moved a section with jal_reach
        # must stay relaxed otherwise, so that its cause holds.
        wanted = collections.defaultdict(list)
        for row in sorted(kept):
            for test in tests.get(row, []):
                if test.row is not None and test.row not in kept:
                    wanted[test.row].append((test, False))
        for row, test in sorted(forced.items()):
            if test.row is not None and test.row not in kept:
                wanted[test.row].append((test, True))
        holes, end = [], start
        for old in sorted(kept.values(), key=lambda i: (i.address, i.row)):
            if old.address > end:
                holes.append([end, old.address])
            end = max(end, old.address + old.linked)
        planned = {row: old.address for row, old in kept.items()}
        where = {}
        for unit in units:
            for hole in holes:
                addresses, after = lay(unit, hole[0])
                if after <= hole[1] and allowed(unit, addresses, own, wanted):
                    hole[0], place = after, "hole"
                    break
            else:
                addresses, after = lay(unit, end)
                while any(own.get(i.row) == at for i, at in zip(unit, addresses)):
                    addresses, after = lay(unit, addresses[0] + 1)
                end, place = after, "end"
            for i, at in zip(unit, addresses):
                planned[i.row], where[i.row] = at, place
        moved = {}
        for row in sorted(kept):
            test = next((t for t in tests.get(row, []) if relaxed_otherwise(t, planned_target(t, planned))), None)
            if test is not None:
                moved[row] = test
        if not moved:
            break
        forced.update(moved)
    places, items, runs = {}, [], set()
    for i in text:
        if i.row not in kept:
            places[i.row] = Place(where[i.row], planned[i.row], *causes.get(i.row, ("-", "-")))
            continue
        places[i.row] = Place("kept", planned[i.row], "-", "-")
        if i.key not in pairing.repeated:
            items.append((planned[i.row], i.row, i))
        elif i.key not in runs:
            runs.add(i.key)
            first = min((m for m in text if m.key == i.key), key=lambda m: (planned[m.row], m.row))
            items.append((planned[first.row], first.row, first))
    items += [(planned[unit[0].row], unit[0].row, unit[0]) for unit in units]
    order = alloc_order(probe.output)
    at = next((k for k, (_, _, name) in enumerate(order) if name == ".text"), None)
    if not at:
        raise LayoutError("the probe link has no SHF_ALLOC section before .text")
    out, lines = ["SECTIONS", "{", f"  .text {hex(start)} :", "  {"], {}
    for address, row, i in sorted(items, key=lambda item: item[:2]):
        out += [f"    . = {hex(address)};", f"    {pattern(i)}"]
        lines[len(out)] = row
    out += ["  }", "}", f"INSERT AFTER {script_name(order[at - 1][2])};"]
    found, next_start = next_segment(base.output, probe.output), None
    if found is not None and end + segment_tail(probe) <= page_floor(found[0]):
        next_start = found[0]
        out.append(f"SECTIONS {{ {script_name(found[1])} {hex(next_start)} : {{ }} }} "
                   f"INSERT BEFORE {script_name(found[2])};")
    return Plan(places, "\n".join(out) + "\n", lines, next_start, None)


def map_index(lines):
    """{(file, member, section, k): index} of the lines of a map (read_map), where k counts the lines of one (file,
    member, section) from 0 in the map's order. One pattern places the sections of one name in input order, as a
    link with no script does, so the k-th of two maps of the same inputs is the same section."""
    seen, found = collections.Counter(), {}
    for index, line in enumerate(lines):
        name = (line.file, line.member, line.section)
        found[name + (seen[name],)] = index
        seen[name] += 1
    return found


def linked_target(call, link):
    """The address that the call `call` of the probe link reaches in the check link `link` (Link): its section's
    address there plus the value, or the check binary's symbol plus the addend. None when it has none."""
    if call.kind == "local":
        at = None if call.target is None else link.match.get(call.target)
        return None if at is None else link.lines[at].address + call.value
    address = link.output.symbols.get(call.target)
    return None if address is None else address + call.value


def relaxed_there(test, address, link):
    """Whether the call `test` of a section at `address` in the check link `link` is in jal's reach of its target
    there (from address + offset) and not of its base target at the base, or the other way round."""
    after = linked_target(test.call, link)
    return after is not None and in_reach(test.site, test.before) != in_reach(address + test.offset, after)


def segments_failure(probe, check):
    """Why the PT_LOAD segments `check` of the check link are not what the append mode may make, or None: they must
    have the count and the flags of the probe link's (`probe`), in order, and no two may share a page."""
    for k in range(max(len(probe), len(check))):
        if k >= len(check):
            return f"the check link lacks the probe link's PT_LOAD {k} at {hex(probe[k].vaddr)}"
        if k >= len(probe):
            return f"the check link has a PT_LOAD {k} at {hex(check[k].vaddr)}, which the probe link does not"
        if check[k].flags != probe[k].flags:
            return (f"the check link's PT_LOAD {k} at {hex(check[k].vaddr)} has the flags "
                    f"{hex(check[k].flags)}, and the probe link's {hex(probe[k].flags)}")
    ordered = sorted(check, key=lambda p: p.vaddr)
    for a, b in zip(ordered, ordered[1:]):
        if page_floor(a.vaddr + max(a.memsz, 1) - 1) >= page_floor(b.vaddr):
            return (f"the check link's PT_LOADs at {hex(a.vaddr)} and {hex(b.vaddr)} share the page "
                    f"{hex(page_floor(b.vaddr))}")
    return None


def placement_rows(found, places, pairing, base):
    """The lines of placement.tsv (read_placement) for `found`: [(the probe link's Input, its address in the final
    link)], in the final link's map order."""
    rows = []
    occurrence, base_occurrence = occurrences([i for i, _ in found]), occurrences(base.inputs)
    for i, address in found:
        partner = pairing.partner[i.row]
        then = ["-"] * 4 if partner is None else list(base.inputs[partner].key) + [str(base_occurrence[partner])]
        place = places[i.row]
        rows.append(list(i.key) + [str(occurrence[i.row])] + then
                    + [place.place, hex(address), place.cause, place.detail])
    return rows


def append(entry, work, script, placement, wraps, renamed, command):
    """The append mode (module docstring), for the base layout tree's entry `entry`: 0. Raise AppendError when a link
    fails, when the check link is not what the plan asks, or when a file or section name holds a double quote or a
    line break, which the script cannot quote; and LayoutError when an input cannot be read."""
    parts = os.path.normpath(entry).split(os.sep)
    label = f"{parts[-1]} ({parts[-2]})" if len(parts) > 1 else parts[-1]
    try:
        return append_link(label, entry, work, script, placement, wraps, renamed, command)
    except (AppendError, LayoutError) as error:
        raise type(error)(f"{label}: {error}") from None


def append_link(label, entry, work, script, placement, wraps, renamed, command):
    wrapped = wraps_of(command)
    write_new(wraps, "".join(f"{name}\n" for name in wrapped).encode("utf-8", "surrogateescape"))
    probe_map, probe_binary = os.path.join(work, "probe.map"), os.path.join(work, "probe")
    status, output = run(command + [f"-Wl,-Map={probe_map}", "-o", probe_binary])
    if status:
        sys.stderr.write(output)
        raise AppendError(f"the probe link fails with exit status {status}")
    base = read_layout(entry)
    copies = read_renamed(renamed) if renamed else {}

    def key_file(file):
        # As collect keys a copy: by the name the link gives it, or else by its real path.
        if file in copies:
            return copies[file]
        return copies.get(os.path.realpath(file), file)

    lines = read_map(text_of(read_regular(probe_map)))
    inputs, calls = describe(lines, Objects(read_linked), key_file, set(wrapped))
    by_row = collections.defaultdict(list)
    for call in calls:
        by_row[call.row].append(call)
    probe = Layout(inputs, by_row, binary_output(probe_binary), {})
    pairing = pair(base.inputs, probe.inputs)
    text = [i for i in probe.inputs if is_text(i.section)]
    tests = call_tests(base, probe, pairing)
    names = map_index(lines)
    check_map, check_binary = os.path.join(work, "check.map"), os.path.join(work, "check")
    forced = {}
    while True:
        planned = plan(base, probe, pairing, forced)
        if planned.script is None:
            if os.path.lexists(script):
                os.unlink(script)
            print(f"layout.py append: {label}: the read-only data in front of .text grew by {planned.growth[0]} "
                  f"bytes, past its room of {planned.growth[1]} bytes, so this is a normal link, and every function "
                  "whose code did not change moves (readonly_growth)", file=sys.stderr)
            write_new(placement, tsv(placement_rows([(i, i.address) for i in text], planned.places, pairing, base)))
            return 0
        write_new(script, planned.script.encode("utf-8", "surrogateescape"))
        status, output = run(command + [f"-Wl,-T,{script}", f"-Wl,-Map={check_map}", "-o", check_binary])
        if status:
            sys.stderr.write(output)
            backward = BACKWARD.search(output)
            number = int(backward.group(1)) if backward else None
            row = planned.lines.get(number, planned.lines.get(number - 1)) if backward else None
            if row is not None:
                raise AppendError(f"the check link cannot move the location counter backward at line {number} of "
                                  f"{script}, at {function(probe.inputs[row])}")
            raise AppendError(f"the check link fails with exit status {status}")
        checked = read_map(text_of(read_regular(check_map)))
        at = map_index(checked)
        link = Link(checked, {row: at[name] for name, row in names.items() if name in at}, binary_output(check_binary))
        moved = {}
        for i in text:
            if planned.places[i.row].place != "kept":
                continue
            if i.row not in link.match:
                raise AppendError(f"{function(i)} is not in the check link's map")
            old, line = base.inputs[pairing.partner[i.row]], checked[link.match[i.row]]
            if (line.address, line.size) == (old.address, old.linked):
                continue
            test = next((t for t in tests.get(i.row, []) if relaxed_there(t, line.address, link)), None)
            if test is None:
                raise AppendError(f"{function(i)}: the script keeps it at {hex(old.address)} with {old.linked} "
                                  f"bytes, and the check link puts it at {hex(line.address)} with {line.size} "
                                  "bytes, and no call of it is relaxed otherwise: a defect of the append mode")
            moved[i.row] = test
        if not moved:
            break
        forced.update(moved)
    places = dict(planned.places)
    for row, place in sorted(places.items()):
        if place.cause != "jal_reach":
            continue
        shown = [jal_detail(t) for t in tests.get(row, []) if relaxed_otherwise(t, linked_target(t.call, link))]
        if not shown:
            raise AppendError(f"{function(probe.inputs[row])} moves with jal_reach, but no call of it is relaxed "
                              "otherwise at its base address in the check link: a defect of the append mode")
        if place.detail not in shown:
            places[row] = place._replace(detail=shown[0])
    failure = segments_failure(probe.output.loads, link.output.loads)
    if failure:
        raise AppendError(failure)
    back = {at: row for row, at in link.match.items()}
    found = []
    for at, line in enumerate(checked):
        if not is_text(line.section):
            continue
        if at not in back:
            where = origin(line.file, line.member)
            raise AppendError(f"the check link takes {where}:({line.section}), which the probe link does not")
        found.append((probe.inputs[back[at]], line.address))
    missing = [i for i in text if i.row not in link.match]
    if missing:
        raise AppendError(f"{function(missing[0])} is not in the check link's map")
    write_new(placement, tsv(placement_rows(found, places, pairing, base)))
    kept = sum(place.place == "kept" for place in places.values())
    causes = collections.Counter(place.cause for place in places.values() if place.cause != "-")
    counts = ", ".join(f"{cause}: {causes[cause]}" for cause in CAUSES if causes[cause])
    changed = sum(not pairing.same[i.row] for i in text)
    tail = "the data moves" if planned.next_start is None else \
        f"the next segment stays at {hex(planned.next_start)}"
    print(f"layout.py append: {label}: {kept} kept, {sum(causes.values())} moved" + (f" ({counts})" if counts else "")
          + f", {changed} changed or new; {tail}", file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="layout.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    collecting = commands.add_parser(
        "collect", help="write the layout tree of a set of builds",
        description="Write the layout tree DIR/<build>/<target>/ of each fuzz target with a link record in "
                    "BUILDS/<build>/, the $OUT of one build of compile. Exit 2 when a record is incomplete, has no "
                    "wraps, or its store lacks a file its map names, or when BUILDS holds no record.")
    collecting.add_argument("builds", metavar="BUILDS", help="a directory of $OUT trees, one for each build")
    collecting.add_argument("dir", metavar="DIR", help="the layout tree to write")
    checking = commands.add_parser(
        "check", help="compare a base layout tree and an append build's",
        description="Compare each (build, target) that the layout trees BASE and NEW both hold: each function whose "
                    "input section has the same bytes must keep its base address and linked size, or move for a "
                    "cause in NEW's placement.tsv that the two trees show. Exit 1 when one does not, 2 when a tree "
                    "cannot be read or the two share no (build, target).")
    checking.add_argument("base", metavar="BASE", help="the base build's layout tree")
    checking.add_argument("new", metavar="NEW", help="the append build's layout tree")
    wrapping = commands.add_parser(
        "wraps", help="print the functions a link wraps",
        description="Print each function that the link COMMAND wraps, one a line, sorted: each --wrap=<f> of the "
                    "linker command that the compiler driver gives for COMMAND -###, with each @file expanded. Exit "
                    "2 when the command fails or prints no linker command.")
    wrapping.add_argument("words", nargs="+", metavar="COMMAND", help="the link's command, after --")
    appending = commands.add_parser(
        "append", help="link a development build that keeps the base's addresses",
        description="The append mode of link-fuzz-target, run in the link's working directory with the link's whole "
                    "command (no -o, no map, no script). Write the link's wraps, link once normally in DIR (the "
                    "probe link), plan where each .text input section goes, write the linker script of that plan, "
                    "link with it in DIR (the check link) and verify that each kept section is at its base address "
                    "with its base linked size, that the PT_LOAD segments are the probe link's and that no two of "
                    "them share a page, and write placement.tsv. When the read-only data in front of .text grew past "
                    "its room, write no script (a normal link). Exit 1 when a link fails, when the check link is not "
                    "what the plan asks, or when a file or section name holds a double quote or a line break, which "
                    "the script cannot quote; 2 when an input cannot be read.")
    appending.add_argument("--base", required=True, metavar="ENTRY",
                           help="the base layout tree's entry <tree>/<build>/<target>/")
    appending.add_argument("--work", required=True, metavar="DIR", help="an empty directory for the links")
    appending.add_argument("--script", required=True, metavar="FILE", help="the linker script to write")
    appending.add_argument("--placement", required=True, metavar="FILE", help="the placement.tsv to write")
    appending.add_argument("--wraps", required=True, metavar="FILE", help="the wraps to write")
    appending.add_argument("--renamed", metavar="FILE", help="an allocation-failure link's renamed")
    appending.add_argument("words", nargs="+", metavar="COMMAND", help="the link's command, after --")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "collect":
            collect(arguments.builds, arguments.dir)
            return 0
        if arguments.command == "wraps":
            for name in wraps_of(arguments.words):
                print(name)
            return 0
        if arguments.command == "append":
            return append(arguments.base, arguments.work, arguments.script, arguments.placement, arguments.wraps,
                          arguments.renamed, arguments.words)
        return check(arguments.base, arguments.new)
    except AppendError as error:
        print(f"layout.py {arguments.command}: {error}", file=sys.stderr)
        return 1
    except (LayoutError, OSError) as error:
        print(f"layout.py {arguments.command}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
