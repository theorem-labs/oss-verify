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
                   SHT_NOBITS, for a section the object does not hold, such as COMMON, and for a line whose bytes the
                   objects do not tell, describe), its input size and its alignment
    calls.tsv      each call (R_RISCV_CALL, R_RISCV_CALL_PLT) and each thread-local access (R_RISCV_TPREL_HI20, the
                   lui of a local-exec access) of each .text input section, in the order lld reads them (by offset):
                   its row in sections.tsv, its offset, its type (call or tprel), relax (1 when the next relocation is
                   R_RISCV_RELAX, so that lld may relax it; else 0, and lld never does), delta (in hexadecimal, the
                   bytes that lld's relaxation removed in front of it in its section: the relocation is at the
                   section's address plus its offset less delta; - from the first relocation of the section whose
                   relaxation the model of it, relaxation, does not know), then `local <row> <value>` for a symbol
                   of the same object (the row of the section it is defined in, or - when the map did not take it),
                   else `global <name> <addend>`, with the name the link resolves it to through its wraps, `weak
                   <name> <addend>` for an undefined weak reference that no object of the link defines (at 0 unless
                   the binary names it), or `ifunc <name> <addend>` for a symbol of type STT_GNU_IFUNC (its call
                   goes through lld's PLT entry, whose address no tree holds), then the definition of a global in
                   the link's own objects, `<row> <value>` (- - when no object defines it: a symbol the linker makes;
                   a line of another kind ends with - -), and last the target delta (in hexadecimal, the bytes that
                   the link's relaxation removed in front of the target's symbol in its section: lld moves a symbol
                   by the bytes it removed in front of it, so that the target is at its section's address plus the
                   value less the target delta; 0 for a target at the start of its section, for a section symbol, in
                   a section that holds no code, and for a target that only the binary's symbol places; - when not
                   known)
    output.tsv     the unstripped binary's section headers, PT_LOAD segments and defined global symbols
    binary.sha256  the sha256 of the unstripped binary and of its stripped twin
    wraps          the functions the link wraps (--wrap=<f>), one a line
    placement.tsv  for an append build only: where the append mode put each .text input section, and the cause for
                   which a same-bytes one moved; for a build that fell back to its normal link, the place normal, the
                   cause normal_layout (a mark of the build, not a cause of a function) and one reason on every line

check compares two layout trees, a base and an append build, for each (build, target) that both hold. It pairs the
.text input sections (pair), and each function whose input section has the same bytes as at the base must have the
base's address and linked size, unless NEW's placement.tsv names a cause that the two trees show: jal_reach (a call
in it with relax 1 would be relaxed otherwise at its base call site: its base address plus the call's offset, less
the bytes that relaxation removed in front of the call at the base; each target at its section's address plus its
offset there, less the target delta of the call's line), tls_reach (a thread-local access in it with relax 1 is
relaxed otherwise: its variable crossed the bound of 2 KiB from the start of the TLS segment), repeated_key (lld's
patterns cannot place it apart from another section of its key, or two sections of its key on one side have the same
bytes: twins, which the trees cannot tell apart), alignment (its base address does not meet its new alignment) or
readonly_growth (the segment in front of .text grew past the page that holds the base's first .text byte). A
same-bytes function of a key with twins must move: at its base address, the trees do not show that the section there
is the base's own, since lld may take the archive members of one name in another order. An entry of NEW whose
placement.tsv marks a build that fell back to its normal link (normal_layout) is listed as `normal layout: <reason>`
and fails nothing: a normal link keeps no base address, so the build claims none, and check does not verify the
reason. It exits 1 when a function neither keeps its base address nor moves for a cause that the trees show, or when a
same-bytes function of a key with twins lies at its base address, naming the function; 2 when a tree cannot be read
(a placement.tsv in which some lines give normal_layout and others do not, or which gives two reasons, does not read)
or the two share no (build, target); else 0.

wraps prints the functions that the link COMMAND wraps, one a line, sorted: each --wrap=<f> of the linker command
that the compiler driver gives for it with -###, with each @file expanded. It exits 2 when the command fails or gives
no linker command.

append is the append mode of link-fuzz-target, which runs it in the link's working directory with the link's whole
command (the compiler and every argument, the seals last; no -o, no map, no script). ENTRY is the base layout tree's
entry <tree>/<build>/<target>/, DIR an empty directory for its links, and --renamed an allocation-failure link's
renamed. It writes the link's wraps to --wraps, links once normally (the probe link, DIR/probe), and plans where
each .text input section goes: each same-bytes one at its base address, unless it moves for one of the causes above
(each one of a key with twins does, with repeated_key), and every other one into a hole before or between them or at
the end of .text. .text ends where the plan ends it, so that lld puts what follows .text in its PT_LOAD (libc++'s
__lcxx_override, for one) where the plan's tests of the calls into it expect it. A call into a section that moves is
tested wherever lld's relaxation there may put its target; one whose target may then lie in jal's reach or out of it is
not decided: it moves nothing, and the build falls back to its normal link (below). Each jal_reach cause that the plan
finds holds in the final plan: a section that it moves for a call relaxed otherwise returns to its base address when
no call of it is relaxed otherwise against that plan. It writes the lld script of that plan to --script, links with it
(the check link, DIR/check), verifies that each kept section is at its base address with its base linked size (one
whose call or thread-local access the check link relaxes otherwise moves, with jal_reach or tls_reach, and the plan
runs again), that each jal_reach and tls_reach cause holds in the last check link, that the PT_LOAD segments are the
probe link's and that no two of them share a page, and writes placement.tsv to --placement. When the read-only data in
front of .text grew past its room, it writes no script: the link is a normal one, and placement.tsv gives every
same-bytes section readonly_growth.

append never stops a link for a change of the code. The build falls back to its normal link when a section that a plan
keeps has a call or a thread-local access that lld may relax and that the plan does not test or decide, when a check
link fails (lld's error that it cannot move the location counter backward, for one) or is not what the plan asks (a
kept section that it changes, a section that an earlier check link moved and whose cause the last one does not show, a
cause that it does not show, PT_LOAD segments that are not the probe link's, a section that it takes or lacks), and
when a file or section name holds a double quote or a line break, which the script cannot quote. append then writes no
script (it removes one that is there), so that link-fuzz-target links normally; placement.tsv gives each .text input
section of the probe link the place normal, its address there, the cause normal_layout and the reason; and it prints
one line, `layout.py append: <target> (<build>): normal link: <reason>`, which names the function and its call, or
the line of the script. It exits 1 when the probe link fails, as the normal link of the same command would; 2 when an
input cannot be read; else 0.

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

CAUSES = ("jal_reach", "tls_reach", "repeated_key", "alignment", "readonly_growth")
# The cause that every line of placement.tsv gives for a build that fell back to its normal link (append_link), with
# the reason as its detail: a mark of the build, not one of the CAUSES for which a function moves.
NORMAL_LAYOUT = "normal_layout"
PLACES = ("kept", "hole", "end", "normal")
# lld relaxes a call to one `jal` when the target lies this many bytes from the call site (isInt<21>), at most.
JAL_REACH = (-0x100000, 0xFFFFF)
# lld removes the lui and the add of a local-exec thread-local access when the variable's offset from the start of
# the TLS segment, plus the addend, is in this range: its hi20 is 0 (lld's relaxTlsLe).
TLS_REACH = (-0x800, 0x7FF)
PAGE = 0x1000
R_RISCV_CALL, R_RISCV_CALL_PLT, R_RISCV_TPREL_HI20, R_RISCV_TPREL_ADD = 18, 19, 29, 32
R_RISCV_ALIGN, R_RISCV_RELAX = 43, 51
R_RISCV_TLSDESC_HI20, R_RISCV_TLSDESC_LOAD_LO12, R_RISCV_TLSDESC_ADD_LO12, R_RISCV_TLSDESC_CALL = 62, 63, 64, 65
R_RISCV_TLSDESC = (R_RISCV_TLSDESC_HI20, R_RISCV_TLSDESC_LOAD_LO12, R_RISCV_TLSDESC_ADD_LO12, R_RISCV_TLSDESC_CALL)
# The R_RISCV_TLSDESC_* relocations of which lld may remove 4 bytes each (most_removed): all but R_RISCV_TLSDESC_CALL.
TLSDESC_REMOVED = (R_RISCV_TLSDESC_HI20, R_RISCV_TLSDESC_LOAD_LO12, R_RISCV_TLSDESC_ADD_LO12)
# The type of a line of calls.tsv, by the relocation it records.
LINE_TYPES = {R_RISCV_CALL: "call", R_RISCV_CALL_PLT: "call", R_RISCV_TPREL_HI20: "tprel"}
# The relocations whose target decides whether lld's relaxation removes bytes (relaxation).
TARGETED = (R_RISCV_CALL, R_RISCV_CALL_PLT, R_RISCV_TPREL_HI20, R_RISCV_TPREL_ADD)
# The relocations that relaxation, most_removed or a line of calls.tsv reads (alike).
MODELED = TARGETED + (R_RISCV_ALIGN, R_RISCV_RELAX) + R_RISCV_TLSDESC
# The kinds of the target of a line of calls.tsv (module docstring).
KINDS = ("local", "global", "weak", "ifunc")
EF_RISCV_RVC = 0x1
SHT_SYMTAB, SHT_RELA, SHT_NOBITS, SHT_REL, SHT_SYMTAB_SHNDX = 2, 4, 8, 9, 18
SHF_ALLOC, SHF_EXECINSTR, SHF_TLS = 0x2, 0x4, 0x400
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_SECTION, STT_GNU_IFUNC = 3, 10
SHN_UNDEF, SHN_LORESERVE, SHN_XINDEX = 0, 0xFF00, 0xFFFF
PT_LOAD = 1
PN_XNUM = 0xFFFF
# The most bytes read from one file: a map, or an archive the link took.
MAX_BYTES = 1 << 30
# lld stops a link whose relaxation has not settled after this many passes (finalizeAddressDependentContent).
RELAX_PASSES = 30
# The most candidates that the search for the assignments of the map lines of one name to its sections gives to a
# line, all lines counted (assigned); past them, every line of that name is ambiguous.
ASSIGNMENT_STEPS = 10000
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

MapLine = collections.namedtuple("MapLine", "address size align file member section loaded")


def read_map(text):
    """The lines of a link record's map that name a file ([MapLine]), in the map's order. infra/base-builder/
    link-fuzz-target (record_link) keeps the input-section lines of lld's map alone, never sorted: four columns —
    address, load address and size in hexadecimal, alignment in decimal — then eight blanks and <file>:(<section>) or
    <archive>(<member>):(<section>). The linker's own sections (<internal>) are left out (map_entries gives them
    too). Each line gives its address, its linked size, its alignment, the file, the member or None, the section, and
    whether the binary loads it. Every line is read, loaded or not: a caller selects lines by their section names,
    never by the order of their addresses.

    Whether the binary loads a line is read as src/oss_verify/check_links.py, parse_map, reads it (parse_map keeps the
    loaded lines only). An address cannot say it alone: lld gives each output section it does not load (.debug_*,
    .comment) and its input sections their offsets from 0, which can fall in the range of a section it loads. So the
    map's order says it: within one output section the addresses do not fall, so a line whose address is below the
    line before it begins another output section, and that one is loaded when the address of its first line is not 0
    (the link is -static -no-pie, so no loaded section is at 0, and lld writes the sections it does not load last).
    Each line of four columns, eight blanks and a text that does not start with a blank takes part in that order, as
    in parse_map, whether or not it names a file, so an <internal> line does too: an output section that lld does not
    load can begin with one of its own lines at 0, such as <internal>:(.comment), and go on with an object's line at
    an offset that is not 0."""
    return [line for line in map_entries(text) if line.file != "<internal>"]


def map_entries(text):
    """The lines of a map that read_map reads, and the lines of the linker's own sections as well, of the file
    <internal> and no member, in the map's order ([MapLine])."""
    lines, loaded, previous = [], False, None
    for line in text.split("\n"):
        found = MAP_COLUMNS.match(line)
        if not found:
            continue
        rest = line[found.end():]
        if not rest.startswith(" " * 8) or rest[8:9] in ("", " "):
            continue
        address = int(found.group(1), 16)
        if previous is None or address < previous:
            loaded = address != 0
        previous = address
        rest = rest[8:]
        at = rest.rfind(":(")
        if at <= 0 or not rest.endswith(")"):
            continue
        file, section = rest[:at], rest[at + 2:-1]
        member = None
        if file.endswith(")") and "(" in file:
            open_at = file.rindex("(")
            file, member = file[:open_at], file[open_at + 1:-1]
        lines.append(MapLine(address, int(found.group(2), 16), int(found.group(3)), file, member, section, loaded))
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
    """A 64-bit little-endian ELF file: its section headers with their names, its symbols, its SHT_RELA relocations,
    its program headers and its e_flags (`flags`). `what` names it in a message. Raise LayoutError for any other file,
    and for a header or a table that runs past the end of the file."""

    def __init__(self, data, what):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise LayoutError(f"{what} is not a 64-bit little-endian ELF file")
        self.data, self.what = data, what
        (_, _, _, _, self.phoff, shoff, self.flags, _, self.phentsize, self.phnum, shentsize, shnum,
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
# A line of calls.tsv (module docstring): a call (type "call") or the lui of a thread-local access ("tprel") at
# `offset` in the .text input section `row`; `relax` whether the next relocation is R_RISCV_RELAX, and `delta` the
# bytes that lld's relaxation removed in front of it in that section (relaxation), or None when they are not known.
# Kind "local": `target` the row of the section its symbol is defined in (None when the map did not take it) and
# `value` the symbol's value plus the addend. Kind "global": `target` the symbol's name as the link resolves it,
# `value` the addend, and `definition` (row, value) of the symbol that defines it in the link's own objects
# (definitions), or None when none does. Kind "weak", an undefined weak reference that no object of the link
# defines, and kind "ifunc", a symbol of type STT_GNU_IFUNC: `target` its name and `value` the addend. Only a global
# line has a definition. `target_delta` the bytes that relaxation removed in front of the target's symbol in its
# section (target_address subtracts them), or None when they are not known; `removable` the most bytes that lld's
# relaxation can remove there, wherever the link puts the sections (most_removed), which describe gives each line,
# and None for a line read from calls.tsv.
Call = collections.namedtuple("Call", "row offset type relax delta kind target value definition target_delta "
                                      "removable")


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


def ordered_relocations(elf, section):
    """The relocations of the section `section` of the object `elf` in lld's order, by offset (lld sorts them
    stably): [(Relocation, the index of its symbol table, relaxable)], where relaxable is whether the next relocation
    is R_RISCV_RELAX, so that lld may relax it (lld's relaxable)."""
    ordered = sorted(elf.relocations(section.index), key=lambda item: item[0].offset)
    return [(relocation, table, k + 1 < len(ordered) and ordered[k + 1][0].type == R_RISCV_RELAX)
            for k, (relocation, table) in enumerate(ordered)]


def assigned(sizes, candidates):
    """The candidates that each map line of one (file, member, section) can be, in map order, each in the order of
    `candidates` ([[(instance, Elf, Section)]]), or None when the search tells none: `sizes` are the lines' linked
    sizes, and `candidates` the sections of that name (Objects.sections).

    lld's relaxation gives a candidate a linked size from its input size less its removable bytes (removable_bytes)
    up to its input size, and which one depends on where the link puts the code, so that it changes from one link to
    the next: the base, the probe link and the final link. Candidates whose ranges of linked sizes overlap, directly
    or through other candidates, form one cluster, and a line can be a candidate of the one cluster whose ranges hold
    its linked size, and of no other. So the candidates of a line do not depend on the linked size that lld gave each
    section in that link: sizes tell two candidates apart only when no linked size of one can be a linked size of the
    other, and the lines of the same sections get the same candidates in every link.

    An assignment gives each line a candidate of its cluster, never the candidate of another line (lld takes each
    section once), and gives the lines of the candidates of one object those candidates in their order in the object
    (lld keeps that order, though --gc-sections may drop some of them). It orders nothing between two objects, and so
    assumes nothing of where the lines of one member lie in the map: lld's map lists the members of one name in the
    order lld took them, which the tree does not know. A line can be each candidate that an assignment gives it, so
    the search finds every assignment. None when no assignment exists (a line whose linked size no cluster holds, for
    one), and when the search, which gives each line in map order each candidate that it can have, gives more than
    ASSIGNMENT_STEPS candidates in all: every line of that name is then ambiguous."""
    # The cluster of each candidate, and of each line (None when no cluster holds its linked size). A cluster is the
    # range from the lowest to the highest linked size of its candidates: the candidates' ranges, in order of their
    # lowest sizes, join the cluster before them while they overlap its range.
    ranges = sorted((section.size - removable_bytes(elf, section), section.size, j)
                    for j, (_, elf, section) in enumerate(candidates))
    clusters, cluster = [], [0] * len(candidates)  # clusters: [[lowest, highest linked size]], in size order
    for low, high, j in ranges:
        if clusters and low <= clusters[-1][1]:
            clusters[-1][1] = max(clusters[-1][1], high)
        else:
            clusters.append([low, high])
        cluster[j] = len(clusters) - 1
    held = [next((k for k, (low, high) in enumerate(clusters) if low <= size <= high), None) for size in sizes]
    places, groups = [], collections.defaultdict(list)  # groups: {instance: [index in candidates] in object order}
    for j, (instance, _, _) in enumerate(candidates):
        places.append(len(groups[instance]))
        groups[instance].append(j)
    # The place in its object of the last candidate given to a line, for each object; the count of the candidates
    # past those places, which the lines not yet given one can have; (candidate, the place before it in its object)
    # of each line given one, in map order; and the candidates that each line has in the assignments found.
    last, free, chosen, given = dict.fromkeys(groups, -1), len(candidates), [], [set() for _ in sizes]

    def options(line):
        # The candidates that `line` can have after the lines before it, last first: each lies past the last
        # candidate given in its object, leaves a candidate for each line after `line`, and is in the cluster of
        # `line`. The candidate at the place p of an object takes p - last of that object's candidates from the lines
        # after `line`: itself and those it passes over.
        reach = max(free - (len(sizes) - line - 1), 0)
        found = [j for instance, members in groups.items()
                 for j in members[last[instance] + 1:last[instance] + 1 + reach]
                 if cluster[j] == held[line]]
        return found[::-1]

    stack, steps = [options(0)], 0
    while stack:
        if len(chosen) == len(stack):
            # Take back the candidate of the last line given one, to give that line its next one.
            j, before = chosen.pop()
            free += places[j] - before
            last[candidates[j][0]] = before
        if not stack[-1]:
            stack.pop()
            continue
        j = stack[-1].pop()
        steps += 1
        if steps > ASSIGNMENT_STEPS:
            return None
        instance = candidates[j][0]
        chosen.append((j, last[instance]))
        free -= places[j] - last[instance]
        last[instance] = places[j]
        if len(chosen) < len(sizes):
            stack.append(options(len(chosen)))
            continue
        for line, (j, _) in enumerate(chosen):
            given[line].add(j)
    if not all(given):
        return None
    return [[candidates[j] for j in sorted(found)] for found in given]


def alike(candidates):
    """Whether the sections `candidates` ([(instance, Elf, Section)]), any of which a map line may be, give it the
    same line of sections.tsv and the same lines of calls.tsv (describe): none is SHT_NOBITS; all have the same
    bytes, size, alignment and flags, in objects that agree on EF_RISCV_RVC; none defines a global or weak symbol
    (definitions would need to know which one the link took); and all have the same relocations of the types that
    relaxation, most_removed or a line of calls.tsv reads (MODELED), in lld's order: the same offset, type and addend,
    and whether the next relocation is R_RISCV_RELAX. Each symbol that one of those relocations names must be a
    global or weak one of one name, and of one kind as describe gives it (weak for an undefined weak one), in all of
    them: a local or section symbol names a section of its own object, which differs from one candidate to the
    next."""
    headers = {(section.type, section.size, section.align, section.flags, elf.flags & EF_RISCV_RVC,
                hashlib.sha256(elf.body(section)).digest()) for _, elf, section in candidates}
    if len(headers) != 1 or next(iter(headers))[0] == SHT_NOBITS:
        return False
    read = set()
    for _, elf, section in candidates:
        if any(symbol.shndx == section.index and symbol.bind in (STB_GLOBAL, STB_WEAK) for symbol in elf.symbols()):
            return False
        found = []
        for relocation, table, relaxable in ordered_relocations(elf, section):
            if relocation.type not in MODELED:
                continue
            named = None
            if relocation.symbol:
                symbol = elf.symbol(table, relocation.symbol)
                if symbol.bind not in (STB_GLOBAL, STB_WEAK):
                    return False
                named = (symbol.name, symbol.bind == STB_WEAK and symbol.shndx == SHN_UNDEF)
            found.append((relocation.offset, relocation.type, relocation.addend, named, relaxable))
        read.add(tuple(found))
    return len(read) == 1


def describe(lines, objects, key_file, wraps, output=None):
    """The sections.tsv lines ([Input]) and the calls.tsv lines ([Call]) of a link: `lines` are its map's lines
    (read_map), `objects` its Objects, `key_file(file)` the file a section's key names, `wraps` the functions it
    wraps, and `output` its binary's Output (read_output), or None, for a link whose deltas are never used. Three
    steps give them: matched_lines matches the map's lines to the sections of the objects and gives the sections.tsv
    lines, code_relocations gives each relocation of each section of code with the call or the thread-local access of
    each one whose target decides a relaxation, and relaxed_calls relaxes the sections of code until the deltas settle.
    The calls.tsv lines are the calls and the thread-local accesses of the .text input sections, in row order, then in
    lld's order."""
    inputs, located, twins, rows = matched_lines(lines, objects, key_file)
    relocated = code_relocations(lines, located, twins, rows, wraps)
    relaxed = relaxed_calls(lines, inputs, relocated, output)
    calls = []
    for row, (_, entries) in sorted(relocated.items()):
        if is_text(lines[row].section):
            calls += [call for (relocation, _, _, _), call in zip(entries, relaxed[row])
                      if relocation.type in LINE_TYPES]
    return inputs, calls


def matched_lines(lines, objects, key_file):
    """The sections.tsv lines of a link (describe), and the sections they are: ([Input], located, twins, rows), where
    `lines`, `objects` and `key_file` are describe's. `located` ({row: (instance, Elf, Section)}) gives the section of
    each line that can be one candidate, `twins` ({row: (instance, Elf, Section)}) the first candidate of each twin
    line, and `rows` ({(file, member, instance, section index): row}) the row of each section that `located` gives.

    The candidates of a map line are the sections of its name in the objects of its file and member
    (Objects.sections), and the line can be each candidate that an assignment of the map's lines of that (file,
    member, section) to those candidates gives it (assigned). lld's relaxation gives a section a linked size from its
    input size less its removable bytes (removable_bytes) up to its input size, which changes from one link to the
    next, so a line's size tells two candidates apart only when no linked size of one can be a linked size of the
    other (assigned's clusters); the line is then the same candidate in the base, the probe link and the final link,
    whichever linked size each of them gives it. lld takes each section once, and keeps the sections of one name of
    one object in their order in the object, but lists the archive members of one name in the order it took them,
    which the tree does not know. A line that can be one candidate is that section. A line that can be two or more
    (candidates of one cluster, when lld took only some of the candidates, through --gc-sections or the archive
    members it extracted, or they lie in two or more members of one name) is a twin line when they are alike (alike):
    asan.module_ctor in two archive members of one name, for one. A twin line gets their sha256, size and alignment,
    and the calls of the first of them, with this link's deltas; as the tree does not know which of them the link
    took, nothing reaches into it: a local reference from another section into it has no target row, and it holds
    no symbol for definitions. Every other line is ambiguous: its candidates are not alike, or no assignment fits (no
    candidate can have its linked size, for one), or the search for the assignments took more than its bound. An
    ambiguous line, as a line with no candidate (COMMON, or a piece of .eh_frame), gets no sha256 (so it never counts
    as same bytes), the map's size and alignment, no calls, and no symbols for definitions."""
    inputs, located, twins, rows = [], {}, {}, {}
    named = collections.defaultdict(list)  # {(file, member, section): [the row of each of its lines, in map order]}
    for row, line in enumerate(lines):
        named[(line.file, line.member, line.section)].append(row)
    possible = {}  # {row: the candidates that its line can be (assigned), or None}
    for name, name_rows in named.items():
        given = assigned([lines[row].size for row in name_rows], objects.sections(*name))
        possible.update(zip(name_rows, given or [None] * len(name_rows)))
    for row, line in enumerate(lines):
        digest, size, align = "", line.size, line.align
        choices = possible[row]
        if choices is not None and (len(choices) == 1 or alike(choices)):
            instance, elf, section = choices[0]
            if section.type != SHT_NOBITS:
                digest = hashlib.sha256(elf.body(section)).hexdigest()
            size, align = section.size, section.align
            if len(choices) == 1:
                located[row] = choices[0]
                rows[(line.file, line.member, instance, section.index)] = row
            else:
                twins[row] = choices[0]
        inputs.append(Input(row, line.address, line.size, line.file,
                            (key_file(line.file), member_text(line.member), line.section), line.member, line.section,
                            digest, size, align))
    return inputs, located, twins, rows


def code_relocations(lines, located, twins, rows, wraps):
    """Each relocation of each section of code of a link, in lld's order (ordered_relocations): {row: (the
    EF_RISCV_RVC flag of its object, [(Relocation, relaxable, Call or None, anchor)])}, in row order, for each map
    line of a .text input section or of another section with SHF_EXECINSTR that is one section (`located`) or a twin
    line (`twins`), which has the relocations of the first of its candidates, which name no local symbol (alike).
    `lines` and `wraps` are describe's, and `located`, `twins` and `rows` matched_lines's.

    Each relocation whose target decides a relaxation (TARGETED) has a Call, with no delta, target delta or removable
    (relaxed_calls gives them): each call and each thread-local access of a .text input section is one. A global one
    names its definition in the link's objects (definitions), and one that an object of the link defines as an
    STT_GNU_IFUNC is an ifunc one. Its anchor is the offset of its symbol in its section, which lld moves: the value
    of a local symbol or of a global's definition, and else 0, as for a section symbol."""
    relocated = {}
    for row, (instance, elf, section) in sorted({**located, **twins}.items()):
        line = lines[row]
        if not (is_text(line.section) or section.flags & SHF_EXECINSTR):
            continue
        entries = []
        for relocation, table, relaxable in ordered_relocations(elf, section):
            call, anchor = None, 0
            if relocation.type in TARGETED:
                line_type = "call" if relocation.type in (R_RISCV_CALL, R_RISCV_CALL_PLT) else "tprel"
                symbol = elf.symbol(table, relocation.symbol)
                if symbol.bind == STB_LOCAL or symbol.type == STT_SECTION:
                    if symbol.type == STT_GNU_IFUNC:
                        kind, target, value = "ifunc", symbol.name, relocation.addend
                    else:
                        target = None
                        if SHN_UNDEF < symbol.shndx < SHN_LORESERVE:
                            target = rows.get((line.file, line.member, instance, symbol.shndx))
                        kind, value = "local", symbol.value + relocation.addend
                        anchor = 0 if symbol.type == STT_SECTION else symbol.value
                else:
                    kind = "weak" if symbol.bind == STB_WEAK and symbol.shndx == SHN_UNDEF else "global"
                    target, value = resolve(symbol.name, wraps), relocation.addend
                call = Call(row, relocation.offset, line_type, relaxable, None, kind, target, value, None, None, None)
            entries.append((relocation, relaxable, call, anchor))
        relocated[row] = (elf.flags & EF_RISCV_RVC, entries)
    found = definitions({call.target for _, entries in relocated.values() for _, _, call, _ in entries
                         if call is not None and call.kind in ("global", "weak")}, lines, located, rows)
    # A global or weak reference that an object of the link defines is a global line, whose symbol is its definition,
    # or an ifunc one.
    for row, (rvc, entries) in relocated.items():
        defined = []
        for relocation, relaxable, call, anchor in entries:
            if call is not None and call.kind in ("global", "weak") and call.target in found:
                at, value, symbol_type = found[call.target]
                if symbol_type == STT_GNU_IFUNC:
                    call = call._replace(kind="ifunc")
                else:
                    call, anchor = call._replace(kind="global", definition=(at, value)), value
            defined.append((relocation, relaxable, call, anchor))
        relocated[row] = (rvc, defined)
    return relocated


def relaxed_calls(lines, inputs, relocated, output):
    """The Call of each relocation of each section of code of `relocated` (code_relocations), with its delta, its
    target delta and its removable: {row: [Call, or None for a relocation with no Call]}, in the order of
    `relocated`. `lines` and `output` are describe's, and `inputs` the sections.tsv lines (matched_lines). A Call's
    delta comes from relaxation, with the addresses of this link: those of the map's lines, of the definitions, and of
    `output`'s symbols. With no `output`, every delta is None.

    lld relaxes each section of code (SHF_EXECINSTR), and moves each symbol of it by the bytes it removed in front of
    the symbol, never a section symbol (its anchors). A line's target_delta is those bytes for the symbol of its
    target: the delta of the first relocation of the target's section at or past the symbol's offset there, or the
    bytes removed in all when there is none. It is 0 when no relocation in front of the symbol can remove a byte
    (removable 0: a target at the start of its section, a section symbol, a section that holds no code, and a target
    that only the binary's symbol places, whose value lld wrote), and None when the map did not take the section, or
    with no `output`. The relaxation of a section depends on the target deltas of its calls, so each round relaxes
    every section with the target deltas of the round before, from 0, until they settle, as lld's passes do; past
    lld's last pass, none of them is known."""
    # The offset of each relocation of each section, and the most bytes that relaxation can remove in front of each
    # (most_removed) and in all: {row: ([offset], [the bytes in front of the k-th relocation, for each k, then all])}.
    bounds = {}
    for row, (rvc, entries) in relocated.items():
        sums = [0]
        for relocation, relaxable, _, _ in entries:
            sums.append(sums[-1] + most_removed(relocation, relaxable, rvc))
        bounds[row] = [relocation.offset for relocation, _, _, _ in entries], sums
    # Each relocation with its Call, which gets its removable, the most bytes that relaxation can remove in front of
    # the symbol of its target (None when the map did not take the target's section), and its target delta when no
    # address decides it (0 when its removable is 0, else None); and the target (row, anchor) of each Call whose
    # removable is neither, whose target delta this link's relaxation decides: {row: [(Relocation, relaxable, Call or
    # None, target or None)]}, with {target: the index k of the first relocation of its section at or past its anchor,
    # or the count of relocations when there is none}.
    targeted, firsts = {}, {}
    for row, (_, entries) in relocated.items():
        targeted[row] = []
        for relocation, relaxable, call, anchor in entries:
            target = None
            if call is not None:
                where, most = target_row(call), 0
                if where is not None and anchor != 0:
                    if where[0] is None:
                        most = None
                    elif where[0] in bounds:
                        offsets, sums = bounds[where[0]]
                        k = bisect.bisect_left(offsets, anchor)
                        most = sums[k]
                        if most:
                            target = (where[0], anchor)
                            firsts[target] = k
                call = call._replace(target_delta=0 if most == 0 else None, removable=most)
            targeted[row].append((relocation, relaxable, call, target))
    calls = {row: [(relocation, relaxable, call) for relocation, relaxable, call, _ in entries]
             for row, entries in targeted.items()}
    relaxed = {row: ([None] * len(entries), None) for row, entries in calls.items()}  # {row: ([delta], removed)}
    if output is not None:
        view = Layout(inputs, {}, output, {}, set())
        removed = dict.fromkeys(firsts, 0)  # {target: the target delta of the round before}
        for passes in range(RELAX_PASSES + 1):
            if passes == RELAX_PASSES:
                # Past lld's last pass, none of the target deltas is known.
                removed = dict.fromkeys(firsts)
            calls = {row: [(relocation, relaxable,
                            call if target is None else call._replace(target_delta=removed[target]))
                           for relocation, relaxable, call, target in entries]
                     for row, entries in targeted.items()}
            relaxed = {row: relaxation(lines[row].address, found, view, relocated[row][0])
                       for row, found in calls.items()}
            settled = {}
            for (row, anchor), k in firsts.items():
                deltas, total = relaxed[row]
                settled[(row, anchor)] = deltas[k] if k < len(deltas) else total
            if settled == removed or passes == RELAX_PASSES:
                break
            removed = settled
    return {row: [None if call is None else call._replace(delta=delta)
                  for (_, _, call), delta in zip(found, relaxed[row][0])]
            for row, found in calls.items()}


def relaxation(address, relocations, view, rvc):
    """lld's relaxation of a section of code at `address` in a static riscv64 link without --relax-gp (lld 20,
    lld/ELF/Arch/RISCV.cpp, relax()): ([delta], removed). `relocations` are the section's [(Relocation, relaxable,
    Call or None)] in lld's order (ordered_relocations), with the Call of each relocation of TARGETED; `view` a Layout
    of the link's inputs and Output, which give each target its address (target_address); `rvc` whether the object
    has EF_RISCV_RVC. Each delta is the bytes removed in front of that relocation (lld's delta: the relocation is at
    address + offset - delta), and `removed` the bytes removed in all. Each is None from the first relocation whose
    relaxation this does not know on.

    lld removes, for an R_RISCV_ALIGN, the nops past its alignment boundary: its addend is the bytes of the nops, and
    the alignment the next power of two at or above the addend plus 2. For an R_RISCV_CALL or R_RISCV_CALL_PLT that
    the next relocation marks R_RISCV_RELAX (lld's relaxable), 4 bytes when its target plus the addend lies in jal's
    reach of it (in_reach). For such an R_RISCV_TPREL_HI20 or R_RISCV_TPREL_ADD, 4 bytes when its variable plus the
    addend lies in the reach of a relaxed access from the start of the TLS segment (tls_relaxed). Nothing else
    removes bytes: R_RISCV_HI20 and R_RISCV_LO12_* only under --relax-gp, which the builder never passes.

    Not known: a relaxable call whose target has no address (an ifunc's call goes through lld's PLT entry), or in an
    object with compressed instructions (lld may write a 2-byte c.j); a relaxable access whose variable has no
    offset in the TLS segment; a relaxable R_RISCV_TLSDESC_*, of which lld removes bytes that this does not model;
    and an R_RISCV_ALIGN whose nops do not reach its boundary, which lld refuses."""
    deltas, delta = [], 0
    for relocation, relaxable, call in relocations:
        remove = 0
        if delta is not None:
            site = address + relocation.offset - delta
            if relocation.type == R_RISCV_ALIGN:
                remove = site + relocation.addend - align_up(site, 1 << (relocation.addend + 1).bit_length())
                remove = remove if remove >= 0 else None
            elif relocation.type in (R_RISCV_CALL, R_RISCV_CALL_PLT) and relaxable:
                target = None if rvc else target_address(call, view)
                remove = None if target is None else 4 if in_reach(site, target) else 0
            elif relocation.type in (R_RISCV_TPREL_HI20, R_RISCV_TPREL_ADD) and relaxable:
                offset = tls_offset(tls_address(call, view), view.output)
                remove = None if offset is None else 4 if tls_relaxed(offset) else 0
            elif relocation.type in R_RISCV_TLSDESC and relaxable:
                remove = None
        if remove is None:
            delta = None
        deltas.append(delta)
        if delta is not None:
            delta += remove
    return deltas, delta


def most_removed(relocation, relaxable, rvc):
    """The most bytes that lld's relaxation can remove at the relocation `relocation` of a section, which is
    `relaxable` when the next relocation in lld's order is R_RISCV_RELAX (ordered_relocations), wherever the link puts
    the section and its targets: an R_RISCV_ALIGN's nops (its addend); 4 bytes for a relaxable R_RISCV_CALL or
    R_RISCV_CALL_PLT, and 6 in an object with compressed instructions (`rvc`), where lld may write a 2-byte c.j; 4 for
    a relaxable R_RISCV_TPREL_HI20 or R_RISCV_TPREL_ADD; and 4 for an R_RISCV_TLSDESC_HI20, R_RISCV_TLSDESC_LOAD_LO12
    or R_RISCV_TLSDESC_ADD_LO12 (TLSDESC_REMOVED), each of which lld may remove. Nothing else removes a byte
    (relaxation)."""
    if relocation.type == R_RISCV_ALIGN:
        return max(relocation.addend, 0)
    if relocation.type in (R_RISCV_CALL, R_RISCV_CALL_PLT) and relaxable:
        return 6 if rvc else 4
    if relocation.type in (R_RISCV_TPREL_HI20, R_RISCV_TPREL_ADD) and relaxable:
        return 4
    return 4 if relocation.type in TLSDESC_REMOVED else 0


def removable_bytes(elf, section):
    """The most bytes that lld's relaxation can remove from the section `section` of the object `elf` in all,
    wherever the link puts it and its targets: the sum of most_removed over each of its relocations, in lld's order
    (by offset, as describe relaxes it). 0 for a section with no relocation that lets lld remove a byte, and for a
    section that holds no code (neither .text nor SHF_EXECINSTR), which describe never relaxes: lld relaxes code
    alone."""
    if not (is_text(section.name) or section.flags & SHF_EXECINSTR):
        return 0
    rvc = elf.flags & EF_RISCV_RVC
    return sum(most_removed(relocation, relaxable, rvc)
               for relocation, _, relaxable in ordered_relocations(elf, section))


def definitions(names, lines, located, rows):
    """{name: (row, value, type)}: where the link defines each of `names` in its own objects, the objects (archive
    members too) whose sections the map took: a defined global or weak symbol of that name in a section that a map
    line names (its row, its value in that section and its type, STT_GNU_IFUNC for an ifunc), a global one before a
    weak one, else the first in map order. lld writes a symbol of hidden visibility into the binary as a local one, so
    the binary's global symbols lack it; the objects give it. `lines` are the link's map lines, and `located` and
    `rows` matched_lines's."""
    found, seen = {}, set()
    for row, (instance, elf, _) in sorted(located.items()):
        where = (lines[row].file, lines[row].member, instance)
        if where in seen:
            continue
        seen.add(where)
        for symbol in elf.symbols():
            if symbol.name not in names or symbol.bind not in (STB_GLOBAL, STB_WEAK) \
                    or not SHN_UNDEF < symbol.shndx < SHN_LORESERVE:
                continue
            at = rows.get(where + (symbol.shndx,))
            rank = (symbol.bind != STB_GLOBAL, at)
            if at is not None and (symbol.name not in found or rank < found[symbol.name][0]):
                found[symbol.name] = (rank, (at, symbol.value, symbol.type))
    return {name: definition for name, (_, definition) in found.items()}


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
# The layout of a link (read_layout): its inputs [Input], its calls {row: [Call]}, its Output, its placement
# {(key_file, member, section, occurrence): Placement}, and `loaded`, the set of the rows whose map line the binary
# loads (read_map).
Layout = collections.namedtuple("Layout", "inputs calls output placement loaded")


def sections_rows(inputs):
    return [[i.file, i.key[0], i.key[1], i.section, i.sha256, str(i.size), str(i.align)] for i in inputs]


def calls_rows(calls):
    rows = []
    for c in calls:
        target = "-" if c.target is None else str(c.target)
        delta = "-" if c.delta is None else hex(c.delta)
        definition = ["-", "-"] if c.definition is None else [str(c.definition[0]), hex(c.definition[1])]
        target_delta = "-" if c.target_delta is None else hex(c.target_delta)
        rows.append([str(c.row), hex(c.offset), c.type, "1" if c.relax else "0", delta, c.kind, target,
                     hex(c.value)] + definition + [target_delta])
    return rows


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
    """{row: [Call]} from calls.tsv (module docstring), for a layout of `count` inputs, with no removable. Raise
    LayoutError for a line of any other shape."""

    def row_of(text):
        return int(text) if DECIMAL.fullmatch(text) and int(text) < count else None

    calls = collections.defaultdict(list)
    for number, fields in enumerate(tsv_rows(path), 1):
        call = None
        if len(fields) == 11 and row_of(fields[0]) is not None and fields[2] in LINE_TYPES.values() \
                and fields[3] in ("0", "1") and fields[5] in KINDS:
            row, offset, line_type, relax, kind, target, value = (row_of(fields[0]), hex_value(fields[1]), fields[2],
                                                                  fields[3] == "1", fields[5], fields[6],
                                                                  hex_value(fields[7]))
            delta = None if fields[4] == "-" else hex_value(fields[4])
            target_delta = None if fields[10] == "-" else hex_value(fields[10])
            known = offset is not None and offset >= 0 and value is not None and (
                fields[4] == "-" or delta is not None and delta >= 0) and (
                fields[10] == "-" or target_delta is not None and target_delta >= 0)
            undefined = fields[8:10] == ["-", "-"]
            at, defined = row_of(fields[8]), hex_value(fields[9])
            line = Call(row, offset, line_type, relax, delta, kind, target, value, None, target_delta, None)
            if known and kind == "local" and undefined and (target == "-" or row_of(target) is not None):
                call = line._replace(target=row_of(target))
            elif known and kind != "local" and target and undefined:
                call = line
            elif known and kind == "global" and target and at is not None and defined is not None and defined >= 0:
                call = line._replace(definition=(at, defined))
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
    hole, end or normal), its address, its cause (- or one of CAUSES) and the cause's detail (- for none). A build
    that fell back to its normal link (append_link) gives every line the place normal and the cause normal_layout, a
    mark of the build and not a cause of a function, with one reason as the detail: a placement.tsv in which some
    lines give normal_layout and others do not, or which gives two reasons, does not read."""
    found, marked, unmarked = {}, {}, None
    unpaired = ("-",) * 4
    for number, fields in enumerate(tsv_rows(path), 1):
        if (len(fields) != 12 or not DECIMAL.fullmatch(fields[3]) or fields[8] not in PLACES
                or hex_value(fields[9]) is None or fields[10] not in ("-", NORMAL_LAYOUT) + CAUSES
                or fields[10] == NORMAL_LAYOUT and fields[8] != "normal"
                or tuple(fields[4:8]) != unpaired and not DECIMAL.fullmatch(fields[7])):
            raise LayoutError(f"{path}: line {number} does not read")
        key = (fields[0], fields[1], fields[2], int(fields[3]))
        if key in found:
            raise LayoutError(f"{path}: line {number} names a section that an earlier line names")
        if fields[10] == NORMAL_LAYOUT:
            marked.setdefault(fields[11], number)
        elif unmarked is None:
            unmarked = number
        base = None if tuple(fields[4:8]) == unpaired else (fields[4], fields[5], fields[6], int(fields[7]))
        found[key] = Placement(base, fields[8], hex_value(fields[9]), fields[10], fields[11])
    if marked and unmarked is not None:
        raise LayoutError(f"{path}: line {min(marked.values())} gives {NORMAL_LAYOUT}, and line {unmarked} does not: "
                          "a build that fell back to its normal link gives it on every line")
    if len(marked) > 1:
        first, second = sorted(marked.values())[:2]
        raise LayoutError(f"{path}: lines {first} and {second} give {NORMAL_LAYOUT} with two reasons: a build that "
                          "fell back to its normal link gives one")
    return found


def normal_layout(placement):
    """The reason that the placement {key: Placement} (read_placement) of a build that fell back to its normal link
    gives with normal_layout, or None for any other placement."""
    return next((p.detail for p in placement.values() if p.cause == NORMAL_LAYOUT), None)


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
    return Layout(inputs, calls, output, placement, {row for row, line in enumerate(lines) if line.loaded})


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


def key_file_for(renamed, real):
    """key_file(file), for describe: the file that the key of a section of `file`, a file a link's map names, names:
    for a copy that an allocation-failure link made, its original, and else `file`. `renamed` is the link's renamed
    (read_renamed), and `real(file)` gives the real path of `file`."""

    # collect (collect_target) and append (append_link) both key a copy with this rule, and must: when they key it
    # differently, compare finds no line of NEW's placement.tsv for the copy's sections. renamed names a copy by the
    # path the link was given, which is the map's name for it; check_links reads it by the real path, which is the same
    # path unless a directory on the way is a link. So a copy is keyed by the map's name, and else by its real path.
    def key_file(file):
        if file in renamed:
            return renamed[file]
        return renamed.get(real(file), file)

    return key_file


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

    key_file = key_file_for(renamed, lambda file: inputs[file][0])
    output = output_rows(Elf(binary, name))
    inputs_of, calls = describe(read_map(text_of(mapping)), Objects(read), key_file, wraps, output_of(output, name))
    files = {
        "map": mapping,
        "sections.tsv": tsv(sections_rows(inputs_of)),
        "calls.tsv": tsv(calls_rows(calls)),
        "output.tsv": tsv(output),
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

Pairing = collections.namedtuple("Pairing", "partner same repeated twins")


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
    (`same`, same_bytes), the keys that occur more than once on either side (`repeated`), and those of them in which
    two of the sections on one side have the same section name, sha256 (not empty) and input size (`twins`).
    The trees cannot tell twins apart: step 3 pairs them in map order, the order in which lld took their archive
    members, which a change of the code can turn. Two such sections of one object, whose order lld keeps, are twins
    too, since a tree does not record which object of a key holds a section."""
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
    twins = set()
    for side in (base, new):
        found = collections.Counter((i.key, content(i)) for i in side if i.sha256)
        twins.update(key for (key, _), n in found.items() if n > 1)
    return Pairing({i.row: partner[i.row].row if i.row in partner else None for i in new},
                   {i.row: i.row in partner and same_bytes(partner[i.row], i) for i in new},
                   repeated, twins)


def kept_run(key, base, new, pairing):
    """Whether the members of the repeated key `key` could all keep their base addresses under one lld pattern: as
    many on both sides, each same-bytes with its partner, side by side at the base (no other .text input section
    between them in BASE's address order), in the same order in NEW's addresses, and no two of them on one side with
    the same bytes (pairing.twins). The map does not tell twins apart, and lld may take their archive members in
    another order: one pattern would then put each twin where the other was at the base, which would read as kept."""
    if key in pairing.twins:
        return False
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


def tls_relaxed(offset):
    """Whether lld removes the lui and the add of a local-exec thread-local access whose variable, plus the addend,
    lies `offset` bytes from the start of the TLS segment."""
    return TLS_REACH[0] <= offset <= TLS_REACH[1]


def tls_offset(address, output):
    """The offset of `address` from the start of the TLS segment of an output.tsv reading (Output), the lowest
    address of an output section with SHF_TLS: for a thread-local variable, the value whose size decides whether lld
    relaxes an access to it. It does not depend on where .text puts the function. None when either is not there."""
    start = min((s.addr for s in output.sections if s.flags & SHF_TLS), default=None)
    return None if address is None or start is None else address - start


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
    """A line's target as calls.tsv and the detail of jal_reach and tls_reach name it: row:<row>+<value>, or the
    symbol's name."""
    if call.kind == "local":
        return f"row:{'-' if call.target is None else call.target}+{hex(call.value)}"
    return call.target


def target_row(call):
    """(row, value): the input section that the target of the calls.tsv line `call` lies in, and how far into it: a
    local symbol's section (row None when the map did not take it), or a global's definition. None for a target that
    no object of the link defines (symbol_address gives its address) and for an ifunc."""
    if call.kind == "local":
        return call.target, call.value
    if call.definition is None:
        return None
    return call.definition[0], call.definition[1] + call.value


def symbol_address(call, symbols):
    """The address of the target of a calls.tsv line that target_row places in no input section, from a binary's
    global symbols `symbols` ({name: address}): its symbol plus the addend; for an undefined weak reference that the
    binary does not name, the addend (lld's value of an undefined weak symbol in a static link is 0). None for an
    ifunc, whose call goes through lld's PLT entry, and for a global that the binary does not name."""
    if call.kind == "ifunc":
        return None
    address = symbols.get(call.target)
    if address is None:
        return call.value if call.kind == "weak" else None
    return address + call.value


def target_address(call, layout):
    """The address that the target of the calls.tsv line `call` has in a layout, or None: the address of its section
    (target_row) plus the value, less the bytes that the layout's relaxation removed in front of the target there
    (its target_delta: None when they are not known), or else symbol_address with the binary's symbols."""
    found = target_row(call)
    if found is None:
        return symbol_address(call, layout.output.symbols)
    row, value = found
    if row is None or call.target_delta is None:
        return None
    return layout.inputs[row].address + value - call.target_delta


def tls_address(line, layout):
    """The address that the target of the tprel line `line` has in a layout (target_address), or None for a target
    that no object of the link defines: the binary gives a thread-local symbol's offset in the TLS segment as its
    value, not its address, so only the map gives the address of a thread-local variable."""
    return None if target_row(line) is None else target_address(line, layout)


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
    if cause in ("jal_reach", "tls_reach"):
        found = re.fullmatch(r"offset=(0x[0-9a-f]+);target=(.+);(lost|gained)", detail)
        if not found:
            return "the detail does not read as offset=0x<offset>;target=<target>;lost or gained"
        offset, named, lost = int(found.group(1), 16), found.group(2), found.group(3) == "lost"
        line_type, what = ("call", "call") if cause == "jal_reach" else ("tprel", "thread-local access")
        then = next((c for c in base.calls.get(old.row, [])
                     if c.type == line_type and c.offset == offset and call_target(c) == named), None)
        if then is None:
            return f"BASE's calls.tsv gives the function no such {what}"
        now = next((c for c in new.calls.get(fn.row, []) if c.type == line_type and c.offset == offset), None)
        if now is None:
            return f"NEW's calls.tsv gives the function no {what} at that offset"
        if not (then.relax and now.relax):
            return (f"the {what} has no R_RISCV_RELAX in {'NEW' if then.relax else 'BASE'}'s calls.tsv (relax 0): "
                    "lld never relaxes it")
        before, after = target_address(then, base), target_address(now, new)
        if cause == "jal_reach":
            if then.delta is None:
                return ("BASE's calls.tsv gives no delta for the call: the bytes that relaxation removed in front of "
                        "it, and so its base call site, are not known")
            site = old.address + offset - then.delta
            if before is None or after is None:
                return "a target of the call has no address in its tree"
            reach = (in_reach(site, before), in_reach(site, after))
            if reach != (lost, not lost):
                return (f"from the base call site {hex(site)}, the base target {hex(before)} is "
                        f"{'in' if reach[0] else 'out of'} reach and the new target {hex(after)} "
                        f"{'in' if reach[1] else 'out of'} reach")
            return None
        before, after = tls_offset(tls_address(then, base), base.output), tls_offset(tls_address(now, new), new.output)
        if before is None or after is None:
            return "a target of the thread-local access has no offset in the TLS segment of its tree"
        reach = (tls_relaxed(before), tls_relaxed(after))
        if reach != (lost, not lost):
            return (f"the base target lies {hex(before)} bytes into the TLS segment, {'in' if reach[0] else 'out of'} "
                    f"the reach of a relaxed access, and the new target {hex(after)}, "
                    f"{'in' if reach[1] else 'out of'} it")
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


def text_change(base, new):
    """check's line of the start and the size of .text in two layouts."""
    text = [text_load(layout.output)[0] for layout in (base, new)]
    return "  .text: start {} -> {}, size {} -> {}".format(*[hex(s.addr) if s else "-" for s in text],
                                                            *[s.size if s else "-" for s in text])


def compare(label, base, new):
    """The comparison of one (build, target) of two layouts: (failures, information), each a list of lines. An append
    build that fell back to its normal link (normal_layout) fails nothing, and its information is `<label>: normal
    layout: <reason>` and the line of .text: a normal link keeps no base address, so the build claims none, and the
    reason is not verified."""
    reason = normal_layout(new.placement)
    if reason is not None:
        return [], [f"{label}: normal layout: {reason}", text_change(base, new)]
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
            if i.key in pairing.twins:
                failures.append(f"FAIL {label}: {function(i)}: address {hex(i.address)}, linked size {i.linked}: it "
                                "has the same bytes and lies at its partner's base address, but two sections of its "
                                "key have the same bytes, which the trees cannot tell apart, and lld may take their "
                                "archive members in another order: the trees do not show that the section at that "
                                "address is the base's own, so it must move, with repeated_key")
                continue
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
    lines.append(text_change(base, new))
    others = pair(base.inputs, new.inputs, kind=lambda name: not is_text(name))
    for i in new.inputs:
        partner = others.partner.get(i.row)
        if partner is None or not others.same[i.row]:
            continue
        old = base.inputs[partner]
        if old.address != i.address and old.row in base.loaded and i.row in new.loaded:
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
    lines, failed, normal = [], 0, 0
    for build, target in shared:
        old, new = read_layout(below(base_tree, build, target)), read_layout(below(new_tree, build, target))
        failures, found = compare(f"{build}/{target}", old, new)
        failed += bool(failures)
        normal += normal_layout(new.placement) is not None
        lines += found[:1] + failures + found[1:]
    for line in lines:
        print(line)
    for entry in base_entries:
        if entry not in new_entries:
            print(f"only in BASE: {entry[0]}/{entry[1]}")
    for entry in new_entries:
        if entry not in base_entries:
            print(f"only in NEW: {entry[0]}/{entry[1]}")
    print(f"layout check: {len(shared) - failed} of {len(shared)} (build, target) pass"
          + (f", {normal} with a normal layout" if normal else ""))
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
    """The probe link fails, as the normal link of the same command would: append exits 1."""


class Fallback(Exception):
    """Why the append mode cannot keep the base's addresses in a link, which then falls back to its normal link
    (append_link): a section that a plan keeps has a call or a thread-local access that lld may relax and that the plan
    does not test or decide, a check link fails or is not what the plan asks, or a file or section name holds a double
    quote or a line break, which the script cannot quote. Its text is the reason, for a person: it names the function
    and its call, or the line of the script."""


# Where the append mode puts a .text input section of the link: `place` (kept, hole, end, or normal for a normal
# link), its address, and for a same-bytes section that moves, the cause and its detail (- for none); for each
# section of a link that fell back to its normal link, normal_layout and the reason.
Place = collections.namedtuple("Place", "place address cause detail")
# A call of a same-bytes .text input section, as the append mode tests it at the section's base address: its offset,
# the bytes that relaxation removed in front of it at the base (BASE's delta), its target as BASE's call at that
# offset names it (call_target), the base call site (the section's base address plus the offset, less the delta) and
# the base target's address, the link's own call, and where the link's target is: in the .text input section `row`,
# `value` bytes into it, or, with row None, at the address `value`, which lies in the tail after .text (segment_tail)
# when `tail` is true. lld's relaxation may remove up to the call's removable bytes in front of the target, wherever
# the plan puts its section. `fixed` is the target's address when its section stays at its base address with the
# base's relaxation: the base address plus the value when no byte can be removed in front of the target, else BASE's
# target address when BASE's call names the same target (the base partner of its section, at the same value), else
# None.
CallTest = collections.namedtuple("CallTest", "offset delta target site before call row value tail fixed")
# A thread-local access of a same-bytes .text input section (a tprel line), as the append mode tests it: its offset,
# its target as BASE's line at that offset names it (call_target), the base target's offset from the start of BASE's
# TLS segment (tls_offset), and the link's own line.
TlsTest = collections.namedtuple("TlsTest", "offset target before call")
# What call_tests or tls_tests gives for the same-bytes .text input sections of a link: `tests` {row: [CallTest or
# TlsTest], in offset order}, and `skipped` {row: [(the link's calls.tsv line, why it is not tested, for a person)], in
# offset order}, for each line of that type that lld may relax (relax 1 on a side) and that is not tested.
Tests = collections.namedtuple("Tests", "tests skipped")
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


def reach_over(site, low, high):
    """Whether jal reaches each address from `low` to `high` from the call site `site` (True), none of them (False),
    or some of them only (None)."""
    first, last = in_reach(site, low), in_reach(site, high)
    if first != last or not first and low - site < JAL_REACH[0] and high - site > JAL_REACH[1]:
        return None
    return first


def otherwise(test, site, span):
    """Whether lld relaxes the call `test` at `site` against a target in `span` (low, high) otherwise than at its base
    call site against its base target: True or False, or None when that depends on where in `span` the target lies
    (reach_over) or `span` is None (not known)."""
    reach = None if span is None else reach_over(site, *span)
    return None if reach is None else reach != in_reach(test.site, test.before)


def moved_span(test, address):
    """(low, high): where the target of the call `test` may lie when lld puts its section at `address`, which lld's
    relaxation there may move down by up to the call's removable bytes."""
    return address + test.value - test.call.removable, address + test.value


def tls_otherwise(test, offset):
    """Whether lld relaxes the thread-local access `test` when its target lies `offset` bytes into the TLS segment
    and not at its base offset, or the other way round. False when `offset` is None."""
    return offset is not None and tls_relaxed(test.before) != tls_relaxed(offset)


def reach_cause(test):
    """(cause, detail) of a kept section that the test `test` moves, as unshown reads them: jal_reach for a call
    (CallTest), tls_reach for a thread-local access (TlsTest)."""
    if test.call.type == "tprel":
        cause, relaxed = "tls_reach", tls_relaxed(test.before)
    else:
        cause, relaxed = "jal_reach", in_reach(test.site, test.before)
    return cause, f"offset={hex(test.offset)};target={test.target};{'lost' if relaxed else 'gained'}"


def paired_lines(base, probe, pairing, line_type):
    """(the link's Input, its BASE partner, the link's line, BASE's line at the same offset or None when BASE's
    partner has none) for each calls.tsv line of the type `line_type` of each same-bytes .text input section of the
    link `probe` (Layout): in row order, then in offset order."""
    for i in probe.inputs:
        if not (is_text(i.section) and pairing.same[i.row]):
            continue
        old = base.inputs[pairing.partner[i.row]]
        then = {}
        for line in base.calls.get(old.row, []):
            if line.type == line_type:
                then.setdefault(line.offset, line)
        for line in sorted(probe.calls.get(i.row, []), key=lambda c: c.offset):
            if line.type == line_type:
                yield i, old, line, then.get(line.offset)


def untestable(line, before):
    """Why the append mode cannot test whether lld relaxes the calls.tsv line `line` of a same-bytes .text input
    section as BASE's line `before` at the same offset (None when BASE has none), by what the two lines say: None
    when they say nothing against a test. `line` or `before` has relax 1. A local symbol of a section with no row of
    its own lies in a twin or an ambiguous map line (describe), which the tree cannot place, or in a section that the
    map did not take."""
    if before is None:
        return "BASE's calls.tsv has no such line"
    if not (line.relax and before.relax):
        return "only one link has R_RISCV_RELAX for it"
    if "ifunc" in (line.kind, before.kind):
        return "its target is an ifunc, whose call goes through lld's PLT entry, whose address no tree holds"
    if any(c.kind == "local" and c.target is None for c in (line, before)):
        return ("its target is a local symbol of a section that has no row: a twin or an ambiguous line of the map, "
                "which the tree cannot place, or a section that the map did not take")
    return None


def call_tests(base, probe, pairing, tail):
    """The tests of the calls of each same-bytes .text input section of the link `probe` (Layout), and each call that
    lld may relax and that is not tested, with why (Tests). A call with relax 0 on both sides is never relaxed, so it
    never changes, and needs no test. A call is tested when BASE's partner has a call at the same offset, both lines
    have relax 1, the two lines say nothing against a test (untestable), BASE's line has a delta, and both targets
    have an address. Its base call site is BASE's address of the section plus the offset, less BASE's delta: lld's
    site of the call at the base, and in a link that keeps the section there with the base's relaxations in front of
    the call. The link's target is in the .text input section that holds it: the section of a local symbol or of a
    global's definition (target_row), or, for a target that no object defines, the section at its address in the
    link's output (symbol_address). A target in no .text input section keeps the link's address, and is marked when
    it lies in the tail after .text in its PT_LOAD, `tail` (the probe link's segment_tail, as the caller computed it,
    or None), which lld lays out wherever .text ends. Where a section that stays at its base address puts the target
    (`fixed`) comes from the base: lld relaxes the section there as at the base, so BASE's target address holds when
    BASE's call names the same target; when it names another, and lld may remove bytes in front of the target, the
    plan does not know where the target lies."""
    text = sorted((i for i in probe.inputs if is_text(i.section) and i.linked), key=lambda i: (i.address, i.row))
    starts = [i.address for i in text]

    def outside(address):
        return None, address, tail is not None and tail[0] <= address < tail[0] + tail[1]

    def where(call):
        found = target_row(call)
        if found is not None:
            row, value = found
            if row is None:
                return None
            target = probe.inputs[row]
            return (row, value, False) if is_text(target.section) else outside(target.address + value)
        address = symbol_address(call, probe.output.symbols)
        if address is None:
            return None
        k = bisect.bisect_right(starts, address) - 1
        if k >= 0 and address < text[k].address + text[k].linked:
            return text[k].row, address - text[k].address, False
        return outside(address)

    tests, skipped = {}, {}
    for i, old, call, before in paired_lines(base, probe, pairing, "call"):
        if not (call.relax or before is not None and before.relax):
            continue
        why = untestable(call, before)
        if why is None and before.delta is None:
            why = "the bytes that relaxation removed in front of it at the base are not known"
        if why is None:
            before_address, now = target_address(before, base), where(call)
            if before_address is None:
                why = ("the bytes that relaxation removed in front of its target at the base are not known"
                       if target_row(before) is not None else "its target has no address at the base")
            elif now is None:
                why = "its target has no address in this link"
        if why is not None:
            skipped.setdefault(i.row, []).append((call, why))
            continue
        row, value, _ = now
        fixed = None
        if row is not None and pairing.partner.get(row) is not None:
            if not call.removable:
                fixed = base.inputs[pairing.partner[row]].address + value
            elif target_row(before) == (pairing.partner[row], value):
                fixed = before_address
        tests.setdefault(i.row, []).append(CallTest(call.offset, before.delta, call_target(before),
                                                    old.address + call.offset - before.delta, before_address, call,
                                                    *now, fixed))
    return Tests(tests, skipped)


def tls_tests(base, probe, pairing):
    """The tests of the thread-local accesses of each same-bytes .text input section of the link `probe` (Layout),
    and each access that lld may relax and that is not tested, with why (Tests). An access with relax 0 on both sides
    is never relaxed, and needs no test. An access is tested when BASE's partner has one at the same offset, both
    lines have relax 1, the two lines say nothing against a test (untestable), and both targets lie in a TLS segment.
    Its offset there does not depend on where .text puts the function: the probe link gives the one of every link of
    its inputs."""
    tests, skipped = {}, {}
    for i, _, line, before in paired_lines(base, probe, pairing, "tprel"):
        if not (line.relax or before is not None and before.relax):
            continue
        why = untestable(line, before)
        if why is None:
            offset = tls_offset(tls_address(before, base), base.output)
            if offset is None:
                why = "its target has no offset in BASE's TLS segment"
            elif tls_offset(tls_address(line, probe), probe.output) is None:
                why = "its target has no offset in this link's TLS segment"
        if why is not None:
            skipped.setdefault(i.row, []).append((line, why))
            continue
        tests.setdefault(i.row, []).append(TlsTest(line.offset, call_target(before), offset, line))
    return Tests(tests, skipped)


def untested(skipped, undecided):
    """For a person, each call and thread-local access of a same-bytes .text input section that lld may relax and that
    the append mode does not test or does not decide, and why ([str], in offset order): `skipped` are the section's
    lines of call_tests' and tls_tests' skipped, each with why, and `undecided` [(CallTest, span)] its calls whose
    target lies in a span (planned_span or linked_span: (low, high), or None when it is not known) that does not tell
    whether lld relaxes the call otherwise (otherwise gives None)."""
    found = list(skipped)
    for test, span in undecided:
        if span is None:
            why = ("lld's relaxation may remove bytes in front of its target in a section that keeps its base address, "
                   "and BASE's call names another target: the plan does not know where the target lies")
        else:
            why = (f"lld's relaxation may remove up to {test.call.removable} bytes in front of its target in the "
                   f"target's section, so that the target lies somewhere from {hex(span[0])} to {hex(span[1])}: in "
                   "jal's reach of the call or out of it")
        found.append((test.call, why))
    return [f"the {'call' if line.type == 'call' else 'thread-local access'} at offset {hex(line.offset)} "
            f"({call_target(line)}): {why}" for line, why in sorted(found, key=lambda item: item[0].offset)]


def kept_set(base, probe, pairing, forced):
    """The .text input sections of the link `probe` that keep their base addresses ({row: BASE's partner}), and the
    cause of each same-bytes one that moves ({row: (cause, detail)}). A same-bytes section is kept, unless: `forced`
    ({row: CallTest or TlsTest}) names it (jal_reach or tls_reach, reach_cause); its base address does not meet its
    alignment now (alignment); or its key repeats (pairing.repeated). The members of such a key are kept, each at its
    base address, when one pattern keeps them all (kept_run, never for a key with twins) and none moves for a cause
    of its own; else the same-bytes ones move with repeated_key."""
    text = [i for i in probe.inputs if is_text(i.section)]
    kept, causes = {}, {}
    for i in text:
        if not pairing.same[i.row]:
            continue
        old = base.inputs[pairing.partner[i.row]]
        if i.row in forced:
            causes[i.row] = reach_cause(forced[i.row])
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


def taken(i):
    """The bytes that a moved input section of the probe link takes: the larger of its input size and its linked size
    there. lld's relaxation only removes bytes, so with lld that is its input size."""
    return max(i.size, i.linked)


def lay(unit, start):
    """The address of each input section of `unit` laid out from `start` in order, each at its alignment and with
    the bytes it takes (taken), and the address after the last."""
    at, addresses = start, []
    for i in unit:
        at = align_up(at, i.align)
        addresses.append(at)
        at += taken(i)
    return addresses, at


def allowed(unit, addresses, own, wanted):
    """Whether the input sections of `unit` may go to `addresses`: none at its own base address (`own`), and each
    call into one that `wanted` names ({row: [(CallTest, whether it must be relaxed otherwise)]}) relaxed so,
    wherever lld's relaxation there puts its target (moved_span)."""
    for i, at in zip(unit, addresses):
        if own.get(i.row) == at:
            return False
        for test, change in wanted.get(i.row, ()):
            if otherwise(test, test.site, moved_span(test, at)) != change:
                return False
    return True


def planned_span(test, planned, kept, shift):
    """(low, high): where the target of the call `test` may lie when each .text input section is at its address in
    `planned`, the sections `kept` at their base addresses, and the tail after .text (segment_tail) `shift` bytes from
    where the probe link put it; None when that is not known. A kept section keeps the base's relaxation: its target
    is at the test's fixed address. lld relaxes each other section where it puts it, and so may move a target there
    down by up to the call's removable bytes (moved_span), as one outside .text."""
    if test.row is None:
        return moved_span(test, shift if test.tail else 0)
    if test.row in kept:
        return None if test.fixed is None else (test.fixed, test.fixed)
    return moved_span(test, planned[test.row])


def relaxed_call(tests, planned, kept, shift):
    """The first of the calls `tests` ([CallTest]) that is relaxed otherwise at its base call site against its
    planned target (planned_span), wherever in its span the target lies, or None."""
    return next((t for t in tests if otherwise(t, t.site, planned_span(t, planned, kept, shift))), None)


def returned(returning, tests, partner, planned, kept, shift):
    """The return of the sections that the rounds of plan moved with jal_reach: (back, causes). `returning` are [the
    rows of each such section, with the other members of its key], `tests` ({row: [CallTest]}), `partner` ({row:
    BASE's partner}), `planned` ({row: address}), `kept` ({row: BASE's partner}) and `shift` (planned_span) the plan's.
    A section returns to its base address, with the other members of its key, when none of their calls is relaxed
    otherwise at its base call site against the plan (relaxed_call): this keeps them, in `kept` and `planned`. A
    return only puts targets back at their base addresses, so the sections that did not return are tested again,
    until none returns. `back` is the set of the rows that returned, and `causes` ({row: (cause, detail)}) the cause
    of each row of a section that stays: jal_reach and the first of its calls that is relaxed otherwise against the
    final plan (reach_cause), or repeated_key for a member of its key with no such call."""
    back, more = set(), True
    while more:
        more = False
        for rows in returning:
            if rows[0] in back or any(relaxed_call(tests.get(row, []), planned, kept, shift) for row in rows):
                continue
            for row in rows:
                kept[row], planned[row] = partner[row], partner[row].address
            back.update(rows)
            more = True
    causes = {}
    for rows in returning:
        if rows[0] not in back:
            for row in rows:
                test = relaxed_call(tests.get(row, []), planned, kept, shift)
                causes[row] = ("repeated_key", "-") if test is None else reach_cause(test)
    return back, causes


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


def segment_tail(probe, internal):
    """(P, bytes, A) of the tail of the probe link, what it puts after .text in the PT_LOAD that holds .text (an
    output section of libc++'s overrides, __lcxx_override, for one): P the end of its .text output section, bytes
    the bytes from P to the end of that PT_LOAD (0 when no PT_LOAD holds .text), and A the largest alignment of the
    loaded input sections there (1 when there are none): the probe's inputs, and the lines of the linker's own
    sections of its map `internal` ([MapLine], map_entries), such as .iplt, which read_map leaves out. lld lays the
    tail out after .text wherever .text ends, each output section at its alignment, which divides A: when .text ends
    at an address E that lies a multiple of A from P, each tail section lies E - P bytes from where the probe link
    put it, and the PT_LOAD ends at E + bytes. None when the probe link has no .text."""
    text, holder = text_load(probe.output)
    if text is None:
        return None
    start = text.addr + text.size
    if holder is None:
        return start, 0, 1
    load = probe.output.loads[holder]
    end = load.vaddr + load.memsz
    aligns = [i.align for i in probe.inputs if i.row in probe.loaded and start <= i.address < end]
    aligns += [line.align for line in internal if line.loaded and start <= line.address < end]
    return start, max(end - start, 0), max(aligns + [1])


def quotable(name):
    """`name`, which the script quotes. Raise Fallback for a quote or a line break, which a quoted name cannot
    hold."""
    if '"' in name or "\n" in name:
        raise Fallback(f"{name!r} holds a double quote or a line break, which a linker script cannot name")
    return name


def script_name(name):
    """A section's name in the script: bare when lld reads it bare as the exact name, else quoted."""
    return name if BARE.fullmatch(name) else f'"{quotable(name)}"'


def pattern(i):
    """The script's pattern of the input section `i`: the file as the map names it (<archive>:<member> for a member
    of an archive), quoted, which lld reads as the exact name with no wildcard, and the section."""
    file = i.file if i.member is None else f"{i.file}:{i.member}"
    return f'"{quotable(file)}"({script_name(i.section)})'


def plan(base, probe, pairing, forced=None, internal=()):
    """The plan (Plan) of an append link: where each .text input section of the probe link `probe` (Layout, with no
    placement) goes against the base layout `base`, with the pairing `pairing` (pair). It reads no file and runs
    nothing. `forced` ({row: CallTest or TlsTest}) names kept sections that the check after the link moves with
    jal_reach or tls_reach: they never return to their base addresses, where the check link would move them again,
    so that the links of append end. `internal` ([MapLine]) are the lines of the linker's own sections of the probe
    link's map (map_entries), which segment_tail counts.

    When the read-only data in front of .text grew past its room (readonly_growth), the link is a normal one: no
    script, each section at the probe's address. Else a same-bytes section with a thread-local access that lld
    relaxes otherwise in the probe link than at the base (tls_tests) moves with tls_reach: it changes size wherever
    it goes. Each same-bytes section that kept_set keeps occupies its base address and base linked size, and the
    holes are the gaps between them from the base's .text address, less the base ranges that are reserved (below).
    Each other section moves: largest first, by the bytes it takes (taken; ties: the probe map's order), into the
    first hole in address order where it fits at its alignment, never at its own base address, and where each call
    from a kept section into it is relaxed as at the base wherever lld's relaxation there puts the target (allowed);
    else to the end of .text, one after another, past every reserved range. The members of a repeated key that move
    are one block: one pattern places them all, in input order. .text ends at E, the first address at or after the
    planned end whose distance from P is a multiple of A (segment_tail), so that lld lays the tail after .text out
    E - P bytes from where the probe link put it. Then each call of each kept section is tested at its base call site
    against its planned target (planned_span: in a kept section where the base put it, in the tail at its probe
    address plus E - P, and in a section that moves anywhere down to the most bytes that lld's relaxation can remove
    in front of it there): a kept section with a call relaxed otherwise wherever in that span the target lies moves
    with jal_reach, and the placement runs again with the larger set of moved sections. A call that its span does not
    decide moves nothing. Each round moves one section more, so it ends. A section that a round moves may return: its
    base range, and those of the other members of its key, are reserved in the next rounds, and no other section goes
    there.

    Then each section that may return, with the other members of its key, returns to its base address when none of
    their calls is relaxed otherwise at its base call site against the plan: it was kept in a round, so one pattern
    keeps the members of its key, and none of them has another cause. Nothing else moves: its slot stays empty, and
    the end of .text and E stay. A return only puts targets back at their base addresses, where a kept section's
    call into one is relaxed as at the base; a section whose cause rested on a call into one is tested again, until
    none returns. Each section that stays moves with jal_reach and the first of its calls that is relaxed otherwise
    against the final plan, which the two layouts then show (unshown), and a member of its key with no such call
    moves with repeated_key, which the member with one shows (dragged).

    A section that the final plan keeps is linked only when the plan tests and decides each of its calls and
    thread-local accesses that lld may relax: else lld may relax it otherwise than at the base, and two such calls
    that lld relaxed the other way round would keep the section's size, not its bytes. Raise Fallback, naming the
    first kept section with a call or an access that call_tests or tls_tests skips, or with a call that its
    planned_span does not decide (otherwise gives None), and that call (untested); and, for a file or section name
    that holds a double quote or a line break, quotable does.

    The script puts .text at the base's address and each section, a kept run or a moved block once, at its address
    in address order, and ends .text with `. = E;`, so that .text ends at E however much lld relaxes the sections at
    the end. When E plus the bytes of the tail is at or below page_floor of the start S of BASE's next PT_LOAD, the
    script keeps that PT_LOAD at S: the first section of the probe's next PT_LOAD at S with an empty body, which lld
    fills in its own order (next_segment)."""
    text = [i for i in probe.inputs if is_text(i.section)]
    figures = readonly_growth(base.output, probe.output)
    if figures is not None and figures[0] > figures[1]:
        cause = ("readonly_growth", "growth={};room={}".format(*figures))
        places = {i.row: Place("normal", i.address, *(cause if pairing.same[i.row] else ("-", "-"))) for i in text}
        return Plan(places, None, {}, None, figures)
    base_text, _ = text_load(base.output)
    if base_text is None:
        raise LayoutError("BASE's output.tsv has no .text")
    tail = segment_tail(probe, internal)
    if tail is None:
        raise LayoutError("the probe link's output.tsv has no .text")
    probe_end, tail_bytes, tail_align = tail
    start = base_text.addr
    calls, accesses = call_tests(base, probe, pairing, tail), tls_tests(base, probe, pairing)
    tests = calls.tests
    partner = {i.row: base.inputs[pairing.partner[i.row]] for i in text if pairing.partner[i.row] is not None}
    forced = dict(forced or {})
    for row, found in accesses.tests.items():
        test = next((t for t in found if tls_otherwise(t, tls_offset(target_address(t.call, probe), probe.output))),
                    None)
        if test is not None:
            forced.setdefault(row, test)
    # The rows of each section that a round moved with jal_reach, with the other members of its key: they may return.
    returning = []
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
        units.sort(key=lambda unit: (-sum(taken(i) for i in unit), unit[0].row))
        own = {i.row: partner[i.row].address for i in movers if i.row in partner}
        # A call from a kept section must be relaxed as at the base; the call that moved a section with jal_reach
        # must stay relaxed otherwise, so that its cause holds.
        wanted = collections.defaultdict(list)
        for row in sorted(kept):
            for test in tests.get(row, []):
                if test.row is not None and test.row not in kept:
                    wanted[test.row].append((test, False))
        for row, test in sorted(forced.items()):
            if test.call.type == "call" and test.row is not None and test.row not in kept:
                wanted[test.row].append((test, True))
        ranges = [(old.address, old.address + old.linked) for old in kept.values()]
        ranges += [(partner[row].address, partner[row].address + partner[row].linked)
                   for rows in returning for row in rows]
        holes, end = [], start
        for low, high in sorted(ranges):
            if low > end:
                holes.append([end, low])
            end = max(end, high)
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
        # .text ends at E (text_end), a multiple of A from P, so that the tail lies E - P (shift) bytes further than in
        # the probe link.
        text_end = end + (probe_end - end) % tail_align
        shift = text_end - probe_end
        moved = {}
        for row in sorted(kept):
            test = relaxed_call(tests.get(row, []), planned, kept, shift)
            if test is not None:
                moved[row] = test
        if not moved:
            break
        forced.update(moved)
        for row in sorted(moved):
            key = probe.inputs[row].key
            rows = tuple(i.row for i in text if i.key == key) if key in pairing.repeated else (row,)
            if rows not in returning:
                returning.append(rows)
    # Each section that may return does when none of its calls, nor of the other members of its key, is relaxed
    # otherwise against the plan, until none does; each that stays names a call that is.
    back, stays = returned(returning, tests, partner, planned, kept, shift)
    causes.update(stays)
    # A kept section whose calls and thread-local accesses the plan does not all test and decide is never linked.
    for i in text:
        if i.row in kept:
            spans = [(t, planned_span(t, planned, kept, shift)) for t in tests.get(i.row, [])]
            why = untested(calls.skipped.get(i.row, []) + accesses.skipped.get(i.row, []),
                           [(t, span) for t, span in spans if otherwise(t, t.site, span) is None])
            if why:
                raise Fallback(f"{function(i)}: the plan keeps it at {hex(planned[i.row])}, and the append mode "
                               f"cannot test {why[0]}")
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
    items += [(planned[unit[0].row], unit[0].row, unit[0]) for unit in units if unit[0].row not in back]
    order = alloc_order(probe.output)
    at = next((k for k, (_, _, name) in enumerate(order) if name == ".text"), None)
    if not at:
        raise LayoutError("the probe link has no SHF_ALLOC section before .text")
    out, lines = ["SECTIONS", "{", f"  .text {hex(start)} :", "  {"], {}
    for address, row, i in sorted(items, key=lambda item: item[:2]):
        out += [f"    . = {hex(address)};", f"    {pattern(i)}"]
        lines[len(out)] = row
    out += [f"    . = {hex(text_end)};", "  }", "}", f"INSERT AFTER {script_name(order[at - 1][2])};"]
    found, next_start = next_segment(base.output, probe.output), None
    if found is not None and text_end + tail_bytes <= page_floor(found[0]):
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
    """The address that the target of the calls.tsv line `call` of the probe link has in the check link `link`
    (Link): the address there of its section (target_row) plus the value, or else symbol_address with the check
    binary's symbols. None when it has none."""
    found = target_row(call)
    if found is None:
        return symbol_address(call, link.output.symbols)
    row, value = found
    at = None if row is None else link.match.get(row)
    return None if at is None else link.lines[at].address + value


def linked_span(test, link, at_base):
    """(low, high): where the target of the call `test` (CallTest) lies in the check link `link` (Link): at the check
    binary's symbol plus the addend for a global that the binary names, which is lld's own address; at the test's
    fixed address when its section is one of `at_base`, the same-bytes sections that the check link puts at their
    base addresses with their base linked sizes, which lld relaxes there as at the base; else at linked_target, less
    up to the call's removable bytes, which lld's relaxation there may have removed in front of the target (the check
    map does not tell how many). None when it has no address there."""
    call = test.call
    if call.kind == "global" and call.target in link.output.symbols:
        address = link.output.symbols[call.target] + call.value
        return address, address
    if test.row in at_base and test.fixed is not None:
        return test.fixed, test.fixed
    address = linked_target(call, link)
    return None if address is None else (address - call.removable, address)


def relaxed_there(test, address, link, at_base):
    """Whether the call `test` of a section at `address` in the check link `link` is in jal's reach of its target
    there and not of its base target at the base, or the other way round: True or False, and None when the check
    link does not tell whether its target lies in reach (linked_span, with `at_base`, otherwise). Its site there is
    address + offset less BASE's delta: a kept section keeps the base's relaxations in front of the call, unless one
    of them is relaxed otherwise, which the test of that earlier call finds. False when the target has no address
    there."""
    span = linked_span(test, link, at_base)
    return False if span is None else otherwise(test, address + test.offset - test.delta, span)


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
    """The append mode (module docstring), for the base layout tree's entry `entry`: 0, also when the build falls
    back to its normal link. Raise AppendError when the probe link fails, and LayoutError when an input cannot be
    read."""
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
    key_file = key_file_for(read_renamed(renamed) if renamed else {}, os.path.realpath)

    # The probe map's lines that name a file (read_map), and those of the linker's own sections, which plan counts.
    entries = map_entries(text_of(read_regular(probe_map)))
    lines = [line for line in entries if line.file != "<internal>"]
    internal = [line for line in entries if line.file == "<internal>"]
    inputs, calls = describe(lines, Objects(read_linked), key_file, set(wrapped))
    by_row = collections.defaultdict(list)
    for call in calls:
        by_row[call.row].append(call)
    probe = Layout(inputs, by_row, binary_output(probe_binary), {},
                   {row for row, line in enumerate(lines) if line.loaded})
    pairing = pair(base.inputs, probe.inputs)
    text = [i for i in probe.inputs if is_text(i.section)]

    def normal_link(places, message):
        # No script, so that link-fuzz-target links normally: each .text input section at the probe link's address.
        if os.path.lexists(script):
            os.unlink(script)
        write_new(placement, tsv(placement_rows([(i, i.address) for i in text], places, pairing, base)))
        print(f"layout.py append: {label}: {message}", file=sys.stderr)
        return 0

    try:
        planned, found = checked_plan(base, probe, pairing, lines, internal, work, script, command)
    except Fallback as error:
        reason = re.sub(r"[\t\n\r]", " ", str(error))
        return normal_link({i.row: Place("normal", i.address, NORMAL_LAYOUT, reason) for i in text},
                           f"normal link: {reason}")
    if planned.script is None:
        return normal_link(planned.places, f"the read-only data in front of .text grew by {planned.growth[0]} bytes, "
                           f"past its room of {planned.growth[1]} bytes, so this is a normal link, and every function "
                           "whose code did not change moves (readonly_growth)")
    places = planned.places
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


def pattern_sections(probe, row):
    """For a person, the .text input sections of the probe link `probe` (Layout) that the script's pattern of its
    section `row` places: each section of that file, member and name (pattern)."""
    first = probe.inputs[row]
    count = sum((i.file, i.member, i.section) == (first.file, first.member, first.section) for i in probe.inputs)
    return function(first) if count == 1 else f"the {count} sections of {function(first)}"


def check_failure(planned, probe, status, output):
    """Why the check link of the plan `planned` of the probe link `probe` (Layout) failed, for a person, from its exit
    status `status` and its output `output`. For lld's error that it cannot move the location counter backward
    (BACKWARD) to the address of a line `. = <address>;` of the script: that line, the sections of the pattern in
    front of it, which took more room than the plan gave them, and those of the pattern after it, which lld could not
    put at that address, or the end of .text. Else the exit status and lld's first line with an error."""
    backward = BACKWARD.search(output)
    script = planned.script.split("\n")
    if backward and 1 < int(backward.group(1)) <= len(script):
        number = int(backward.group(1))
        front, after = planned.lines.get(number - 1), planned.lines.get(number + 1)
        if front is not None:
            what = "end .text there" if after is None else \
                f"put {pattern_sections(probe, after)} at {hex(planned.places[after].address)}"
            return (f"lld cannot move the location counter backward at line {number} of the script, "
                    f"`{script[number - 1].strip()}`: {pattern_sections(probe, front)}, on the line before, takes more "
                    f"room than the plan gives it, so lld cannot {what}")
    error = next((line.strip() for line in output.split("\n") if "error:" in line), None)
    return f"the check link fails with exit status {status}" + (f": {error}" if error else "")


def checked_plan(base, probe, pairing, lines, internal, work, script, command):
    """The plan of the append link of the probe link `probe` (Layout) that its check links verify (module docstring),
    with each cause's detail as the last check link shows it, and [(the probe link's Input, its address)] of each .text
    input section of the last check link, in its map's order; or the plan of a normal link and None, when the
    read-only data in front of .text grew past its room (plan). `lines` are the probe map's lines (read_map) and
    `internal` those of the linker's own sections (map_entries). It writes the script of each plan to `script`, and
    links with it in `work` with the link's `command`. Raise Fallback when a plan does; when a check link fails
    (check_failure); when it does not put a kept section at its base address with its base linked size, and relaxes
    no call or thread-local access of it otherwise; when the last check link does not show a jal_reach or tls_reach
    cause (for one of a section that an earlier check link moved, the append mode never returns it, so that its links
    end); when its PT_LOAD segments are not the probe link's, or two share a page; and when it takes a .text input
    section that the probe link does not, or lacks one."""
    text = [i for i in probe.inputs if is_text(i.section)]
    tests = call_tests(base, probe, pairing, segment_tail(probe, internal)).tests
    tls = tls_tests(base, probe, pairing).tests
    names = map_index(lines)
    check_map, check_binary = os.path.join(work, "check.map"), os.path.join(work, "check")
    forced = {}
    while True:
        planned = plan(base, probe, pairing, forced, internal)
        if planned.script is None:
            return planned, None
        write_new(script, planned.script.encode("utf-8", "surrogateescape"))
        status, output = run(command + [f"-Wl,-T,{script}", f"-Wl,-Map={check_map}", "-o", check_binary])
        if status:
            raise Fallback(check_failure(planned, probe, status, output))
        checked = read_map(text_of(read_regular(check_map)))
        at = map_index(checked)
        link = Link(checked, {row: at[name] for name, row in names.items() if name in at}, binary_output(check_binary))
        # The same-bytes sections that the check link puts at their base addresses with their base linked sizes.
        at_base = set()
        for i in text:
            if pairing.same[i.row] and i.row in link.match:
                old, line = base.inputs[pairing.partner[i.row]], checked[link.match[i.row]]
                if (line.address, line.size) == (old.address, old.linked):
                    at_base.add(i.row)
        moved = {}
        for i in text:
            if planned.places[i.row].place != "kept":
                continue
            if i.row not in link.match:
                raise Fallback(f"{function(i)} is not in the check link's map")
            old, line = base.inputs[pairing.partner[i.row]], checked[link.match[i.row]]
            if i.row in at_base:
                continue
            decided = [(t, relaxed_there(t, line.address, link, at_base)) for t in tests.get(i.row, [])]
            test = next((t for t, there in decided if there), None)
            if test is None:
                test = next((t for t in tls.get(i.row, [])
                             if tls_otherwise(t, tls_offset(linked_target(t.call, link), link.output))), None)
            if test is None:
                kept_there = (f"{function(i)}: the script keeps it at {hex(old.address)} with {old.linked} bytes, and "
                              f"the check link puts it at {hex(line.address)} with {line.size} bytes")
                # The plan keeps no section with a line that call_tests or tls_tests skips (plan), so that only a call
                # whose target the check link does not put in jal's reach or out of it is not tested here.
                why = untested([], [(t, linked_span(t, link, at_base)) for t, there in decided if there is None])
                if why:
                    raise Fallback(f"{kept_there}; the append mode cannot test whether lld relaxes "
                                   f"{'these' if len(why) > 1 else 'this'} otherwise: {'; '.join(why)}")
                raise Fallback(f"{kept_there}, and no call or thread-local access of it is relaxed otherwise: a "
                               "defect of the append mode")
            moved[i.row] = test
        if not moved:
            break
        forced.update(moved)
    places = dict(planned.places)
    for row, place in sorted(places.items()):
        if place.cause == "jal_reach":
            shown = [reach_cause(t)[1] for t in tests.get(row, [])
                     if otherwise(t, t.site, linked_span(t, link, at_base))]
            what = "call of it is relaxed otherwise at its base address"
        elif place.cause == "tls_reach":
            shown = [reach_cause(t)[1] for t in tls.get(row, [])
                     if tls_otherwise(t, tls_offset(linked_target(t.call, link), link.output))]
            what = "thread-local access of it is relaxed otherwise"
        else:
            continue
        if not shown and place.cause == "jal_reach" and row in forced:
            raise Fallback(f"{function(probe.inputs[row])}: a check link moved it for its call at offset "
                           f"{hex(forced[row].offset)} ({forced[row].target}), and no call of it is relaxed otherwise "
                           "at its base address in the last check link: its cause rested on a call whose target the "
                           "last check link puts where lld relaxes the call as at the base, as in a section that the "
                           "plan put back at its base address, and the append mode never returns a function that a "
                           "check link moved, so that its links end (a limit of the append mode)")
        if not shown:
            raise Fallback(f"{function(probe.inputs[row])} moves with {place.cause}, but no {what} in the check "
                           "link: a defect of the append mode")
        if place.detail not in shown:
            places[row] = place._replace(detail=shown[0])
    failure = segments_failure(probe.output.loads, link.output.loads)
    if failure:
        raise Fallback(failure)
    back = {at: row for row, at in link.match.items()}
    found = []
    for at, line in enumerate(checked):
        if not is_text(line.section):
            continue
        if at not in back:
            where = origin(line.file, line.member)
            raise Fallback(f"the check link takes {where}:({line.section}), which the probe link does not")
        found.append((probe.inputs[back[at]], line.address))
    missing = [i for i in text if i.row not in link.match]
    if missing:
        raise Fallback(f"{function(missing[0])} is not in the check link's map")
    return planned._replace(places=places), found


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
                    "cause in NEW's placement.tsv that the two trees show (jal_reach, tls_reach, repeated_key, "
                    "alignment or readonly_growth); one of a key with two sections of the same bytes, which the trees "
                    "cannot tell apart, must move. A build of NEW that fell back to its normal link (normal_layout "
                    "in its placement.tsv) is listed as \"normal layout: <reason>\" and fails nothing: a normal link "
                    "keeps no base address, so the build claims none, and the check does not verify the reason. "
                    "Exit 1 when a function fails, 2 when a tree cannot be read or the two share no (build, target).")
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
                    "with its base linked size (a kept section whose call or thread-local access the check link "
                    "relaxes otherwise moves, with jal_reach or tls_reach, and the plan runs again), that the "
                    "PT_LOAD segments are the probe link's and that no two of them share a page, and write "
                    "placement.tsv. When the read-only data in front of .text grew past its room, write no script (a "
                    "normal link). Never stop a link for a change of the code: when a kept section has a call or a "
                    "thread-local access that the plan cannot test or decide, when the check link fails or is not "
                    "what the plan asks, or when a file or section name holds a double quote or a line break, which "
                    "the script cannot quote, write no script (the build falls back to its normal link), give each "
                    ".text input section of placement.tsv the cause normal_layout and the reason, and print one line "
                    "that names the function and its call, or the line of the script. Exit 1 when the probe link "
                    "fails, 2 when an input cannot be read.")
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
