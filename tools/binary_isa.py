#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The instruction check of a built fuzz target: every executable byte of the binary is part of a 32-bit RISC-V
instruction that the process model executes, or zero padding.

    python3 tools/binary_isa.py FILE...     one JSON line per file: check(FILE)

check(path) examines one ELF file. It passes when all of these hold:

1. The file is ELF64, little-endian, e_type ET_EXEC and e_machine EM_RISCV. The model loads a program at its fixed
   link-time addresses, so a position-independent (ET_DYN) program would be modeled at the wrong addresses.
2. Every executable byte is uniform rv64g code: 32-bit instructions at 4-byte-aligned addresses, and zero padding.
   Compressed instructions make instruction boundaries non-uniform, which the decoding in every proof would pay for,
   so the builds target rv64g. A compressed (16-bit) instruction, an encoding longer than 32 bits, a misaligned 32-bit
   instruction or a region that ends inside an instruction is a finding. This rule is the builds' target, not a limit
   of the model: the model decodes compressed instructions too (theories/Riscv/DecodeC.v, decode_any) and fetches at
   any even address (theories/LinuxProcessSem/RiscvSemantics.v, fetch_word).
3. Every 32-bit word is one the model gives a meaning to. The rules are those of the model at MODEL_COMMIT.
   RiscvSemantics.v's decode_exec_accesses takes the fetched word; a word that is exactly ecall (0x00000073) is a
   system call, and any other goes to DecodeC.v's decode_any, which hands a word whose low two bits are 11 to
   theories/Riscv/Decode.v's decode. theories/Riscv/Sem.v's exec gives the decoded instruction its effect, with the
   rounding modes of theories/Riscv/Fpu.v, and RiscvSemantics.v's interp_eff_accesses runs that effect. A word is in
   the model when the result is modeled: the instruction runs, or the process dies the way a real process does
   (MachineFault). It is outside the model when the model gives up (MachineUnmodeled). outside() says which words.

The check reads the instructions, not the header. The EF_RISCV_RVC bit of e_flags is the producer's claim about its
own output, and a producer can set it over code without a compressed instruction, or leave it clear over compressed
code. What the proofs decode is the instructions.

THE WALK. The length of a RISC-V instruction is in its first 16-bit parcel: low two bits other than 11 is a 16-bit
(compressed) instruction; low two bits 11 with bits [4:2] other than 111 is a 32-bit instruction; bits [4:2] = 111
starts an encoding longer than 32 bits. walk() reads each executable region parcel by parcel from its first byte, as
a hart that can fetch compressed instructions would read it in a straight line. Each step is one of these:

    insn32        a 32-bit encoding at a 4-byte-aligned address: the only thing an rv64g stream holds, apart from
                  padding.
    rvc16         a 16-bit parcel, not 0x0000, whose low two bits are not 11: a compressed instruction.
    zero padding  a run of 0x0000 parcels. A zero parcel is in the model: DecodeC.v's is_defined_illegal names it as
                  the one encoding every RISC-V implementation must refuse, and RiscvSemantics.v's
                  decode_exec_accesses answers MachineFault (the process takes SIGILL). 0x0000 is also c.unimp, a
                  16-bit instruction, so a run is padding only when it starts 4-byte aligned and either has an even
                  number of parcels (whole zero words, which keep the next instruction aligned) or runs to the end of
                  the region (nothing after it can be misaligned). lld fills the gaps between input sections with
                  zeros, and Go's linker ends .text with a zero fill that can be 2 mod 4 bytes long. Any other zero
                  run is `odd_zero`: a lone c.unimp, or padding that misaligns the stream.
    misaligned32  a 32-bit encoding at an address that is not a multiple of 4. Only a 16-bit step, or a region that
                  does not start at a multiple of 4, leads to one. In a region at an odd address no parcel is
                  aligned, so every 32-bit encoding and every zero run in it is a finding; the model's fetch_word
                  refuses an odd address too.
    tail          a region that ends inside an instruction: a 32-bit first parcel in its last two bytes, or an odd
                  last byte.

After a finding the walk goes on at the next parcel, so the counts after it are an estimate; the result does not
depend on them. A region with no finding is tiled exactly by aligned 32-bit words, each an instruction or zero.

DATA IN CODE. A stripped binary does not say where code ends and data starts, and this check does not guess: every
executable byte is decoded as an instruction. A data word whose low two bits are 11 reads as a 32-bit instruction
and is held to the model's ISA like one. Any other data word reads as 16-bit parcels and is a finding: the check
fails on data in code, it never passes it. When the file still has RISC-V mapping symbols ($d marks data, $x code),
the findings that fall inside $d data are counted (`in_data`); that count does not change the result.

WHERE THE CODE IS. The model fetches an instruction from any byte of a loaded segment marked executable, and from
nothing else (RiscvSemantics.v, code_read and fetch_byte_traps). Two sources are cross-checked:

    sections   every SHF_EXECINSTR section with bytes in the file is decoded, whether or not a PF_X segment maps it.
    segments   every PT_LOAD segment with PF_X is what the loader maps executable. Its file bytes are: bytes inside an
               SHF_EXECINSTR section (decoded above); the ELF header and the program and section header tables (a
               text segment can start at file offset 0); and every other byte, inside a section without SHF_EXECINSTR
               or inside no section. A run of those that is all zero is padding; any other run is decoded as code,
               since the loader maps it executable.

A section header is the producer's claim, and the loader does not read it: a section without SHF_EXECINSTR inside a
PF_X segment is named and counted (data_in_x), and its bytes are decoded like a gap. Data mapped executable therefore
fails the check, as data in code does; it never passes unexamined. The one exception is a note section (SHT_NOTE)
whose bytes are, whole, a sequence of well-formed ELF notes: Go's linker puts two in front of .text, and they are
named and not decoded, as the header tables are not.

A file with no section headers is decoded from its PF_X segments, without the ELF header and program header table.
The three header tables are the other bytes in an executable segment that are not decoded: the check trusts that a
program does not jump into its own headers. The ELF header is taken as its 64 bytes, whatever its e_ehsize says.
A file in which nothing is decoded (no executable section with bytes, and no byte of a PF_X segment outside the header
tables that is not zero) had nothing examined: the result is "error", never "pass".

SCOPE. This examines one ELF file. It does not open ar archives (static libraries); check each member as a file of
its own.
"""
import array
import bisect
import collections
import json
import pathlib
import struct
import sys

# The model these rules were checked against: its commit, and the code_sha256 (tools/model_release.py) of each model
# file the rules transcribe, at that commit. LinuxProcessSem/RiscvSemantics.v fetches a word, intercepts ecall and
# sorts each result into modeled and unmodeled; Riscv/DecodeC.v chooses the decoder and names the zero parcel
# defined-illegal; Riscv/Decode.v decodes a 32-bit word; Riscv/Sem.v and Riscv/Fpu.v give it its effect.
MODEL_COMMIT = "505d161e1a2e89273739c0c44675892ed4c671a0"
MODEL_FILES = {
    "theories/LinuxProcessSem/RiscvSemantics.v": "e10ee5ef3c24003d148fc8fb20a26727e720b45502dc018a10e7c79712c1eaff",
    "theories/Riscv/Decode.v": "b759119d79a63c9c1d68ecdab41f1058d409fbd4d04201d54b3fa63e8dddf9c8",
    "theories/Riscv/DecodeC.v": "90f0a0831557233865a767d5cb2da5fbae5903995dd50d53bfd94510d52c5970",
    "theories/Riscv/Fpu.v": "077d372a91939063063b9722e4ff03ad7b7f6cfeea14123458adc85bf3c9b15d",
    "theories/Riscv/Sem.v": "965e972412f92002ad140afb7a55b72e45a4e4af270f49caa19f6e31e3ff3087",
}

EM_RISCV = 0xF3
ET_EXEC = 2
ET_NAMES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
SHT_SYMTAB = 2
SHT_NOBITS = 8
SHT_NOTE = 7
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PF_X = 0x1
# The findings of the walk that are about the shape of the stream, in the order it reports them for a region.
SHAPES = ("rvc16", "long", "misaligned32", "odd_zero", "tail")
# The array typecode of a 4-byte unsigned integer, so that a region without a finding is read as words in one cast.
WORD_TYPECODE = next(code for code in "IL" if array.array(code).itemsize == 4)


class Unexamined(Exception):
    """The file cannot be decoded as RISC-V code. The result is "error", never "pass"."""


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def elf64_header(data):
    """Raise Unexamined unless `data` starts with a whole ELF64 little-endian header."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise Unexamined("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise Unexamined(f"not ELF64 little-endian (EI_CLASS={data[4]} EI_DATA={data[5]})")


def parse_elf(data):
    """The ELF header's fields, the section headers and the program headers of a RISC-V ELF64 file: (header,
    [section], [segment]). Raise Unexamined if the file is not one, or a table or a section runs past its end."""
    elf64_header(data)
    e = {
        "type": u16(data, 16), "machine": u16(data, 18), "flags": u32(data, 48),
        "phoff": u64(data, 32), "shoff": u64(data, 40),
        "phentsize": u16(data, 54), "phnum": u16(data, 56),
        "shentsize": u16(data, 58), "shnum": u16(data, 60), "shstrndx": u16(data, 62),
    }
    if e["machine"] != EM_RISCV:
        raise Unexamined(f"e_machine {e['machine']:#x} is not EM_RISCV ({EM_RISCV:#x})")
    shnum, shstrndx, phnum = e["shnum"], e["shstrndx"], e["phnum"]
    # Extended numbering: when a count does not fit its header field, the real one is in section header 0.
    if e["shoff"] and (shnum == 0 or shstrndx == 0xFFFF or phnum == 0xFFFF):
        if e["shoff"] + 64 > len(data):
            raise Unexamined("section header table is past the end of the file")
        s0 = e["shoff"]
        if shnum == 0:
            shnum = u64(data, s0 + 32)
        if shstrndx == 0xFFFF:
            shstrndx = u32(data, s0 + 40)
        if phnum == 0xFFFF:
            phnum = u32(data, s0 + 44)
    secs = []
    if e["shoff"] and shnum:
        if e["shentsize"] != 64:
            raise Unexamined(f"e_shentsize {e['shentsize']} != 64")
        if e["shoff"] + shnum * 64 > len(data):
            raise Unexamined("section header table is past the end of the file")
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, _info, align, _entsize = struct.unpack_from(
                "<IIQQQQIIQQ", data, e["shoff"] + i * 64)
            secs.append({"idx": i, "name_off": name, "type": typ, "flags": flags, "addr": addr,
                         "off": off, "size": size, "link": link, "align": align})
        names = b""
        if shstrndx < len(secs):
            st = secs[shstrndx]
            names = data[st["off"]:st["off"] + st["size"]]
        for s in secs:
            end = names.find(b"\0", s["name_off"])
            s["name"] = names[s["name_off"]:end if end >= 0 else None].decode("latin1") or f"[{s['idx']}]"
            if s["type"] != SHT_NOBITS and s["off"] + s["size"] > len(data):
                raise Unexamined(f"section {s['name']} extends past the end of the file")
    segs = []
    if e["phoff"] and phnum:
        if e["phentsize"] != 56:
            raise Unexamined(f"e_phentsize {e['phentsize']} != 56")
        if e["phoff"] + phnum * 56 > len(data):
            raise Unexamined("program header table is past the end of the file")
        for i in range(phnum):
            typ, flags, off, vaddr, _paddr, filesz, memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", data, e["phoff"] + i * 56)
            if typ == PT_LOAD and off + filesz > len(data):
                raise Unexamined(f"PT_LOAD {i} extends past the end of the file")
            segs.append({"idx": i, "type": typ, "flags": flags, "off": off, "vaddr": vaddr,
                         "filesz": filesz, "memsz": memsz})
    e["phnum"], e["shnum"] = phnum, shnum
    return e, secs, segs


def mapping_symbols(data, secs):
    """The RISC-V mapping symbols of the file's symbol tables: {section index: sorted [(address, "d" or "x")]}."""
    out = {}
    for s in secs:
        if s["type"] != SHT_SYMTAB or s["link"] >= len(secs):
            continue
        st = secs[s["link"]]
        strtab = data[st["off"]:st["off"] + st["size"]]
        for o in range(s["off"], s["off"] + s["size"] - 23, 24):
            name, _info, _other, shndx, value, _size = struct.unpack_from("<IBBHQQ", data, o)
            if strtab[name:name + 1] != b"$":
                continue
            kind = strtab[name + 1:name + 2]
            end = strtab[name + 2:name + 3]
            # $d, $x, $d.<n>, $x.<n>, and $x<ISA string>, which LLVM writes where the ISA changes.
            if kind == b"d" and end in (b"\0", b"."):
                out.setdefault(shndx, []).append((value, "d"))
            elif kind == b"x":
                out.setdefault(shndx, []).append((value, "x"))
    for v in out.values():
        v.sort()
    return out


def aligned_parity(base):
    """Which parcels of a region at address `base` sit at a multiple of 4: those whose index has this parity (0 or
    1), or none (-1) when `base` is odd. walk(), isa_census() and outside_sites() all read words by it, so the words
    the census reads are the steps the walk counted."""
    return -1 if base & 1 else (base >> 1) & 1


def walk(buf, base):
    """Decode `buf`, the bytes at address `base`, parcel by parcel (see THE WALK). Return ({"insn32", "zero_parcels"},
    {finding: [address]}), with every address at which each finding of SHAPES occurs."""
    n = len(buf) // 2
    h = memoryview(buf[:2 * n]).cast("H")
    if sys.byteorder != "little":
        a = array.array("H", buf[:2 * n])
        a.byteswap()
        h = a
    insn32 = zero = 0
    at = {k: [] for k in SHAPES}
    rvc, lng, mis, odd = at["rvc16"], at["long"], at["misaligned32"], at["odd_zero"]
    i = 0
    # A 32-bit step keeps the parity of the parcel index, so only a 16-bit step can misalign the stream. `par` is
    # the parity at which a parcel is 4-byte aligned; at an odd base no parcel is, and `i & 1` never equals -1.
    par = aligned_parity(base)
    while i < n:
        p = h[i]
        if p & 3 == 3:
            if p & 0x1C != 0x1C:
                if i + 1 >= n:
                    at["tail"].append(base + 2 * i)
                    i += 1
                    break
                if (i & 1) != par:
                    mis.append(base + 2 * i)
                insn32 += 1
                i += 2
            else:
                lng.append(base + 2 * i)
                i += 1
        elif p == 0:
            j = i + 1
            while j < n and h[j] == 0:
                j += 1
            zero += j - i
            # Padding starts aligned, and is whole words or runs to the end of the region.
            if (i & 1) != par or ((j - i) & 1 and j < n):
                odd.append(base + 2 * i)
            i = j
        else:
            rvc.append(base + 2 * i)
            i += 1
    if len(buf) & 1:
        at["tail"].append(base + len(buf) - 1)
    return {"insn32": insn32, "zero_parcels": zero}, at


def insn32_words(buf, base):
    """Yield (address, word) for every step that walk() counts as insn32, in the same order and by the same steps.
    This is the slow path, for a region with a finding."""
    n = len(buf) // 2
    i = 0
    while i < n:
        p = u16(buf, 2 * i)
        if p & 3 == 3:
            if p & 0x1C != 0x1C:
                if i + 1 >= n:
                    return
                yield base + 2 * i, p | (u16(buf, 2 * i + 2) << 16)
                i += 2
            else:
                i += 1
        elif p == 0:
            j = i + 1
            while j < n and u16(buf, 2 * j) == 0:
                j += 1
            i = j
        else:
            i += 1


def isa_census(buf, base, clean, n_insn32):
    """The region's insn32 words: ({word: occurrences}, a function that yields (address, word) for each). In a region
    without a finding (`clean`), every aligned non-zero word is an insn32 step and every zero word is padding, so the
    words are read in one cast from the first aligned parcel. That is checked: the cast must count the walk's
    `n_insn32` words, or this raises Unexamined. A region at an odd address always has a finding (walk() finds no
    parcel aligned there); one called clean raises Unexamined."""
    if not clean:
        pairs = list(insn32_words(buf, base))
        return collections.Counter(w for _, w in pairs), lambda: iter(pairs)
    par = aligned_parity(base)
    if par < 0:
        raise Unexamined(f"region at {base:#x}: an odd address has no aligned word to read")
    off = 2 * par
    m = (len(buf) - off) // 4
    a = array.array(WORD_TYPECODE)
    a.frombytes(buf[off:off + 4 * m])
    if sys.byteorder != "little":
        a.byteswap()
    cnt = collections.Counter(a)
    cnt.pop(0, None)
    if sum(cnt.values()) != n_insn32:
        raise Unexamined(f"region at {base:#x}: the aligned-word census counts "
                         f"{sum(cnt.values())} instructions and the parcel walk {n_insn32}")
    return cnt, lambda: ((base + off + 4 * k, w) for k, w in enumerate(a) if w)


# THE MODEL'S ISA. decode() is theories/Riscv/Decode.v's decode, case for case and in its order. It returns a short
# class name where Decode.v returns Some, and None exactly where Decode.v returns None. The class names are for
# outside() and for a reader.

# The CSR addresses that Sem.v's csr_slice resolves: fflags, frm and fcsr.
MODELED_CSRS = frozenset((0x001, 0x002, 0x003))
VECTOR_CSRS = {0x008: "vstart", 0x009: "vxsat", 0x00A: "vxrm", 0x00F: "vcsr",
               0xC20: "vl", 0xC21: "vtype", 0xC22: "vlenb"}


def _bits(w, lo, n):
    return (w >> lo) & ((1 << n) - 1)


def decode(w):
    """Decode.v's decode of the 32-bit word `w`: a class name, or None where Decode.v returns None."""
    opc = w & 0x7F
    rd = _bits(w, 7, 5)
    f3 = _bits(w, 12, 3)
    rs1 = _bits(w, 15, 5)
    rs2 = _bits(w, 20, 5)
    f7 = _bits(w, 25, 7)
    # A word whose low two bits are not 11, or that starts an encoding longer than 32 bits, matches no opcode below.
    if opc == 0x37:
        return "lui"
    if opc == 0x17:
        return "auipc"
    if opc == 0x6F:
        return "jal"
    if opc == 0x67:
        return "jalr" if f3 == 0 else None
    if opc == 0x63:
        return "branch" if f3 in (0, 1, 4, 5, 6, 7) else None
    if opc == 0x03:
        return "load" if f3 in (0, 1, 2, 3, 4, 5, 6) else None
    if opc == 0x23:
        return "store" if f3 in (0, 1, 2, 3) else None
    if opc == 0x13:
        if f3 in (0, 2, 3, 4, 6, 7):
            return "op-imm"
        # RV64 shifts take a 6-bit shift amount; the bits above it, [31:26], select the shift.
        if f3 == 1:
            return "slli" if _bits(w, 26, 6) == 0 else None
        return "srli/srai" if _bits(w, 26, 6) in (0x00, 0x10) else None
    if opc == 0x1B:
        if f3 == 0:
            return "addiw"
        if f3 == 1:
            return "slliw" if f7 == 0 else None
        if f3 == 5:
            return "srliw/sraiw" if f7 in (0x00, 0x20) else None
        return None
    if opc == 0x33:
        if f7 == 0x00:
            return "op"
        if f7 == 0x20:
            return "op" if f3 in (0, 5) else None
        if f7 == 0x01:
            return "mul"
        return None
    if opc == 0x3B:
        if f7 == 0x00:
            return "op-32" if f3 in (0, 1, 5) else None
        if f7 == 0x20:
            return "op-32" if f3 in (0, 5) else None
        if f7 == 0x01:
            return "mul-32" if f3 in (0, 4, 5, 6, 7) else None
        return None
    if opc == 0x0F:
        # fence needs rd = rs1 = 0, and fm = 0 or exactly fence.tso (fm = 8, pred = succ = rw); fence.i is one word.
        if f3 == 0:
            ok = rd == 0 and rs1 == 0 and (_bits(w, 28, 4) == 0 or _bits(w, 20, 12) == 0x833)
            return "fence" if ok else None
        if f3 == 1:
            return "fence.i" if w == 0x0000100F else None
        return None
    if opc == 0x73:
        # ecall and ebreak only: the privileged SYSTEM instructions decode to None.
        if f3 == 0:
            if w == 0x00000073:
                return "ecall"
            if w == 0x00100073:
                return "ebreak"
            return None
        if f3 == 4:
            return None
        return "csr"
    if opc == 0x2F:
        if f3 not in (2, 3):
            return None
        f5 = _bits(w, 27, 5)
        if f5 == 0x02:
            return "lr" if rs2 == 0 else None
        if f5 in (0x00, 0x01, 0x03, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C):
            return "amo"
        return None
    if opc in (0x07, 0x27):
        return ("flw/fld" if opc == 0x07 else "fsw/fsd") if f3 in (2, 3) else None
    if opc in (0x43, 0x47, 0x4B, 0x4F):
        return "fma" if _bits(w, 25, 2) in (0, 1) else None
    if opc == 0x53:
        if f7 in (0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0C, 0x0D):
            return "fp-arith"
        if f7 in (0x2C, 0x2D):
            return "fsqrt" if rs2 == 0 else None
        if f7 in (0x10, 0x11):
            return "fsgnj" if f3 in (0, 1, 2) else None
        if f7 in (0x14, 0x15):
            return "fminmax" if f3 in (0, 1) else None
        if f7 in (0x50, 0x51):
            return "fcmp" if f3 in (0, 1, 2) else None
        if f7 in (0x60, 0x61, 0x68):
            return "fcvt" if rs2 in (0, 1, 2, 3) else None
        if f7 == 0x69:
            # fcvt.d.w and fcvt.d.wu are exact, and decode only with rm = 0; fcvt.d.l and fcvt.d.lu take any rm.
            if rs2 in (0, 1):
                return "fcvt" if f3 == 0 else None
            return "fcvt" if rs2 in (2, 3) else None
        if f7 == 0x20:
            return "fcvt" if rs2 == 1 else None
        if f7 == 0x21:
            return "fcvt" if rs2 == 0 and f3 == 0 else None
        if f7 in (0x70, 0x71):
            return "fmv/fclass" if rs2 == 0 and f3 in (0, 1) else None
        if f7 in (0x78, 0x79):
            return "fmv" if rs2 == 0 and f3 == 0 else None
        return None
    return None


def undecoded_family(w):
    """The extension a word that decode() rejects belongs to, for a reader: a family name; "other" is one too."""
    opc = w & 0x7F
    f3 = _bits(w, 12, 3)
    f7 = _bits(w, 25, 7)
    rs2 = _bits(w, 20, 5)
    f6 = _bits(w, 26, 6)
    imm = _bits(w, 20, 12)
    if w & 3 != 3 or (w & 0x1C) == 0x1C:
        return "not-32bit"
    if opc == 0x57:
        return "rvv-vsetvl" if f3 == 7 else "rvv-op"
    if opc in (0x07, 0x27):
        if f3 in (0, 5, 6, 7):
            return "rvv-mem"
        return "fp-zfh-q-mem"
    if opc == 0x33:
        if f7 == 0x10 and f3 in (2, 4, 6):
            return "zba"
        if (f7 == 0x20 and f3 in (4, 6, 7)) or (f7 == 0x05 and f3 in (4, 5, 6, 7)) \
                or (f7 == 0x30 and f3 in (1, 5)):
            return "zbb"
        if f7 == 0x05 and f3 in (1, 2, 3):
            return "zbc"
        if (f7 == 0x24 and f3 in (1, 5)) or (f7 in (0x14, 0x34) and f3 == 1):
            return "zbs"
        if f7 == 0x07 and f3 in (5, 7):
            return "zicond"
        if f7 == 0x04 and f3 in (4, 7):
            return "zbkb"
        return "other-op"
    if opc == 0x3B:
        if (f7 == 0x04 and f3 == 0) or (f7 == 0x10 and f3 in (2, 4, 6)):
            return "zba"
        if (f7 == 0x04 and f3 == 4 and rs2 == 0) or (f7 == 0x30 and f3 in (1, 5)):
            return "zbb"
        if f7 == 0x04 and f3 == 4:
            return "zbkb"
        return "other-op-32"
    if opc == 0x13:
        if f3 == 1 and imm in (0x600, 0x601, 0x602, 0x604, 0x605):
            return "zbb"
        if f3 == 5 and (f6 == 0x18 or imm in (0x287, 0x6B8)):
            return "zbb"
        if (f3 == 1 and f6 in (0x12, 0x0A, 0x1A)) or (f3 == 5 and f6 == 0x12):
            return "zbs"
        if f3 == 5 and imm == 0x687:
            return "zbkb"
        return "other-op-imm"
    if opc == 0x1B:
        if f3 == 1 and f6 == 0x02:
            return "zba"
        if (f3 == 1 and imm in (0x600, 0x601, 0x602)) or (f3 == 5 and f7 == 0x30):
            return "zbb"
        return "other-op-imm-32"
    if opc == 0x73:
        return "system-priv"
    if opc == 0x2F:
        return "amo-ext"
    if opc == 0x0F:
        return "cbo-or-fence-ext" if f3 == 2 else "misc-mem-ext"
    if opc in (0x0B, 0x2B, 0x5B, 0x7B):
        return "custom"
    if opc in (0x53, 0x43, 0x47, 0x4B, 0x4F):
        return "fp-ext"
    return "other"


def outside(w):
    """None when the model gives the 32-bit word `w` a meaning; otherwise the family it belongs to. The meaning comes
    from theories/LinuxProcessSem/RiscvSemantics.v: decode_exec_accesses decodes the word, and interp_eff_accesses
    runs the effect that Sem.v's exec builds. The model gives up (MachineUnmodeled) on a word in three ways:

    1. decode() rejects it: DecodeC.v's decode_any hands a word whose low two bits are 11 to Decode.v's decode, and
       decode_exec_accesses answers MachineUnmodeled when that returns None (is_defined_illegal names only words whose
       low parcel is zero, never such a word). Vector, Zba/Zbb/Zbc/Zbs, Zicond, Zfh and Q, cache-block and privileged
       SYSTEM instructions, and custom opcodes all land here.
    2. It is a CSR instruction (Decode.v accepts every Zicsr word) on an address other than fflags, frm and fcsr:
       Sem.v's exec_csr answers EIllegal, since csr_slice resolves only 0x001-0x003, and interp_eff_accesses turns
       EIllegal into MachineUnmodeled. vlenb, vl, vtype and the counters that rdcycle and rdtime read are such
       addresses. One exception comes first in Sem.v's exec: an instruction whose write side happens
       (csr_write_illegal: csrrw and csrrwi always write, the others only with a source other than x0 or 0) on a
       read-only address (csr[11:10] = 11) is EDefinedIllegal, the architecture's illegal-instruction trap, which
       interp_eff_accesses turns into MachineFault: the process dies with SIGILL, as a real one does, so the word is
       in the model. That is `unimp` (0xC0001073, csrrw x0, cycle, x0), the word sanitizers in trap mode emit for
       each check. ebreak is in the model the same way (EEbreak, MachineFault: SIGTRAP), and ecall is the system call
       that decode_exec_accesses takes before it decodes.
    3. It is an F or D arithmetic, square root, fused multiply-add or conversion with the reserved rounding mode 5 or
       6: Sem.v's resolve_rm calls Fpu.v's rmode_of_field, which answers None for them, so exec answers EIllegal and
       interp_eff_accesses MachineUnmodeled. Rounding mode 7 takes frm at run time and is not decided here.
    """
    cls = decode(w)
    if cls is None:
        return undecoded_family(w)
    if cls == "csr":
        f3 = _bits(w, 12, 3)
        csr = _bits(w, 20, 12)
        src = _bits(w, 15, 5)        # rs1, or the immediate of csrrwi, csrrsi and csrrci
        rw = f3 & 3                  # 1 = csrrw(i), 2 = csrrs(i), 3 = csrrc(i)
        writes = rw == 1 or src != 0
        if writes and (csr >> 10) & 3 == 3:
            return None              # EDefinedIllegal: a modeled death
        if csr in MODELED_CSRS:
            return None
        if csr in VECTOR_CSRS:
            return "csr-" + VECTOR_CSRS[csr]
        if 0xC00 <= csr <= 0xC1F or 0xC80 <= csr <= 0xC9F:
            return "csr-counter"
        return "csr-other"
    if cls in ("fp-arith", "fsqrt", "fma", "fcvt") and _bits(w, 12, 3) in (5, 6):
        return "fp-reserved-rm"
    return None


# THE UNWINDER'S vlenb READ. LLVM's libunwind reads vlenb (`csrr rd, vlenb`, a CSR the model does not resolve) in
# Registers_riscv::getRegister, which every program that links the unwinder carries:
#
#     lui   rX, 0x2 ; addiw rX, rX, -0x3de   # rX = 7202, the RISC-V psABI's DWARF number for vlenb
#     bne   rN, rX, ...                      # asked for another register?
#     csrr  rd, vlenb
#
# The unwinder asks for a register only when a call-frame rule or expression names it. So in a file whose call-frame
# information names no register 7202 the read is never reached. That is checked, not assumed: the file's .eh_frame
# is parsed (every CIE, FDE and call-frame instruction; expression blocks are searched for any ULEB128 spelling of
# 7202), and a site is exempt only when the parse succeeds and finds no 7202. Exempt sites are counted
# (`unwinder_vlenb`), never dropped. A file whose .eh_frame does not parse, names 7202, or is not there (no section
# headers, or no section of that name: the unwinder finds call-frame information through PT_GNU_EH_FRAME or
# registered frames, not by section name) has no exempt site. The branch must be `bne` between two different
# registers: only then does the csrr run for 7202 alone (a `beq` falls through for every other register). What this
# cannot see is a program that calls unw_get_reg() or _Unwind_GetGR() with 7202 itself. Only this four-word idiom is
# exempt; any other vlenb read is a finding.

DW_EH_PE_SIZE = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}
VLENB_DWARF = 7202                     # 4096 + 0xC22


def _uleb(b, o):
    v = s = 0
    while True:
        x = b[o]
        o += 1
        v |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            return v, o


def _enc_len(enc, b, o):
    """The length in bytes of one value in DW_EH_PE encoding `enc` at b[o:]."""
    if enc == 0xFF:
        return 0
    fmt = enc & 0x0F
    if fmt in (0x01, 0x09):
        return _uleb(b, o)[1] - o
    if fmt not in DW_EH_PE_SIZE:
        raise ValueError(f"pointer encoding {enc:#x}")
    return DW_EH_PE_SIZE[fmt]


# The call-frame instructions that take operands: opcode -> its operands, in order. 'r' a ULEB128 register, 'u' a
# ULEB128, 's' an SLEB128, 'b' a block of ULEB128 length (an expression), '1' '2' '4' '8' that many bytes, 'a' an
# address in the FDE's pointer encoding.
CFA_OPS = {0x00: "", 0x01: "a", 0x02: "1", 0x03: "2", 0x04: "4", 0x05: "ru", 0x06: "r",
           0x07: "r", 0x08: "r", 0x09: "rr", 0x0A: "", 0x0B: "", 0x0C: "ru", 0x0D: "r",
           0x0E: "u", 0x0F: "b", 0x10: "rb", 0x11: "rs", 0x12: "rs", 0x13: "s",
           0x14: "ru", 0x15: "rs", 0x16: "rb", 0x1D: "8", 0x2D: "", 0x2E: "u", 0x2F: "ru"}
# The ULEB128 spellings of 7202 that an expression block is searched for: 0xA2 0x38, or the non-minimal 0xA2 0xB8
# (0x80)* 0x00. Searching instead of decoding can only find too much, and that fails closed.
_ULEB7202 = (b"\xa2\x38", b"\xa2\xb8")


def cfi_names_register(data, secs, reg, stats=None):
    """(parsed, named): whether every .eh_frame section parses, and whether a call-frame instruction names DWARF
    register `reg` (or an expression block could). No .eh_frame section is (False, True). `stats`, when given,
    receives the number of sections, CIEs, FDEs and call-frame instructions read."""
    named = False
    st = stats if stats is not None else {}
    st.update(cies=0, fdes=0, insns=0, sections=0)
    for s in secs:
        if s["name"] != ".eh_frame" or s["type"] == SHT_NOBITS:
            continue
        b = data[s["off"]:s["off"] + s["size"]]
        st["sections"] += 1
        cies = {}
        o = 0
        try:
            while o + 4 <= len(b):
                start = o
                ln = u32(b, o)
                o += 4
                if ln == 0:
                    break
                if ln == 0xFFFFFFFF:
                    ln = u64(b, o)
                    o += 8
                body = o
                end = body + ln
                if end > len(b):
                    raise ValueError("record past the end of .eh_frame")
                cid = u32(b, o)
                o += 4
                if cid == 0:                                    # a CIE
                    ver = b[o]
                    o += 1
                    z = b.index(b"\0", o)
                    aug = b[o:z].decode("latin1")
                    o = z + 1
                    if "eh" in aug:
                        o += 8
                    _, o = _uleb(b, o)                          # code alignment factor
                    _, o = _uleb(b, o)                          # data alignment factor (an SLEB128, same length)
                    if ver == 1:
                        o += 1
                    else:
                        _, o = _uleb(b, o)
                    fde_enc = 0x00
                    if aug.startswith("z"):
                        alen, o = _uleb(b, o)
                        ad, q = o, o
                        for ch in aug[1:]:
                            if ch == "R":
                                fde_enc = b[q]
                                q += 1
                            elif ch == "L":
                                q += 1
                            elif ch == "P":
                                pe = b[q]
                                q += 1 + _enc_len(pe, b, q + 1)
                            elif ch in "SB":
                                pass
                            else:
                                raise ValueError(f"augmentation {aug!r}")
                        o = ad + alen
                    cies[start] = (fde_enc, aug)
                    st["cies"] += 1
                    insns = (o, end, fde_enc)
                else:                                           # an FDE
                    cie = body - cid
                    if cie not in cies:
                        raise ValueError(f"FDE at {start:#x} names no CIE seen before it")
                    fde_enc, aug = cies[cie]
                    n = _enc_len(fde_enc, b, o)
                    o += 2 * n                                  # pc_begin, pc_range
                    if aug.startswith("z"):
                        alen, o = _uleb(b, o)
                        o += alen
                    st["fdes"] += 1
                    insns = (o, end, fde_enc)
                o, stop, enc = insns
                while o < stop:
                    op = b[o]
                    o += 1
                    st["insns"] += 1
                    hi = op & 0xC0
                    if hi == 0x40:                              # DW_CFA_advance_loc
                        continue
                    if hi in (0x80, 0xC0):                      # DW_CFA_offset, DW_CFA_restore: a register below 64
                        if (op & 0x3F) == reg:
                            named = True
                        if hi == 0x80:
                            _, o = _uleb(b, o)
                        continue
                    if op not in CFA_OPS:
                        raise ValueError(f"call-frame opcode {op:#x}")
                    for kind in CFA_OPS[op]:
                        if kind == "r":
                            v, o = _uleb(b, o)
                            if v == reg:
                                named = True
                        elif kind in "us":
                            _, o = _uleb(b, o)
                        elif kind == "b":
                            bl, o = _uleb(b, o)
                            blk = b[o:o + bl]
                            if reg == VLENB_DWARF and any(p in blk for p in _ULEB7202):
                                named = True
                            o += bl
                        elif kind == "a":
                            o += _enc_len(enc, b, o)
                        else:
                            o += int(kind)
                    if o > stop:
                        raise ValueError(f"instruction runs past its record at {o:#x}")
                o = end
        except (ValueError, IndexError, struct.error):
            return False, True
    if st["sections"] == 0:
        return False, True
    return True, named


def unwinder_vlenb_idiom(buf, off):
    """Whether the csrr vlenb at buf[off:off + 4] ends libunwind's getRegister(7202): lui rX, 2 ; addiw rX, rX, -0x3de
    ; bne rN, rX with rN != rX ; csrr rd, vlenb. The csrr is the fall-through, reached only when rN = 7202."""
    if off < 12:
        return False
    a, b_, c = (u32(buf, off - 12), u32(buf, off - 8), u32(buf, off - 4))
    if a & 0x7F != 0x37 or a >> 12 != 2:
        return False
    rx = (a >> 7) & 31
    if b_ & 0x7F != 0x1B or (b_ >> 12) & 7 or (b_ >> 7) & 31 != rx or (b_ >> 15) & 31 != rx \
            or b_ >> 20 != 0xC22:
        return False
    c1, c2 = (c >> 15) & 31, (c >> 20) & 31
    if c & 0x7F != 0x63 or (c >> 12) & 7 != 1 or rx not in (c1, c2) or c1 == c2:
        return False
    return u32(buf, off) >> 20 == 0xC22


def outside_sites(buf, base, clean, outw, pairs_fn):
    """Every (address, word) of the region whose word is in `outw`, in address order. A region without a finding (at
    an even address, see isa_census()) is searched with bytes.find, and only hits at aligned words are kept."""
    if not clean:
        return [(a, w) for a, w in pairs_fn() if w in outw]
    res = []
    lead = 2 * aligned_parity(base)
    for w in outw:
        pat = struct.pack("<I", w)
        i = buf.find(pat, lead)
        while i >= 0:
            if (i - lead) % 4 == 0:
                res.append((base + i, w))
            i = buf.find(pat, i + 1)
    res.sort()
    return res


# The two notes Go's linker writes in front of .text: the Go build id (name "Go", type 4) and the GNU build id (name
# "GNU", type NT_GNU_BUILD_ID 3), each with a short descriptor.
BUILD_ID_NOTES = {(b"Go\0\0", 4), (b"GNU\0", 3)}
BUILD_ID_MAX = 128


def whole_notes(data, off, size, seen=None):
    """True when the bytes [off, off + size) are exactly a sequence of build-id notes (BUILD_ID_NOTES): each a 12-byte
    header (namesz, descsz, type), the name and a descriptor of at most BUILD_ID_MAX bytes, each padded to 4 bytes,
    the last ending at the end, and each of the two notes at most once in the whole binary (so they wrap no more than
    their own few bytes): `seen` holds the notes earlier sections of the binary were taken for, and gets this
    section's when it is taken. Any other bytes are not taken for notes."""
    end = off + size
    if off % 4 or size % 4 or end > len(data) or size == 0:
        return False
    seen = set() if seen is None else seen
    at, here = off, set()
    while at < end:
        if at + 12 > end:
            return False
        namesz, descsz, kind = struct.unpack_from("<III", data, at)
        name = data[at + 12:at + 12 + (namesz + 3) // 4 * 4]
        if (name, kind) not in BUILD_ID_NOTES or descsz > BUILD_ID_MAX or (name, kind) in seen | here:
            return False
        here.add((name, kind))
        at += 12 + len(name) + (descsz + 3) // 4 * 4
    if at != end:
        return False
    seen |= here
    return True


def regions(data, e, secs, segs):
    """The byte ranges to decode (see WHERE THE CODE IS): (how the code was located, [PF_X segment], [region], {what
    the PF_X segments map besides executable sections}). An executable section inside a PF_X segment must say it is
    at the address the segment maps its bytes at, or alignment cannot be checked."""
    regs, notes = [], {"data_in_x": [], "gap_zero": 0, "gap_nonzero": 0, "header_in_x": 0}
    seen_notes = set()  # the build-id notes taken so far, in any section of any PF_X segment
    xsegs = [g for g in segs if g["type"] == PT_LOAD and g["flags"] & PF_X and g["filesz"]]
    filled = [s for s in secs if s["type"] != SHT_NOBITS and s["size"] and s["type"] != 0]
    if secs:
        mode = "sections"
        for s in secs:
            if s["flags"] & SHF_EXECINSTR and s["type"] != SHT_NOBITS and s["size"]:
                regs.append({"idx": s["idx"], "addr": s["addr"], "off": s["off"], "size": s["size"]})
    else:
        mode = "segments"
    # The ELF header (64 bytes in ELF64) and the program and section header tables, as parse_elf() read them.
    hdr = [(0, 64)]
    if e["phoff"] and e["phnum"]:
        hdr.append((e["phoff"], e["phoff"] + e["phnum"] * 56))
    if e["shoff"] and e["shnum"]:
        hdr.append((e["shoff"], e["shoff"] + e["shnum"] * 64))
    for g in xsegs:
        lo, hi = g["off"], g["off"] + g["filesz"]
        cover = []
        for s in filled:
            a, b = max(lo, s["off"]), min(hi, s["off"] + s["size"])
            if a < b:
                if s["flags"] & SHF_EXECINSTR and s["addr"] - s["off"] != g["vaddr"] - lo:
                    raise Unexamined(f"section {s['name']} says it is at {s['addr']:#x}, but PF_X LOAD[{g['idx']}] "
                                     f"maps it at {g['vaddr'] + s['off'] - lo:#x}")
                if s["flags"] & SHF_EXECINSTR:
                    cover.append((a, b))
                elif s["type"] == SHT_NOTE and (a, b) == (s["off"], s["off"] + s["size"]) and \
                        whole_notes(data, a, b - a, seen_notes):
                    # A note section (Go's linker puts .note.go.buildid and .note.gnu.build-id in front of .text) is
                    # data only when its bytes are well-formed notes, whole; it is named, and not decoded.
                    cover.append((a, b))
                    notes["data_in_x"].append((s["name"], b - a))
                else:
                    # The loader maps these bytes executable whatever the section header says, so they are not
                    # covered: like a gap, they are padding when all zero and decoded as code otherwise.
                    notes["data_in_x"].append((s["name"], b - a))
        for a, b in hdr:
            a, b = max(lo, a), min(hi, b)
            if a < b:
                cover.append((a, b))
                notes["header_in_x"] += b - a
        cover.sort()
        pos = lo
        gaps = []
        for a, b in cover:
            if a > pos:
                gaps.append((pos, a))
            pos = max(pos, b)
        if pos < hi:
            gaps.append((pos, hi))
        for a, b in gaps:
            chunk = data[a:b]
            if chunk.count(0) == len(chunk):
                notes["gap_zero"] += b - a
            else:
                notes["gap_nonzero"] += b - a
                regs.append({"idx": None, "addr": g["vaddr"] + (a - lo), "off": a, "size": b - a})
    return mode, xsegs, regs, notes


def _in_data(ms, keys, addresses):
    """How many of `addresses` fall in data: after a $d mapping symbol of `ms` ([(address, "d" or "x")], sorted;
    `keys` are its addresses) with no $x between."""
    n = 0
    for a in addresses:
        j = bisect.bisect_right(keys, a) - 1
        if j >= 0 and ms[j][1] == "d":
            n += 1
    return n


def scan(data):
    """Decode the executable bytes of a RISC-V ELF64 file, `data`. Return its counts: {"verdict", "e_type",
    "machine", "e_flags", "located_by", "regions", "exec_bytes", "insn32", "zero_parcels", each finding of SHAPES,
    "outside_model", "families", "unwinder_vlenb", "in_data", "mapping_symbols", "first", "pf_x", "cfi"}. "verdict"
    is "CLEAN", "RVC" (a compressed instruction), "NOT-RV64G" (another finding of SHAPES), "NOT-MODEL" (a word
    outside the model) or "UNEXAMINED" (no executable byte). "first" is (finding, address) or None. "cfi" is None
    unless an unwinder site made .eh_frame be read. Raise Unexamined if the file cannot be decoded."""
    e, secs, segs = parse_elf(data)
    mode, xsegs, regs, notes = regions(data, e, secs, segs)
    msyms = mapping_symbols(data, secs) if secs else {}
    tot = {"exec_bytes": 0, "insn32": 0, "zero_parcels": 0}
    tot.update({k: 0 for k in SHAPES})
    tot.update(outside_model=0, unwinder_vlenb=0, in_data=0)
    fams = collections.Counter()
    first = None
    cfi = None                   # (parsed, names 7202), read when an unwinder site first needs it
    cfist = {}
    for r in regs:
        buf = data[r["off"]:r["off"] + r["size"]]
        c, at = walk(buf, r["addr"])
        tot["exec_bytes"] += r["size"]
        tot["insn32"] += c["insn32"]
        tot["zero_parcels"] += c["zero_parcels"]
        ms = msyms.get(r["idx"], []) if r["idx"] is not None else []
        keys = [v for v, _ in ms]
        clean = not any(at[k] for k in SHAPES)
        cnt, word_addrs = isa_census(buf, r["addr"], clean, c["insn32"])
        outw = {}
        for w in cnt:
            fam = outside(w)
            if fam:
                outw[w] = fam
        sites = outside_sites(buf, r["addr"], clean, outw, word_addrs) if outw else []
        if sum(cnt[w] for w in outw) != len(sites):
            raise Unexamined(f"region at {r['addr']:#x}: {sum(cnt[w] for w in outw)} outside-model "
                             f"words counted but {len(sites)} located")
        kept = []
        for a, w in sites:
            if outw[w] == "csr-vlenb" and clean and unwinder_vlenb_idiom(buf, a - r["addr"]):
                if cfi is None:
                    cfi = cfi_names_register(data, secs, VLENB_DWARF, cfist)
                if cfi[0] and not cfi[1]:
                    tot["unwinder_vlenb"] += 1
                    continue
            fams[outw[w]] += 1
            kept.append(a)
        tot["outside_model"] += len(kept)
        for k in SHAPES:
            tot[k] += len(at[k])
            if at[k]:
                first = first or (k, at[k][0])
                if ms:
                    tot["in_data"] += _in_data(ms, keys, at[k])
        if kept:
            first = first or ("outside_model", kept[0])
            if ms:
                tot["in_data"] += _in_data(ms, keys, kept)
    if tot["exec_bytes"] == 0:
        verdict = "UNEXAMINED"
    elif tot["rvc16"]:
        verdict = "RVC"
    elif any(tot[k] for k in SHAPES):
        verdict = "NOT-RV64G"
    elif tot["outside_model"]:
        verdict = "NOT-MODEL"
    else:
        verdict = "CLEAN"
    tot.update(verdict=verdict, e_type=e["type"], machine=e["machine"], e_flags=e["flags"], located_by=mode,
               regions=len(regs), families=dict(sorted(fams.items(), key=lambda x: (-x[1], x[0]))),
               mapping_symbols=sum(len(v) for v in msyms.values()), first=first,
               pf_x=dict(notes, segments=len(xsegs)),
               cfi=None if cfi is None else dict(cfist, parsed=cfi[0], names_vlenb=cfi[1]))
    return tot


def _families(families):
    return ", ".join(f"{name} {n}" for name, n in families.items())


def _scan_detail(res):
    """One line on the instructions that scan() returned `res` for."""
    words = f"{res['insn32']} 32-bit word(s) in {res['exec_bytes']} executable byte(s)"
    first = f"; first {res['first'][0]} at {res['first'][1]:#x}" if res["first"] else ""
    data = f"; {res['in_data']} finding(s) inside $d data" if res["in_data"] else ""
    if res["verdict"] == "UNEXAMINED":
        return "no executable byte to examine: the check examined nothing"
    if res["verdict"] == "RVC":
        return f"{res['rvc16']} compressed (16-bit) instruction(s) beside {words}{first}{data}"
    if res["verdict"] == "NOT-RV64G":
        kinds = ", ".join(f"{k} {res[k]}" for k in SHAPES if res[k])
        return f"not uniform aligned 32-bit code ({kinds}); {words}{first}{data}"
    if res["verdict"] == "NOT-MODEL":
        return (f"{res['outside_model']} word(s) outside the model's ISA ({_families(res['families'])}) "
                f"among {words}{first}{data}")
    exempt = (f"; {res['unwinder_vlenb']} libunwind vlenb read(s) exempt: .eh_frame names no register 7202"
              if res["unwinder_vlenb"] else "")
    return f"{words}, every one in the model's ISA, no compressed instruction{exempt}"


def check(path):
    """Check the ELF file at `path`. Return {"result", "e_type", "machine", "words", "compressed", "outside_model",
    "families", "unwinder_vlenb", "first", "detail"}:

    result          "pass", "fail", or "error" when the file is not an ELF64 file this can examine, or nothing was
                    examined. A wrong e_type or e_machine is "fail".
    e_type          the ELF type's name ("ET_EXEC", "ET_DYN", ...), or None when the file has no ELF64 header.
    machine         "EM_RISCV", another e_machine in hex, or None.
    words           the number of 32-bit words decoded.
    compressed      the number of compressed (16-bit) instructions.
    outside_model   the number of 32-bit words the model does not execute (exempt unwinder reads not counted).
    families        {family: count} of those words.
    unwinder_vlenb  the number of libunwind vlenb reads exempt.
    first           "<finding> at 0x<address>" for the first finding, or None.
    detail          one line for a person, naming the first finding.
    """
    out = {"result": "error", "e_type": None, "machine": None, "words": 0, "compressed": 0, "outside_model": 0,
           "families": {}, "unwinder_vlenb": 0, "first": None, "detail": ""}
    try:
        data = pathlib.Path(path).read_bytes()
    except OSError as error:
        out["detail"] = f"cannot read the file: {error}"
        return out
    try:
        elf64_header(data)
    except Unexamined as error:
        out["detail"] = f"cannot examine: {error}"
        return out
    e_type, machine = u16(data, 16), u16(data, 18)
    out["e_type"] = ET_NAMES.get(e_type, f"{e_type:#x}")
    out["machine"] = "EM_RISCV" if machine == EM_RISCV else f"{machine:#x}"
    try:
        res, why = scan(data), None
    except (Unexamined, struct.error) as error:
        res, why = None, str(error)
    if res:
        out.update(words=res["insn32"], compressed=res["rvc16"], outside_model=res["outside_model"],
                   families=res["families"], unwinder_vlenb=res["unwinder_vlenb"])
        if res["first"]:
            out["first"] = f"{res['first'][0]} at {res['first'][1]:#x}"
    also = f"; also {_scan_detail(res)}" if res and res["verdict"] not in ("CLEAN", "UNEXAMINED") else ""
    if e_type != ET_EXEC:
        out["result"] = "fail"
        out["detail"] = (f"e_type is {out['e_type']}, not ET_EXEC: the model loads a program at its fixed "
                         f"link-time addresses{also}")
    elif machine != EM_RISCV:
        out["result"] = "fail"
        out["detail"] = f"e_machine is {machine:#x}, not EM_RISCV ({EM_RISCV:#x})"
    elif res is None:
        out["detail"] = f"cannot examine: {why}"
    else:
        out["result"] = {"CLEAN": "pass", "UNEXAMINED": "error"}.get(res["verdict"], "fail")
        out["detail"] = _scan_detail(res)
    return out


def main(argv):
    """Print check() of each file in `argv`, one JSON object per line. Return 0 when every file passes, 1 when one
    fails, 2 when one could not be examined."""
    if not argv or argv[0].startswith("-"):
        print("usage: binary_isa.py FILE...", file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        result = check(path)
        print(json.dumps(dict(result, path=path)))
        status = max(status, {"pass": 0, "fail": 1}.get(result["result"], 2))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
