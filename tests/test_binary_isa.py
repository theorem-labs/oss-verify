# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/binary_isa.py, the instruction check:  python3 -m pytest tests

Each file case is a hand-built ELF whose executable bytes are chosen so that the right answer is known before the
check runs, and each verdict has a case that must land in it: a check that only ever passed, or only ever failed,
fails here. The decoder cases are theories/Riscv/Decode.v's own Goal checks, its other match arms, and the rules of
theories/Riscv/Sem.v and theories/LinuxProcessSem/RiscvSemantics.v that decide whether the model gives a decoded word
a meaning. No toolchain and no Docker. With OSS_VERIFY_MODEL set to a checkout of the model (the directory that holds
theories/), ModelCheckout also checks MODEL_FILES and the Goal checks against that checkout.
"""
import contextlib
import io
import json
import os
import pathlib
import re
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import binary_isa  # noqa: E402

NOP = struct.pack("<I", 0x00000013)        # addi x0, x0, 0
ADD = struct.pack("<I", 0x00B50533)        # add a0, a0, a1
CNOP = struct.pack("<H", 0x0001)           # c.nop
CADD = struct.pack("<H", 0x952E)           # c.add a0, a1
Z16 = b"\0\0"
Z32 = b"\0\0\0\0"
LONG48 = struct.pack("<H", 0x001F)         # the first parcel of a 48-bit encoding
# 32-bit words on either side of the model's ISA, as llvm-mc encodes them.
VSETVLI = struct.pack("<I", 0x0C007057)    # vsetvli zero,zero,e8,m1,ta,ma   (OP-V)
VLE8 = struct.pack("<I", 0x02058007)       # vle8.v v0,(a1)                  (LOAD-FP, width 0)
SH1ADD = struct.pack("<I", 0x20B52533)     # sh1add a0,a0,a1                 (Zba)
CLZ = struct.pack("<I", 0x60051513)        # clz a0,a0                       (Zbb)
VLENB_A0 = struct.pack("<I", 0xC2202573)   # csrr a0,vlenb: decodes, the CSR is not modeled
VLENB_T0 = struct.pack("<I", 0xC22022F3)   # csrr t0,vlenb
RDTIME = struct.pack("<I", 0xC0102573)     # rdtime a0: a counter CSR, not modeled
UNIMP = struct.pack("<I", 0xC0001073)      # unimp: a write to the read-only cycle, a modeled death
FRCSR = struct.pack("<I", 0x00302573)      # frcsr a0: fcsr, modeled
FADD_RM5 = struct.pack("<I", 0x00C5D553)   # fadd.s with the reserved rm 5
# LLVM libunwind's Registers_riscv::getRegister(7202) as compiled: lui a0,2 ; addiw a0,a0,-990 ; bne a1,a0,8 ;
# csrr a0,vlenb ; ret.
UNW_IDIOM = struct.pack("<5I", 0x00002537, 0xC225051B, 0x00A59463, 0xC2202573, 0x00008067)
# An .eh_frame FDE body that parses and names only sp (2) and ra (1): def_cfa_offset 16 ; offset ra, 1.
EH_SP_RA = b"\x0e\x10\x81\x01"

TEXT_VADDR = 0x11000
TEXT_OFF = 0x1000
API_KEYS = {"result", "e_type", "machine", "words", "compressed", "outside_model", "families", "unwinder_vlenb",
            "first", "detail"}


def cie_fde(fde_insns):
    """An .eh_frame: one zR CIE (FDE pointers pc-relative sdata4, CFA = sp) and one FDE whose call-frame instructions
    are `fde_insns`, then the terminator."""
    def rec(payload):
        payload += b"\0" * (-(len(payload) + 4) % 4)      # DW_CFA_nop padding
        return struct.pack("<I", len(payload)) + payload
    cie = rec(struct.pack("<I", 0) + b"\x01zR\0" + b"\x01\x78\x01" + b"\x01\x1b" + b"\x0c\x02\x00")
    fde_body = struct.pack("<iI", 0, 20) + b"\x00" + fde_insns
    # The CIE pointer is the distance from its own field back to the CIE.
    fde = rec(struct.pack("<I", len(cie) + 4) + fde_body)
    return cie + fde + struct.pack("<I", 0)


def mkelf(text, e_flags=4, e_machine=0xF3, text_flags=0x6, gap=b"", sections=True, seg_from_zero=False,
          text_vaddr=TEXT_VADDR, pf_x=True, mapsyms=None, ehframe=None):
    """A static ET_EXEC whose .text is `text`, at file offset 0x1000. `gap` is bytes after .text inside the PF_X
    segment and inside no section. `seg_from_zero` starts the text segment at file offset 0, so it maps the ELF
    header. `mapsyms` is [(address, "$d" or "$x")], put in a .symtab against .text. `ehframe` is the body of an
    .eh_frame section, added last so that no other section index moves."""
    body = bytearray(TEXT_OFF)
    body += text + gap
    shstr = b"\0.text\0.shstrtab\0.symtab\0.strtab\0.eh_frame\0"
    names = {".text": 1, ".shstrtab": 7, ".symtab": 17, ".strtab": 25, ".eh_frame": 33}
    secs = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    secs.append((names[".text"], 1, text_flags, text_vaddr, TEXT_OFF, len(text), 0, 0, 4, 0))
    extra = bytearray()
    base = len(body)
    shstr_off = base
    extra += shstr
    secs_tail = [(names[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)]
    if mapsyms:
        strtab = bytearray(b"\0")
        syms = bytearray(24)                       # the null symbol
        for address, name in mapsyms:
            off = len(strtab)
            strtab += name.encode() + b"\0"
            syms += struct.pack("<IBBHQQ", off, 0, 0, 1, address, 0)
        while (base + len(extra)) % 8:
            extra += b"\0"
        sym_off = base + len(extra)
        extra += syms
        str_off = base + len(extra)
        extra += strtab
        # .symtab links to .strtab, the section after it (index 4).
        secs_tail.append((names[".symtab"], 2, 0, 0, sym_off, len(syms), 4, 1, 8, 24))
        secs_tail.append((names[".strtab"], 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0))
    if ehframe is not None:
        while (base + len(extra)) % 8:
            extra += b"\0"
        eh_off = base + len(extra)
        extra += ehframe
        secs_tail.append((names[".eh_frame"], 1, 2, 0, eh_off, len(ehframe), 0, 0, 8, 0))
    secs += secs_tail
    body += extra
    while len(body) % 8:
        body += b"\0"
    shoff = len(body) if sections else 0
    if sections:
        for s in secs:
            body += struct.pack("<IIQQQQIIQQ", *s)
    if seg_from_zero:
        p_off, p_vaddr = 0, text_vaddr - TEXT_OFF
        p_filesz = TEXT_OFF + len(text) + len(gap)
    else:
        p_off, p_vaddr, p_filesz = TEXT_OFF, text_vaddr, len(text) + len(gap)
    flags = 0x5 if pf_x else 0x4
    ph = struct.pack("<IIQQQQQQ", 1, flags, p_off, p_vaddr, p_vaddr, p_filesz, p_filesz, 0x1000)
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4], eh[5], eh[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, e_machine, 1, text_vaddr, 64, shoff, e_flags, 64, 56, 1,
                     64 if sections else 0, len(secs) if sections else 0, 2 if sections else 0)
    body[0:64] = eh
    body[64:64 + 56] = ph
    return bytes(body)


def with_e_type(data, e_type):
    b = bytearray(data)
    struct.pack_into("<H", b, 16, e_type)
    return bytes(b)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(prefix="binary-isa.")))
        self.n = 0

    def put(self, data):
        self.n += 1
        path = self.dir / f"case{self.n}"
        path.write_bytes(data)
        return path

    def one(self, data, want_verdict, **counts):
        """scan() of `data`, which must have verdict `want_verdict` and the given counts; and check() of it as a
        file, whose result must follow from the verdict. Return (scan's counts, check's result)."""
        res = binary_isa.scan(data)
        self.assertEqual(res["verdict"], want_verdict, res)
        for key, value in counts.items():
            self.assertEqual(res[key], value, f"{key}: {res}")
        out = binary_isa.check(self.put(data))
        self.assertEqual(set(out), API_KEYS)
        self.assertEqual(out["result"], {"CLEAN": "pass", "UNEXAMINED": "error"}.get(want_verdict, "fail"), out)
        self.assertEqual((out["words"], out["compressed"], out["outside_model"], out["unwinder_vlenb"]),
                         (res["insn32"], res["rvc16"], res["outside_model"], res["unwinder_vlenb"]), out)
        return res, out


class Verdicts(Base):
    def test_clean_with_a_zero_padding_word(self):
        res, out = self.one(mkelf(NOP + ADD + Z32 + NOP), "CLEAN", insn32=3, zero_parcels=2, rvc16=0, odd_zero=0,
                            exec_bytes=16)
        self.assertEqual((out["e_type"], out["machine"], out["words"], out["first"]), ("ET_EXEC", "EM_RISCV", 3, None))
        self.assertIn("every one in the model's ISA", out["detail"])

    def test_compressed_instructions_are_found_and_located(self):
        res, out = self.one(mkelf(NOP + CNOP + CADD + ADD), "RVC", rvc16=2, insn32=2)
        self.assertEqual(out["first"], f"rvc16 at {TEXT_VADDR + 4:#x}")
        self.assertIn("2 compressed (16-bit) instruction(s)", out["detail"])
        self.assertIn(f"first rvc16 at {TEXT_VADDR + 4:#x}", out["detail"])
        _, at = binary_isa.walk(NOP + CNOP + CADD + ADD, TEXT_VADDR)
        self.assertEqual(at["rvc16"], [TEXT_VADDR + 4, TEXT_VADDR + 6])

    def test_a_lone_zero_parcel_mid_stream_is_a_finding(self):
        # c.unimp, or padding that leaves the next instruction at 2 mod 4.
        self.one(mkelf(NOP + Z16 + ADD + CNOP), "RVC", odd_zero=1, misaligned32=1)
        # The last parcel starts at 2 mod 4 too, so it is not padding.
        self.one(mkelf(NOP + Z16 + ADD + Z16), "NOT-RV64G", odd_zero=2, misaligned32=1, rvc16=0)

    def test_a_trailing_zero_fill_of_either_parity_is_padding(self):
        self.one(mkelf(NOP + ADD + Z16), "CLEAN", zero_parcels=1, odd_zero=0)
        self.one(mkelf(NOP + ADD + Z32 + Z16), "CLEAN", zero_parcels=3, odd_zero=0)

    def test_a_misaligned_zero_run_at_the_end_is_still_a_finding(self):
        # The run starts at 2 mod 4, which only a 16-bit step can cause.
        self.one(mkelf(NOP + CNOP + Z16), "RVC", rvc16=1, odd_zero=1)

    def test_a_long_encoding_is_not_rv64g(self):
        res, out = self.one(mkelf(NOP + LONG48 + Z16 + ADD), "NOT-RV64G", long=1, rvc16=0)
        self.assertEqual(out["first"], f"long at {TEXT_VADDR + 4:#x}")
        self.assertIn("not uniform aligned 32-bit code (long 1", out["detail"])

    def test_a_region_ending_inside_an_instruction(self):
        self.one(mkelf(NOP + ADD[:2]), "NOT-RV64G", tail=1)
        self.one(mkelf(NOP + b"\x13"), "NOT-RV64G", tail=1)

    def test_a_section_starting_at_2_mod_4(self):
        self.one(mkelf(NOP + ADD, text_vaddr=TEXT_VADDR + 2), "NOT-RV64G", misaligned32=2)

    def test_a_section_at_an_odd_address_has_no_aligned_word(self):
        # The words are in the model, but none of them is at a multiple of 4.
        res, _ = self.one(mkelf(NOP + ADD + NOP, text_vaddr=TEXT_VADDR + 1), "NOT-RV64G", misaligned32=3,
                          insn32=3)
        self.assertEqual(res["first"], ("misaligned32", TEXT_VADDR + 1))
        self.one(mkelf(Z32 + NOP, text_vaddr=TEXT_VADDR + 3), "NOT-RV64G", odd_zero=1, misaligned32=1)
        # The census reads the walk's words, or none: an odd address is never read as a clean region.
        with self.assertRaisesRegex(binary_isa.Unexamined, "an odd address has no aligned word"):
            binary_isa.isa_census(NOP + ADD, TEXT_VADDR + 1, True, 2)
        # A region that starts at 2 mod 4 is never clean either: its first parcel is not aligned.
        _, at = binary_isa.walk(Z16 + NOP + ADD + Z16, TEXT_VADDR + 2)
        self.assertEqual(at["odd_zero"], [TEXT_VADDR + 2])
        # In a clean region, the one cast and the bytes.find search find what the slow path finds.
        buf = NOP + ADD + Z32 + VSETVLI + Z32 + VSETVLI
        counts, at = binary_isa.walk(buf, TEXT_VADDR)
        self.assertFalse(any(at.values()), at)
        census, pairs = binary_isa.isa_census(buf, TEXT_VADDR, True, counts["insn32"])
        slow, slow_pairs = binary_isa.isa_census(buf, TEXT_VADDR, False, counts["insn32"])
        self.assertEqual((census, list(pairs())), (slow, list(slow_pairs())))
        outw = {0x0C007057: "rvv-vsetvl"}
        self.assertEqual(binary_isa.outside_sites(buf, TEXT_VADDR, True, outw, pairs),
                         binary_isa.outside_sites(buf, TEXT_VADDR, False, outw, slow_pairs))
        self.assertEqual(binary_isa.outside_sites(buf, TEXT_VADDR, True, outw, pairs),
                         [(TEXT_VADDR + 12, 0x0C007057), (TEXT_VADDR + 20, 0x0C007057)])


class HeaderClaims(Base):
    """The EF_RISCV_RVC bit decides nothing; the instructions do."""

    def test_bit_set_over_code_without_compressed_instructions_passes(self):
        res, out = self.one(mkelf(NOP + ADD + NOP, e_flags=5), "CLEAN")
        self.assertEqual(res["e_flags"], 5)

    def test_bit_clear_over_compressed_code_fails(self):
        res, out = self.one(mkelf(NOP + CNOP + CNOP + ADD, e_flags=4), "RVC", rvc16=2)
        self.assertEqual(res["e_flags"], 4)
        self.assertEqual(out["e_type"], "ET_EXEC")


class WhereTheCodeIs(Base):
    def test_a_text_segment_from_offset_0_does_not_decode_the_headers(self):
        res, out = self.one(mkelf(NOP + ADD, seg_from_zero=True), "CLEAN", exec_bytes=8)
        self.assertEqual(res["pf_x"]["header_in_x"], 64 + 56)
        self.assertEqual(res["pf_x"]["gap_zero"], TEXT_OFF - 64 - 56)

    def test_a_section_header_table_in_the_text_segment_is_not_decoded(self):
        # Go's linker puts the section header table right after the program header table, in the text segment.
        b = bytearray(mkelf(NOP + ADD, seg_from_zero=True))
        shoff, shnum = struct.unpack_from("<Q", b, 40)[0], struct.unpack_from("<H", b, 60)[0]
        b[0x200:0x200 + 64 * shnum] = b[shoff:shoff + 64 * shnum]
        struct.pack_into("<Q", b, 40, 0x200)
        res, _ = self.one(bytes(b), "CLEAN", exec_bytes=8, regions=1)
        self.assertEqual(res["pf_x"]["header_in_x"], 64 + 56 + 64 * shnum)

    def test_e_ehsize_does_not_hide_a_segment_gap(self):
        # There is no section header table. e_ehsize claims 65535 bytes, but the ELF header is still only 64 bytes and
        # the non-zero gap after the program header is decoded.
        b = bytearray(mkelf(NOP + VSETVLI, sections=False, seg_from_zero=True))
        struct.pack_into("<H", b, 52, 0xFFFF)
        res, _ = self.one(bytes(b), "NOT-MODEL", outside_model=1, exec_bytes=TEXT_OFF + 8 - 64 - 56)
        self.assertEqual(res["pf_x"]["header_in_x"], 64 + 56)

    def test_a_non_zero_gap_mapped_executable_is_decoded(self):
        self.one(mkelf(NOP + ADD, gap=CNOP + CNOP), "RVC", rvc16=2, regions=2)

    def test_a_zero_gap_is_padding(self):
        res, _ = self.one(mkelf(NOP + ADD, gap=Z32 * 4), "CLEAN", regions=1)
        self.assertEqual((res["pf_x"]["gap_zero"], res["pf_x"]["gap_nonzero"]), (16, 0))

    def test_without_section_headers_the_segment_is_decoded(self):
        self.one(mkelf(NOP + CNOP + CNOP, sections=False, seg_from_zero=True), "RVC", rvc16=2)
        res, _ = self.one(mkelf(NOP + ADD, sections=False, seg_from_zero=True), "CLEAN",
                          exec_bytes=TEXT_OFF + 8 - 64 - 56, rvc16=0)
        self.assertEqual(res["located_by"], "segments")

    def test_mapping_symbols_mark_data_without_passing_it(self):
        data = struct.pack("<I", 0x12345678)       # low bits 00: two "16-bit" parcels
        res, out = self.one(mkelf(NOP + data + ADD, mapsyms=[(TEXT_VADDR, "$x"), (TEXT_VADDR + 4, "$d"),
                                                             (TEXT_VADDR + 8, "$x")]),
                            "RVC", rvc16=2, in_data=2, mapping_symbols=3)
        self.assertIn("2 finding(s) inside $d data", out["detail"])

    def test_a_data_section_mapped_executable_is_decoded(self):
        # The loader maps a PF_X segment executable whatever its section headers say: a section without
        # SHF_EXECINSTR inside one is named, and its bytes are decoded like a gap, so they never pass unexamined.
        for text, verdict in ((NOP + CNOP + CNOP, "RVC"), (NOP + VSETVLI, "NOT-MODEL"), (NOP + ADD, "CLEAN")):
            res, out = self.one(mkelf(text, text_flags=0x2), verdict)
            self.assertEqual(res["pf_x"]["data_in_x"], [(".text", len(text))])
            self.assertEqual((res["pf_x"]["gap_zero"], res["pf_x"]["gap_nonzero"]), (0, len(text)))
        # All zero, it is padding, and nothing was examined.
        res, out = self.one(mkelf(Z32 * 2, text_flags=0x2), "UNEXAMINED", exec_bytes=0)
        self.assertEqual((res["pf_x"]["gap_zero"], res["pf_x"]["gap_nonzero"]), (8, 0))

    def test_a_well_formed_note_section_mapped_executable_is_data(self):
        # Go's linker puts .note.go.buildid and .note.gnu.build-id in the text segment, in front of .text. A note
        # section whose bytes are whole, well-formed notes is named and not decoded; any other bytes are decoded.
        def as_note(blob):
            b = bytearray(blob)
            shoff = struct.unpack_from("<Q", b, 40)[0]
            struct.pack_into("<I", b, shoff + 64 + 4, binary_isa.SHT_NOTE)
            return bytes(b)
        note = struct.pack("<III", 4, 8, 4) + b"Go\0\0" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        res, out = self.one(as_note(mkelf(note, text_flags=0x2, gap=NOP + ADD)), "CLEAN")
        self.assertEqual(res["pf_x"]["data_in_x"], [(".text", len(note))])
        # The same bytes with a size that runs past the section are not notes: decoded, and they fail.
        bad = struct.pack("<III", 4, 4000, 4) + b"Go\0\0" + CNOP * 4
        res, out = self.one(as_note(mkelf(bad, text_flags=0x2, gap=NOP)), "RVC")
        # A well-formed note that is not a build id can wrap any bytes: it is decoded too.
        other = struct.pack("<III", 4, 8, 1) + b"XYZ\0" + CNOP * 4
        self.one(as_note(mkelf(other, text_flags=0x2, gap=NOP)), "RVC")
        # One Go and one GNU build id are notes; a second of either is not, so repeats cannot wrap any bytes.
        gnu = struct.pack("<III", 4, 8, 3) + b"GNU\0" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        res, out = self.one(as_note(mkelf(note + gnu, text_flags=0x2, gap=NOP + ADD)), "CLEAN")
        self.assertEqual(res["pf_x"]["data_in_x"], [(".text", len(note + gnu))])
        wrap = struct.pack("<III", 4, 8, 3) + b"GNU\0" + CNOP * 4
        for twice in (gnu + wrap, struct.pack("<III", 4, 8, 4) + b"Go\0\0" + CNOP * 4 + note):
            self.assertFalse(binary_isa.whole_notes(twice, 0, len(twice)))
        self.one(as_note(mkelf(gnu + wrap, text_flags=0x2, gap=NOP)), "RVC")
        self.one(as_note(mkelf(note + struct.pack("<III", 4, 8, 4) + b"Go\0\0" + CNOP * 4, text_flags=0x2,
                               gap=NOP)), "RVC")

    def test_a_build_id_note_is_taken_once_in_the_whole_binary(self):
        # Two note sections, each one GNU build-id note whose descriptor is compressed code: each is whole notes on its
        # own, but the binary has one GNU build id, so the second section is decoded, and fails.
        def gnu(desc):
            return struct.pack("<III", 4, len(desc), 3) + b"GNU\0" + desc
        first, second = gnu(CNOP * 32), gnu(CNOP * 32)
        b = bytearray(mkelf(first + second, text_flags=0x2, gap=NOP + ADD))
        shoff = struct.unpack_from("<Q", b, 40)[0]
        shnum = struct.unpack_from("<H", b, 60)[0]
        self.assertEqual(shoff + shnum * 64, len(b), "the section header table ends the file")
        header = bytearray(b[shoff + 64:shoff + 128])
        struct.pack_into("<I", b, shoff + 64 + 4, binary_isa.SHT_NOTE)
        struct.pack_into("<Q", b, shoff + 64 + 32, len(first))
        struct.pack_into("<I", header, 4, binary_isa.SHT_NOTE)
        struct.pack_into("<QQQ", header, 16, TEXT_VADDR + len(first), TEXT_OFF + len(first), len(second))
        b += header
        struct.pack_into("<H", b, 60, shnum + 1)
        self.one(bytes(b), "RVC")
        seen = set()
        self.assertTrue(binary_isa.whole_notes(first, 0, len(first), seen))
        self.assertFalse(binary_isa.whole_notes(second, 0, len(second), seen))

    def test_a_section_must_be_where_its_segment_maps_it(self):
        # The code is at 2 mod 4, and its section header says 0 mod 4.
        b = bytearray(mkelf(NOP + ADD, text_vaddr=TEXT_VADDR + 2))
        shoff = struct.unpack_from("<Q", b, 40)[0]
        struct.pack_into("<Q", b, shoff + 64 + 16, TEXT_VADDR)
        with self.assertRaisesRegex(binary_isa.Unexamined, r"section \.text says it is at 0x11000, but PF_X "
                                                           r"LOAD\[0\] maps it at 0x11002"):
            binary_isa.scan(bytes(b))
        out = binary_isa.check(self.put(bytes(b)))
        self.assertEqual(out["result"], "error", out)


class NothingExamined(Base):
    def test_no_executable_section_and_no_pf_x_segment(self):
        res, out = self.one(mkelf(NOP, text_flags=0x2, pf_x=False), "UNEXAMINED", exec_bytes=0)
        self.assertIn("examined nothing", out["detail"])

    def test_an_empty_executable_section(self):
        self.one(mkelf(b""), "UNEXAMINED", exec_bytes=0)

    def test_files_that_are_not_riscv_elf64(self):
        b = bytearray(mkelf(NOP))
        b[4] = 1                                    # ELF32
        big = bytearray(mkelf(NOP))
        big[5] = 2                                  # big-endian
        cut = mkelf(NOP)[:TEXT_OFF]                 # the section header table is past the end
        for data, e_type in ((b"not an elf at all" * 8, None), (b"\x7fELF", None), (bytes(b), None),
                             (bytes(big), None), (cut, "ET_EXEC")):
            out = binary_isa.check(self.put(data))
            self.assertEqual((out["result"], out["e_type"]), ("error", e_type), out)
            self.assertTrue(out["detail"].startswith("cannot examine: "), out)
        out = binary_isa.check(self.dir / "absent")
        self.assertEqual(out["result"], "error", out)
        self.assertTrue(out["detail"].startswith("cannot read the file: "), out)

    def test_another_machine_fails(self):
        out = binary_isa.check(self.put(mkelf(NOP, e_machine=0x3E)))
        self.assertEqual((out["result"], out["machine"], out["words"]), ("fail", "0x3e", 0), out)
        self.assertIn("not EM_RISCV", out["detail"])
        with self.assertRaises(binary_isa.Unexamined):
            binary_isa.scan(mkelf(NOP, e_machine=0x3E))

    def test_et_dyn_fails_even_with_clean_code(self):
        out = binary_isa.check(self.put(with_e_type(mkelf(NOP + ADD), 3)))
        self.assertEqual((out["result"], out["e_type"], out["words"], out["first"]), ("fail", "ET_DYN", 2, None), out)
        self.assertTrue(out["detail"].startswith("e_type is ET_DYN, not ET_EXEC"), out)
        # The instructions are still examined and named.
        out = binary_isa.check(self.put(with_e_type(mkelf(NOP + CNOP + CNOP), 1)))
        self.assertEqual((out["result"], out["e_type"], out["compressed"]), ("fail", "ET_REL", 2), out)
        self.assertIn("; also 2 compressed (16-bit) instruction(s)", out["detail"])


class ModelISA(Base):
    """A 32-bit word the model does not execute is a finding, and the modeled neighbours of each family are not."""

    def test_modeled_words_stay_clean(self):
        # unimp is EDefinedIllegal, the word sanitizers in trap mode emit; frcsr reads fcsr.
        self.one(mkelf(NOP + UNIMP + FRCSR + ADD), "CLEAN", insn32=4, outside_model=0)

    def test_vector_and_bit_manipulation_words_are_outside(self):
        res, out = self.one(mkelf(NOP + VSETVLI + VLE8 + SH1ADD + CLZ + ADD), "NOT-MODEL", insn32=6,
                            outside_model=4, rvc16=0)
        self.assertEqual(out["families"], {"rvv-mem": 1, "rvv-vsetvl": 1, "zba": 1, "zbb": 1})
        self.assertEqual(out["first"], f"outside_model at {TEXT_VADDR + 4:#x}")
        self.assertIn("4 word(s) outside the model's ISA (rvv-mem 1, rvv-vsetvl 1, zba 1, zbb 1) among 6 32-bit",
                      out["detail"])

    def test_a_csr_read_that_decodes_is_still_outside(self):
        res, out = self.one(mkelf(NOP + VLENB_A0 + VLENB_T0 + RDTIME), "NOT-MODEL", outside_model=3)
        self.assertEqual(list(out["families"].items()), [("csr-vlenb", 2), ("csr-counter", 1)])

    def test_a_reserved_rounding_mode_is_outside(self):
        self.one(mkelf(NOP + FADD_RM5), "NOT-MODEL", outside_model=1, families={"fp-reserved-rm": 1})

    def test_compressed_outranks_outside_and_both_are_counted(self):
        # The slow path, for a region with a finding, must find the same words.
        res, out = self.one(mkelf(NOP + CNOP + CNOP + VSETVLI + ADD), "RVC", rvc16=2, outside_model=1)
        self.assertEqual(out["families"], {"rvv-vsetvl": 1})

    def test_the_first_finding_names_the_isa_failure(self):
        res, out = self.one(mkelf(NOP + VSETVLI + ADD), "NOT-MODEL")
        self.assertTrue(out["first"].startswith("outside_model at "), out)
        self.assertNotIn("compressed", out["detail"])

    def test_the_unwinder_read_is_exempt_when_no_cfi_names_7202(self):
        res, out = self.one(mkelf(NOP + UNW_IDIOM, ehframe=cie_fde(EH_SP_RA)), "CLEAN", outside_model=0,
                            unwinder_vlenb=1)
        self.assertEqual({k: res["cfi"][k] for k in ("parsed", "names_vlenb", "sections", "cies", "fdes", "insns")},
                         {"parsed": True, "names_vlenb": False, "sections": 1, "cies": 1, "fdes": 1, "insns": 6})
        self.assertIn("1 libunwind vlenb read(s) exempt", out["detail"])

    def test_the_unwinder_read_is_a_finding_when_cfi_names_7202(self):
        # DW_CFA_offset_extended 7202, 0: the rule a frame that saves vector state would carry.
        res, _ = self.one(mkelf(NOP + UNW_IDIOM, ehframe=cie_fde(b"\x05\xa2\x38\x00")), "NOT-MODEL",
                          outside_model=1, unwinder_vlenb=0)
        self.assertEqual((res["cfi"]["parsed"], res["cfi"]["names_vlenb"]), (True, True))
        # 7202 inside a CFA expression (DW_OP_bregx 7202 0), found by the block search.
        self.one(mkelf(NOP + UNW_IDIOM, ehframe=cie_fde(b"\x0f\x04\x92\xa2\x38\x00")), "NOT-MODEL",
                 outside_model=1, unwinder_vlenb=0)
        # The non-minimal spelling 0xA2 0xB8 0x00.
        self.one(mkelf(NOP + UNW_IDIOM, ehframe=cie_fde(b"\x0f\x05\x92\xa2\xb8\x00\x00")), "NOT-MODEL",
                 outside_model=1, unwinder_vlenb=0)

    def test_the_unwinder_read_is_a_finding_when_cfi_does_not_parse(self):
        # 0x3f is no call-frame opcode: an .eh_frame this cannot read exempts nothing.
        res, _ = self.one(mkelf(NOP + UNW_IDIOM, ehframe=cie_fde(b"\x3f")), "NOT-MODEL", outside_model=1,
                          unwinder_vlenb=0)
        self.assertEqual((res["cfi"]["parsed"], res["cfi"]["names_vlenb"]), (False, True))

    def test_the_unwinder_read_is_a_finding_without_an_eh_frame_to_read(self):
        # No .eh_frame section: call-frame information is found by program header, not by name.
        res, _ = self.one(mkelf(NOP + UNW_IDIOM), "NOT-MODEL", outside_model=1, unwinder_vlenb=0)
        self.assertEqual((res["cfi"]["parsed"], res["cfi"]["sections"]), (False, 0))
        # No section headers at all: the segment is still decoded, and nothing is exempt.
        self.one(mkelf(NOP + UNW_IDIOM, sections=False), "NOT-MODEL", outside_model=1, unwinder_vlenb=0)

    def test_the_idiom_branch_must_be_bne_between_two_registers(self):
        eh = cie_fde(EH_SP_RA)
        # beq a1,a0,8: the csrr is the fall-through for every register but 7202.
        beq = struct.pack("<5I", 0x00002537, 0xC225051B, 0x00A58463, 0xC2202573, 0x00008067)
        self.one(mkelf(NOP + beq, ehframe=eh), "NOT-MODEL", outside_model=1, unwinder_vlenb=0)
        # bne a0,a0,8 never branches: the csrr always runs.
        same = struct.pack("<5I", 0x00002537, 0xC225051B, 0x00A51463, 0xC2202573, 0x00008067)
        self.one(mkelf(NOP + same, ehframe=eh), "NOT-MODEL", outside_model=1, unwinder_vlenb=0)
        # The idiom with the same .eh_frame is exempt.
        self.one(mkelf(NOP + UNW_IDIOM, ehframe=eh), "CLEAN", outside_model=0, unwinder_vlenb=1)

    def test_only_the_idiom_is_exempt(self):
        eh = cie_fde(EH_SP_RA)
        # The same csrr without the compare against 7202.
        bare = struct.pack("<4I", 0x00002537, 0x00000013, 0x00A59463, 0xC2202573)
        self.one(mkelf(NOP + bare, ehframe=eh), "NOT-MODEL", outside_model=1, unwinder_vlenb=0)
        # A compare against another number (7201).
        near = struct.pack("<4I", 0x00002537, 0xC215051B, 0x00A59463, 0xC2202573)
        self.one(mkelf(NOP + near, ehframe=eh), "NOT-MODEL", outside_model=1, unwinder_vlenb=0)
        # The idiom exempts its own site, not the file: a second, bare read stays a finding.
        self.one(mkelf(NOP + UNW_IDIOM + VLENB_T0, ehframe=eh), "NOT-MODEL", outside_model=1, unwinder_vlenb=1)
        # The idiom in a region with another finding is not exempt: its words are not known to be instructions.
        self.one(mkelf(NOP + UNW_IDIOM + CNOP, ehframe=eh), "RVC", outside_model=1, unwinder_vlenb=0)


def enc(opc, f3=0, f7=0, rd=0, rs1=0, rs2=0):
    """An R-type word: the fields where Decode.v reads them."""
    return opc | rd << 7 | f3 << 12 | rs1 << 15 | rs2 << 20 | f7 << 25


def csr(address, f3, rd=0, src=0):
    """A Zicsr word: csrrw/csrrs/csrrc (f3 = 1, 2, 3) or csrrwi/csrrsi/csrrci (5, 6, 7) on CSR `address`."""
    return 0x73 | rd << 7 | f3 << 12 | src << 15 | address << 20


# theories/Riscv/Decode.v's Goal checks, every one: (word, the class decode() names, or None where the Goal says
# decode is None).
DECODE_GOALS = [
    (0x00000013, "op-imm"),      # addi x0,x0,0 = nop
    (0x00C58533, "op"),          # add a0,a1,a2
    (0xFE0796E3, "branch"),      # bnez a5, .-20
    (0x00153513, "op-imm"),      # sltiu a0,a0,1 = seqz
    (0x02B4D53B, "mul-32"),      # divuw a0,s1,a1
    (0x140536AF, "lr"),          # lr.d.aq a3,(a0)
    (0x00000073, "ecall"),
    (0x00100073, "ebreak"),
    (0x00200073, None),          # uret: privileged
    (0x0FF0000F, "fence"),       # fence iorw,iorw
    (0x8330000F, "fence"),       # fence.tso
    (0x0000100F, "fence.i"),
    (0x00A0100F, None),          # fence.i with non-zero reserved fields
    (0x0FF0080F, None),          # fence with rd != 0
    (0x8120000F, None),          # fm = 8 without pred = succ = rw
    (0x341022F3, "csr"),         # csrrs t0,mepc,zero
    (0x00C58553, "fp-arith"),    # fadd.s fa0,fa1,fa2,rne
    (0x40058553, None),          # fcvt.s.s
    (0x42158553, None),          # fcvt.d.d
    (0x00000001, None),          # low two bits not 11
    (0x0000852A, None),
]

# The other match arms of Decode.v's decode, at their edges.
DECODE_ARMS = [
    (enc(0x67, f3=1), None),                    # jalr needs funct3 0
    (enc(0x63, f3=2), None),                    # no branch with funct3 2 or 3
    (enc(0x63, f3=3), None),
    (enc(0x03, f3=6), "load"),                  # lwu
    (enc(0x03, f3=7), None),                    # no "ldu"
    (enc(0x23, f3=3), "store"),                 # sd
    (enc(0x23, f3=4), None),
    (enc(0x13, f3=1, f7=0x01), "slli"),         # shift amount 32..63: bit 25 is the amount's bit 5
    (enc(0x13, f3=1, f7=0x02), None),           # bits [31:26] must be 0
    (enc(0x13, f3=5, f7=0x21), "srli/srai"),    # srai by 32..63
    (enc(0x13, f3=5, f7=0x40), None),
    (enc(0x1B, f3=1, f7=0x01), None),           # slliw: bit 25 must be 0
    (enc(0x1B, f3=5, f7=0x20), "srliw/sraiw"),
    (enc(0x1B, f3=2), None),
    (enc(0x33, f3=1, f7=0x20), None),           # only sub and sra take funct7 0x20
    (enc(0x33, f3=7, f7=0x01), "mul"),          # remu
    (enc(0x33, f7=0x02), None),
    (enc(0x3B, f3=2), None),
    (enc(0x3B, f3=1, f7=0x01), None),           # no mulhw
    (enc(0x3B, f3=0, f7=0x01), "mul-32"),       # mulw
    (0x0000000F, "fence"),                      # fm = 0, pred = succ = 0
    (0x8320000F, None),                         # fm = 8, pred = rw, succ = r
    (enc(0x0F, f3=2), None),
    (enc(0x73, f3=4), None),
    (csr(0xC00, 2, rd=10), "csr"),              # rdcycle a0: decodes
    (enc(0x2F, f3=1), None),                    # AMO width other than .w and .d
    (enc(0x2F, f3=2, f7=0x05 << 2), None),      # funct5 0x05
    (enc(0x2F, f3=3, f7=0x02 << 2, rs2=1), None),   # lr.d with rs2 != 0
    (enc(0x2F, f3=3, f7=0x03 << 2, rs2=1), "amo"),  # sc.d
    (enc(0x2F, f3=2, f7=0x1C << 2), "amo"),     # amomaxu.w
    (enc(0x07, f3=2), "flw/fld"),
    (enc(0x07, f3=1), None),                    # flh: no Zfh
    (enc(0x27, f3=3), "fsw/fsd"),
    (enc(0x27, f3=4), None),                    # fsq: no Q
    (enc(0x43, f7=0x01), "fma"),                # fmadd.d
    (enc(0x4F, f7=0x02), None),                 # fmt 10: no H
    (enc(0x53, f7=0x2C, rs2=1), None),          # fsqrt needs rs2 0
    (enc(0x53, f7=0x11, f3=3), None),           # fsgnj funct3 3
    (enc(0x53, f7=0x15, f3=2), None),           # fmin/fmax funct3 2
    (enc(0x53, f7=0x51, f3=3), None),           # fcmp funct3 3
    (enc(0x53, f7=0x60, rs2=4), None),          # fcvt to an integer type that is not w, wu, l or lu
    (enc(0x53, f7=0x69, rs2=0, f3=1), None),    # fcvt.d.w: exact, rm must be 0
    (enc(0x53, f7=0x69, rs2=2, f3=1), "fcvt"),  # fcvt.d.l: any rm
    (enc(0x53, f7=0x20, rs2=1), "fcvt"),        # fcvt.s.d
    (enc(0x53, f7=0x21, f3=1), None),           # fcvt.d.s: exact, rm must be 0
    (enc(0x53, f7=0x70, f3=2), None),           # fmv.x.w / fclass.s: funct3 0 or 1
    (enc(0x53, f7=0x71, f3=1), "fmv/fclass"),   # fclass.d
    (enc(0x53, f7=0x78, f3=1), None),           # fmv.w.x: funct3 0
    (enc(0x53, f7=0x79), "fmv"),                # fmv.d.x
    (enc(0x53, f7=0x02), None),
    (enc(0x0B), None),                          # custom-0
    (0x0000001F, None),                         # the first parcel of a 48-bit encoding
]

# The rules of theories/Riscv/Sem.v (and Fpu.v's rmode_of_field) that decide whether a decoded word executes, and of
# theories/LinuxProcessSem/RiscvSemantics.v (decode_exec_accesses, interp_eff_accesses) that sort the result into
# modeled and unmodeled: (word, what outside() answers).
SEM_CASES = [
    (0x00000073, None),                          # ecall: the system call, taken before the decoder
    (0x00100073, None),                          # ebreak: EEbreak, MachineFault (SIGTRAP), a modeled death
    (0xC0001073, None),                          # unimp = csrrw x0,cycle,x0: EDefinedIllegal, a modeled death
    (csr(0xC22, 1), None),                       # csrrw x0,vlenb,x0: a write to read-only, EDefinedIllegal
    (csr(0xC22, 2, rd=10, src=11), None),        # csrrs a0,vlenb,a1 writes: EDefinedIllegal
    (csr(0xC00, 6, rd=10, src=1), None),         # csrrsi a0,cycle,1 writes: EDefinedIllegal
    (csr(0xC00, 2, rd=10), "csr-counter"),       # rdcycle: reads a read-only CSR legally; csr_slice has none
    (csr(0xC00, 7, rd=10, src=0), "csr-counter"),    # csrrci with uimm 0 does not write
    (0xC22022F3, "csr-vlenb"),                   # csrr t0,vlenb
    (0xC2202573, "csr-vlenb"),                   # csrr a0,vlenb
    (0xC21027F3, "csr-vtype"),                   # csrr a5,vtype
    (csr(0xC20, 2, rd=10), "csr-vl"),
    (0xC0102573, "csr-counter"),                 # rdtime a0
    (0x341022F3, "csr-other"),                   # csrrs t0,mepc,zero: decodes, not executed
    (csr(0x800, 1, src=10), "csr-other"),        # a read/write address csr_slice does not resolve
    (0x00302573, None),                          # frcsr a0
    (0x00251073, None),                          # fsrm a0
    (csr(0x001, 5, src=0), None),                # csrrwi x0,fflags,0
    (0x00C58553, None),                          # fadd.s, rm 0
    (0x00C5D553, "fp-reserved-rm"),              # fadd.s, rm 5
    (enc(0x53, f3=6), "fp-reserved-rm"),         # fadd.s, rm 6
    (enc(0x53, f3=7), None),                     # fadd.s, rm 7 (frm at run time)
    (enc(0x53, f7=0x2D, f3=5), "fp-reserved-rm"),    # fsqrt.d, rm 5
    (enc(0x43, f3=6), "fp-reserved-rm"),         # fmadd.s, rm 6
    (enc(0x53, f7=0x60, f3=5), "fp-reserved-rm"),    # fcvt.w.s, rm 5
    (enc(0x53, f7=0x69, rs2=2, f3=6), "fp-reserved-rm"),   # fcvt.d.l, rm 6
    (enc(0x53, f7=0x10, f3=2), None),            # fsgnjx.s: funct3 is not a rounding mode
    (enc(0x53, f7=0x51, f3=2), None),            # feq.d
    # Words decode rejects, with the family named for a reader.
    (0x00200073, "system-priv"),                 # uret
    (0x00A0100F, "misc-mem-ext"),
    (0x0FF0080F, "misc-mem-ext"),
    (0x8120000F, "misc-mem-ext"),
    (0x40058553, "fp-ext"),                      # fcvt.s.s
    (0x42158553, "fp-ext"),                      # fcvt.d.d
    (0xD205C553, "fp-ext"),                      # fcvt.d.w with rm != 0
    (0x4205C553, "fp-ext"),                      # fcvt.d.s with rm != 0
    (0x00000001, "not-32bit"),
    (0x0000852A, "not-32bit"),
    (0x0C007057, "rvv-vsetvl"),                  # vsetvli zero,zero,e8,m1,ta,ma
    (0x02058007, "rvv-mem"),                     # vle8.v v0,(a1)
    (0x20B52533, "zba"),                         # sh1add a0,a0,a1
    (0x0805151B, "zba"),                         # slli.uw a0,a0,0
    (0x60051513, "zbb"),                         # clz a0,a0
    (0x60151513, "zbb"),                         # ctz a0,a0
    (0x0AB54533, "zbb"),                         # min a0,a0,a1
    (0x0AB55533, "zbb"),                         # minu a0,a0,a1
    (0x0AB56533, "zbb"),                         # max a0,a0,a1
    (0x0AB51533, "zbc"),                         # clmul a0,a0,a1
    (0x0EB55533, "zicond"),                      # czero.eqz a0,a0,a1
    (enc(0x0B), "custom"),
]


class Decoder(unittest.TestCase):
    def test_decode_v_goal_checks(self):
        for word, want in DECODE_GOALS:
            self.assertEqual(binary_isa.decode(word), want, f"{word:#010x}")

    def test_decode_v_match_arms(self):
        for word, want in DECODE_ARMS:
            self.assertEqual(binary_isa.decode(word), want, f"{word:#010x}")

    def test_sem_v_execution_rules(self):
        for word, want in SEM_CASES:
            self.assertEqual(binary_isa.outside(word), want, f"{word:#010x}")

    def test_every_goal_word_executes_unless_decode_rejects_it(self):
        # Of Decode.v's Goal words, only mepc's CSR read decodes and does not execute.
        for word, cls in DECODE_GOALS:
            self.assertEqual(binary_isa.outside(word) is None, cls is not None and word != 0x341022F3, f"{word:#010x}")

    def test_both_sides_are_reached(self):
        # A decoder that accepted everything, or nothing, would fail one side.
        self.assertTrue(any(want is None for _, want in SEM_CASES))
        self.assertTrue(any(want is not None for _, want in SEM_CASES))
        self.assertTrue(any(want is None for _, want in DECODE_ARMS + DECODE_GOALS))
        self.assertTrue(any(want is not None for _, want in DECODE_ARMS + DECODE_GOALS))


class Model(unittest.TestCase):
    def test_the_model_the_rules_were_checked_against(self):
        self.assertRegex(binary_isa.MODEL_COMMIT, r"^[0-9a-f]{40}$")
        self.assertEqual(set(binary_isa.MODEL_FILES),
                         {"theories/Riscv/Decode.v", "theories/Riscv/DecodeC.v", "theories/Riscv/Sem.v",
                          "theories/Riscv/Fpu.v", "theories/LinuxProcessSem/RiscvSemantics.v"})
        for sha in binary_isa.MODEL_FILES.values():
            self.assertRegex(sha, r"^[0-9a-f]{64}$")


MODEL = os.environ.get("OSS_VERIFY_MODEL")
# Decode.v's constructors in its Goal checks, and the class decode() names for each.
GOAL_CLASSES = {"OpImm": "op-imm", "Op": "op", "Branch": "branch", "Mul32": "mul-32", "Lr": "lr", "Ecall": "ecall",
                "Ebreak": "ebreak", "Fence": "fence", "FenceI": "fence.i", "Csr": "csr", "Fari": "fp-arith"}


@unittest.skipUnless(MODEL, "OSS_VERIFY_MODEL is not set: the directory of a checkout of the model, holding theories/")
class ModelCheckout(unittest.TestCase):
    def test_the_model_files_have_the_code_the_rules_were_checked_against(self):
        import model_release
        self.assertEqual(model_release.stale(MODEL, binary_isa.MODEL_FILES), [])

    def test_the_goal_checks_of_the_checkout_are_the_ones_ported(self):
        text = (pathlib.Path(MODEL) / "theories" / "Riscv" / "Decode.v").read_text(encoding="utf-8")
        goals = re.findall(r"Goal\s+(?:bool_decide\s*\(\s*)?decode\s+(0x[0-9a-fA-F]+)\s*(?:\(\*.*?\*\)\s*)?"
                           r"=\s*(?:None|Some\s*\(?\s*(\w+))", text, re.S)
        found = [(int(word, 16), GOAL_CLASSES[ctor] if ctor else None) for word, ctor in goals]
        self.assertEqual(found, DECODE_GOALS)


class CommandLine(Base):
    def test_one_json_line_per_file_and_the_worst_status(self):
        clean, rvc = self.put(mkelf(NOP + ADD)), self.put(mkelf(NOP + CNOP + CNOP))
        bad = self.put(b"\x7fELF-truncated")
        for paths, status in (([clean], 0), ([clean, rvc], 1), ([rvc, bad, clean], 2)):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(binary_isa.main([str(p) for p in paths]), status)
            rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual([row["path"] for row in rows], [str(p) for p in paths])
            self.assertTrue(all(set(row) == API_KEYS | {"path"} for row in rows))
        self.assertEqual(binary_isa.main([]), 2)

    def test_first_has_the_documented_form(self):
        out = binary_isa.check(self.put(mkelf(NOP + CNOP + CNOP + ADD)))
        self.assertRegex(out["first"], r"^[a-z0-9_]+ at 0x[0-9a-f]+$")
        self.assertNotIn("\n", out["detail"])


if __name__ == "__main__":
    unittest.main()
