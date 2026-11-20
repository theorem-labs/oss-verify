# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests of .github/scripts/frame-pointers/frames.py, which need no Docker and no llvm-objdump:  uv run pytest

The probe job of .github/workflows/toolchain-images.yaml runs frames.py on llvm-objdump's disassembly of the probes
(frames.py probe) and of the base image's libraries (frames.py count). Each test here runs it as a program on a short
disassembly in the shape that `llvm-objdump -d -M no-aliases --no-show-raw-insn` prints for riscv64, given on standard
input (--objdump-output -), with an empty PATH, so that it can run no llvm-objdump. What is tested is what a user of
probe and count reads: the exit status, the functions that probe names, and the two numbers of count's line.
"""
import os
import pathlib
import re
import subprocess
import sys
import unittest

FRAMES = pathlib.Path(__file__).resolve().parents[1] / ".github" / "scripts" / "frame-pointers" / "frames.py"
PREFIX = "fp_probe_"  # the functions that probe reads
BINARY = "/out/fp-c/fp_probe"  # the binary that probe reads, as the probe job names it
ARCHIVE = "/opt/musl-sysroot/lib/libc.a"

# The functions of a probe binary, as llvm-objdump prints them: the label, then one line for each instruction. A
# linked binary calls with jal ra and makes a tail call with jal zero; each function returns with jalr zero, 0(ra).
LEAF = """\
0000000000011200 <fp_probe_leaf>:
   11200:      \taddiw\ta0, a0, 1
   11204:      \tjalr\tzero, 0(ra)
"""
# Its prologue sets s0 from sp before its call: it keeps a frame record.
FRAMED = """\
0000000000011208 <fp_probe_framed>:
   11208:      \taddi\tsp, sp, -16
   1120c:      \tsd\tra, 8(sp)
   11210:      \tsd\ts0, 0(sp)
   11214:      \taddi\ts0, sp, 16
   11218:      \tjal\tra, 0x11200 <fp_probe_leaf>
   1121c:      \tld\tra, 8(sp)
   11220:      \tld\ts0, 0(sp)
   11224:      \taddi\tsp, sp, 16
   11228:      \tjalr\tzero, 0(ra)
"""
# It keeps a value in s0 across its call (addi s0, a0, 0 is mv s0, a0): it keeps no frame record.
KEEPS_A_VALUE = """\
000000000001122c <fp_probe_keeps_a_value>:
   1122c:      \taddi\tsp, sp, -16
   11230:      \tsd\tra, 8(sp)
   11234:      \tsd\ts0, 0(sp)
   11238:      \taddi\ts0, a0, 0
   1123c:      \tjal\tra, 0x11200 <fp_probe_leaf>
   11240:      \tmulw\ta0, a0, s0
   11244:      \tld\tra, 8(sp)
   11248:      \tld\ts0, 0(sp)
   1124c:      \taddi\tsp, sp, 16
   11250:      \tjalr\tzero, 0(ra)
"""
# Its one jump is a tail call, which writes no ra: it makes no call.
TAIL_CALL = """\
0000000000011254 <fp_probe_tail_call>:
   11254:      \taddiw\ta0, a0, 7
   11258:      \tjal\tzero, 0x11200 <fp_probe_leaf>
"""
# It sets s0 from sp only after its first call: it keeps no frame record.
LATE_FRAME = """\
000000000001125c <fp_probe_late_frame>:
   1125c:      \taddi\tsp, sp, -16
   11260:      \tsd\tra, 8(sp)
   11264:      \tjal\tra, 0x11200 <fp_probe_leaf>
   11268:      \tsd\ts0, 0(sp)
   1126c:      \taddi\ts0, sp, 16
   11270:      \tjal\tra, 0x11200 <fp_probe_leaf>
   11274:      \tld\tra, 8(sp)
   11278:      \tld\ts0, 0(sp)
   1127c:      \taddi\tsp, sp, 16
   11280:      \tjalr\tzero, 0(ra)
"""
# It sets s0 from sp, then calls under a local label that it branches to: one function, which keeps a frame record.
BRANCHES = """\
0000000000011284 <fp_probe_branches>:
   11284:      \taddi\tsp, sp, -16
   11288:      \tsd\tra, 8(sp)
   1128c:      \tsd\ts0, 0(sp)
   11290:      \taddi\ts0, sp, 16
   11294:      \tbeq\ta0, zero, 0x1129c <.Ltmp0>
   11298:      \taddiw\ta0, a0, 1

000000000001129c <.Ltmp0>:
   1129c:      \tjal\tra, 0x11200 <fp_probe_leaf>
   112a0:      \tld\tra, 8(sp)
   112a4:      \tld\ts0, 0(sp)
   112a8:      \taddi\tsp, sp, 16
   112ac:      \tjalr\tzero, 0(ra)
"""
# A calling function that keeps a frame record, but whose name is not a probe's.
MAIN = """\
00000000000112b0 <main>:
   112b0:      \taddi\tsp, sp, -16
   112b4:      \tsd\tra, 8(sp)
   112b8:      \tsd\ts0, 0(sp)
   112bc:      \taddi\ts0, sp, 16
   112c0:      \tjal\tra, 0x112d4 <helper>
   112c4:      \tld\tra, 8(sp)
   112c8:      \tld\ts0, 0(sp)
   112cc:      \taddi\tsp, sp, 16
   112d0:      \tjalr\tzero, 0(ra)

00000000000112d4 <helper>:
   112d4:      \taddiw\ta0, a0, 1
   112d8:      \tjalr\tzero, 0(ra)
"""

# Two members of an archive, each under its heading. An object file calls with auipc ra and jalr ra, and makes a tail
# call with auipc t1 and jalr zero. a.o: framed, a calling function that keeps a frame record, and leaf, which sets s0
# from sp and makes no call. b.o: code under a local label, the member's first label, which calls and keeps no frame
# record; kept, which calls and keeps a value in s0; and tail, a tail call. The calling functions are framed, the code
# under .Lpcrel_hi0 and kept, and framed alone keeps a frame record: 1 of 3. Were a.o's last function not ended by
# b.o's heading, the code under .Lpcrel_hi0 would be inside leaf, and leaf would be a calling function that keeps a
# frame record: 2 of 3.
ARCHIVE_TEXT = f"""
{ARCHIVE}(a.o):\tfile format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <framed>:
       0:      \taddi\tsp, sp, -16
       4:      \tsd\tra, 8(sp)
       8:      \tsd\ts0, 0(sp)
       c:      \taddi\ts0, sp, 16
      10:      \tauipc\tra, 0
      14:      \tjalr\tra, 0(ra)
      18:      \tld\tra, 8(sp)
      1c:      \tld\ts0, 0(sp)
      20:      \taddi\tsp, sp, 16
      24:      \tjalr\tzero, 0(ra)

0000000000000028 <leaf>:
      28:      \taddi\tsp, sp, -16
      2c:      \tsd\ts0, 8(sp)
      30:      \taddi\ts0, sp, 16
      34:      \tld\ts0, 8(sp)
      38:      \taddi\tsp, sp, 16
      3c:      \tjalr\tzero, 0(ra)

{ARCHIVE}(b.o):\tfile format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <.Lpcrel_hi0>:
       0:      \tauipc\ta0, 0
       4:      \taddi\tsp, sp, -16
       8:      \tsd\tra, 8(sp)
       c:      \tauipc\tra, 0
      10:      \tjalr\tra, 0(ra)
      14:      \tld\tra, 8(sp)
      18:      \taddi\tsp, sp, 16
      1c:      \tjalr\tzero, 0(ra)

0000000000000020 <kept>:
      20:      \taddi\tsp, sp, -16
      24:      \tsd\tra, 8(sp)
      28:      \tsd\ts0, 0(sp)
      2c:      \taddi\ts0, a0, 0
      30:      \tauipc\tra, 0
      34:      \tjalr\tra, 0(ra)
      38:      \tld\tra, 8(sp)
      3c:      \tld\ts0, 0(sp)
      40:      \taddi\tsp, sp, 16
      44:      \tjalr\tzero, 0(ra)

0000000000000048 <tail>:
      48:      \tauipc\tt1, 0
      4c:      \tjalr\tzero, 0(t1)
"""


def disassembly(path, *functions):
    """What llvm-objdump prints for the file `path` whose .text holds `functions`: the file's heading, the section's,
    and each function after a blank line."""
    return (f"\n{path}:\tfile format elf64-littleriscv\n\nDisassembly of section .text:\n"
            + "".join(f"\n{function}" for function in functions))


def frames(text, *arguments):
    """frames.py ARGUMENT..., run as a program with `text` on its standard input and an empty PATH."""
    return subprocess.run([sys.executable, str(FRAMES), *arguments], input=text, capture_output=True, text=True,
                          env={**os.environ, "PATH": ""}, timeout=60)


class Probe(unittest.TestCase):
    """frames.py probe --expect fp|base on the disassembly of a probe binary."""

    def probe(self, expect, *functions):
        """frames.py probe --expect `expect` on a binary whose .text holds `functions`: its exit status, the probe
        functions it gives a line to, and its last line, the verdict. Its standard error must be empty: frames.py
        writes there only when it stops with status 2, and an exception, which exits 1 as a failed rule does, writes
        its traceback there."""
        done = frames(disassembly(BINARY, *functions), "probe", "--expect", expect, "--objdump-output", "-", BINARY)
        self.assertEqual(done.stderr, "")
        lines = done.stdout.splitlines()
        self.assertTrue(lines)
        return done.returncode, [line.split(":", 1)[0] for line in lines if line.startswith(PREFIX)], lines[-1]

    def test_a_calling_function_that_sets_s0_from_sp_before_its_call_keeps_a_frame_record(self):
        status, named, verdict = self.probe("fp", LEAF, FRAMED)
        self.assertEqual(status, 0, verdict)
        self.assertEqual(named, ["fp_probe_leaf", "fp_probe_framed"])
        status, _, verdict = self.probe("base", LEAF, FRAMED)
        self.assertEqual(status, 1, verdict)

    def test_a_calling_function_that_moves_a_value_into_s0_keeps_no_frame_record(self):
        status, _, verdict = self.probe("fp", LEAF, FRAMED, KEEPS_A_VALUE)
        self.assertEqual(status, 1, verdict)
        self.assertIn("fp_probe_keeps_a_value", verdict)
        self.assertNotIn("fp_probe_framed", verdict)
        status, _, verdict = self.probe("base", LEAF, FRAMED, KEEPS_A_VALUE)
        self.assertEqual(status, 0, verdict)
        self.assertIn("fp_probe_keeps_a_value", verdict)
        self.assertNotIn("fp_probe_framed", verdict)

    def test_a_tail_call_is_no_call_and_does_not_fail_expect_fp(self):
        status, named, verdict = self.probe("fp", LEAF, FRAMED, TAIL_CALL)
        self.assertEqual(status, 0, verdict)
        self.assertEqual(named, ["fp_probe_leaf", "fp_probe_framed", "fp_probe_tail_call"])
        self.assertNotIn("fp_probe_tail_call", verdict)

    def test_with_only_a_tail_call_no_function_calls_and_the_probe_fails(self):
        for expect in ("fp", "base"):
            with self.subTest(expect=expect):
                status, named, verdict = self.probe(expect, LEAF, TAIL_CALL)
                self.assertEqual(status, 1, verdict)
                self.assertEqual(named, ["fp_probe_leaf", "fp_probe_tail_call"])
                # The verdict is about the binary, which has no calling function, and names neither function as one
                # that keeps no frame record.
                self.assertIn(BINARY, verdict)
                self.assertNotIn("fp_probe_tail_call", verdict)
                self.assertNotIn("fp_probe_leaf", verdict)

    def test_an_addi_s0_sp_after_the_first_call_does_not_count(self):
        status, _, verdict = self.probe("fp", LEAF, FRAMED, LATE_FRAME)
        self.assertEqual(status, 1, verdict)
        self.assertIn("fp_probe_late_frame", verdict)
        self.assertNotIn("fp_probe_framed", verdict)
        status, _, verdict = self.probe("base", LEAF, FRAMED, LATE_FRAME)
        self.assertEqual(status, 0, verdict)
        self.assertIn("fp_probe_late_frame", verdict)

    def test_a_local_label_inside_a_function_does_not_start_a_new_function(self):
        # Were .Ltmp0 a function of its own, fp_probe_branches would make no call, and no probe function would.
        status, named, verdict = self.probe("fp", LEAF, BRANCHES)
        self.assertEqual(status, 0, verdict)
        self.assertEqual(named, ["fp_probe_leaf", "fp_probe_branches"])

    def test_a_binary_with_no_fp_probe_function_fails_the_probe(self):
        for expect in ("fp", "base"):
            with self.subTest(expect=expect):
                status, named, verdict = self.probe(expect, MAIN)
                self.assertEqual((status, named), (1, []), verdict)
                self.assertIn(BINARY, verdict)


class Count(unittest.TestCase):
    """frames.py count on the disassembly of an archive."""

    def test_an_archive_member_heading_ends_the_function_before_it(self):
        done = frames(ARCHIVE_TEXT, "count", "--objdump-output", "-", ARCHIVE)
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        lines = done.stdout.splitlines()
        self.assertEqual(len(lines), 1, done.stdout)
        path, _, numbers = lines[0].partition(": ")
        self.assertEqual(path, ARCHIVE)
        # N of M: the calling functions that keep a frame record, of the calling functions (ARCHIVE_TEXT says which).
        self.assertEqual(re.findall(r"\d+", numbers), ["1", "3"])


if __name__ == "__main__":
    unittest.main()
