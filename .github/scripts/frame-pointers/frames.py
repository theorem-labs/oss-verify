#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""frames.py: which functions of riscv64 machine code keep a frame record, from llvm-objdump's disassembly.

    frames.py probe --expect fp|base [--objdump-output FILE] BINARY
    frames.py count [--objdump-output FILE] ARCHIVE...

It runs `llvm-objdump -d -M no-aliases --no-show-raw-insn` on each file, with the llvm-objdump on PATH, and splits what
it prints into functions at their `<name>:` labels. A local label (.L...) inside a function does not start a new one.
With --objdump-output FILE (- is standard input), it reads that text and runs no llvm-objdump; it then takes one
BINARY or ARCHIVE, whose name it only prints. The job make of .github/workflows/toolchain-images.yaml runs it in a
builder container, which has llvm-objdump and python3 (.github/scripts/frame-pointers/probe).

The rules:
  * A call is a jal or a jalr whose destination register is ra (also printed x1), or a c.jalr, which writes ra. A
    jal or a jalr whose destination is zero (x0), such as a tail call or a return, is not a call, and nor is a c.jr.
  * A calling function is a function with a call.
  * A function keeps a frame record when an `addi s0, sp, N` or a `c.addi4spn s0, sp, N` comes before its first call
    (s0 is also printed fp or x8, and sp x2): before it calls, its prologue points s0 at its frame record.

probe reads the functions whose names start with fp_probe_ (the probes of this directory), and prints one line for
each. With --expect fp it passes when every calling function keeps a frame record; with --expect base, when at least
one calling function does not. It fails when no function has such a name, or when none of them calls.

count prints, for each archive, how many of its calling functions keep a frame record.

Exit status: 0 when it passes, 1 when the rule fails, 2 on a usage error or when llvm-objdump cannot run.
"""
import argparse
import re
import shutil
import subprocess
import sys

PREFIX = "fp_probe_"
OBJDUMP = "llvm-objdump"
OBJDUMP_FLAGS = ["-d", "-M", "no-aliases", "--no-show-raw-insn"]

# `0000000000011234 <name>:`, at the start of the line.
LABEL = re.compile(r"^[0-9a-fA-F]+ <(.+)>:$")
# `   11234:      \taddi\ts0, sp, 32`: the address (right-aligned, so indented while it is short), the mnemonic and the
# operands.
INSTRUCTION = re.compile(r"^\s*[0-9a-fA-F]+:\s+(\S+)\s*(.*)$")
RA = {"ra", "x1"}
S0 = {"s0", "fp", "x8"}
SP = {"sp", "x2"}


def say(text):
    print(text, flush=True)


def stop(status, message):
    print(f"frames.py: {message}", file=sys.stderr, flush=True)
    sys.exit(status)


class Function:
    """One function of the disassembly: its name, whether it calls, and whether it keeps a frame record."""

    def __init__(self, name):
        self.name = name
        self.calls = False
        self.frame = False  # an addi s0, sp, N before the first call


def operands(text):
    """The operands of an instruction: no `<symbol>` after a target, and no `#` comment."""
    text = re.sub(r"<[^>]*>", "", text.split("#", 1)[0])
    return [operand.strip() for operand in text.split(",") if operand.strip()]


def is_call(mnemonic, registers):
    if mnemonic in ("jal", "jalr"):
        return bool(registers) and registers[0] in RA
    return mnemonic == "c.jalr"


def sets_frame_pointer(mnemonic, registers):
    return (mnemonic in ("addi", "c.addi4spn") and len(registers) == 3 and registers[0] in S0
            and registers[1] in SP)


def functions(lines):
    """The functions of llvm-objdump's disassembly, in their order."""
    current = None
    for line in lines:
        line = line.rstrip("\n")
        label = LABEL.match(line)
        if label:
            if current is not None and label.group(1).startswith((".L", "$")):
                continue
            if current is not None:
                yield current
            current = Function(label.group(1))
            continue
        instruction = INSTRUCTION.match(line)
        if instruction:
            if current is not None and not current.calls:
                mnemonic, rest = instruction.groups()
                registers = operands(rest)
                if sets_frame_pointer(mnemonic, registers):
                    current.frame = True
                elif is_call(mnemonic, registers):
                    current.calls = True
            continue
        if line.strip() and not line[0].isspace():
            # A heading: the file, the archive member or the section. The function before it ends.
            if current is not None:
                yield current
            current = None
    if current is not None:
        yield current


def disassembly(path, given):
    """The lines of llvm-objdump's disassembly of `path`, or the lines of the file `given` (- is standard input)."""
    if given is not None:
        if given == "-":
            yield from sys.stdin
            return
        try:
            with open(given, encoding="utf-8", errors="replace") as text:
                yield from text
        except OSError as error:
            stop(2, f"cannot read {given}: {error}")
        return
    objdump = shutil.which(OBJDUMP)
    if objdump is None:
        stop(2, f"{OBJDUMP} is not on PATH: run this where the toolchain is, as in a builder container")
    try:
        process = subprocess.Popen([objdump, *OBJDUMP_FLAGS, path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   text=True, errors="replace")
    except OSError as error:
        stop(2, f"{OBJDUMP} cannot run: {error}")
    try:
        yield from process.stdout
    finally:
        process.stdout.close()
        status = process.wait()
    if status != 0:
        stop(2, f"{OBJDUMP} exited {status} on {path}")


def probe(arguments):
    found = [function for function in functions(disassembly(arguments.binary, arguments.objdump_output))
             if function.name.startswith(PREFIX)]
    if not found:
        say(f"fail: {arguments.binary} has no function whose name starts {PREFIX}")
        return 1
    for function in found:
        say(f"{function.name}: {'calling' if function.calls else 'not calling'}, "
            f"{'keeps a frame record' if function.frame else 'keeps no frame record'}")
    calling = [function for function in found if function.calls]
    if not calling:
        say(f"fail: no {PREFIX} function of {arguments.binary} makes a call")
        return 1
    without = [function.name for function in calling if not function.frame]
    if arguments.expect == "fp":
        if without:
            say(f"fail (--expect fp): {len(without)} of the {len(calling)} calling functions keep no frame record: "
                f"{', '.join(without)}")
            return 1
        say(f"pass (--expect fp): each of the {len(calling)} calling functions keeps a frame record")
        return 0
    if not without:
        say(f"fail (--expect base): each of the {len(calling)} calling functions keeps a frame record")
        return 1
    say(f"pass (--expect base): {len(without)} of the {len(calling)} calling functions keep no frame record: "
        f"{', '.join(without)}")
    return 0


def count(arguments):
    for archive in arguments.archives:
        calling = keeping = 0
        for function in functions(disassembly(archive, arguments.objdump_output)):
            if function.calls:
                calling += 1
                keeping += function.frame
        say(f"{archive}: {keeping} of {calling} calling functions keep a frame record")
    return 0


def main():
    given = argparse.ArgumentParser(add_help=False)
    given.add_argument("--objdump-output", metavar="FILE",
                       help="read this disassembly (- is standard input) and run no llvm-objdump")
    parser = argparse.ArgumentParser(description="Which functions of riscv64 machine code keep a frame record.")
    commands = parser.add_subparsers(dest="command", required=True)
    probing = commands.add_parser("probe", parents=[given], help="check the fp_probe_* functions of a binary")
    probing.add_argument("--expect", choices=("fp", "base"), required=True)
    probing.add_argument("binary")
    counting = commands.add_parser("count", parents=[given], help="count the calling functions that keep one")
    counting.add_argument("archives", nargs="+", metavar="archive")
    arguments = parser.parse_args()
    if arguments.command == "count" and arguments.objdump_output is not None and len(arguments.archives) != 1:
        counting.error("--objdump-output takes one ARCHIVE")
    return probe(arguments) if arguments.command == "probe" else count(arguments)


if __name__ == "__main__":
    sys.exit(main())
