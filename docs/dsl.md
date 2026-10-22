# The DSL format

This page describes the DSL format: how a DSL fuzz target reads its input as a small program of API calls, and what it writes. It is for maintainers and coding agents who write DSL fuzz targets, and for readers of their statements.

A DSL fuzz target is also called an API driver. It is the starting point for a fuzz target at the level of the API. It is a fuzz target with the usual shape: an `LLVMFuzzerTestOneInput` ([build-contract.md](build-contract.md#the-fuzz-targets)). Inside that function, a small virtual machine runs the program that the input holds. Each operation of the program calls the library. The project defines its own operations. The machine gives the frames, the checks, the observables and the limits that this page describes.

**Pending.** The runtime of the DSL is not in this repository yet. It comes with a later toolchain version. The parts of this page that are not settled yet are marked "pending".

## The input

The driver reads the outer header of the input file, and gives `LLVMFuzzerTestOneInput` the payload ([build-contract.md](build-contract.md#the-driver)). For a DSL fuzz target, the payload starts with an inner header, and then the program:

    [u16 config length][config bytes][u32 allocation mask][program]

The two integers are little-endian.

* The low 15 bits of the first word give the length of the config bytes. A published build has no counting mode, so the top bit has no effect.
* If the input file is shorter than the outer header, the driver refuses it with status 2, as for each fuzz target.
* If the payload is shorter than the 6-byte inner header, the fuzz target runs no operation and returns 0, never -1. With the next toolchain version, -1 gives status 3, which must tell only that a check failed.

Thus status 2 tells that the driver refused the outer header, and status 3 tells only that a check failed.

The config bytes of the inner header set the run:

| byte | bits | meaning |
|---|---|---|
| 0 | 0 and 1 | repeats: the program runs 1 + n times in one call. Each repeat starts with a new machine state, but the library keeps its global state. |
| 0 | 2 | terse: write only the summary line of each repeat. Each operation still runs, and each check is still evaluated. |
| 0 | 3 and 4 | the scale of the step budget: 1, 4, 16 or 64 times the base budget ([below](#the-step-budget)) |
| 0 | 5 to 7 | reserved |
| 1 | all | the seed of the deterministic filler, which makes the bytes that an operation asks for. If there is no byte 1, the seed is 0. |
| 2 and more | all | the extension of the allocation mask ([below](#the-allocation-mask)) |

A one-byte config `00` gives one repeat, the full output, the base budget and seed 0. Thus the shortest useful payload starts with the inner header `01 00 00 00 00 00 00`: config length 1, config byte 0 and an empty allocation mask.

## Frames

The program is a sequence of frames. The machine reads each frame once, in order, from the first byte.

    [op][length][operand bytes]

* `length` is one byte. The value 255 means that a little-endian u16 length follows.
* A frame that goes past the end of the program stops at the end. A last op byte with nothing after it runs with length 0. A missing header byte reads as 0.
* An operation reads its operands only from its own frame. A read past the end of the frame gives 0, and a slice stops at the end of the frame. The machine skips each operand that the operation does not read.

Thus the meaning of each frame depends only on its op byte and its own operand bytes.

## Operand encoding

An operation reads its operands with these readers. All integers are little-endian.

| reader | bytes | value |
|---|---|---|
| u8, u16, u32 | 1, 2, 4 | the integer |
| flag | one byte for each 8 flags | the next bit, low bit first. The supply of bits starts again at each frame. |
| choice of n | 1 | the byte modulo n |
| bounded by a cap | 2 | the u16 modulo (cap + 1) |
| slice | 2 + length | a u16 length, then that many bytes |

## Project operations

The op byte selects the operation:

* `255` selects an operation of the machine ([below](#machine-operations)).
* Each other value selects the project operation `op % n`, where n is the number of operations that the project defines, from 1 to 255.

Thus each byte except 255 is a valid instruction. After each project operation, the machine records its result:

| result | value | meaning |
|---|---|---|
| ok | 0 | the call succeeded |
| liberr | 1 | the library reported a failure |
| skip | 2 | the operation did not call the library, for example because a handle is missing |
| none | 3 | no project operation ran yet |

A library failure is an observable, not an exit status: the trace, the counters and the digest record it ([below](#the-observables)). In C++, a `std::bad_alloc` during an operation becomes the result liberr.

> **WARNING:** Do not call `abort()` for a result of the library. Call `abort()` only for a property that the fuzz target states, inside a project operation ([the add-project skill](../.claude/skills/add-project/SKILL.md), step 3.7).

## Machine operations

A frame with op byte 255 is an operation of the machine:

    [255][length][sub][operands]

The operands have fixed widths. In the examples, H is a u64 and N is a u32.

| sub | form | operands | a check? | it passes if |
|---|---|---|---|---|
| none | | | yes | never |
| 0 | `snap` | none | no | (it writes the state of the machine) |
| 1 | `expect digest H` | u64 | yes | the digest is H |
| 2 | `expect count SEL N` | u8, u32 | yes | the counter SEL (0 steps, 1 ok, 2 liberr, 3 skip) is N |
| 3 | `expect last R` | u8 | yes | the last result is R |
| 4 | `expect live K N` | u8, u8 | yes | N live handles have kind K (K 0: any kind) |
| 5 | `expect slot S K` | u8, u8 | yes | handle slot S has kind K (K 0: empty) |
| 6 | `expect obj S K LEN H` | u8, u8, u32, u64 | yes | slot S holds an object of kind K, and its serialized form has LEN bytes and the hash H |
| 7 | `expect alloc N` | u32 | yes | this repeat made N counted allocations |
| 8 | `allocs` | none | no | (it writes the number of counted allocations of this repeat) |
| 9 to 255 | | any | yes | never |

For example, `ff 02 03 00` is `expect last 0`, and `ff 01 08` is `allocs`.

The checks are expectations that the input chooses: the input predicts a value, and the check compares. These rules apply to them:

* **Checks fail closed.** A check fails if its frame has fewer operand bytes than its width. A check also fails for an empty 255 frame, an unknown sub, or a selector, slot or kind out of range. The same applies to an empty slot, a kind that does not agree, and a kind that cannot be serialized.
* **Each check is evaluated.** A failed check writes one line that ends in `FAIL`, and counts in the summary. The run continues.
* **A check that the budget does not reach fails.** If the budget stops the run early, each check after that point counts as one failure.
* **A machine operation changes nothing.** It does not change the digest, the counters, the handles or the filler. Thus a check added to a program changes no value that the program computes, if the program still fits in the budget.

## The result of a call

`LLVMFuzzerTestOneInput` returns -1 if a check failed in a repeat, and 0 in all other cases. A failed check is normal, because most inputs predict wrongly. A failed property is not: the fuzz target calls `abort()` for it.

* Today's driver writes the -1 on standard output and exits with status 0 ([build-contract.md](build-contract.md#exit-statuses)).
* The driver of the next toolchain version exits with status 3 after a -1.
* A library that calls `exit()`, `abort()` or `assert()` ends the process with its own status, before the summary line.

## The observables

A statement compares and constrains what a DSL fuzz target writes. These items are its observables:

* **The trace.** Each project operation writes lines. A report line has the form `<what> rc=<rc> n=<length> h=<hash>`. Each line is at most 239 bytes. The output stops at 256 KiB, but the counters and the digest continue.
* **The digest.** It is a 64-bit FNV-1a hash (offset basis 1469598103934665603, prime 1099511628211). It folds each byte of each line that a project operation writes, whether the line is written or not. It also folds two bytes after each project operation: `op % n` and the result. The lines of the machine operations are not folded.
* **The summary line.** Each repeat writes one, also in terse mode:

      <name> rep=R steps=S ok=A err=B skip=C chk=N fail=F out=O digest=<16 hex digits>

  `steps` counts the project operations that ran, `chk` the checks, and `fail` the failed checks.
* **The return value** of each call, which the driver writes ([above](#the-result-of-a-call)).

A quiet build computes the same values, counters and result, but writes nothing. A statement is about the loud builds.

## Repeats

Bits 0 and 1 of config byte 0 make the program run 1 to 4 times in one call. Each repeat starts with a new machine state: empty handles, zero counters and the same seed. The library keeps its global state between repeats. Thus a difference between the first repeat and a later one shows hidden state in the library.

## The step budget

Each frame that the machine runs costs one step: a project operation or a machine operation. The run stops when the steps reach the budget:

    budget = base << (2 × scale)

The base budget is 4,096 steps, or less if the fuzz target sets it lower. The scale is bits 3 and 4 of config byte 0. Thus each run ends, whatever the program.

## The allocation mask

The allocation mask makes chosen allocations fail ([build-contract.md](build-contract.md#allocation-failure-fuzz-targets)). Bit i of the mask makes the i-th counted allocation fail. The allocation then returns `NULL` with `errno` set to `ENOMEM`, or a throwing `operator new` throws `std::bad_alloc`.

* Bits 0 to 31 are the u32 of the inner header.
* Bit i, for i of 32 or more, is bit (i − 32) % 8 of config byte 2 + (i − 32) / 8, low bit first. The extension has at most 4,096 bytes. A missing byte reads as 0.
* The memory of the machine itself is never counted, so no mask can make it fail.
* `expect alloc` and `allocs` give the number of counted allocations of this repeat.

**Pending:** which part arms the mask, and where its counter starts. Either the fuzz target arms the mask of the inner header at each call, or the allocation-failure driver owns the mask. The allocation functions that are counted, and whether `allocs` writes a total after the run, are also pending.

## An example

The toy library `kv` is a key-value store. Its DSL fuzz target defines four operations:

| op | operation | operands |
|---|---|---|
| 0 | `new`: make a store | none |
| 1 | `put`: store a value under a key | key slice, value slice |
| 2 | `get`: read the value of a key | key slice |
| 3 | `del`: remove a key | key slice |

This payload makes a store, stores `v` under `k1` and reads it back. Then it checks that the last call succeeded:

    01 00  00  00 00 00 00        inner header: config length 1, config byte 0, allocation mask 0
    00 00                         new
    01 07  02 00 6b 31  01 00 76  put: key "k1", value "v"
    02 04  02 00 6b 31            get: key "k1"
    ff 02  03 00                  expect last 0

To run it under the driver, put the outer header in front of it: six zero bytes ([build-contract.md](build-contract.md#run-a-binary)). The run writes the trace of the three operations, then a summary line with `steps=3 ok=3 err=0 skip=0 chk=1 fail=0`. The call returns 0. If you change the last frame to `ff 02 03 01`, the check fails, and the call returns -1.

A property of `kv` itself goes in a project operation, as a check that aborts. For example, `get` can check that a key read right after `put` gives the stored value, and call `abort()` if it does not.
