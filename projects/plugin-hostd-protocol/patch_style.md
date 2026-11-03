# Patch style and report preferences

plugin-hostd-protocol is the command protocol library of FreeMixer's plugin hosts: plugin-hostd and FreeMixer's
mod-host link it to read their controller's commands. Its command parser (`src/protocol.c`) reads every byte a local
client sends on the command socket, the dispatcher (`src/host-dispatch.c`) turns each verb into a call of the host's
backend and writes the reply, and the scenario reader (`src/host-scenario.c`) reads the test scenarios. The three fuzz
targets drive them.

## How findings and patches land

Nothing from the pipeline enters plugin-hostd-protocol as it is. A maintainer reads each finding, reproduces it
against the library's harness and build, and writes the fix in FreeMixer/plugin-hostd-protocol as an ordinary change.
A patch you send is a description of a fix, and we re-author it before it lands.

Every commit in plugin-hostd-protocol is signed. No attribution line, trailer, or generated-by marker enters the
history. When a finding leads to a fix, we quote its id in the issue that tracks the fix, not in a commit.

## Which findings to report

Report all of them. A memory-safety bug in the parser or the dispatcher is the most severe: a write out of bounds
first, then a read out of bounds, then undefined behaviour that a sanitizer traps. A property check that fails is a
bug of the same rank as the code it guards. A finding without a patch is welcome. Put findings that share one cause in
one report.

Bugs that no fuzz target can hit are welcome too, with the input or the reasoning that reaches them.

## Which patches to write

- A fix is minimal: the smallest change that removes the bug, with a test under `tests/` that fails before the fix and
  passes after it. An input that finds the bug goes into `fuzz/corpus/<harness>/` and `fuzz/gen-corpus.sh` as well.
- A fix that moves a line a check's `mutant:` record names updates that record in the same change
  (`make fuzz-records` names it).
- Patches that change only the documentation are welcome.
- A refactoring that makes the code easier to verify is welcome only if it keeps the behaviour, and only with a test
  that shows it.

## Patch format

- Plain C, in the style of the file you change: four spaces, braces on their own lines, `/* */` comments in new code.
- One change per commit. The subject line says what the change does, in the present tense. The body is plain prose
  that says why.
- Comments and commit messages describe the code as it is, not how it came to be.

## What the proofs mean for us

A proof is about the static riscv64 binary that this directory builds, under Theorem's RISC-V and Linux process
semantics. It does not transfer by itself to the x86-64 glibc packages that we ship. A proof removes classes of bugs
from the code that the fuzz targets drive. It does not certify a shipped binary, and we do not describe it as if it
did.
