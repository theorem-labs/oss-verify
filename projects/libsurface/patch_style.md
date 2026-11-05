# Patch style and report preferences

libsurface is FreeMixer's library for the device behaviour of a motorised control surface: the
motor-fader policy (never fight the hand), touch with its self-heal and release debounce, the bank
window, the board shadow and its replay, the meter step and the ring renderer. It speaks no wire
and keeps no thread or clock. The five fuzz targets drive its core through the calls a backend and
a host make (`surface_in_fader`, `surface_in_touch`, `surface_fader_served`, `surface_led`,
`surface_scribble`, `surface_bank_set` and the rest of `include/surface/surface.h`) and the key
table of the Control|24 (`src/diginet/c24_keys.c`).

## How findings and patches land

Nothing from the pipeline enters libsurface as it is. A maintainer reads each finding,
reproduces it against the libsurface harness and build, and writes the fix in FreeMixer/libsurface
as an ordinary change. A patch you send is a description of a fix, and we re-author it before it
lands.

Every commit in libsurface is signed. No attribution line, trailer, or generated-by marker enters
the history. When a finding leads to a fix, we quote its id in the libsurface issue that tracks
the fix, not in a commit.

## Which findings to report

Report all of them. A memory-safety bug is the most severe: a write out of bounds first, then a
read out of bounds, then undefined behaviour that a sanitizer traps (a NULL passed to memcpy
counts). A property check that fails is a bug of the same rank as the code it guards. A motor
write to a cap a hand holds is as severe as a memory-safety bug on the X-Touch, because it moves a
fader under the operator's fingers. A finding without a patch is welcome. Put findings that share
one cause in one report.

Bugs that no fuzz target can hit are welcome too, with the input or the reasoning that reaches
them. The DigiNet module (`src/diginet/surface_diginet.c`), the Mackie module
(`src/mackie/surface_mackie.c`) and `tools/surface-c24.c` have no harness (`fuzz/README.md` says
why); a finding there is welcome with the reasoning that reaches it.

## Which patches to write

- A fix is minimal: the smallest change that removes the bug, with a test under `tests/` that
  fails before the fix and passes after it. An input that finds the bug goes into
  `fuzz/corpus/<harness>/`, written by `fuzz/gen-corpus.c`, as well.
- The library allocates once, in `surface_create()`; a stop after the harness's own allocation
  failed is not a property.
- A change to a documented behaviour changes its comment in `include/surface/surface.h`, which is
  the contract the harnesses hold the library to (`fuzz/spec.h`).
- Patches that change only the documentation are welcome.
- A refactoring that makes the code easier to verify is welcome only if it keeps the behaviour,
  and only with a test that shows it.

## Patch format

- Plain C11, in the style of the file you change: tabs, braces on the line of the statement,
  `/* */` comments.
- One change per commit. The subject line says what the change does, in the present tense. The
  body is plain prose that says why.
- Comments and commit messages describe the code as it is, not how it came to be.

## What the proofs mean for us

A proof is about the static riscv64 binary that this directory builds, under Theorem's RISC-V
and Linux process semantics. It does not transfer by itself to the x86-64 glibc packages that
we ship. A proof removes classes of bugs from the code that the fuzz targets drive. It does not
certify a shipped binary, and we do not describe it as if it did.
