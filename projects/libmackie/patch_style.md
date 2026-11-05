# Patch style and report preferences

libmackie is FreeMixer's library for the Mackie Control Universal (MCU) wire protocol, the
language a Behringer X-Touch speaks over MIDI. It decodes what the surface sends (the channel
messages in `src/mackie_codec.c`, the handshake SysEx in `src/mackie_sysex.c`), reads the text
the host puts on its displays (`src/mackie_text.c`, `src/mackie_display.c`), checks the control
map the host builds (`src/mackie_map.c`) and encodes what the host sends back. These readers are
the code that matters most here, and the five fuzz targets drive them.

## How findings and patches land

Nothing from the pipeline enters libmackie as it is. A maintainer reads each finding, reproduces
it against the libmackie harness and build, and writes the fix in FreeMixer/libmackie as an
ordinary change. A patch you send is a description of a fix, and we re-author it before it lands.

No attribution line, trailer, or generated-by marker enters the history. When a finding leads to
a fix, we quote its id in the libmackie issue that tracks the fix, not in a commit.

## Which findings to report

Report all of them. A memory-safety bug in a reader is the most severe: a write out of bounds
first, then a read out of bounds, then undefined behaviour that a sanitizer traps. A property
check that fails is a bug of the same rank as the code it guards. A finding without a patch is
welcome. Put findings that share one cause in one report.

## Which patches to write

- A fix is minimal: the smallest change that removes the bug, with a test under `tests/` that
  fails before the fix and passes after it. An input that finds the bug goes into
  `fuzz/corpus/<harness>/`, written by `fuzz/gen-corpus.c`, as well.
- The library allocates nothing; a stop after the harness's own allocation failed is not a
  property.
- A change to the wire format cites its source in `include/mackie/mackie.h`, where the bytes
  captured live from an X-Touch are recorded.
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
