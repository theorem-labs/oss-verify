# Patch style and report preferences

omx-dsp is the DSP library of FreeMixer: the primitives, the effect kernels and the instance faces that the mixing
engine and the omx plugins link statically. It holds no parser of files or presets. What reaches it from outside is a
host's control port words (any float or int, NaN and the infinities included), a block's samples, a rate, and a stream
of MIDI messages (`omx_note_map.h`). The six fuzz targets drive those: the instance faces (`include/omxdsp/fx/`), the
scalar laws every port goes through, the EQ's design and run path, the sample-rate converter, the two delay lines and
the note map. Most of the library is inline in `include/omxdsp/`.

## How findings and patches land

Nothing from the pipeline enters omx-dsp as it is. A maintainer reads each finding, reproduces it against the omx-dsp
harness and build, and writes the fix in FreeMixer/omx-dsp as an ordinary change. A patch you send is a description of
a fix, and we re-author it before it lands.

Every commit in omx-dsp is signed. No attribution line, trailer, or generated-by marker enters the history. When a
finding leads to a fix, we quote its id in the omx-dsp issue that tracks the fix, not in a commit.

## Which findings to report

Report all of them. A memory-safety bug on the path of a port word or a sample is the most severe: a write out of
bounds first, then a read out of bounds, then undefined behaviour that a sanitizer traps. A broken PRE or POST law of
the library, or a property check that fails, is a bug of the same rank as the code it guards. A finding without a patch
is welcome. Put findings that share one cause in one report.

A sample that goes non-finite from finite samples and any port value is a bug, because it reaches a live output.

Bugs that no fuzz target can hit are welcome too, with the input or the reasoning that reaches them. `fuzz/README.md`
says what the harnesses leave alone and why: two laws they skip (`rate-is-declared` at the rates that are not declared,
`bands-partition-unity` while a corner moves) and non-finite samples, where only the sanitizers read the run.

## Which patches to write

- A fix is minimal: the smallest change that removes the bug, with an oracle under `test/` that fails before the fix
  and passes after it. An input that finds the bug goes into `fuzz/corpus/<harness>/`, written by `fuzz/gen-corpus.c`,
  as well.
- A change to a kernel's output moves its golden digests in `test/golden/`, which only a commit that bumps the minor
  version may rewrite. Say so in the report.
- The library allocates nothing on the audio path; a stop after the harness's own allocation failed is not a property.
- Patches that change only the documentation are welcome.
- A refactoring that makes the code easier to verify is welcome only if it keeps the behaviour bit for bit, and only
  with a test that shows it.

## Patch format

- Plain C11, in the style of the file you change: two spaces, the brace on the line of the statement.
- One change per commit. The subject line says what the change does, in the present tense. The body is plain prose
  that says why.
- Comments and commit messages describe the code as it is, not how it came to be.

## What the proofs mean for us

A proof is about the static riscv64 binary that this directory builds, under Theorem's RISC-V and Linux process
semantics. It does not transfer by itself to the x86-64 and arm64 packages that we ship. A proof removes classes of
bugs from the code that the fuzz targets drive. It does not certify a shipped binary, and we do not describe it as if
it did.
