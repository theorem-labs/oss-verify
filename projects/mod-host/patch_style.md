# Patch style and report preferences

mod-host is the LV2 host that MOD and Zynthian drive over a text command protocol on a local socket. FreeMixer
carries it on the branch `freemixer` of FreeMixer/mod-host: the upstream code, a few patches FreeMixer offers
upstream, and a host backend layer that other hosts share. The commands of any local client reach the command parser
(`src/protocol.c`), the dispatcher that maps each verb onto a host backend (`src/host-dispatch.c`), and, for the state
verbs, the state paths below the host's directory (`src/state-paths.c`). The scenario reader (`src/host-scenario.c`)
reads the test scenarios that every host backend must answer the same way. These are the code the four fuzz targets
drive.

## How findings and patches land

Nothing from the pipeline enters mod-host as it is. A maintainer reads each finding, reproduces it against the
mod-host harness and build, and writes the fix in FreeMixer/mod-host as an ordinary change; a fix in upstream code is
also offered to mod-audio/mod-host. A patch you send is a description of a fix, and we re-author it before it lands.

Every commit on the `freemixer` branch is signed. No attribution line, trailer, or generated-by marker enters the
history. When a finding leads to a fix, we quote its id in the issue that tracks the fix, not in a commit.

## Which findings to report

Report all of them. A memory-safety bug in the parser or the dispatcher is the most severe: a write out of bounds
first, then a read out of bounds, then undefined behaviour that a sanitizer traps. A property check that fails is a
bug of the same rank as the code it guards. A finding without a patch is welcome. Put findings that share one cause in
one report.

`fuzz_statepaths` does not give `MakePluginStatePath()` a request path that holds `..`: the function does not confine
such a path to the instance's directory. If you find that a command can reach it with such a path, report it as a
finding of its own.

## Which patches to write

- A fix is minimal: the smallest change that removes the bug. An input that finds the bug goes into
  `fuzz/corpus/<harness>/` and `fuzz/gen-corpus.sh` as well.
- The fuzz targets do not refuse allocations; a stop after the harness's own allocation failed is not a property.
- Patches that change only the documentation are welcome.
- A refactoring that makes the code easier to verify is welcome only if it keeps the behaviour, and only with a test
  that shows it.

## Patch format

- Plain C in the style of the file you change: four spaces, braces on their own lines.
- One change per commit. The subject line says what the change does, in the present tense. The body is plain prose
  that says why.
- Comments and commit messages describe the code as it is, not how it came to be.

## What the proofs mean for us

A proof is about the static riscv64 binary that this directory builds, under Theorem's RISC-V and Linux process
semantics. It does not transfer by itself to the x86-64 and arm64 packages that we ship. A proof removes classes of
bugs from the code that the fuzz targets drive. It does not certify a shipped binary, and we do not describe it as if
it did.
