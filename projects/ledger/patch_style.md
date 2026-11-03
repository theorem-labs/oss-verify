# Patch style and report preferences

The ledger is a small C99 project. Its core is the record, category and filter API in `src/manager.c`.

## What we care about
Memory safety and correctness of the record/category/filter core come first. The interactive terminal UI
(`src/ui.c`, `src/platform.c`) matters less; a finding there is still welcome.

## Which findings to report
Report all correctness and security findings. Rate an out-of-bounds write, a use-after-free or a NULL
dereference as critical; an out-of-bounds read as high; a wrong result that does not touch memory as
medium; a crash on malformed input as high. Report a finding even when there is no patch.

## How to report
Group related findings into one report when they share a root cause. Otherwise one report per finding.

## Which patches to write
Also report bugs that the fuzz targets cannot reach, if the proof finds them. Refused allocations are not a
supported behaviour of this project yet: the map growth path calls `exit()`. Prefer a narrower fuzz target
over a library change that makes allocation failure a supported case. Do not send patches that change only
the documentation. Refactoring is welcome only when it keeps behaviour; a change that can fix a bug must be
a separate finding with its own patch.

## Our contribution policy
The project has no separate policy on AI-generated contributions. Findings and patches are reviewed by the
maintainer before they are used.

## Patch format
Keep each patch minimal and focused on the reported bug. Use one commit per patch. The commit message says
what fails and why the change fixes it. Add a regression test under `test/` when the existing GTest setup
can express it. Do not require Simplified Technical English (ASD-STE100).

## Where and how to send patches
Send the patch to `primary_contact` with the report it belongs to. Do not open a pull request for a finding.
