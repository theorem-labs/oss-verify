<!-- Copyright 2026 Vishal Sachdev. SPDX-License-Identifier: Apache-2.0 -->
# Patch style and report preferences: canvas-mcp

## What we care about
- canvas-mcp reads Canvas LMS content that students and other course members write: page bodies, syllabi,
  announcements, discussion posts and calendar events. Treat each byte of that content as untrusted.
- The anonymization of student data (FERPA) comes first. Then the HTML tokenizer (`src/canvas_mcp/core/html.py`),
  which turns untrusted HTML into text for the model and gives the offsets that the accessibility tools write back to
  Canvas.

## Which findings to report
- Report all findings, with a severity on each.
- Severity: a leak of student identity or other personal data past the anonymization is critical. A crash, an
  uncaught exception, a hang or a quadratic cost on untrusted HTML is high. A wrong offset that can corrupt a page
  that a tool writes back to Canvas is high. Wrong plain text with no other effect is low.
- Also send a finding that has no patch.

## How to report
- Put related findings into one report.

## Which patches to write
- Bugs that no fuzz target can hit: also report them, with a patch if you have one.
- Behaviour that we do not support, for example a refused allocation (`MemoryError`): make the fuzz target narrower.
- Documentation: do not send patches that change only the documentation.
- Refactoring that makes the code easier to verify: only changes that keep the behaviour. No proof of the same
  behaviour is necessary.

## Our contribution policy
- AI-generated patches are welcome. A human maintainer reviews each one before it merges.

## Patch format
- Add a regression test under `tests/` that fails before the fix and passes after it.
- Keep `ruff check .` clean. Type hints on each function, with PEP 604 unions (`X | Y`).
- One commit for each patch, with a conventional-commit subject (`fix: ...`), under 72 characters.
- Do not write `fixes #N`, `closes #N` or `resolves #N` in the middle of a sentence: GitHub then closes the issue. A
  trailer at the start of a line (`Closes #N`) is permitted.
- Write commit messages, comments and documentation changes in Simplified Technical English (ASD-STE100).

## Where and how to send patches
- Attach the patch to the report, sent to `primary_contact`. Do not open a pull request without our request.
