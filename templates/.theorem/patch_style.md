<!-- Adapted from OSS Scanner's templates/threat_model.md (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, Apache-2.0. Modified 2026 by Theorem Labs, PBC: free text about the reports and patches that a project wants. Modified 2026 by Theorem Labs, PBC: the patch_style.md of .theorem/. -->
<!-- Template: copy to .theorem/patch_style.md in your repository, beside config.yml. -->
# Patch style and report preferences

This file covers your report preferences and your patch style. It is free text for our AI, which reads it before it sends you a report or writes a patch. Each item below is only a suggestion. Keep the topics that matter to you, and delete the others.

## What you care about
- e.g. "memory safety in the parser comes first; the CLI tools matter less"

## Which findings to report
- Only security-critical findings, or all of them? How do you rate severity?
- e.g. "report only memory-safety bugs; an out-of-bounds write is critical, an out-of-bounds read is high, a crash on input over 1 GiB is low"
- Findings without a patch: e.g. "also send a finding that has no patch" or "send a finding only with a patch"

## How to report
- e.g. "put related findings into one report"

## Which patches to write
- Bugs that no fuzz target can hit: e.g. "only bugs that a fuzz target can hit" or "also bugs that you find on the way"
- Behaviour that we do not support, in particular refused allocations: e.g. "make the fuzz target narrower" or "make the library handle it"
- Documentation: e.g. "also send patches that change only the documentation"
- Refactoring that makes the code easier to verify: e.g. "only changes that keep the behaviour" or "also minor changes that can fix bugs"
- A proof that the behaviour does not change: e.g. "send a refactoring only with such a proof"

## Our contribution policy
- e.g. "our policy on AI-generated contributions: https://example.org/CONTRIBUTING.md#ai"

## Patch format
- e.g. "minimal: just enough to fix the bug, with a regression test under tests/" or "merge-ready: follow CONTRIBUTING.md and clang-format, and add a test"
- e.g. "one commit for each patch; a subject line under 72 characters; a Signed-off-by line"
- e.g. "write commit messages, comments and documentation changes in Simplified Technical English (ASD-STE100)"

## Where and how to send patches
- By default, a patch goes to `primary_contact`, with the report that it belongs to.
- e.g. "attach the patch to the report; do not open a pull request"

## Anything to leave alone
- e.g. "the deprecated v1 API, which we are removing"
