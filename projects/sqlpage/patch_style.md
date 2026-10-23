<!-- Copyright 2026 SQLPage contributors. SPDX-License-Identifier: Apache-2.0 -->
# SQLPage report and patch preferences

Report all actionable findings, including findings without a patch and bugs
outside the initial fuzz target. Explain security impact separately from other
correctness problems, and group findings with the same root cause.

Documentation fixes and small, behavior-preserving refactorings are welcome.
A separate equivalence proof is not required. Keep changes focused and include
appropriate regression coverage. Follow the project's
[CONTRIBUTING.md](https://github.com/sqlpage/SQLPage/blob/main/CONTRIBUTING.md) and
[AGENTS.md](https://github.com/sqlpage/SQLPage/blob/main/AGENTS.md), including its
SQL parameter-binding, streaming and database-portability contracts.

AI-generated findings and patches are welcome for maintainer review. Send them
privately to the enrollment contact. Publish proofs after fixes are public
(`publish: after_fixes`).
