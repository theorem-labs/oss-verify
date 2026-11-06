# Findings and patches

Report memory safety defects, including out-of-bounds access, leaks, and double frees. Reports without patches are welcome. Keep reports concise and clear; identify the root cause and group related symptoms when possible. Findings and fixes for bugs outside the fuzz targets are welcome.

When a fuzz target reaches unsupported behavior, prefer making the library handle it. Allocation failure need not be survived.

Documentation-only patches are welcome. Accept bug fixes, but not refactoring solely to make the code easier to verify. A behavior-preserving refactoring must include a proof that behavior is unchanged.

Follow the project's contribution policy, including its AI-assisted contribution rules and requirement to reproduce a bug or security issue before reporting it: https://github.com/Yikai-Liao/tessera-sort/blob/main/CONTRIBUTING.md. Follow the project's code style, tests, and signed-off commit format. Use Simplified Technical English (ASD-STE100) for commit messages, comments, and documentation.
