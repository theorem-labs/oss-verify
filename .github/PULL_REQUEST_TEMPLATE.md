<!-- Adapted from OSS Scanner's .github/PULL_REQUEST_TEMPLATE.md (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: OSS Verify's checklist (terms, tools/check --twice, fuzz-target properties, build files, patch style). -->
## Enroll `projects/<name>`

Before I opened this pull request, I made sure of each point:

- [ ] I am a core maintainer of this project.
- [ ] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/).
- [ ] This pull request changes only `projects/<name>/`, for one project, and `tools/validate.py` finds no problem in it.
- [ ] `tools/check --no-shell --twice <name>` builds each fuzz target that I want verified, and the second build has the same bytes.
- [ ] Each property that a fuzz target checks stops the fuzz target when it is false (in C and C++, `abort()`, not `assert()`), an input in its seed corpus runs it, and its comment records a one-line change that makes it fail (step 3 of `.claude/skills/add-project/SKILL.md`).
- [ ] A `Dockerfile` and a `build.sh` are next to `project.yaml`. Or they are in one directory of the project's repository, and `dockerfile:` gives the path of the `Dockerfile`.
- [ ] `patch_style.md` (optional) tells which findings, reports and patches I want, and how they must look. It is next to `project.yaml`, or in the project's repository at the path that `patch_style:` gives.

To change the enrollment, edit `projects/<name>/`. To pause the project, set `disabled: true`. To leave, remove `projects/<name>/`.

Context (optional): what a reviewer must know about the project or its build, for example which fuzz targets matter most to you.
