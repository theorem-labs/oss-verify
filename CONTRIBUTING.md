<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: the files a project provides, no contributor licence agreement, adopting a seeded project, the licence lines of a contributed file. -->
# Contributing

This page tells which contributions this repository accepts. It is for maintainers who want to enroll a project.

We accept one type of pull request: a pull request that enrolls, changes, pauses or removes one project under `projects/<name>/`. We do not accept other changes, for example to `tools/`, `templates/`, `infra/` or `docs/`.

To enroll a project, follow the [README](README.md), or give a coding agent the prompt in [Enroll with a coding agent](README.md#enroll-with-a-coding-agent). To adopt a project that we seeded, follow [docs/project-yaml.md](docs/project-yaml.md#seeded-projects).

You make contributions under the Apache License 2.0 ([LICENSE](LICENSE), section 5). There is no separate contributor licence agreement. The driver in `infra/base-builder/driver/`, which takes no contributions, is under MIT OR Apache-2.0, so that a program under version 2 of the GNU GPL can be linked with it ([NOTICE](NOTICE)). A contribution to a file whose SPDX line says MIT OR Apache-2.0, or to a file or lines that NOTICE says are MIT OR Apache-2.0, is made under both licences.

Each file of code that you add begins with licence lines. A file that you copied from outside this repository keeps its own, a seeded project's file that you keep is copied byte for byte, and a file that you wrote says `SPDX-License-Identifier: Apache-2.0`, or `MIT OR Apache-2.0` for a project under version 2 of the GNU GPL only. Step 3.8 of [the add-project skill](.claude/skills/add-project/SKILL.md) gives every case. No check reads these lines.

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public issue for it.

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Review of an enrollment

Usually we do not accept a fork, a new project, or a project that nobody maintains. A person reviews each enrollment. The triage comment on the pull request helps the review: for example, it shows the licence, the activity and the criticality score of the project. If we decline a project, we tell you why in the pull request. To see the triage comment before you open the pull request, run `python3 .github/scripts/triage.py --repo theorem-labs/oss-verify --local projects/<name> --login <your GitHub account> --body <a file with your pull request description>`. Without `GITHUB_TOKEN` in the environment, the rows that need GitHub's GraphQL API say "could not be checked". That is a limit of the preview, not a problem with your project.

Until we have merged a first contribution from you, GitHub holds the `tests` check on each push until one of our maintainers approves its run. The other checks run at once. For a pull request from a fork, `tests` then passes without running anything: `enrollment` and `project-builds` check your project.

## Attribution

We do not require credit. If you fix a bug that OSS Verify found, we ask for one line about it. Put the line in the commit message, or in the place where you give credits. Give the id from our report in it, for example:

    Found by Theorem's OSS Verify, as finding THM-2026-7K3QF9XA.

The id helps us find which findings were real and which got fixed.

A finding id has these parts, in this order:

1. `THM-`;
2. the year in which we first report the finding, for example `2026`;
3. a hyphen, `-`;
4. 8 random characters from Crockford's base32 alphabet, in capitals. This alphabet has the digits 0 to 9, and the letters A to Z but not I, L, O and U.

As a regular expression, an id is `THM-[0-9]{4}-[0-9A-HJKMNP-TV-Z]{8}`. Each finding gets one id, when we first report it. We never use an id again. A duplicate of a finding keeps the id of that finding.
