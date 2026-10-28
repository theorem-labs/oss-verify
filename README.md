<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: rewritten for OSS Verify, which proves theorems about fuzz targets instead of scanning. -->
# OSS Verify

OSS Verify is a Theorem program that verifies open-source software. We prove theorems about the compiled fuzz targets of a project. For example, we prove that no input makes a fuzz target crash, hang or fail a sanitizer check. This page tells a maintainer how to enroll a project. A coding agent starts at [AGENTS.md](AGENTS.md).

## Who can enroll

We accept an established open-source project ([theorem.dev/oss-verify](https://theorem.dev/oss-verify/#what-projects-are-eligible) tells how we choose projects). A project must also obey these conditions:

1. The person who enrolls the project is a core maintainer of it.
2. The project has a licence that the Open Source Initiative approves.
3. The project has a public git repository, which we get anonymously over `https`. One project directory names one repository.
4. The project has at least one fuzz target: its own, its OSS-Fuzz fuzz targets, or new ones.
5. Our builder can build the project. The [language table](docs/project-yaml.md#language) tells which languages it builds today.
6. The enrollment names, in `primary_contact`, the one address that gets findings.

A project of any size can enroll. Because of our capacity, we are most likely to respond quickly to a project in C whose plain binaries (`<target>.plain`) are statically linked and have less than 1 MB of code: the larger of their `.text` section, the size that `tools/check` shows, and their executable segments (which can hold read-only data too). If your organisation wants to help us increase that capacity, so that we can take on more projects now, write to [oss-verify@theorem.dev](mailto:oss-verify@theorem.dev). We are interested in corporate partners and sponsorship.

We seeded some projects already, and a maintainer can adopt one ([docs/project-yaml.md](docs/project-yaml.md#seeded-projects)).

## Enroll with a coding agent

Copy and paste this prompt into your coding agent (Claude Code, Codex, Cursor, etc.). Start the agent in a checkout of your project.

```
Enroll this project in OSS Verify by following the instructions here:
https://raw.githubusercontent.com/theorem-labs/oss-verify/refs/heads/main/AGENTS.md
```

The agent asks you what "correct" means for your code, and which findings and patches you want. Then it makes `projects/<name>/` and runs the checks, on a machine that has what [Enroll a project](#enroll-a-project) lists. You push its branch to your fork of this repository, and you open the pull request.

> **WARNING:** The agent runs `tools/check`. `tools/check` builds the project's `Dockerfile` with network access. Use the agent only on a project that you trust ([SECURITY.md](SECURITY.md)).

## Enroll a project

> **WARNING:** `tools/check` builds the project's `Dockerfile` with network access. Use it only on a project that you trust ([SECURITY.md](SECURITY.md)).

You need a Linux x86-64 machine with Docker and its buildx plugin, git, and Python 3 with PyYAML (on Ubuntu, `apt install docker.io docker-buildx python3-yaml`), and about 10 GB of free disk. The first run of `tools/check` downloads a toolchain image of about 1.1 GB, which unpacks to about 5 GB.

1. Fork this repository.
2. Make `projects/<name>/` from [templates/](templates/): `project.yaml` ([docs/project-yaml.md](docs/project-yaml.md)), a `Dockerfile` and a `build.sh` ([docs/build-contract.md](docs/build-contract.md)).
3. Optional: write a `patch_style.md`. Tell us which findings, reports and patches you want, and how they must look.
4. Run `tools/validate.py projects/<name>`. Correct each problem that it shows.
5. Run `tools/check --no-shell --twice <name>`. Make sure that it builds each fuzz target, and that the second build has the same bytes. Without `--no-shell`, `tools/check` opens a shell in the build image when it finishes.
6. Open a pull request. Complete its checklist.

## When the checks pass

When every required check of your pull request passes, and each plain binary has at most 1 MB of code, we start to write the theorem statements for the commit that the pull request is at. The code of a binary is the larger of its `.text` section and its executable segments, which can hold read-only data too. We start a few projects a day, and one commit of each project a day. If your pull request must wait for a later day, or for our next release because statements of an earlier commit of the project are not released yet, it gets the label `statements-queued`. If a plain binary has more than 1 MB of code, or a size that we cannot read, the pull request gets the label `size-review`, and we decide what to do. Python and Go projects are paused for now (our tools do not write theorem statements for Go yet): such a pull request gets the label `language-paused`. A project name with a dot, which the names in our statements repository cannot have, or a name that we already use there for another project, gets the label `name-review`. A new commit on the pull request starts this again, and so does an edit of its title or description; a commit whose statements we already wrote is not written again. A pull request that changes a project that is already enrolled starts it too.

For these statements, we build the fuzz targets two times, and pin the SHA-256 of each binary in a lock.

## After we merge

We merge an enrollment when we intend to prove the project.

1. We prove the theorem statements ([docs/what-gets-proven.md](docs/what-gets-proven.md)). Our tools do not write theorem statements for Go projects yet ([docs/project-yaml.md](docs/project-yaml.md#language)).
2. We send each finding privately to `primary_contact`, with a patch when we have one. There is no disclosure deadline, and we do not publish findings.
3. We publish the proofs when the `publish` field tells us to.

Findings and patches are generated by AI models, and they can be wrong or incomplete. We do not promise that a person reviews them before we send them. Review every patch before you use it. We follow your project's policy on AI-generated contributions.

## Pause or leave

To pause the project, set `disabled: true` in `project.yaml`. To leave, remove `projects/<name>/`. Make each change in a pull request.

## Learn more

The [OSS Verify FAQ](https://theorem.dev/oss-verify/#faq) answers questions. To send feedback about a finding or a patch, reply to its report, or write to [oss-verify@theorem.dev](mailto:oss-verify@theorem.dev). [SECURITY.md](SECURITY.md) tells how to report a vulnerability in this repository. Use of OSS Verify is subject to the [OSS Verify terms](https://theorem.dev/oss-verify/terms/). We accept only enrollment pull requests ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Licence

This repository is under the Apache License 2.0 ([LICENSE](LICENSE)). The driver that `$LIB_FUZZING_ENGINE` links into a fuzz target, [infra/base-builder/driver/](infra/base-builder/driver/), is under MIT OR Apache-2.0 ([LICENSES/MIT.txt](LICENSES/MIT.txt)), so that a program under version 2 of the GNU GPL can be linked with it. [NOTICE](NOTICE) says which files and lines have another licence, and why.
