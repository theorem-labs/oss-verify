<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: the security model of building and checking projects, who maintains this repository, and how to report. -->
# Security policy

This page tells what security our tools give, and how to report a vulnerability in this repository. It is for people who run our tools and for security researchers.

## Our security model

Our tools treat a project's build files and source as trusted data. They build what the project tells them to build.

* `tools/check` builds a project's `Dockerfile` with network access, as `docker build` does. The `Dockerfile` can run any command.
* `build.sh` runs in a container with no network (`docker run --network=none`).
* A binary that you run yourself runs on your machine, with your permissions.

> **WARNING:** Docker is not a security boundary. A `Dockerfile` or `build.sh` can attack the machine that builds it. Use our tools only on projects that you trust. Otherwise, use a machine that has nothing of value on it.

The GitHub workflows of this repository build pull requests on GitHub's runners, with no secrets and no write permissions.

## Report a vulnerability in this repository

Theorem maintains this repository. To report a vulnerability in this repository, in its tools (`tools/`), its builder (`infra/base-builder/`) or its workflows (`.github/`):

1. Open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.
2. Do not open a public issue or pull request for the vulnerability.

## Findings about an enrolled project

A finding is a failure that we find in an enrolled project while we work on a proof. We send it privately to the project's `primary_contact`. We set no disclosure deadline, and we do not publish findings ([docs/what-gets-proven.md](docs/what-gets-proven.md#findings)).

## Who receives reports

* Only a core maintainer can enroll a project. We review each enrollment before we merge it.
* We send findings only to `primary_contact` and `auto_ccs`. If you set `pgp`, we encrypt each report to your key and send it to `primary_contact` only.
* We send the findings of a seeded project to no one automatically.
* A statement is about the binaries that we build from your repository at a pinned commit, with the fuzz targets in `fuzz_targets`.

## How we keep the data secure

* We build your project from its public repository. The compile step has no network access.
* If you set `pgp`, we encrypt each report to your key.
* We do not publish findings. What we publish does not show a finding that is not public.
