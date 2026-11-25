# Adapted from OSS Scanner's templates/Dockerfile (https://github.com/anthropics/oss-scanner), Copyright 2026
# Anthropic PBC, Apache-2.0. Modified 2026 by Theorem Labs, PBC: built FROM the OSS Verify builder, OSS-Fuzz style.
# Modified 2026 by Theorem Labs, PBC: the Dockerfile of .theorem/, whose build context is the repository root.
#
# Copy this template to .theorem/Dockerfile in your repository.
# This file sets up the build: it copies your source, fetches each dependency, and copies build.sh into $SRC. This file
# builds with network access. build.sh runs once per build with no network, so this file must fetch everything that
# build.sh needs. docs/build-contract.md describes the builder.
#
# theorem app build plan prints the Docker commands that build this file. The build context is the root of your
# repository at the commit that theorem app build builds. Thus this file names each file by its path from the root,
# for example .theorem/build.sh.

# The builder image. theorem app build plan builds it from infra/base-builder and passes it here.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}

# theorem app build plan passes both: REPO is your repository, and COMMIT is the full commit id that it builds. Never
# write a commit id into this file.
ARG REPO
ARG COMMIT

# Copy the source from the build context, which is your repository at COMMIT. Do not use fetch-commit.
COPY . $SRC/example

# Fetch each dependency here, at a fixed version. build.sh builds it with the flags of each build. For example:
# RUN git clone --depth 1 --branch v1.3.1 https://github.com/madler/zlib $SRC/zlib

COPY .theorem/build.sh $SRC/
WORKDIR $SRC/example
