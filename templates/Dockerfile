# Adapted from OSS Scanner's templates/Dockerfile (https://github.com/anthropics/oss-scanner), Copyright 2026
# Anthropic PBC, Apache-2.0. Modified 2026 by Theorem Labs, PBC: built FROM the OSS Verify builder, OSS-Fuzz style.
#
# Copy this template to projects/<name>/Dockerfile, next to your project.yaml, or into your repository at the path
# dockerfile: names (we suggest .oss-verify/Dockerfile).
# This file sets up the build: it fetches your source and any dependencies, and copies build.sh into $SRC. Network
# access is available while this file is built and removed after it: build.sh runs once per build with no network,
# so everything it needs must be fetched here. docs/build-contract.md describes the builder.

# The builder image. oss-verify check builds it from infra/base-builder and passes it here.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}

# oss-verify check passes both: REPO is project.yaml's repo without its #ref, and COMMIT is the full commit id the ref
# resolved to. Never write a commit id into this file.
ARG REPO
ARG COMMIT

# --- if this file sits next to project.yaml, the build context is projects/<name>/: fetch the source ---
RUN fetch-commit $SRC/example
# --- if it lives in your repository instead, the build context is your repository at COMMIT: use this line ---
# COPY . $SRC/example

# Fetch dependencies here, at fixed versions; build.sh builds them with each build's flags. oss-verify check records the
# commit of every git checkout under $SRC in its manifest. For example:
# RUN git clone --depth 1 --branch v1.3.1 https://github.com/madler/zlib $SRC/zlib

COPY build.sh $SRC/
WORKDIR $SRC/example
