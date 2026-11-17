# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The Rust probe's project image, as tests/fixtures/rust-example/Dockerfile makes that fixture's: the crate is the build
# context's crate/, and sources lays out its tree, its Cargo.lock and its crates. The Cargo.lock is
# tests/fixtures/rust-example/Cargo.lock, which .github/scripts/frame-pointers/probe copies into the build context.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
COPY crate $SRC/upstream/example
COPY sources Cargo.lock build.sh $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK && cp $SRC/project/build.sh $SRC/build.sh
WORKDIR $SRC
