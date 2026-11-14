# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# A Rust project, in the form of a ported Rust build (docs/build-contract.md#rust-fuzz-targets): the crate is the
# build context's crate/ here, and sources lays out its tree, its Cargo.lock and its crates.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY crate $SRC/upstream/example
COPY sources Cargo.lock build.sh $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK && cp $SRC/project/build.sh $SRC/build.sh
WORKDIR $SRC
