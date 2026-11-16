# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# wasm3 on the OSS Verify builder. oss-verify check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/wasm3
COPY build.sh $SRC/
WORKDIR $SRC/wasm3
