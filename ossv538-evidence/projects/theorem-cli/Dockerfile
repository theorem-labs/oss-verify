# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The private `theorem` CLI on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER, and mounts
# the read-only token it minted for this build as the secret oss-verify-git-token.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN --mount=type=secret,id=oss-verify-git-token fetch-commit $SRC/theorem-cli
COPY build.sh $SRC/
WORKDIR $SRC/theorem-cli
