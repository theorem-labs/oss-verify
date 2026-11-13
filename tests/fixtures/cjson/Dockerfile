# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# cJSON on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/cjson
COPY build.sh $SRC/
WORKDIR $SRC/cjson
