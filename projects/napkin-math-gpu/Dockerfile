# Copyright 2026 Tushar Dahiya
# SPDX-License-Identifier: Apache-2.0
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit "$SRC/upstream/napkin-math-gpu"
COPY . $SRC/project/
RUN lay-out-sources "$SRC/project/sources" "$WORK" \
 && cp "$SRC/project/build.sh" "$SRC/build.sh"
WORKDIR $SRC
