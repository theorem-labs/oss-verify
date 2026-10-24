# Copyright 2026 Vishal Sachdev
# SPDX-License-Identifier: Apache-2.0
#
# canvas-mcp on the OSS Verify builder, in the form of a ported Python build (tools/seeds/mdurl/): lay-out-sources
# reads the sources file. tools/check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/upstream/canvas-mcp
COPY . $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK && cp $SRC/project/build.sh $SRC/build.sh
WORKDIR $SRC
