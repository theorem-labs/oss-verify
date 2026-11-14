# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# A Go project, in the form of a ported Go build: the module is the build context's example/ here, sources lays out
# the module proxy of its go.lock (which pins no module), and build.sh is in the form of an OSS-Fuzz Go build.sh.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY sources go.lock $WORK/project/
RUN lay-out-sources $WORK/project/sources $WORK
COPY example $SRC/example
WORKDIR $SRC/example
COPY build.sh $SRC/
