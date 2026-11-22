# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# A test project for the settings of one fuzz target, in the form of a ported build. The build context holds each of
# its source files, and lay-out-sources lays them out under $WORK. The build fetches nothing. The build tools give
# REPO and COMMIT. This project does not use them.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY . $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK && cp $SRC/project/build.sh $SRC/build.sh
WORKDIR $SRC
