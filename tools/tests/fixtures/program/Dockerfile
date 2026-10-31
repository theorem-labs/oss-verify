# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The Dockerfile of a project whose source is the build context, here this directory (as fixtures/example's).
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY program.c $SRC/program/
COPY build.sh $SRC/
WORKDIR $SRC/program
