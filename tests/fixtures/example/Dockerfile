# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# templates/Dockerfile, as a project whose Dockerfile lives in its own repository writes it: the source is the
# build context, here this directory.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY . $SRC/example
COPY build.sh $SRC/
WORKDIR $SRC/example
