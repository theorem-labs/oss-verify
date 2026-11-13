# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the step that runs curl-fuzz_proto_gen.sh, which writes the message code of the
# structured fuzz targets one time for every build.
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# curl on the OSS Verify builder, laid out as the release built it (lay-out-sources reads the sources file).
# tools/check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/upstream/curl
COPY . $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK && cp $SRC/project/build.sh $SRC/build.sh
# The message code of the structured fuzz targets, the same in every build (curl-fuzz_proto_gen.sh says what it writes)
RUN sh $WORK/gen/curl-fuzz_proto_gen.sh
WORKDIR $SRC
