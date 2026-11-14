# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# cJSON on the OSS Verify builder. oss-verify check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/cjson
# A copy of the checkout, without its .git, at the path where the oss-fuzz-theorems 2026.10 release built its cjson
# binaries: build.sh builds this copy, and says why. The copy is in the image, so that each file that a build's compile
# commands name is also in a new container of this image. It is the working directory, where build.sh runs and where
# tools/check --checks applies a breakage patch, so a breakage changes the files that build.sh builds. Without .git,
# the image holds one git checkout, the one tools/check's manifest records.
RUN mkdir -p $SRC/cjson-cjson_read_fuzzer/src && cp -a $SRC/cjson/. $SRC/cjson-cjson_read_fuzzer/src/ \
 && rm -rf $SRC/cjson-cjson_read_fuzzer/src/.git
COPY build.sh $SRC/
WORKDIR $SRC/cjson-cjson_read_fuzzer/src
