# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# plugin-hostd-protocol on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are the library's own, in fuzz/ of the checkout, and it has no dependency, so nothing but build.sh
# is copied in.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/plugin-hostd-protocol
COPY build.sh $SRC/
WORKDIR $SRC/plugin-hostd-protocol
