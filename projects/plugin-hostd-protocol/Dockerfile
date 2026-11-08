# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# plugin-hostd-protocol on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are the library's own, in fuzz/ of the checkout. Its dependencies are the headers of
# omx-dsp (omx_curve.h, which the curve verbs draw with) and of omx-contract, at the fixed commits that sources lists.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/plugin-hostd-protocol
COPY sources build.sh $SRC/
RUN lay-out-sources $SRC/sources
WORKDIR $SRC/plugin-hostd-protocol
