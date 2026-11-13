# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# plugin-hostd on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are plugin-hostd's own, in fuzz/ of the checkout. Its two dependencies, plugin-hostd-protocol and
# plugin-db, are checkouts the sources file pins, laid out in $SRC; nothing is installed and no OpenSSL is needed.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/plugin-hostd
COPY sources build.sh $SRC/
RUN lay-out-sources $SRC/sources
WORKDIR $SRC/plugin-hostd
