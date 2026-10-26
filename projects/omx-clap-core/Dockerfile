# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# omx-clap-core on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are omx-clap-core's own, in fuzz/ of the checkout, so nothing but build.sh is copied in.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/omx-clap-core
COPY build.sh $SRC/
WORKDIR $SRC/omx-clap-core
