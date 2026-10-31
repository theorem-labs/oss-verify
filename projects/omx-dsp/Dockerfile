# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# omx-dsp on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER. The fuzz targets are omx-dsp's
# own, in fuzz/ of the checkout. The one dependency is omx-contract's headers, which the sources file pins.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/omx-dsp
COPY sources build.sh $SRC/
RUN lay-out-sources $SRC/sources
WORKDIR $SRC/omx-dsp
