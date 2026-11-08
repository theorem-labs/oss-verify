# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# plugin-hostd-protocol on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are the library's own, in fuzz/ of the checkout. Its one dependency is omx-dsp's header-only
# omx_curve.h, which the curve verbs draw with: omx-dsp's main at the commit below, a fixed version. Nothing but
# build.sh is copied in.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/plugin-hostd-protocol
RUN REPO=https://github.com/FreeMixer/omx-dsp COMMIT=f19a1a97fcdd79f0f1cb71684fdbf6438296c4a4 fetch-commit $SRC/omx-dsp
COPY build.sh $SRC/
WORKDIR $SRC/plugin-hostd-protocol
