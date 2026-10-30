# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# mod-host on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER. The fuzz targets are
# mod-host's own, in fuzz/ of the checkout, and they link only the protocol sources: no JACK, no LV2 library.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/mod-host
COPY build.sh $SRC/
WORKDIR $SRC/mod-host
