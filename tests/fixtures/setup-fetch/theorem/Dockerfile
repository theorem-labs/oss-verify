# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the Dockerfile of .theorem/, whose build context is the repository root.
#
# libreac on the OSS Verify builder. theorem app build plan passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are libreac's own, in fuzz/ of the repository, so the source and build.sh are all that is copied in.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY . $SRC/libreac
COPY .theorem/build.sh $SRC/
WORKDIR $SRC/libreac
