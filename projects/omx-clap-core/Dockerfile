# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: copied in fuzz_preset.c and alloc.c for fuzz_preset, which omx-clap-core's own
# fuzz/ now carries, and the test fuzz_preset_oom.c.
#
# omx-clap-core on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are omx-clap-core's own, in fuzz/ of the checkout, all three of them. fuzz_preset_oom.c, a test of
# fuzz/fuzz_preset.c and fuzz/alloc.c when memory runs out at each allocation, is copied in beside build.sh.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/omx-clap-core
COPY build.sh $SRC/
COPY fuzz_preset_oom.c $SRC/fuzz_preset/
WORKDIR $SRC/omx-clap-core
