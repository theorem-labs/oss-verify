# THORNode on the OSS Verify builder: its Go fuzz targets, built with OSS-Fuzz's Go helpers in the Go toolchain image
# (go/compile-go). tools/check passes REPO, COMMIT and BASE_BUILDER.
#
# Copyright (c) THORChain contributors. SPDX-License-Identifier: Apache-2.0
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
# The modules that go.lock pins, as the module proxy of the build (lay-out-sources). They are only the modules that the
# fuzz targets import: THORNode also needs gitlab.com/thorchain/tss/tss-lib-private, which is not public, and no fuzz
# target here imports a package that uses it.
COPY sources go.lock $WORK/project/
RUN lay-out-sources $WORK/project/sources $WORK
RUN fetch-commit $SRC/thornode
COPY build.sh fuzz_common.go fuzz_chains.go fuzz_memo.go $SRC/
WORKDIR $SRC/thornode
