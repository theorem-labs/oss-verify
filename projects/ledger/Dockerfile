# Copyright 2026 EmptyEmptySet
# SPDX-License-Identifier: Apache-2.0
#
# The ledger on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The library is the C version of the ledger at the commit that project.yaml names; the
# API driver lives in this directory and is copied into the checkout.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/SoftwareEngineering
COPY build.sh $SRC/
COPY fuzz_main.c ledger_api.c $SRC/SoftwareEngineering/
WORKDIR $SRC/SoftwareEngineering
