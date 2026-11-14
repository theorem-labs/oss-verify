# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# A Python project, in the form of a ported Python build: the package is the build context's pkg/ here, and sources
# lays out its tree, its harness, its seed corpus and the file that pip installs from.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY pkg $SRC/upstream/example
COPY sources fuzz_example.py fuzz_example_seed_corpus.zip build.sh $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK && cp $SRC/project/build.sh $SRC/build.sh
WORKDIR $SRC
