# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# A port of one whole program, for tests/test_binary_checks_docker.py. The program's source is the build context's
# src/, here this directory's. It is checked out under $SRC and copied to the fixed path /opt/hello, which the
# program's own Makefile builds in and which is the WORKDIR (docs/build-contract.md). OV_TEST_PORT_SETTING is a
# setting of the port's own: the program's build.sh must not see it.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
ENV OV_TEST_PORT_SETTING=port
COPY src/ $SRC/hello/
COPY build.sh $SRC/
RUN cp -R "$SRC/hello" /opt/hello
WORKDIR /opt/hello
