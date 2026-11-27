#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The build of a port of one whole program, for tests/test_binary_checks_docker.py. compile runs it with bash -eux from
# the WORKDIR, /opt/hello. It runs the program's own build, and writes the program and its link map to $OUT. It also
# writes the environment that the build sees to $OUT/env.txt, which the test compares with that of the toolchain image.
make
cp hello hello.map "$OUT/"
env | sort > "$OUT/env.txt"
