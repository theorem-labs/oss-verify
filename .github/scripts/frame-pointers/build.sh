#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds the C probe (probe.c) as a fuzz target, as tests/fixtures/example/build.sh links its own, for
# .github/scripts/frame-pointers/probe: compile runs it from $SRC, where the project image puts both files.
$CC $CFLAGS -c probe.c -o "$WORK/probe.o"
$CC $CFLAGS "$WORK/probe.o" -o "$OUT/fp_probe" $LIB_FUZZING_ENGINE
