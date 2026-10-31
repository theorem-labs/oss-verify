#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# A whole program, for tools/tests/test_builder.py: its own main, linked with $OV_PROGRAM_LDFLAGS, with no driver and
# no seals (docs/build-contract.md, "Whole programs").
$CC $CFLAGS -c program.c -o "$WORK/program.o"
$CC $CFLAGS "$WORK/program.o" -o "$OUT/ov_program" $OV_PROGRAM_LDFLAGS
