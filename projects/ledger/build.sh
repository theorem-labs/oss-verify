#!/bin/bash -eu
# Copyright 2026 EmptyEmptySet
# SPDX-License-Identifier: Apache-2.0
#
# Builds the ledger core as a static library and links the two fuzz targets into $OUT.
# The core files are C99; the builder's $CC is the static riscv64 cross compiler.

mkdir -p "$WORK/obj"

$CC $CFLAGS -std=c99 -Iinclude -c src/manager.c -o "$WORK/obj/manager.o"
$CC $CFLAGS -std=c99 -Iinclude -c src/platform.c -o "$WORK/obj/platform.o"
$AR rcs "$WORK/liblegder.a" "$WORK/obj/manager.o" "$WORK/obj/platform.o"

$CC $CFLAGS -std=c99 -Iinclude -c fuzz_main.c -o "$WORK/obj/fuzz_main.o"
$CC $CFLAGS "$WORK/obj/fuzz_main.o" -o "$OUT/fuzz_main" $LIB_FUZZING_ENGINE "$WORK/liblegder.a"

$CC $CFLAGS -std=c99 -Iinclude -c ledger_api.c -o "$WORK/obj/ledger_api.o"
$CC $CFLAGS "$WORK/obj/ledger_api.o" -o "$OUT/ledger_api" $LIB_FUZZING_ENGINE "$WORK/liblegder.a"
