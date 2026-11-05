#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds libsurface's five fuzz targets (fuzz/fuzz_*.c in the libsurface repository) into $OUT.
# libsurface's own Makefile builds them with a native clang and libFuzzer; this script makes the
# same harnesses into static riscv64 programs, each linked against a static library of this build.

# The library: the core (surface, motor policy, bank window, meter and ring helpers) and the
# Control|24 key table, which is data and needs no libdiginet. The DigiNet and Mackie modules need
# their transport libraries and have no harness (fuzz/README.md).
mkdir -p "$WORK/obj"
objs=()
for src in src/surface.c src/motor.c src/bank.c src/meter.c src/diginet/c24_keys.c; do
  obj="$WORK/obj/$(basename "$src" .c).o"
  $CC $CFLAGS -std=c11 -D_DEFAULT_SOURCE -Iinclude -c "$src" -o "$obj"
  objs+=("$obj")
done
$AR rcs "$WORK/libsurface-fuzz.a" "${objs[@]}"

# The fuzz targets.
for h in pure board bank motor keys; do
  $CC $CFLAGS -std=c11 -D_DEFAULT_SOURCE -Iinclude -Ifuzz -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE "$WORK/libsurface-fuzz.a"
done
