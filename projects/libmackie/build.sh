#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds libmackie's five fuzz targets (fuzz/fuzz_*.c in the libmackie repository) into $OUT.
# libmackie's own Makefile builds them with a native clang and libFuzzer; this script makes the
# same harnesses into static riscv64 programs, each linked against a static library of this build.

# The library: the five sources of src/, in a fixed order. It opens no port, reads no clock and
# allocates nothing, so all of it is built.
mkdir -p "$WORK/obj"
objs=()
for src in src/mackie_map.c src/mackie_text.c src/mackie_codec.c src/mackie_display.c \
           src/mackie_sysex.c; do
  obj="$WORK/obj/$(basename "$src" .c).o"
  $CC $CFLAGS -std=c11 -Iinclude -c "$src" -o "$obj"
  objs+=("$obj")
done
$AR rcs "$WORK/libmackie-fuzz.a" "${objs[@]}"

# The fuzz targets.
for h in decode sysex text map encode; do
  $CC $CFLAGS -std=c11 -Iinclude -Ifuzz -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE "$WORK/libmackie-fuzz.a"
done
