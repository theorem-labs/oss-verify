#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds omx-clap-core's three fuzz targets (fuzz/fuzz_*.c in the omx-clap-core repository) into $OUT.
# omx-clap-core's own Makefile builds them with a native clang and libFuzzer; this script makes the same
# harnesses into static riscv64 programs, each linked against a static library of the readers of this
# build.

# The library: the two readers the fuzz targets drive, src/preset_file.c (the preset file and its base64
# state body) and src/lv2_locate.c (the manifest.ttl reader), in a fixed order. As the Makefile does, each
# is compiled with fuzz/alloc.h forced on it, which sends the reader's malloc, calloc, realloc, strdup and
# free to fuzz/alloc.c: the count of the bytes a reader holds that the reject_clean and bounded_alloc
# properties read. The rest of the host (JACK, the CLAP and LV2 loaders) is not a target and is not built.
mkdir -p "$WORK/obj"
objs=()
for src in src/lv2_locate.c src/preset_file.c; do
  obj="$WORK/obj/$(basename "$src" .c).o"
  $CC $CFLAGS -std=gnu99 -D_GNU_SOURCE -Isrc -include fuzz/alloc.h -c "$src" -o "$obj"
  objs+=("$obj")
done
$AR rcs "$WORK/libomx-clap-readers.a" "${objs[@]}"

# The allocation count every fuzz target links, compiled once with the harness's flags.
$CC $CFLAGS -std=gnu99 -D_GNU_SOURCE -Isrc -Ifuzz -c fuzz/alloc.c -o "$WORK/alloc.o"

# The fuzz targets.
for h in preset state manifest; do
  $CC $CFLAGS -std=gnu99 -D_GNU_SOURCE -Isrc -Ifuzz -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" "$WORK/alloc.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE "$WORK/libomx-clap-readers.a" -lm
done
