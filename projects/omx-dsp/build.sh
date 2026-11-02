#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds omx-dsp's six fuzz targets (fuzz/fuzz_*.c in the omx-dsp repository) into $OUT. omx-dsp's own Makefile builds
# them with a native clang and libFuzzer; this script makes the same harnesses into static riscv64 programs. As the
# Makefile does, everything is compiled with -DOMX_CONTRACTS, so the library's PRE and POST laws record into the ledger
# the harnesses read, and -ffp-contract=off, which the library asks of every consumer. Most of the library is inline in
# the headers; src/*.c is its compiled part, in a fixed order.
flags=(-std=gnu11 -DOMX_CONTRACTS -ffp-contract=off -Iinclude -isystem "$SRC/omx-contract/include")

mkdir -p "$WORK/obj"
objs=()
for src in src/omx_align_fit.c src/omx_fbs_detect.c src/omx_oversampler.c src/omx_room.c src/omx_sweep.c; do
  obj="$WORK/obj/$(basename "$src" .c).o"
  $CC $CFLAGS "${flags[@]}" -c "$src" -o "$obj"
  objs+=("$obj")
done
$AR rcs "$WORK/libomxdsp.a" "${objs[@]}"

for h in fx laws eq src delay note_map; do
  $CC $CFLAGS "${flags[@]}" -Ifuzz -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE "$WORK/libomxdsp.a" -lm
done
