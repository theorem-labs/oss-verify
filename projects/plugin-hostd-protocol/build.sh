#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds plugin-hostd-protocol's four fuzz targets (fuzz/fuzz_*.c in its repository) into $OUT.
# The library's own Makefile builds them with a native clang and libFuzzer; this script makes the same harnesses into
# static riscv64 programs, each linked against a static library of this build.
flags=(-std=gnu99 -D_GNU_SOURCE -Iinclude)

# The library: the command parser, the dispatcher, the scenario reader and the string helpers, in a fixed order, and
# fuzz/socket_fuzz.c in place of src/socket.c: its socket_send() copies each reply into a buffer the harness reads, so a
# run opens no socket.
mkdir -p "$WORK/obj"
objs=()
for src in src/protocol.c src/utils.c src/host-dispatch.c src/host-scenario.c fuzz/socket_fuzz.c; do
  obj="$WORK/obj/$(basename "$src" .c).o"
  $CC $CFLAGS "${flags[@]}" -c "$src" -o "$obj"
  objs+=("$obj")
done
$AR rcs "$WORK/libplugin-hostd-protocol-fuzz.a" "${objs[@]}"

# The fuzz targets.
for h in protocol dispatch scenario session; do
  $CC $CFLAGS "${flags[@]}" -Ifuzz -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE "$WORK/libplugin-hostd-protocol-fuzz.a" -lm
done
