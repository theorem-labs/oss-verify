#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds mod-host's four fuzz targets (fuzz/fuzz_*.c) into $OUT. mod-host's Makefile builds them with a native clang
# and libFuzzer from the same sources (FUZZ_SRCS), with fuzz/socket_fuzz.c in place of src/socket.c, so a reply is
# copied into a buffer and no socket is opened; this script compiles those sources once, with this build's flags,
# into a static archive in a fixed order, and links each fuzz target against it.
mkdir -p "$WORK/obj"
objs=()
for src in src/protocol.c src/utils.c fuzz/socket_fuzz.c src/host-dispatch.c src/host-scenario.c src/state-paths.c; do
  obj="$WORK/obj/$(basename "$src" .c).o"
  $CC $CFLAGS -std=gnu99 -D_GNU_SOURCE -Isrc -c "$src" -o "$obj"
  objs+=("$obj")
done
$AR rcs "$WORK/libmodhost-protocol.a" "${objs[@]}"

for h in protocol dispatch scenario statepaths; do
  $CC $CFLAGS -std=gnu99 -D_GNU_SOURCE -Isrc -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE "$WORK/libmodhost-protocol.a" -lpthread -lm
done
