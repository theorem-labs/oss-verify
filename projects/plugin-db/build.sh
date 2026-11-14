#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds plugin-db's three fuzz targets (fuzz/fuzz_*.c in the plugin-db repository) into $OUT.
# plugin-db is a header-only library (include/plugin-db/pin.h): there is no library to archive, so each
# target is compiled against the header and linked with the sysroot's static libcrypto, which the
# digest calls for SHA-256. libcrypto is linked as the sysroot holds it, with no instrumentation.
for h in pin layout digest; do
  $CC $CFLAGS -std=gnu99 -D_GNU_SOURCE -Iinclude -Ifuzz -c "fuzz/fuzz_$h.c" -o "$WORK/fuzz_$h.o"
  $CC $CFLAGS "$WORK/fuzz_$h.o" -o "$OUT/fuzz_$h" $LIB_FUZZING_ENGINE -lcrypto
done
