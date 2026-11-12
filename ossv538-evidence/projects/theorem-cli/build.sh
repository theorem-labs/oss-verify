#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# core_argv_fuzzer, from the CLI's own sources. Its source list and flags are the ones the repository's Makefile and
# verify/container-build.sh give for that target: fuzz/core_argv_fuzzer.c, core/core.c and core/alloc.c, with the
# allocation names mapped onto the counting allocator of core/alloc.c.

cd "$SRC/theorem-cli"
ALLOC_DEFS="-Dmalloc=theorem_malloc -Dcalloc=theorem_calloc -Drealloc=theorem_realloc -Dstrdup=theorem_strdup -Dstrndup=theorem_strndup"
CLI_CFLAGS="-std=c11 -D_POSIX_C_SOURCE=200809L -Iinclude -Icore $ALLOC_DEFS"

objects=()
for source in fuzz/core_argv_fuzzer.c core/core.c core/alloc.c; do
  object="$WORK/$(echo "$source" | tr / _).o"
  $CC $CFLAGS $CLI_CFLAGS -c "$source" -o "$object"
  objects+=("$object")
done
$CC $CFLAGS "${objects[@]}" -o "$OUT/core_argv_fuzzer" $LIB_FUZZING_ENGINE
