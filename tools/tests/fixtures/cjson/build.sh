#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# projects/cjson/build.sh, and the allocation-failure variants of its fuzz target, for tools/tests/test_builder.py:
# cjson_read_fuzzer_allocation_failure as a project would publish it, and cjson_read_fuzzer_allocation_counting as a
# sweep or test build would make it, with counting mode on.
# Ported from OSS-Fuzz's projects/cjson/build.sh, which runs cJSON's fuzzing/ossfuzz.sh.

# Build the copy of the checkout that the Dockerfile made, at the path where the oss-fuzz-theorems 2026.10 release built
# its cjson binaries, so that, at the release's cJSON commit, all four builds reproduce the SHA-256s it published. An
# AddressSanitizer build records the path of each source file it instruments, so the path is part of the bytes: built
# in place at $SRC/cjson, the plain and UBSan binaries are the same, and the two ASan binaries differ in that path
# (/src/cjson/cJSON.c).
build=$SRC/cjson-cjson_read_fuzzer
mkdir -p "$build/cmk"

cd "$build/cmk"
# ENABLE_CUSTOM_COMPILER_FLAGS=OFF: cJSON's own flags add -std=c89 -pedantic -Werror, and musl's isnan and isinf
# expand to unsigned long long constants, which C89 -pedantic rejects. The flags it leaves out are warnings only.
# ENABLE_CJSON_TEST=OFF: as fuzzing/ossfuzz.sh.
cmake "$build/src" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_CJSON_TEST=OFF -DENABLE_CUSTOM_COMPILER_FLAGS=OFF
make -j"$(nproc)"

# The harness is C: compiled with $CC, not with $CXX as OSS-Fuzz's build does.
$CC $CFLAGS -c "$build/src/fuzzing/cjson_read_fuzzer.c" -o "$WORK/cjson_read_fuzzer.o"
$CC $CFLAGS "$WORK/cjson_read_fuzzer.o" -o "$OUT/cjson_read_fuzzer" $LIB_FUZZING_ENGINE "$build/cmk/libcjson.a"

# The same fuzz target, with cJSON's allocations (and the harness's) failing as the input's allocation mask says
# (docs/build-contract.md). cJSON returns NULL when an allocation fails, and the harness then returns 0.
$CC $CFLAGS "$WORK/cjson_read_fuzzer.o" -o "$OUT/cjson_read_fuzzer_allocation_failure" $LIB_ALLOCATION_FAILURE_ENGINE \
  "$build/cmk/libcjson.a"
$CC $CFLAGS "$WORK/cjson_read_fuzzer.o" -o "$OUT/cjson_read_fuzzer_allocation_counting" $LIB_ALLOCATION_COUNTING_ENGINE \
  "$build/cmk/libcjson.a"
