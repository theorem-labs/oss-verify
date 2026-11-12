#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds cjson_read_fuzzer, cJSON's own fuzz target (fuzzing/cjson_read_fuzzer.c), into $OUT.
# Ported from OSS-Fuzz's projects/cjson/build.sh, which runs cJSON's fuzzing/ossfuzz.sh.

# Build a copy of the checkout, at the path the oss-fuzz-theorems 2026.10 release built its cjson binaries at, so that
# all four builds reproduce the SHA-256s it published. An AddressSanitizer build records the path of each source file it
# instruments, so the path is part of the bytes: built in place at $SRC/cjson, the plain and UBSan binaries are the
# same, and the two ASan binaries differ in that path (/src/cjson/cJSON.c).
build=$SRC/cjson-cjson_read_fuzzer
mkdir -p "$build/src" "$build/cmk"
cp -a "$SRC/cjson/." "$build/src/"

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
