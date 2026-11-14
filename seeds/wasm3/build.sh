#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds fuzzer, wasm3's own fuzz target (platforms/app_fuzz/fuzzer.c), into $OUT.
# Ported from OSS-Fuzz's projects/wasm3/build.sh as the oss-fuzz-theorems 2026.10 release built it: this reproduces that
# release's four wasm3 binaries byte for byte.

# Build a copy of the checkout, at the path the release built wasm3 at. An AddressSanitizer build records the path of
# each source file it instruments, so the path is part of the bytes.
build=$SRC/wasm3-fuzzer
mkdir -p "$build/src" "$build/cmk" "$build/lib"
cp -a "$SRC/wasm3/." "$build/src/"

cd "$build/cmk"
# BUILD_NATIVE=OFF: no machine-specific flags. BUILD_WASI=none: as OSS-Fuzz's build.
cmake "$build/src" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_NATIVE=OFF -DBUILD_WASI=none
make -j"$(nproc)"

# Link as the release does: the archives the build made (here libm3.a), merged into one in path order, with the
# harness as the last member. The harness's references are then resolved with the whole library in view, which
# decides the order of the program's code. Linked as OSS-Fuzz does (the harness object, then libm3.a), every binary
# has the same size and a different SHA-256.
{ echo "create $build/lib/libwasm3-all.a"
  find "$build" -name '*.a' -type f -not -path "$build/lib/*" | LC_ALL=C sort | sed 's/^/addlib /'
  printf 'save\nend\n'; } | "$AR" -M
$CC $CFLAGS -I"$build/src/source" -c "$build/src/platforms/app_fuzz/fuzzer.c" -o "$build/harness.o"
"$AR" r "$build/lib/libwasm3-all.a" "$build/harness.o"
$CC $CFLAGS -o "$OUT/fuzzer" $LIB_FUZZING_ENGINE "$build/lib/libwasm3-all.a"
