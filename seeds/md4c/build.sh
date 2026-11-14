#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds fuzz-mdhtml, md4c's own fuzz target (test/fuzzers/fuzz-mdhtml.c), into $OUT.
# Ported from OSS-Fuzz's projects/md4c/build.sh as the oss-fuzz-theorems 2026.10 release built it: this reproduces that
# release's four md4c binaries byte for byte.

# Build a copy of the checkout, at the path the release built md4c at. An AddressSanitizer build records the path of
# each source file it instruments, so the path is part of the bytes.
build=$SRC/md4c-fuzz-mdhtml
mkdir -p "$build/src" "$build/cmk" "$build/lib"
cp -a "$SRC/md4c/." "$build/src/"

cd "$build/cmk"
cmake "$build/src" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
make -j"$(nproc)"

# Link as the release does: the archives the build made, merged into one in path order, with the harness as the last
# member. The harness's references are then resolved with the whole library in view, which decides the order of the
# program's code. Linked as OSS-Fuzz does (the harness object, then the two archives), every binary has the same size
# and a different SHA-256.
{ echo "create $build/lib/libmd4c-all.a"
  find "$build" -name '*.a' -type f -not -path "$build/lib/*" | LC_ALL=C sort | sed 's/^/addlib /'
  printf 'save\nend\n'; } | "$AR" -M
$CC $CFLAGS -I"$build/src/src" -c "$build/src/test/fuzzers/fuzz-mdhtml.c" -o "$build/harness.o"
"$AR" r "$build/lib/libmd4c-all.a" "$build/harness.o"
$CC $CFLAGS -o "$OUT/fuzz-mdhtml" $LIB_FUZZING_ENGINE "$build/lib/libmd4c-all.a"
