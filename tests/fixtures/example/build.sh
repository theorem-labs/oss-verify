#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# templates/build.sh with its C++ lines in use, for tests/test_builder.py.
cmake -S . -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build "$WORK/build" -j"$(nproc)"

$CC $CFLAGS -I. -c fuzz/example_fuzzer.c -o "$WORK/example_fuzzer.o"
$CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE "$WORK/build/libexample.a"

$CXX $CXXFLAGS -I. -c fuzz/example_fuzzer.cc -o "$WORK/example_fuzzer_cc.o"
$CXX $CXXFLAGS "$WORK/example_fuzzer_cc.o" -o "$OUT/example_fuzzer_cc" $LIB_FUZZING_ENGINE "$WORK/build/libexample.a"

# The allocation-failure variants of both (docs/build-contract.md): the same objects, linked with
# $LIB_ALLOCATION_FAILURE_ENGINE, and with $LIB_ALLOCATION_COUNTING_ENGINE, as a sweep or test build would be.
$CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_af" $LIB_ALLOCATION_FAILURE_ENGINE "$WORK/build/libexample.a"
$CXX $CXXFLAGS "$WORK/example_fuzzer_cc.o" -o "$OUT/example_fuzzer_cc_af" $LIB_ALLOCATION_FAILURE_ENGINE \
  "$WORK/build/libexample.a"
$CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_count" $LIB_ALLOCATION_COUNTING_ENGINE \
  "$WORK/build/libexample.a"
$CXX $CXXFLAGS "$WORK/example_fuzzer_cc.o" -o "$OUT/example_fuzzer_cc_count" $LIB_ALLOCATION_COUNTING_ENGINE \
  "$WORK/build/libexample.a"

# An executable that is not a fuzz target, which discovery must leave out.
printf 'int main(void) { return 0; }\n' > "$WORK/tool.c"
$CC $CFLAGS "$WORK/tool.c" -o "$OUT/tool"
