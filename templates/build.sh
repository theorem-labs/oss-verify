#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Copy this template to projects/<name>/build.sh, or into your repository beside your Dockerfile.
# It builds each fuzz target into $OUT. compile runs it once per build (plain, ubsan, asan, asan-ubsan, msan), each
# time in a fresh container with no network, from the Dockerfile's WORKDIR. $CC, $CXX, $CFLAGS and $CXXFLAGS are that
# build's; link each fuzz target with $LIB_FUZZING_ENGINE, through $CC or $CXX. docs/build-contract.md lists what the
# builder provides.

# --- example for a CMake project; replace with your build ---
# Build the library statically, with this build's flags. CMake finds the cross toolchain by itself
# ($CMAKE_TOOLCHAIN_FILE).
cmake -S . -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build "$WORK/build" -j"$(nproc)"

# Compile each fuzz target, and link it with the driver.
$CC $CFLAGS -I. -c fuzz/example_fuzzer.c -o "$WORK/example_fuzzer.o"
$CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE "$WORK/build/libexample.a"

# A C++ fuzz target: the same with $CXX and $CXXFLAGS.
# $CXX $CXXFLAGS -I. -c fuzz/example_fuzzer.cc -o "$WORK/example_fuzzer.o"
# $CXX $CXXFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE "$WORK/build/libexample.a"

# Optional: an allocation-failure fuzz target, in which allocations fail as the input says
# (docs/build-contract.md, Allocation-failure fuzz targets). The same object, linked with
# $LIB_ALLOCATION_FAILURE_ENGINE into a binary of its own.
# $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_allocation_failure" $LIB_ALLOCATION_FAILURE_ENGINE \
#   "$WORK/build/libexample.a"
