#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Copy this template to .theorem/build.sh in your repository. The Dockerfile of .theorem/ copies it to $SRC.
# It builds each fuzz target into $OUT. compile runs it once per build (plain, ubsan, asan, asan-ubsan), each time in a
# fresh container with no network, from the Dockerfile's WORKDIR. $CC, $CXX, $CFLAGS and $CXXFLAGS are that build's.
# Link each fuzz target with $LIB_FUZZING_ENGINE, through $CC or $CXX. docs/build-contract.md lists what the builder
# provides.
#
# templates/.theorem/Dockerfile copies your whole repository, .theorem/ included, to $SRC/example, its WORKDIR. Thus a
# fuzz target source in .theorem/ is at .theorem/<file> from the WORKDIR.

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

# A fuzz target source in .theorem/: the same with its path from the WORKDIR.
# $CC $CFLAGS -I. -c .theorem/example_fuzzer.c -o "$WORK/example_fuzzer.o"

# Optional: an allocation-failure fuzz target, in which allocations fail as the input says
# (docs/build-contract.md, Allocation-failure fuzz targets). The same object, linked with
# $LIB_ALLOCATION_FAILURE_ENGINE into a binary of its own.
# $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_allocation_failure" $LIB_ALLOCATION_FAILURE_ENGINE \
#   "$WORK/build/libexample.a"
