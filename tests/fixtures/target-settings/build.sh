#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds the fuzz targets of a test project into $OUT, one block for each. A block gives its fuzz target one setting
# (docs/build-contract.md), or none. Each block builds the same library from its own copy of the tree. After the
# blocks, build.sh makes two links itself, as an OSS-Fuzz build does. Then it copies the driver objects that compile
# made.
# compile runs build.sh with bash. A build ported from the release runs each target's build with sh -e, and so does
# this file.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# limit_fuzzer: the driver refuses an input of 2^29 bytes or more (OV_MAX_INPUT_LOG2).
(
ov_target_begin fxs-limit
build_lib() {
  oft_build_cmake
  oft_build_harness "step_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
export OV_MAX_INPUT_LOG2=29
ov_target_build limit_fuzzer
)

# libc_fuzzer: the link takes the C library that the block makes, in place of the image's (OV_LIBC). This C library
# is a copy of the image's, with one more member in libc.a: marker.o, which defines fxs_libc_marker.
(
ov_target_begin fxs-libc
build_lib() {
  oft_build_cmake
  # The C library is outside $BUILDDIR, because oft_merge_archives puts each archive under $BUILDDIR into
  # lib/liboft.a.
  rm -rf "$LIBROOT/$T.libc"
  mkdir -p "$LIBROOT/$T.libc/lib"
  for f in crt1.o crti.o crtn.o libc.a; do
    cp "/opt/musl-sysroot/usr/lib/$f" "$LIBROOT/$T.libc/lib/$f"
  done
  "$SHIM/$CHOST-clang-plain" $BASE_CFLAGS -c "/work/targets/$T/marker.c" -o "$LIBROOT/$T.libc/marker.o"
  llvm-ar r "$LIBROOT/$T.libc/lib/libc.a" "$LIBROOT/$T.libc/marker.o"
  oft_build_harness "marker_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
export OV_LIBC="$LIBROOT/$T.libc/lib/libc.a"
ov_target_build libc_fuzzer
)

# paths_fuzzer: the compiler shims rewrite no source path (OV_PATH_REWRITE=off). The harness and the vendored file
# keep their __FILE__ in the binary.
(
OV_PATH_REWRITE=off
ov_target_begin fxs-paths
build_lib() {
  oft_build_cmake
  # The vendored file, by its path relative to the copy of the tree.
  (cd "$BUILDDIR/src" && "$CC" $CFLAGS -c oft-vendor/v.c -o "$BUILDDIR/v.o")
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/v.o"
  oft_build_harness "paths_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build paths_fuzzer
)

# none_fuzzer: no setting, after the blocks above. The library and the harness are those of paths_fuzzer.
(
ov_target_begin fxs-none
build_lib() {
  oft_build_cmake
  # The vendored file, by its path relative to the copy of the tree.
  (cd "$BUILDDIR/src" && "$CC" $CFLAGS -c oft-vendor/v.c -o "$BUILDDIR/v.o")
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/v.o"
  oft_build_harness "paths_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build none_fuzzer
)

# undeclared_fuzzer: the block makes its own C library: a copy of the image's, with one more member in libc.a,
# marker.o. It names that libc.a as one more archive of the link, and sets no OV_LIBC. This is the control of the link
# check: in the AddressSanitizer builds, the check fails a target whose link takes a C library that its block does not
# declare.
(
ov_target_begin fxs-undeclared
build_lib() {
  oft_build_cmake
  # The C library is outside $BUILDDIR, because oft_merge_archives puts each archive under $BUILDDIR into
  # lib/liboft.a.
  rm -rf "$LIBROOT/$T.libc"
  mkdir -p "$LIBROOT/$T.libc/lib"
  for f in crt1.o crti.o crtn.o libc.a; do
    cp "/opt/musl-sysroot/usr/lib/$f" "$LIBROOT/$T.libc/lib/$f"
  done
  "$SHIM/$CHOST-clang-plain" $BASE_CFLAGS -c "/work/targets/$T/marker.c" -o "$LIBROOT/$T.libc/marker.o"
  llvm-ar r "$LIBROOT/$T.libc/lib/libc.a" "$LIBROOT/$T.libc/marker.o"
  oft_build_harness "marker_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  LIB_EXTRA="$LIB_EXTRA $LIBROOT/$T.libc/lib/libc.a"
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build undeclared_fuzzer
)

# Two links that build.sh makes itself, as an OSS-Fuzz build does, with the $CC and $CFLAGS of compile.
# ov_target_begin changes CC and CFLAGS only in the subshell of its block. But each ov_target_begin writes again the
# compiler shims that compile's $CC runs. So the commands below run the shims of the last block, fxs-undeclared.
$CC $CFLAGS -I"$WORK/ext/fxs-limit/src" -c "$WORK/oss-style/step_fuzzer.c" -o "$WORK/oss-style/step_fuzzer.o"
$CC $CFLAGS -c "$WORK/ext/fxs-limit/src/fxs.c" -o "$WORK/oss-style/fxs.o"
# limit_af_fuzzer: an allocation-failure fuzz target. Its link command alone sets the limit 2^29.
OV_MAX_INPUT_LOG2=29 $CC $CFLAGS "$WORK/oss-style/step_fuzzer.o" "$WORK/oss-style/fxs.o" -o "$OUT/limit_af_fuzzer" \
  $LIB_ALLOCATION_FAILURE_ENGINE
# oss_none_fuzzer: no setting.
$CC $CFLAGS "$WORK/oss-style/step_fuzzer.o" "$WORK/oss-style/fxs.o" -o "$OUT/oss_none_fuzzer" $LIB_FUZZING_ENGINE

# The driver objects that compile made before build.sh ran. No block changes them.
mkdir -p "$OUT/driver-objects"
cp /tmp/ov/*.o "$OUT/driver-objects/"
