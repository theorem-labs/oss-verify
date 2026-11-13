#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of thrift-cpp into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# FuzzRoundtripBinary: the release's target thrift-cpp-FuzzRoundtripBinary
(
ov_target_begin thrift-cpp-FuzzRoundtripBinary
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "lib/cpp/test/fuzz/FuzzRoundtripBinary.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DWITH_C_GLIB=OFF -DWITH_JAVA=OFF -DWITH_JAVASCRIPT=OFF \
                  -DWITH_NODEJS=OFF -DWITH_PYTHON=OFF -DBUILD_TUTORIALS=OFF
  local tc="$BUILDDIR/cmk/compiler/cpp/bin/thrift"
  [ -x "$tc" ] || tc="$BUILDDIR/src/compiler/cpp/thrift"
  [ -x "$tc" ] || { echo "oft: thrift compiler missing after cmake build" >&2; return 1; }
  ( cd "$BUILDDIR/src/lib/cpp/test/fuzz" \
    && "$tc" --gen cpp "$BUILDDIR/src/test/FuzzTest.thrift" ) \
    || { echo "oft: thrift --gen cpp failed (binfmt qemu absent?)" >&2; return 1; }
  [ -s "$BUILDDIR/src/lib/cpp/test/fuzz/gen-cpp/FuzzTest_types.h" ] \
    || { echo "oft: gen-cpp/FuzzTest_types.h absent after generation" >&2; return 1; }
  OFT_COMPANION_SRCS="gen-cpp/FuzzTest_types.cpp"
  oft_build_harness "lib/cpp/test/fuzz/FuzzRoundtripBinary.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzRoundtripBinary
)
