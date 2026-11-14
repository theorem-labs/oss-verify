#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of thrift-c_glib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_parse_binary: the release's target thrift-c_glib-fuzz_parse_binary
(
ov_target_begin thrift-c_glib-fuzz_parse_binary
build_lib() {
  oft_build_cmake
  oft_build_harness "lib/c_glib/test/fuzz/fuzz_parse_binary.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  oft_build_cmake \
    -DBUILD_COMPILER=OFF -DWITH_CPP=OFF -DWITH_JAVASCRIPT=OFF \
    -DWITH_NODEJS=OFF -DWITH_JAVA=OFF -DWITH_PYTHON=OFF
  mkdir -p "$BUILDDIR/src/lib/c_glib/test/fuzz/gen-c_glib"
  cp "/work/targets/$T/gen-c_glib/fuzz_test_no_uuid_types.c" \
     "/work/targets/$T/gen-c_glib/fuzz_test_no_uuid_types.h" \
     "$BUILDDIR/src/lib/c_glib/test/fuzz/gen-c_glib/"
  export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include -I$BUILDDIR/src/lib/c_glib/src -I$BUILDDIR/cmk/thrift"
  export OFT_COMPANION_SRCS="gen-c_glib/fuzz_test_no_uuid_types.c"
  oft_build_harness "lib/c_glib/test/fuzz/fuzz_parse_binary.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_parse_binary
)
