#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libxslt into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# xpath: the release's target libxslt-xpath
(
ov_target_begin libxslt-xpath
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/xpath.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































build_lib() {
  oft_build_cmake -DLIBXSLT_WITH_PYTHON=OFF
  oft_build_harness "tests/fuzz/xpath.c" -I"${OFT_SYSROOT:-/opt/musl-sysroot}/usr/include/libxml2"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xpath
)

# xslt: the release's target libxslt-xslt
(
ov_target_begin libxslt-xslt
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/xslt.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































build_lib() {
  oft_build_cmake -DLIBXSLT_WITH_PYTHON=OFF
  oft_build_harness "tests/fuzz/xslt.c" -I"${OFT_SYSROOT:-/opt/musl-sysroot}/usr/include/libxml2"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xslt
)
