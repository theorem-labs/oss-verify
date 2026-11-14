#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of tinyxml2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# xmltest: the release's target tinyxml2-xmltest
(
ov_target_begin tinyxml2-xmltest
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "xmltest.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  sed 's|#include "tinyxml2/tinyxml2.h"|#include "tinyxml2.h"|' \
    "/work/targets/$T/xmltest.cpp" > "$BUILDDIR/src/xmltest.cpp"
  oft_build_harness "xmltest.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xmltest
)

# xmltest2: the release's target tinyxml2-xmltest2
(
ov_target_begin tinyxml2-xmltest2
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "xmltest2.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  sed 's|#include "tinyxml2/tinyxml2.h"|#include "tinyxml2.h"|' \
    "/work/targets/$T/xmltest2.cpp" > "$BUILDDIR/src/xmltest2.cpp"
  oft_build_harness "xmltest2.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xmltest2
)
