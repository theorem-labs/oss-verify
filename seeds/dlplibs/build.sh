#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of dlplibs into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# olefuzzer: the release's target dlplibs-olefuzzer
(
ov_target_begin dlplibs-olefuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "src/fuzz/olefuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""































build_lib() {
  oft_require_target_cxx
  oft_build_autotools --disable-tests --without-docs --disable-werror
  oft_build_harness "src/fuzz/olefuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build olefuzzer
)
