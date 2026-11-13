#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of cmake into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cmCMakePathFuzzer: the release's target cmake-cmCMakePathFuzzer
(
ov_target_begin cmake-cmCMakePathFuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "Tests/Fuzzing/cmCMakePathFuzzer.cxx"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































































OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-16}"
ov_target_build cmCMakePathFuzzer
)
