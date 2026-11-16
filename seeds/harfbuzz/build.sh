#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of harfbuzz into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# hb-shape-fuzzer: the release's target harfbuzz-hb-shape-fuzzer
(
ov_target_begin harfbuzz-hb-shape-fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/hb-shape-fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build hb-shape-fuzzer
)

# hb-subset-fuzzer: the release's target harfbuzz-hb-subset-fuzzer
(
ov_target_begin harfbuzz-hb-subset-fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/hb-subset-fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build hb-subset-fuzzer
)
