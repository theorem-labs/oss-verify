#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of croaring into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# croaring_fuzzer: the release's target croaring-croaring_fuzzer
(
ov_target_begin croaring-croaring_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/croaring_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""















































build_lib() {
  oft_build_cmake -DROARING_USE_CPM=OFF -DENABLE_ROARING_TESTS=OFF
  oft_build_harness "fuzz/croaring_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build croaring_fuzzer
)

# croaring_fuzzer_cc: the release's target croaring-croaring_fuzzer_cc
(
ov_target_begin croaring-croaring_fuzzer_cc
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/croaring_fuzzer_cc.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""









































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DROARING_USE_CPM=OFF -DENABLE_ROARING_TESTS=OFF
  oft_build_harness "fuzz/croaring_fuzzer_cc.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build croaring_fuzzer_cc
)
