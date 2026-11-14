#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of nghttp2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# nghttp2_fuzzer: the release's target nghttp2-fuzz_target
(
ov_target_begin nghttp2-fuzz_target
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_target.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DENABLE_LIB_ONLY=ON -DBUILD_STATIC_LIBS=ON
  oft_build_harness "fuzz/fuzz_target.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build nghttp2_fuzzer
)

# nghttp2_fuzzer_fdp: the release's target nghttp2-fuzz_target_fdp
(
ov_target_begin nghttp2-fuzz_target_fdp
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_target_fdp.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DENABLE_LIB_ONLY=ON -DBUILD_STATIC_LIBS=ON
  oft_build_harness "fuzz/fuzz_target_fdp.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build nghttp2_fuzzer_fdp
)
