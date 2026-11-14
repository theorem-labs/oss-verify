#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libzmq into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# test_z85_decode_fuzzer: the release's target libzmq-test_z85_decode_fuzzer
(
ov_target_begin libzmq-test_z85_decode_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/test_z85_decode_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD_TESTS=ON -DWITH_TLS=OFF
  oft_build_harness "tests/test_z85_decode_fuzzer.cpp" -DZMQ_CUSTOM_PLATFORM_HPP -DZMQ_USE_FUZZING_ENGINE
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build test_z85_decode_fuzzer
)
