#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of muparser into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# c_api_fuzzer: the release's target muparser-c_api_fuzzer
(
ov_target_begin muparser-c_api_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "c_api_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DENABLE_OPENMP=OFF
  oft_build_harness "c_api_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build c_api_fuzzer
)

# set_eval_fuzzer: the release's target muparser-set_eval_fuzzer
(
ov_target_begin muparser-set_eval_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "set_eval_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DENABLE_OPENMP=OFF
  oft_build_harness "set_eval_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build set_eval_fuzzer
)
