#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of behaviortreecpp into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# bb_fuzzer: the release's target behaviortreecpp-bb_fuzzer
(
ov_target_begin behaviortreecpp-bb_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzing/bb_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBTCPP_SQLITE_LOGGING=OFF -DBTCPP_SHARED_LIBS=OFF -DBTCPP_EXAMPLES=OFF -DBTCPP_BUILD_TOOLS=OFF
  oft_build_harness "fuzzing/bb_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build bb_fuzzer
)

# script_fuzzer: the release's target behaviortreecpp-script_fuzzer
(
ov_target_begin behaviortreecpp-script_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzing/script_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBTCPP_SQLITE_LOGGING=OFF -DBTCPP_SHARED_LIBS=OFF -DBTCPP_EXAMPLES=OFF -DBTCPP_BUILD_TOOLS=OFF
  oft_build_harness "fuzzing/script_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build script_fuzzer
)
