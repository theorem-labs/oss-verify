#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of arduinojson into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# json_fuzzer: the release's target arduinojson-json_fuzzer
(
ov_target_begin arduinojson-json_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "extras/fuzzing/json_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build json_fuzzer
)

# msgpack_fuzzer: the release's target arduinojson-msgpack_fuzzer
(
ov_target_begin arduinojson-msgpack_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "extras/fuzzing/msgpack_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build msgpack_fuzzer
)

# number_fuzzer: the release's target arduinojson-number_fuzzer
(
ov_target_begin arduinojson-number_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "extras/fuzzing/number_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build number_fuzzer
)
