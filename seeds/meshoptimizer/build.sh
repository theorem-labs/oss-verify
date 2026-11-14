#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of meshoptimizer into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# clusterfuzz: the release's target meshoptimizer-clusterfuzz
(
ov_target_begin meshoptimizer-clusterfuzz
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/clusterfuzz.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build clusterfuzz
)

# codecfuzzer: the release's target meshoptimizer-codecfuzz
(
ov_target_begin meshoptimizer-codecfuzz
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/codecfuzz.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build codecfuzzer
)

# simplifyfuzz: the release's target meshoptimizer-simplifyfuzz
(
ov_target_begin meshoptimizer-simplifyfuzz
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/simplifyfuzz.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build simplifyfuzz
)
