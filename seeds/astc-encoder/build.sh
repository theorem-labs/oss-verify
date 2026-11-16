#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of astc-encoder into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_astc_compress: the release's target astc-encoder-fuzz_astc_compress
(
ov_target_begin astc-encoder-fuzz_astc_compress
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "Source/Fuzzers/fuzz_astc_compress.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DASTCENC_ISA_NONE=ON -DASTCENC_CLI=OFF
  oft_build_harness "Source/Fuzzers/fuzz_astc_compress.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_astc_compress
)

# fuzz_astc_decompress: the release's target astc-encoder-fuzz_astc_decompress
(
ov_target_begin astc-encoder-fuzz_astc_decompress
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "Source/Fuzzers/fuzz_astc_decompress.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DASTCENC_ISA_NONE=ON -DASTCENC_CLI=OFF
  oft_build_harness "Source/Fuzzers/fuzz_astc_decompress.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_astc_decompress
)
