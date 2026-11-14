#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of openjpeg into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# opj_decompress_fuzzer_J2K: the release's target openjpeg-opj_decompress_fuzzer_J2K
(
ov_target_begin openjpeg-opj_decompress_fuzzer_J2K
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzzers/opj_decompress_fuzzer_J2K.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build opj_decompress_fuzzer_J2K
)

# opj_decompress_fuzzer_JP2: the release's target openjpeg-opj_decompress_fuzzer_JP2
(
ov_target_begin openjpeg-opj_decompress_fuzzer_JP2
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzzers/opj_decompress_fuzzer_JP2.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build opj_decompress_fuzzer_JP2
)
