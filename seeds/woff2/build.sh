#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of woff2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# convert_woff2ttf_fuzzer: the release's target woff2-convert_woff2ttf_fuzzer
(
ov_target_begin woff2-convert_woff2ttf_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "src/convert_woff2ttf_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build convert_woff2ttf_fuzzer
)

# convert_woff2ttf_fuzzer_new_entry: the release's target woff2-convert_woff2ttf_fuzzer_new_entry
(
ov_target_begin woff2-convert_woff2ttf_fuzzer_new_entry
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "src/convert_woff2ttf_fuzzer_new_entry.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build convert_woff2ttf_fuzzer_new_entry
)
