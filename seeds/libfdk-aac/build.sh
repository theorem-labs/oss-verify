#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libfdk-aac into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# aac_dec_fuzzer: the release's target libfdk-aac-aac_dec_fuzzer
(
ov_target_begin libfdk-aac-aac_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzzer/aac_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























OFT_BLIND_SKIP=1
ov_target_build aac_dec_fuzzer
)
