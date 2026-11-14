#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of pycryptodome into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# aes_fuzzer: the release's target pycryptodome-pcd_aes_fuzzer
(
ov_target_begin pycryptodome-pcd_aes_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "pcd_aes_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""









































export OFT_BLIND_CFLAGS="-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DSYS_BITS=64"
export OFT_HARNESS_CFLAGS="-DHAVE_STDINT_H -DHAVE_POSIX_MEMALIGN -DSYS_BITS=64"
export OFT_BLIND_SKIP=1















build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "pcd_aes_fuzzer_oft.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build aes_fuzzer
)
