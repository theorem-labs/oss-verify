#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of jbig2dec into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# jbig2_fuzzer: the release's target jbig2dec-jbig2_fuzzer
(
ov_target_begin jbig2dec-jbig2_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "jbig2_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build jbig2_fuzzer
)
