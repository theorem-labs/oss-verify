#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of nanopb into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzztest_io_errors: the release's target nanopb-fuzztest
(
ov_target_begin nanopb-fuzztest
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzztest/fuzztest.c" -DLLVMFUZZER
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



























































build_lib() {
  export CFLAGS="$CFLAGS -DPB_ENABLE_MALLOC -include /work/targets/nanopb-fuzztest/pb_malloc_shim.h"
  oft_build_cmake
  oft_build_harness "tests/fuzztest/fuzztest.c" -DLLVMFUZZER
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
OFT_COMPANION_SRCS="../common/malloc_wrappers.c"
ov_target_build fuzztest_io_errors
)
