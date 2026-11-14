#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of faad2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_config: the release's target faad2-fuzz_config
(
ov_target_begin faad2-fuzz_config
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_config.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_config
)

# fuzz_decode: the release's target faad2-fuzz_decode
(
ov_target_begin faad2-fuzz_decode
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_decode
)
