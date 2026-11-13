#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of c-blosc into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# compress_fuzzer: the release's target c-blosc-fuzz_compress
(
ov_target_begin c-blosc-fuzz_compress
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_compress.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build compress_fuzzer
)

# decompress_fuzzer: the release's target c-blosc-fuzz_decompress
(
ov_target_begin c-blosc-fuzz_decompress
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_decompress.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build decompress_fuzzer
)
