#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libspng into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# spng_read_fuzzer: the release's target libspng-spng_read_fuzzer
(
ov_target_begin libspng-spng_read_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/spng_read_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build spng_read_fuzzer
)

# spng_write_fuzzer: the release's target libspng-spng_write_fuzzer
(
ov_target_begin libspng-spng_write_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/spng_write_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build spng_write_fuzzer
)
