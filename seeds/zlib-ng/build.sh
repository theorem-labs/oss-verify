#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of zlib-ng into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzer_checksum: the release's target zlib-ng-fuzzer_checksum
(
ov_target_begin zlib-ng-fuzzer_checksum
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzzer_checksum.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzzer_checksum
)

# fuzzer_compress: the release's target zlib-ng-fuzzer_compress
(
ov_target_begin zlib-ng-fuzzer_compress
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzzer_compress.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzzer_compress
)

# fuzzer_example_dict: the release's target zlib-ng-fuzzer_example_dict
(
ov_target_begin zlib-ng-fuzzer_example_dict
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzzer_example_dict.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzzer_example_dict
)

# fuzzer_example_flush: the release's target zlib-ng-fuzzer_example_flush
(
ov_target_begin zlib-ng-fuzzer_example_flush
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzzer_example_flush.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzzer_example_flush
)

# fuzzer_example_large: the release's target zlib-ng-fuzzer_example_large
(
ov_target_begin zlib-ng-fuzzer_example_large
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzzer_example_large.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzzer_example_large
)

# fuzzer_example_small: the release's target zlib-ng-fuzzer_example_small
(
ov_target_begin zlib-ng-fuzzer_example_small
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzzer_example_small.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzzer_example_small
)
