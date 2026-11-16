#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of yyjson into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# yyjson_fuzzer: the release's target yyjson-fuzzer
(
ov_target_begin yyjson-fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build yyjson_fuzzer
)

# yyjson_merge_patch_fuzzer: the release's target yyjson-merge_patch_fuzzer
(
ov_target_begin yyjson-merge_patch_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/merge_patch_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build yyjson_merge_patch_fuzzer
)

# yyjson_patch_fuzzer: the release's target yyjson-patch_fuzzer
(
ov_target_begin yyjson-patch_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/patch_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build yyjson_patch_fuzzer
)
