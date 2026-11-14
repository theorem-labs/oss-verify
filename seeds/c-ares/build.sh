#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of c-ares into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ares_create_query_fuzzer: the release's target c-ares-ares-test-fuzz-name
(
ov_target_begin c-ares-ares-test-fuzz-name
build_lib() {
  oft_build_cmake
  oft_build_harness "test/ares-test-fuzz-name.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build ares_create_query_fuzzer
)

# ares_parse_reply_fuzzer: the release's target c-ares-ares-test-fuzz
(
ov_target_begin c-ares-ares-test-fuzz
build_lib() {
  oft_build_cmake
  oft_build_harness "test/ares-test-fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build ares_parse_reply_fuzzer
)
