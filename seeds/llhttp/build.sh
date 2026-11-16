#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of llhttp into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_parser: the release's target llhttp-fuzz_parser
(
ov_target_begin llhttp-fuzz_parser
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzzers/fuzz_parser.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  oft_build_cmake -DLLHTTP_BUILD_STATIC_LIBS=ON -DLLHTTP_BUILD_SHARED_LIBS=OFF
  oft_build_harness "test/fuzzers/fuzz_parser.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_parser
)
