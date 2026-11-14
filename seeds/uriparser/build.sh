#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of uriparser into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# uri_dissect_query_malloc_fuzzer: the release's target uriparser-DissectQueryMallocFuzzer
(
ov_target_begin uriparser-DissectQueryMallocFuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/DissectQueryMallocFuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DURIPARSER_BUILD_DOCS=OFF -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_TOOLS=OFF
  oft_build_harness "fuzz/DissectQueryMallocFuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build uri_dissect_query_malloc_fuzzer
)
