#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of cpp-httplib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# header_parser_fuzzer: the release's target cpp-httplib-header_parser_fuzzer
(
ov_target_begin cpp-httplib-header_parser_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "test/fuzzing/header_parser_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build header_parser_fuzzer
)

# multipart_parser_fuzzer: the release's target cpp-httplib-multipart_parser_fuzzer
(
ov_target_begin cpp-httplib-multipart_parser_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "test/fuzzing/multipart_parser_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build multipart_parser_fuzzer
)

# url_parser_fuzzer: the release's target cpp-httplib-url_parser_fuzzer
(
ov_target_begin cpp-httplib-url_parser_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "test/fuzzing/url_parser_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build url_parser_fuzzer
)
