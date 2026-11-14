#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of grpc-httpjson-transcoding into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# http_template_fuzz_test: the release's target grpc-httpjson-transcoding-http_template_fuzz_test
(
ov_target_begin grpc-httpjson-transcoding-http_template_fuzz_test
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "test/http_template_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















OFT_BLIND_SKIP=1
ov_target_build http_template_fuzz_test
)
