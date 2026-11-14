#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of fluent-bit into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ares-test-fuzz: the release's target fluent-bit-ares-test-fuzz
(
ov_target_begin fluent-bit-ares-test-fuzz
build_lib() {
  oft_build_cmake -DFLB_CONFIG_YAML=Off -DFLB_SIMD=Off
  oft_build_harness "lib/c-ares-1.34.6/test/ares-test-fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build ares-test-fuzz
)
