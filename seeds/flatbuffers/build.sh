#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of flatbuffers into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# 64bit_fuzzer: the release's target flatbuffers-flatbuffers_64bit_fuzzer
(
ov_target_begin flatbuffers-flatbuffers_64bit_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzzer/flatbuffers_64bit_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































































build_lib() {
  oft_require_target_cxx




  grep -qF '#include "../test_assert.cpp"' "$SRCDIR/tests/fuzzer/test_init.h" \
    || { echo "oft: flatbuffers-flatbuffers_64bit_fuzzer: $SRCDIR/tests/fuzzer/test_init.h does not carry the test_assert.cpp include of patch 0003-test-init-carries-test-assert -- refusing to build a tree whose link would fail on InitTestEngine" >&2; return 1; }
  oft_build_cmake
  oft_build_harness "tests/fuzzer/flatbuffers_64bit_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build 64bit_fuzzer
)
