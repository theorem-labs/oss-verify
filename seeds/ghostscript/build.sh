#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ghostscript into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# decode_fuzzer: the release's target ghostscript-decode_fuzzer
(
ov_target_begin ghostscript-decode_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "brotli/c/fuzz/decode_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  OFT_BUILD_SUBDIR=brotli
  oft_build_cmake
  oft_build_harness "brotli/c/fuzz/decode_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build decode_fuzzer
)

# xml_parse_fuzzer: the release's target ghostscript-xml_parse_fuzzer
(
ov_target_begin ghostscript-xml_parse_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "expat/fuzz/xml_parse_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























build_lib() {
  OFT_BUILD_SUBDIR=expat
  oft_build_cmake -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_SHARED_LIBS=OFF
  OFT_HARNESS_CFLAGS="-DENCODING_FOR_FUZZING=UTF-8 -I$BUILDDIR/src/expat/lib"
  oft_build_harness "expat/fuzz/xml_parse_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xml_parse_fuzzer
)
