#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wxwidgets into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# xml_parse_fuzzer: the release's target wxwidgets-xml_parse_fuzzer
(
ov_target_begin wxwidgets-xml_parse_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "src/expat/expat/fuzz/xml_parse_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























































build_lib() {
  oft_build_cmake -DwxUSE_GUI=OFF -DwxUSE_SYS_LIBS=OFF -DwxUSE_XLOCALE=OFF
  oft_build_harness "src/expat/expat/fuzz/xml_parse_fuzzer.c" -DENCODING_FOR_FUZZING=UTF-8
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xml_parse_fuzzer
)
