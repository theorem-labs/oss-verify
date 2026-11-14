#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of tidy-html5 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# tidy_config_fuzzer: the release's target tidy-html5-tidy_config_fuzzer
(
ov_target_begin tidy-html5-tidy_config_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tidy_config_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build tidy_config_fuzzer
)

# tidy_fuzzer: the release's target tidy-html5-tidy_fuzzer
(
ov_target_begin tidy-html5-tidy_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tidy_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build tidy_fuzzer
)

# tidy_parse_string_fuzzer: the release's target tidy-html5-tidy_parse_string_fuzzer
(
ov_target_begin tidy-html5-tidy_parse_string_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tidy_parse_string_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build tidy_parse_string_fuzzer
)

# tidy_xml_fuzzer: the release's target tidy-html5-tidy_xml_fuzzer
(
ov_target_begin tidy-html5-tidy_xml_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tidy_xml_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build tidy_xml_fuzzer
)
