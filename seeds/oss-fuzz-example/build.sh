#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of oss-fuzz-example into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_char_lib: the release's target oss-fuzz-example-fuzz_char_lib
(
ov_target_begin oss-fuzz-example-fuzz_char_lib
build_lib() {
  oft_build_blind
  oft_build_harness "fuzz_char_lib.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_char_lib
)

# fuzz_complex_parser: the release's target oss-fuzz-example-fuzz_complex_parser
(
ov_target_begin oss-fuzz-example-fuzz_complex_parser
build_lib() {
  oft_build_blind
  oft_build_harness "fuzz_complex_parser.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_complex_parser
)
