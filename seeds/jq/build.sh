#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of jq into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# base: the release's target jq-base
(
ov_target_begin jq-base
build_lib() {
  oft_build_autotools
  oft_build_harness "vendor/oniguruma/harnesses/base.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build base
)

# deluxe: the release's target jq-deluxe
(
ov_target_begin jq-deluxe
build_lib() {
  oft_build_autotools
  oft_build_harness "vendor/oniguruma/harnesses/deluxe.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build deluxe
)

# jq_fuzz_parse_extended: the release's target jq-jq_fuzz_parse_extended
(
ov_target_begin jq-jq_fuzz_parse_extended
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/jq_fuzz_parse_extended.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build jq_fuzz_parse_extended
)

# jq_fuzz_parse_stream: the release's target jq-jq_fuzz_parse_stream
(
ov_target_begin jq-jq_fuzz_parse_stream
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/jq_fuzz_parse_stream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build jq_fuzz_parse_stream
)

# libfuzzer-onig: the release's target jq-libfuzzer-onig
(
ov_target_begin jq-libfuzzer-onig
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "vendor/oniguruma/harnesses/libfuzzer-onig.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libfuzzer-onig
)
