#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of pcre2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# pcre2_fuzzer: the release's target pcre2-pcre2_fuzzsupport
(
ov_target_begin pcre2-pcre2_fuzzsupport
build_lib() {
  oft_build_cmake
  oft_build_harness "src/pcre2_fuzzsupport.c" -DHAVE_CONFIG_H
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build pcre2_fuzzer
)
