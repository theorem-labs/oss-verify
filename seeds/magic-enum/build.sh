#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of magic-enum into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# magic_enum_fuzzer: the release's target magic-enum-magic_enum_fuzzer
(
ov_target_begin magic-enum-magic_enum_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "magic_enum_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























OFT_HARNESS_CFLAGS="-I$BUILDDIR/src/include/magic_enum"
ov_target_build magic_enum_fuzzer
)
