#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of phmap into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# phashmap_fuzz: the release's target phmap-phashmap_fuzz
(
ov_target_begin phmap-phashmap_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "phashmap_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build phashmap_fuzz
)
