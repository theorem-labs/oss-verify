#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of spice-usbredir into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# usbredirfilterfuzz: the release's target spice-usbredir-usbredirfilterfuzz
(
ov_target_begin spice-usbredir-usbredirfilterfuzz
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "fuzzing/usbredirfilterfuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build usbredirfilterfuzz
)

# usbredirparserfuzz: the release's target spice-usbredir-usbredirparserfuzz
(
ov_target_begin spice-usbredir-usbredirparserfuzz
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "fuzzing/usbredirparserfuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build usbredirparserfuzz
)
