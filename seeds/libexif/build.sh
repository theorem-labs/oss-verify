#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libexif into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# exif_from_data_fuzzer: the release's target libexif-exif_from_data_fuzzer
(
ov_target_begin libexif-exif_from_data_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "exif_from_data_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build exif_from_data_fuzzer
)

# exif_loader_fuzzer: the release's target libexif-exif_loader_fuzzer
(
ov_target_begin libexif-exif_loader_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "exif_loader_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build exif_loader_fuzzer
)
