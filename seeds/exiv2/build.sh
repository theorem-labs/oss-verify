#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of exiv2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-preview: the release's target exiv2-fuzz-preview
(
ov_target_begin exiv2-fuzz-preview
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/fuzz-preview.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-preview
)

# fuzz-read-print-write: the release's target exiv2-fuzz-read-print-write
(
ov_target_begin exiv2-fuzz-read-print-write
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/fuzz-read-print-write.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-read-print-write
)

# fuzz-read-write: the release's target exiv2-fuzz-read-write
(
ov_target_begin exiv2-fuzz-read-write
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/fuzz-read-write.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-read-write
)
