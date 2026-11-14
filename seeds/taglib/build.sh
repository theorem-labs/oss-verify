#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of taglib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# taglib_fileref_fuzzer: the release's target taglib-taglib_fileref_fuzzer
(
ov_target_begin taglib-taglib_fileref_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzzing/taglib_fileref_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD_BINDINGS=OFF -DENABLE_CCACHE=OFF -DVISIBILITY_HIDDEN=OFF
  oft_build_harness "tests/fuzzing/taglib_fileref_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build taglib_fileref_fuzzer
)
