#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of openjph into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ojph_compress_fuzz_target: the release's target openjph-ojph_compress_fuzz_target
(
ov_target_begin openjph-ojph_compress_fuzz_target
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzing/fuzz_targets/ojph_compress_fuzz_target.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build ojph_compress_fuzz_target
)

# ojph_expand_fuzz_target: the release's target openjph-ojph_expand_fuzz_target
(
ov_target_begin openjph-ojph_expand_fuzz_target
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzing/fuzz_targets/ojph_expand_fuzz_target.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build ojph_expand_fuzz_target
)
