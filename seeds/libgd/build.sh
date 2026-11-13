#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libgd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_bmp_decode: the release's target libgd-fuzz_bmp_decode
(
ov_target_begin libgd-fuzz_bmp_decode
build_lib() {
  oft_build_cmake -DBUILD_STATIC_LIBS=ON -DBUILD_PROGRAMS=OFF -DBUILD_DOCS=OFF -DENABLE_CPP=0 -DENABLE_PNG=1 -DENABLE_JPEG=1 -DENABLE_TIFF=1
  oft_build_harness "tests/fuzzing/fuzz_bmp_decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_bmp_decode
)
