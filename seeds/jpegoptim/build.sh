#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of jpegoptim into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libjpeg_compression_fuzzer: the release's target jpegoptim-fuzz_compression
(
ov_target_begin jpegoptim-fuzz_compression
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_compression.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































































build_lib() {
  oft_build_cmake \
    -DBUILD_FUZZERS=On \
    -DUSE_MOZJPEG=0 \
    -DLIBJPEG_INCLUDE_DIR=/opt/musl-sysroot/usr/include \
    -DLIBJPEG_LIBRARY=/opt/musl-sysroot/usr/lib/libjpeg.a \
    -DCMAKE_BUILD_TYPE=None \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF
  oft_build_harness "fuzz/fuzz_compression.c" -DBUILD_FOR_OSS_FUZZ=1
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libjpeg_compression_fuzzer
)
