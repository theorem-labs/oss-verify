#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of librawspeed into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# RawSpeedFuzzer: the release's target librawspeed-RawSpeedFuzzer
(
ov_target_begin librawspeed-RawSpeedFuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/rawspeed/main.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























































OFT_CXX_STD="-std=c++20"
OFT_HARNESS_CFLAGS="-I$BUILDDIR/src/fuzz/librawspeed -O3 -ffast-math -mtune=generic"
OFT_COMPANION_SRCS="../librawspeed/fuzz/Common.cpp ../librawspeed/fuzz/RawSpeed.cpp"
build_lib() {
  oft_require_target_cxx
  oft_build_cmake \
    -DCMAKE_BUILD_TYPE=FUZZ -DLIB_FUZZING_ENGINE=oft_ossfuzz_adapter \
    -DBINARY_PACKAGE_BUILD=ON -DWITH_OPENMP=OFF \
    -DWITH_PUGIXML=OFF -DUSE_XMLLINT=OFF -DWITH_JPEG=OFF -DWITH_ZLIB=OFF \
    -DBUILD_TESTING=OFF -DBUILD_TOOLS=OFF -DBUILD_BENCHMARKING=OFF \
    -DBUILD_FUZZERS=OFF -DRAWSPEED_ENABLE_WERROR=OFF
  oft_build_harness "fuzz/rawspeed/main.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build RawSpeedFuzzer
)

# TiffDecoderFuzzer-DngDecoder: the release's target librawspeed-TiffDecoderFuzzer-DngDecoder
(
ov_target_begin librawspeed-TiffDecoderFuzzer-DngDecoder
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/librawspeed/decoders/TiffDecoders/main.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


























































OFT_CXX_STD="-std=c++20"
OFT_HARNESS_CFLAGS="-I$BUILDDIR/src/fuzz/librawspeed -O3 -ffast-math -mtune=generic"
OFT_COMPANION_SRCS="../../fuzz/Common.cpp ../../fuzz/RawSpeed.cpp"
build_lib() {
  oft_require_target_cxx
  oft_build_cmake \
    -DCMAKE_BUILD_TYPE=FUZZ -DLIB_FUZZING_ENGINE=oft_ossfuzz_adapter \
    -DBINARY_PACKAGE_BUILD=ON -DWITH_OPENMP=OFF \
    -DWITH_PUGIXML=OFF -DUSE_XMLLINT=OFF -DWITH_JPEG=OFF -DWITH_ZLIB=OFF \
    -DBUILD_TESTING=OFF -DBUILD_TOOLS=OFF -DBUILD_BENCHMARKING=OFF \
    -DBUILD_FUZZERS=OFF -DRAWSPEED_ENABLE_WERROR=OFF
  oft_build_harness "fuzz/librawspeed/decoders/TiffDecoders/main.cpp" -DDECODER=DngDecoder
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build TiffDecoderFuzzer-DngDecoder
)
