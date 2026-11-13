#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of opendnp3 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzdecoder: the release's target opendnp3-fuzzdecoder
(
ov_target_begin opendnp3-fuzzdecoder
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "cpp/tests/fuzz/fuzzdecoder.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ASIO="$BUILDDIR/src/oft-vendor/asio" \
    -DFETCHCONTENT_SOURCE_DIR_EXE4CPP="$BUILDDIR/src/oft-vendor/exe4cpp" \
    -DFETCHCONTENT_SOURCE_DIR_SER4CPP="$BUILDDIR/src/oft-vendor/ser4cpp"
  oft_build_harness "cpp/tests/fuzz/fuzzdecoder.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}

















VENDOR_TREES="
oft-vendor/asio sha256:18883c350558eadf91218ae5ce9a8f8f85099c2f036c1c8579fb639092e928c5 https://github.com/chriskohlhoff/asio/archive/asio-1-16-0.zip 1
oft-vendor/exe4cpp sha256:2a8a2c7d9982f54858b92c03cff91ef433907472039f8e61ff7c9f9b3d48db6c https://github.com/automatak/exe4cpp/archive/fb878a4de598ba9d6e4338afebf83f96e03af1b8.zip 1
oft-vendor/ser4cpp sha256:5a78f83de2d70bdf4be2ab607bc4416c6866ce64a257a8f19948cf5746762f6e https://github.com/automatak/ser4cpp/archive/3c449734dc530a8f465eb0982de29165cc4e23d5.zip 1
"
ov_target_build fuzzdecoder
)
