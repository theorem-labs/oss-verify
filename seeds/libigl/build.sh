#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libigl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# igl_fuzzer: the release's target libigl-igl_fuzzer
(
ov_target_begin libigl-igl_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "igl_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





































































OFT_EIGEN_SRC="$BUILDDIR/src/oft-vendor/eigen"
OFT_HARNESS_CFLAGS="-DIGL_STATIC_LIBRARY -I$OFT_EIGEN_SRC"











build_lib() {
  oft_require_target_cxx
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_EIGEN="$OFT_EIGEN_SRC" \
    -DLIBIGL_USE_STATIC_LIBRARY=ON \
    -DLIBIGL_BUILD_TESTS=OFF -DLIBIGL_BUILD_TUTORIALS=OFF -DLIBIGL_INSTALL=OFF \
    -DLIBIGL_CYCODEBASE=OFF -DLIBIGL_EMBREE=OFF -DLIBIGL_GLFW=OFF \
    -DLIBIGL_IMGUI=OFF -DLIBIGL_OPENGL=OFF -DLIBIGL_STB=OFF \
    -DLIBIGL_PREDICATES=OFF -DLIBIGL_SPECTRA=OFF -DLIBIGL_XML=OFF \
    -DLIBIGL_COPYLEFT_CORE=OFF -DLIBIGL_COPYLEFT_CGAL=OFF \
    -DLIBIGL_COPYLEFT_COMISO=OFF -DLIBIGL_COPYLEFT_TETGEN=OFF \
    -DLIBIGL_RESTRICTED_MATLAB=OFF -DLIBIGL_RESTRICTED_MOSEK=OFF \
    -DLIBIGL_RESTRICTED_TRIANGLE=OFF -DLIBIGL_GLFW_TESTS=OFF
  oft_build_harness "igl_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}












































VENDOR_TREES="
oft-vendor/eigen sha256:e9c326dc8c05cd1e044c71f30f1b2e34a6161a3b6ecf445d56b53ff1669e3dec https://gitlab.com/libeigen/eigen/-/archive/5.0.1/eigen-5.0.1.tar.gz 1 Eigen/,unsupported/Eigen/,COPYING.APACHE,COPYING.BSD,COPYING.MINPACK,COPYING.MPL2,COPYING.README,LICENSE,README.md
"
ov_target_build igl_fuzzer
)
