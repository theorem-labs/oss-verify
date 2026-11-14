#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of serenity into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# FuzzASN1: the release's target serenity-FuzzASN1
(
ov_target_begin serenity-FuzzASN1
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































































build_lib() {
  oft_require_target_cxx || return 1

  oft_copy_src
  local tools_bld=/tmp/lagom-tools-build
  local tools_prefix=/tmp/lagom-tools-install
  rm -rf -- "$tools_bld" "$tools_prefix"
  CC=gcc CXX=g++ CFLAGS= CXXFLAGS= LDFLAGS= \
    cmake -S "$BUILDDIR/src/Meta/Lagom" -B "$tools_bld" \
      -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_LAGOM=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DENABLE_LAGOM_CCACHE=OFF \
      -DENABLE_NETWORK_DOWNLOADS=OFF \
      -DENABLE_CACERT_DOWNLOAD=OFF \
      -DENABLE_TIME_ZONE_DATABASE_DOWNLOAD=OFF \
      -DENABLE_UNICODE_DATABASE_DOWNLOAD=OFF \
      -DENABLE_ADOBE_ICC_PROFILES_DOWNLOAD=OFF \
      -DCMAKE_INSTALL_PREFIX="$tools_prefix" \
      -Dpackage=LagomTools || return 1
  CC=gcc CXX=g++ CFLAGS= CXXFLAGS= LDFLAGS= \
    make -C "$tools_bld" -j"$(oft_jobs)" install || return 1


  rm -rf -- "$tools_bld"











  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake"
  rm -rf "$BUILDDIR/cmk"
  mkdir -p "$BUILDDIR/cmk"
  ( cd "$BUILDDIR/cmk" \
    && cmake "$BUILDDIR/src/Meta/Lagom" -GNinja \
         -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX="${OFT_PREFIX:?}" \
         -DBUILD_SHARED_LIBS=OFF \
         -DBUILD_TESTING=OFF \
         -DBUILD_LAGOM=ON \
         -DENABLE_FUZZERS=ON \
         -DENABLE_LAGOM_LIBWEB=OFF \
         -DENABLE_LAGOM_CCACHE=OFF \
         -DENABLE_NETWORK_DOWNLOADS=OFF \
         -DENABLE_CACERT_DOWNLOAD=OFF \
         -DENABLE_TIME_ZONE_DATABASE_DOWNLOAD=OFF \
         -DENABLE_UNICODE_DATABASE_DOWNLOAD=OFF \
         -DENABLE_ADOBE_ICC_PROFILES_DOWNLOAD=OFF \
         -DCMAKE_PREFIX_PATH="$tools_prefix" ) || return 1




  ( cd "$BUILDDIR/cmk" && ninja -j"$(oft_jobs)" -k 0 ) || true
  oft_merge_archives











  OFT_CXX_STD="-std=c++26"
  oft_build_harness "Meta/Lagom/Fuzzers/FuzzASN1.cpp" \
    -fno-exceptions \
    -I"$BUILDDIR/src" \
    -I"$BUILDDIR/src/Userland" \
    -I"$BUILDDIR/src/Userland/Libraries" \
    -I"$BUILDDIR/src/Userland/Services" \
    -I"$BUILDDIR/cmk" \
    -I"$BUILDDIR/cmk/Userland/Libraries" \
    -I"$BUILDDIR/cmk/Userland/Services"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzASN1
)
