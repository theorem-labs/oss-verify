#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of estoraged into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# estoraged_fuzzer: the release's target estoraged-estoraged_fuzzer
(
ov_target_begin estoraged-estoraged_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "estoraged_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_copy_src
  mkdir -p "$BUILDDIR/lib" "$BUILDDIR/include"
  rm -f "$BUILDDIR/lib/liboft.a"


  cp -R "/work/targets/$T/shims/." "$BUILDDIR/include/"



  local tu obj
  for tu in src/erase/pattern.cpp src/erase/zero.cpp src/erase/cryptoErase.cpp src/util.cpp; do
    obj="$BUILDDIR/$(basename "$tu" .cpp).o"

    "$CC" $CFLAGS -x c++ -stdlib=libc++ -std=c++23 -fno-omit-frame-pointer \
      -I"$BUILDDIR/include" -I"$BUILDDIR/src/include" -I"$BUILDDIR/src/src" \
      -c "$BUILDDIR/src/$tu" -o "$obj" || return 1
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$obj" || return 1
  done
  "$CHOST-ranlib" "$BUILDDIR/lib/liboft.a" || return 1
  OFT_CXX_STD="-std=c++23"
  OFT_HARNESS_CFLAGS="-fno-omit-frame-pointer"
  oft_build_harness "estoraged_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build estoraged_fuzzer
)
