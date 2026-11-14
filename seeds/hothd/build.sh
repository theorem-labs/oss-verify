#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of hothd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# hothd_payload_fuzzer: the release's target hothd-hothd_payload_fuzzer
(
ov_target_begin hothd-hothd_payload_fuzzer hothd-dep-stdplus
ov_target_dependency hothd-dep-stdplus <<'OV_PIN_END'
build_lib() {
  mkdir -p "$BUILDDIR/include" "$BUILDDIR/srcs"
  cp -R "$SRCDIR/include/stdplus" "$BUILDDIR/include/"
  cp "$SRCDIR/src/exception.cpp" "$SRCDIR/src/print.cpp" "$SRCDIR/src/raw.cpp" \
    "$BUILDDIR/srcs/"
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "hothd_payload_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""































DEPENDS="hothd-dep-stdplus"
build_lib() {
  oft_require_target_cxx
  oft_copy_src
  mkdir -p "$BUILDDIR/lib" "$BUILDDIR/include"
  rm -f "$BUILDDIR/lib/liboft.a"
  cp -R "$LIBROOT/hothd-dep-stdplus/include/." "$BUILDDIR/include/"
  cp -R "/work/targets/$T/shims/xyz" "$BUILDDIR/include/"
  local tu
  for tu in exception print raw; do

    "$CC" $CFLAGS -x c++ -stdlib=libc++ -std=c++23 \
      -I"$BUILDDIR/include" \
      -c "$LIBROOT/hothd-dep-stdplus/srcs/$tu.cpp" \
      -o "$BUILDDIR/stdplus-$tu.o" || return 1
  done

  "$CC" $CFLAGS -x c++ -stdlib=libc++ -std=c++23 \
    -I"$BUILDDIR/src" -I"$BUILDDIR/src/google3" -I"$BUILDDIR/include" \
    -c "$BUILDDIR/src/payload_update.cpp" \
    -o "$BUILDDIR/payload_update.o" || return 1
  "$CHOST-ar" crs "$BUILDDIR/lib/liboft.a" \
    "$BUILDDIR/payload_update.o" "$BUILDDIR/stdplus-exception.o" \
    "$BUILDDIR/stdplus-print.o" "$BUILDDIR/stdplus-raw.o" || return 1
  OFT_CXX_STD="-std=c++23"
  oft_build_harness "hothd_payload_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build hothd_payload_fuzzer
)
