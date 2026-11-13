#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of mupdf into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_quadratic: the release's target mupdf-fuzz_quadratic
(
ov_target_begin mupdf-fuzz_quadratic
build_lib() {
  oft_build_blind
  oft_build_harness "thirdparty/cmark-gfm/fuzz/fuzz_quadratic.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































build_lib() {
  oft_copy_src
  make -C "$BUILDDIR/src" -j "${OFT_MAKE_JOBS:-1}" \
    OUT=build/oft build=release verbose=yes \
    CC="$CC" CXX="$CXX" AR="$CHOST-ar" XCFLAGS="$CFLAGS" \
    HAVE_GLUT=no HAVE_X11=no HAVE_OBJCOPY=no USE_SYSTEM_LIBS=no \
    libs






  mkdir -p "$BUILDDIR/oft-extra"
  local cmf
  for cmf in commonmark latex man plaintext xml render; do

    "$CC" $CFLAGS -DCMARK_GFM_STATIC_DEFINE \
      -I"$BUILDDIR/src/thirdparty/cmark-gfm/src" \
      -I"$BUILDDIR/src/thirdparty/cmark-gfm/extensions" \
      -I"$BUILDDIR/src/scripts/cmark-gfm" \
      -c "$BUILDDIR/src/thirdparty/cmark-gfm/src/$cmf.c" \
      -o "$BUILDDIR/oft-extra/cmark-$cmf.o"
  done
  "$CHOST-ar" crs "$BUILDDIR/oft-extra/liboft-cmark-render.a" "$BUILDDIR/oft-extra/"cmark-*.o
  oft_merge_archives





  oft_build_harness "thirdparty/cmark-gfm/fuzz/fuzz_quadratic.c" \
    -DCMARK_GFM_STATIC_DEFINE \
    -I"$BUILDDIR/src/thirdparty/cmark-gfm/src" \
    -I"$BUILDDIR/src/thirdparty/cmark-gfm/extensions" \
    -I"$BUILDDIR/src/scripts/cmark-gfm"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_quadratic
)
