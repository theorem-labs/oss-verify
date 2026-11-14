#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libcacard into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_simpletlv: the release's target libcacard-fuzz_simpletlv
(
ov_target_begin libcacard-fuzz_simpletlv
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz_simpletlv.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































build_lib() {
  oft_copy_src
  local sr="${OFT_SYSROOT:-/opt/musl-sysroot}"

  local ginc="-I$sr/usr/include/glib-2.0 -I$sr/usr/lib/glib-2.0/include"
  : > "$BUILDDIR/src/config.h"
  mkdir -p "$BUILDDIR/lib"
  local f
  for f in simpletlv common; do

    "$CC" $CFLAGS $ginc -I"$BUILDDIR/src" -I"$BUILDDIR/src/src" \
      -c "$BUILDDIR/src/src/$f.c" -o "$BUILDDIR/src/src/$f.o" \
      || { echo "oft: libcacard: $f.c failed to compile" >&2; return 1; }
  done
  rm -f "$BUILDDIR/lib/liboft.a"
  "$CHOST-ar" crs "$BUILDDIR/lib/liboft.a" \
    "$BUILDDIR/src/src/simpletlv.o" "$BUILDDIR/src/src/common.o"


  "$CHOST-nm" "$BUILDDIR/lib/liboft.a" | grep -q ' T simpletlv_parse$' || {
    echo "oft: libcacard: lib/liboft.a defines no simpletlv_parse" >&2; return 1; }
  LIB_ARCHIVE="lib/liboft.a"


  oft_add_sysroot_deps

  oft_build_harness "fuzz/fuzz_simpletlv.c" $ginc
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_simpletlv
)
