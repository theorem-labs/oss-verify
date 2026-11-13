#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libldac into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libldac_encode_fuzzer: the release's target libldac-libldac_encode_fuzzer
(
ov_target_begin libldac-libldac_encode_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzzer/libldac_encode_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































build_lib() {
  oft_require_target_cxx
  oft_copy_src
  local objdir="$BUILDDIR/obj"
  rm -rf "$objdir"; mkdir -p "$objdir"
  local f
  for f in ldaclib ldacBT; do

    "$CC" $CFLAGS -I"$BUILDDIR/src/inc" -c "$BUILDDIR/src/src/$f.c" \
      -o "$objdir/src_$f.o" || return 1
  done
  mkdir -p "$BUILDDIR/lib"
  rm -f "$BUILDDIR/lib/liboft.a"
  "$CHOST-ar" crs "$BUILDDIR/lib/liboft.a" "$objdir"/*.o || return 1
  "$CHOST-nm" "$BUILDDIR/lib/liboft.a" > /dev/null || return 1
  LIB_ARCHIVE="lib/liboft.a"
  oft_add_sysroot_deps




  oft_build_harness "libldac_encode_fuzzer_oft.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libldac_encode_fuzzer
)
