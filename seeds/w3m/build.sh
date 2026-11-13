#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of w3m into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_conv: the release's target w3m-fuzz-conv
(
ov_target_begin w3m-fuzz-conv
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-conv.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























































oft_w3m_add_loose_objects() {
  local o
  for o in Str myctype; do
    [ -f "$BUILDDIR/src/$o.o" ] || { echo "oft: w3m loose object $o.o missing under $BUILDDIR/src" >&2; return 1; }
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o.o" || return 1
  done
  echo "oft: added 2 loose w3m objects (upstream build.sh link line) to lib/liboft.a"
}
build_lib() {
  oft_build_autotools ac_cv_func_setpgrp_void=yes
  oft_w3m_add_loose_objects
  oft_build_harness "fuzz/fuzz-conv.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_conv
)
