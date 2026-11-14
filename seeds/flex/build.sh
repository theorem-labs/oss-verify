#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of flex into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-scanopt: the release's target flex-fuzz-scanopt
(
ov_target_begin flex-fuzz-scanopt
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz-scanopt.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


























build_lib() {
  oft_build_autotools
  local o b
  for o in "$BUILDDIR"/src/src/*.o "$BUILDDIR"/src/lib/*.o; do
    b=$(basename "$o")
    case "$b" in main.o|stage1flex-*) continue ;; esac
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$o" || return 1
  done
  oft_build_harness "fuzz-scanopt.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-scanopt
)
