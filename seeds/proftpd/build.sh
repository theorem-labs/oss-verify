#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of proftpd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzer: the release's target proftpd-json_fuzzer
(
ov_target_begin proftpd-json_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/fuzzing/json_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























































build_lib() {
  oft_build_autotools --disable-cap
  "$CHOST-objcopy" --redefine-sym main=oft_proftpd_main_unused \
    "$BUILDDIR/src/src/main.o"
  n_added=0
  for o in "$BUILDDIR"/src/src/*.o "$BUILDDIR"/src/modules/*.o; do
    [ -f "$o" ] || continue
    case "$o" in */ftpdctl.o) continue ;; esac
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$o"
    n_added=$((n_added + 1))
  done


  [ "$n_added" -ge 10 ] || {
    echo "oft: proftpd: appended only $n_added objects (layout moved?)" >&2
    return 1
  }
  echo "oft: proftpd: appended $n_added src/ + modules/ objects to liboft.a"
  oft_build_harness "tests/fuzzing/json_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer
)
