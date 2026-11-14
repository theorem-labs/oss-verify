#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of unit into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_basic: the release's target unit-nxt_basic_fuzz
(
ov_target_begin unit-nxt_basic_fuzz
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzzing/nxt_basic_fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CFLAGS="$CFLAGS" ./configure --cc="$CC" --no-regex --no-pcre2 \
    && oft_make_then_keep_going E=0 build/lib/libnxt.a )
  oft_merge_archives


  oft_build_harness "fuzzing/nxt_basic_fuzz.c" "-I$BUILDDIR/src/build/include"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
























  local sobj="$BUILDDIR/wrap_unit_init.o"
  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/unit-nxt_basic_fuzz/wrap_unit_init.c -o "$sobj" || return 1



  local sym
  for sym in __wrap_geteuid __wrap_getegid __wrap_sysconf __wrap_fcntl \
             clock_gettime sched_getaffinity; do
    "$CHOST-nm" "$sobj" | grep -q " T $sym\$" || {
      echo "oft: wrap_unit_init.o defines no $sym" >&2
      return 1
    }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $sobj -Wl,--wrap=geteuid -Wl,--wrap=getegid"
  LIB_EXTRA="$LIB_EXTRA -Wl,--wrap=sysconf -Wl,--wrap=fcntl"
}
ov_target_build fuzz_basic
)
