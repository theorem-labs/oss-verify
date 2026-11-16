#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of gbmc-pacemaker into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# pacemaker_fuzzer: the release's target gbmc-pacemaker-pacemaker_fuzzer
(
ov_target_begin gbmc-pacemaker-pacemaker_fuzzer gbmc-pacemaker-dep-abseil
ov_target_dependency gbmc-pacemaker-dep-abseil <<'OV_PIN_END'
build_lib() {
  oft_require_target_cxx





















  oft_build_cmake -DCMAKE_CXX_STANDARD=20 -DABSL_PROPAGATE_CXX_STD=ON \
    -DCMAKE_CXX_FLAGS_RELEASE="-Os -DNDEBUG -DABSL_MIN_LOG_LEVEL=3 -DABSL_FLAGS_STRIP_NAMES=1"
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















CFLAGS="$CFLAGS -DABSL_USE_UNSCALED_CYCLECLOCK=0"
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "pacemaker_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































DEPENDS="gbmc-pacemaker-dep-abseil"


























build_lib() {
  oft_require_target_cxx
  oft_copy_src




  [ -d "$BUILDDIR/src/tlbmc" ] || { echo "oft: gbmc-pacemaker: no tlbmc/ in the pinned tree" >&2; return 1; }
  ( cd "$BUILDDIR/src" \
    && find tlbmc -name "*.cc" -o -name "*.h" \
       | xargs -r sed -i 's/\(absl::\)\?MutexLock\s\+\([a-zA-Z0-9_]*\)\s*(\([^&][^)]*\))/\1MutexLock \2(\&\3)/g' ) || return 1
  [ -f "$BUILDDIR/src/tlbmc/scheduler/scheduler.h" ] || { echo "oft: gbmc-pacemaker: scheduler.h missing" >&2; return 1; }
  sed -i '/#include "boost\/asio\/steady_timer.hpp"/a #include <boost\/asio\/executor_work_guard.hpp>' \
    "$BUILDDIR/src/tlbmc/scheduler/scheduler.h" || return 1
  ABSL="$LIBROOT/gbmc-pacemaker-dep-abseil"
  [ -f "$ABSL/lib/liboft.a" ] || { echo "oft: gbmc-pacemaker: dep abseil archive absent at $ABSL/lib/liboft.a" >&2; return 1; }
  CXXBIN=$(oft_cxx) || return 1
  mkdir -p "$BUILDDIR/lib" "$BUILDDIR/oftobj"




  for tu in pacemaker/pacemaker scheduler/scheduler time/clock; do

    "$CXXBIN" $(oft_cxxflags) -std=c++20 -DBOOST_ASIO_HAS_STD_INVOKE_RESULT \
      -DABSL_MIN_LOG_LEVEL=3 -DABSL_FLAGS_STRIP_NAMES=1 \
      -I"$BUILDDIR/src" -I"$BUILDDIR/src/tlbmc" -I"$ABSL/src" \
      -c "$BUILDDIR/src/tlbmc/$tu.cc" -o "$BUILDDIR/oftobj/${tu##*/}.o" || return 1
  done



  "$CC" $CFLAGS -c "/work/targets/$T/atomic16.c" -o "$BUILDDIR/oftobj/atomic16.o" || return 1
  "$CHOST-ar" rcs "$BUILDDIR/lib/liboft.a" \
    "$BUILDDIR/oftobj/pacemaker.o" "$BUILDDIR/oftobj/scheduler.o" \
    "$BUILDDIR/oftobj/clock.o" "$BUILDDIR/oftobj/atomic16.o" || return 1












  OFT_CXX_STD="-std=c++20"
  OFT_HARNESS_CFLAGS="-DBOOST_ASIO_HAS_STD_INVOKE_RESULT -DABSL_MIN_LOG_LEVEL=3 -DABSL_FLAGS_STRIP_NAMES=1 -I$BUILDDIR/src/tlbmc -I$ABSL/src"
  oft_build_harness "pacemaker_fuzzer.cc" || return 1
  unset OFT_CXX_STD OFT_HARNESS_CFLAGS
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_EXTRA="$LIBROOT/gbmc-pacemaker-dep-abseil/lib/liboft.a"


























CFLAGS="$CFLAGS -DABSL_USE_UNSCALED_CYCLECLOCK=0"
ov_target_build pacemaker_fuzzer
)
