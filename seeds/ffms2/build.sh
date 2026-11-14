#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ffms2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ffms2_fuzzer: the release's target ffms2-ffms2_fuzzer
(
ov_target_begin ffms2-ffms2_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "ffms2_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  local _sr="${OFT_SYSROOT:-/opt/musl-sysroot}" _av _avs=""
  for _av in libavformat.a libavcodec.a libswscale.a libswresample.a libavutil.a; do
    [ -f "$_sr/usr/lib/$_av" ] || { echo "oft: ffms2: $_sr/usr/lib/$_av missing from the image" >&2; return 1; }
    _avs="$_avs $_sr/usr/lib/$_av"
  done
  LIB_EXTRA="${_avs# } ${LIB_EXTRA:-}"
  oft_build_harness "ffms2_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build ffms2_fuzzer
)
