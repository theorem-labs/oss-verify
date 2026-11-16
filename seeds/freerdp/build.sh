#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of freerdp into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# TestFuzzCommonAssistanceBinToHexString: the release's target freerdp-TestFuzzCommonAssistanceBinToHexString
(
ov_target_begin freerdp-TestFuzzCommonAssistanceBinToHexString
build_lib() {
  oft_build_cmake
  oft_build_harness "libfreerdp/common/test/TestFuzzCommonAssistanceBinToHexString.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































































build_lib() {
  oft_build_cmake -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_KRB5=OFF -DWITH_X11=OFF -DWITH_FUSE=OFF -DWITH_MANPAGES=OFF -DWITH_CLIENT=OFF -DWITH_SERVER=OFF -DWITH_SAMPLE=OFF
  oft_build_harness "libfreerdp/common/test/TestFuzzCommonAssistanceBinToHexString.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build TestFuzzCommonAssistanceBinToHexString
)
