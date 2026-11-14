#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of janus-gateway into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# rtcp_fuzzer: the release's target janus-gateway-rtcp_fuzzer
(
ov_target_begin janus-gateway-rtcp_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzzers/rtcp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include"
build_lib() {
  oft_build_autotools












  LIB_EXTRA="/opt/musl-sysroot/usr/lib/libjansson.a ${LIB_EXTRA:-}"
  local o
  for o in janus-log.o janus-utils.o janus-rtcp.o janus-rtp.o janus-sdp-utils.o; do
    if [ ! -f "$BUILDDIR/src/src/$o" ]; then
      echo "oft: janus: expected program object src/src/$o missing" >&2
      return 1
    fi
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/src/$o"
  done
  oft_build_harness "fuzzers/rtcp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build rtcp_fuzzer
)

# rtp_fuzzer: the release's target janus-gateway-rtp_fuzzer
(
ov_target_begin janus-gateway-rtp_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzzers/rtp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include"
build_lib() {
  oft_build_autotools












  LIB_EXTRA="/opt/musl-sysroot/usr/lib/libjansson.a ${LIB_EXTRA:-}"
  local o
  for o in janus-log.o janus-utils.o janus-rtcp.o janus-rtp.o janus-sdp-utils.o; do
    if [ ! -f "$BUILDDIR/src/src/$o" ]; then
      echo "oft: janus: expected program object src/src/$o missing" >&2
      return 1
    fi
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/src/$o"
  done
  oft_build_harness "fuzzers/rtp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build rtp_fuzzer
)

# sdp_fuzzer: the release's target janus-gateway-sdp_fuzzer
(
ov_target_begin janus-gateway-sdp_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzzers/sdp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include"
build_lib() {
  oft_build_autotools












  LIB_EXTRA="/opt/musl-sysroot/usr/lib/libjansson.a ${LIB_EXTRA:-}"
  local o
  for o in janus-log.o janus-utils.o janus-rtcp.o janus-rtp.o janus-sdp-utils.o; do
    if [ ! -f "$BUILDDIR/src/src/$o" ]; then
      echo "oft: janus: expected program object src/src/$o missing" >&2
      return 1
    fi
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/src/$o"
  done
  oft_build_harness "fuzzers/sdp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build sdp_fuzzer
)
