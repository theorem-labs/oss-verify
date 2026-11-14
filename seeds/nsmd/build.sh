#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of nsmd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# decode_nsm_disable_tokens_req_fuzzer: the release's target nsmd-decode_nsm_disable_tokens_req_fuzzer
(
ov_target_begin nsmd-decode_nsm_disable_tokens_req_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "decode_nsm_disable_tokens_req_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




























build_lib() {
  oft_require_target_cxx
  oft_copy_src
  local o="$BUILDDIR/libnsm-obj"
  rm -rf -- "${BUILDDIR:?}/libnsm-obj"
  mkdir -p "$o" "$BUILDDIR/lib"
  local f
  for f in base debug-token device-capability-discovery device-configuration \
           diagnostics firmware-utils network-ports pci-links \
           platform-environmental; do

    "$CC" $CFLAGS -I"$BUILDDIR/src" -I"$BUILDDIR/src/libnsm" \
      -c "$BUILDDIR/src/libnsm/$f.c" -o "$o/$f.o" || return 1
  done
  rm -f "$BUILDDIR/lib/liboft.a"
  "$CHOST-ar" crs "$BUILDDIR/lib/liboft.a" "$o"/*.o || return 1
  oft_build_harness "decode_nsm_disable_tokens_req_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build decode_nsm_disable_tokens_req_fuzzer
)
