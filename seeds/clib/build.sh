#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of clib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_manifest: the release's target clib-fuzz_manifest
(
ov_target_begin clib-fuzz_manifest
build_lib() {
  oft_build_blind
  oft_build_harness "test/fuzzing/fuzz_manifest.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





































oft_clib_add_curl_stub() {
  local obj="$BUILDDIR/obj/oft_curl_stub.o"



  "$CC" $CFLAGS -c /work/targets/clib-fuzz_manifest/curl_stub.c -o "$obj" || return 1
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$obj" || return 1
  "$CHOST-nm" "$obj" | grep -q " T curl_easy_init$" || {
    echo "oft: curl stub object missing curl_easy_init" >&2; return 1; }
}


build_lib() {
  export CFLAGS="$CFLAGS -isystem /work/targets/clib-fuzz_manifest/stub-include"
  oft_build_blind
  oft_clib_add_curl_stub
  oft_build_harness "test/fuzzing/fuzz_manifest.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_manifest
)
