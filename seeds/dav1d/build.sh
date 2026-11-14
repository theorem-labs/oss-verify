#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of dav1d into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# dav1d_fuzzer: the release's target dav1d-dav1d_fuzzer
(
ov_target_begin dav1d-dav1d_fuzzer
build_lib() {












  local _oft_wipe=""
  [ -d "${BUILDDIR:?}/mes/meson-private" ] && _oft_wipe="--wipe"
  oft_build_meson $_oft_wipe -Denable_tests=false
  oft_build_harness "tests/libfuzzer/dav1d_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































build_lib() {
  local _oft_wipe=""
  [ -d "${BUILDDIR:?}/mes/meson-private" ] && _oft_wipe="--wipe"
  oft_build_meson $_oft_wipe -Denable_tests=false -Denable_asm=false
  oft_build_harness "tests/libfuzzer/dav1d_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build dav1d_fuzzer
)
