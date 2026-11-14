#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of dnsmasq into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_util: the release's target dnsmasq-fuzz_util
(
ov_target_begin dnsmasq-fuzz_util
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzz_util.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































































build_lib() {
  oft_require_target_cxx

  export OFT_BLIND_CFLAGS='-DVERSION="UNKNOWN"'
  oft_build_blind


  sed -i 's/class/class2/g; s/new/new2/g' "$BUILDDIR/src/src/dnsmasq.h"

  (
    set -e
    cd "$BUILDDIR/lib"
    llvm-ar x liboft.a src_dnsmasq.o
    llvm-objcopy --redefine-sym main=oft_dnsmasq_main_renamed src_dnsmasq.o
    llvm-ar r liboft.a src_dnsmasq.o
    rm -f src_dnsmasq.o
  )
  oft_build_harness "fuzz_util.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_util
)
