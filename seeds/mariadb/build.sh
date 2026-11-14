#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of mariadb into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_json: the release's target mariadb
(
ov_target_begin mariadb
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz_json.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DCMAKE_CROSSCOMPILING_EMULATOR=/usr/bin/env -DWITHOUT_SERVER=ON -DWITH_UNIT_TESTS=ON










  OFT_HARNESS_CFLAGS="-include $BUILDDIR/src/unittest/mytap/tap.h"










  oft_build_harness "fuzz_json_mdev32854.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_json
)
