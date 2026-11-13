#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of geos into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_geo2: the release's target geos
(
ov_target_begin geos
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_geo2.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""














GIT_MIRRORS="https://github.com/libgeos/geos"
ov_target_build fuzz_geo2
)
