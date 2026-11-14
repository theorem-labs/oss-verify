#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of mdbtools into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_mdb: the release's target mdbtools-fuzz_mdb
(
ov_target_begin mdbtools-fuzz_mdb
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_mdb.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































build_lib() {
  oft_build_autotools --disable-man

  oft_build_harness "src/fuzz/fuzz_mdb.c" -include stdint.h $(pkg-config --cflags glib-2.0)
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_mdb
)
