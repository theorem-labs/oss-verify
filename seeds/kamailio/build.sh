#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of kamailio into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_basex: the release's target kamailio-fuzz_basex
(
ov_target_begin kamailio-fuzz_basex
build_lib() {
  oft_build_cmake
  oft_build_harness "misc/fuzz/fuzz_basex.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""















































build_lib() {
  oft_build_cmake

  (
    set -e
    cd "$BUILDDIR/lib"
    llvm-ar x liboft.a main.c.o
    llvm-objcopy --redefine-sym main=ksr_main_renamed_oft main.c.o
    llvm-ar r liboft.a main.c.o
    rm -f main.c.o
  )
  oft_build_harness "misc/fuzz/fuzz_basex.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_basex
)
