#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of stb into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# stbi_read_fuzzer: the release's target stb-stbi_read_fuzzer
(
ov_target_begin stb-stbi_read_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "tests/stbi_read_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""































































build_lib() {
  oft_build_header_only || return 1
  oft_build_harness "tests/stbi_read_fuzzer.c" || return 1
  local oft_sibm
  for oft_sibm in $("$CHOST-ar" t "$BUILDDIR/lib/liboft.a" | grep '^oftsib-'); do
    "$CHOST-ar" d "$BUILDDIR/lib/liboft.a" "$oft_sibm" || return 1
    echo "oft: stb: dropped swept tests/ sibling $oft_sibm from lib/liboft.a"
  done
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build stbi_read_fuzzer
)
