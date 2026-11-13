#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of cxxopts into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cxxopts_fuzz_test: the release's target cxxopts-fuzz
(
ov_target_begin cxxopts-fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzz.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



























build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "test/fuzz.cpp"














  local m
  for m in $("$CHOST-ar" t "$BUILDDIR/lib/liboft.a" | grep "^oftsib-" || :); do
    "$CHOST-ar" d "$BUILDDIR/lib/liboft.a" "$m"
    echo "oft: cxxopts: dropped sibling member $m (Catch test, not scaffolding)"
  done
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build cxxopts_fuzz_test
)
