#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of yoga into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_layout: the release's target yoga-FuzzLayout
(
ov_target_begin yoga-FuzzLayout
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/FuzzLayout.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















































oft_yoga_vendored_googletest() {
  local d="$SRCDIR/oft-vendor/googletest"
  if ! { [ -f "$d/CMakeLists.txt" ] && [ -d "$d/googletest" ] && [ -d "$d/googlemock" ]; }; then
    echo "oft: vendored googletest missing at $d (expected the release-1.12.1 tree the pin vendors)" >&2
    return 1
  fi
  printf '%s' "$d"
}



build_lib() {
  oft_require_target_cxx
  local gtest_src
  gtest_src="$(oft_yoga_vendored_googletest)" || return 1
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="$gtest_src"
  oft_build_harness "fuzz/FuzzLayout.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/googletest sha256:81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2 https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz 1
"
ov_target_build fuzz_layout
)
