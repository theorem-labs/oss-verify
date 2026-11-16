#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of brunsli into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_decode: the release's target brunsli-fuzz_decode
(
ov_target_begin brunsli-fuzz_decode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "c/tests/fuzz_decode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































oft_brunsli_unforce_brotli_package() {
  local cml="$SRCDIR/CMakeLists.txt" bcm="$SRCDIR/brunsli.cmake"
  if ! grep -q 'set(BROTLI_BUILD_FOR_PACKAGE OFF CACHE INTERNAL "")' "$cml"; then
    grep -q 'set(BROTLI_BUILD_FOR_PACKAGE ON CACHE INTERNAL "")' "$cml" || {
      echo "oft: brunsli CMakeLists.txt has neither the ON line this fix flips nor the OFF result -- upstream moved the anchor" >&2
      return 1; }
    sed -i 's/set(BROTLI_BUILD_FOR_PACKAGE ON CACHE INTERNAL "")/set(BROTLI_BUILD_FOR_PACKAGE OFF CACHE INTERNAL "")/' "$cml" || return 1
  fi
  if grep -q 'brotli[a-z]*-static' "$bcm"; then
    sed -i -e 's/brotlidec-static brotlicommon-static/brotlidec brotlicommon/' \
           -e 's/brotlienc-static brotlicommon-static/brotlienc brotlicommon/' "$bcm" || return 1
  fi


  grep -q 'set(BROTLI_BUILD_FOR_PACKAGE OFF CACHE INTERNAL "")' "$cml" || {
    echo "oft: BROTLI_BUILD_FOR_PACKAGE flip is not present in $cml" >&2; return 1; }
  if grep -q 'brotli[a-z]*-static' "$bcm"; then
    echo "oft: a brotli*-static link name survived in $bcm" >&2; return 1
  fi
}














OFT_HARNESS_CFLAGS='-DTEST_DATA_PATH="/nonexistent-brunsli-testdata"'

















































































oft_brunsli_require_vendor() {
  local v="$SRCDIR/oft-vendor" n
  [ -f "$v/SHA256SUMS" ] || { echo "oft: $v/SHA256SUMS missing -- the vendored gtest/brotli trees did not ship" >&2; return 1; }
  [ -f "$v/gtest/CMakeLists.txt" ] || { echo "oft: $v/gtest/CMakeLists.txt missing" >&2; return 1; }
  [ -f "$v/brotli/CMakeLists.txt" ] || { echo "oft: $v/brotli/CMakeLists.txt missing" >&2; return 1; }
  n=$(grep -c . "$v/SHA256SUMS")
  [ "$n" -ge 400 ] || { echo "oft: $v/SHA256SUMS has only $n lines; expected 414" >&2; return 1; }
  ( cd "$v" && sha256sum --quiet -c SHA256SUMS ) || {
    echo "oft: vendored gtest/brotli tree differs from oft-vendor/SHA256SUMS" >&2; return 1; }
}



build_lib() {
  oft_require_target_cxx
  oft_brunsli_unforce_brotli_package
  oft_brunsli_require_vendor
  CFLAGS="$CFLAGS -DBRUNSLI_DISABLE_LOG"; export CFLAGS
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_GTEST="$BUILDDIR/src/oft-vendor/gtest" \
    -DFETCHCONTENT_SOURCE_DIR_BROTLI="$BUILDDIR/src/oft-vendor/brotli"
  oft_build_harness "c/tests/fuzz_decode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}


























VENDOR_TREES="
oft-vendor/gtest sha256:745c55415660044610f7fcd3af7a6420d5de16a7dbb9ebfe2e131275676232be https://github.com/google/googletest/archive/52eb8108c5bdec04579160ae17225d66034bd723.tar.gz 1 !.github,!.gitattributes
oft-vendor/brotli sha256:0afe09a53c8bad9861c8dd1fc1284308d54f19d2979ba3541cfdcc9b05fe360f https://github.com/google/brotli/archive/028fb5a23661f123017c060daa546b55cf4bde29.tar.gz 1 !.github,!.gitattributes
"
ov_target_build fuzz_decode
)

# fuzz_decode_streaming: the release's target brunsli-fuzz_decode_streaming
(
ov_target_begin brunsli-fuzz_decode_streaming
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "c/tests/fuzz_decode_streaming.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































oft_brunsli_unforce_brotli_package() {
  local cml="$SRCDIR/CMakeLists.txt" bcm="$SRCDIR/brunsli.cmake"
  if ! grep -q 'set(BROTLI_BUILD_FOR_PACKAGE OFF CACHE INTERNAL "")' "$cml"; then
    grep -q 'set(BROTLI_BUILD_FOR_PACKAGE ON CACHE INTERNAL "")' "$cml" || {
      echo "oft: brunsli CMakeLists.txt has neither the ON line this fix flips nor the OFF result -- upstream moved the anchor" >&2
      return 1; }
    sed -i 's/set(BROTLI_BUILD_FOR_PACKAGE ON CACHE INTERNAL "")/set(BROTLI_BUILD_FOR_PACKAGE OFF CACHE INTERNAL "")/' "$cml" || return 1
  fi
  if grep -q 'brotli[a-z]*-static' "$bcm"; then
    sed -i -e 's/brotlidec-static brotlicommon-static/brotlidec brotlicommon/' \
           -e 's/brotlienc-static brotlicommon-static/brotlienc brotlicommon/' "$bcm" || return 1
  fi


  grep -q 'set(BROTLI_BUILD_FOR_PACKAGE OFF CACHE INTERNAL "")' "$cml" || {
    echo "oft: BROTLI_BUILD_FOR_PACKAGE flip is not present in $cml" >&2; return 1; }
  if grep -q 'brotli[a-z]*-static' "$bcm"; then
    echo "oft: a brotli*-static link name survived in $bcm" >&2; return 1
  fi
}














OFT_HARNESS_CFLAGS='-DTEST_DATA_PATH="/nonexistent-brunsli-testdata"'

















































































oft_brunsli_require_vendor() {
  local v="$SRCDIR/oft-vendor" n
  [ -f "$v/SHA256SUMS" ] || { echo "oft: $v/SHA256SUMS missing -- the vendored gtest/brotli trees did not ship" >&2; return 1; }
  [ -f "$v/gtest/CMakeLists.txt" ] || { echo "oft: $v/gtest/CMakeLists.txt missing" >&2; return 1; }
  [ -f "$v/brotli/CMakeLists.txt" ] || { echo "oft: $v/brotli/CMakeLists.txt missing" >&2; return 1; }
  n=$(grep -c . "$v/SHA256SUMS")
  [ "$n" -ge 400 ] || { echo "oft: $v/SHA256SUMS has only $n lines; expected 414" >&2; return 1; }
  ( cd "$v" && sha256sum --quiet -c SHA256SUMS ) || {
    echo "oft: vendored gtest/brotli tree differs from oft-vendor/SHA256SUMS" >&2; return 1; }
}



build_lib() {
  oft_require_target_cxx
  oft_brunsli_unforce_brotli_package
  oft_brunsli_require_vendor
  CFLAGS="$CFLAGS -DBRUNSLI_DISABLE_LOG"; export CFLAGS
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_GTEST="$BUILDDIR/src/oft-vendor/gtest" \
    -DFETCHCONTENT_SOURCE_DIR_BROTLI="$BUILDDIR/src/oft-vendor/brotli"
  oft_build_harness "c/tests/fuzz_decode_streaming.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}


























VENDOR_TREES="
oft-vendor/gtest sha256:745c55415660044610f7fcd3af7a6420d5de16a7dbb9ebfe2e131275676232be https://github.com/google/googletest/archive/52eb8108c5bdec04579160ae17225d66034bd723.tar.gz 1 !.github,!.gitattributes
oft-vendor/brotli sha256:0afe09a53c8bad9861c8dd1fc1284308d54f19d2979ba3541cfdcc9b05fe360f https://github.com/google/brotli/archive/028fb5a23661f123017c060daa546b55cf4bde29.tar.gz 1 !.github,!.gitattributes
"
ov_target_build fuzz_decode_streaming
)
