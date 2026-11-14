#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ntpsec into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# FuzzClient: the release's target ntpsec-FuzzClient
(
ov_target_begin ntpsec-FuzzClient
build_lib() {
  oft_build_blind
  oft_build_harness "FuzzClient.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


























































build_lib() {
  oft_copy_src
  local S="$BUILDDIR/src"
  ( cd "$S" && rm -rf build \
    && env CC=clang CXX=clang++ CFLAGS= LDFLAGS= python3 ./waf configure \
         --cross-compiler="$CC" \
         --cross-cflags="$CFLAGS" \
         --cross-ldflags="$CFLAGS" \
         --enable-debug \
    && env CC=clang CXX=clang++ python3 ./waf build --notests -j"$(oft_jobs)" ) \
    || { echo "oft: ntpsec waf cross-build failed" >&2; return 1; }
  local ntpd="$S/build/main/ntpd/libntpd_lib.a"
  local ntp="$S/build/main/libntp/libntp.a"
  local aes="$S/build/main/libaes_siv/libaes_siv.a"
  local sslroot="${OFT_SYSROOT:-/opt/musl-sysroot}/usr/lib"
  local a
  for a in "$ntpd" "$ntp" "$aes" "$sslroot/libssl.a" "$sslroot/libcrypto.a"; do
    [ -f "$a" ] || { echo "oft: expected archive missing: $a" >&2; return 1; }
  done





  local ninc="-I$S/include -I$S/ntpd -I$S/build -I$S/tests/unity -I$S/tests/common"

  "$CC" $CFLAGS $ninc -c "/work/targets/$T/setup.c" -o "$BUILDDIR/setup.o" \
    || { echo "oft: setup.c failed to compile" >&2; return 1; }








  mkdir -p "$BUILDDIR/lib"
  rm -f "$BUILDDIR/lib/liboft.a"
  echo 'const char oft_ntpsec_marker = 0;' > "$BUILDDIR/header-only-stub.c"

  "$CC" $CFLAGS -c "$BUILDDIR/header-only-stub.c" -o "$BUILDDIR/header-only-stub.o" || return 1
  "$CHOST-ar" crs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/header-only-stub.o" || return 1
  OFT_HARNESS_CFLAGS="$ninc" oft_build_harness "FuzzClient.c"


  LIB_EXTRA="$BUILDDIR/setup.o -Wl,--start-group $ntpd $ntp $aes -Wl,--end-group $sslroot/libssl.a $sslroot/libcrypto.a"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzClient
)
