#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libressl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# asn1parse: the release's target libressl-driver
(
ov_target_begin libressl-driver
build_lib() {
  oft_build_cmake
  oft_build_harness "driver.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































AUX_REPOS="
src/openbsd https://github.com/libressl/openbsd 6b13eef79d2dc54c1b0203f967b3fc8b8971df78
"


































build_lib() {



  local SRCDIR="${SRCDIR:?}"
  if ! [ -f "$SRCDIR/ssl/VERSION" ]; then
    if ! [ -d "$SRCDIR/openbsd/src/lib/libcrypto" ]; then
      echo "oft: libressl: ext tree is a SKELETON (no ssl/VERSION) and has no pinned" >&2
      echo "  openbsd tree at src/openbsd to assemble it from -- AUX_REPOS in this pin" >&2
      echo "  declares it; re-fetch. Refusing to configure a tree with no sources." >&2
      return 1
    fi
    local asm="$BUILDDIR/libressl-assembled"
    rm -rf "${asm:?}"
    mkdir -p "$asm"
    cp -a "$SRCDIR/." "$asm/"
    ( cd "$asm" && LIBRESSL_OPENBSD_PINNED=1 sh ./update.sh ) > "$BUILDDIR/libressl-update.log" 2>&1 || {
      echo "oft: libressl: update.sh (pinned openbsd tree) failed; last lines of $BUILDDIR/libressl-update.log:" >&2
      tail -n 20 "$BUILDDIR/libressl-update.log" >&2
      return 1
    }
    [ -f "$asm/ssl/VERSION" ] || {
      echo "oft: libressl: update.sh exited 0 but wrote no ssl/VERSION" >&2
      return 1
    }
    echo "oft: libressl: assembled from the pinned openbsd tree ($(cat "$asm/ssl/VERSION") libssl)"
    SRCDIR="$asm"
  fi
  oft_build_cmake -DLIBRESSL_APPS=OFF -DLIBRESSL_TESTS=OFF
  OFT_COMPANION_SRCS="asn1parse.c"
  oft_build_harness "driver.c"
  "$CHOST-nm" "$BUILDDIR/lib/liboft.a" 2>/dev/null | grep -q ' T FuzzerTestOneInput$' || {
    echo "oft: libressl: archive defines no FuzzerTestOneInput -- the companion fuzzer" >&2
    echo "  TU (OFT_COMPANION_SRCS) did not make it into lib/liboft.a; driver.c alone" >&2
    echo "  is only an adapter and would fail at the final link." >&2
    return 1
  }
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build asn1parse
)
