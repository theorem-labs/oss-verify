#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of quickjs into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_regexp: the release's target quickjs-fuzz_regexp
(
ov_target_begin quickjs-fuzz_regexp
build_lib() {
  oft_build_blind
  oft_build_harness "fuzz/fuzz_regexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""














































































build_lib() {
  [ -s "$SRCDIR/VERSION" ] || { echo "oft: quickjs-fuzz_regexp pin: pinned tree has no VERSION file" >&2; return 1; }
  OFT_BLIND_CFLAGS="-D_GNU_SOURCE -DCONFIG_VERSION=\"$(cat "$SRCDIR/VERSION")\""
  OFT_BLIND_SKIP=1
  oft_build_blind || return 1
  OFT_BLIND_SKIP=0
  OFT_BLIND_CFLAGS=""
  read -r _blind_ok _blind_skipped _blind_n < "$BUILDDIR/blind-counts.txt" || return 1
  if [ "$_blind_skipped" != "1" ]; then
    echo "oft: quickjs-fuzz_regexp pin: expected exactly 1 skipped TU (the closefrom probe), got $_blind_skipped -- see blind-errors.txt" >&2
    return 1
  fi
  if ! grep -q 'compat/test-closefrom\.c' "$BUILDDIR/blind-errors.txt"; then
    echo "oft: quickjs-fuzz_regexp pin: the one skipped TU is not compat/test-closefrom.c -- see blind-errors.txt" >&2
    return 1
  fi
  oft_build_harness "fuzz/fuzz_regexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_regexp
)
