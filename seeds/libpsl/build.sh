#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libpsl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libpsl_load_fuzzer: the release's target libpsl-libpsl_load_fuzzer
(
ov_target_begin libpsl-libpsl_load_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libpsl_load_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




































































































































export SOURCE_DATE_EPOCH=1756684800

















oft_libpsl_require_list() {
  local l="$SRCDIR/list" m="/work/targets/${T:?}/list.sha256" n have
  [ -f "$l/public_suffix_list.dat" ] || { echo "oft: $l/public_suffix_list.dat missing -- the vendored publicsuffix/list tree did not ship" >&2; return 1; }
  [ -f "$m" ] || { echo "oft: $m missing" >&2; return 1; }
  n=$(grep -c . "$m")
  [ "$n" -eq 80 ] || { echo "oft: $m has $n lines; expected 80" >&2; return 1; }
  ( cd "$l" && sha256sum --quiet -c "$m" ) || { echo "oft: list/ differs from its manifest $m" >&2; return 1; }
  have=$(sha256sum "$l/public_suffix_list.dat" | cut -d' ' -f1)
  [ "$have" = "fe6adc7fb8014f57d28d69b18d0aa3e581efb432544922e12131a5d4a87bd954" ] \
    || { echo "oft: list/public_suffix_list.dat is $have, not the pinned e1b8015c gitlink content" >&2; return 1; }
  echo "oft: vendored list/ verified (80 files, public_suffix_list.dat fe6adc7f...)"
}
build_lib() {
  oft_libpsl_require_list
  oft_build_autotools --disable-runtime
  oft_build_harness "fuzz/libpsl_load_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libpsl_load_fuzzer
)
