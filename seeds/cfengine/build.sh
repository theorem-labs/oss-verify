#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of cfengine into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# string_fuzzer: the release's target cfengine-string_fuzzer
(
ov_target_begin cfengine-string_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "string_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































oft_build_string_expressions_tu() {
  local src="$BUILDDIR/src" obj="$BUILDDIR/strexp"
  mkdir -p "$obj"





  sed -f "$src/libpromises/enterprise_extension.sed" \
      "$src/libpromises/extensions_template.h.pre" \
      > "$obj/enterprise_extension.h" \
    || { echo "oft: enterprise_extension.h did not generate" >&2; return 1; }



  "$CC" $CFLAGS -DHAVE_CONFIG_H \
    -I"$src/libntech" \
    -I"$src/libntech/libutils" \
    -I"$src/libntech/libcompat" \
    -I"$src/libpromises" \
    -I"$src/libcfnet" \
    -I"$obj" \
    -c "$src/libpromises/string_expressions.c" \
    -o "$obj/string_expressions.o" \
    || { echo "oft: string_expressions.c did not compile" >&2; return 1; }
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$obj/string_expressions.o" \
    || { echo "oft: could not archive string_expressions.o" >&2; return 1; }
}
build_lib() {
  OFT_BUILD_SUBDIR=libntech
  oft_build_autotools
  OFT_BUILD_SUBDIR=
  oft_build_string_expressions_tu
  oft_build_harness "string_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build string_fuzzer
)
