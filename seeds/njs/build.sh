#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of njs into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# njs_process_script_fuzzer: the release's target njs-njs_shell
(
ov_target_begin njs-njs_shell
build_lib() {
  oft_build_autotools
  oft_build_harness "external/njs_shell.c" -DNJS_FUZZER_TARGET
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



























































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CFLAGS="$CFLAGS" AR="$CHOST-ar" \
       ./configure --cc="$CC" --ar="$CHOST-ar" \
         --no-openssl --no-libxml2 --no-zlib --no-quickjs \
    && oft_make_then_keep_going build/libnjs.a )



  [ -f "$BUILDDIR/src/build/libnjs.a" ] || {
    echo "oft: njs configure/make left no build/libnjs.a" >&2; return 1; }
  oft_merge_archives
  oft_build_harness "external/njs_shell.c" -DNJS_FUZZER_TARGET \
    "-I$BUILDDIR/src/build" "-I$BUILDDIR/src/src" "-I$BUILDDIR/src/external"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build njs_process_script_fuzzer
)
