#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of gdk-pixbuf into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# pixbuf_cons_fuzzer: the release's target gdk-pixbuf-pixbuf_cons_fuzzer
(
ov_target_begin gdk-pixbuf-pixbuf_cons_fuzzer
build_lib() {
  oft_build_meson
  oft_build_harness "pixbuf_cons_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













OFT_HARNESS_CFLAGS="-I${OFT_SYSROOT:-/opt/musl-sysroot}/usr/include/glib-2.0 -I${OFT_SYSROOT:-/opt/musl-sysroot}/usr/lib/glib-2.0/include"
ov_target_build pixbuf_cons_fuzzer
)
