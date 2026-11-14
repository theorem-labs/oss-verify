#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libsoup into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_content_sniffer: the release's target libsoup-fuzz_content_sniffer
(
ov_target_begin libsoup-fuzz_content_sniffer
build_lib() {
  oft_build_meson
  oft_build_harness "fuzzing/fuzz_content_sniffer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































build_lib() {
  oft_build_meson -Dtls_check=false -Dtests=false -Ddocs=disabled -Dintrospection=disabled -Dvapi=disabled -Dsysprof=disabled
  OFT_HARNESS_CFLAGS="-I${OFT_SYSROOT:-/opt/musl-sysroot}/usr/include/glib-2.0 -I${OFT_SYSROOT:-/opt/musl-sysroot}/usr/lib/glib-2.0/include"
  oft_build_harness "fuzzing/fuzz_content_sniffer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_content_sniffer
)
