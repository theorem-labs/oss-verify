#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of p11-kit into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# conf_fuzzer: the release's target p11-kit-conf_fuzzer
(
ov_target_begin p11-kit-conf_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/conf_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























build_lib() {
  oft_build_autotools --without-libffi --without-libtasn1 --without-trust-paths --disable-nls
  oft_build_harness "fuzz/conf_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build conf_fuzzer
)
