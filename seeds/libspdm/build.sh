#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libspdm into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_x509crt: the release's target libspdm-fuzz_x509crt
(
ov_target_begin libspdm-fuzz_x509crt
build_lib() {
  oft_build_cmake
  oft_build_harness "os_stub/mbedtlslib/mbedtls/programs/fuzz/fuzz_x509crt.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































build_lib() {
  OFT_HARNESS_CFLAGS="-I$BUILDDIR/src/os_stub/mbedtlslib/mbedtls/include -I$BUILDDIR/src/os_stub/mbedtlslib/include/mbedtls -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>"
  oft_build_cmake -DARCH=riscv64 -DTOOLCHAIN=NONE -DTARGET=Release -DCRYPTO=mbedtls -DDISABLE_TESTS=1









  find "${BUILDDIR:?}/src" -name '*.a' -type f -delete
  LIB_EXTRA=""
  oft_merge_archives
  oft_build_harness "os_stub/mbedtlslib/mbedtls/programs/fuzz/fuzz_x509crt.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_x509crt
)
