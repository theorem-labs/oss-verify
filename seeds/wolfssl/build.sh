#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wolfssl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# pem_cert: the release's target wolfssl-pem_cert
(
ov_target_begin wolfssl-pem_cert
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "differential.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""









































build_lib() {
  oft_build_cmake
  oft_build_harness "pem_cert.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build pem_cert
)
