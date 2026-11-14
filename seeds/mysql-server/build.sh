#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of mysql-server into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cbor_load_fuzzer: the release's target mysql-server-cbor_load_fuzzer
(
ov_target_begin mysql-server-cbor_load_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "extra/libcbor/libcbor-0.11.0/oss-fuzz/cbor_load_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































OFT_BUILD_SUBDIR=extra/libcbor/libcbor-0.11.0










build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DCBOR_VERSION=0.11.0 -DCMAKE_POLICY_DEFAULT_CMP0048=NEW
  oft_build_harness "extra/libcbor/libcbor-0.11.0/oss-fuzz/cbor_load_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build cbor_load_fuzzer
)
