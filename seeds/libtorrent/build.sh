#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libtorrent into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# bdecode_node: the release's target libtorrent
(
ov_target_begin libtorrent
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzers/src/bdecode_node.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








OFT_HARNESS_CFLAGS="-DTORRENT_ABI_VERSION=2 -DTORRENT_SSL_PEERS -DTORRENT_USE_LIBCRYPTO -DTORRENT_USE_OPENSSL -DBOOST_ASIO_HAS_STD_CHRONO -DBOOST_ASIO_NO_DEPRECATED -DBOOST_EXCEPTION_DISABLE -DBOOST_JSON_HEADER_ONLY -DBOOST_SYSTEM_USE_UTF8 -D_FILE_OFFSET_BITS=64"
build_lib() {
  oft_require_target_cxx
  oft_build_cmake 
  oft_build_harness "fuzzers/src/bdecode_node.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build bdecode_node
)
