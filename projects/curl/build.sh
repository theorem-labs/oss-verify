#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the fuzz targets after fuzz_fnmatch, which are not of the release, and fuzz_bufq's
# harness patch (sources).
#
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release.
#
# Builds the fuzz targets of curl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_bufq: the release's target curl-fuzz_bufq, its harness patched by curl-fuzz_bufq.0001-no-syscalls.patch (sources)
(
ov_target_begin curl-fuzz_bufq
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz_bufq.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DCURL_USE_LIBPSL=OFF
  OFT_HARNESS_CFLAGS="-DHAVE_CONFIG_H -I$BUILDDIR/cmk/lib"
  oft_build_harness "fuzz_bufq.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_bufq
)

# fuzz_fnmatch: the release's target curl-fuzz_fnmatch
(
ov_target_begin curl-fuzz_fnmatch
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz_fnmatch.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DCURL_USE_LIBPSL=OFF
  oft_build_harness "fuzz_fnmatch.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_fnmatch
)

# Not of the release: the targets below are built with TLS off (-DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_MBEDTLS=OFF), so their binaries hold no TLS
# code; fuzz_bufq and fuzz_fnmatch above keep the release's build: they reach no TLS code, so the link keeps none.

# fuzz_url: curl-fuzzer de8de303d3e0's harness, unchanged, on curl-fuzz_fnmatch's pin
(
ov_target_begin curl-fuzz_url
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DCURL_USE_LIBPSL=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_MBEDTLS=OFF
  OFT_HARNESS_CFLAGS="-DHAVE_CONFIG_H -I$BUILDDIR/cmk/lib -I$SRCDIR/lib -I$SRCDIR/include -I/work/targets/curl-fuzz_url"
  oft_build_harness "fuzz_url.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_url
)

# fuzz_doh: curl-fuzzer de8de303d3e0's harness, on curl-fuzz_fnmatch's pin, with a debug libcurl built with UNITTESTS,
# as curl-fuzzer builds it
(
ov_target_begin curl-fuzz_doh
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  CFLAGS="$CFLAGS -DUNITTESTS"; CXXFLAGS="${CXXFLAGS:-} -DUNITTESTS"
  oft_build_cmake -DCURL_USE_LIBPSL=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_MBEDTLS=OFF -DENABLE_DEBUG=ON -DCMAKE_BUILD_TYPE=Debug -DUSE_HTTPSRR=ON
  OFT_HARNESS_CFLAGS="-DHAVE_CONFIG_H -I$BUILDDIR/cmk/lib -I$SRCDIR/lib -I$SRCDIR/include -I/work/targets/curl-fuzz_doh"
  oft_build_harness "fuzz_doh.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_doh
)

# fuzz_netrc: curl-fuzzer de8de303d3e0's harness and the input-file helper it includes, on curl-fuzz_fnmatch's pin,
# with a debug libcurl built with UNITTESTS, as curl-fuzzer builds it
(
ov_target_begin curl-fuzz_netrc
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  CFLAGS="$CFLAGS -DUNITTESTS"; CXXFLAGS="${CXXFLAGS:-} -DUNITTESTS"
  oft_build_cmake -DCURL_USE_LIBPSL=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_MBEDTLS=OFF -DENABLE_DEBUG=ON -DCMAKE_BUILD_TYPE=Debug
  "$CC" $CFLAGS -x c++ -stdlib=libc++ -std=c++17 -DBUILDING_LIBCURL -DDEBUGBUILD -DHAVE_CONFIG_H -I/work/targets/curl-fuzz_netrc -c /work/targets/curl-fuzz_netrc/proto_fuzzer/bounded_anonymous_input_file.cc -o "$BUILDDIR/baif.o" && "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/baif.o"
  OFT_HARNESS_CFLAGS="-DHAVE_CONFIG_H -DBUILDING_LIBCURL -DDEBUGBUILD -DUNITTESTS -I$BUILDDIR/cmk/lib -I$SRCDIR/lib -I$SRCDIR/include -I/work/targets/curl-fuzz_netrc"
  oft_build_harness "fuzz_netrc.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_netrc
)
