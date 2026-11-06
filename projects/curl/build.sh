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

# curl_fuzzer_proto_file: curl-fuzzer de8de303d3e0's structured fuzz target of file:// transfers
# (curl_add_proto_fuzzer(curl_fuzzer_proto_file PROFILE fast_file), its CMakeLists.txt:2099), on curl-fuzz_fnmatch's
# pin, as curl-fuzzer builds it without a TLS backend (its MemorySanitizer build): a debug libcurl built with UNITTESTS,
# the zstd and nghttp2 contract shims and their wraps, and libprotobuf-mutator v1.5 with the protobuf v29.3 and abseil
# that v1.5 builds. libcurl links the sysroot's zlib, brotli, zstd and nghttp2, as the targets above do; curl-fuzzer
# builds its own, and libidn2 and OpenLDAP, which the toolchain image does not have. protoc runs on the build machine,
# so it is built for the host from the same protobuf, as curl-fuzzer's MemorySanitizer build does. pf_de8de30_lib
# follows de8de303d3e0's CMakeLists.txt:
# - libcurl gets its options that apply without TLS, CURL_USE_GSASL=OFF among them (CMakeLists.txt:512-514).
# - the message code is made as CMakeLists.txt:1652-1789 makes it: the annotated descriptor of schemas/curl_fuzzer.proto;
#   schema_eligibility.py for the profile `compatibility`, which also writes the runtime schema and the option manifest,
#   and for the target's own profile; protoc for the runtime schema and the profile's schema. schema_eligibility.py
#   needs Python's protobuf, which the image does not have: sources lays out the pure-Python wheel of protobuf 7.36.2,
#   the version curl-fuzzer's uv.lock pins.
# - the runtime is the object list of curl_fuzzer_proto_runtime (CMakeLists.txt:1837-1876, less its TLS sources, which
#   it compiles only with an OpenSSL target) and curl_fuzzer_proto_runner (:1908-1910); the target adds its profile's
#   message code (:1764) and its same-named entry point (:2006-2011). Every object is compiled with COMMON_FLAGS only
#   (:816); de8de303d3e0 gives no target a FUZZ_PROTOCOLS_* definition.
# pf_de8de30_lib <target directory> <profile> <entry point>, from build_lib.
pf_de8de30_lib() {
  F=/work/targets/$1
  pf_slug=$2
  pf_entry=$3
  PB=/work/ext/protobuf-29.3
  LPM=/work/ext/libprotobuf-mutator-1.5
  PYPB=/work/ext/python-protobuf-7.36.2
  P=$BUILDDIR/proto
  G=$P/gen/schema_eligibility
  # libcurl, with curl-fuzzer's options that apply without TLS, and UNITTESTS in its own compiles only
  CFLAGS="$CFLAGS -DUNITTESTS"
  oft_build_cmake -DCURL_USE_LIBPSL=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_MBEDTLS=OFF \
    -DENABLE_DEBUG=ON -DCMAKE_BUILD_TYPE=Debug -DCURL_DISABLE_INSTALL=ON -DCURL_HIDDEN_SYMBOLS=OFF \
    -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF \
    -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none -DCURL_DISABLE_TELNET=OFF -DCURL_DISABLE_FTP=OFF \
    -DCURL_DISABLE_TFTP=OFF -DCURL_DISABLE_GOPHER=OFF -DCURL_USE_GSASL=OFF \
    -DUSE_HTTPSRR=ON -DCURL_BROTLI=ON
  pf_kept=""; for pf_f in $CFLAGS; do [ "$pf_f" = -DUNITTESTS ] || pf_kept="$pf_kept $pf_f"; done; CFLAGS=${pf_kept# }
  rm -rf "$P"
  mkdir -p "$G/runtime" "$P/gen/schemas" "$P/obj" "$P/lpm/include/libprotobuf-mutator" "$P/lpm/lib"
  # protoc for the host, with the host's compiler and no flags (curl-fuzzer's host protoc build, less its install)
  env -u CC -u CXX -u CFLAGS -u CXXFLAGS cmake -S "$PB" -B "$P/host" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS= -DCMAKE_CXX_FLAGS= \
    -DCMAKE_EXE_LINKER_FLAGS= -DCMAKE_CXX_STANDARD=14 -Dprotobuf_INSTALL=OFF -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_CONFORMANCE=OFF -Dprotobuf_BUILD_EXAMPLES=OFF -Dprotobuf_BUILD_LIBUPB=OFF \
    -Dprotobuf_BUILD_SHARED_LIBS=OFF -Dprotobuf_WITH_ZLIB=OFF
  env -u CC -u CXX -u CFLAGS -u CXXFLAGS cmake --build "$P/host" --target protoc -j "$(oft_jobs)"
  # protobuf and abseil for the target, as libprotobuf-mutator v1.5 builds them (cmake/external/protobuf.cmake): C++14,
  # Release, the build's flags with -fsanitize-coverage=0 -w -pthread, without position-independent code (a static
  # program), protoc, or zlib, which the fuzz target does not use. Installed, so that abseil's options.h is the one
  # its install rewrites for the C++14 ABI the libraries were compiled with.
  ( CFLAGS="$CFLAGS -fsanitize-coverage=0 -w -pthread"; oft_cmake_toolchain "$P/pb-toolchain.cmake" )
  cmake -S "$PB" -B "$P/pb-build" -G Ninja -DCMAKE_TOOLCHAIN_FILE="$P/pb-toolchain.cmake" \
    -DCMAKE_INSTALL_PREFIX="$P/pb" -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_STANDARD=14 \
    -Dprotobuf_BUILD_LIBUPB=OFF -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_PROTOC_BINARIES=OFF \
    -Dprotobuf_WITH_ZLIB=OFF
  cmake --build "$P/pb-build" -j "$(oft_jobs)"
  cmake --install "$P/pb-build" > "$P/pb-install.log"
  # libprotobuf-mutator v1.5: its two libraries, with the flags its CMakeLists gives them (by hand: with
  # LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF its CMake would fetch protobuf), and its installed headers
  pf_lpm="-fno-exceptions -Wall -Wstring-conversion -O3 -DNDEBUG -fsanitize-coverage=0 -I$LPM -I$P/pb/include"
  for pf_s in binary_format mutator text_format utf8_fix libfuzzer/libfuzzer_mutator libfuzzer/libfuzzer_macro; do
    "$CXX" $CFLAGS $pf_lpm -c "$LPM/src/$pf_s.cc" -o "$P/lpm/${pf_s#libfuzzer/}.o"
  done
  "$CHOST-ar" rcs "$P/lpm/lib/libprotobuf-mutator.a" "$P/lpm/binary_format.o" "$P/lpm/mutator.o" \
    "$P/lpm/text_format.o" "$P/lpm/utf8_fix.o"
  "$CHOST-ar" rcs "$P/lpm/lib/libprotobuf-mutator-libfuzzer.a" "$P/lpm/libfuzzer_mutator.o" "$P/lpm/libfuzzer_macro.o"
  for pf_h in $(cd "$LPM" && find port src -name '*.h' | LC_ALL=C sort); do
    mkdir -p "$P/lpm/include/libprotobuf-mutator/${pf_h%/*}"
    cp "$LPM/$pf_h" "$P/lpm/include/libprotobuf-mutator/$pf_h"
  done
  # the message code (CMakeLists.txt:1652-1789): the annotated descriptor, the profiles checked against this curl.h,
  # the runtime schema's code and the profile's
  "$P/host/protoc" --proto_path="$F/schemas" --proto_path="$PB/src" --include_imports --include_source_info \
    --descriptor_set_out="$G/annotated.desc" "$F/schemas/curl_fuzzer.proto"
  for pf_p in compatibility $pf_slug; do
    pf_r=$G/profiles/$pf_p
    [ ! -e "$pf_r/$pf_p.desc" ] || continue
    mkdir -p "$pf_r"
    pf_global=""
    [ "$pf_p" != compatibility ] || pf_global="--authoring-descriptor-out $G/authoring.desc \
      --authoring-schema-out-dir $P/gen/schemas --runtime-descriptor-out $G/runtime/runtime.desc \
      --runtime-schema-out-dir $G/runtime --native-manifest-out $P/gen/curl_fuzzer_option_manifest.inc"
    # shellcheck disable=SC2086 # the global outputs, made by the profile compatibility only
    PYTHONPATH="$F/src:$PYPB" python3 "$F/src/curl_fuzzer_tools/schema_eligibility.py" \
      --descriptor-set "$G/annotated.desc" --curl-header "$SRCDIR/include/curl/curl.h" \
      --target-profile-header "$F/proto_fuzzer/target_profile.h" --profile "$pf_p" \
      --projected-descriptor-out "$pf_r/$pf_p.desc" --report-out "$pf_r/$pf_p.json" --schema-out-dir "$pf_r" \
      --adapter-out "$pf_r/generated/$pf_p/${pf_p}_traits.h" $pf_global
  done
  pf_prof=$G/profiles/$pf_slug
  "$P/host/protoc" --descriptor_set_in="$pf_prof/$pf_slug.desc" --cpp_out="$pf_prof" \
    "generated/$pf_slug/$pf_slug.proto"
  "$P/host/protoc" --descriptor_set_in="$G/runtime/runtime.desc" --cpp_out="$P/gen" curl_fuzzer.proto
  # the structured runtime and runner (their sources without a TLS backend), the runtime message code, the profile's
  # message code and the contract shims, compiled as curl-fuzzer compiles them, in parallel; archived with libcurl, in
  # this order, as the release links one archive that holds the library and the harness
  pf_inc="-I$SRCDIR/include -I$P/gen -I$F -I$P/lpm/include -I$P/lpm/include/libprotobuf-mutator -I$P/pb/include"
  pf_objs=""; pf_pids=""
  for pf_s in proto_fuzzer/allocation_fault_injection proto_fuzzer/api_lifecycle proto_fuzzer/curl_global_lifecycle \
      proto_fuzzer/dict_mock_server proto_fuzzer/fuzzer_main proto_fuzzer/ftp_mock_server \
      proto_fuzzer/gopher_mock_server proto_fuzzer/h2_cleartext_mock_server proto_fuzzer/h2_plan \
      proto_fuzzer/happy_eyeballs_mock_server proto_fuzzer/h2_runtime proto_fuzzer/http_transport_mock_server \
      proto_fuzzer/imap_mock_server proto_fuzzer/ipfs_url proto_fuzzer/ldap_mock_server proto_fuzzer/option_apply \
      proto_fuzzer/option_model proto_fuzzer/pingpong_mock_server proto_fuzzer/pop3_mock_server \
      proto_fuzzer/proxy_option_mock_server proto_fuzzer/request_data proto_fuzzer/rtsp_mock_server \
      proto_fuzzer/socks4_mock_server proto_fuzzer/smtp_mock_server proto_fuzzer/mock_server \
      proto_fuzzer/mock_server_base proto_fuzzer/mqtt_mock_server proto_fuzzer/multi_socket_driver \
      proto_fuzzer/multi_transfer_runner proto_fuzzer/transfer_session proto_fuzzer/target_policy \
      proto_fuzzer/telnet_mock_server proto_fuzzer/telnet_scenario proto_fuzzer/tftp_mock_server \
      proto_fuzzer/websocket_mock_server proto_fuzzer/ws_frame gen/curl_fuzzer.pb \
      proto_fuzzer/bounded_anonymous_input_file proto_fuzzer/scenario_runner "profile/$pf_slug.pb" \
      zstd_contract_shim nghttp2_contract_shim; do
    case "$pf_s" in
      gen/*) pf_src=$P/$pf_s.cc; pf_i=$pf_inc ;;
      profile/*) pf_src=$pf_prof/generated/$pf_slug/$pf_slug.pb.cc; pf_i="-I$pf_prof -I$P/pb/include" ;;
      *) pf_src=$F/$pf_s.cc; pf_i=$pf_inc ;;
    esac
    pf_o=$P/obj/${pf_s##*/}.o
    "$CXX" $CFLAGS -g -DCURL_DISABLE_DEPRECATION $pf_i -c "$pf_src" -o "$pf_o" &
    pf_pids="$pf_pids $!"; pf_objs="$pf_objs $pf_o"
  done
  for pf_p in $pf_pids; do wait "$pf_p"; done
  # shellcheck disable=SC2086 # the object list
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" $pf_objs
  # the same-named entry point is the harness; it reads its profile's traits
  OFT_CXX_STD=-std=gnu++17
  OFT_HARNESS_CFLAGS="-DCURL_DISABLE_DEPRECATION $pf_inc -I$pf_prof"
  oft_build_harness "$pf_entry"
  # the link: curl-fuzzer's response file (every archive of libprotobuf-mutator and its protobuf, sorted, in one
  # group), the shims' wraps (cmake/ZstdContractApis.cmake, cmake/Nghttp2ContractApis.cmake), and the sysroot's
  # libraries less its protobuf 3.21, so that no object of that other protobuf can be linked
  pf_link="-Wl,--start-group"
  for pf_a in $(find "$P/lpm/lib" "$P/pb/lib" -name '*.a' | LC_ALL=C sort); do pf_link="$pf_link $pf_a"; done
  pf_link="$pf_link -Wl,--end-group"
  for pf_w in ZSTD_createDCtx ZSTD_createDCtx_advanced ZSTD_createDStream ZSTD_createDStream_advanced ZSTD_freeDCtx \
      ZSTD_freeDStream ZSTD_initDStream ZSTD_DCtx_reset ZSTD_decompressStream nghttp2_session_client_new3 \
      nghttp2_session_del nghttp2_session_check_request_allowed nghttp2_session_consume \
      nghttp2_session_get_local_window_size nghttp2_session_get_remote_settings \
      nghttp2_session_get_remote_window_size nghttp2_session_get_stream_effective_local_window_size \
      nghttp2_session_get_stream_effective_recv_data_length nghttp2_session_get_stream_remote_window_size \
      nghttp2_session_get_stream_user_data nghttp2_session_mem_recv nghttp2_session_resume_data nghttp2_session_send \
      nghttp2_session_set_local_window_size nghttp2_session_set_stream_user_data nghttp2_session_upgrade2 \
      nghttp2_session_want_read nghttp2_session_want_write nghttp2_submit_goaway nghttp2_submit_ping \
      nghttp2_submit_priority nghttp2_submit_request nghttp2_submit_rst_stream nghttp2_submit_settings \
      nghttp2_submit_window_update; do
    pf_link="$pf_link -Wl,--wrap=$pf_w"
  done
  for pf_a in $LIB_EXTRA; do
    case "$pf_a" in */libprotobuf.a|*/libprotobuf-lite.a) ;; *) pf_link="$pf_link $pf_a" ;; esac
  done
  LIB_EXTRA=$pf_link
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}

(
ov_target_begin curl-fuzz_proto_file
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_de8de30_lib curl-fuzz_proto_file fast_file fuzzer_entrypoints/curl_fuzzer_proto_file.cc
}
ov_target_build curl_fuzzer_proto_file
)
