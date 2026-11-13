#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the fuzz targets after fuzz_fnmatch, which are not of the release (among them the
# structured fuzz targets and the stack they share, curl-fuzz_proto_lib), and fuzz_bufq's harness patches (sources).
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

# Not of the release: the structured fuzz targets of curl-fuzzer de8de303d3e0 (curl_add_proto_fuzzer, its
# CMakeLists.txt:1973-2049), on curl-fuzz_fnmatch's pin, built as that CMakeLists.txt builds them, with TLS off. The
# block curl-fuzz_proto_lib builds what they share, one time for each build, in its own directory (pf_proto_lib), and
# compiles, in parallel with the runtime, the message code of each target's profile and each target's entry point
# (pf_proto_compile); it links no fuzz target. The block of each target links its two objects with what they share
# (pf_proto_target). What they share:
# - OpenLDAP 2.6.13 without TLS, as curl-fuzzer builds it (:393-435): its options, its headers, liblber and libldap,
#   cross-compiled with the build's compilers and flags.
# - libcurl with curl-fuzzer's options that apply without TLS (CURL_COMMON_CMAKE_ARGS, :486-540), among them that
#   OpenLDAP: a debug build, with UNITTESTS in its own compiles only.
# - libprotobuf-mutator v1.5, on the toolchain's protobuf 3.21.12 (the sysroot's headers and libprotobuf.a), which its
#   port/protobuf.h supports, in place of the protobuf that v1.5's CMake downloads.
# - the runtime: the objects of curl_fuzzer_proto_runtime (:1837-1876, less its TLS sources, which it compiles only
#   with an OpenSSL target) and curl_fuzzer_proto_runner (:1908-1910), with the zstd and nghttp2 contract shims, each
#   compiled with COMMON_FLAGS only (:816), as de8de303d3e0 gives no target a FUZZ_PROTOCOLS_* definition.
# The message code (:1652-1789) is the same in each build: curl-fuzz_proto_gen.sh writes it in PF_GEN when the
# Dockerfile runs, with the toolchain's protoc 3.21.12. Each target links the archives of libprotobuf-mutator and its
# protobuf in one group (:1793-1814), OpenLDAP's libldap.a and liblber.a, and the shims' wraps
# (cmake/ZstdContractApis.cmake, cmake/Nghttp2ContractApis.cmake).
PF_GEN=/work/gen/curl-fuzz_proto
# The structured fuzz targets, one row each: <fuzz target>:<profile> (CMakeLists.txt:2054-2123). The entry point of a
# target is fuzzer_entrypoints/<fuzz target>.cc, as curl_add_proto_fuzzer names it, and its block is
# curl-fuzz_proto<what follows curl_fuzzer_proto in its name>. PROFILES of curl-fuzz_proto_gen.sh holds each profile.
PF_TARGETS="
  curl_fuzzer_proto_file:fast_file
  curl_fuzzer_proto:compatibility
  curl_fuzzer_proto_http:fast_http
  curl_fuzzer_proto_http2:fast_http2
  curl_fuzzer_proto_socks4:proxy_transport
  curl_fuzzer_proto_ws:fast_websocket
  curl_fuzzer_proto_telnet:fast_telnet
  curl_fuzzer_proto_smtp:fast_smtp
  curl_fuzzer_proto_imap:fast_imap
  curl_fuzzer_proto_pop3:fast_pop3
  curl_fuzzer_proto_mqtt:fast_mqtt
  curl_fuzzer_proto_dict:fast_dict
  curl_fuzzer_proto_ldap:fast_ldap
  curl_fuzzer_proto_rtsp:fast_rtsp
  curl_fuzzer_proto_ipfs:fast_ipfs
  curl_fuzzer_proto_gopher:fast_gopher
  curl_fuzzer_proto_api:api
  curl_fuzzer_proto_multi:multi
  curl_fuzzer_proto_timing:timing
"

# pf_profile <fuzz target>: its profile, from its row of PF_TARGETS.
pf_profile() {
  for pf_row in $PF_TARGETS; do
    if [ "${pf_row%%:*}" = "$1" ]; then echo "${pf_row#*:}"; return 0; fi
  done
  echo "build.sh: PF_TARGETS has no row for $1" >&2
  return 1
}

# pf_bg <command> [<argument> ...]: the command in the background, with at most $(oft_jobs) such commands at a time.
# pf_wait waits for those that still run. A command that fails stops the build (sh -e) when it is waited for.
pf_bg() {
  "$@" &
  pf_running="${pf_running:-} $!"
  # shellcheck disable=SC2086 # the process ids
  set -- $pf_running
  if [ "$#" -ge "$(oft_jobs)" ]; then
    wait "$1"
    shift
    pf_running="$*"
  fi
}
pf_wait() {
  for pf_pid in ${pf_running:-}; do wait "$pf_pid"; done
  pf_running=""
}

# pf_proto_lib: from the block curl-fuzz_proto_lib, in its directory $BUILDDIR (which $OFT_PREFIX names): what the
# structured fuzz targets share, OpenLDAP in include/ and lib/, libprotobuf-mutator in proto/lpm/, and lib/liboft.a, the
# archive of libcurl and the runtime, which each target's block copies; and the two objects of each target, its message
# code and its entry point, in proto/t/<fuzz target>/ (pf_proto_compile), which its block adds to that copy.
pf_proto_lib() {
  pf_tree=/work/targets/$T
  pf_lpm=/work/ext/libprotobuf-mutator-1.5
  pf_ol=$BUILDDIR/openldap
  pf_p=$BUILDDIR/proto
  # OpenLDAP, and each compile below, get the flags that oft_build_cmake gives libcurl (whose compiles add UNITTESTS).
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  # OpenLDAP, as curl-fuzzer builds it: in a copy of its tree, configured with curl-fuzzer's options, and for this
  # target, with the toolchain's archiver. A cross build cannot run configure's test programs, so it is given two
  # answers that they give on Linux: select() yields to other threads (configure stops without an answer), and memcmp
  # works (else libldap calls lutil_memcmp, a replacement that only liblutil has). Its headers are installed in
  # $OFT_PREFIX/include and its two archives copied to $OFT_PREFIX/lib, as curl-fuzzer installs them, and the copy of
  # its tree is removed, so that oft_build_cmake merges none of its archives into liboft.a.
  rm -rf "$pf_ol" "$OFT_PREFIX/include" "$OFT_PREFIX/lib"
  mkdir -p "$pf_ol" "$OFT_PREFIX/lib"
  cp -a /work/ext/openldap-2.6.13/. "$pf_ol/"
  ( cd "$pf_ol" && CC="$CC" CFLAGS="$CFLAGS" AR="$CHOST-ar" ./configure --host="$CHOST" \
      --build=x86_64-pc-linux-gnu --prefix="$OFT_PREFIX" --disable-shared --enable-static --without-tls \
      --disable-slapd --with-yielding-select=yes ac_cv_func_memcmp_working=yes )
  make -C "$pf_ol/include" -j"$(oft_jobs)" all
  make -C "$pf_ol/libraries/liblber" -j"$(oft_jobs)" liblber.la
  make -C "$pf_ol/libraries/libldap" -j"$(oft_jobs)" libldap.la
  make -C "$pf_ol/include" install
  cp "$pf_ol/libraries/liblber/.libs/liblber.a" "$pf_ol/libraries/libldap/.libs/libldap.a" "$OFT_PREFIX/lib/"
  rm -rf "$pf_ol"
  # libcurl, with curl-fuzzer's options that apply without TLS, that OpenLDAP, and UNITTESTS in its own compiles only
  CFLAGS="$CFLAGS -DUNITTESTS"
  oft_build_cmake -DCURL_USE_LIBPSL=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_MBEDTLS=OFF \
    -DENABLE_DEBUG=ON -DCMAKE_BUILD_TYPE=Debug -DCURL_DISABLE_INSTALL=ON -DCURL_HIDDEN_SYMBOLS=OFF \
    -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF \
    -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none -DCURL_DISABLE_TELNET=OFF -DCURL_DISABLE_FTP=OFF \
    -DCURL_DISABLE_TFTP=OFF -DCURL_DISABLE_GOPHER=OFF -DCURL_USE_GSASL=OFF \
    -DUSE_HTTPSRR=ON -DCURL_BROTLI=ON -DLDAP_INCLUDE_DIR="$OFT_PREFIX/include" \
    -DLDAP_LIBRARY="$OFT_PREFIX/lib/libldap.a" -DLDAP_LBER_LIBRARY="$OFT_PREFIX/lib/liblber.a"
  pf_kept=""
  for pf_f in $CFLAGS; do [ "$pf_f" = -DUNITTESTS ] || pf_kept="$pf_kept $pf_f"; done
  CFLAGS=${pf_kept# }
  # libprotobuf-mutator v1.5: its two libraries, with the flags its CMakeLists gives them (by hand: its CMake would
  # download a protobuf), and its installed headers
  rm -rf "$pf_p"
  mkdir -p "$pf_p/obj" "$pf_p/lpm/include/libprotobuf-mutator" "$pf_p/lpm/lib"
  pf_flags="-fno-exceptions -Wall -Wstring-conversion -O3 -DNDEBUG -fsanitize-coverage=0 -I$pf_lpm"
  for pf_s in binary_format mutator text_format utf8_fix libfuzzer/libfuzzer_mutator libfuzzer/libfuzzer_macro; do
    pf_bg "$CXX" $CFLAGS $pf_flags -c "$pf_lpm/src/$pf_s.cc" -o "$pf_p/lpm/${pf_s#libfuzzer/}.o"
  done
  pf_wait
  "$CHOST-ar" rcs "$pf_p/lpm/lib/libprotobuf-mutator.a" "$pf_p/lpm/binary_format.o" "$pf_p/lpm/mutator.o" \
    "$pf_p/lpm/text_format.o" "$pf_p/lpm/utf8_fix.o"
  "$CHOST-ar" rcs "$pf_p/lpm/lib/libprotobuf-mutator-libfuzzer.a" "$pf_p/lpm/libfuzzer_mutator.o" \
    "$pf_p/lpm/libfuzzer_macro.o"
  for pf_h in $(cd "$pf_lpm" && find port src -name '*.h' | LC_ALL=C sort); do
    mkdir -p "$pf_p/lpm/include/libprotobuf-mutator/${pf_h%/*}"
    cp "$pf_lpm/$pf_h" "$pf_p/lpm/include/libprotobuf-mutator/$pf_h"
  done
  # the runtime, its message code and the shims, compiled as curl-fuzzer compiles them, and archived after libcurl, in
  # the order of their object names; in the same queue, the two objects of each target (pf_proto_compile), which stay
  # out of this archive
  pf_inc="-I$SRCDIR/include -I$PF_GEN -I$pf_tree -I$pf_p/lpm/include -I$pf_p/lpm/include/libprotobuf-mutator"
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
      proto_fuzzer/bounded_anonymous_input_file proto_fuzzer/scenario_runner zstd_contract_shim \
      nghttp2_contract_shim; do
    case "$pf_s" in
      gen/*) pf_src=$PF_GEN/${pf_s#gen/}.cc ;;
      *) pf_src=$pf_tree/$pf_s.cc ;;
    esac
    pf_bg "$CXX" $CFLAGS -g -DCURL_DISABLE_DEPRECATION $pf_inc -c "$pf_src" -o "$pf_p/obj/${pf_s##*/}.o"
  done
  for pf_row in $PF_TARGETS; do
    pf_s=${pf_row#*:}
    [ -f "$PF_GEN/schema_eligibility/profiles/$pf_s/generated/$pf_s/$pf_s.pb.cc" ] || {
      echo "build.sh: no message code for the profile $pf_s: add it to PROFILES of curl-fuzz_proto_gen.sh" >&2
      exit 1
    }
    pf_bg pf_proto_compile "${pf_row%%:*}" "$pf_s"
  done
  pf_wait
  # shellcheck disable=SC2046 # the object names, which hold no space
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" $(find "$pf_p/obj" -name '*.o' | LC_ALL=C sort)
}

# pf_proto_compile <fuzz target> <profile>: from pf_proto_lib, in the background: the profile's message code and the
# target's entry point, compiled as curl-fuzzer compiles them, in proto/t/<fuzz target>/. The entry point is the
# harness: oft_build_harness compiles and checks it with that directory as its BUILDDIR, and adds harness.o to the
# lib/liboft.a there, which holds the message code.
pf_proto_compile() {
  BUILDDIR=$pf_p/t/$1
  pf_prof=$PF_GEN/schema_eligibility/profiles/$2
  mkdir -p "$BUILDDIR/lib"
  "$CXX" $CFLAGS -g -DCURL_DISABLE_DEPRECATION -I"$pf_prof" -c "$pf_prof/generated/$2/$2.pb.cc" -o "$BUILDDIR/$2.pb.o"
  "$CHOST-ar" rc "$BUILDDIR/lib/liboft.a" "$BUILDDIR/$2.pb.o"
  # the same-named entry point; it reads its profile's traits
  OFT_CXX_STD=-std=gnu++17
  OFT_HARNESS_CFLAGS="-DCURL_DISABLE_DEPRECATION -I$SRCDIR/include -I$PF_GEN -I$pf_tree -I$pf_p/lpm/include"
  OFT_HARNESS_CFLAGS="$OFT_HARNESS_CFLAGS -I$pf_p/lpm/include/libprotobuf-mutator -I$pf_prof"
  oft_build_harness "fuzzer_entrypoints/$1.cc"
}

# pf_proto_target: from build_lib of a structured fuzz target's block, for the fuzz target that the block's name ($T)
# names, with the profile of its row of PF_TARGETS: a copy of the archive of curl-fuzz_proto_lib, with the target's
# message code and entry point (the harness, also as $BUILDDIR/harness.o) added, in that order, from what
# pf_proto_compile compiled for it, and the link.
pf_proto_target() {
  pf_lib=$LIBROOT/curl-fuzz_proto_lib
  pf_name=curl_fuzzer_proto${T#curl-fuzz_proto}
  pf_prof=$(pf_profile "$pf_name")
  pf_obj=$pf_lib/proto/t/$pf_name
  rm -rf "$BUILDDIR/lib"
  mkdir -p "$BUILDDIR/lib"
  cp "$pf_lib/lib/liboft.a" "$BUILDDIR/lib/liboft.a"
  cp "$pf_obj/harness.o" "$BUILDDIR/harness.o"
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$pf_obj/$pf_prof.pb.o" "$BUILDDIR/harness.o"
  oft_add_sysroot_deps
  # the C++ runtime, as oft_build_harness adds it for a C++ harness
  oft_require_target_cxx
  LIB_EXTRA="${LIB_EXTRA:-} $OFT_CXX_RUNTIME"
  # the link: the archives of libprotobuf-mutator and the sysroot's libprotobuf.a in one group, OpenLDAP's libraries,
  # the shims' wraps, and the sysroot's other libraries but libprotobuf-lite.a, whose code libprotobuf.a holds
  pf_link="-Wl,--start-group $pf_lib/proto/lpm/lib/libprotobuf-mutator-libfuzzer.a"
  pf_link="$pf_link $pf_lib/proto/lpm/lib/libprotobuf-mutator.a"
  pf_rest=""
  for pf_a in $LIB_EXTRA; do
    case "$pf_a" in
      */libprotobuf.a) pf_link="$pf_link $pf_a" ;;
      */libprotobuf-lite.a) ;;
      *) pf_rest="$pf_rest $pf_a" ;;
    esac
  done
  pf_link="$pf_link -Wl,--end-group $pf_lib/lib/libldap.a $pf_lib/lib/liblber.a"
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
  LIB_EXTRA=$pf_link$pf_rest
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}

# curl-fuzz_proto_lib: what the structured fuzz targets below share, and the objects of each (pf_proto_lib); it links
# no fuzz target
(
ov_target_begin curl-fuzz_proto_lib
oft_require_target_cxx
pf_proto_lib
)

# curl_fuzzer_proto_file: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_file)
(
ov_target_begin curl-fuzz_proto_file
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_file
)

# curl_fuzzer_proto: curl-fuzzer de8de303d3e0's structured fuzz target (profile compatibility)
(
ov_target_begin curl-fuzz_proto
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto
)

# curl_fuzzer_proto_http: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_http)
(
ov_target_begin curl-fuzz_proto_http
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_http
)

# curl_fuzzer_proto_http2: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_http2)
(
ov_target_begin curl-fuzz_proto_http2
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_http2
)

# curl_fuzzer_proto_socks4: curl-fuzzer de8de303d3e0's structured fuzz target (profile proxy_transport)
(
ov_target_begin curl-fuzz_proto_socks4
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_socks4
)

# curl_fuzzer_proto_ws: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_websocket)
(
ov_target_begin curl-fuzz_proto_ws
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_ws
)

# curl_fuzzer_proto_telnet: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_telnet)
(
ov_target_begin curl-fuzz_proto_telnet
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_telnet
)

# curl_fuzzer_proto_smtp: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_smtp)
(
ov_target_begin curl-fuzz_proto_smtp
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_smtp
)

# curl_fuzzer_proto_imap: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_imap)
(
ov_target_begin curl-fuzz_proto_imap
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_imap
)

# curl_fuzzer_proto_pop3: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_pop3)
(
ov_target_begin curl-fuzz_proto_pop3
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_pop3
)

# curl_fuzzer_proto_mqtt: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_mqtt)
(
ov_target_begin curl-fuzz_proto_mqtt
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_mqtt
)

# curl_fuzzer_proto_dict: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_dict)
(
ov_target_begin curl-fuzz_proto_dict
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_dict
)

# curl_fuzzer_proto_ldap: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_ldap)
(
ov_target_begin curl-fuzz_proto_ldap
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_ldap
)

# curl_fuzzer_proto_rtsp: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_rtsp)
(
ov_target_begin curl-fuzz_proto_rtsp
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_rtsp
)

# curl_fuzzer_proto_ipfs: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_ipfs)
(
ov_target_begin curl-fuzz_proto_ipfs
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_ipfs
)

# curl_fuzzer_proto_gopher: curl-fuzzer de8de303d3e0's structured fuzz target (profile fast_gopher)
(
ov_target_begin curl-fuzz_proto_gopher
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_gopher
)

# curl_fuzzer_proto_api: curl-fuzzer de8de303d3e0's structured fuzz target (profile api)
(
ov_target_begin curl-fuzz_proto_api
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_api
)

# curl_fuzzer_proto_multi: curl-fuzzer de8de303d3e0's structured fuzz target (profile multi)
(
ov_target_begin curl-fuzz_proto_multi
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_multi
)

# curl_fuzzer_proto_timing: curl-fuzzer de8de303d3e0's structured fuzz target (profile timing)
(
ov_target_begin curl-fuzz_proto_timing
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
build_lib() {
  oft_require_target_cxx
  pf_proto_target
}
ov_target_build curl_fuzzer_proto_timing
)
