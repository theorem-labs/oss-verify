#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of s2opc into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# decode_fuzzer: the release's target s2opc-fuzz_decoder
(
ov_target_begin s2opc-fuzz_decoder
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/ClientServer/unit_tests/fuzzing/fuzz_decoder.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















oft_s2opc_expat_config() {
  mkdir -p "$BUILDDIR/expat-cmake"
  cat > "$BUILDDIR/expat-cmake/expat-config.cmake" <<'EOF_EXPAT'
                                                             
if(NOT TARGET expat::expat)
  add_library(expat::expat STATIC IMPORTED)
  set_target_properties(expat::expat PROPERTIES
    IMPORTED_LOCATION "/opt/musl-sysroot/usr/lib/libexpat.a"
    INTERFACE_INCLUDE_DIRECTORIES "/opt/musl-sysroot/usr/include")
endif()
set(expat_FOUND TRUE)
set(expat_VERSION "2.7.1")
EOF_EXPAT
}













oft_s2opc_scrub_testdata_members() {
  local out="$BUILDDIR/lib/liboft.a" m
  for m in $("$CHOST-ar" t "$out" | sort | uniq -d); do
    "$CHOST-ar" dN 2 "$out" "$m" || return 1
    echo "oft: dropped duplicate archive member (in-tree test data): $m"
  done
  if [ -n "$("$CHOST-ar" t "$out" | sort | uniq -d)" ]; then
    echo "oft: duplicate members survived the scrub" >&2
    return 1
  fi
}


build_lib() {
  oft_s2opc_expat_config
  oft_build_cmake \
    -Dexpat_DIR="$BUILDDIR/expat-cmake" \
    -DS2OPC_CRYPTO_MBEDTLS=OFF \
    -DENABLE_TESTING=OFF -DENABLE_SAMPLES=OFF
  oft_s2opc_scrub_testdata_members




  OFT_HARNESS_CFLAGS="-I$BUILDDIR/src/tests/ClientServer/unit_tests/fuzzing/data_fx"
  OFT_COMPANION_SRCS="../helpers/custom_types.c ../helpers/custom2_types.c data_fx/fx_ac_types.c data_fx/fx_cm_types.c data_fx/fx_data_types.c"
  oft_build_harness "tests/ClientServer/unit_tests/fuzzing/fuzz_decoder.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build decode_fuzzer
)

# parse_tcp_uri_fuzzer: the release's target s2opc-fuzz_parse_tcp_uri
(
ov_target_begin s2opc-fuzz_parse_tcp_uri
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/ClientServer/unit_tests/fuzzing/fuzz_parse_tcp_uri.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























oft_s2opc_expat_config() {
  mkdir -p "$BUILDDIR/expat-cmake"
  cat > "$BUILDDIR/expat-cmake/expat-config.cmake" <<'EOF_EXPAT'
                                                             
if(NOT TARGET expat::expat)
  add_library(expat::expat STATIC IMPORTED)
  set_target_properties(expat::expat PROPERTIES
    IMPORTED_LOCATION "/opt/musl-sysroot/usr/lib/libexpat.a"
    INTERFACE_INCLUDE_DIRECTORIES "/opt/musl-sysroot/usr/include")
endif()
set(expat_FOUND TRUE)
set(expat_VERSION "2.7.1")
EOF_EXPAT
}













oft_s2opc_scrub_testdata_members() {
  local out="$BUILDDIR/lib/liboft.a" m
  for m in $("$CHOST-ar" t "$out" | sort | uniq -d); do
    "$CHOST-ar" dN 2 "$out" "$m" || return 1
    echo "oft: dropped duplicate archive member (in-tree test data): $m"
  done
  if [ -n "$("$CHOST-ar" t "$out" | sort | uniq -d)" ]; then
    echo "oft: duplicate members survived the scrub" >&2
    return 1
  fi
}


build_lib() {
  oft_s2opc_expat_config
  oft_build_cmake \
    -Dexpat_DIR="$BUILDDIR/expat-cmake" \
    -DS2OPC_CRYPTO_MBEDTLS=OFF \
    -DENABLE_TESTING=OFF -DENABLE_SAMPLES=OFF
  oft_s2opc_scrub_testdata_members
  oft_build_harness "tests/ClientServer/unit_tests/fuzzing/fuzz_parse_tcp_uri.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse_tcp_uri_fuzzer
)

# server_request_fuzzer: the release's target s2opc-fuzz_server_request
(
ov_target_begin s2opc-fuzz_server_request
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/ClientServer/unit_tests/fuzzing/fuzz_server_request.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























oft_s2opc_expat_config() {
  mkdir -p "$BUILDDIR/expat-cmake"
  cat > "$BUILDDIR/expat-cmake/expat-config.cmake" <<'EOF_EXPAT'
                                                             
if(NOT TARGET expat::expat)
  add_library(expat::expat STATIC IMPORTED)
  set_target_properties(expat::expat PROPERTIES
    IMPORTED_LOCATION "/opt/musl-sysroot/usr/lib/libexpat.a"
    INTERFACE_INCLUDE_DIRECTORIES "/opt/musl-sysroot/usr/include")
endif()
set(expat_FOUND TRUE)
set(expat_VERSION "2.7.1")
EOF_EXPAT
}













oft_s2opc_scrub_testdata_members() {
  local out="$BUILDDIR/lib/liboft.a" m
  for m in $("$CHOST-ar" t "$out" | sort | uniq -d); do
    "$CHOST-ar" dN 2 "$out" "$m" || return 1
    echo "oft: dropped duplicate archive member (in-tree test data): $m"
  done
  if [ -n "$("$CHOST-ar" t "$out" | sort | uniq -d)" ]; then
    echo "oft: duplicate members survived the scrub" >&2
    return 1
  fi
}


build_lib() {
  oft_s2opc_expat_config
  oft_build_cmake \
    -Dexpat_DIR="$BUILDDIR/expat-cmake" \
    -DS2OPC_CRYPTO_MBEDTLS=OFF \
    -DENABLE_TESTING=OFF -DENABLE_SAMPLES=OFF
  oft_s2opc_scrub_testdata_members
  oft_build_harness "tests/ClientServer/unit_tests/fuzzing/fuzz_server_request.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build server_request_fuzzer
)

# sub_fuzzer: the release's target s2opc-fuzz_sub
(
ov_target_begin s2opc-fuzz_sub
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/PubSub/fuzzing/fuzz_sub.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























oft_s2opc_expat_config() {
  mkdir -p "$BUILDDIR/expat-cmake"
  cat > "$BUILDDIR/expat-cmake/expat-config.cmake" <<'EOF_EXPAT'
                                                             
if(NOT TARGET expat::expat)
  add_library(expat::expat STATIC IMPORTED)
  set_target_properties(expat::expat PROPERTIES
    IMPORTED_LOCATION "/opt/musl-sysroot/usr/lib/libexpat.a"
    INTERFACE_INCLUDE_DIRECTORIES "/opt/musl-sysroot/usr/include")
endif()
set(expat_FOUND TRUE)
set(expat_VERSION "2.7.1")
EOF_EXPAT
}













oft_s2opc_scrub_testdata_members() {
  local out="$BUILDDIR/lib/liboft.a" m
  for m in $("$CHOST-ar" t "$out" | sort | uniq -d); do
    "$CHOST-ar" dN 2 "$out" "$m" || return 1
    echo "oft: dropped duplicate archive member (in-tree test data): $m"
  done
  if [ -n "$("$CHOST-ar" t "$out" | sort | uniq -d)" ]; then
    echo "oft: duplicate members survived the scrub" >&2
    return 1
  fi
}


build_lib() {
  oft_s2opc_expat_config
  oft_build_cmake \
    -Dexpat_DIR="$BUILDDIR/expat-cmake" \
    -DS2OPC_CRYPTO_MBEDTLS=OFF \
    -DENABLE_TESTING=OFF -DENABLE_SAMPLES=OFF
  oft_s2opc_scrub_testdata_members
  oft_build_harness "tests/PubSub/fuzzing/fuzz_sub.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build sub_fuzzer
)
