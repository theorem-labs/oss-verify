#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of rabbitmq-c into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_codec: the release's target rabbitmq-c-fuzz_codec
(
ov_target_begin rabbitmq-c-fuzz_codec
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_codec.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_codec
)

# fuzz_handle_input: the release's target rabbitmq-c-fuzz_handle_input
(
ov_target_begin rabbitmq-c-fuzz_handle_input
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_handle_input.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_handle_input
)

# fuzz_method_decode: the release's target rabbitmq-c-fuzz_method_decode
(
ov_target_begin rabbitmq-c-fuzz_method_decode
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_method_decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_method_decode
)

# fuzz_properties_decode: the release's target rabbitmq-c-fuzz_properties_decode
(
ov_target_begin rabbitmq-c-fuzz_properties_decode
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_properties_decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_properties_decode
)

# fuzz_server: the release's target rabbitmq-c-fuzz_server
(
ov_target_begin rabbitmq-c-fuzz_server
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_server.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_server
)

# fuzz_table: the release's target rabbitmq-c-fuzz_table
(
ov_target_begin rabbitmq-c-fuzz_table
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_table.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_table
)

# fuzz_url: the release's target rabbitmq-c-fuzz_url
(
ov_target_begin rabbitmq-c-fuzz_url
build_lib() {
  oft_build_cmake -DENABLE_SSL_SUPPORT=OFF
  oft_build_harness "fuzz/fuzz_url.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_url
)
