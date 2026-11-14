#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of open62541 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_attributeoperand: the release's target open62541-fuzz_attributeoperand
(
ov_target_begin open62541-fuzz_attributeoperand
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_attributeoperand.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_attributeoperand
)

# fuzz_base64_decode: the release's target open62541-fuzz_base64_decode
(
ov_target_begin open62541-fuzz_base64_decode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_base64_decode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_base64_decode
)

# fuzz_base64_encode: the release's target open62541-fuzz_base64_encode
(
ov_target_begin open62541-fuzz_base64_encode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_base64_encode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_base64_encode
)

# fuzz_binary_decode: the release's target open62541-fuzz_binary_decode
(
ov_target_begin open62541-fuzz_binary_decode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_binary_decode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_binary_decode
)

# fuzz_datatype_description: the release's target open62541-fuzz_datatype_description
(
ov_target_begin open62541-fuzz_datatype_description
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_datatype_description.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_datatype_description
)

# fuzz_eventfilter_parse: the release's target open62541-fuzz_eventfilter_parse
(
ov_target_begin open62541-fuzz_eventfilter_parse
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_eventfilter_parse.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_eventfilter_parse
)

# fuzz_json_decode: the release's target open62541-fuzz_json_decode
(
ov_target_begin open62541-fuzz_json_decode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_json_decode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_json_decode
)

# fuzz_json_decode_encode: the release's target open62541-fuzz_json_decode_encode
(
ov_target_begin open62541-fuzz_json_decode_encode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_json_decode_encode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_json_decode_encode
)

# fuzz_parse_string: the release's target open62541-fuzz_parse_string
(
ov_target_begin open62541-fuzz_parse_string
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_parse_string.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_parse_string
)

# fuzz_pubsub_binary: the release's target open62541-fuzz_pubsub_binary
(
ov_target_begin open62541-fuzz_pubsub_binary
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_pubsub_binary.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_pubsub_binary
)

# fuzz_pubsub_connection_config: the release's target open62541-fuzz_pubsub_connection_config
(
ov_target_begin open62541-fuzz_pubsub_connection_config
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_pubsub_connection_config.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_pubsub_connection_config
)

# fuzz_pubsub_json: the release's target open62541-fuzz_pubsub_json
(
ov_target_begin open62541-fuzz_pubsub_json
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_pubsub_json.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_pubsub_json
)

# fuzz_src_ua_util: the release's target open62541-fuzz_src_ua_util
(
ov_target_begin open62541-fuzz_src_ua_util
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_src_ua_util.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_src_ua_util
)

# fuzz_xml_decode_encode: the release's target open62541-fuzz_xml_decode_encode
(
ov_target_begin open62541-fuzz_xml_decode_encode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/fuzz_xml_decode_encode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_xml_decode_encode
)
