#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libiec61850 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_acse_parse: the release's target libiec61850-fuzz_acse_parse
(
ov_target_begin libiec61850-fuzz_acse_parse
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_acse_parse.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_acse_parse
)

# fuzz_goose_subscriber: the release's target libiec61850-fuzz_goose_subscriber
(
ov_target_begin libiec61850-fuzz_goose_subscriber
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_goose_subscriber.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_goose_subscriber
)

# fuzz_mms_decode: the release's target libiec61850-fuzz_mms_decode
(
ov_target_begin libiec61850-fuzz_mms_decode
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_mms_decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_mms_decode
)

# fuzz_mms_encode: the release's target libiec61850-fuzz_mms_encode
(
ov_target_begin libiec61850-fuzz_mms_encode
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_mms_encode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_mms_encode
)

# fuzz_mms_print: the release's target libiec61850-fuzz_mms_print
(
ov_target_begin libiec61850-fuzz_mms_print
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_mms_print.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_mms_print
)

# fuzz_mms_server_decode_mms_pdu: the release's target libiec61850-fuzz_mms_server_decode_mms_pdu
(
ov_target_begin libiec61850-fuzz_mms_server_decode_mms_pdu
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_mms_server_decode_mms_pdu.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_mms_server_decode_mms_pdu
)

# fuzz_pres_userdata: the release's target libiec61850-fuzz_pres_userdata
(
ov_target_begin libiec61850-fuzz_pres_userdata
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_pres_userdata.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_pres_userdata
)

# fuzz_sv_subscriber: the release's target libiec61850-fuzz_sv_subscriber
(
ov_target_begin libiec61850-fuzz_sv_subscriber
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_sv_subscriber.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_sv_subscriber
)
