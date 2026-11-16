#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libjxl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# color_encoding_fuzzer: the release's target libjxl-color_encoding_fuzzer
(
ov_target_begin libjxl-color_encoding_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/color_encoding_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build color_encoding_fuzzer
)

# decode_fuzzer: the release's target libjxl-decode_fuzzer
(
ov_target_begin libjxl-decode_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "third_party/brotli/c/fuzz/decode_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build decode_fuzzer
)

# fields_fuzzer: the release's target libjxl-fields_fuzzer
(
ov_target_begin libjxl-fields_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/fields_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fields_fuzzer
)

# fuzz_iccprofile_atf: the release's target libjxl-fuzz_iccprofile_atf
(
ov_target_begin libjxl-fuzz_iccprofile_atf
build_lib() {
  oft_build_cmake
  oft_build_harness "third_party/skcms/fuzz/fuzz_iccprofile_atf.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_iccprofile_atf
)

# fuzz_iccprofile_info: the release's target libjxl-fuzz_iccprofile_info
(
ov_target_begin libjxl-fuzz_iccprofile_info
build_lib() {
  oft_build_cmake
  oft_build_harness "third_party/skcms/fuzz/fuzz_iccprofile_info.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_iccprofile_info
)

# fuzz_iccprofile_transform: the release's target libjxl-fuzz_iccprofile_transform
(
ov_target_begin libjxl-fuzz_iccprofile_transform
build_lib() {
  oft_build_cmake
  oft_build_harness "third_party/skcms/fuzz/fuzz_iccprofile_transform.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_iccprofile_transform
)

# icc_codec_fuzzer: the release's target libjxl-icc_codec_fuzzer
(
ov_target_begin libjxl-icc_codec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/icc_codec_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build icc_codec_fuzzer
)

# rans_fuzzer: the release's target libjxl-rans_fuzzer
(
ov_target_begin libjxl-rans_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tools/rans_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build rans_fuzzer
)
