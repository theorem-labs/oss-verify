#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libjpeg-turbo into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# compress12_fuzzer: the release's target libjpeg-turbo-compress12
(
ov_target_begin libjpeg-turbo-compress12
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/compress12.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/compress12.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build compress12_fuzzer
)

# compress12_lossless_fuzzer: the release's target libjpeg-turbo-compress12_lossless
(
ov_target_begin libjpeg-turbo-compress12_lossless
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/compress12_lossless.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/compress12_lossless.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build compress12_lossless_fuzzer
)

# compress16_lossless_fuzzer: the release's target libjpeg-turbo-compress16_lossless
(
ov_target_begin libjpeg-turbo-compress16_lossless
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/compress16_lossless.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/compress16_lossless.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build compress16_lossless_fuzzer
)

# compress_fuzzer: the release's target libjpeg-turbo-compress
(
ov_target_begin libjpeg-turbo-compress
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/compress.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/compress.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build compress_fuzzer
)

# compress_lossless_fuzzer: the release's target libjpeg-turbo-compress_lossless
(
ov_target_begin libjpeg-turbo-compress_lossless
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/compress_lossless.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/compress_lossless.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build compress_lossless_fuzzer
)

# compress_yuv_fuzzer: the release's target libjpeg-turbo-compress_yuv
(
ov_target_begin libjpeg-turbo-compress_yuv
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/compress_yuv.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/compress_yuv.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build compress_yuv_fuzzer
)

# decompress_libjpeg_fuzzer: the release's target libjpeg-turbo-decompress_libjpeg
(
ov_target_begin libjpeg-turbo-decompress_libjpeg
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/decompress_libjpeg.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/decompress_libjpeg.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build decompress_libjpeg_fuzzer
)

# decompress_yuv_fuzzer: the release's target libjpeg-turbo-decompress_yuv
(
ov_target_begin libjpeg-turbo-decompress_yuv
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/decompress_yuv.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/decompress_yuv.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build decompress_yuv_fuzzer
)

# libjpeg_turbo_fuzzer: the release's target libjpeg-turbo-decompress
(
ov_target_begin libjpeg-turbo-decompress
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/decompress.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/decompress.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libjpeg_turbo_fuzzer
)

# transform_fuzzer: the release's target libjpeg-turbo-transform
(
ov_target_begin libjpeg-turbo-transform
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/transform.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DBUILD=20250901
  oft_build_harness "fuzz/transform.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build transform_fuzzer
)
