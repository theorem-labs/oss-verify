#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of miniz into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# add_in_place_fuzzer: the release's target miniz-add_in_place_fuzzer
(
ov_target_begin miniz-add_in_place_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/add_in_place_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build add_in_place_fuzzer
)

# checksum_fuzzer: the release's target miniz-checksum_fuzzer
(
ov_target_begin miniz-checksum_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/checksum_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build checksum_fuzzer
)

# compress_fuzzer: the release's target miniz-compress_fuzzer
(
ov_target_begin miniz-compress_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/compress_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build compress_fuzzer
)

# flush_fuzzer: the release's target miniz-flush_fuzzer
(
ov_target_begin miniz-flush_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/flush_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build flush_fuzzer
)

# large_fuzzer: the release's target miniz-large_fuzzer
(
ov_target_begin miniz-large_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/large_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build large_fuzzer
)

# miniz_zip_validate_fuzzer: the release's target miniz-miniz_zip_validate_fuzzer
(
ov_target_begin miniz-miniz_zip_validate_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/miniz_zip_validate_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build miniz_zip_validate_fuzzer
)

# small_fuzzer: the release's target miniz-small_fuzzer
(
ov_target_begin miniz-small_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/small_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build small_fuzzer
)

# uncompress2_fuzzer: the release's target miniz-uncompress2_fuzzer
(
ov_target_begin miniz-uncompress2_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/uncompress2_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build uncompress2_fuzzer
)

# uncompress_fuzzer: the release's target miniz-uncompress_fuzzer
(
ov_target_begin miniz-uncompress_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/uncompress_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build uncompress_fuzzer
)

# zip_fuzzer: the release's target miniz-zip_fuzzer
(
ov_target_begin miniz-zip_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/zip_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zip_fuzzer
)
