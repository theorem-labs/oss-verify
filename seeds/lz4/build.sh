#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of lz4 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# compress_frame_fuzzer: the release's target lz4-compress_frame_fuzzer
(
ov_target_begin lz4-compress_frame_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/compress_frame_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build compress_frame_fuzzer
)

# compress_fuzzer: the release's target lz4-compress_fuzzer
(
ov_target_begin lz4-compress_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/compress_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build compress_fuzzer
)

# compress_hc_fuzzer: the release's target lz4-compress_hc_fuzzer
(
ov_target_begin lz4-compress_hc_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/compress_hc_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build compress_hc_fuzzer
)

# decompress_frame_fuzzer: the release's target lz4-decompress_frame_fuzzer
(
ov_target_begin lz4-decompress_frame_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/decompress_frame_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build decompress_frame_fuzzer
)

# decompress_fuzzer: the release's target lz4-decompress_fuzzer
(
ov_target_begin lz4-decompress_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/decompress_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build decompress_fuzzer
)

# round_trip_frame_fuzzer: the release's target lz4-round_trip_frame_fuzzer
(
ov_target_begin lz4-round_trip_frame_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/round_trip_frame_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build round_trip_frame_fuzzer
)

# round_trip_frame_uncompressed_fuzzer: the release's target lz4-round_trip_frame_uncompressed_fuzzer
(
ov_target_begin lz4-round_trip_frame_uncompressed_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/round_trip_frame_uncompressed_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build round_trip_frame_uncompressed_fuzzer
)

# round_trip_fuzzer: the release's target lz4-round_trip_fuzzer
(
ov_target_begin lz4-round_trip_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/round_trip_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build round_trip_fuzzer
)

# round_trip_hc_fuzzer: the release's target lz4-round_trip_hc_fuzzer
(
ov_target_begin lz4-round_trip_hc_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/round_trip_hc_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build round_trip_hc_fuzzer
)

# round_trip_stream_fuzzer: the release's target lz4-round_trip_stream_fuzzer
(
ov_target_begin lz4-round_trip_stream_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "ossfuzz/round_trip_stream_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build round_trip_stream_fuzzer
)
