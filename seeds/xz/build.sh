#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of xz into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_decode_alone: the release's target xz-fuzz_decode_alone
(
ov_target_begin xz-fuzz_decode_alone
build_lib() {
  oft_build_cmake -DXZ_SANDBOX=no
  oft_build_harness "tests/ossfuzz/fuzz_decode_alone.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_decode_alone
)

# fuzz_decode_stream: the release's target xz-fuzz_decode_stream
(
ov_target_begin xz-fuzz_decode_stream
build_lib() {
  oft_build_cmake -DXZ_SANDBOX=no
  oft_build_harness "tests/ossfuzz/fuzz_decode_stream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_decode_stream
)

# fuzz_decode_stream_mt: the release's target xz-fuzz_decode_stream_mt
(
ov_target_begin xz-fuzz_decode_stream_mt
build_lib() {











  oft_build_cmake -DXZ_SANDBOX=no
  oft_build_harness "tests/ossfuzz/fuzz_decode_stream_mt.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_decode_stream_mt
)

# fuzz_encode_stream: the release's target xz-fuzz_encode_stream
(
ov_target_begin xz-fuzz_encode_stream
build_lib() {
  oft_build_cmake -DXZ_SANDBOX=no
  oft_build_harness "tests/ossfuzz/fuzz_encode_stream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_encode_stream
)
