#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of zxc into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# zxc_fuzzer_decompress: the release's target zxc-fuzz_decompress
(
ov_target_begin zxc-fuzz_decompress
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz_decompress.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zxc_fuzzer_decompress
)

# zxc_fuzzer_dict: the release's target zxc-fuzz_dict
(
ov_target_begin zxc-fuzz_dict
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz_dict.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zxc_fuzzer_dict
)

# zxc_fuzzer_pstream: the release's target zxc-fuzz_pstream
(
ov_target_begin zxc-fuzz_pstream
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz_pstream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zxc_fuzzer_pstream
)

# zxc_fuzzer_roundtrip: the release's target zxc-fuzz_roundtrip
(
ov_target_begin zxc-fuzz_roundtrip
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz_roundtrip.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zxc_fuzzer_roundtrip
)

# zxc_fuzzer_seekable: the release's target zxc-fuzz_seekable
(
ov_target_begin zxc-fuzz_seekable
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz_seekable.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zxc_fuzzer_seekable
)
