#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wabt into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# read_binary_ir_fuzzer: the release's target wabt-read_binary_ir_fuzzer
(
ov_target_begin wabt-read_binary_ir_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzers/read_binary_ir_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build read_binary_ir_fuzzer
)

# wasm2wat-fuzz: the release's target wabt-wasm2wat-fuzz
(
ov_target_begin wabt-wasm2wat-fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "src/tools/wasm2wat-fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build wasm2wat-fuzz
)

# wat2wasm_fuzzer: the release's target wabt-wat2wasm_fuzzer
(
ov_target_begin wabt-wat2wasm_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzers/wat2wasm_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build wat2wasm_fuzzer
)
