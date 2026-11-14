#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of bazel-rules-fuzzing-test into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzed_data_provider_fuzz_test: the release's target bazel-rules-fuzzing-test-fuzzed_data_provider_fuzz_test
(
ov_target_begin bazel-rules-fuzzing-test-fuzzed_data_provider_fuzz_test
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "examples/fuzzed_data_provider_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "examples/fuzzed_data_provider_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzed_data_provider_fuzz_test
)

# input_buffer_overflow_fuzz_test: the release's target bazel-rules-fuzzing-test-input_buffer_overflow_fuzz_test
(
ov_target_begin bazel-rules-fuzzing-test-input_buffer_overflow_fuzz_test
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "examples/input_buffer_overflow_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "examples/input_buffer_overflow_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build input_buffer_overflow_fuzz_test
)

# new_buffer_overflow_fuzz_test: the release's target bazel-rules-fuzzing-test-new_buffer_overflow_fuzz_test
(
ov_target_begin bazel-rules-fuzzing-test-new_buffer_overflow_fuzz_test
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "examples/new_buffer_overflow_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "examples/new_buffer_overflow_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build new_buffer_overflow_fuzz_test
)

# ubsan_function_ptr_fuzz_test: the release's target bazel-rules-fuzzing-test-ubsan_function_ptr_fuzz_test
(
ov_target_begin bazel-rules-fuzzing-test-ubsan_function_ptr_fuzz_test
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "examples/ubsan_function_ptr_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "examples/ubsan_function_ptr_fuzz_test.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build ubsan_function_ptr_fuzz_test
)
