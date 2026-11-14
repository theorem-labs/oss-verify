#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of spdlog into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# backtrace_fuzzer: the release's target spdlog-backtrace_fuzzer
(
ov_target_begin spdlog-backtrace_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "backtrace_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_NO_TLS=ON
  export OFT_HARNESS_CFLAGS="-DSPDLOG_COMPILED_LIB -DSPDLOG_NO_TLS"
  oft_build_harness "backtrace_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build backtrace_fuzzer
)

# format_fuzzer: the release's target spdlog-format_fuzzer
(
ov_target_begin spdlog-format_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "format_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_NO_TLS=ON
  export OFT_HARNESS_CFLAGS="-DSPDLOG_COMPILED_LIB -DSPDLOG_NO_TLS"
  oft_build_harness "format_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build format_fuzzer
)

# levels_fuzzer: the release's target spdlog-levels_fuzzer
(
ov_target_begin spdlog-levels_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "levels_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_NO_TLS=ON
  export OFT_HARNESS_CFLAGS="-DSPDLOG_COMPILED_LIB -DSPDLOG_NO_TLS"
  oft_build_harness "levels_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build levels_fuzzer
)

# log_fuzzer: the release's target spdlog-log_fuzzer
(
ov_target_begin spdlog-log_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "log_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_NO_TLS=ON
  export OFT_HARNESS_CFLAGS="-DSPDLOG_COMPILED_LIB -DSPDLOG_NO_TLS"
  oft_build_harness "log_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build log_fuzzer
)

# pattern_fuzzer: the release's target spdlog-pattern_fuzzer
(
ov_target_begin spdlog-pattern_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "pattern_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_NO_TLS=ON
  export OFT_HARNESS_CFLAGS="-DSPDLOG_COMPILED_LIB -DSPDLOG_NO_TLS"
  oft_build_harness "pattern_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build pattern_fuzzer
)
