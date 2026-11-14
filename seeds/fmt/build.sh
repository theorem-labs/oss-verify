#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of fmt into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# chrono-duration-fuzzer: the release's target fmt
(
ov_target_begin fmt
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/chrono-duration.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build chrono-duration-fuzzer
)

# chrono-timepoint-fuzzer: the release's target fmt-chrono-timepoint
(
ov_target_begin fmt-chrono-timepoint
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/chrono-timepoint.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build chrono-timepoint-fuzzer
)

# float-fuzzer: the release's target fmt-float
(
ov_target_begin fmt-float
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/float.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build float-fuzzer
)

# named-arg-fuzzer: the release's target fmt-named-arg
(
ov_target_begin fmt-named-arg
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/named-arg.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build named-arg-fuzzer
)

# one-arg-fuzzer: the release's target fmt-one-arg
(
ov_target_begin fmt-one-arg
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/one-arg.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build one-arg-fuzzer
)

# two-args-fuzzer: the release's target fmt-two-args
(
ov_target_begin fmt-two-args
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "test/fuzzing/two-args.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build two-args-fuzzer
)
