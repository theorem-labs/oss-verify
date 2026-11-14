#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of eigen into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# basicstuff_fuzzer: the release's target eigen-basicstuff_fuzzer
(
ov_target_begin eigen-basicstuff_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "basicstuff_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "basicstuff_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build basicstuff_fuzzer
)

# geometry_fuzzer: the release's target eigen-geometry_fuzzer
(
ov_target_begin eigen-geometry_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "geometry_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "geometry_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build geometry_fuzzer
)

# solver_fuzzer: the release's target eigen-solver_fuzzer
(
ov_target_begin eigen-solver_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "solver_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "solver_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build solver_fuzzer
)

# sparse_fuzzer: the release's target eigen-sparse_fuzzer
(
ov_target_begin eigen-sparse_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "sparse_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "sparse_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build sparse_fuzzer
)

# tensor_fuzzer: the release's target eigen-tensor_fuzzer
(
ov_target_begin eigen-tensor_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tensor_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""























build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "tensor_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build tensor_fuzzer
)
