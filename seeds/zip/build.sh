#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of zip into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_entry: the release's target zip-fuzz_entry
(
ov_target_begin zip-fuzz_entry
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_entry.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_entry
)

# fuzz_stream: the release's target zip-fuzz_stream
(
ov_target_begin zip-fuzz_stream
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_stream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_stream
)
