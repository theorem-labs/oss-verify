#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of qpid-proton into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-message-decode: the release's target qpid-proton-fuzz-message-decode
(
ov_target_begin qpid-proton-fuzz-message-decode
build_lib() {











  oft_build_cmake -DENABLE_WARNING_ERROR=OFF
  oft_build_harness "c/tests/fuzz/fuzz-message-decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































build_lib() {











  oft_build_cmake -DENABLE_WARNING_ERROR=OFF -DENABLE_LINKTIME_OPTIMIZATION=OFF
  oft_build_harness "c/tests/fuzz/fuzz-message-decode.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-message-decode
)

# fuzz-sniff-header: the release's target qpid-proton-fuzz-sniff-header
(
ov_target_begin qpid-proton-fuzz-sniff-header
build_lib() {
  oft_build_cmake
  oft_build_harness "c/tests/fuzz/fuzz-sniff-header.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-sniff-header
)
