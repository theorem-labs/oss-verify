#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of lighttpd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_burl: the release's target lighttpd-fuzz_burl
(
ov_target_begin lighttpd-fuzz_burl
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz_burl.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_build_cmake -DWITH_PCRE2=OFF
  oft_build_harness "fuzz_burl.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_burl
)

# fuzz_utils: the release's target lighttpd-fuzz_utils
(
ov_target_begin lighttpd-fuzz_utils
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz_utils.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_build_cmake -DWITH_PCRE2=OFF
  oft_build_harness "fuzz_utils.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_utils
)
