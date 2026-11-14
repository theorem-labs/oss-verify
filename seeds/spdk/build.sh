#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of spdk into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# crc_fuzz_test: the release's target spdk-crc_fuzz_test
(
ov_target_begin spdk-crc_fuzz_test
build_lib() {
  oft_build_autotools
  oft_build_harness "isa-l/tests/fuzz/crc_fuzz_test.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















OFT_BUILD_SUBDIR=isa-l



































build_lib() {
  CFLAGS="$CFLAGS -UHAVE_RVV -DHAVE_RVV=0" oft_build_autotools
  oft_build_harness "isa-l/tests/fuzz/crc_fuzz_test.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build crc_fuzz_test
)

# igzip_simple_inflate_fuzz_test: the release's target spdk-igzip_simple_inflate_fuzz_test
(
ov_target_begin spdk-igzip_simple_inflate_fuzz_test
build_lib() {
  oft_build_autotools
  oft_build_harness "isa-l/tests/fuzz/igzip_simple_inflate_fuzz_test.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















OFT_BUILD_SUBDIR=isa-l



































build_lib() {
  CFLAGS="$CFLAGS -UHAVE_RVV -DHAVE_RVV=0" oft_build_autotools
  oft_build_harness "isa-l/tests/fuzz/igzip_simple_inflate_fuzz_test.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build igzip_simple_inflate_fuzz_test
)
