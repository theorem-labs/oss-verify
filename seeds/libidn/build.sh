#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libidn into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libidn_stringprep_fuzzer: the release's target libidn-libidn_stringprep_fuzzer
(
ov_target_begin libidn-libidn_stringprep_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libidn_stringprep_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libidn_stringprep_fuzzer
)

# libidn_toascii_fuzzer: the release's target libidn-libidn_toascii_fuzzer
(
ov_target_begin libidn-libidn_toascii_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libidn_toascii_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libidn_toascii_fuzzer
)

# libidn_tounicode_fuzzer: the release's target libidn-libidn_tounicode_fuzzer
(
ov_target_begin libidn-libidn_tounicode_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libidn_tounicode_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libidn_tounicode_fuzzer
)
