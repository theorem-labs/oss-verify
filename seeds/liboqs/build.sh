#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of liboqs into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_test_kem: the release's target liboqs-fuzz_test_kem
(
ov_target_begin liboqs-fuzz_test_kem
build_lib() {
  oft_build_cmake -DOQS_USE_OPENSSL=OFF
  oft_build_harness "tests/fuzz_test_kem.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_test_kem
)

# fuzz_test_sig: the release's target liboqs-fuzz_test_sig
(
ov_target_begin liboqs-fuzz_test_sig
build_lib() {
  oft_build_cmake -DOQS_USE_OPENSSL=OFF
  oft_build_harness "tests/fuzz_test_sig.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_test_sig
)

# fuzz_test_sig_stfl_lms: the release's target liboqs-fuzz_test_sig_stfl_lms
(
ov_target_begin liboqs-fuzz_test_sig_stfl_lms
build_lib() {
  oft_build_cmake -DOQS_USE_OPENSSL=OFF
  oft_build_harness "tests/fuzz_test_sig_stfl_lms.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_test_sig_stfl_lms
)

# fuzz_test_sig_stfl_xmss: the release's target liboqs-fuzz_test_sig_stfl_xmss
(
ov_target_begin liboqs-fuzz_test_sig_stfl_xmss
build_lib() {
  oft_build_cmake -DOQS_USE_OPENSSL=OFF
  oft_build_harness "tests/fuzz_test_sig_stfl_xmss.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_test_sig_stfl_xmss
)
