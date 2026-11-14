#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of nettle into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_dsa_openssl_private_key_from_der: the release's target nettle-fuzz_dsa_openssl_private_key_from_der
(
ov_target_begin nettle-fuzz_dsa_openssl_private_key_from_der
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_dsa_openssl_private_key_from_der.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dsa_openssl_private_key_from_der
)

# fuzz_dsa_sha1_keypair_from_sexp: the release's target nettle-fuzz_dsa_sha1_keypair_from_sexp
(
ov_target_begin nettle-fuzz_dsa_sha1_keypair_from_sexp
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_dsa_sha1_keypair_from_sexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dsa_sha1_keypair_from_sexp
)

# fuzz_dsa_sha256_keypair_from_sexp: the release's target nettle-fuzz_dsa_sha256_keypair_from_sexp
(
ov_target_begin nettle-fuzz_dsa_sha256_keypair_from_sexp
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_dsa_sha256_keypair_from_sexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dsa_sha256_keypair_from_sexp
)

# fuzz_dsa_signature_from_sexp: the release's target nettle-fuzz_dsa_signature_from_sexp
(
ov_target_begin nettle-fuzz_dsa_signature_from_sexp
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_dsa_signature_from_sexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dsa_signature_from_sexp
)

# fuzz_rsa_keypair_from_der: the release's target nettle-fuzz_rsa_keypair_from_der
(
ov_target_begin nettle-fuzz_rsa_keypair_from_der
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_rsa_keypair_from_der.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_rsa_keypair_from_der
)

# fuzz_rsa_keypair_from_sexp: the release's target nettle-fuzz_rsa_keypair_from_sexp
(
ov_target_begin nettle-fuzz_rsa_keypair_from_sexp
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_rsa_keypair_from_sexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_rsa_keypair_from_sexp
)

# fuzz_rsa_public_key_from_der: the release's target nettle-fuzz_rsa_public_key_from_der
(
ov_target_begin nettle-fuzz_rsa_public_key_from_der
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_rsa_public_key_from_der.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_rsa_public_key_from_der
)
