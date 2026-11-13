#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libsodium into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# crypto_aead_fuzzer: the release's target libsodium-crypto_aead_fuzzer
(
ov_target_begin libsodium-crypto_aead_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "crypto_aead_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build crypto_aead_fuzzer
)

# crypto_box_fuzzer: the release's target libsodium-crypto_box_fuzzer
(
ov_target_begin libsodium-crypto_box_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "crypto_box_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build crypto_box_fuzzer
)

# crypto_generichash_fuzzer: the release's target libsodium-crypto_generichash_fuzzer
(
ov_target_begin libsodium-crypto_generichash_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "crypto_generichash_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build crypto_generichash_fuzzer
)

# crypto_kdf_fuzzer: the release's target libsodium-crypto_kdf_fuzzer
(
ov_target_begin libsodium-crypto_kdf_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "crypto_kdf_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build crypto_kdf_fuzzer
)

# crypto_kx_fuzzer: the release's target libsodium-crypto_kx_fuzzer
(
ov_target_begin libsodium-crypto_kx_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "crypto_kx_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build crypto_kx_fuzzer
)

# crypto_sign_fuzzer: the release's target libsodium-crypto_sign_fuzzer
(
ov_target_begin libsodium-crypto_sign_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "crypto_sign_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build crypto_sign_fuzzer
)

# secret_key_auth_fuzzer: the release's target libsodium-secret_key_auth_fuzzer
(
ov_target_begin libsodium-secret_key_auth_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "secret_key_auth_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build secret_key_auth_fuzzer
)

# secretbox_easy_fuzzer: the release's target libsodium-secretbox_easy_fuzzer
(
ov_target_begin libsodium-secretbox_easy_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "secretbox_easy_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build secretbox_easy_fuzzer
)
