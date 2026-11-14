#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wget2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libwget_bar_fuzzer: the release's target wget2-libwget_bar_fuzzer
(
ov_target_begin wget2-libwget_bar_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libwget_bar_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































































build_lib() {
  oft_build_autotools --with-ssl=gnutls \
    --without-libpsl --without-libhsts --without-libidn2 --without-libidn \
    --without-libdane --without-gpgme --without-libmicrohttpd --without-lzip
  oft_build_harness "fuzz/libwget_bar_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libwget_bar_fuzzer
)

# libwget_base64_fuzzer: the release's target wget2-libwget_base64_fuzzer
(
ov_target_begin wget2-libwget_base64_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libwget_base64_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""









































































build_lib() {
  oft_build_autotools --with-ssl=gnutls \
    --without-libpsl --without-libhsts --without-libidn2 --without-libidn \
    --without-libdane --without-gpgme --without-libmicrohttpd --without-lzip
  oft_build_harness "fuzz/libwget_base64_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libwget_base64_fuzzer
)

# libwget_cookie_fuzzer: the release's target wget2-libwget_cookie_fuzzer
(
ov_target_begin wget2-libwget_cookie_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libwget_cookie_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































































build_lib() {
  oft_build_autotools --with-ssl=gnutls \
    --without-libpsl --without-libhsts --without-libidn2 --without-libidn \
    --without-libdane --without-gpgme --without-libmicrohttpd --without-lzip
  oft_build_harness "fuzz/libwget_cookie_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libwget_cookie_fuzzer
)

# libwget_css_url_fuzzer: the release's target wget2-libwget_css_url_fuzzer
(
ov_target_begin wget2-libwget_css_url_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libwget_css_url_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































































build_lib() {
  oft_build_autotools --with-ssl=gnutls \
    --without-libpsl --without-libhsts --without-libidn2 --without-libidn \
    --without-libdane --without-gpgme --without-libmicrohttpd --without-lzip
  oft_build_harness "fuzz/libwget_css_url_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libwget_css_url_fuzzer
)

# libwget_hpkp_fuzzer: the release's target wget2-libwget_hpkp_fuzzer
(
ov_target_begin wget2-libwget_hpkp_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libwget_hpkp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































































build_lib() {
  oft_build_autotools --with-ssl=gnutls \
    --without-libpsl --without-libhsts --without-libidn2 --without-libidn \
    --without-libdane --without-gpgme --without-libmicrohttpd --without-lzip
  oft_build_harness "fuzz/libwget_hpkp_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libwget_hpkp_fuzzer
)
