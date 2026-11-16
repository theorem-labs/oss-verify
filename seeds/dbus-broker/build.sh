#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of dbus-broker into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-message: the release's target dbus-broker-fuzz-message
(
ov_target_begin dbus-broker-fuzz-message
build_lib() {
  oft_build_meson
  oft_build_harness "fuzz-message.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""









































































































export OFT_HARNESS_CFLAGS="-include sys/uio.h"
build_lib() {
  oft_build_meson -Dlauncher=false --wrap-mode=nodownload
  oft_build_harness "fuzz-message.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
subprojects/libcdvar-1 sha256:95e0cb8360c24217335c543e46b12fe42c531934463a025a48c3e823f8bcbe56 https://github.com/c-util/c-dvar/archive/8bd67b1659b289d3b7d2726a9ac68f89b7fd30f1.tar.gz 1
subprojects/libcini-1 sha256:39ada0566dbc3d2a8102c63f89897ed766e1a3872b1656d858c882d6ccbcde3b https://github.com/c-util/c-ini/archive/d08d5edeaee9127e72bc1c1f20aca3a63bb880fb.tar.gz 1
subprojects/libclist-3 sha256:8a577dc86a9dd0cf88e38d4f7da43603449981e0166b8b73df3ec47eea896e9d https://github.com/c-util/c-list/archive/9aa81d84cadc67e92b441c89f84c57e72dd1e8a9.tar.gz 1
subprojects/libcrbtree-3 sha256:f627fdd274749784e8a72201b895e8ba870015fc9d563dc1cf311cc6c216abd4 https://github.com/c-util/c-rbtree/archive/2567be09d6249b8d8e601ff5cc4dada5c899512f.tar.gz 1
subprojects/libcshquote-1 sha256:b8bf4331bb367dc13db6d2159803038c302efd64bada87b3b56b82a661383308 https://github.com/c-util/c-shquote/archive/c4d0c851126c43eb52a1d7b0063429a79f7579d3.tar.gz 1
subprojects/libcstdaux-1 sha256:b5c338613fb8163afa6f5198e67d8ff7129b3f6873accad94ab2078197c46e81 https://github.com/c-util/c-stdaux/archive/652caf87acbcad55fefd01023a12f370ba124e05.tar.gz 1
subprojects/libcutf8-1 sha256:cb9fdc5bb4f1bc2d2cb6b44323861fb7930b00b6cd7aba319776370abf984c40 https://github.com/c-util/c-utf8/archive/aab553d293bbffa42f34dc966be61313d9433c2f.tar.gz 1
"
ov_target_build fuzz-message
)
