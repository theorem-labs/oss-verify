#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ostree into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-bootconfig: the release's target ostree-fuzz-bootconfig
(
ov_target_begin ostree-fuzz-bootconfig
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz-bootconfig.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















































build_lib() {
  export CPPFLAGS="${CPPFLAGS:-} -include stdint.h"
  export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include -I/opt/musl-sysroot/usr/include/gio-unix-2.0 -I$BUILDDIR/src -I$BUILDDIR/src/src/libostree -I$BUILDDIR/src/libglnx"
  oft_build_autotools --without-gpgme --disable-rofiles-fuse --disable-man \
    --without-libsystemd --without-libarchive
  oft_build_harness "fuzz-bootconfig.c" -include glib/gstdio.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-bootconfig
)

# fuzz-bsdiff: the release's target ostree-fuzz-bsdiff
(
ov_target_begin ostree-fuzz-bsdiff
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz-bsdiff.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  export CPPFLAGS="${CPPFLAGS:-} -include stdint.h"
  export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include -I/opt/musl-sysroot/usr/include/gio-unix-2.0 -I$BUILDDIR/src -I$BUILDDIR/src/src/libostree -I$BUILDDIR/src/libglnx"
  oft_build_autotools --without-gpgme --disable-rofiles-fuse --disable-man \
    --without-libsystemd --without-libarchive
  oft_build_harness "fuzz-bsdiff.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-bsdiff
)

# fuzz-content-stream: the release's target ostree-fuzz-content-stream
(
ov_target_begin ostree-fuzz-content-stream
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz-content-stream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  export CPPFLAGS="${CPPFLAGS:-} -include stdint.h"
  export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include -I/opt/musl-sysroot/usr/include/gio-unix-2.0 -I$BUILDDIR/src -I$BUILDDIR/src/src/libostree -I$BUILDDIR/src/libglnx"
  oft_build_autotools --without-gpgme --disable-rofiles-fuse --disable-man \
    --without-libsystemd --without-libarchive
  oft_build_harness "fuzz-content-stream.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-content-stream
)

# fuzz-repo: the release's target ostree-fuzz-repo
(
ov_target_begin ostree-fuzz-repo
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz-repo.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  export CPPFLAGS="${CPPFLAGS:-} -include stdint.h"
  export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include -I/opt/musl-sysroot/usr/include/gio-unix-2.0 -I$BUILDDIR/src -I$BUILDDIR/src/src/libostree -I$BUILDDIR/src/libglnx"
  oft_build_autotools --without-gpgme --disable-rofiles-fuse --disable-man \
    --without-libsystemd --without-libarchive
  oft_build_harness "fuzz-repo.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-repo
)

# fuzz-rfc2616-date: the release's target ostree-fuzz-rfc2616-date
(
ov_target_begin ostree-fuzz-rfc2616-date
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz-rfc2616-date.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  export CPPFLAGS="${CPPFLAGS:-} -include stdint.h"
  export OFT_HARNESS_CFLAGS="-I/opt/musl-sysroot/usr/include/glib-2.0 -I/opt/musl-sysroot/usr/lib/glib-2.0/include -I/opt/musl-sysroot/usr/include/gio-unix-2.0 -I$BUILDDIR/src -I$BUILDDIR/src/src/libostree -I$BUILDDIR/src/libglnx"
  oft_build_autotools --without-gpgme --disable-rofiles-fuse --disable-man \
    --without-libsystemd --without-libarchive
  oft_build_harness "fuzz-rfc2616-date.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-rfc2616-date
)
