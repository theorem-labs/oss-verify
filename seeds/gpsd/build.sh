#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of gpsd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# FuzzClient: the release's target gpsd-FuzzClient
(
ov_target_begin gpsd-FuzzClient
build_lib() {
  oft_build_blind
  oft_build_harness "FuzzClient.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" AR="$CHOST-ar" CFLAGS="$CFLAGS" \
       scons -j"$(oft_jobs)" python=no shared=no manbuild=no qt=no \
         libgpsmm=no usb=no bluez=no ncurses=no dbus_export=no \
         gpsd_user=root gpsd_group=root \
         gpsd-3.27.6~dev/libgps_static.a gpsd-3.27.6~dev/libgpsd.a ) \
    || { echo "oft: scons failed to build libgps_static.a/libgpsd.a" >&2; return 1; }
  oft_merge_archives
  oft_build_harness "FuzzClient.c" -D_GNU_SOURCE -include string.h \
    -I"$BUILDDIR/src/gpsd-3.27.6~dev/include"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzClient
)

# FuzzDrivers: the release's target gpsd-FuzzDrivers
(
ov_target_begin gpsd-FuzzDrivers
build_lib() {
  oft_build_blind
  oft_build_harness "FuzzDrivers.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" AR="$CHOST-ar" CFLAGS="$CFLAGS" \
       scons -j"$(oft_jobs)" python=no shared=no manbuild=no qt=no \
         libgpsmm=no usb=no bluez=no ncurses=no dbus_export=no \
         gpsd_user=root gpsd_group=root \
         gpsd-3.27.6~dev/libgps_static.a gpsd-3.27.6~dev/libgpsd.a ) \
    || { echo "oft: scons failed to build libgps_static.a/libgpsd.a" >&2; return 1; }
  oft_merge_archives
  oft_build_harness "FuzzDrivers.c" -D_GNU_SOURCE -include string.h \
    -I"$BUILDDIR/src/gpsd-3.27.6~dev/include"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzDrivers
)

# FuzzDriversStructured: the release's target gpsd-FuzzDriversStructured
(
ov_target_begin gpsd-FuzzDriversStructured
build_lib() {
  oft_build_blind
  oft_build_harness "FuzzDriversStructured.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" AR="$CHOST-ar" CFLAGS="$CFLAGS" \
       scons -j"$(oft_jobs)" python=no shared=no manbuild=no qt=no \
         libgpsmm=no usb=no bluez=no ncurses=no dbus_export=no \
         gpsd_user=root gpsd_group=root \
         gpsd-3.27.6~dev/libgps_static.a gpsd-3.27.6~dev/libgpsd.a ) \
    || { echo "oft: scons failed to build libgps_static.a/libgpsd.a" >&2; return 1; }
  oft_merge_archives
  oft_build_harness "FuzzDriversStructured.c" -D_GNU_SOURCE -include string.h \
    -I"$BUILDDIR/src/gpsd-3.27.6~dev/include"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzDriversStructured
)

# FuzzJson: the release's target gpsd-FuzzJson
(
ov_target_begin gpsd-FuzzJson
build_lib() {
  oft_build_blind
  oft_build_harness "FuzzJson.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" AR="$CHOST-ar" CFLAGS="$CFLAGS" \
       scons -j"$(oft_jobs)" python=no shared=no manbuild=no qt=no \
         libgpsmm=no usb=no bluez=no ncurses=no dbus_export=no \
         gpsd_user=root gpsd_group=root \
         gpsd-3.27.6~dev/libgps_static.a gpsd-3.27.6~dev/libgpsd.a ) \
    || { echo "oft: scons failed to build libgps_static.a/libgpsd.a" >&2; return 1; }
  oft_merge_archives
  oft_build_harness "FuzzJson.c" -D_GNU_SOURCE -include string.h \
    -I"$BUILDDIR/src/gpsd-3.27.6~dev/include"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzJson
)

# FuzzPacket: the release's target gpsd-FuzzPacket
(
ov_target_begin gpsd-FuzzPacket
build_lib() {
  oft_build_blind
  oft_build_harness "FuzzPacket.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


















































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" AR="$CHOST-ar" CFLAGS="$CFLAGS" \
       scons -j"$(oft_jobs)" python=no shared=no manbuild=no qt=no \
         libgpsmm=no usb=no bluez=no ncurses=no dbus_export=no \
         gpsd_user=root gpsd_group=root \
         gpsd-3.27.6~dev/libgps_static.a gpsd-3.27.6~dev/libgpsd.a ) \
    || { echo "oft: scons failed to build libgps_static.a/libgpsd.a" >&2; return 1; }
  oft_merge_archives
  oft_build_harness "FuzzPacket.c" -D_GNU_SOURCE -include string.h \
    -I"$BUILDDIR/src/gpsd-3.27.6~dev/include"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build FuzzPacket
)
