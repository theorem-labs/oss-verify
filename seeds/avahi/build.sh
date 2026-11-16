#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of avahi into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-consume-key: the release's target avahi-fuzz-consume-key
(
ov_target_begin avahi-fuzz-consume-key
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-consume-key.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












build_lib() {
  oft_build_autotools --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent --disable-libsystemd --with-distro=none --with-xml=none
  oft_build_harness "fuzz/fuzz-consume-key.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-consume-key
)

# fuzz-consume-record: the release's target avahi-fuzz-consume-record
(
ov_target_begin avahi-fuzz-consume-record
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-consume-record.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












build_lib() {
  oft_build_autotools --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent --disable-libsystemd --with-distro=none --with-xml=none
  oft_build_harness "fuzz/fuzz-consume-record.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-consume-record
)

# fuzz-domain: the release's target avahi-fuzz-domain
(
ov_target_begin avahi-fuzz-domain
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-domain.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












build_lib() {
  oft_build_autotools --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent --disable-libsystemd --with-distro=none --with-xml=none
  oft_build_harness "fuzz/fuzz-domain.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-domain
)

# fuzz-ini-file-parser: the release's target avahi-fuzz-ini-file-parser
(
ov_target_begin avahi-fuzz-ini-file-parser
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-ini-file-parser.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































build_lib() {
  export PTHREAD_CFLAGS="-pthread -Wl,-z,undefs" PTHREAD_LIBS="-pthread"
  oft_build_autotools --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent --disable-libsystemd --with-distro=none --with-xml=none
  OFT_COMPANION_SRCS="../avahi-daemon/ini-file-parser.c"
  oft_build_harness "fuzz/fuzz-ini-file-parser.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-ini-file-parser
)

# fuzz-packet: the release's target avahi-fuzz-packet
(
ov_target_begin avahi-fuzz-packet
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-packet.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












build_lib() {
  oft_build_autotools --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent --disable-libsystemd --with-distro=none --with-xml=none
  oft_build_harness "fuzz/fuzz-packet.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-packet
)

# fuzz-strlst: the release's target avahi-fuzz-strlst
(
ov_target_begin avahi-fuzz-strlst
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-strlst.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












build_lib() {
  oft_build_autotools --disable-stack-protector --disable-qt3 --disable-qt4 --disable-qt5 --disable-gtk --disable-gtk3 --disable-dbus --disable-gdbm --disable-libdaemon --disable-python --disable-manpages --disable-mono --disable-monodoc --disable-glib --disable-gobject --disable-libevent --disable-libsystemd --with-distro=none --with-xml=none
  oft_build_harness "fuzz/fuzz-strlst.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz-strlst
)
