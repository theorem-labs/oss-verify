#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of systemd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-bus-label: the release's target systemd-fuzz-bus-label
(
ov_target_begin systemd-fuzz-bus-label
build_lib() {
  oft_build_meson -Dlibc=musl
  oft_build_harness "src/fuzz/fuzz-bus-label.c" -include "$BUILDDIR/mes/config.h" -DTEST_CODE=1
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-bus-label
)
