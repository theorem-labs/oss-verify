#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of radvd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_config: the release's target radvd-fuzz_config
(
ov_target_begin radvd-fuzz_config
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_config.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























oft_radvd_add_loose_objects() {
  local o
  for o in util interface device-common device-linux privsep-linux recv socket send timer process; do
    [ -f "$BUILDDIR/src/$o.o" ] || { echo "oft: radvd loose object $o.o missing under $BUILDDIR/src" >&2; return 1; }
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o.o" || return 1
  done
  echo "oft: added 10 loose radvd objects (upstream build.sh OBJS + process.o) to lib/liboft.a"
}


build_lib() {
  oft_build_autotools
  oft_radvd_add_loose_objects
  oft_build_harness "fuzz_config.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_config
)

# fuzz_process: the release's target radvd-fuzz_process
(
ov_target_begin radvd-fuzz_process
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_process.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


























oft_radvd_add_loose_objects() {
  local o
  for o in util interface device-common device-linux privsep-linux recv socket send timer process; do
    [ -f "$BUILDDIR/src/$o.o" ] || { echo "oft: radvd loose object $o.o missing under $BUILDDIR/src" >&2; return 1; }
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o.o" || return 1
  done
  echo "oft: added 10 loose radvd objects (upstream build.sh OBJS + process.o) to lib/liboft.a"
}










oft_seal_radvd_ifname() {
  local obj="$BUILDDIR/seal_radvd_ifname.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/radvd-fuzz_process/seal_extra.c -o "$obj" || return 1
  "$CHOST-nm" "$obj" | grep -q ' T if_indextoname$' || {
    echo "oft: seal_radvd_ifname.o defines no if_indextoname" >&2; return 1; }
  LIB_EXTRA="${LIB_EXTRA:-} $obj"
}



build_lib() {
  oft_build_autotools
  oft_radvd_add_loose_objects
  oft_build_harness "fuzz_process.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_seal_radvd_ifname
}
ov_target_build fuzz_process
)
