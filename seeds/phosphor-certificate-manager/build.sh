#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of phosphor-certificate-manager into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# parse_cert_fuzzer: the release's target phosphor-certificate-manager-parse_cert_fuzzer
(
ov_target_begin phosphor-certificate-manager-parse_cert_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "parse_cert_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































AUX_REPOS="
src/subprojects/CLI11 https://github.com/CLIUtils/CLI11.git c1cfe00d2f3d862aecfe6e69ec810414d5f4c906
src/subprojects/phosphor-dbus-interfaces https://github.com/openbmc/phosphor-dbus-interfaces.git 5ad64945d177b76dc68f93ca0c16b4defdd04729
src/subprojects/phosphor-logging https://github.com/openbmc/phosphor-logging.git 84993d25a70b01a84ef13303fdb6190c3c5c1a2a
src/subprojects/sdbusplus https://github.com/openbmc/sdbusplus.git 2af34c3f50ff8488bfcddbfc394aaaaaabf2e00d
src/subprojects/sdeventplus https://github.com/openbmc/sdeventplus.git 857171a82d6cb3c098c99a94ecb043118963ecc9
src/subprojects/stdexec https://github.com/NVIDIA/stdexec d48726ba2c33fb4cd764b56ea33721bed4ee0415
src/subprojects/stdplus https://github.com/openbmc/stdplus.git 9b9648d459c0b42fe5fee4cb92e47c0e28050e9e
"
oft_phosphor_sdbusplus_unistd() {
  local f="$SRCDIR/subprojects/sdbusplus/include/sdbusplus/event.hpp" tmp="$BUILDDIR/oft-sdbusplus-event.hpp" l1
  local line='#include <unistd.h>                                                                                                                     '
  [ -f "$f" ] || { echo "oft: phosphor: no $f -- AUX_REPOS fetches sdbusplus; re-fetch" >&2; return 1; }
  if ! l1=$(head -n 1 "$f") || [ "${l1#'#include <unistd.h>        '}" = "$l1" ]; then
    mkdir -p "$BUILDDIR"
    { printf '%s\n' "$line"; cat "$f"; } > "$tmp" && cat "$tmp" > "$f" || return 1
    echo "oft: phosphor: sdbusplus event.hpp gains the <unistd.h> include"
  fi
}
build_lib() {
  oft_require_target_cxx
  oft_phosphor_sdbusplus_unistd || return 1
  local _oft_saved_cflags="$CFLAGS"
  CFLAGS="$CFLAGS -Wno-c99-extensions -Wno-pessimizing-move"
  oft_build_meson \
    -Dtests=disabled \
    -Dphosphor-logging:libonly=true \
    -Dphosphor-logging:tests=disabled \
    -Dsdbusplus:tests=disabled \
    -Dsdbusplus:examples=disabled \
    -Dstdplus:tests=disabled \
    -Dstdplus:examples=false \
    -Dsdeventplus:tests=disabled \
    -Dsdeventplus:examples=false \
    -DCLI11:tests=disabled
  CFLAGS="$_oft_saved_cflags"
  oft_build_harness "parse_cert_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse_cert_fuzzer
)
