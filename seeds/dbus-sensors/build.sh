#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of dbus-sensors into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# utils_fuzzer: the release's target dbus-sensors-utils_fuzzer
(
ov_target_begin dbus-sensors-utils_fuzzer dbus-sensors-dep-sdbusplus phosphor-host-ipmid-hdrs-logging
ov_target_dependency dbus-sensors-dep-sdbusplus <<'OV_PIN_END'
build_lib() {
  oft_require_target_cxx
  mkdir -p "$BUILDDIR/include" "$BUILDDIR/lib" "$BUILDDIR/obj"
  rm -rf "$BUILDDIR/include/sdbusplus"
  cp -R "$SRCDIR/include/sdbusplus" "$BUILDDIR/include/"
  sed -i 's/std::move_only_function/std::function/g' \
    "$BUILDDIR/include/sdbusplus/asio/connection.hpp"
  sed -i '1s/^/#include <unistd.h>\n/' "$BUILDDIR/include/sdbusplus/event.hpp"
  grep -q 'std::move_only_function' "$BUILDDIR/include/sdbusplus/asio/connection.hpp" && {
    echo "oft: dep-sdbusplus: move_only_function sed did not take" >&2; return 1; }
  rm -f "$BUILDDIR/lib/libsdbusplus.a"
  local f o n=0
  for f in bus.cpp bus/match.cpp event.cpp exception.cpp message/native_types.cpp \
           sdbus.cpp server/interface.cpp server/transaction.cpp; do
    o="$BUILDDIR/obj/sdbusplus_$(echo "$f" | tr '/' '_' | sed 's/\.cpp$/.o/')"

    "$(oft_cxx)" $(oft_cxxflags) -std=c++23 -Wno-c++26-extensions \
      -D_GNU_SOURCE -DBOOST_ALLOW_DEPRECATED_HEADERS -DBOOST_ASIO_DISABLE_THREADS \
      -I"$BUILDDIR/include" -c "$SRCDIR/src/$f" -o "$o" || {
      echo "oft: dep-sdbusplus: $f failed to compile" >&2; return 1; }
    n=$((n + 1))
  done
  [ "$n" = 8 ] || { echo "oft: dep-sdbusplus: expected 8 objects, compiled $n" >&2; return 1; }
  "$CHOST-ar" crs "$BUILDDIR/lib/libsdbusplus.a" "$BUILDDIR"/obj/sdbusplus_*.o || return 1
  echo "oft: dep-sdbusplus: $n TUs in lib/libsdbusplus.a"
}
OV_PIN_END
ov_target_dependency phosphor-host-ipmid-hdrs-logging <<'OV_PIN_END'
build_lib() {
  mkdir -p "$BUILDDIR/include"
  cp -R "$SRCDIR/lib/include/phosphor-logging" "$BUILDDIR/include/"
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "utils_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































DEPENDS="dbus-sensors-dep-sdbusplus phosphor-host-ipmid-hdrs-logging"
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  mkdir -p "$BUILDDIR/include"
  cp -R "$LIBROOT/phosphor-host-ipmid-hdrs-logging/include/." "$BUILDDIR/include/"
  cp -R "$LIBROOT/dbus-sensors-dep-sdbusplus/include/." "$BUILDDIR/include/"
  printf '#pragma once\nconstexpr const int validateUnsecureFeature = 0;\nconstexpr const int insecureSensorOverride = 0;\n' \
    > "$BUILDDIR/src/src/dbus-sensor_config.h"
  local defs="-D_GNU_SOURCE -DBOOST_ALLOW_DEPRECATED_HEADERS -DBOOST_ASIO_DISABLE_THREADS"
  local f n=0
  for f in Utils Thresholds SensorPaths DeviceMgmt FileHandle; do

    "$(oft_cxx)" $(oft_cxxflags) -std=c++23 $defs \
      -I"$BUILDDIR/src/src" -I"$BUILDDIR/src/include" -I"$BUILDDIR/include" \
      -c "$BUILDDIR/src/src/$f.cpp" -o "$BUILDDIR/dbs-$f.o" || {
      echo "oft: dbus-sensors: $f.cpp failed to compile" >&2; return 1; }
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/dbs-$f.o" || return 1
    n=$((n + 1))
  done
  [ "$n" = 5 ] || { echo "oft: dbus-sensors: expected 5 project TUs, got $n" >&2; return 1; }




  rm -rf "$BUILDDIR/sdbusplus-objs"; mkdir -p "$BUILDDIR/sdbusplus-objs"
  ( cd "$BUILDDIR/sdbusplus-objs" && \
    "$CHOST-ar" x "$LIBROOT/dbus-sensors-dep-sdbusplus/lib/libsdbusplus.a" ) || return 1
  n=$(ls "$BUILDDIR"/sdbusplus-objs/sdbusplus_*.o | wc -l)
  [ "$n" = 8 ] || { echo "oft: dbus-sensors: expected 8 sdbusplus members, got $n" >&2; return 1; }
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR"/sdbusplus-objs/sdbusplus_*.o || return 1
  OFT_CXX_STD="-std=c++23"
  OFT_HARNESS_CFLAGS="$defs -I$BUILDDIR/src/src"
  OFT_COMPANION_SRCS="lg2_stub.cpp"
  oft_build_harness "utils_fuzzer.cpp"
  oft_add_sysroot_deps
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_seal_prctl_capbset
}









oft_seal_prctl_capbset() {
  local obj="$BUILDDIR/seal_prctl.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c \
    /work/targets/dbus-sensors-utils_fuzzer/seal_prctl.c -o "$obj" || return 1
  "$CHOST-nm" "$obj" | grep -q ' T prctl$' || {
    echo "oft: seal_prctl.o defines no strong prctl" >&2; return 1; }
  LIB_EXTRA="${LIB_EXTRA:-} $obj"
}
ov_target_build utils_fuzzer
)
