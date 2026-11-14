#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of nccl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_xml: the release's target nccl-fuzz_xml
(
ov_target_begin nccl-fuzz_xml
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz_xml.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































































































OFT_CXX_STD="-std=gnu++17"
OFT_HARNESS_CFLAGS="-DNCCL_OS_LINUX -fno-c++-static-destructors -I/work/targets/nccl-fuzz_xml/cuda_stub -I$BUILDDIR/include"







oft_nccl_build_lib() {
  local S="$BUILDDIR/src" O="$BUILDDIR/obj-nccl"
  mkdir -p "$O" "$BUILDDIR/include" "$BUILDDIR/lib"

  local vmk="$S/makefiles/version.mk" maj min pat suf ver
  maj=$(sed -n 's/^NCCL_MAJOR *:= *//p' "$vmk")
  min=$(sed -n 's/^NCCL_MINOR *:= *//p' "$vmk")
  pat=$(sed -n 's/^NCCL_PATCH *:= *//p' "$vmk")
  suf=$(sed -n 's/^NCCL_SUFFIX *:= *//p' "$vmk")
  if [ -z "$maj" ] || [ -z "$min" ] || [ -z "$pat" ]; then
    echo "oft: could not parse NCCL version from $vmk" >&2; return 1
  fi
  ver=$(printf '%d%02d%02d' "$maj" "$min" "$pat")
  sed -e 's/${nccl:Major}/'"$maj"'/g' \
      -e 's/${nccl:Minor}/'"$min"'/g' \
      -e 's/${nccl:Patch}/'"$pat"'/g' \
      -e 's/${nccl:Suffix}/'"$suf"'/g' \
      -e 's/${nccl:Version}/'"$ver"'/g' \
      "$S/src/nccl.h.in" > "$BUILDDIR/include/nccl.h"
  echo "oft: generated nccl.h version $ver"
  local inc="-I/work/targets/nccl-fuzz_xml/cuda_stub -I$BUILDDIR/include"
  inc="$inc -I$S/src/include -I$S/src/include/plugin -I$S/src/graph"
  local tu n extra src
  for tu in src/graph/xml.cc src/debug.cc src/misc/utils.cc src/os/linux.cc \
            src/misc/nvmlwrap.cc src/misc/param.cc src/misc/socket.cc \
            src/param/param_registry.cc src/param/param.cc src/plugin/env.cc \
            src/plugin/env/default_env.cc src/plugin/env/env_v1.cc \
            src/plugin/env/env_v2.cc src/plugin/plugin_open.cc \
            /work/targets/nccl-fuzz_xml/oft_shim.cc; do
    case "$tu" in
      /*) src="$tu" ;;
      *)  src="$S/$tu" ;;
    esac
    [ -f "$src" ] || { echo "oft: missing TU $src" >&2; return 1; }
    n=$(echo "$tu" | tr / _)


    extra=""
    [ "$tu" = "src/plugin/env.cc" ] && extra="-include strings.h"

    "$CC" $CFLAGS -x c++ -stdlib=libc++ -std=gnu++17 -fno-c++-static-destructors \
      -DNCCL_OS_LINUX -w $inc $extra -c "$src" -o "$O/${n%.cc}.o" || {
      echo "oft: compile failed: $tu" >&2; return 1; }
  done
  "$CHOST-ar" rcs "$BUILDDIR/lib/liboft.a" "$O"/*.o || return 1


  "$CHOST-nm" "$BUILDDIR/lib/liboft.a" | grep -q ' T .*ncclTopoGetXmlFromFile' || {
    echo "oft: liboft.a defines no ncclTopoGetXmlFromFile" >&2; return 1; }
}







oft_seal_nccl_extra() {
  local obj="$BUILDDIR/seal_nccl_extra.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/nccl-fuzz_xml/seal_extra.c -o "$obj" || return 1
  local sym
  for sym in ' T clock_gettime$' ' T uname$' ' T unlink$'; do
    "$CHOST-nm" "$obj" | grep -q "$sym" || {
      echo "oft: seal_extra.o missing expected symbol $sym" >&2; return 1; }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $obj"
}
build_lib() {
  oft_require_target_cxx
  oft_copy_src
  oft_nccl_build_lib || return 1
  oft_build_harness "fuzz_xml.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_seal_nccl_extra
}
ov_target_build fuzz_xml
)
