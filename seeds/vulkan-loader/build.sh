#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of vulkan-loader into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# json_load_fuzzer: the release's target vulkan-loader-json_load_fuzzer
(
ov_target_begin vulkan-loader-json_load_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "json_load_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































































































build_lib() {



  local vhsrc="${SRCDIR:?}/oft-vendor/vulkan-headers"
  if [ ! -f "$vhsrc/include/vulkan/vulkan_core.h" ]; then
    echo "oft: vendored Vulkan-Headers missing at $vhsrc -- recreate it with the" \
         "curl/sha256sum/tar commands this pin gives" >&2
    return 1
  fi
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake"
  rm -rf "$BUILDDIR/vh-bld"
  mkdir -p "$BUILDDIR/vh-bld"
  ( cd "$BUILDDIR/vh-bld" \
    && cmake "$vhsrc" \
         -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX="${OFT_PREFIX:?}" \
         -DVULKAN_HEADERS_ENABLE_TESTS=OFF \
         -DVULKAN_HEADERS_ENABLE_MODULE=OFF \
    && make install )
  oft_build_cmake \
    -DCMAKE_PREFIX_PATH="$BUILDDIR" \
    -DBUILD_WSI_XCB_SUPPORT=OFF \
    -DBUILD_WSI_XLIB_SUPPORT=OFF \
    -DBUILD_WSI_XLIB_XRANDR_SUPPORT=OFF \
    -DBUILD_WSI_WAYLAND_SUPPORT=OFF
  OFT_HARNESS_CFLAGS="-include loader_json.h"
  oft_build_harness "json_load_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}















































VENDOR_TREES="
oft-vendor/vulkan-headers sha256:efe79256adb6f2a5112bdcd03712d3aeb59a2e1a54a9e97650223dfe57b12067 https://github.com/KhronosGroup/Vulkan-Headers/archive/31386378257ac8653ce5b32c93baec385259ebbe.tar.gz 1
"
ov_target_build json_load_fuzzer
)
