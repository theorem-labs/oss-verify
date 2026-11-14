#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of opusfile into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# opusfile_fuzzer: the release's target opusfile-opusfile_fuzzer
(
ov_target_begin opusfile-opusfile_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "opusfile_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""














































































































oft_build_opus_dep() {
  local osrc="$SRCDIR/oft-vendor/opus" oprefix="$BUILDDIR/opus-prefix"
  [ -d "$osrc" ] || { echo "oft: missing vendored opus tree at $osrc (the pin vendors it from the opus release tarball)" >&2; return 1; }
  [ -f "$osrc/package_version" ] || { echo "oft: $osrc/package_version missing -- opus's cmake would fall back to git or version 0" >&2; return 1; }
  [ ! -e "$osrc/.git" ] || { echo "oft: $osrc/.git exists -- opus's cmake would read the version from git here and from package_version in a tree without .git (vendor from the tarball, not a clone)" >&2; return 1; }
  rm -rf -- "${BUILDDIR:?}/opus-cmk" "${BUILDDIR:?}/opus-prefix"
  mkdir -p "$BUILDDIR/opus-cmk"
  oft_cmake_toolchain "$BUILDDIR/opus-toolchain.cmake"
  ( cd "$BUILDDIR/opus-cmk" \
    && cmake "$osrc" \
         -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/opus-toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX="$oprefix" \
         -DCMAKE_INSTALL_LIBDIR=lib \
         -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
         -DOPUS_BUILD_TESTING=OFF -DOPUS_BUILD_PROGRAMS=OFF \
    && make -j"$(oft_jobs)" install )
}





















OFT_HARNESS_CFLAGS="-I$BUILDDIR/srcroot -I$BUILDDIR/opus-prefix/include/opus"







build_lib() {
  oft_build_opus_dep
  oft_build_cmake \
    -DCMAKE_PREFIX_PATH="$BUILDDIR/opus-prefix" \
    -DOpus_DIR="$BUILDDIR/opus-prefix/lib/cmake/Opus" \
    -DOP_DISABLE_HTTP=ON -DOP_DISABLE_EXAMPLES=ON -DOP_DISABLE_DOCS=ON
  mkdir -p "$BUILDDIR/srcroot"
  ln -sfn "$BUILDDIR/src" "$BUILDDIR/srcroot/opusfile"
  : > "$BUILDDIR/src/config.h"
  oft_build_harness "opusfile_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}

































VENDOR_TREES="
oft-vendor/opus sha256:bff0afd729477dc60a2a0920b23bf7ef6060720ed2bcb5c8c87d1ba928eca234 https://gitlab.xiph.org/xiph/opus/-/archive/3704fb816bc8d299eaa2ff2879070b790edf6f5e/opus-3704fb816bc8d299eaa2ff2879070b790edf6f5e.tar.gz 1
"
ov_target_build opusfile_fuzzer
)
