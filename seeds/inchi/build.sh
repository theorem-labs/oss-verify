#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of inchi into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# molfile_fuzzer: the release's target inchi-molfile_fuzzer
(
ov_target_begin inchi-molfile_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "molfile_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




























































































build_lib() {
  rm -rf -- "${BUILDDIR:?}/src-patched"
  mkdir -p "${BUILDDIR:?}/src-patched"
  cp -a "${SRCDIR:?}/." "${BUILDDIR:?}/src-patched/"
  oft_inchi_cml="${BUILDDIR:?}/src-patched/INCHI-1-SRC/INCHI_API/libinchi/src/CMakeLists.txt"
  grep -qF 'add_library(libinchi SHARED)' "$oft_inchi_cml" \
    || { echo "oft: inchi add_library(libinchi SHARED) not where this pin expects it; refusing" >&2; return 1; }
  sed -i 's/^add_library(libinchi SHARED)$/add_library(libinchi STATIC)/' "$oft_inchi_cml"
  test -f "${BUILDDIR:?}/src-patched/oft-vendor/googletest/CMakeLists.txt" \
    || { echo "oft: inchi vendored googletest (oft-vendor/googletest) missing from the src tree; refusing" >&2; return 1; }
  oft_inchi_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="${BUILDDIR:?}/src/oft-vendor/googletest"
  SRCDIR=$oft_inchi_srcdir_orig
  oft_build_harness "molfile_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}








































VENDOR_TREES="
oft-vendor/googletest sha256:65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz 1
"
ov_target_build molfile_fuzzer
)
