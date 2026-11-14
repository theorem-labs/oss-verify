#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of netcdf into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_open: the release's target netcdf-fuzz_open
(
ov_target_begin netcdf-fuzz_open
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_open.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  oft_build_cmake -DNETCDF_ENABLE_HDF5=OFF -DNETCDF_ENABLE_DAP=OFF -DNETCDF_ENABLE_REMOTE_FUNCTIONALITY=OFF -DNETCDF_ENABLE_NCZARR=OFF -DNETCDF_BUILD_UTILITIES=OFF -DNETCDF_ENABLE_EXAMPLES=OFF -DNETCDF_ENABLE_TESTS=OFF
  oft_build_harness "fuzz/fuzz_open.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_open
)
