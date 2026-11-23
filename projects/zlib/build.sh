#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the DSL fuzz targets api-driver and sysfail_fuzzer, which are not of the release.
#
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release.
#
# Builds the fuzz targets of zlib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# api-driver: not a target of the release. A DSL fuzz target (docs/build-contract.md, "DSL fuzz targets"): the input is
# a script of zlib calls that api-driver.dsl.c runs on live streams. Its tree is checksum_fuzzer's, with the same patch.
# zlib's allocations go to tramp_alloc.c's trampolines through api-driver.tramp_alloc.redefs, so the input's allocation
# mask makes them fail. The map renames the driver object too (OV_DSL_REDEFS), for the code it compiles from zlib's
# headers; the driver's own arena calls tramp_alloc_raw_malloc, which no map renames, so it is on no schedule. As zlib
# 1.4's CMake no longer does, the block moves the source tree's zconf.h aside, so that the driver compiles against the
# configured one.
(
ov_target_begin zlib-api-driver
build_lib() {
  oft_build_cmake
  if [ -f "$BUILDDIR/src/zconf.h" ]; then mv "$BUILDDIR/src/zconf.h" "$BUILDDIR/src/zconf.h.included" || return 1; fi
  ov_dsl_driver dsl.c
  ov_dsl_trampoline tramp_alloc.c
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
export OV_DSL_REDEFS="/work/targets/$T/tramp_alloc.redefs"
ov_target_build_dsl api-driver
)

# checksum_fuzzer: the release's target zlib-checksum_fuzzer
(
ov_target_begin zlib-checksum_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "checksum_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build checksum_fuzzer
)

# compress_fuzzer: the release's target zlib-compress_fuzzer
(
ov_target_begin zlib-compress_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "compress_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build compress_fuzzer
)

# example_dict_fuzzer: the release's target zlib-example_dict_fuzzer
(
ov_target_begin zlib-example_dict_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "example_dict_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build example_dict_fuzzer
)

# example_flush_fuzzer: the release's target zlib-example_flush_fuzzer
(
ov_target_begin zlib-example_flush_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "example_flush_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build example_flush_fuzzer
)

# example_large_fuzzer: the release's target zlib-example_large_fuzzer
(
ov_target_begin zlib-example_large_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "example_large_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build example_large_fuzzer
)

# example_small_fuzzer: the release's target zlib-example_small_fuzzer
(
ov_target_begin zlib-example_small_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "example_small_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build example_small_fuzzer
)

# gzio_fuzzer: the release's target zlib-gzio_fuzzer
(
ov_target_begin zlib-gzio_fuzzer
build_lib() {
  oft_build_cmake
  # gzio_fuzzer.c calls close(), which is declared in unistd.h; zlib 1.4's headers do not include it.
  OFT_HARNESS_CFLAGS="-include unistd.h" oft_build_harness "gzio_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build gzio_fuzzer
)

# minigzip_fuzzer: the release's target zlib-minigzip_fuzzer
(
ov_target_begin zlib-minigzip_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "minigzip_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build minigzip_fuzzer
)

# sysfail_fuzzer: not a target of the release. A DSL fuzz target, api-driver's driver with 31 more operations: zlib's
# gz file functions over one file in memory, whose open, read, write, lseek, close and fcntl calls fail as the script
# tells them to. Its own tree carries the inflate fix of madler/zlib #1390 and three fixes of zlib's gz layer
# (zlib-sysfail_fuzzer.0002 to 0004). zlib's allocations go to tramp_alloc.c's trampolines
# (sysfail_fuzzer.tramp_alloc.redefs), which rename the driver object too, while the driver's own arena is on no
# schedule (it calls tramp_alloc_raw_malloc); and zlib's six system calls, in zlib alone, to tramp_sys.c's
# (sysfail_fuzzer.tramp_sys.redefs). Each other function that zlib calls is a line of sysfail_fuzzer.sys.allow.
(
ov_target_begin zlib-sysfail_fuzzer
build_lib() {
  oft_build_cmake
  if [ -f "$BUILDDIR/src/zconf.h" ]; then mv "$BUILDDIR/src/zconf.h" "$BUILDDIR/src/zconf.h.included" || return 1; fi
  ov_dsl_driver dsl.c
  ov_dsl_trampoline tramp_alloc.c
  ov_dsl_trampoline tramp_sys.c
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
export OV_DSL_REDEFS="/work/targets/$T/tramp_alloc.redefs"
export OV_DSL_LIBRARY_REDEFS="/work/targets/$T/tramp_sys.redefs"
export OV_DSL_ALLOW="/work/targets/$T/sys.allow"
ov_target_build_dsl sysfail_fuzzer
)

# zlib_uncompress2_fuzzer: the release's target zlib-zlib_uncompress2_fuzzer
(
ov_target_begin zlib-zlib_uncompress2_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "zlib_uncompress2_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zlib_uncompress2_fuzzer
)

# zlib_uncompress3_fuzzer: the release's target zlib-zlib_uncompress3_fuzzer
(
ov_target_begin zlib-zlib_uncompress3_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "zlib_uncompress3_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zlib_uncompress3_fuzzer
)

# zlib_uncompress_fuzzer: the release's target zlib-zlib_uncompress_fuzzer
(
ov_target_begin zlib-zlib_uncompress_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "zlib_uncompress_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build zlib_uncompress_fuzzer
)
