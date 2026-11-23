#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the fuzz target compress_roundtrip_full_fuzzer, which is not of the release,
# and the C library that its block builds (musl and its two patches, which sources lays out).
#
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release.
#
# Builds the fuzz targets of zlib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

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

# compress_roundtrip_full_fuzzer: not a target of the release. Its block gives it the three settings of one fuzz target
# (docs/build-contract.md): the 2^29-byte driver limit, the C library that the block builds (musl f21a9653 with the
# patches musl-0001-export-pthread-struct-size.diff and musl-0002-init-tls-check-mmap.diff, built by musl's own
# configure, make and make install), and no path rewrite. These give the bytes that its harness record pins.
# compress_roundtrip_full_fuzzer.c is copied byte for byte from Theorem Labs' internal proofs repository, where the
# fuzz target's harness record names it (projects/zlib/compress_roundtrip_full_fuzzer/source/
# compress_roundtrip_full_fuzzer.c, sha256 11910d23066ab2b686aa6f9a49098fa39c2b3479a27ee5a0c422965f8a1d7201).
# Copyright 2026 Theorem Labs, PBC. It is under MIT OR Apache-2.0. It has no licence lines of its own: a line added at
# its top would move the line numbers that its sanitizer builds hold, and so the bytes of its pinned binaries.
(
OV_PATH_REWRITE=off
ov_target_begin zlib-compress_roundtrip_full_fuzzer
ov_build_musl() {
  # Outside $BUILDDIR: oft_build_cmake merges every archive under $BUILDDIR into the target's archive.
  m=$LIBROOT/$T.musl
  rm -rf "$m"
  mkdir -p "$m/src" "$m/build"
  cp -a /work/ext/musl/src/. "$m/src/"
  for p in /work/ext/musl/series/*.diff; do
    (cd "$m/src" && patch -p1 --fuzz=0 --no-backup-if-mismatch -i "$p") || return 1
  done
  (cd "$m/build" \
    && env -u CFLAGS -u CXXFLAGS -u CPPFLAGS -u LDFLAGS -u CC -u CXX "$m/src/configure" \
         --target=riscv64-linux-musl --prefix=/usr --exec-prefix=/usr --syslibdir=/usr/lib --disable-gcc-wrapper \
         CC="clang --target=riscv64-alpine-linux-musl -fuse-ld=lld" AR=llvm-ar RANLIB=llvm-ranlib \
         CFLAGS="-march=rv64g -mabi=lp64d -ffunction-sections -fdata-sections" \
    && env -u CFLAGS -u CXXFLAGS -u CPPFLAGS -u LDFLAGS make -j"$(nproc)" \
    && env -u CFLAGS -u CXXFLAGS -u CPPFLAGS -u LDFLAGS make DESTDIR="$m/install" install) || return 1
}
build_lib() {
  ov_build_musl
  oft_build_cmake
  if [ -f "$BUILDDIR/src/zconf.h" ]; then mv "$BUILDDIR/src/zconf.h" "$BUILDDIR/src/zconf.h.included" || return 1; fi
  oft_build_harness "compress_roundtrip_full_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
export OV_MAX_INPUT_LOG2=29
export OV_LIBC="$LIBROOT/$T.musl/install/usr/lib/libc.a"
ov_target_build compress_roundtrip_full_fuzzer
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
