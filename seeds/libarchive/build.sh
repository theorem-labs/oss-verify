#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libarchive into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libarchive_7zip_fuzzer: the release's target libarchive-libarchive_7zip_fuzzer
(
ov_target_begin libarchive-libarchive_7zip_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_7zip_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_7zip_fuzzer
)

# libarchive_ar_fuzzer: the release's target libarchive-libarchive_ar_fuzzer
(
ov_target_begin libarchive-libarchive_ar_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_ar_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_ar_fuzzer
)

# libarchive_cab_fuzzer: the release's target libarchive-libarchive_cab_fuzzer
(
ov_target_begin libarchive-libarchive_cab_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_cab_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_cab_fuzzer
)

# libarchive_cpio_fuzzer: the release's target libarchive-libarchive_cpio_fuzzer
(
ov_target_begin libarchive-libarchive_cpio_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_cpio_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_cpio_fuzzer
)

# libarchive_entry_fuzzer: the release's target libarchive-libarchive_entry_fuzzer
(
ov_target_begin libarchive-libarchive_entry_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_entry_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_entry_fuzzer
)

# libarchive_filter_fuzzer: the release's target libarchive-libarchive_filter_fuzzer
(
ov_target_begin libarchive-libarchive_filter_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_filter_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_filter_fuzzer
)

# libarchive_iso9660_fuzzer: the release's target libarchive-libarchive_iso9660_fuzzer
(
ov_target_begin libarchive-libarchive_iso9660_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_iso9660_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_iso9660_fuzzer
)

# libarchive_lha_fuzzer: the release's target libarchive-libarchive_lha_fuzzer
(
ov_target_begin libarchive-libarchive_lha_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_lha_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_lha_fuzzer
)

# libarchive_linkify_fuzzer: the release's target libarchive-libarchive_linkify_fuzzer
(
ov_target_begin libarchive-libarchive_linkify_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_linkify_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_linkify_fuzzer
)

# libarchive_mtree_fuzzer: the release's target libarchive-libarchive_mtree_fuzzer
(
ov_target_begin libarchive-libarchive_mtree_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_mtree_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_mtree_fuzzer
)

# libarchive_rar5_fuzzer: the release's target libarchive-libarchive_rar5_fuzzer
(
ov_target_begin libarchive-libarchive_rar5_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_rar5_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_rar5_fuzzer
)

# libarchive_rar_fuzzer: the release's target libarchive-libarchive_rar_fuzzer
(
ov_target_begin libarchive-libarchive_rar_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_rar_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_rar_fuzzer
)

# libarchive_roundtrip_fuzzer: the release's target libarchive-libarchive_roundtrip_fuzzer
(
ov_target_begin libarchive-libarchive_roundtrip_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_roundtrip_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_roundtrip_fuzzer
)

# libarchive_seek_fuzzer: the release's target libarchive-libarchive_seek_fuzzer
(
ov_target_begin libarchive-libarchive_seek_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_seek_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_seek_fuzzer
)

# libarchive_string_fuzzer: the release's target libarchive-libarchive_string_fuzzer
(
ov_target_begin libarchive-libarchive_string_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_string_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_string_fuzzer
)

# libarchive_tar_fuzzer: the release's target libarchive-libarchive_tar_fuzzer
(
ov_target_begin libarchive-libarchive_tar_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_tar_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_tar_fuzzer
)

# libarchive_warc_fuzzer: the release's target libarchive-libarchive_warc_fuzzer
(
ov_target_begin libarchive-libarchive_warc_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_warc_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_warc_fuzzer
)

# libarchive_write_fuzzer: the release's target libarchive-libarchive_write_fuzzer
(
ov_target_begin libarchive-libarchive_write_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_write_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_write_fuzzer
)

# libarchive_xar_fuzzer: the release's target libarchive-libarchive_xar_fuzzer
(
ov_target_begin libarchive-libarchive_xar_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_xar_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_xar_fuzzer
)

# libarchive_zip_fuzzer: the release's target libarchive-libarchive_zip_fuzzer
(
ov_target_begin libarchive-libarchive_zip_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "contrib/oss-fuzz/libarchive_zip_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libarchive_zip_fuzzer
)
