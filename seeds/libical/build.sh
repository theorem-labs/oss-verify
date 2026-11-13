#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libical into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libical_extended_fuzzer: the release's target libical-libical_extended_fuzzer
(
ov_target_begin libical-libical_extended_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "libical_extended_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DLIBICAL_STATIC=ON -DLIBICAL_JAVA_BINDINGS=False -DLIBICAL_GOBJECT_INTROSPECTION=False -DLIBICAL_GLIB=False -DLIBICAL_GLIB_BUILD_DOCS=False -DLIBICAL_BUILD_EXAMPLES=False -DCMAKE_DISABLE_FIND_PACKAGE_ICU=ON
  oft_build_harness "libical_extended_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libical_extended_fuzzer
)

# libical_fuzzer: the release's target libical-libical_fuzzer
(
ov_target_begin libical-libical_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "libical_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DLIBICAL_STATIC=ON -DLIBICAL_JAVA_BINDINGS=False -DLIBICAL_GOBJECT_INTROSPECTION=False -DLIBICAL_GLIB=False -DLIBICAL_GLIB_BUILD_DOCS=False -DLIBICAL_BUILD_EXAMPLES=False -DCMAKE_DISABLE_FIND_PACKAGE_ICU=ON
  oft_build_harness "libical_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libical_fuzzer
)

# libicalvcard_fuzzer: the release's target libical-libicalvcard_fuzzer
(
ov_target_begin libical-libicalvcard_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "libicalvcard_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DLIBICAL_STATIC=ON -DLIBICAL_JAVA_BINDINGS=False -DLIBICAL_GOBJECT_INTROSPECTION=False -DLIBICAL_GLIB=False -DLIBICAL_GLIB_BUILD_DOCS=False -DLIBICAL_BUILD_EXAMPLES=False -DCMAKE_DISABLE_FIND_PACKAGE_ICU=ON











  mkdir -p "$BUILDDIR/include/libical"
  cp "$BUILDDIR"/cmk/src/libicalvcard/*.h "$BUILDDIR/include/libical/"
  oft_build_harness "libicalvcard_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libicalvcard_fuzzer
)
