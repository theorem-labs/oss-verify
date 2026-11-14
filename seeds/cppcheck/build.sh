#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of cppcheck into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# oss-fuzz-client: the release's target cppcheck-main
(
ov_target_begin cppcheck-main
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/main.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  cat > "${BUILDDIR:?}/oft_cxa_thread_atexit.c" <<'OFTEOF'
typedef void (*oft_dtor_t)(void *);
extern int __cxa_atexit(oft_dtor_t, void *, void *);
int __cxa_thread_atexit(oft_dtor_t dtor, void *obj, void *dso)
{
  return __cxa_atexit(dtor, obj, dso);
}
OFTEOF

  "${CC:?}" ${CFLAGS:-} -c "${BUILDDIR:?}/oft_cxa_thread_atexit.c" \
    -o "${BUILDDIR:?}/oft_cxa_thread_atexit.o"
  "${CHOST:?}-ar" r "${BUILDDIR:?}/lib/liboft.a" "${BUILDDIR:?}/oft_cxa_thread_atexit.o"
  oft_build_harness "oss-fuzz/main.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build oss-fuzz-client
)
