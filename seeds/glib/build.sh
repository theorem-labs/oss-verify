#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of glib into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_bookmark: the release's target glib-fuzz_bookmark
(
ov_target_begin glib-fuzz_bookmark
build_lib() {
  oft_build_meson
  oft_build_harness "fuzzing/fuzz_bookmark.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















































build_lib() {
  rm -rf -- "${BUILDDIR:?}/src-patched" "${BUILDDIR:?}/mes"
  mkdir -p "${BUILDDIR:?}/src-patched"
  cp -a "${SRCDIR:?}/." "${BUILDDIR:?}/src-patched/"
  grep -q "glib_conf.set('HAVE_FUTEX', 1)" "${BUILDDIR:?}/src-patched/meson.build" \
    || { echo "oft: glib futex probe not where this pin expects it; refusing" >&2; return 1; }
  sed -i -e "s/glib_conf.set('HAVE_FUTEX', 1)/message('oft: futex probe disabled: pthread fallback')/" \
         -e "s/glib_conf.set('HAVE_FUTEX_TIME64', 1)/message('oft: futex_time64 probe disabled: pthread fallback')/" \
         "${BUILDDIR:?}/src-patched/meson.build"
  rm -rf -- "${BUILDDIR:?}/src-patched/glib/dirent"
  OFT_GLIB_SRCDIR_ORIG=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_meson
  SRCDIR=$OFT_GLIB_SRCDIR_ORIG


  if grep -q 'define HAVE_FUTEX' "${BUILDDIR:?}/mes/config.h"; then
    echo "oft: config.h still carries HAVE_FUTEX*; futex-off did not take" >&2
    return 1
  fi
  if [ -e "${BUILDDIR:?}/src/glib/dirent/dirent.h" ]; then
    echo "oft: windows dirent shim still present in the swept tree" >&2
    return 1
  fi
  oft_build_harness "fuzzing/fuzz_bookmark.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_bookmark
)
