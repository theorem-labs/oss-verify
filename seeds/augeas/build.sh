#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of augeas into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# augeas_api_fuzzer: the release's target augeas-augeas_api_fuzzer
(
ov_target_begin augeas-augeas_api_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "augeas_api_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































































oft_augeas_bootstrap_offline() {
  local boot="${BUILDDIR:?}/oft-src-boot"
  rm -rf -- "$boot"
  mkdir -p "$boot"
  cp -a "${SRCDIR:?}/." "$boot/"
  [ -f "$boot/.gnulib/gnulib-tool" ] || {
    echo "oft: augeas: .gnulib/gnulib-tool is not in the tree (submodule content missing); refusing" >&2; return 1; }
  ( cd "$boot" \
    && sed -e '/^  git submodule init || exit \$?$/d;/^  git submodule update || exit \$?$/d' bootstrap > bootstrap.oft-offline \
    && [ "$(grep -c '^  git submodule' bootstrap)" -eq 2 ] \
    && [ "$(grep -c '^  git submodule' bootstrap.oft-offline)" -eq 0 ] \
    && echo "oft: augeas: running ./bootstrap offline (git submodule init/update removed; .gnulib/ ships)" \
    && unset GNULIB_SRCDIR \
    && sh ./bootstrap.oft-offline \
    && echo "oft: augeas: running autoreconf -fi on the bootstrapped copy" \
    && autoreconf -fi ) \
    || { echo "oft: augeas offline bootstrap failed" >&2; return 1; }
  [ -x "$boot/configure" ] || {
    echo "oft: augeas offline bootstrap produced no ./configure; refusing" >&2; return 1; }
  [ -f "$boot/gnulib/lib/Makefile.am" ] || {
    echo "oft: augeas offline bootstrap produced no gnulib/lib/Makefile.am; refusing" >&2; return 1; }
}
build_lib() {
  oft_require_target_cxx
  oft_augeas_bootstrap_offline
  oft_augeas_srcdir_orig="${SRCDIR:?}"
  SRCDIR="${BUILDDIR:?}/oft-src-boot"
  oft_build_autotools
  SRCDIR="$oft_augeas_srcdir_orig"

  rm -rf -- "${BUILDDIR:?}/oft-harness-inc"
  mkdir -p "${BUILDDIR:?}/oft-harness-inc"
  cp "${BUILDDIR:?}/src/config.h" "${BUILDDIR:?}/src/src/"*.h "${BUILDDIR:?}/oft-harness-inc/"
  [ -f "${BUILDDIR:?}/oft-harness-inc/internal.h" ] || {
    echo "oft: augeas header staging produced no internal.h; refusing" >&2; return 1; }
  oft_build_harness "augeas_api_fuzzer.cc" \
    -iquote "${BUILDDIR:?}/oft-harness-inc" \
    "-I${OFT_SYSROOT:-/opt/musl-sysroot}/usr/include/libxml2" \
    -D_GNU_SOURCE -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build augeas_api_fuzzer
)
