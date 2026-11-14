#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wolftpm into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fwtpm_fuzz: the release's target wolftpm-fwtpm_fuzz
(
ov_target_begin wolftpm-fwtpm_fuzz
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/fwtpm_fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""















































build_lib() {
  oft_build_cmake -DWOLFTPM_FWTPM=yes
  local d="$BUILDDIR/cmk/CMakeFiles/fwtpm_unit_test.dir/src" o
  for o in fwtpm/fwtpm.c.o fwtpm/fwtpm_command.c.o fwtpm/fwtpm_crypto.c.o \
           fwtpm/fwtpm_nv.c.o tpm2_util.c.o tpm2_packet.c.o \
           tpm2_crypto.c.o tpm2_param_enc.c.o; do
    [ -f "$d/$o" ] || { echo "oft: missing fwtpm object $d/$o" >&2; return 1; }
  done
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" \
    "$d"/fwtpm/fwtpm.c.o "$d"/fwtpm/fwtpm_command.c.o \
    "$d"/fwtpm/fwtpm_crypto.c.o "$d"/fwtpm/fwtpm_nv.c.o \
    "$d"/tpm2_util.c.o "$d"/tpm2_packet.c.o \
    "$d"/tpm2_crypto.c.o "$d"/tpm2_param_enc.c.o || return 1
  oft_build_harness "tests/fuzz/fwtpm_fuzz.c" -DWOLFTPM_FWTPM
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fwtpm_fuzz
)
