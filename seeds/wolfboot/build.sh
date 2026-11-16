#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wolfboot into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_gzip: the release's target wolfboot-fuzz_gzip
(
ov_target_begin wolfboot-fuzz_gzip
build_lib() {
  oft_build_cmake
  oft_build_harness "lib/wolfTPM/tests/fuzz/fwtpm_fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































build_lib() {
  oft_copy_src
  cp "$BUILDDIR/src/config/examples/library.config" "$BUILDDIR/src/.config"


  OFT_WB_EXTRA="$CFLAGS -DPRINTF_ENABLED -Wno-error=undefined-internal -Wno-error"
  ( cd "$BUILDDIR/src" \
    && make -j"$(oft_jobs)" libwolfboot.a \
         CC="$CC" AR="$CHOST-ar" SIGN=NONE ELF=1 GZIP=1 DELTA_UPDATES=1 \
         CFLAGS_EXTRA="$OFT_WB_EXTRA" \
    && make -j"$(oft_jobs)" src/gpt.o src/fdt.o \
         CC="$CC" AR="$CHOST-ar" SIGN=NONE ELF=1 GZIP=1 DELTA_UPDATES=1 \
         CFLAGS_EXTRA="$OFT_WB_EXTRA -DWOLFBOOT_FDT" \
    && "$CHOST-ar" r libwolfboot.a src/gpt.o src/fdt.o )
  oft_merge_archives
  oft_build_harness "fuzz_gzip.c" -DWOLFBOOT_GZIP -DPRINTF_ENABLED -DARCH_FLASH_OFFSET=0
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_gzip
)
