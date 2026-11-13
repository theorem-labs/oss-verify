#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of dovecot into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-message-parser: the release's target dovecot-fuzz-message-parser
(
ov_target_begin dovecot-fuzz-message-parser
build_lib() {
  oft_build_autotools
  oft_build_harness "src/lib-test/fuzzer.h"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""









































































































build_lib() {
  grep -qxF '0.0.0-37214+25eb82b31e' "${SRCDIR:?}/version.txt" || {
    echo "oft: $SRCDIR/version.txt missing or not the pinned version" >&2
    return 1
  }
  grep -qF '#define DOVECOT_REVISION "25eb82b31e"' "${SRCDIR:?}/dovecot-version.h" || {
    echo "oft: $SRCDIR/dovecot-version.h missing or not the pinned revision" >&2
    return 1
  }
  ( cd "${SRCDIR:?}/src/lib/ucd" && sha256sum -c --quiet -- /work/targets/dovecot-fuzz-message-parser/ucd.sha256 ) || {
    echo "oft: vendored UCD files under $SRCDIR/src/lib/ucd missing or changed" >&2
    return 1
  }
  oft_build_autotools \
    PKG_CONFIG_LIBDIR=/opt/musl-sysroot/usr/lib/pkgconfig \
    i_cv_epoll_works=yes \
    i_cv_posix_fallocate_works=yes \
    i_cv_gmtime_max_time_t=40 \
    i_cv_mmap_plays_with_write=yes \
    i_cv_fd_passing=yes \
    lib_cv_va_copy=yes \
    lib_cv___va_copy=yes
  oft_build_harness "src/lib-mail/fuzz-message-parser.c" -DHAVE_CONFIG_H
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  local obj="$BUILDDIR/wrap_ambient.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/dovecot-fuzz-message-parser/wrap_ambient.c -o "$obj" || return 1
  "$CHOST-nm" "$obj" | grep -q ' T __wrap_gethostname$' || {
    echo "oft: wrap_ambient.o defines no __wrap_gethostname" >&2
    return 1
  }
  LIB_EXTRA="${LIB_EXTRA:-} $obj -Wl,--wrap=gethostname -Wl,--wrap=fd_close_on_exec -Wl,--wrap=open"
  LIB_EXTRA="$LIB_EXTRA -Wl,--wrap=lib_signals_init -Wl,--wrap=lib_signals_deinit -Wl,--wrap=lib_signals_ignore"
}





























































VENDOR_FILES="
src/lib/ucd/CaseFolding.txt sha256:ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183 https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt
src/lib/ucd/CompositionExclusions.txt sha256:2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f https://www.unicode.org/Public/17.0.0/ucd/CompositionExclusions.txt
src/lib/ucd/DerivedBidiClass.txt sha256:4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4 https://www.unicode.org/Public/17.0.0/ucd/extracted/DerivedBidiClass.txt
src/lib/ucd/DerivedCoreProperties.txt sha256:24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08 https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt
src/lib/ucd/DerivedJoiningType.txt sha256:f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d https://www.unicode.org/Public/17.0.0/ucd/extracted/DerivedJoiningType.txt
src/lib/ucd/DerivedNormalizationProps.txt sha256:71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488 https://www.unicode.org/Public/17.0.0/ucd/DerivedNormalizationProps.txt
src/lib/ucd/GraphemeBreakProperty.txt sha256:d6b51d1d2ae5c33b451b7ed994b48f1f4dc62b2272a5831e7fd418514a6bae89 https://www.unicode.org/Public/17.0.0/ucd/auxiliary/GraphemeBreakProperty.txt
src/lib/ucd/GraphemeBreakTest.txt sha256:e2d134d2c52919bace503ebb6a551c1855fe1a1faec18478c78fff254a1793ec https://www.unicode.org/Public/17.0.0/ucd/auxiliary/GraphemeBreakTest.txt
src/lib/ucd/IdnaMappingTable.txt sha256:87f05505dc026fdb2bff16132bdc68a8014675836882a9a2b1844540ad3be382 https://www.unicode.org/Public/17.0.0/idna/IdnaMappingTable.txt
src/lib/ucd/IdnaTestV2.txt sha256:beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf https://www.unicode.org/Public/17.0.0/idna/IdnaTestV2.txt
src/lib/ucd/NormalizationTest.txt sha256:5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt
src/lib/ucd/PropList.txt sha256:130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd https://www.unicode.org/Public/17.0.0/ucd/PropList.txt
src/lib/ucd/PropertyValueAliases.txt sha256:64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a https://www.unicode.org/Public/17.0.0/ucd/PropertyValueAliases.txt
src/lib/ucd/Scripts.txt sha256:9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf https://www.unicode.org/Public/17.0.0/ucd/Scripts.txt
src/lib/ucd/SpecialCasing.txt sha256:efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588 https://www.unicode.org/Public/17.0.0/ucd/SpecialCasing.txt
src/lib/ucd/UnicodeData.txt sha256:2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt
src/lib/ucd/WordBreakProperty.txt sha256:72274cac1e6b919507db35655c3e175aa27274668a1ece95c28d2069f2ad9852 https://www.unicode.org/Public/17.0.0/ucd/auxiliary/WordBreakProperty.txt
src/lib/ucd/emoji-data.txt sha256:2cb2bb9455cda83e8481541ecf5b6dfda66a3bb89efa3fa7c5297eccf607b72b https://www.unicode.org/Public/17.0.0/ucd/emoji/emoji-data.txt
"
ov_target_build fuzz-message-parser
)
