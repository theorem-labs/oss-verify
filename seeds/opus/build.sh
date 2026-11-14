#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of opus into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# opus_decode_fuzzer: the release's target opus-opus_decode_fuzzer
(
ov_target_begin opus-opus_decode_fuzzer
COMMIT=$(git -C "$SRC/upstream/opus" rev-parse HEAD)
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/opus_decode_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















































build_lib() {
  local stage saved_srcdir e pv=1.6.1-5-g3704fb81
  case "${COMMIT:?}" in
    3704fb81*) ;;
    *) echo "oft: the package_version constant $pv is for 3704fb81, but COMMIT=$COMMIT; re-derive it" >&2; return 1 ;;
  esac
  [ ! -e "${SRCDIR:?}/package_version" ] \
    || { echo "oft: $SRCDIR/package_version exists upstream now; this block would silently override it" >&2; return 1; }
  stage=$(mktemp -d)
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/package_version"' "$stage/cmake/OpusPackageVersion.cmake" \
    || { echo "oft: OpusPackageVersion.cmake no longer reads package_version; re-read the mechanism" >&2; return 1; }
  printf '%s\n' \
    '                                                                       ' \
    '                                                                         ' \
    '                               ' \
    'AUTO_UPDATE=no' \
    "PACKAGE_VERSION=\"$pv\"" > "$stage/package_version"
  grep -qxF "PACKAGE_VERSION=\"$pv\"" "$stage/package_version" \
    || { echo "oft: $stage/package_version was not written" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_cmake
  SRCDIR="$saved_srcdir"
  grep -qxF "#define PACKAGE_VERSION \"$pv\"" "$BUILDDIR/cmk/config.h" \
    || { echo "oft: cmk/config.h does not carry the pinned PACKAGE_VERSION:" >&2
         grep -n 'PACKAGE_VERSION' "$BUILDDIR/cmk/config.h" >&2 || echo "oft: (no PACKAGE_VERSION line at all)" >&2
         return 1; }
  oft_build_harness "tests/opus_decode_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build opus_decode_fuzzer
)
