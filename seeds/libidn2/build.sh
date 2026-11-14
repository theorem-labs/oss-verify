#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libidn2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libidn2_register_fuzzer: the release's target libidn2-libidn2_register_fuzzer
(
ov_target_begin libidn2-libidn2_register_fuzzer
COMMIT=$(git -C "$SRC/upstream/libidn2" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libidn2_register_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































build_lib() {
  local stage saved_srcdir e version=2.3.8.35-8d9f
  case "${COMMIT:?}" in
    8d9fc983*) ;;
    *) echo "oft: the .tarball-version constant $version is for 8d9fc983, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4, then git-version-gen's rendering)" >&2; return 1 ;;
  esac
  [ ! -e "${SRCDIR:?}/.tarball-version" ] \
    || { echo "oft: $SRCDIR/.tarball-version exists upstream now; this block would silently override it" >&2; return 1; }
  grep -qF 'git-version-gen .tarball-version' "$SRCDIR/configure.ac" \
    || { echo "oft: configure.ac no longer derives the version through git-version-gen .tarball-version; re-read the mechanism" >&2; return 1; }
  stage=$(mktemp -d)
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  printf '%s\n' "$version" > "$stage/.tarball-version"
  [ "$(cat "$stage/.tarball-version")" = "$version" ] \
    || { echo "oft: $stage/.tarball-version was not written" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF "# define IDN2_VERSION \"$version\"" "$BUILDDIR/src/lib/idn2.h" \
    || { echo "oft: lib/idn2.h does not carry the pinned version:" >&2
         grep -n 'IDN2_VERSION' "$BUILDDIR/src/lib/idn2.h" >&2 || echo "oft: (no lib/idn2.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libidn2_register_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libidn2_register_fuzzer
)

# libidn2_to_ascii_8z_fuzzer: the release's target libidn2-libidn2_to_ascii_8z_fuzzer
(
ov_target_begin libidn2-libidn2_to_ascii_8z_fuzzer
COMMIT=$(git -C "$SRC/upstream/libidn2" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libidn2_to_ascii_8z_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































build_lib() {
  local stage saved_srcdir e version=2.3.8.35-8d9f
  case "${COMMIT:?}" in
    8d9fc983*) ;;
    *) echo "oft: the .tarball-version constant $version is for 8d9fc983, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4, then git-version-gen's rendering)" >&2; return 1 ;;
  esac
  [ ! -e "${SRCDIR:?}/.tarball-version" ] \
    || { echo "oft: $SRCDIR/.tarball-version exists upstream now; this block would silently override it" >&2; return 1; }
  grep -qF 'git-version-gen .tarball-version' "$SRCDIR/configure.ac" \
    || { echo "oft: configure.ac no longer derives the version through git-version-gen .tarball-version; re-read the mechanism" >&2; return 1; }
  stage=$(mktemp -d)
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  printf '%s\n' "$version" > "$stage/.tarball-version"
  [ "$(cat "$stage/.tarball-version")" = "$version" ] \
    || { echo "oft: $stage/.tarball-version was not written" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF "# define IDN2_VERSION \"$version\"" "$BUILDDIR/src/lib/idn2.h" \
    || { echo "oft: lib/idn2.h does not carry the pinned version:" >&2
         grep -n 'IDN2_VERSION' "$BUILDDIR/src/lib/idn2.h" >&2 || echo "oft: (no lib/idn2.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libidn2_to_ascii_8z_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libidn2_to_ascii_8z_fuzzer
)

# libidn2_to_unicode_8z8z_fuzzer: the release's target libidn2-libidn2_to_unicode_8z8z_fuzzer
(
ov_target_begin libidn2-libidn2_to_unicode_8z8z_fuzzer
COMMIT=$(git -C "$SRC/upstream/libidn2" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libidn2_to_unicode_8z8z_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































build_lib() {
  local stage saved_srcdir e version=2.3.8.35-8d9f
  case "${COMMIT:?}" in
    8d9fc983*) ;;
    *) echo "oft: the .tarball-version constant $version is for 8d9fc983, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4, then git-version-gen's rendering)" >&2; return 1 ;;
  esac
  [ ! -e "${SRCDIR:?}/.tarball-version" ] \
    || { echo "oft: $SRCDIR/.tarball-version exists upstream now; this block would silently override it" >&2; return 1; }
  grep -qF 'git-version-gen .tarball-version' "$SRCDIR/configure.ac" \
    || { echo "oft: configure.ac no longer derives the version through git-version-gen .tarball-version; re-read the mechanism" >&2; return 1; }
  stage=$(mktemp -d)
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  printf '%s\n' "$version" > "$stage/.tarball-version"
  [ "$(cat "$stage/.tarball-version")" = "$version" ] \
    || { echo "oft: $stage/.tarball-version was not written" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF "# define IDN2_VERSION \"$version\"" "$BUILDDIR/src/lib/idn2.h" \
    || { echo "oft: lib/idn2.h does not carry the pinned version:" >&2
         grep -n 'IDN2_VERSION' "$BUILDDIR/src/lib/idn2.h" >&2 || echo "oft: (no lib/idn2.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libidn2_to_unicode_8z8z_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libidn2_to_unicode_8z8z_fuzzer
)
