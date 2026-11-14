#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wget into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# wget_cookie_fuzzer: the release's target wget-wget_cookie_fuzzer
(
ov_target_begin wget-wget_cookie_fuzzer
COMMIT=$(git -C "$SRC/upstream/wget" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/wget_cookie_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























































































build_lib() {
  local stage saved_srcdir e version=1.25.0.77-e9697-modified
  case "${COMMIT:?}" in
    e9697d98*) ;;
    *) echo "oft: the .tarball-version constant $version is for e9697d98, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', git-version-gen's rendering, and the -modified suffix if the tree is patched in place)" >&2; return 1 ;;
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
  oft_build_autotools --enable-fuzzing --with-ssl=no --without-libpsl
  SRCDIR="$saved_srcdir"


  grep -qxF "#define PACKAGE_VERSION \"$version\"" "$BUILDDIR/src/src/config.h" \
    || { echo "oft: src/config.h does not carry the pinned version:" >&2
         grep -n 'PACKAGE_VERSION' "$BUILDDIR/src/src/config.h" >&2 || echo "oft: (no src/config.h at all)" >&2
         return 1; }
  ( cd "$BUILDDIR/src/src" && make -j"$(oft_jobs)" libunittest.a ) || return 1
  grep -qxF "const char *version_string = \"$version\";" "$BUILDDIR/src/src/version.c" \
    || { echo "oft: src/version.c does not carry the pinned version_string:" >&2
         grep -n 'version_string' "$BUILDDIR/src/src/version.c" >&2 || echo "oft: (no src/version.c at all)" >&2
         return 1; }
  oft_merge_archives
  oft_build_harness "fuzz/wget_cookie_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  local tobj="$BUILDDIR/seal_time_wget.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/wget-wget_cookie_fuzzer/seal_time.c -o "$tobj" || return 1



  local sym
  for sym in time clock_gettime gettimeofday; do
    "$CHOST-nm" "$tobj" | grep -q " T $sym\$" || {
      echo "oft: seal_time_wget.o defines no $sym" >&2
      return 1
    }
  done






  LIB_EXTRA="${LIB_EXTRA:-} $tobj"






  local zobj="$BUILDDIR/seal_tz_wget.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/wget-wget_cookie_fuzzer/seal_tz.c -o "$zobj" || return 1
  for sym in localtime localtime_r tzset; do
    "$CHOST-nm" "$zobj" | grep -q " T $sym\$" || {
      echo "oft: seal_tz_wget.o defines no $sym" >&2
      return 1
    }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $zobj"












  local kobj="$BUILDDIR/keep_pthread_wget.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/wget-wget_cookie_fuzzer/keep_pthread.c -o "$kobj" || return 1
  for sym in pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock \
             pthread_mutex_destroy pthread_mutexattr_gettype pthread_once; do
    "$CHOST-nm" "$kobj" | grep -q " U $sym\$" || {
      echo "oft: keep_pthread_wget.o references no $sym" >&2
      return 1
    }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $kobj"
}
ov_target_build wget_cookie_fuzzer
)
