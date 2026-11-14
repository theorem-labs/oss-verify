#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libtasn1 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# asn1_decode_simple_ber_fuzzer: the release's target libtasn1-asn1_decode_simple_ber_fuzzer
(
ov_target_begin libtasn1-asn1_decode_simple_ber_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/asn1_decode_simple_ber_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/asn1_decode_simple_ber_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build asn1_decode_simple_ber_fuzzer
)

# asn1_decode_simple_der_fuzzer: the release's target libtasn1-asn1_decode_simple_der_fuzzer
(
ov_target_begin libtasn1-asn1_decode_simple_der_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/asn1_decode_simple_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/asn1_decode_simple_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build asn1_decode_simple_der_fuzzer
)

# asn1_get_length_ber_fuzzer: the release's target libtasn1-asn1_get_length_ber_fuzzer
(
ov_target_begin libtasn1-asn1_get_length_ber_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/asn1_get_length_ber_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/asn1_get_length_ber_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build asn1_get_length_ber_fuzzer
)

# asn1_get_length_der_fuzzer: the release's target libtasn1-asn1_get_length_der_fuzzer
(
ov_target_begin libtasn1-asn1_get_length_der_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/asn1_get_length_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/asn1_get_length_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build asn1_get_length_der_fuzzer
)

# asn1_get_object_id_der_fuzzer: the release's target libtasn1-asn1_get_object_id_der_fuzzer
(
ov_target_begin libtasn1-asn1_get_object_id_der_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/asn1_get_object_id_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/asn1_get_object_id_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build asn1_get_object_id_der_fuzzer
)

# libtasn1_array2tree_fuzzer: the release's target libtasn1-libtasn1_array2tree_fuzzer
(
ov_target_begin libtasn1-libtasn1_array2tree_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libtasn1_array2tree_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libtasn1_array2tree_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libtasn1_array2tree_fuzzer
)

# libtasn1_gnutls_der_fuzzer: the release's target libtasn1-libtasn1_gnutls_der_fuzzer
(
ov_target_begin libtasn1-libtasn1_gnutls_der_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libtasn1_gnutls_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libtasn1_gnutls_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libtasn1_gnutls_der_fuzzer
)

# libtasn1_parser2tree_fuzzer: the release's target libtasn1-libtasn1_parser2tree_fuzzer
(
ov_target_begin libtasn1-libtasn1_parser2tree_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libtasn1_parser2tree_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libtasn1_parser2tree_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libtasn1_parser2tree_fuzzer
)

# libtasn1_pkix_der_fuzzer: the release's target libtasn1-libtasn1_pkix_der_fuzzer
(
ov_target_begin libtasn1-libtasn1_pkix_der_fuzzer
COMMIT=$(git -C "$SRC/upstream/libtasn1" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/libtasn1_pkix_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































build_lib() {
  local stage saved_srcdir e version=4.21.0.10-2b20
  case "${COMMIT:?}" in
    2b2065b2*) ;;
    *) echo "oft: the .tarball-version constant $version is for 2b2065b2, but COMMIT=$COMMIT; re-derive it (git describe --abbrev=4 --match='v*', then git-version-gen's rendering)" >&2; return 1 ;;
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
  grep -qxF "# define ASN1_VERSION \"$version\"" "$BUILDDIR/src/lib/includes/libtasn1.h" \
    || { echo "oft: lib/includes/libtasn1.h does not carry the pinned version:" >&2
         grep -n 'ASN1_VERSION "' "$BUILDDIR/src/lib/includes/libtasn1.h" >&2 || echo "oft: (no lib/includes/libtasn1.h at all)" >&2
         return 1; }
  oft_build_harness "fuzz/libtasn1_pkix_der_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build libtasn1_pkix_der_fuzzer
)
