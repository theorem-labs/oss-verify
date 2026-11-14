#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ndpi into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_alg_anomalymodel: the release's target ndpi-fuzz_alg_anomalymodel
(
ov_target_begin ndpi-fuzz_alg_anomalymodel
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/fuzz_alg_anomalymodel.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















































build_lib() {
  oft_require_target_cxx
  local stage saved_srcdir e api
  stage=$(mktemp -d)
  for e in "${SRCDIR:?}"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'if test -d "${srcdir}/.git" || test -r "${srcdir}/.git"; then' "$stage/configure.ac" \
    || { echo "oft: configure.ac no longer keys the release string on .git; re-read the mechanism" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF '#define NDPI_GIT_RELEASE "5.1.0"' "$BUILDDIR/src/src/include/ndpi_config.h" \
    || { echo "oft: NDPI_GIT_RELEASE is not the bare PACKAGE_VERSION -- configure took the git branch:" >&2
         grep -n 'NDPI_GIT_RELEASE' "$BUILDDIR/src/src/include/ndpi_config.h" >&2 || echo "oft: (no NDPI_GIT_RELEASE line at all)" >&2
         return 1; }
  api=$(( ${SOURCE_DATE_EPOCH:?} % 65536 ))
  grep -qxF "#define NDPI_API_VERSION $api" "$BUILDDIR/src/src/include/ndpi_define.h" \
    || { echo "oft: NDPI_API_VERSION is not SOURCE_DATE_EPOCH % 65536 = $api -- configure took the git branch:" >&2
         grep -n 'NDPI_API_VERSION' "$BUILDDIR/src/src/include/ndpi_define.h" >&2 || echo "oft: (no NDPI_API_VERSION line at all)" >&2
         return 1; }
  oft_build_harness "fuzz/fuzz_alg_anomalymodel.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_alg_anomalymodel
)

# fuzz_alg_crc32_md5: the release's target ndpi-fuzz_alg_crc32_md5
(
ov_target_begin ndpi-fuzz_alg_crc32_md5
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz_alg_crc32_md5.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















































build_lib() {
  local stage saved_srcdir e api
  stage=$(mktemp -d)
  for e in "${SRCDIR:?}"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'if test -d "${srcdir}/.git" || test -r "${srcdir}/.git"; then' "$stage/configure.ac" \
    || { echo "oft: configure.ac no longer keys the release string on .git; re-read the mechanism" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF '#define NDPI_GIT_RELEASE "5.1.0"' "$BUILDDIR/src/src/include/ndpi_config.h" \
    || { echo "oft: NDPI_GIT_RELEASE is not the bare PACKAGE_VERSION -- configure took the git branch:" >&2
         grep -n 'NDPI_GIT_RELEASE' "$BUILDDIR/src/src/include/ndpi_config.h" >&2 || echo "oft: (no NDPI_GIT_RELEASE line at all)" >&2
         return 1; }
  api=$(( ${SOURCE_DATE_EPOCH:?} % 65536 ))
  grep -qxF "#define NDPI_API_VERSION $api" "$BUILDDIR/src/src/include/ndpi_define.h" \
    || { echo "oft: NDPI_API_VERSION is not SOURCE_DATE_EPOCH % 65536 = $api -- configure took the git branch:" >&2
         grep -n 'NDPI_API_VERSION' "$BUILDDIR/src/src/include/ndpi_define.h" >&2 || echo "oft: (no NDPI_API_VERSION line at all)" >&2
         return 1; }
  oft_build_harness "fuzz/fuzz_alg_crc32_md5.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_alg_crc32_md5
)

# fuzz_libinjection: the release's target ndpi-fuzz_libinjection
(
ov_target_begin ndpi-fuzz_libinjection
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz_libinjection.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















































build_lib() {
  local stage saved_srcdir e api
  stage=$(mktemp -d)
  for e in "${SRCDIR:?}"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'if test -d "${srcdir}/.git" || test -r "${srcdir}/.git"; then' "$stage/configure.ac" \
    || { echo "oft: configure.ac no longer keys the release string on .git; re-read the mechanism" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF '#define NDPI_GIT_RELEASE "5.1.0"' "$BUILDDIR/src/src/include/ndpi_config.h" \
    || { echo "oft: NDPI_GIT_RELEASE is not the bare PACKAGE_VERSION -- configure took the git branch:" >&2
         grep -n 'NDPI_GIT_RELEASE' "$BUILDDIR/src/src/include/ndpi_config.h" >&2 || echo "oft: (no NDPI_GIT_RELEASE line at all)" >&2
         return 1; }
  api=$(( ${SOURCE_DATE_EPOCH:?} % 65536 ))
  grep -qxF "#define NDPI_API_VERSION $api" "$BUILDDIR/src/src/include/ndpi_define.h" \
    || { echo "oft: NDPI_API_VERSION is not SOURCE_DATE_EPOCH % 65536 = $api -- configure took the git branch:" >&2
         grep -n 'NDPI_API_VERSION' "$BUILDDIR/src/src/include/ndpi_define.h" >&2 || echo "oft: (no NDPI_API_VERSION line at all)" >&2
         return 1; }
  oft_build_harness "fuzz/fuzz_libinjection.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_libinjection
)

# fuzz_ndpi_decode_tls_blocks: the release's target ndpi-fuzz_ndpi_decode_tls_blocks
(
ov_target_begin ndpi-fuzz_ndpi_decode_tls_blocks
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz_ndpi_decode_tls_blocks.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















































build_lib() {
  local stage saved_srcdir e api
  stage=$(mktemp -d)
  for e in "${SRCDIR:?}"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'if test -d "${srcdir}/.git" || test -r "${srcdir}/.git"; then' "$stage/configure.ac" \
    || { echo "oft: configure.ac no longer keys the release string on .git; re-read the mechanism" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF '#define NDPI_GIT_RELEASE "5.1.0"' "$BUILDDIR/src/src/include/ndpi_config.h" \
    || { echo "oft: NDPI_GIT_RELEASE is not the bare PACKAGE_VERSION -- configure took the git branch:" >&2
         grep -n 'NDPI_GIT_RELEASE' "$BUILDDIR/src/src/include/ndpi_config.h" >&2 || echo "oft: (no NDPI_GIT_RELEASE line at all)" >&2
         return 1; }
  api=$(( ${SOURCE_DATE_EPOCH:?} % 65536 ))
  grep -qxF "#define NDPI_API_VERSION $api" "$BUILDDIR/src/src/include/ndpi_define.h" \
    || { echo "oft: NDPI_API_VERSION is not SOURCE_DATE_EPOCH % 65536 = $api -- configure took the git branch:" >&2
         grep -n 'NDPI_API_VERSION' "$BUILDDIR/src/src/include/ndpi_define.h" >&2 || echo "oft: (no NDPI_API_VERSION line at all)" >&2
         return 1; }
  oft_build_harness "fuzz/fuzz_ndpi_decode_tls_blocks.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_ndpi_decode_tls_blocks
)
