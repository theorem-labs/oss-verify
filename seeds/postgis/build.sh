#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of postgis into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# wkt_import_fuzzer: the release's target postgis-wkt_import_fuzzer
(
ov_target_begin postgis-wkt_import_fuzzer
COMMIT=$(git -C "$SRC/upstream/postgis" rev-parse HEAD)
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzzers/wkt_import_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































































build_lib() {
  oft_require_target_cxx

  local stage stubs saved_srcdir e guard rev=3.7.0rc1-17-g8b815ddad
  case "${COMMIT:?}" in
    8b815ddad*) ;;
    *) echo "oft: the postgis_revision.h constant $rev is for 8b815ddad, but COMMIT=$COMMIT; re-derive it" >&2; return 1 ;;
  esac
  [ ! -e "${SRCDIR:?}/postgis_revision.h" ] \
    || { echo "oft: $SRCDIR/postgis_revision.h exists upstream now; this block would silently override it" >&2; return 1; }
  stage=$(mktemp -d)
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'AC_ARG_WITH([phony-revision]' "$stage/configure.ac" \
    || { echo "oft: configure.ac no longer has --without-phony-revision; re-read the mechanism" >&2; return 1; }
  grep -qxF 'postgis_revision.h:' "$stage/GNUmakefile.in" \
    || { echo "oft: GNUmakefile.in no longer has the postgis_revision.h rule; re-read the mechanism" >&2; return 1; }
  printf '#define POSTGIS_REVISION %s\n' "$rev" > "$stage/postgis_revision.h"
  grep -qxF "#define POSTGIS_REVISION $rev" "$stage/postgis_revision.h" \
    || { echo "oft: $stage/postgis_revision.h was not written" >&2; return 1; }




  stubs=$(mktemp -d)
  cp -a /work/targets/postgis-wkt_import_fuzzer/oft-stub/. "$stubs/"
  mkdir -p "$stubs/geos/lib" "$stubs/proj/lib"
  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c "$stubs/src/geos_stub.c" -o "$stubs/geos/lib/geos_stub.o"
  "$DRVCC" ${BASE_CFLAGS} -c "$stubs/src/proj_stub.c" -o "$stubs/proj/lib/proj_stub.o"
  "$CHOST-ar" crs "$stubs/geos/lib/libgeos_c.a" "$stubs/geos/lib/geos_stub.o"
  "$CHOST-ar" crs "$stubs/proj/lib/libproj.a" "$stubs/proj/lib/proj_stub.o"
  "$CHOST-nm" "$stubs/geos/lib/libgeos_c.a" | grep -q ' T initGEOS$' \
    || { echo "oft: the GEOS link-probe archive defines no initGEOS" >&2; return 1; }
  [ "$("$CHOST-nm" "$stubs/proj/lib/libproj.a" | grep -c -E ' T (pj_get_release|proj_info)$')" -eq 2 ] \
    || { echo "oft: the PROJ link-probe archive lacks pj_get_release or proj_info" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools \
    --without-pgconfig --without-raster --without-protobuf \
    --without-phony-revision \
    --with-geosconfig="$stubs/geos-config" \
    --with-projdir="$stubs/proj" \
    --with-xml2config=/work/targets/postgis-wkt_import_fuzzer/oft-stub/xml2-config \
    PROJ_VERSION=9.4.1 \
    GMP_CFLAGS=-I/opt/musl-sysroot/usr/include \
    "GMP_LIBS=-L/opt/musl-sysroot/usr/lib -lgmp" \
    JSONC_CFLAGS=-I/opt/musl-sysroot/usr/include/json-c \
    "JSONC_LIBS=-L/opt/musl-sysroot/usr/lib -ljson-c"
  SRCDIR="$saved_srcdir"


  guard=$(grep -B1 -xF '.PHONY: postgis_revision.h' "$BUILDDIR/src/GNUmakefile" | head -n 1)
  [ "$guard" = 'ifeq (no,yes)' ] \
    || { echo "oft: postgis_revision.h .PHONY guard is '$guard', expected 'ifeq (no,yes)' -- --without-phony-revision was not honoured" >&2; return 1; }
  grep -qxF "#define POSTGIS_REVISION $rev" "$BUILDDIR/src/postgis_revision.h" \
    || { echo "oft: postgis_revision.h does not carry the pinned revision:" >&2
         cat "$BUILDDIR/src/postgis_revision.h" >&2 || echo "oft: (no postgis_revision.h at all)" >&2
         return 1; }
  [ "$(wc -l < "$BUILDDIR/src/postgis_revision.h")" -eq 1 ] \
    || { echo "oft: postgis_revision.h has more than the one pinned line; repo_revision.pl rewrote it" >&2; return 1; }


  OFT_HARNESS_CFLAGS="-I/work/targets/postgis-wkt_import_fuzzer/oft-stub/proj/include -I/work/targets/postgis-wkt_import_fuzzer/oft-stub/geos/include"
  oft_build_harness "fuzzers/wkt_import_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}








































































GIT_MIRRORS="https://github.com/postgis/postgis"
ov_target_build wkt_import_fuzzer
)
