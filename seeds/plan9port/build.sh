#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of plan9port into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_libsec: the release's target plan9port-fuzz_libsec
(
ov_target_begin plan9port-fuzz_libsec
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_libsec.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""














































oft_p9_cc() {

  local src=$1 obj=$2; shift 2

  if ! "$CC" $CFLAGS -DPLAN9PORT -fsigned-char -fno-common \
       -I"$BUILDDIR/src/include" -I"$(dirname "$src")" "$@" \
       -c "$src" -o "$obj" 2>"$BUILDDIR/p9-cc.err"; then
    echo "oft: compile failed: ${src#$BUILDDIR/src/}" >&2
    cat "$BUILDDIR/p9-cc.err" >&2
    return 1
  fi
}


build_lib() {
  oft_copy_src
  local root="$BUILDDIR/src"







  local x="$root/src/libsec/port/x509.c"
  if ! grep -q 'exits("didn.t parse");' "$x"; then
    echo "oft: x509.c asn1dump no longer calls exits(); revisit the fuzz patch" >&2
    return 1
  fi
  sed -i -e '/print("didn.t parse/d' \
         -e 's/exits("didn.t parse");/return;/' "$x"
  if grep -q 'didn.t parse' "$x"; then
    echo "oft: asn1dump fuzz patch did not apply cleanly" >&2
    return 1
  fi

  local objdir="$BUILDDIR/obj9"
  rm -rf "$objdir"; mkdir -p "$objdir"





  local f src extra n9=0 nmp=0 nsec=0
  for f in $(sed -n 's/^[[:space:]]*\([A-Za-z0-9_]\{1,\}\)\.\$O\\$/\1/p' "$root/src/lib9/mkfile"); do
    extra=""
    if [ -f "$root/src/lib9/$f.c" ]; then src="$root/src/lib9/$f.c"
    elif [ -f "$root/src/lib9/fmt/$f.c" ]; then src="$root/src/lib9/fmt/$f.c"; extra="-I$root/src/lib9/fmt"
    elif [ -f "$root/src/lib9/utf/$f.c" ]; then src="$root/src/lib9/utf/$f.c"
    else echo "oft: lib9 mkfile names $f but no source exists" >&2; return 1; fi
    if [ "$f" = get9root ]; then extra="$extra -DPLAN9_TARGET=\"/usr/local/plan9\""; fi
    oft_p9_cc "$src" "$objdir/lib9_$f.o" $extra || return 1
    n9=$((n9+1))
  done
  if [ "$n9" -lt 120 ]; then
    echo "oft: lib9 mkfile extraction found only $n9 sources (floor 120)" >&2; return 1
  fi



  for f in $(sed -n 's/^[[:space:]]\{1,\}\([a-z0-9_]\{1,\}\)\\$/\1/p' "$root/src/libmp/port/mkfile"); do
    oft_p9_cc "$root/src/libmp/port/$f.c" "$objdir/mp_$f.o" || return 1
    nmp=$((nmp+1))
  done
  if [ "$nmp" -lt 25 ]; then
    echo "oft: libmp mkfile extraction found only $nmp sources (floor 25)" >&2; return 1
  fi


  for f in $(sed -n 's/^[[:space:]]*\([A-Za-z0-9_]\{1,\}\)\.\$O\\$/\1/p' "$root/src/libsec/port/mkfile"); do
    oft_p9_cc "$root/src/libsec/port/$f.c" "$objdir/sec_$f.o" || return 1
    nsec=$((nsec+1))
  done
  if [ "$nsec" -lt 50 ]; then
    echo "oft: libsec mkfile extraction found only $nsec sources (floor 50)" >&2; return 1
  fi
  if [ ! -f "$objdir/sec_x509.o" ]; then
    echo "oft: libsec built without x509.o -- asn1dump is not in the archive" >&2; return 1
  fi

  mkdir -p "$BUILDDIR/lib"
  rm -f "$BUILDDIR/lib/liboft.a"
  "$CHOST-ar" crs "$BUILDDIR/lib/liboft.a" "$objdir"/*.o || return 1
  echo "oft: plan9port archive holds $((n9+nmp+nsec)) objects (lib9 $n9, libmp $nmp, libsec $nsec)"





  printf 'void asn1dump(unsigned char *der, int len);\n' > "$BUILDDIR/oft_p9_decl.h"
  oft_build_harness "fuzz_libsec.c" -DPLAN9PORT -include "$BUILDDIR/oft_p9_decl.h" || return 1
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_libsec
)
