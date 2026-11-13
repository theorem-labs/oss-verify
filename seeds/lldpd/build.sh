#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of lldpd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_lldp: the release's target lldpd-fuzz_lldp
(
ov_target_begin lldpd-fuzz_lldp
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/fuzz_lldp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_lldpd_seal_libcap
}






























oft_lldpd_seal_libcap() {
  local src="$BUILDDIR/oft_cap_stub.c" obj="$BUILDDIR/oft_cap_stub.o"
  cat > "$src" <<'EOF'
                                                                         
                                                                          
                                                                          
   
typedef struct _cap_struct *cap_t;
cap_t cap_from_text(const char *s);
int cap_set_proc(cap_t c);
int cap_free(void *p);
cap_t cap_from_text(const char *s) { (void)s; return (cap_t)0; }
int cap_set_proc(cap_t c) { (void)c; return -1; }
int cap_free(void *p) { (void)p; return 0; }
EOF

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c "$src" -o "$obj" || return 1
  "$CHOST-nm" "$obj" | grep -q ' T cap_from_text$' || {
    echo "oft: oft_cap_stub.o defines no cap_from_text" >&2
    return 1
  }
  LIB_EXTRA="$obj ${LIB_EXTRA:-}"
  echo "oft: libcap sealed: cap_from_text/cap_set_proc/cap_free from $obj, libcap.a not pulled"
}

LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_lldp
)
