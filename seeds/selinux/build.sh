#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of selinux into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# binpolicy-fuzzer: the release's target selinux-binpolicy-fuzzer
(
ov_target_begin selinux-binpolicy-fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "libsepol/fuzz/binpolicy-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































build_lib() {




  OFT_BLIND_CFLAGS="${OFT_BLIND_CFLAGS:-} -DHAVE_REALLOCARRAY"
  oft_build_blind libsepol
  oft_build_harness "libsepol/fuzz/binpolicy-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build binpolicy-fuzzer
)

# module-package-fuzzer: the release's target selinux-module-package-fuzzer
(
ov_target_begin selinux-module-package-fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "libsepol/fuzz/module-package-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































build_lib() {




  OFT_BLIND_CFLAGS="${OFT_BLIND_CFLAGS:-} -DHAVE_REALLOCARRAY"
  oft_build_blind libsepol
  oft_build_harness "libsepol/fuzz/module-package-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build module-package-fuzzer
)

# secilc-fuzzer: the release's target selinux-secilc-fuzzer
(
ov_target_begin selinux-secilc-fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "libsepol/fuzz/secilc-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































build_lib() {




  OFT_BLIND_CFLAGS="${OFT_BLIND_CFLAGS:-} -DHAVE_REALLOCARRAY"
  oft_build_blind libsepol
  flex -o "$BUILDDIR/obj/cil_lexer.c" "$BUILDDIR/src/libsepol/cil/src/cil_lexer.l"

  "$CC" $CFLAGS \
    -I"$BUILDDIR/src/libsepol/cil/src" \
    -I"$BUILDDIR/src/libsepol/cil/include" \
    -I"$BUILDDIR/src/libsepol/include" \
    -c "$BUILDDIR/obj/cil_lexer.c" -o "$BUILDDIR/obj/cil_lexer.o"
  "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/obj/cil_lexer.o"
  oft_build_harness "libsepol/fuzz/secilc-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build secilc-fuzzer
)
