#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of knot-dns into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_dname_from_str: the release's target knot-dns-fuzz_dname_from_str
(
ov_target_begin knot-dns-fuzz_dname_from_str
build_lib() {
  oft_build_autotools
  oft_build_harness "tests-fuzz/fuzz_dname_from_str.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



























build_lib() {
  export KNOT_VERSION_FORMAT=release
  oft_build_autotools --with-lmdb=embedded --disable-daemon \
    --disable-utilities --disable-documentation --disable-modules \
    --disable-fastparser
  oft_build_harness "tests-fuzz/fuzz_dname_from_str.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_dname_from_str
)

# fuzz_dname_to_str: the release's target knot-dns-fuzz_dname_to_str
(
ov_target_begin knot-dns-fuzz_dname_to_str
build_lib() {
  oft_build_autotools
  oft_build_harness "tests-fuzz/fuzz_dname_to_str.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



























build_lib() {
  export KNOT_VERSION_FORMAT=release
  oft_build_autotools --with-lmdb=embedded --disable-daemon \
    --disable-utilities --disable-documentation --disable-modules \
    --disable-fastparser
  oft_build_harness "tests-fuzz/fuzz_dname_to_str.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_dname_to_str
)

# fuzz_zscanner: the release's target knot-dns-fuzz_zscanner
(
ov_target_begin knot-dns-fuzz_zscanner
build_lib() {
  oft_build_autotools
  oft_build_harness "tests-fuzz/fuzz_zscanner.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




































build_lib() {
  export KNOT_VERSION_FORMAT=release
  oft_build_autotools --with-lmdb=embedded --disable-daemon \
    --disable-utilities --disable-documentation --disable-modules \
    --disable-fastparser
  oft_build_harness "tests-fuzz/fuzz_zscanner.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_zscanner
)
