#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of powerdns into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_target_dnslabeltext_parseRFC1035CharString: the release's target powerdns-fuzz_dnslabeltext_parseRFC1035CharString
(
ov_target_begin powerdns-fuzz_dnslabeltext_parseRFC1035CharString
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "pdns/fuzz_dnslabeltext_parseRFC1035CharString.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















build_lib() {
  oft_require_target_cxx
  oft_build_autotools --without-dynmodules --with-modules= \
    --disable-lua-records --disable-ixfrdist
  oft_build_harness "pdns/fuzz_dnslabeltext_parseRFC1035CharString.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_target_dnslabeltext_parseRFC1035CharString
)
