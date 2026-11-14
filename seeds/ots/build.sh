#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ots into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ots-fuzzer: the release's target ots-ots-fuzzer
(
ov_target_begin ots-ots-fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "util/ots-fuzzer.cc" -DOTS_FUZZER_NO_MAIN
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



























































build_lib() {
  oft_require_target_cxx
  local sp
  for sp in woff2-1.0.2 lz4-1.10.0; do
    [ -f "$SRCDIR/subprojects/$sp/meson.build" ] || {
      echo "oft: vendored meson subproject $sp is missing from $SRCDIR/subprojects" >&2
      echo "oft: recreate it as targets/$T/pin vendors it (meson configures offline)" >&2
      return 1
    }
  done
  oft_build_meson --wrap-mode=nodownload
  oft_build_harness "util/ots-fuzzer.cc" -DOTS_FUZZER_NO_MAIN
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
subprojects/lz4-1.10.0 sha256:537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b https://github.com/lz4/lz4/archive/v1.10.0.tar.gz 1
subprojects/lz4-1.10.0 sha256:ce568b4e1a7a593bb233f3ec97af88ceb850524cef802fe3f916b21d8a79b6b6 https://wrapdb.mesonbuild.com/v2/lz4_1.10.0-2/get_patch 1
subprojects/woff2-1.0.2 sha256:add272bb09e6384a4833ffca4896350fdb16e0ca22df68c0384773c67a175594 https://github.com/google/woff2/archive/v1.0.2.tar.gz 1
subprojects/woff2-1.0.2 sha256:3ee19aee6b83c85d979b5ada1a786a2cb8a111d345312bc397e2ed68f0d03090 https://wrapdb.mesonbuild.com/v2/google-woff2_1.0.2-4/get_patch 1
"
ov_target_build ots-fuzzer
)
