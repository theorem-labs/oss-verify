#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of numactl into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_parse_str: the release's target numactl-fuzz_parse_str
(
ov_target_begin numactl-fuzz_parse_str
# In place of the release's patch 0001-autoreconf-output-for-the-tracked-aux-dir.patch, which is what this writes:
( cd "$SRCDIR" && autoreconf -fi >/dev/null && rm -rf autom4te.cache configure~ )
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz_parse_str.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_parse_str
)
