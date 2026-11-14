#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of janet into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_compile: the release's target janet-fuzz_compile
(
ov_target_begin janet-fuzz_compile
build_lib() {
  oft_build_meson
  oft_build_harness "test/fuzzers/fuzz_compile.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_compile
)

# fuzz_dobytes: the release's target janet-fuzz_dobytes
(
ov_target_begin janet-fuzz_dobytes
build_lib() {
  oft_build_meson
  oft_build_harness "test/fuzzers/fuzz_dobytes.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dobytes
)

# fuzz_dostring: the release's target janet-fuzz_dostring
(
ov_target_begin janet-fuzz_dostring
build_lib() {
  oft_build_meson
  oft_build_harness "test/fuzzers/fuzz_dostring.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dostring
)

# fuzz_unmarshal: the release's target janet-fuzz_unmarshal
(
ov_target_begin janet-fuzz_unmarshal
build_lib() {
  oft_build_meson
  oft_build_harness "test/fuzzers/fuzz_unmarshal.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_unmarshal
)
