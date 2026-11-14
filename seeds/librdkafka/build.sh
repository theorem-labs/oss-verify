#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of librdkafka into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_regex: the release's target librdkafka-fuzz_regex
(
ov_target_begin librdkafka-fuzz_regex
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzzers/fuzz_regex.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























build_lib() {
  oft_build_cmake -DRDKAFKA_BUILD_EXAMPLES=OFF -DRDKAFKA_BUILD_TESTS=OFF -DHAVE_REGEX=OFF || return 1
  cp "$BUILDDIR/cmk/generated/config.h" "$BUILDDIR/src/config.h" || return 1
  if ! "$CHOST-nm" "$BUILDDIR/lib/liboft.a" 2>/dev/null | grep -q ' T re_regcomp$'; then
    echo "oft: HAVE_REGEX probe said yes; compiling builtin src/regexp.c for the harness"
    "$CC" $CFLAGS $LIB_CFLAGS -c "$BUILDDIR/src/src/regexp.c" -o "$BUILDDIR/oft_regexp_builtin.o" || return 1
    llvm-ar r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/oft_regexp_builtin.o" || return 1
    "$CHOST-nm" "$BUILDDIR/lib/liboft.a" 2>/dev/null | grep -q ' T re_regcomp$' || {
      echo "oft: re_regcomp still missing from lib/liboft.a after manual compile" >&2
      return 1
    }
  fi
  oft_build_harness "tests/fuzzers/fuzz_regex.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_regex
)
