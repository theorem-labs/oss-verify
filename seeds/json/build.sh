#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of json into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# parse_afl_fuzzer: the release's target json-fuzzer-parse_json
(
ov_target_begin json-fuzzer-parse_json
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "tests/src/fuzzer-parse_json.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  mkdir -p "$BUILDDIR/oft-harness-solo"
  cp "$BUILDDIR/src/tests/src/fuzzer-parse_json.cpp" "$BUILDDIR/oft-harness-solo/"
  oft_build_harness "$BUILDDIR/oft-harness-solo/fuzzer-parse_json.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse_afl_fuzzer
)

# parse_bjdata_fuzzer: the release's target json-fuzzer-parse_bjdata
(
ov_target_begin json-fuzzer-parse_bjdata
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "tests/src/fuzzer-parse_bjdata.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  mkdir -p "$BUILDDIR/oft-harness-solo"
  cp "$BUILDDIR/src/tests/src/fuzzer-parse_bjdata.cpp" "$BUILDDIR/oft-harness-solo/"
  oft_build_harness "$BUILDDIR/oft-harness-solo/fuzzer-parse_bjdata.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse_bjdata_fuzzer
)

# parse_bson_fuzzer: the release's target json-fuzzer-parse_bson
(
ov_target_begin json-fuzzer-parse_bson
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "tests/src/fuzzer-parse_bson.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  mkdir -p "$BUILDDIR/oft-harness-solo"
  cp "$BUILDDIR/src/tests/src/fuzzer-parse_bson.cpp" "$BUILDDIR/oft-harness-solo/"
  oft_build_harness "$BUILDDIR/oft-harness-solo/fuzzer-parse_bson.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse_bson_fuzzer
)

# parse_cbor_fuzzer: the release's target json-fuzzer-parse_cbor
(
ov_target_begin json-fuzzer-parse_cbor
build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "tests/src/fuzzer-parse_cbor.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  mkdir -p "$BUILDDIR/oft-harness-solo"
  cp "$BUILDDIR/src/tests/src/fuzzer-parse_cbor.cpp" "$BUILDDIR/oft-harness-solo/"
  oft_build_harness "$BUILDDIR/oft-harness-solo/fuzzer-parse_cbor.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse_cbor_fuzzer
)
