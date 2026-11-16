#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ada-url into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ada_c: the release's target ada-url-ada_c
(
ov_target_begin ada-url-ada_c
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/ada_c.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/ada_c.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build ada_c
)

# can_parse: the release's target ada-url-can_parse
(
ov_target_begin ada-url-can_parse
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/can_parse.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/can_parse.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build can_parse
)

# idna: the release's target ada-url-idna
(
ov_target_begin ada-url-idna
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/idna.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/idna.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build idna
)

# max_length: the release's target ada-url-max_length
(
ov_target_begin ada-url-max_length
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/max_length.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/max_length.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build max_length
)

# parse: the release's target ada-url-parse
(
ov_target_begin ada-url-parse
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/parse.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/parse.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parse
)

# serializers: the release's target ada-url-serializers
(
ov_target_begin ada-url-serializers
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/serializers.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/serializers.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build serializers
)

# simple_absolute: the release's target ada-url-simple_absolute
(
ov_target_begin ada-url-simple_absolute
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/simple_absolute.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/simple_absolute.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build simple_absolute
)

# unicode: the release's target ada-url-unicode
(
ov_target_begin ada-url-unicode
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/unicode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/unicode.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build unicode
)

# url_search_params: the release's target ada-url-url_search_params
(
ov_target_begin ada-url-url_search_params
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzz/url_search_params.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  oft_require_target_cxx
  oft_build_header_only
  oft_build_harness "fuzz/url_search_params.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build url_search_params
)
