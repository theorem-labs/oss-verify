#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libxml2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# api: the release's target libxml2-api
(
ov_target_begin libxml2-api
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/api.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build api
)

# html: the release's target libxml2-html
(
ov_target_begin libxml2-html
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/html.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build html
)

# reader: the release's target libxml2-reader
(
ov_target_begin libxml2-reader
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/reader.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build reader
)

# regexp: the release's target libxml2-regexp
(
ov_target_begin libxml2-regexp
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/regexp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build regexp
)

# schema: the release's target libxml2-schema
(
ov_target_begin libxml2-schema
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/schema.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build schema
)

# uri: the release's target libxml2-uri
(
ov_target_begin libxml2-uri
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/uri.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build uri
)

# valid: the release's target libxml2-valid
(
ov_target_begin libxml2-valid
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/valid.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build valid
)

# xinclude: the release's target libxml2-xinclude
(
ov_target_begin libxml2-xinclude
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/xinclude.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build xinclude
)

# xml: the release's target libxml2-xml
(
ov_target_begin libxml2-xml
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/xml.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build xml
)

# xpath: the release's target libxml2-xpath
(
ov_target_begin libxml2-xpath
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/xpath.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build xpath
)
