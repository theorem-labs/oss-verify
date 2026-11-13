#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of httrack into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz-cachendx: the release's target httrack-fuzz-cachendx
(
ov_target_begin httrack-fuzz-cachendx
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-cachendx.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-cachendx
)

# fuzz-entities: the release's target httrack-fuzz-entities
(
ov_target_begin httrack-fuzz-entities
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-entities.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-entities
)

# fuzz-filters: the release's target httrack-fuzz-filters
(
ov_target_begin httrack-fuzz-filters
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-filters.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-filters
)

# fuzz-header: the release's target httrack-fuzz-header
(
ov_target_begin httrack-fuzz-header
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-header.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-header
)

# fuzz-meta: the release's target httrack-fuzz-meta
(
ov_target_begin httrack-fuzz-meta
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-meta.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-meta
)

# fuzz-sitemap: the release's target httrack-fuzz-sitemap
(
ov_target_begin httrack-fuzz-sitemap
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-sitemap.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-sitemap
)

# fuzz-unescape: the release's target httrack-fuzz-unescape
(
ov_target_begin httrack-fuzz-unescape
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-unescape.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-unescape
)

# fuzz-url: the release's target httrack-fuzz-url
(
ov_target_begin httrack-fuzz-url
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/fuzz-url.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz-url
)
