#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of openvswitch into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# json_parser_target: the release's target openvswitch-json_parser_target
(
ov_target_begin openvswitch-json_parser_target
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/oss-fuzz/json_parser_target.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build json_parser_target
)

# odp_target: the release's target openvswitch-odp_target
(
ov_target_begin openvswitch-odp_target
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/oss-fuzz/odp_target.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build odp_target
)

# ofctl_parse_target: the release's target openvswitch-ofctl_parse_target
(
ov_target_begin openvswitch-ofctl_parse_target
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/oss-fuzz/ofctl_parse_target.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build ofctl_parse_target
)
