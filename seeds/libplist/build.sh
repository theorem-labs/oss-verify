#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libplist into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# bplist_fuzzer: the release's target libplist-bplist_fuzzer
(
ov_target_begin libplist-bplist_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/bplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























build_lib() {
  export RELEASE_VERSION=2.7.0-66-g32428ab
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/bplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build bplist_fuzzer
)

# jplist_fuzzer: the release's target libplist-jplist_fuzzer
(
ov_target_begin libplist-jplist_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/jplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























build_lib() {
  export RELEASE_VERSION=2.7.0-66-g32428ab
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/jplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build jplist_fuzzer
)

# oplist_fuzzer: the release's target libplist-oplist_fuzzer
(
ov_target_begin libplist-oplist_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/oplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























build_lib() {
  export RELEASE_VERSION=2.7.0-66-g32428ab
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/oplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build oplist_fuzzer
)

# xplist_fuzzer: the release's target libplist-xplist_fuzzer
(
ov_target_begin libplist-xplist_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/xplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























build_lib() {
  export RELEASE_VERSION=2.7.0-66-g32428ab
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "fuzz/xplist_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build xplist_fuzzer
)
