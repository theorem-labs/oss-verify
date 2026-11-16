#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of igraph into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# basic_properties_directed: the release's target igraph-basic_properties_directed
(
ov_target_begin igraph-basic_properties_directed
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzing/basic_properties_directed.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































































OFT_IGRAPH_VERSION_STRING='1.0.1-65-ge8e03b245'
oft_igraph_version_file() {
  local f="${SRCDIR:?}/IGRAPH_VERSION" have
  if [ ! -e "$f" ]; then
    echo "oft: igraph: $f is missing (re-cloned ext tree?); writing the pinned version string" >&2
    printf '%s\n' "$OFT_IGRAPH_VERSION_STRING" > "$f" || return 1
  fi



  IFS= read -r have < "$f" || { echo "oft: igraph: cannot read $f" >&2; return 1; }
  [ "$have" = "$OFT_IGRAPH_VERSION_STRING" ] || {
    echo "oft: igraph: $f says '$have', pin says '$OFT_IGRAPH_VERSION_STRING' -- the tree and the shipped binaries would disagree; refusing" >&2
    return 1; }
}
build_lib() {
  oft_require_target_cxx
  oft_igraph_version_file
  oft_build_cmake -DF2C_EXTERNAL_ARITH_HEADER=/work/targets/igraph-basic_properties_directed/arith.h
  oft_build_harness "fuzzing/basic_properties_directed.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build basic_properties_directed
)
