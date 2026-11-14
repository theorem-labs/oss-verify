#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libbpf into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# bpf-object-fuzzer: the release's target libbpf-bpf-object-fuzzer
(
ov_target_begin libbpf-bpf-object-fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "fuzz/bpf-object-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""































if [ -d "${SRCDIR:-/nonexistent}/include/uapi" ] && [ -d "${BUILDDIR:-/nonexistent}" ]; then
  mkdir -p "$BUILDDIR/hdr-promote"
  cp -r "$SRCDIR/include/." "$BUILDDIR/hdr-promote/"
fi
OFT_BLIND_CFLAGS="-I${BUILDDIR:-}/hdr-promote -I${BUILDDIR:-}/hdr-promote/uapi"
OFT_HARNESS_CFLAGS="-I${BUILDDIR:-}/hdr-promote -I${BUILDDIR:-}/hdr-promote/uapi"
ov_target_build bpf-object-fuzzer
)
