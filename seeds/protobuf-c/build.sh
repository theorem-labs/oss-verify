#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of protobuf-c into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# unpack_fuzzer: the release's target protobuf-c-unpack_fuzzer
(
ov_target_begin protobuf-c-unpack_fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "unpack_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















































build_lib() {
  oft_build_autotools --disable-protoc
  command -v protoc >/dev/null 2>&1 || {
    echo "oft: protobuf-c pin: no protoc on this image (needed to generate t/test-full.pb-c.*)" >&2
    return 1
  }
  command -v protoc-gen-c >/dev/null 2>&1 || {
    echo "oft: protobuf-c pin: no protoc-gen-c on this image (protoc --c_out needs the plugin)" >&2
    return 1
  }
  mkdir -p "$BUILDDIR/gen"
  protoc --c_out="$BUILDDIR/gen" -I"$BUILDDIR/src" "$BUILDDIR/src/t/test-full.proto" || {
    echo "oft: protobuf-c pin: protoc --c_out failed on t/test-full.proto" >&2
    return 1
  }

  "$CC" $CFLAGS -I"$BUILDDIR/gen" -I"$BUILDDIR/src" \
    -c "$BUILDDIR/gen/t/test-full.pb-c.c" -o "$BUILDDIR/test-full.pb-c.o" || {
    echo "oft: protobuf-c pin: generated test-full.pb-c.c failed to compile" >&2
    return 1
  }
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$BUILDDIR/test-full.pb-c.o" || return 1
  OFT_HARNESS_CFLAGS="${OFT_HARNESS_CFLAGS:-} -I$BUILDDIR/gen"
  oft_build_harness "unpack_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build unpack_fuzzer
)
