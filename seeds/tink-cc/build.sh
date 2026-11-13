#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of tink-cc into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# tink_encrypt_fuzzer: the release's target tink-cc-tink_encrypt_decrypt_fuzzer
(
ov_target_begin tink-cc-tink_encrypt_decrypt_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tink_encrypt_decrypt_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































































































OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-8}"
export OFT_MAKE_JOBS





build_lib() {
  oft_require_target_cxx
  for oft_v in abseil boringssl protobuf; do
    [ -f "$SRCDIR/oft-vendor/$oft_v/CMakeLists.txt" ] || {
      echo "oft: tink-cc: vendored $oft_v missing at $SRCDIR/oft-vendor/$oft_v -- this pin vendors it" >&2
      return 1
    }
  done
  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ABSEIL="$BUILDDIR/src/oft-vendor/abseil" \
    -DFETCHCONTENT_SOURCE_DIR_BORINGSSL="$BUILDDIR/src/oft-vendor/boringssl" \
    -DFETCHCONTENT_SOURCE_DIR_PROTOBUF="$BUILDDIR/src/oft-vendor/protobuf"
  oft_build_harness "tink_encrypt_decrypt_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}







































VENDOR_TREES="
oft-vendor/abseil sha256:6e1aee535473414164bf83e4ebc40240dec71a4701f8a642d906e95bea1aea0c https://github.com/abseil/abseil-cpp/releases/download/20260526.0/abseil-cpp-20260526.0.tar.gz 1
oft-vendor/boringssl sha256:585c91782fc0651ba6f2376b672acdc30437705d8a50b4967c20e6293e318969 https://github.com/google/boringssl/releases/download/0.20260803.0/boringssl-0.20260803.0.tar.gz 1 !util/ar/testdata/,!third_party/wycheproof_testvectors/,!fuzz/
oft-vendor/protobuf sha256:6544e5ceec7f29d00397193360435ca8b3c4e843de3cf5698a99d36b72d65342 https://github.com/protocolbuffers/protobuf/releases/download/v30.2/protobuf-30.2.zip 1 !compatibility/
"
ov_target_build tink_encrypt_fuzzer
)
