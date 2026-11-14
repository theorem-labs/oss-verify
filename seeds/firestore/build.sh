#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of firestore into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# firestore_fieldpath_fuzzer: the release's target firestore-fieldpath_fuzzer
(
ov_target_begin firestore-fieldpath_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "Firestore/fuzzing/fieldpath_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""















































































































































build_lib() {
  oft_require_target_cxx
  ( cd "${SRCDIR:?}/oft-vendor" && sha256sum -c --quiet SHA256SUMS ) \
    || { echo "oft: firestore vendored downloads (oft-vendor/SHA256SUMS) missing or corrupt; refusing" >&2; return 1; }
  for oft_fs_f in googletest leveldb; do
    grep -q '^  URL_HASH SHA256=' "${SRCDIR:?}/cmake/external/$oft_fs_f.cmake" \
      && ! grep -q '^ *GIT_REPOSITORY ' "${SRCDIR:?}/cmake/external/$oft_fs_f.cmake" \
      || { echo "oft: firestore cmake/external/$oft_fs_f.cmake still clones (expected the URL/URL_HASH edit of patch 0001); refusing" >&2; return 1; }
  done
  grep -q "os.path.join(root_dir, 'Firestore')" "${SRCDIR:?}/scripts/binary_to_array.py" \
    || { echo "oft: firestore scripts/binary_to_array.py still asserts on .github (a tree without .github/ fails it; expected the Firestore/ marker edit of patch 0002); refusing" >&2; return 1; }


  export PIP_NO_INDEX=1
  export PIP_FIND_LINKS="${BUILDDIR:?}/src/oft-vendor/wheels"
  export PIP_DISABLE_PIP_VERSION_CHECK=1
  oft_build_cmake \
    -DFIREBASE_DOWNLOAD_DIR="${BUILDDIR:?}/src/oft-vendor/downloads" \
    -DgRPC_DOWNLOAD_ARCHIVES=OFF
  echo "oft: firestore: removing BoringSSL ar-parser fixture archives before re-merge:"
  find "$BUILDDIR/cmk" -path '*/util/ar/testdata/*' -name '*.a' -print -delete


  LIB_EXTRA=""
  oft_merge_archives
  oft_build_harness "Firestore/fuzzing/fieldpath_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









































VENDOR_FILES="
oft-vendor/downloads/abseil-cpp-20240722.1.tar.gz sha256:40cee67604060a7c8794d931538cb55f4d444073e556980c88b6c49bb9b19bb7 https://github.com/abseil/abseil-cpp/archive/20240722.1.tar.gz
oft-vendor/downloads/boringssl-ae72a4514c7afd150596b0a80947f3ca9b8363b5.tar.gz sha256:057f662b0e85931a84945b2e89ba201fd44b0583da827c948fe443593690fb83 https://github.com/google/boringssl/archive/ae72a4514c7afd150596b0a80947f3ca9b8363b5.tar.gz
oft-vendor/downloads/c-ares-e982924acee7f7313b4baa4ee5ec000c5e373c30.tar.gz sha256:e8c2751ddc70fed9dc6f999acd92e232d5846f009ee1674f8aee81f19b2b915a https://github.com/c-ares/c-ares/archive/e982924acee7f7313b4baa4ee5ec000c5e373c30.tar.gz
oft-vendor/downloads/GoogleUtilities-8.0.0.tar.gz sha256:570f492dcf5ead37ca4dd11cfb65f3f6fd82ebf42658e9df687047d17b290f79 https://github.com/google/GoogleUtilities/archive/8.0.0.tar.gz
oft-vendor/downloads/googletest-4a00a24fff3cf82254de382437bf840cab1d3993.tar.gz sha256:6e1d9fe2d3a03f5b4ff3705849481c60e3bd5dbc0685bf0ad562eab47f94c16a https://github.com/google/googletest/archive/4a00a24fff3cf82254de382437bf840cab1d3993.tar.gz
oft-vendor/downloads/grpc-1.69.0.tar.gz sha256:cd256d91781911d46a57506978b3979bfee45d5086a1b6668a3ae19c5e77f8dc https://github.com/grpc/grpc/archive/v1.69.0.tar.gz
oft-vendor/downloads/leveldb-1.22.tar.gz sha256:55423cac9e3306f4a9502c738a001e4a339d1a38ffbee7572d4a07d5d63949b2 https://github.com/google/leveldb/archive/refs/tags/1.22.tar.gz
oft-vendor/downloads/nanopb-0.3.9.8.tar.gz sha256:2047ff111ca408c9b3c06a6774b723c1b1c9e31dc2320c61ee3abce93359eb30 https://github.com/nanopb/nanopb/archive/nanopb-0.3.9.8.tar.gz
oft-vendor/downloads/protobuf-7f94235e552599141950d7a4a3eaf93bc87d1b22.tar.gz sha256:70f480fe9cb0c6829dbf6be3c388103313aacb65de667b86d981bbc9eaedb905 https://github.com/protocolbuffers/protobuf/archive/7f94235e552599141950d7a4a3eaf93bc87d1b22.tar.gz
oft-vendor/downloads/re2-2022-04-01.tar.gz sha256:1ae8ccfdb1066a731bba6ee0881baad5efd2cd661acd9569b689f2586e1a50e9 https://github.com/google/re2/archive/2022-04-01.tar.gz
oft-vendor/downloads/snappy-1.1.9.tar.gz sha256:75c1fbb3d618dd3a0483bff0e26d0a92b495bbe5059c8b4f1c962b478b6e06e7 https://github.com/google/snappy/archive/refs/tags/1.1.9.tar.gz
oft-vendor/wheels/six-1.17.0-py2.py3-none-any.whl sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274 https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl
"
ov_target_build firestore_fieldpath_fuzzer
)
