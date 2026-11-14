#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of botan into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# uri: the release's target botan-fuzzers
(
ov_target_begin botan-fuzzers
COMMIT=$(git -C "$SRC/upstream/botan" rev-parse HEAD)
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "src/fuzzer/fuzzers.h"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





















































































build_lib() {
  oft_require_target_cxx || return 1
  oft_copy_src
  ( set -e
    cd "$BUILDDIR/src"

    vc=7700a955ed5cc8d4cc3dd05cc6c75007b243084f
    [ "${COMMIT:?}" = "$vc" ] \
      || { echo "oft: the release_vc_rev constant is for $vc, but COMMIT=$COMMIT; re-derive it" >&2; exit 1; }
    grep -qxF 'release_vc_rev = None' src/build-data/version.txt \
      || { echo "oft: src/build-data/version.txt has no 'release_vc_rev = None' line; re-read configure.py" >&2; exit 1; }
    sed -i "s|^release_vc_rev = None\$|release_vc_rev = 'git:$vc'|" src/build-data/version.txt
    grep -qxF "release_vc_rev = 'git:$vc'" src/build-data/version.txt \
      || { echo "oft: the release_vc_rev pin did not apply to src/build-data/version.txt" >&2; exit 1; }
    python3 ./configure.py \
      --os=linux --cpu=riscv64 --cc=clang \
      --cc-bin="$(oft_cxx)" \
      --cc-abi-flags="$(oft_cxxflags)" \
      --without-documentation --build-targets=static --disable-shared \
      --optimize-for-size \
      --minimized-build --enable-modules=uri,chacha_rng \
      --unsafe-fuzzer-mode \
      --without-os-features=getrandom,getentropy \
      --disable-modules=locking_allocator,system_rng,processor_rng



    grep -qxF "#define BOTAN_VC_REVISION \"git:$vc\"" build/version_info.h \
      || { echo "oft: build/version_info.h does not carry the pinned BOTAN_VC_REVISION:" >&2
           grep -n -e 'VERSION_STRING' -e 'VC_REVISION' build/version_info.h >&2 || echo "oft: (no version lines at all)" >&2
           exit 1; }
    grep -q "^#define BOTAN_FULL_VERSION_STRING \".*, revision git:$vc)\"\$" build/version_info.h \
      || { echo "oft: BOTAN_FULL_VERSION_STRING does not end in the pinned revision:" >&2
           grep -n 'BOTAN_FULL_VERSION_STRING' build/version_info.h >&2 || echo "oft: (no BOTAN_FULL_VERSION_STRING line at all)" >&2
           exit 1; }
    make -j"${OFT_MAKE_JOBS:-4}" libs
  ) || return 1
  oft_merge_archives
  oft_build_harness "src/fuzzer/uri.cpp" \
    -I"$BUILDDIR/src/build/include/public" \
    -I"$BUILDDIR/src/build/include/internal"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build uri
)
