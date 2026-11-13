#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libvpx into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# vpx_dec_fuzzer_vp9: the release's target libvpx-vpx_dec_fuzzer
(
ov_target_begin libvpx-vpx_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "examples/vpx_dec_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


































build_lib() {
  oft_require_target_cxx
  oft_copy_src
  sed -i 's|! diff --version >/dev/null|! command -v diff >/dev/null|' "$BUILDDIR/src/configure"
  grep -q '! command -v diff >/dev/null' "$BUILDDIR/src/configure" || {
    echo "oft: diff-probe patch did not apply to configure" >&2; return 1; }


















  sed -i -e 's|^git_version_id=""$|git_version_id="v1.17.0-56-g5c880e08d"|' \
         -e 's|^if \[ -e "${source_path}/\.git" \]; then$|if false; then                                                  |' \
      "$BUILDDIR/src/build/make/version.sh"
  grep -q '^git_version_id="v1.17.0-56-g5c880e08d"$' "$BUILDDIR/src/build/make/version.sh" || {
    echo "oft: version pin did not apply to build/make/version.sh (git_version_id)" >&2; return 1; }
  grep -q '^if false; then                            ' "$BUILDDIR/src/build/make/version.sh" || {
    echo "oft: version pin did not apply to build/make/version.sh (.git branch)" >&2; return 1; }
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" LD="$CC" AR="$CHOST-ar" \
       ./configure --target=generic-gnu \
         --disable-examples --disable-tools --disable-docs --disable-unit-tests \
         --disable-webm-io --enable-vp8-encoder --enable-vp9-encoder \
         --enable-vp9-highbitdepth --size-limit=12288x12288 \
         --extra-cflags="$CFLAGS -DVPX_MAX_ALLOCABLE_MEMORY=1073741824" \
    && make -j"${OFT_MAKE_JOBS:-8}" ) || return 1
  oft_merge_archives







  oft_build_harness "examples/vpx_dec_fuzzer.cc" -DDECODER=vp9 -DFUZZER_DISABLE_NALLOC
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid







  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/libvpx-vpx_dec_fuzzer/wrap_sysconf.c \
      -o "$BUILDDIR/wrap_sysconf.o" || return 1
  "$CHOST-nm" "$BUILDDIR/wrap_sysconf.o" | grep -q ' T __wrap_sysconf$' || {
    echo "oft: wrap_sysconf.o defines no __wrap_sysconf" >&2; return 1; }
  LIB_EXTRA="${LIB_EXTRA:-} $BUILDDIR/wrap_sysconf.o -Wl,--wrap=sysconf"
}
ov_target_build vpx_dec_fuzzer_vp9
)

# vpx_enc_fuzzer_vp9: the release's target libvpx-vpx_enc_fuzzer
(
ov_target_begin libvpx-vpx_enc_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "examples/vpx_enc_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


































build_lib() {
  oft_require_target_cxx
  oft_copy_src
  sed -i 's|! diff --version >/dev/null|! command -v diff >/dev/null|' "$BUILDDIR/src/configure"
  grep -q '! command -v diff >/dev/null' "$BUILDDIR/src/configure" || {
    echo "oft: diff-probe patch did not apply to configure" >&2; return 1; }


















  sed -i -e 's|^git_version_id=""$|git_version_id="v1.17.0-56-g5c880e08d"|' \
         -e 's|^if \[ -e "${source_path}/\.git" \]; then$|if false; then                                                  |' \
      "$BUILDDIR/src/build/make/version.sh"
  grep -q '^git_version_id="v1.17.0-56-g5c880e08d"$' "$BUILDDIR/src/build/make/version.sh" || {
    echo "oft: version pin did not apply to build/make/version.sh (git_version_id)" >&2; return 1; }
  grep -q '^if false; then                            ' "$BUILDDIR/src/build/make/version.sh" || {
    echo "oft: version pin did not apply to build/make/version.sh (.git branch)" >&2; return 1; }
  ( cd "$BUILDDIR/src" \
    && CC="$CC" CXX="$(oft_cxx)" LD="$CC" AR="$CHOST-ar" \
       ./configure --target=generic-gnu \
         --disable-examples --disable-tools --disable-docs --disable-unit-tests \
         --disable-webm-io --enable-vp8-encoder --enable-vp9-encoder \
         --enable-vp9-highbitdepth --size-limit=12288x12288 \
         --extra-cflags="$CFLAGS -DVPX_MAX_ALLOCABLE_MEMORY=1073741824" \
    && make -j"${OFT_MAKE_JOBS:-8}" ) || return 1
  oft_merge_archives







  oft_build_harness "examples/vpx_enc_fuzzer.cc" -DENCODER=vp9 -DFUZZER_DISABLE_NALLOC
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build vpx_enc_fuzzer_vp9
)
