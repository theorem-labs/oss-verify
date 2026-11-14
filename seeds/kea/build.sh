#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of kea into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_util: the release's target kea-fuzz_util
(
ov_target_begin kea-fuzz_util
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "src/fuzz/fuzz_util.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































oft_kea_static_prep() {






  rm -rf -- "${BUILDDIR:?}/mes" "${BUILDDIR:?}/partial-build"
  rm -rf -- "${BUILDDIR:?}/src-patched"
  mkdir -p "${BUILDDIR:?}/src-patched"
  cp -a "${SRCDIR:?}/." "${BUILDDIR:?}/src-patched/"



  local files n
  files=$(find "${BUILDDIR:?}/src-patched" -name meson.build \
            -exec grep -l 'shared_library(' {} +)
  n=$(printf '%s\n' "$files" | sed '/^$/d' | wc -l)
  if [ "$n" -lt 50 ]; then
    echo "oft: kea prep expected >=50 meson.build files calling shared_library(, found $n; refusing" >&2
    return 1
  fi
  printf '%s\n' "$files" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    sed -i 's/shared_library(/library(/g' "$f" || exit 1
  done || return 1
  if find "${BUILDDIR:?}/src-patched" -name meson.build \
       -exec grep -l 'shared_library(' {} + | grep -q .; then
    echo "oft: kea prep left shared_library( survivors" >&2
    return 1
  fi










  local pcn
  pcn=$(grep -c '^    libraries: LIBS_BUILT_SO_FAR,$' "${BUILDDIR:?}/src-patched/meson.build")
  if [ "$pcn" != 1 ]; then
    echo "oft: kea prep expected exactly 1 pkg.generate libraries line, found $pcn; refusing" >&2
    return 1
  fi
  sed -i 's/^    libraries: LIBS_BUILT_SO_FAR,$/    libraries: [],/' \
    "${BUILDDIR:?}/src-patched/meson.build"
  grep -q '^    libraries: \[\],$' "${BUILDDIR:?}/src-patched/meson.build" || {
    echo "oft: kea prep pkg.generate neutralization did not take" >&2
    return 1
  }
}
















OFT_KEA_MAX_JOBS=6
oft_kea_cap_jobs() {
  local j
  j="${OFT_MAKE_JOBS:-$(nproc)}"
  case "$j" in ''|*[!0-9]*) j=$(nproc) ;; esac
  [ "$j" -le "$OFT_KEA_MAX_JOBS" ] || j=$OFT_KEA_MAX_JOBS
  [ "$j" -ge 1 ] || j=1
  OFT_MAKE_JOBS=$j
  export OFT_MAKE_JOBS
  echo "oft: kea ninja parallelism -j$OFT_MAKE_JOBS (cap $OFT_KEA_MAX_JOBS, to bound the peak memory of the build)"
}
build_lib() {
  oft_require_target_cxx
  oft_kea_static_prep || return 1
  oft_kea_cap_jobs
  OFT_KEA_SRCDIR_ORIG=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"




  oft_build_meson -Dbackend_max_links=2
  local rc=$?
  SRCDIR=$OFT_KEA_SRCDIR_ORIG
  [ "$rc" -eq 0 ] || return "$rc"


  local nka
  nka=$(find "${BUILDDIR:?}/mes" -name 'libkea-*.a' | wc -l)
  if [ "$nka" -lt 20 ]; then
    echo "oft: static rewrite produced only $nka libkea-*.a archives; refusing" >&2
    return 1
  fi




  LIB_EXTRA="${LIB_EXTRA:-} ${OFT_SYSROOT:-/opt/musl-sysroot}/usr/lib/liblog4cplus.a"
  oft_build_harness "src/fuzz/fuzz_util.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_util
)
