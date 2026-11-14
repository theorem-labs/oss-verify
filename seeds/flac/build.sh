#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of flac into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzer_decoder: the release's target flac-decoder
(
ov_target_begin flac-decoder
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/decoder.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


























































OFT_FLAC_GIT_COMMIT_HASH='e94ff9f6'
OFT_FLAC_GIT_COMMIT_DATE='20260719'
oft_flac_version_stamp_check_src() {
  local f="${SRCDIR:?}/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: flac: $f missing" >&2; return 1; }
  grep -q 'set(OFT_FLAC_VERSION_STAMP_PINNED 1)' -- "$f" || {
    echo "oft: flac: $f has no pinned version stamp (re-cloned ext tree?) -- it would read .git at configure, which the shipped materials do not carry; apply patch 0002-version-stamp-pinned; refusing" >&2
    return 1; }
  grep -q "set(GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_HASH other than $OFT_FLAC_GIT_COMMIT_HASH; refusing" >&2; return 1; }
  grep -q "set(GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_DATE other than $OFT_FLAC_GIT_COMMIT_DATE; refusing" >&2; return 1; }
  if grep -q 'execute_process' -- "$f"; then
    echo "oft: flac: $f still calls execute_process (the git stamp was not removed); refusing" >&2; return 1; fi
}
oft_flac_version_stamp_check_cfg() {
  local h="${BUILDDIR:?}/cmk/config.h"
  [ -f "$h" ] || { echo "oft: flac: $h missing after configure" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"; refusing" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"; refusing" >&2; return 1; }
  if grep -q '^#define GIT_COMMIT_TAG' -- "$h"; then
    echo "oft: flac: $h defines GIT_COMMIT_TAG, which no shipped flavour had; refusing" >&2; return 1; fi
}




build_lib() {
  oft_flac_version_stamp_check_src
  oft_require_target_cxx
  oft_build_cmake
  oft_flac_version_stamp_check_cfg
  oft_build_harness "oss-fuzz/decoder.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_decoder
)

# fuzzer_encoder: the release's target flac-encoder
(
ov_target_begin flac-encoder
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/encoder.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















































OFT_FLAC_GIT_COMMIT_HASH='e94ff9f6'
OFT_FLAC_GIT_COMMIT_DATE='20260719'
oft_flac_version_stamp_check_src() {
  local f="${SRCDIR:?}/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: flac: $f missing" >&2; return 1; }
  grep -q 'set(OFT_FLAC_VERSION_STAMP_PINNED 1)' -- "$f" || {
    echo "oft: flac: $f has no pinned version stamp (re-cloned ext tree?) -- it would read .git at configure, which the shipped materials do not carry; apply patch 0002-version-stamp-pinned; refusing" >&2
    return 1; }
  grep -q "set(GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_HASH other than $OFT_FLAC_GIT_COMMIT_HASH; refusing" >&2; return 1; }
  grep -q "set(GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_DATE other than $OFT_FLAC_GIT_COMMIT_DATE; refusing" >&2; return 1; }
  if grep -q 'execute_process' -- "$f"; then
    echo "oft: flac: $f still calls execute_process (the git stamp was not removed); refusing" >&2; return 1; fi
}
oft_flac_version_stamp_check_cfg() {
  local h="${BUILDDIR:?}/cmk/config.h"
  [ -f "$h" ] || { echo "oft: flac: $h missing after configure" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"; refusing" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"; refusing" >&2; return 1; }
  if grep -q '^#define GIT_COMMIT_TAG' -- "$h"; then
    echo "oft: flac: $h defines GIT_COMMIT_TAG, which no shipped flavour had; refusing" >&2; return 1; fi
}




build_lib() {
  oft_flac_version_stamp_check_src
  oft_require_target_cxx
  oft_build_cmake
  oft_flac_version_stamp_check_cfg
  oft_build_harness "oss-fuzz/encoder.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_encoder
)

# fuzzer_encoder_v2: the release's target flac-encoder_v2
(
ov_target_begin flac-encoder_v2
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/encoder_v2.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















































OFT_FLAC_GIT_COMMIT_HASH='e94ff9f6'
OFT_FLAC_GIT_COMMIT_DATE='20260719'
oft_flac_version_stamp_check_src() {
  local f="${SRCDIR:?}/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: flac: $f missing" >&2; return 1; }
  grep -q 'set(OFT_FLAC_VERSION_STAMP_PINNED 1)' -- "$f" || {
    echo "oft: flac: $f has no pinned version stamp (re-cloned ext tree?) -- it would read .git at configure, which the shipped materials do not carry; apply patch 0002-version-stamp-pinned; refusing" >&2
    return 1; }
  grep -q "set(GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_HASH other than $OFT_FLAC_GIT_COMMIT_HASH; refusing" >&2; return 1; }
  grep -q "set(GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_DATE other than $OFT_FLAC_GIT_COMMIT_DATE; refusing" >&2; return 1; }
  if grep -q 'execute_process' -- "$f"; then
    echo "oft: flac: $f still calls execute_process (the git stamp was not removed); refusing" >&2; return 1; fi
}
oft_flac_version_stamp_check_cfg() {
  local h="${BUILDDIR:?}/cmk/config.h"
  [ -f "$h" ] || { echo "oft: flac: $h missing after configure" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"; refusing" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"; refusing" >&2; return 1; }
  if grep -q '^#define GIT_COMMIT_TAG' -- "$h"; then
    echo "oft: flac: $h defines GIT_COMMIT_TAG, which no shipped flavour had; refusing" >&2; return 1; fi
}




build_lib() {
  oft_flac_version_stamp_check_src
  oft_require_target_cxx
  oft_build_cmake
  oft_flac_version_stamp_check_cfg
  oft_build_harness "oss-fuzz/encoder_v2.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_encoder_v2
)

# fuzzer_metadata: the release's target flac-metadata
(
ov_target_begin flac-metadata
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/metadata.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















































OFT_FLAC_GIT_COMMIT_HASH='e94ff9f6'
OFT_FLAC_GIT_COMMIT_DATE='20260719'
oft_flac_version_stamp_check_src() {
  local f="${SRCDIR:?}/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: flac: $f missing" >&2; return 1; }
  grep -q 'set(OFT_FLAC_VERSION_STAMP_PINNED 1)' -- "$f" || {
    echo "oft: flac: $f has no pinned version stamp (re-cloned ext tree?) -- it would read .git at configure, which the shipped materials do not carry; apply patch 0002-version-stamp-pinned; refusing" >&2
    return 1; }
  grep -q "set(GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_HASH other than $OFT_FLAC_GIT_COMMIT_HASH; refusing" >&2; return 1; }
  grep -q "set(GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_DATE other than $OFT_FLAC_GIT_COMMIT_DATE; refusing" >&2; return 1; }
  if grep -q 'execute_process' -- "$f"; then
    echo "oft: flac: $f still calls execute_process (the git stamp was not removed); refusing" >&2; return 1; fi
}
oft_flac_version_stamp_check_cfg() {
  local h="${BUILDDIR:?}/cmk/config.h"
  [ -f "$h" ] || { echo "oft: flac: $h missing after configure" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"; refusing" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"; refusing" >&2; return 1; }
  if grep -q '^#define GIT_COMMIT_TAG' -- "$h"; then
    echo "oft: flac: $h defines GIT_COMMIT_TAG, which no shipped flavour had; refusing" >&2; return 1; fi
}




build_lib() {
  oft_flac_version_stamp_check_src
  oft_require_target_cxx
  oft_build_cmake
  oft_flac_version_stamp_check_cfg
  oft_build_harness "oss-fuzz/metadata.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_metadata
)

# fuzzer_reencoder: the release's target flac-reencoder
(
ov_target_begin flac-reencoder
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/reencoder.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















































OFT_FLAC_GIT_COMMIT_HASH='e94ff9f6'
OFT_FLAC_GIT_COMMIT_DATE='20260719'
oft_flac_version_stamp_check_src() {
  local f="${SRCDIR:?}/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: flac: $f missing" >&2; return 1; }
  grep -q 'set(OFT_FLAC_VERSION_STAMP_PINNED 1)' -- "$f" || {
    echo "oft: flac: $f has no pinned version stamp (re-cloned ext tree?) -- it would read .git at configure, which the shipped materials do not carry; apply patch 0002-version-stamp-pinned; refusing" >&2
    return 1; }
  grep -q "set(GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_HASH other than $OFT_FLAC_GIT_COMMIT_HASH; refusing" >&2; return 1; }
  grep -q "set(GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_DATE other than $OFT_FLAC_GIT_COMMIT_DATE; refusing" >&2; return 1; }
  if grep -q 'execute_process' -- "$f"; then
    echo "oft: flac: $f still calls execute_process (the git stamp was not removed); refusing" >&2; return 1; fi
}
oft_flac_version_stamp_check_cfg() {
  local h="${BUILDDIR:?}/cmk/config.h"
  [ -f "$h" ] || { echo "oft: flac: $h missing after configure" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"; refusing" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"; refusing" >&2; return 1; }
  if grep -q '^#define GIT_COMMIT_TAG' -- "$h"; then
    echo "oft: flac: $h defines GIT_COMMIT_TAG, which no shipped flavour had; refusing" >&2; return 1; fi
}




build_lib() {
  oft_flac_version_stamp_check_src
  oft_require_target_cxx
  oft_build_cmake
  oft_flac_version_stamp_check_cfg
  oft_build_harness "oss-fuzz/reencoder.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_reencoder
)

# fuzzer_seek: the release's target flac-seek
(
ov_target_begin flac-seek
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "oss-fuzz/seek.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















































OFT_FLAC_GIT_COMMIT_HASH='e94ff9f6'
OFT_FLAC_GIT_COMMIT_DATE='20260719'
oft_flac_version_stamp_check_src() {
  local f="${SRCDIR:?}/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: flac: $f missing" >&2; return 1; }
  grep -q 'set(OFT_FLAC_VERSION_STAMP_PINNED 1)' -- "$f" || {
    echo "oft: flac: $f has no pinned version stamp (re-cloned ext tree?) -- it would read .git at configure, which the shipped materials do not carry; apply patch 0002-version-stamp-pinned; refusing" >&2
    return 1; }
  grep -q "set(GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_HASH other than $OFT_FLAC_GIT_COMMIT_HASH; refusing" >&2; return 1; }
  grep -q "set(GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\")" -- "$f" || {
    echo "oft: flac: $f pins a GIT_COMMIT_DATE other than $OFT_FLAC_GIT_COMMIT_DATE; refusing" >&2; return 1; }
  if grep -q 'execute_process' -- "$f"; then
    echo "oft: flac: $f still calls execute_process (the git stamp was not removed); refusing" >&2; return 1; fi
}
oft_flac_version_stamp_check_cfg() {
  local h="${BUILDDIR:?}/cmk/config.h"
  [ -f "$h" ] || { echo "oft: flac: $h missing after configure" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_HASH \"$OFT_FLAC_GIT_COMMIT_HASH\"; refusing" >&2; return 1; }
  grep -q "^#define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"\$" -- "$h" || {
    echo "oft: flac: $h does not define GIT_COMMIT_DATE \"$OFT_FLAC_GIT_COMMIT_DATE\"; refusing" >&2; return 1; }
  if grep -q '^#define GIT_COMMIT_TAG' -- "$h"; then
    echo "oft: flac: $h defines GIT_COMMIT_TAG, which no shipped flavour had; refusing" >&2; return 1; fi
}




build_lib() {
  oft_flac_version_stamp_check_src
  oft_require_target_cxx
  oft_build_cmake
  oft_flac_version_stamp_check_cfg
  oft_build_harness "oss-fuzz/seek.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_seek
)
