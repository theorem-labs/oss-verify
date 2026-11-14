#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libgit2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# config_file_fuzzer: the release's target libgit2-config_file_fuzzer
(
ov_target_begin libgit2-config_file_fuzzer
build_lib() {
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/config_file_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































OFT_LIBGIT2_BUILD_COMMIT='0551dfd4ad989b6a3d5683c0d4cf326c6efef929'
oft_libgit2_build_commit_pinned() {
  local f="${SRCDIR:?}/src/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: libgit2: $f is missing" >&2; return 1; }



  if grep -qE '^[[:space:]]*execute_process\(COMMAND[[:space:]]+git' "$f"; then
    echo "oft: libgit2: $f still asks git for GIT_BUILD_COMMIT (unpatched ext tree?); refusing" >&2
    return 1
  fi
  grep -qF "set(GIT_BUILD_COMMIT \"$OFT_LIBGIT2_BUILD_COMMIT\")" "$f" || {
    echo "oft: libgit2: $f does not pin GIT_BUILD_COMMIT to $OFT_LIBGIT2_BUILD_COMMIT; refusing" >&2
    return 1; }
}
build_lib() {
  oft_libgit2_build_commit_pinned
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/config_file_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build config_file_fuzzer
)

# objects_fuzzer: the release's target libgit2-objects_fuzzer
(
ov_target_begin libgit2-objects_fuzzer
build_lib() {
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/objects_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































OFT_LIBGIT2_BUILD_COMMIT='0551dfd4ad989b6a3d5683c0d4cf326c6efef929'
oft_libgit2_build_commit_pinned() {
  local f="${SRCDIR:?}/src/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: libgit2: $f is missing" >&2; return 1; }



  if grep -qE '^[[:space:]]*execute_process\(COMMAND[[:space:]]+git' "$f"; then
    echo "oft: libgit2: $f still asks git for GIT_BUILD_COMMIT (unpatched ext tree?); refusing" >&2
    return 1
  fi
  grep -qF "set(GIT_BUILD_COMMIT \"$OFT_LIBGIT2_BUILD_COMMIT\")" "$f" || {
    echo "oft: libgit2: $f does not pin GIT_BUILD_COMMIT to $OFT_LIBGIT2_BUILD_COMMIT; refusing" >&2
    return 1; }
}
build_lib() {
  oft_libgit2_build_commit_pinned
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/objects_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build objects_fuzzer
)

# packfile_fuzzer: the release's target libgit2-packfile_fuzzer
(
ov_target_begin libgit2-packfile_fuzzer
build_lib() {
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/packfile_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































OFT_LIBGIT2_BUILD_COMMIT='0551dfd4ad989b6a3d5683c0d4cf326c6efef929'
oft_libgit2_build_commit_pinned() {
  local f="${SRCDIR:?}/src/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: libgit2: $f is missing" >&2; return 1; }



  if grep -qE '^[[:space:]]*execute_process\(COMMAND[[:space:]]+git' "$f"; then
    echo "oft: libgit2: $f still asks git for GIT_BUILD_COMMIT (unpatched ext tree?); refusing" >&2
    return 1
  fi
  grep -qF "set(GIT_BUILD_COMMIT \"$OFT_LIBGIT2_BUILD_COMMIT\")" "$f" || {
    echo "oft: libgit2: $f does not pin GIT_BUILD_COMMIT to $OFT_LIBGIT2_BUILD_COMMIT; refusing" >&2
    return 1; }
}
build_lib() {
  oft_libgit2_build_commit_pinned
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/packfile_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build packfile_fuzzer
)

# patch_parse_fuzzer: the release's target libgit2-patch_parse_fuzzer
(
ov_target_begin libgit2-patch_parse_fuzzer
build_lib() {
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/patch_parse_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































OFT_LIBGIT2_BUILD_COMMIT='0551dfd4ad989b6a3d5683c0d4cf326c6efef929'
oft_libgit2_build_commit_pinned() {
  local f="${SRCDIR:?}/src/CMakeLists.txt"
  [ -f "$f" ] || { echo "oft: libgit2: $f is missing" >&2; return 1; }



  if grep -qE '^[[:space:]]*execute_process\(COMMAND[[:space:]]+git' "$f"; then
    echo "oft: libgit2: $f still asks git for GIT_BUILD_COMMIT (unpatched ext tree?); refusing" >&2
    return 1
  fi
  grep -qF "set(GIT_BUILD_COMMIT \"$OFT_LIBGIT2_BUILD_COMMIT\")" "$f" || {
    echo "oft: libgit2: $f does not pin GIT_BUILD_COMMIT to $OFT_LIBGIT2_BUILD_COMMIT; refusing" >&2
    return 1; }
}
build_lib() {
  oft_libgit2_build_commit_pinned
  oft_build_cmake -DUSE_HTTPS=OFF -DUSE_NTLMCLIENT=OFF
  oft_build_harness "fuzzers/patch_parse_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build patch_parse_fuzzer
)
