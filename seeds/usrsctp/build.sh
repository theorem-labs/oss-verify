#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of usrsctp into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzer_connect: the release's target usrsctp-fuzzer_connect
(
ov_target_begin usrsctp-fuzzer_connect
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzzer/fuzzer_connect.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































oft_seal_usrsctp_time() {
  local obj="$BUILDDIR/seal_usrsctp_time.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/usrsctp-fuzzer_connect/seal_extra.c -o "$obj" || return 1
  for sym in ' T gettimeofday$' ' T clock_gettime$' ' T __wrap_sctp_startup_iterator$'; do
    "$CHOST-nm" "$obj" | grep -q "$sym" || {
      echo "oft: seal_extra.o missing expected symbol $sym" >&2; return 1; }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $obj -Wl,--wrap=sctp_startup_iterator"
}


build_lib() {
  oft_build_cmake -Dsctp_werror=OFF -Dsctp_build_programs=OFF -Dsctp_inet=OFF -Dsctp_inet6=OFF
  oft_build_harness "fuzzer/fuzzer_connect.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_seal_usrsctp_time
}
ov_target_build fuzzer_connect
)

# fuzzer_fragment: the release's target usrsctp-fuzzer_fragment
(
ov_target_begin usrsctp-fuzzer_fragment
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzzer/fuzzer_fragment.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































oft_seal_usrsctp_time() {
  local obj="$BUILDDIR/seal_usrsctp_time.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/usrsctp-fuzzer_fragment/seal_extra.c -o "$obj" || return 1
  for sym in ' T gettimeofday$' ' T clock_gettime$' ' T __wrap_sctp_startup_iterator$'; do
    "$CHOST-nm" "$obj" | grep -q "$sym" || {
      echo "oft: seal_extra.o missing expected symbol $sym" >&2; return 1; }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $obj -Wl,--wrap=sctp_startup_iterator"
}


build_lib() {
  oft_build_cmake -Dsctp_werror=OFF -Dsctp_build_programs=OFF -Dsctp_inet=OFF -Dsctp_inet6=OFF
  oft_build_harness "fuzzer/fuzzer_fragment.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_seal_usrsctp_time
}
ov_target_build fuzzer_fragment
)

# fuzzer_listen: the release's target usrsctp-fuzzer_listen
(
ov_target_begin usrsctp-fuzzer_listen
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzzer/fuzzer_listen.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































oft_seal_usrsctp_time() {
  local obj="$BUILDDIR/seal_usrsctp_time.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/usrsctp-fuzzer_listen/seal_extra.c -o "$obj" || return 1
  for sym in ' T gettimeofday$' ' T clock_gettime$' ' T __wrap_sctp_startup_iterator$'; do
    "$CHOST-nm" "$obj" | grep -q "$sym" || {
      echo "oft: seal_extra.o missing expected symbol $sym" >&2; return 1; }
  done
  LIB_EXTRA="${LIB_EXTRA:-} $obj -Wl,--wrap=sctp_startup_iterator"
}


build_lib() {
  oft_build_cmake -Dsctp_werror=OFF -Dsctp_build_programs=OFF -Dsctp_inet=OFF -Dsctp_inet6=OFF
  oft_build_harness "fuzzer/fuzzer_listen.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
  oft_seal_usrsctp_time
}
ov_target_build fuzzer_listen
)
