#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of tcpreplay into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_pcap: the release's target tcpreplay-fuzz_pcap
(
ov_target_begin tcpreplay-fuzz_pcap
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzz_pcap.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_build_cmake -DWITH_LIBPCAP=/opt/musl-sysroot/usr -DENABLE_STATIC_LINK=ON -DHAVE_TX_RING=0
  oft_build_harness "test/fuzz/fuzz_pcap.c"
  LIB_EXTRA="${LIB_EXTRA:-} /opt/musl-sysroot/usr/lib/libpcap.a"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_pcap
)

# fuzz_services: the release's target tcpreplay-fuzz_services
(
ov_target_begin tcpreplay-fuzz_services
build_lib() {
  oft_build_cmake
  oft_build_harness "test/fuzz/fuzz_services.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































build_lib() {
  oft_build_cmake -DWITH_LIBPCAP=/opt/musl-sysroot/usr -DENABLE_STATIC_LINK=ON -DHAVE_TX_RING=0
  oft_build_harness "test/fuzz/fuzz_services.c"
  LIB_EXTRA="${LIB_EXTRA:-} /opt/musl-sysroot/usr/lib/libpcap.a"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_services
)
