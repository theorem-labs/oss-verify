#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wolfmqtt into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# broker_fuzz: the release's target wolfmqtt-broker_fuzz
(
ov_target_begin wolfmqtt-broker_fuzz
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/fuzz/broker_fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
























































build_lib() {
  oft_build_cmake -DWOLFMQTT_TLS=no -DWOLFMQTT_V5=yes -DWOLFMQTT_BROKER=ON \
      -DWOLFMQTT_BROKER_LOG=no -DWOLFMQTT_EXAMPLES=no -DWOLFMQTT_UNIT_TESTS=no
  [ -f "$BUILDDIR/src/wolfmqtt/options.h" ] || {
    echo "oft: cmake did not generate wolfmqtt/options.h" >&2; return 1; }
  local tu
  for tu in mqtt_broker mqtt_broker_persist mqtt_broker_persist_posix; do

    "$CC" $CFLAGS -I"$BUILDDIR/src" \
        -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET \
        -DWOLFMQTT_BROKER_NO_LOG -DNO_MAIN_DRIVER \
        '-DWOLFMQTT_BROKER_GET_TIME_S()=((WOLFMQTT_BROKER_TIME_T)0)' \
        '-DBROKER_SLEEP_MS(ms)=do{}while(0)' \
        -c "$BUILDDIR/src/src/$tu.c" -o "$BUILDDIR/oft-$tu.o" || return 1
  done
  "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" \
      "$BUILDDIR/oft-mqtt_broker.o" \
      "$BUILDDIR/oft-mqtt_broker_persist.o" \
      "$BUILDDIR/oft-mqtt_broker_persist_posix.o" || return 1
  oft_build_harness "tests/fuzz/broker_fuzz.c" \
      -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET \
      -DWOLFMQTT_BROKER_NO_LOG -DNO_MAIN_DRIVER \
      '-DWOLFMQTT_BROKER_GET_TIME_S()=((WOLFMQTT_BROKER_TIME_T)0)' \
      '-DBROKER_SLEEP_MS(ms)=do{}while(0)'
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build broker_fuzz
)
