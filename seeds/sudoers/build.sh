#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of sudoers into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_iolog_json: the release's target sudoers-fuzz_iolog_json
(
ov_target_begin sudoers-fuzz_iolog_json
build_lib() {
  oft_build_autotools
  oft_build_harness "lib/iolog/regress/fuzz/fuzz_iolog_json.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































build_lib() {
  oft_build_autotools \
    --with-rundir=/run/sudo --with-vardir=/var/lib/sudo \
    --with-logpath=/var/log/sudo.log --with-relaydir=/var/log/sudo_logsrvd \
    --with-iologdir=/var/log/sudo-io --without-tzdir \
    --with-sendmail=/usr/sbin/sendmail \
    sudo_cv_log_dir=/var/log \
    VIPROG=/usr/bin/vi MVPROG=/bin/mv BSHELLPROG=/bin/sh
  oft_build_harness "lib/iolog/regress/fuzz/fuzz_iolog_json.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_iolog_json
)

# fuzz_iolog_legacy: the release's target sudoers-fuzz_iolog_legacy
(
ov_target_begin sudoers-fuzz_iolog_legacy
build_lib() {
  oft_build_autotools
  oft_build_harness "lib/iolog/regress/fuzz/fuzz_iolog_legacy.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""








































build_lib() {
  oft_build_autotools \
    --with-rundir=/run/sudo --with-vardir=/var/lib/sudo \
    --with-logpath=/var/log/sudo.log --with-relaydir=/var/log/sudo_logsrvd \
    --with-iologdir=/var/log/sudo-io --without-tzdir \
    --with-sendmail=/usr/sbin/sendmail \
    sudo_cv_log_dir=/var/log \
    VIPROG=/usr/bin/vi MVPROG=/bin/mv BSHELLPROG=/bin/sh
  oft_build_harness "lib/iolog/regress/fuzz/fuzz_iolog_legacy.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_iolog_legacy
)
