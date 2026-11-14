#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of openssh into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# agent_fuzz: the release's target openssh-agent_fuzz
(
ov_target_begin openssh-agent_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/agent_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

























































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o ssh-sk.o
  oft_build_harness "regress/misc/fuzz-harness/agent_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build agent_fuzz
)

# authkeys_fuzz: the release's target openssh-authkeys_fuzz
(
ov_target_begin openssh-authkeys_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/authkeys_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o auth-options.o auth2-pubkeyfile.o
  oft_build_harness "regress/misc/fuzz-harness/authkeys_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build authkeys_fuzz
)

# authopt_fuzz: the release's target openssh-authopt_fuzz
(
ov_target_begin openssh-authopt_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/authopt_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o auth-options.o
  oft_build_harness "regress/misc/fuzz-harness/authopt_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build authopt_fuzz
)

# kex_fuzz: the release's target openssh-kex_fuzz
(
ov_target_begin openssh-kex_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/kex_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""












































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o
  oft_build_harness "regress/misc/fuzz-harness/kex_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build kex_fuzz
)

# privkey_fuzz: the release's target openssh-privkey_fuzz
(
ov_target_begin openssh-privkey_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/privkey_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o
  oft_build_harness "regress/misc/fuzz-harness/privkey_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build privkey_fuzz
)

# pubkey_fuzz: the release's target openssh-pubkey_fuzz
(
ov_target_begin openssh-pubkey_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/pubkey_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o
  oft_build_harness "regress/misc/fuzz-harness/pubkey_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build pubkey_fuzz
)

# sig_fuzz: the release's target openssh-sig_fuzz
(
ov_target_begin openssh-sig_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/sig_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o
  oft_build_harness "regress/misc/fuzz-harness/sig_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build sig_fuzz
)

# sshsig_fuzz: the release's target openssh-sshsig_fuzz
(
ov_target_begin openssh-sshsig_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/sshsig_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o sshsig.o
  oft_build_harness "regress/misc/fuzz-harness/sshsig_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build sshsig_fuzz
)

# sshsigopt_fuzz: the release's target openssh-sshsigopt_fuzz
(
ov_target_begin openssh-sshsigopt_fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "regress/misc/fuzz-harness/sshsigopt_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

































































































oft_openssh_add_objs() {





  local o
  for o in "$@"; do
    if [ ! -f "$BUILDDIR/src/$o" ]; then
      echo "oft: openssh: make did not build $o" >&2
      return 1
    fi
    "$CHOST-ar" rs "$BUILDDIR/lib/liboft.a" "$BUILDDIR/src/$o" || return 1
    echo "oft: openssh: $o added to lib/liboft.a"
  done
}
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_openssh_add_objs ssh-pkcs11-client.o sshsig.o
  oft_build_harness "regress/misc/fuzz-harness/sshsigopt_fuzz.cc" \
    -D_GNU_SOURCE=1 \
    "-I$BUILDDIR/src/openbsd-compat/include" \
    -include "$BUILDDIR/src/config.h" \
    -include sys/types.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build sshsigopt_fuzz
)
