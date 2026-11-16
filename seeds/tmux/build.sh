#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of tmux into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cmd-parse-fuzzer: the release's target tmux-cmd-parse-fuzzer
(
ov_target_begin tmux-cmd-parse-fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/cmd-parse-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















build_lib() {
  oft_build_autotools

  (
    set -e
    cd "$BUILDDIR/lib"
    llvm-ar x liboft.a tmux.o
    llvm-objcopy --redefine-sym main=oft_tmux_main_renamed tmux.o
    llvm-ar r liboft.a tmux.o
    rm -f tmux.o
  )





  oft_build_harness "fuzz/cmd-parse-fuzzer.c" -include stdlib.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build cmd-parse-fuzzer
)

# format-fuzzer: the release's target tmux-format-fuzzer
(
ov_target_begin tmux-format-fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/format-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















build_lib() {
  oft_build_autotools

  (
    set -e
    cd "$BUILDDIR/lib"
    llvm-ar x liboft.a tmux.o
    llvm-objcopy --redefine-sym main=oft_tmux_main_renamed tmux.o
    llvm-ar r liboft.a tmux.o
    rm -f tmux.o
  )





  oft_build_harness "fuzz/format-fuzzer.c" -include stdlib.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build format-fuzzer
)

# input-fuzzer: the release's target tmux-input-fuzzer
(
ov_target_begin tmux-input-fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/input-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















build_lib() {
  oft_build_autotools

  (
    set -e
    cd "$BUILDDIR/lib"
    llvm-ar x liboft.a tmux.o
    llvm-objcopy --redefine-sym main=oft_tmux_main_renamed tmux.o
    llvm-ar r liboft.a tmux.o
    rm -f tmux.o
  )
  oft_build_harness "fuzz/input-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build input-fuzzer
)

# style-fuzzer: the release's target tmux-style-fuzzer
(
ov_target_begin tmux-style-fuzzer
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/style-fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






















build_lib() {
  oft_build_autotools

  (
    set -e
    cd "$BUILDDIR/lib"
    llvm-ar x liboft.a tmux.o
    llvm-objcopy --redefine-sym main=oft_tmux_main_renamed tmux.o
    llvm-ar r liboft.a tmux.o
    rm -f tmux.o
  )





  oft_build_harness "fuzz/style-fuzzer.c" -include stdlib.h
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build style-fuzzer
)
