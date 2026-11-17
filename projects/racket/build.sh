#!/bin/bash -eu
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
#
# Builds the Racket CS fuzz targets of fuzz/ (this project's harness, which
# the Dockerfile puts in the checkout) into $OUT: static riscv64 musl, no
# threads, boot files and modules embedded in each target.
#
# Racket CS cross-builds with a Racket and a Chez Scheme for the build
# machine, so this first builds those natively, without threads to match
# the target's machine type (a6le, not ta6le).

SRCDIR=$SRC/racket/racket/src
FUZZ=$SRC/racket/fuzz

# Gensyms get their unique names from session keys derived from this
# base, instead of from random ones, so that two builds of the same
# commit give the same bytes
SESSION_KEY=racket-oss-verify

# 1. Native Racket for the build machine. The builder exports CC and
# CFLAGS for riscv64, and make passes them on to sub-builds such as
# zuo's, so the whole step runs with the native compiler's settings.
mkdir -p $WORK/host && cd $WORK/host
(
  export CC=cc CXX=c++ CFLAGS=-O2 CXXFLAGS=-O2 CPPFLAGS= LDFLAGS= LIBS=
  $SRCDIR/configure --enable-cs --disable-pthread --prefix=$WORK/host-racket \
    --enable-sessionkey=$SESSION_KEY
  make -j$(nproc)
  make install
)
HOST_RACKET=$WORK/host-racket/bin/racket

# Chez Scheme's collector (c/gc*.c) expands so many macros that llvm-cov
# export of a coverage build needs more memory than a runner has, so it
# is left out of coverage; the flag changes nothing in other builds
printf 'source:*c/gc*.c=skip\n' > $WORK/profile-list
CFLAGS="$CFLAGS -fprofile-list=$WORK/profile-list"

# 2. Cross-build for riscv64; `--disable-curses` avoids needing a
# riscv64 ncurses, and zlib and LZ4 come from the Chez Scheme sources
# (`--disable-libz` and `--disable-liblz4`, because the builder's sysroot
# has a libz that would otherwise be linked by -lz instead of being part
# of libracketcs.a);
# tools such as zuo that run during the build need the native compiler
mkdir -p $WORK/target && cd $WORK/target
$SRCDIR/configure --host=riscv64-linux-musl \
  --enable-cs --disable-pthread --disable-curses --enable-libs \
  --disable-libz --disable-liblz4 \
  --enable-racket=$HOST_RACKET --enable-scheme=$WORK/host/cs/c \
  --prefix=$WORK/target-racket --enable-sessionkey=$SESSION_KEY \
  CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="-static" CC_FOR_BUILD="cc -O2"
make -j$(nproc)
# a cross `raco setup` with parallel workers loses the cross compiler,
# so compile collections with one worker
make install PLT_SETUP_OPTIONS="-j 1"
R=$WORK/target-racket

# 3. The module bundle must hold riscv64 machine code. The host Racket
# makes it in cross mode, as `make install` does for the collections, so
# that no riscv64 program runs during the build: first compile the
# harness modules for riscv64, then write the bundle.
CROSS_RACKET="$HOST_RACKET -MCR $WORK/target/cs/c/compiled: \
  --cross-compiler rv64le $WORK/target/cs/c \
  -X $R/share/racket/collects -G $R/etc/racket"
$CROSS_RACKET -l racket/base -l compiler/cm \
  -e '(for ([f (vector->list (current-command-line-arguments))]) (managed-compile-zo (path->complete-path f)))' \
  $FUZZ/embed-modules.rkt $FUZZ/safe-eval.rkt
$CROSS_RACKET $FUZZ/embed-modules.rkt $WORK/fuzz-modules.bin

$CC -c -Ulinux -Uunix $FUZZ/embed-data.S -o $WORK/embed-data.o \
  -DPETITE_BOOT=$R/lib/racket/petite.boot \
  -DSCHEME_BOOT=$R/lib/racket/scheme.boot \
  -DRACKET_BOOT=$R/lib/racket/racket.boot \
  -DFUZZ_MODULES=$WORK/fuzz-modules.bin

# Naming an addon directory keeps Racket from reading "/etc/passwd" to
# find the home directory
for t in eval heap-eval read print-roundtrip number regexp fasl ; do
  $CC $CFLAGS -c -I$R/include/racket \
    -DFUZZ_ADDON_DIR='"/nonexistent/racket-addon"' \
    -DFUZZ_ENTRY="\"fuzz-$t\"" $FUZZ/driver.c -o $WORK/driver-$t.o
  $CC $CFLAGS -static $WORK/driver-$t.o $WORK/embed-data.o \
    $R/lib/libracketcs.a $LIB_FUZZING_ENGINE -lm \
    -o $OUT/racket_${t}_fuzzer
done
