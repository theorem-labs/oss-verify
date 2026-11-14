#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of binutils into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_bfd: the release's target binutils-fuzz_bfd
(
ov_target_begin binutils-fuzz_bfd
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_bfd.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































oft_binutils_lib() {
  oft_copy_src
  local s="$BUILDDIR/src"
  sed -i 's/vfprintf (stderr/\/\//' "$s/binutils/elfcomm.c"
  sed -i 's/fprintf (stderr/\/\//' "$s/binutils/elfcomm.c"
  sed -i '/^%%$/i%destructor { free (\$\$); } ID' "$s/binutils/defparse.y"

  if grep -q 'fprintf (stderr' "$s/binutils/elfcomm.c"; then
    echo "oft: binutils/elfcomm.c still writes to stderr after the OSS-Fuzz edit" >&2; return 1
  fi
  grep -qxF '%destructor { free ($$); } ID' "$s/binutils/defparse.y" \
    || { echo "oft: the OSS-Fuzz defparse.y %destructor edit did not apply" >&2; return 1; }
  ( cd "$s" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       CC_FOR_BUILD=/usr/bin/cc CFLAGS_FOR_BUILD="-O2" \
       CXX="$(oft_cxx)" CXXFLAGS="$(oft_cxxflags)" \
       ./configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared --prefix="${OFT_PREFIX:?build.sh sets the flavour-independent install prefix}" \
         --disable-gdb --disable-gdbserver --disable-gdbsupport \
         --disable-libdecnumber --disable-readline --disable-sim \
         --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
         --enable-targets=all --without-zstd \
    && oft_make_then_keep_going MAKEINFO=true ) || return 1
  local out="$BUILDDIR/lib/liboft.a" mri="$BUILDDIR/merge.mri" a n=0
  mkdir -p "$BUILDDIR/lib"
  echo "create $out" > "$mri"
  for a in opcodes/libopcodes.a libctf/.libs/libctf.a bfd/.libs/libbfd.a \
           zlib/libz.a libsframe/.libs/libsframe.a libiberty/libiberty.a; do
    [ -f "$s/$a" ] || { echo "oft: the binutils build left no $a" >&2; return 1; }
    echo "addlib $s/$a" >> "$mri"
    n=$((n + 1))
  done
  printf 'save\nend\n' >> "$mri"
  "$CHOST-ar" -M < "$mri"
  [ -f "$out" ] || { echo "oft: merging $n archive(s) produced no $out" >&2; return 1; }
  echo "oft: merged $n named archive(s) into lib/liboft.a ($("$CHOST-ar" t "$out" | wc -l) members)"
  LIB_ARCHIVE="lib/liboft.a"
  oft_add_sysroot_deps
}
oft_binutils_objs() {
  local d="$BUILDDIR/oftbu" o
  mkdir -p "$d"
  for o in "$@"; do
    [ -f "$BUILDDIR/src/binutils/$o" ] || { echo "oft: binutils/$o was not built" >&2; return 1; }
    cp "$BUILDDIR/src/binutils/$o" "$d/oftbu-$o"
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$d/oftbu-$o" || return 1
  done
  echo "oft: archived $# binutils tool object(s) as oftbu-*.o: $*"
}
build_lib() {
  oft_binutils_lib || return 1
  local s="$BUILDDIR/src"
  oft_build_harness "fuzz_bfd.c" \
    -iquote "$s/include" -iquote "$s/bfd" -iquote "$s/opcodes" \
    -I"$s/include" -I"$s/bfd" -I"$s/opcodes"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_bfd
)

# fuzz_disassemble: the release's target binutils-fuzz_disassemble
(
ov_target_begin binutils-fuzz_disassemble
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_disassemble.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































oft_binutils_lib() {
  oft_copy_src
  local s="$BUILDDIR/src"
  sed -i 's/vfprintf (stderr/\/\//' "$s/binutils/elfcomm.c"
  sed -i 's/fprintf (stderr/\/\//' "$s/binutils/elfcomm.c"
  sed -i '/^%%$/i%destructor { free (\$\$); } ID' "$s/binutils/defparse.y"

  if grep -q 'fprintf (stderr' "$s/binutils/elfcomm.c"; then
    echo "oft: binutils/elfcomm.c still writes to stderr after the OSS-Fuzz edit" >&2; return 1
  fi
  grep -qxF '%destructor { free ($$); } ID' "$s/binutils/defparse.y" \
    || { echo "oft: the OSS-Fuzz defparse.y %destructor edit did not apply" >&2; return 1; }
  ( cd "$s" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       CC_FOR_BUILD=/usr/bin/cc CFLAGS_FOR_BUILD="-O2" \
       CXX="$(oft_cxx)" CXXFLAGS="$(oft_cxxflags)" \
       ./configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared --prefix="${OFT_PREFIX:?build.sh sets the flavour-independent install prefix}" \
         --disable-gdb --disable-gdbserver --disable-gdbsupport \
         --disable-libdecnumber --disable-readline --disable-sim \
         --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
         --enable-targets=all --without-zstd \
    && oft_make_then_keep_going MAKEINFO=true ) || return 1
  local out="$BUILDDIR/lib/liboft.a" mri="$BUILDDIR/merge.mri" a n=0
  mkdir -p "$BUILDDIR/lib"
  echo "create $out" > "$mri"
  for a in opcodes/libopcodes.a libctf/.libs/libctf.a bfd/.libs/libbfd.a \
           zlib/libz.a libsframe/.libs/libsframe.a libiberty/libiberty.a; do
    [ -f "$s/$a" ] || { echo "oft: the binutils build left no $a" >&2; return 1; }
    echo "addlib $s/$a" >> "$mri"
    n=$((n + 1))
  done
  printf 'save\nend\n' >> "$mri"
  "$CHOST-ar" -M < "$mri"
  [ -f "$out" ] || { echo "oft: merging $n archive(s) produced no $out" >&2; return 1; }
  echo "oft: merged $n named archive(s) into lib/liboft.a ($("$CHOST-ar" t "$out" | wc -l) members)"
  LIB_ARCHIVE="lib/liboft.a"
  oft_add_sysroot_deps
}
oft_binutils_objs() {
  local d="$BUILDDIR/oftbu" o
  mkdir -p "$d"
  for o in "$@"; do
    [ -f "$BUILDDIR/src/binutils/$o" ] || { echo "oft: binutils/$o was not built" >&2; return 1; }
    cp "$BUILDDIR/src/binutils/$o" "$d/oftbu-$o"
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$d/oftbu-$o" || return 1
  done
  echo "oft: archived $# binutils tool object(s) as oftbu-*.o: $*"
}
build_lib() {
  oft_binutils_lib || return 1
  local s="$BUILDDIR/src"
  oft_build_harness "fuzz_disassemble.c" \
    -iquote "$s/include" -iquote "$s/bfd" -iquote "$s/opcodes" \
    -I"$s/include" -I"$s/bfd" -I"$s/opcodes"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_disassemble
)

# fuzz_objdump: the release's target binutils-fuzz_objdump
(
ov_target_begin binutils-fuzz_objdump
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz_objdump.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































































oft_binutils_lib() {
  oft_copy_src
  local s="$BUILDDIR/src"
  sed -i 's/vfprintf (stderr/\/\//' "$s/binutils/elfcomm.c"
  sed -i 's/fprintf (stderr/\/\//' "$s/binutils/elfcomm.c"
  sed -i '/^%%$/i%destructor { free (\$\$); } ID' "$s/binutils/defparse.y"

  if grep -q 'fprintf (stderr' "$s/binutils/elfcomm.c"; then
    echo "oft: binutils/elfcomm.c still writes to stderr after the OSS-Fuzz edit" >&2; return 1
  fi
  grep -qxF '%destructor { free ($$); } ID' "$s/binutils/defparse.y" \
    || { echo "oft: the OSS-Fuzz defparse.y %destructor edit did not apply" >&2; return 1; }
  ( cd "$s" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       CC_FOR_BUILD=/usr/bin/cc CFLAGS_FOR_BUILD="-O2" \
       CXX="$(oft_cxx)" CXXFLAGS="$(oft_cxxflags)" \
       ./configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared --prefix="${OFT_PREFIX:?build.sh sets the flavour-independent install prefix}" \
         --disable-gdb --disable-gdbserver --disable-gdbsupport \
         --disable-libdecnumber --disable-readline --disable-sim \
         --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
         --enable-targets=all --without-zstd \
    && oft_make_then_keep_going MAKEINFO=true ) || return 1
  local out="$BUILDDIR/lib/liboft.a" mri="$BUILDDIR/merge.mri" a n=0
  mkdir -p "$BUILDDIR/lib"
  echo "create $out" > "$mri"
  for a in opcodes/libopcodes.a libctf/.libs/libctf.a bfd/.libs/libbfd.a \
           zlib/libz.a libsframe/.libs/libsframe.a libiberty/libiberty.a; do
    [ -f "$s/$a" ] || { echo "oft: the binutils build left no $a" >&2; return 1; }
    echo "addlib $s/$a" >> "$mri"
    n=$((n + 1))
  done
  printf 'save\nend\n' >> "$mri"
  "$CHOST-ar" -M < "$mri"
  [ -f "$out" ] || { echo "oft: merging $n archive(s) produced no $out" >&2; return 1; }
  echo "oft: merged $n named archive(s) into lib/liboft.a ($("$CHOST-ar" t "$out" | wc -l) members)"
  LIB_ARCHIVE="lib/liboft.a"
  oft_add_sysroot_deps
}
oft_binutils_objs() {
  local d="$BUILDDIR/oftbu" o
  mkdir -p "$d"
  for o in "$@"; do
    [ -f "$BUILDDIR/src/binutils/$o" ] || { echo "oft: binutils/$o was not built" >&2; return 1; }
    cp "$BUILDDIR/src/binutils/$o" "$d/oftbu-$o"
    "$CHOST-ar" r "$BUILDDIR/lib/liboft.a" "$d/oftbu-$o" || return 1
  done
  echo "oft: archived $# binutils tool object(s) as oftbu-*.o: $*"
}
build_lib() {
  oft_binutils_lib || return 1
  local s="$BUILDDIR/src"
  ( cd "$s/binutils" \
    && sed -i 's/strip_main/strip_mian/g' objdump.c \
    && sed -i 's/copy_main/copy_mian/g' objdump.c \
    && sed 's/main (int argc/old_main32 (int argc, char **argv);\nint old_main32 (int argc/' objdump.c > fuzz_objdump.h \
    && sed -i 's/copy_mian/copy_main/g' fuzz_objdump.h \
    && grep -q '^int old_main32 (int argc' fuzz_objdump.h ) \
    || { echo "oft: fuzz_objdump.h was not generated from objdump.c as OSS-Fuzz does" >&2; return 1; }
  oft_binutils_objs dwarf.o prdbg.o rddbg.o unwind-ia64.o debug.o stabs.o rdcoff.o \
    bucomm.o version.o filemode.o elfcomm.o od-xcoff.o demanguse.o || return 1
  oft_build_harness "fuzz_objdump.c" \
    -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS= \
    -iquote "$s/binutils" -iquote "$s/bfd" -iquote "$s/include" -iquote "$s/zlib" \
    -I"$s/binutils" -I"$s/bfd" -I"$s/include" -I"$s/zlib" \
    '-DLOCALEDIR="/usr/local/share/locale"' \
    -Dbin_dummy_emulation=bin_vanilla_emulation
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_objdump
)
