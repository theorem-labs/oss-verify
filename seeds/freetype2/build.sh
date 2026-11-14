#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of freetype2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cff: the release's target freetype2-cff
(
ov_target_begin freetype2-cff freetype2-dep-freetype
ov_target_dependency freetype2-dep-freetype <<'OV_PIN_END'
build_lib() {
  local e
  [ -f "$SRCDIR/include/freetype/freetype.h" ] && [ -f "$SRCDIR/builds/unix/configure.raw" ] || {
    echo "oft: freetype2-dep-freetype: $SRCDIR is not a FreeType tree" >&2; return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$BUILDDIR/src" || return 1
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    [ "${e##*/}" = .git ] && continue
    cp -a "$e" "$BUILDDIR/src/" || return 1
  done
  [ ! -e "$BUILDDIR/src/.git" ] || { echo "oft: freetype2-dep-freetype: .git was copied" >&2; return 1; }
  [ -f "$BUILDDIR/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2-dep-freetype: staging produced no include/freetype/freetype.h" >&2; return 1; }
  echo "oft: freetype2-dep-freetype: FreeType $(grep -E '^#define FREETYPE_(MAJOR|MINOR|PATCH) ' "$BUILDDIR/src/include/freetype/freetype.h" | awk '{print $3}' | tr '\n' '.' | sed 's/\.$//') staged at $BUILDDIR/src"
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzzing/src/fuzzers/template.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































































DEPENDS="freetype2-dep-freetype"







SUBMODULES="external/zlib external/bzip2 external/libarchive external/brotli external/libpng"

ft2_dep="$LIBROOT/freetype2-dep-freetype"




ft2_stage() {
  local s="$BUILDDIR/src" d
  [ -f "$ft2_dep/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2: $ft2_dep/src holds no FreeType tree -- did freetype2-dep-freetype's build_lib run?" >&2
    return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$s/external" || return 1
  cp -a "$SRCDIR/fuzzing" "$SRCDIR/LICENSE" "$SRCDIR/README.md" "$s/" || return 1
  for d in zlib bzip2 libarchive brotli libpng; do
    if [ ! -d "$SRCDIR/external/$d" ] || [ -z "$(ls -A "$SRCDIR/external/$d")" ]; then
      echo "oft: freetype2: submodule external/$d is not populated in $SRCDIR" >&2
      return 1
    fi
    cp -a "$SRCDIR/external/$d" "$s/external/" || return 1
  done
  cp -a "$ft2_dep/src" "$s/external/freetype2" || return 1
}


ft2_zlib() {
  local z="$BUILDDIR/src/external/zlib"
  ( cd "$z" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       ./configure --zprefix --prefix="$z/usr" --libdir="$z/usr/lib-asan" --static \
    && make -j"$(oft_jobs)" libz.a \
    && make install ) || return 1
  [ -f "$z/usr/lib-asan/libz.a" ] && [ -f "$z/usr/include/zconf.h" ] || {
    echo "oft: freetype2: zlib did not install libz.a + zconf.h under $z/usr" >&2; return 1; }
}




ft2_bzip2() {
  local b="$BUILDDIR/src/external/bzip2"
  ( cd "$b" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/scripts/build/0001-Don-t-override-CC-CFLAGS-and-LDFLAGS.patch" \
    && CC="$CC" CFLAGS="$CFLAGS" AR="$CHOST-ar" RANLIB="$CHOST-ranlib" \
       make -j"$(oft_jobs)" libbz2.a ) || return 1
  [ -f "$b/libbz2.a" ] || { echo "oft: freetype2: bzip2 produced no libbz2.a" >&2; return 1; }
}



ft2_libarchive() {
  local a="$BUILDDIR/src/external/libarchive"
  ( cd "$a" \
    && sh build/autogen.sh \
    && CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc ac_cv_lib_md_MD5Init=no \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --disable-dependency-tracking --disable-shared --enable-static \
         --disable-bsdtar --disable-bsdcat --disable-bsdcpio \
         --enable-posix-regex-lib=libc --disable-xattr --disable-acl \
         --disable-largefile --without-zlib --without-bz2lib --without-iconv \
         --without-libiconv-prefix --without-lz4 --without-zstd --without-lzma \
         --with-lzo2 --without-cng --without-nettle --without-openssl \
         --without-xml2 --without-expat \
         --without-libb2 --without-mbedtls \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$a/.libs/libarchive.a" ] || { echo "oft: freetype2: libarchive produced no .libs/libarchive.a" >&2; return 1; }
}


ft2_brotli() {
  local r="$BUILDDIR/src/external/brotli"
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$r/build" || return 1
  ( cd "$r/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" brotlicommon-static brotlidec-static ) || return 1
  [ -f "$r/build/libbrotlidec-static.a" ] && [ -f "$r/build/libbrotlicommon-static.a" ] || {
    echo "oft: freetype2: brotli produced no lib{brotlicommon,brotlidec}-static.a" >&2; return 1; }
}




ft2_libpng() {
  local p="$BUILDDIR/src/external/libpng" z="$BUILDDIR/src/external/zlib"
  ( cd "$p" \
    && sed -e "s/option STDIO/option STDIO disabled/" \
           -e "s/option WARNING /option WARNING disabled/" \
           -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
           scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp \
    && mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa \
    && autoreconf -f -i \
    && mkdir -p build && cd build \
    && CPPFLAGS="-I$z/usr/include" LDFLAGS="-L$z/usr/lib-asan" \
       CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc \
       sh ../configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --with-libpng-prefix=OSS_FUZZ_ --prefix="$p/usr" --libdir="$p/usr/lib-asan" \
         --enable-static --disable-shared \
    && make -j"$(oft_jobs)" \
    && make install ) || return 1
  [ -e "$p/usr/lib-asan/libpng.a" ] && [ -f "$p/usr/include/libpng16/png.h" ] || {
    echo "oft: freetype2: libpng did not install libpng.a + png.h under $p/usr" >&2; return 1; }
}





ft2_freetype() {
  local f="$BUILDDIR/src/external/freetype2"
  ( cd "$f" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/settings/freetype2/ftoption.patch" \
    && sh autogen.sh \
    && BZIP2_CFLAGS="-I../bzip2" BZIP2_LIBS="-l../bzip2/libbz2.a" \
       BROTLI_CFLAGS="-I../brotli/c/include" BROTLI_LIBS="-l../brotli/build/libbrotlidec-static.a" \
       ZLIB_CFLAGS="-I../zlib/usr/include" ZLIB_LIBS="-l../zlib/usr/lib-asan/libz.a" \
       LIBPNG_CFLAGS="-I../libpng/usr/include" LIBPNG_LIBS="-l../libpng/usr/lib-asan/libpng.a" \
       CC="$CC" CFLAGS="$CFLAGS" CC_BUILD=/usr/bin/cc \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared \
         --with-brotli --with-bzip2 --with-zlib --with-png --without-harfbuzz \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$f/objs/.libs/libfreetype.a" ] || { echo "oft: freetype2: FreeType produced no objs/.libs/libfreetype.a" >&2; return 1; }
}




ft2_fuzztargets() {
  local z="$BUILDDIR/src/fuzzing" n
  sed -i -e '/^add_compile_options($/,/^  "-nostdinc++")$/s/^/# #### /' \
         -e 's/^add_link_options("-nostdlib++")$/# #### &/' "$z/CMakeLists.txt" || return 1
  n=$(grep -c '^# #### ' "$z/CMakeLists.txt" || true)
  if [ "$n" != 5 ] || grep -v '^#' "$z/CMakeLists.txt" | grep -q -e '-nostdinc++' -e '-nostdlib++'; then
    echo "oft: freetype2: fuzzing/CMakeLists.txt libc++ lines not neutralised as expected ($n of 5)" >&2
    return 1
  fi
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$z/build" || return 1
  ( cd "$z/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" fuzztargets ) || return 1
  [ -f "$z/build/lib/libfuzztargets.a" ] || { echo "oft: freetype2: no fuzzing/build/lib/libfuzztargets.a" >&2; return 1; }
}

build_lib() {
  oft_require_target_cxx
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  ft2_stage
  ft2_zlib
  ft2_bzip2
  ft2_libarchive
  ft2_brotli
  ft2_libpng
  ft2_freetype
  ft2_fuzztargets


  oft_merge_archives


  oft_build_harness "fuzzing/src/fuzzers/template.cpp" \
    '-DFUZZ_TARGET_HEADER_PATH="targets/font-drivers/cff.h"' \
    -DFUZZ_TARGET_CLASS_NAME=freetype::CffFuzzTarget \
    -I"$BUILDDIR/src/external/freetype2/include" -I"$BUILDDIR/src/fuzzing/src" \
    -I"$BUILDDIR/src/external/libarchive/libarchive"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build cff
)

# ftfuzzer: the release's target freetype2-ftfuzzer
(
ov_target_begin freetype2-ftfuzzer freetype2-dep-freetype
ov_target_dependency freetype2-dep-freetype <<'OV_PIN_END'
build_lib() {
  local e
  [ -f "$SRCDIR/include/freetype/freetype.h" ] && [ -f "$SRCDIR/builds/unix/configure.raw" ] || {
    echo "oft: freetype2-dep-freetype: $SRCDIR is not a FreeType tree" >&2; return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$BUILDDIR/src" || return 1
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    [ "${e##*/}" = .git ] && continue
    cp -a "$e" "$BUILDDIR/src/" || return 1
  done
  [ ! -e "$BUILDDIR/src/.git" ] || { echo "oft: freetype2-dep-freetype: .git was copied" >&2; return 1; }
  [ -f "$BUILDDIR/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2-dep-freetype: staging produced no include/freetype/freetype.h" >&2; return 1; }
  echo "oft: freetype2-dep-freetype: FreeType $(grep -E '^#define FREETYPE_(MAJOR|MINOR|PATCH) ' "$BUILDDIR/src/include/freetype/freetype.h" | awk '{print $3}' | tr '\n' '.' | sed 's/\.$//') staged at $BUILDDIR/src"
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzzing/src/legacy/ftfuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















































































DEPENDS="freetype2-dep-freetype"







SUBMODULES="external/zlib external/bzip2 external/libarchive external/brotli external/libpng"

ft2_dep="$LIBROOT/freetype2-dep-freetype"




ft2_stage() {
  local s="$BUILDDIR/src" d
  [ -f "$ft2_dep/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2: $ft2_dep/src holds no FreeType tree -- did freetype2-dep-freetype's build_lib run?" >&2
    return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$s/external" || return 1
  cp -a "$SRCDIR/fuzzing" "$SRCDIR/LICENSE" "$SRCDIR/README.md" "$s/" || return 1
  for d in zlib bzip2 libarchive brotli libpng; do
    if [ ! -d "$SRCDIR/external/$d" ] || [ -z "$(ls -A "$SRCDIR/external/$d")" ]; then
      echo "oft: freetype2: submodule external/$d is not populated in $SRCDIR" >&2
      return 1
    fi
    cp -a "$SRCDIR/external/$d" "$s/external/" || return 1
  done
  cp -a "$ft2_dep/src" "$s/external/freetype2" || return 1
}


ft2_zlib() {
  local z="$BUILDDIR/src/external/zlib"
  ( cd "$z" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       ./configure --zprefix --prefix="$z/usr" --libdir="$z/usr/lib-asan" --static \
    && make -j"$(oft_jobs)" libz.a \
    && make install ) || return 1
  [ -f "$z/usr/lib-asan/libz.a" ] && [ -f "$z/usr/include/zconf.h" ] || {
    echo "oft: freetype2: zlib did not install libz.a + zconf.h under $z/usr" >&2; return 1; }
}




ft2_bzip2() {
  local b="$BUILDDIR/src/external/bzip2"
  ( cd "$b" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/scripts/build/0001-Don-t-override-CC-CFLAGS-and-LDFLAGS.patch" \
    && CC="$CC" CFLAGS="$CFLAGS" AR="$CHOST-ar" RANLIB="$CHOST-ranlib" \
       make -j"$(oft_jobs)" libbz2.a ) || return 1
  [ -f "$b/libbz2.a" ] || { echo "oft: freetype2: bzip2 produced no libbz2.a" >&2; return 1; }
}



ft2_libarchive() {
  local a="$BUILDDIR/src/external/libarchive"
  ( cd "$a" \
    && sh build/autogen.sh \
    && CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc ac_cv_lib_md_MD5Init=no \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --disable-dependency-tracking --disable-shared --enable-static \
         --disable-bsdtar --disable-bsdcat --disable-bsdcpio \
         --enable-posix-regex-lib=libc --disable-xattr --disable-acl \
         --disable-largefile --without-zlib --without-bz2lib --without-iconv \
         --without-libiconv-prefix --without-lz4 --without-zstd --without-lzma \
         --with-lzo2 --without-cng --without-nettle --without-openssl \
         --without-xml2 --without-expat \
         --without-libb2 --without-mbedtls \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$a/.libs/libarchive.a" ] || { echo "oft: freetype2: libarchive produced no .libs/libarchive.a" >&2; return 1; }
}


ft2_brotli() {
  local r="$BUILDDIR/src/external/brotli"
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$r/build" || return 1
  ( cd "$r/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" brotlicommon-static brotlidec-static ) || return 1
  [ -f "$r/build/libbrotlidec-static.a" ] && [ -f "$r/build/libbrotlicommon-static.a" ] || {
    echo "oft: freetype2: brotli produced no lib{brotlicommon,brotlidec}-static.a" >&2; return 1; }
}




ft2_libpng() {
  local p="$BUILDDIR/src/external/libpng" z="$BUILDDIR/src/external/zlib"
  ( cd "$p" \
    && sed -e "s/option STDIO/option STDIO disabled/" \
           -e "s/option WARNING /option WARNING disabled/" \
           -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
           scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp \
    && mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa \
    && autoreconf -f -i \
    && mkdir -p build && cd build \
    && CPPFLAGS="-I$z/usr/include" LDFLAGS="-L$z/usr/lib-asan" \
       CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc \
       sh ../configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --with-libpng-prefix=OSS_FUZZ_ --prefix="$p/usr" --libdir="$p/usr/lib-asan" \
         --enable-static --disable-shared \
    && make -j"$(oft_jobs)" \
    && make install ) || return 1
  [ -e "$p/usr/lib-asan/libpng.a" ] && [ -f "$p/usr/include/libpng16/png.h" ] || {
    echo "oft: freetype2: libpng did not install libpng.a + png.h under $p/usr" >&2; return 1; }
}





ft2_freetype() {
  local f="$BUILDDIR/src/external/freetype2"
  ( cd "$f" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/settings/freetype2/ftoption.patch" \
    && sh autogen.sh \
    && BZIP2_CFLAGS="-I../bzip2" BZIP2_LIBS="-l../bzip2/libbz2.a" \
       BROTLI_CFLAGS="-I../brotli/c/include" BROTLI_LIBS="-l../brotli/build/libbrotlidec-static.a" \
       ZLIB_CFLAGS="-I../zlib/usr/include" ZLIB_LIBS="-l../zlib/usr/lib-asan/libz.a" \
       LIBPNG_CFLAGS="-I../libpng/usr/include" LIBPNG_LIBS="-l../libpng/usr/lib-asan/libpng.a" \
       CC="$CC" CFLAGS="$CFLAGS" CC_BUILD=/usr/bin/cc \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared \
         --with-brotli --with-bzip2 --with-zlib --with-png --without-harfbuzz \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$f/objs/.libs/libfreetype.a" ] || { echo "oft: freetype2: FreeType produced no objs/.libs/libfreetype.a" >&2; return 1; }
}




ft2_fuzztargets() {
  local z="$BUILDDIR/src/fuzzing" n
  sed -i -e '/^add_compile_options($/,/^  "-nostdinc++")$/s/^/# #### /' \
         -e 's/^add_link_options("-nostdlib++")$/# #### &/' "$z/CMakeLists.txt" || return 1
  n=$(grep -c '^# #### ' "$z/CMakeLists.txt" || true)
  if [ "$n" != 5 ] || grep -v '^#' "$z/CMakeLists.txt" | grep -q -e '-nostdinc++' -e '-nostdlib++'; then
    echo "oft: freetype2: fuzzing/CMakeLists.txt libc++ lines not neutralised as expected ($n of 5)" >&2
    return 1
  fi
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$z/build" || return 1
  ( cd "$z/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" fuzztargets ) || return 1
  [ -f "$z/build/lib/libfuzztargets.a" ] || { echo "oft: freetype2: no fuzzing/build/lib/libfuzztargets.a" >&2; return 1; }
}

build_lib() {
  oft_require_target_cxx
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  ft2_stage
  ft2_zlib
  ft2_bzip2
  ft2_libarchive
  ft2_brotli
  ft2_libpng
  ft2_freetype
  ft2_fuzztargets


  oft_merge_archives


  oft_build_harness "fuzzing/src/legacy/ftfuzzer.cc" \
    -I"$BUILDDIR/src/external/freetype2/include" -I"$BUILDDIR/src/fuzzing/src" \
    -I"$BUILDDIR/src/external/libarchive/libarchive"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build ftfuzzer
)

# truetype: the release's target freetype2-truetype
(
ov_target_begin freetype2-truetype freetype2-dep-freetype
ov_target_dependency freetype2-dep-freetype <<'OV_PIN_END'
build_lib() {
  local e
  [ -f "$SRCDIR/include/freetype/freetype.h" ] && [ -f "$SRCDIR/builds/unix/configure.raw" ] || {
    echo "oft: freetype2-dep-freetype: $SRCDIR is not a FreeType tree" >&2; return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$BUILDDIR/src" || return 1
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    [ "${e##*/}" = .git ] && continue
    cp -a "$e" "$BUILDDIR/src/" || return 1
  done
  [ ! -e "$BUILDDIR/src/.git" ] || { echo "oft: freetype2-dep-freetype: .git was copied" >&2; return 1; }
  [ -f "$BUILDDIR/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2-dep-freetype: staging produced no include/freetype/freetype.h" >&2; return 1; }
  echo "oft: freetype2-dep-freetype: FreeType $(grep -E '^#define FREETYPE_(MAJOR|MINOR|PATCH) ' "$BUILDDIR/src/include/freetype/freetype.h" | awk '{print $3}' | tr '\n' '.' | sed 's/\.$//') staged at $BUILDDIR/src"
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzzing/src/fuzzers/template.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































































DEPENDS="freetype2-dep-freetype"







SUBMODULES="external/zlib external/bzip2 external/libarchive external/brotli external/libpng"

ft2_dep="$LIBROOT/freetype2-dep-freetype"




ft2_stage() {
  local s="$BUILDDIR/src" d
  [ -f "$ft2_dep/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2: $ft2_dep/src holds no FreeType tree -- did freetype2-dep-freetype's build_lib run?" >&2
    return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$s/external" || return 1
  cp -a "$SRCDIR/fuzzing" "$SRCDIR/LICENSE" "$SRCDIR/README.md" "$s/" || return 1
  for d in zlib bzip2 libarchive brotli libpng; do
    if [ ! -d "$SRCDIR/external/$d" ] || [ -z "$(ls -A "$SRCDIR/external/$d")" ]; then
      echo "oft: freetype2: submodule external/$d is not populated in $SRCDIR" >&2
      return 1
    fi
    cp -a "$SRCDIR/external/$d" "$s/external/" || return 1
  done
  cp -a "$ft2_dep/src" "$s/external/freetype2" || return 1
}


ft2_zlib() {
  local z="$BUILDDIR/src/external/zlib"
  ( cd "$z" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       ./configure --zprefix --prefix="$z/usr" --libdir="$z/usr/lib-asan" --static \
    && make -j"$(oft_jobs)" libz.a \
    && make install ) || return 1
  [ -f "$z/usr/lib-asan/libz.a" ] && [ -f "$z/usr/include/zconf.h" ] || {
    echo "oft: freetype2: zlib did not install libz.a + zconf.h under $z/usr" >&2; return 1; }
}




ft2_bzip2() {
  local b="$BUILDDIR/src/external/bzip2"
  ( cd "$b" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/scripts/build/0001-Don-t-override-CC-CFLAGS-and-LDFLAGS.patch" \
    && CC="$CC" CFLAGS="$CFLAGS" AR="$CHOST-ar" RANLIB="$CHOST-ranlib" \
       make -j"$(oft_jobs)" libbz2.a ) || return 1
  [ -f "$b/libbz2.a" ] || { echo "oft: freetype2: bzip2 produced no libbz2.a" >&2; return 1; }
}



ft2_libarchive() {
  local a="$BUILDDIR/src/external/libarchive"
  ( cd "$a" \
    && sh build/autogen.sh \
    && CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc ac_cv_lib_md_MD5Init=no \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --disable-dependency-tracking --disable-shared --enable-static \
         --disable-bsdtar --disable-bsdcat --disable-bsdcpio \
         --enable-posix-regex-lib=libc --disable-xattr --disable-acl \
         --disable-largefile --without-zlib --without-bz2lib --without-iconv \
         --without-libiconv-prefix --without-lz4 --without-zstd --without-lzma \
         --with-lzo2 --without-cng --without-nettle --without-openssl \
         --without-xml2 --without-expat \
         --without-libb2 --without-mbedtls \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$a/.libs/libarchive.a" ] || { echo "oft: freetype2: libarchive produced no .libs/libarchive.a" >&2; return 1; }
}


ft2_brotli() {
  local r="$BUILDDIR/src/external/brotli"
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$r/build" || return 1
  ( cd "$r/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" brotlicommon-static brotlidec-static ) || return 1
  [ -f "$r/build/libbrotlidec-static.a" ] && [ -f "$r/build/libbrotlicommon-static.a" ] || {
    echo "oft: freetype2: brotli produced no lib{brotlicommon,brotlidec}-static.a" >&2; return 1; }
}




ft2_libpng() {
  local p="$BUILDDIR/src/external/libpng" z="$BUILDDIR/src/external/zlib"
  ( cd "$p" \
    && sed -e "s/option STDIO/option STDIO disabled/" \
           -e "s/option WARNING /option WARNING disabled/" \
           -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
           scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp \
    && mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa \
    && autoreconf -f -i \
    && mkdir -p build && cd build \
    && CPPFLAGS="-I$z/usr/include" LDFLAGS="-L$z/usr/lib-asan" \
       CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc \
       sh ../configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --with-libpng-prefix=OSS_FUZZ_ --prefix="$p/usr" --libdir="$p/usr/lib-asan" \
         --enable-static --disable-shared \
    && make -j"$(oft_jobs)" \
    && make install ) || return 1
  [ -e "$p/usr/lib-asan/libpng.a" ] && [ -f "$p/usr/include/libpng16/png.h" ] || {
    echo "oft: freetype2: libpng did not install libpng.a + png.h under $p/usr" >&2; return 1; }
}





ft2_freetype() {
  local f="$BUILDDIR/src/external/freetype2"
  ( cd "$f" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/settings/freetype2/ftoption.patch" \
    && sh autogen.sh \
    && BZIP2_CFLAGS="-I../bzip2" BZIP2_LIBS="-l../bzip2/libbz2.a" \
       BROTLI_CFLAGS="-I../brotli/c/include" BROTLI_LIBS="-l../brotli/build/libbrotlidec-static.a" \
       ZLIB_CFLAGS="-I../zlib/usr/include" ZLIB_LIBS="-l../zlib/usr/lib-asan/libz.a" \
       LIBPNG_CFLAGS="-I../libpng/usr/include" LIBPNG_LIBS="-l../libpng/usr/lib-asan/libpng.a" \
       CC="$CC" CFLAGS="$CFLAGS" CC_BUILD=/usr/bin/cc \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared \
         --with-brotli --with-bzip2 --with-zlib --with-png --without-harfbuzz \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$f/objs/.libs/libfreetype.a" ] || { echo "oft: freetype2: FreeType produced no objs/.libs/libfreetype.a" >&2; return 1; }
}




ft2_fuzztargets() {
  local z="$BUILDDIR/src/fuzzing" n
  sed -i -e '/^add_compile_options($/,/^  "-nostdinc++")$/s/^/# #### /' \
         -e 's/^add_link_options("-nostdlib++")$/# #### &/' "$z/CMakeLists.txt" || return 1
  n=$(grep -c '^# #### ' "$z/CMakeLists.txt" || true)
  if [ "$n" != 5 ] || grep -v '^#' "$z/CMakeLists.txt" | grep -q -e '-nostdinc++' -e '-nostdlib++'; then
    echo "oft: freetype2: fuzzing/CMakeLists.txt libc++ lines not neutralised as expected ($n of 5)" >&2
    return 1
  fi
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$z/build" || return 1
  ( cd "$z/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" fuzztargets ) || return 1
  [ -f "$z/build/lib/libfuzztargets.a" ] || { echo "oft: freetype2: no fuzzing/build/lib/libfuzztargets.a" >&2; return 1; }
}

build_lib() {
  oft_require_target_cxx
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  ft2_stage
  ft2_zlib
  ft2_bzip2
  ft2_libarchive
  ft2_brotli
  ft2_libpng
  ft2_freetype
  ft2_fuzztargets


  oft_merge_archives


  oft_build_harness "fuzzing/src/fuzzers/template.cpp" \
    '-DFUZZ_TARGET_HEADER_PATH="targets/font-drivers/truetype.h"' \
    -DFUZZ_TARGET_CLASS_NAME=freetype::TrueTypeFuzzTarget \
    -I"$BUILDDIR/src/external/freetype2/include" -I"$BUILDDIR/src/fuzzing/src" \
    -I"$BUILDDIR/src/external/libarchive/libarchive"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build truetype
)

# type1: the release's target freetype2-type1
(
ov_target_begin freetype2-type1 freetype2-dep-freetype
ov_target_dependency freetype2-dep-freetype <<'OV_PIN_END'
build_lib() {
  local e
  [ -f "$SRCDIR/include/freetype/freetype.h" ] && [ -f "$SRCDIR/builds/unix/configure.raw" ] || {
    echo "oft: freetype2-dep-freetype: $SRCDIR is not a FreeType tree" >&2; return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$BUILDDIR/src" || return 1
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    [ "${e##*/}" = .git ] && continue
    cp -a "$e" "$BUILDDIR/src/" || return 1
  done
  [ ! -e "$BUILDDIR/src/.git" ] || { echo "oft: freetype2-dep-freetype: .git was copied" >&2; return 1; }
  [ -f "$BUILDDIR/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2-dep-freetype: staging produced no include/freetype/freetype.h" >&2; return 1; }
  echo "oft: freetype2-dep-freetype: FreeType $(grep -E '^#define FREETYPE_(MAJOR|MINOR|PATCH) ' "$BUILDDIR/src/include/freetype/freetype.h" | awk '{print $3}' | tr '\n' '.' | sed 's/\.$//') staged at $BUILDDIR/src"
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "fuzzing/src/fuzzers/template.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
















































































DEPENDS="freetype2-dep-freetype"







SUBMODULES="external/zlib external/bzip2 external/libarchive external/brotli external/libpng"

ft2_dep="$LIBROOT/freetype2-dep-freetype"




ft2_stage() {
  local s="$BUILDDIR/src" d
  [ -f "$ft2_dep/src/include/freetype/freetype.h" ] || {
    echo "oft: freetype2: $ft2_dep/src holds no FreeType tree -- did freetype2-dep-freetype's build_lib run?" >&2
    return 1; }
  rm -rf -- "${BUILDDIR:?}/src"
  mkdir -p "$s/external" || return 1
  cp -a "$SRCDIR/fuzzing" "$SRCDIR/LICENSE" "$SRCDIR/README.md" "$s/" || return 1
  for d in zlib bzip2 libarchive brotli libpng; do
    if [ ! -d "$SRCDIR/external/$d" ] || [ -z "$(ls -A "$SRCDIR/external/$d")" ]; then
      echo "oft: freetype2: submodule external/$d is not populated in $SRCDIR" >&2
      return 1
    fi
    cp -a "$SRCDIR/external/$d" "$s/external/" || return 1
  done
  cp -a "$ft2_dep/src" "$s/external/freetype2" || return 1
}


ft2_zlib() {
  local z="$BUILDDIR/src/external/zlib"
  ( cd "$z" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       ./configure --zprefix --prefix="$z/usr" --libdir="$z/usr/lib-asan" --static \
    && make -j"$(oft_jobs)" libz.a \
    && make install ) || return 1
  [ -f "$z/usr/lib-asan/libz.a" ] && [ -f "$z/usr/include/zconf.h" ] || {
    echo "oft: freetype2: zlib did not install libz.a + zconf.h under $z/usr" >&2; return 1; }
}




ft2_bzip2() {
  local b="$BUILDDIR/src/external/bzip2"
  ( cd "$b" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/scripts/build/0001-Don-t-override-CC-CFLAGS-and-LDFLAGS.patch" \
    && CC="$CC" CFLAGS="$CFLAGS" AR="$CHOST-ar" RANLIB="$CHOST-ranlib" \
       make -j"$(oft_jobs)" libbz2.a ) || return 1
  [ -f "$b/libbz2.a" ] || { echo "oft: freetype2: bzip2 produced no libbz2.a" >&2; return 1; }
}



ft2_libarchive() {
  local a="$BUILDDIR/src/external/libarchive"
  ( cd "$a" \
    && sh build/autogen.sh \
    && CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc ac_cv_lib_md_MD5Init=no \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --disable-dependency-tracking --disable-shared --enable-static \
         --disable-bsdtar --disable-bsdcat --disable-bsdcpio \
         --enable-posix-regex-lib=libc --disable-xattr --disable-acl \
         --disable-largefile --without-zlib --without-bz2lib --without-iconv \
         --without-libiconv-prefix --without-lz4 --without-zstd --without-lzma \
         --with-lzo2 --without-cng --without-nettle --without-openssl \
         --without-xml2 --without-expat \
         --without-libb2 --without-mbedtls \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$a/.libs/libarchive.a" ] || { echo "oft: freetype2: libarchive produced no .libs/libarchive.a" >&2; return 1; }
}


ft2_brotli() {
  local r="$BUILDDIR/src/external/brotli"
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$r/build" || return 1
  ( cd "$r/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" brotlicommon-static brotlidec-static ) || return 1
  [ -f "$r/build/libbrotlidec-static.a" ] && [ -f "$r/build/libbrotlicommon-static.a" ] || {
    echo "oft: freetype2: brotli produced no lib{brotlicommon,brotlidec}-static.a" >&2; return 1; }
}




ft2_libpng() {
  local p="$BUILDDIR/src/external/libpng" z="$BUILDDIR/src/external/zlib"
  ( cd "$p" \
    && sed -e "s/option STDIO/option STDIO disabled/" \
           -e "s/option WARNING /option WARNING disabled/" \
           -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
           scripts/pnglibconf.dfa > scripts/pnglibconf.dfa.temp \
    && mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa \
    && autoreconf -f -i \
    && mkdir -p build && cd build \
    && CPPFLAGS="-I$z/usr/include" LDFLAGS="-L$z/usr/lib-asan" \
       CC="$CC" CFLAGS="$CFLAGS" CC_FOR_BUILD=/usr/bin/cc \
       sh ../configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --with-libpng-prefix=OSS_FUZZ_ --prefix="$p/usr" --libdir="$p/usr/lib-asan" \
         --enable-static --disable-shared \
    && make -j"$(oft_jobs)" \
    && make install ) || return 1
  [ -e "$p/usr/lib-asan/libpng.a" ] && [ -f "$p/usr/include/libpng16/png.h" ] || {
    echo "oft: freetype2: libpng did not install libpng.a + png.h under $p/usr" >&2; return 1; }
}





ft2_freetype() {
  local f="$BUILDDIR/src/external/freetype2"
  ( cd "$f" \
    && patch -p1 < "$BUILDDIR/src/fuzzing/settings/freetype2/ftoption.patch" \
    && sh autogen.sh \
    && BZIP2_CFLAGS="-I../bzip2" BZIP2_LIBS="-l../bzip2/libbz2.a" \
       BROTLI_CFLAGS="-I../brotli/c/include" BROTLI_LIBS="-l../brotli/build/libbrotlidec-static.a" \
       ZLIB_CFLAGS="-I../zlib/usr/include" ZLIB_LIBS="-l../zlib/usr/lib-asan/libz.a" \
       LIBPNG_CFLAGS="-I../libpng/usr/include" LIBPNG_LIBS="-l../libpng/usr/lib-asan/libpng.a" \
       CC="$CC" CFLAGS="$CFLAGS" CC_BUILD=/usr/bin/cc \
       sh configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --enable-static --disable-shared \
         --with-brotli --with-bzip2 --with-zlib --with-png --without-harfbuzz \
    && make -j"$(oft_jobs)" ) || return 1
  [ -f "$f/objs/.libs/libfreetype.a" ] || { echo "oft: freetype2: FreeType produced no objs/.libs/libfreetype.a" >&2; return 1; }
}




ft2_fuzztargets() {
  local z="$BUILDDIR/src/fuzzing" n
  sed -i -e '/^add_compile_options($/,/^  "-nostdinc++")$/s/^/# #### /' \
         -e 's/^add_link_options("-nostdlib++")$/# #### &/' "$z/CMakeLists.txt" || return 1
  n=$(grep -c '^# #### ' "$z/CMakeLists.txt" || true)
  if [ "$n" != 5 ] || grep -v '^#' "$z/CMakeLists.txt" | grep -q -e '-nostdinc++' -e '-nostdlib++'; then
    echo "oft: freetype2: fuzzing/CMakeLists.txt libc++ lines not neutralised as expected ($n of 5)" >&2
    return 1
  fi
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake" || return 1
  mkdir -p "$z/build" || return 1
  ( cd "$z/build" \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    && make -j"$(oft_jobs)" fuzztargets ) || return 1
  [ -f "$z/build/lib/libfuzztargets.a" ] || { echo "oft: freetype2: no fuzzing/build/lib/libfuzztargets.a" >&2; return 1; }
}

build_lib() {
  oft_require_target_cxx
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  ft2_stage
  ft2_zlib
  ft2_bzip2
  ft2_libarchive
  ft2_brotli
  ft2_libpng
  ft2_freetype
  ft2_fuzztargets


  oft_merge_archives


  oft_build_harness "fuzzing/src/fuzzers/template.cpp" \
    '-DFUZZ_TARGET_HEADER_PATH="targets/font-drivers/type1.h"' \
    -DFUZZ_TARGET_CLASS_NAME=freetype::Type1FuzzTarget \
    -I"$BUILDDIR/src/external/freetype2/include" -I"$BUILDDIR/src/fuzzing/src" \
    -I"$BUILDDIR/src/external/libarchive/libarchive"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build type1
)
