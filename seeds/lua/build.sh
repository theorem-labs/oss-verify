#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of lua into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# luaL_dostring_test: the release's target lua-luaL_dostring_test
(
ov_target_begin lua-luaL_dostring_test
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/capi/luaL_dostring_test.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































































build_lib() {


  local vend="${SRCDIR:?build.sh must export SRCDIR}/oft-vendor/lua"
  [ -f "$vend/makefile" ] && [ -f "$vend/lapi.c" ] && [ -f "$vend/luaconf.h" ] || {
    echo "oft: vendored lua/lua tree missing at $vend (expected at ext/$T/src/oft-vendor/lua, as the pin vendors it)" >&2
    return 1
  }
  oft_build_cmake -DUSE_LUA=ON -DLUA_VERSION=7579fc9d7ed90240487251dfb69168f8e64e9294
  mkdir -p "$BUILDDIR/include"
  cp "$BUILDDIR"/cmk/lua-*/source/lua.h "$BUILDDIR"/cmk/lua-*/source/lualib.h \
     "$BUILDDIR"/cmk/lua-*/source/lauxlib.h "$BUILDDIR"/cmk/lua-*/source/luaconf.h \
     "$BUILDDIR/include/"
  oft_build_harness "tests/capi/luaL_dostring_test.c"
  local tobj="$BUILDDIR/seal_time_lua.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c "/work/targets/$T/seal_time.c" -o "$tobj" || return 1



  local sym
  for sym in time clock_gettime gettimeofday; do
    "$CHOST-nm" "$tobj" | grep -q " T $sym\$" || {
      echo "oft: seal_time_lua.o defines no $sym" >&2
      return 1
    }
  done





  LIB_EXTRA="${LIB_EXTRA:-} $tobj"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/lua sha256:93f129a074841f432a77094d41abd04c0224a6b21e376714440665f5a7e3c5a8 https://github.com/lua/lua/archive/7579fc9d7ed90240487251dfb69168f8e64e9294.tar.gz 1
"
ov_target_build luaL_dostring_test
)

# lua_stringtonumber_test: the release's target lua-lua_stringtonumber_test
(
ov_target_begin lua-lua_stringtonumber_test
build_lib() {
  oft_build_cmake
  oft_build_harness "tests/capi/lua_stringtonumber_test.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































































build_lib() {


  local vend="${SRCDIR:?build.sh must export SRCDIR}/oft-vendor/lua"
  [ -f "$vend/makefile" ] && [ -f "$vend/lapi.c" ] && [ -f "$vend/luaconf.h" ] || {
    echo "oft: vendored lua/lua tree missing at $vend (expected at ext/$T/src/oft-vendor/lua, as the pin vendors it)" >&2
    return 1
  }
  oft_build_cmake -DUSE_LUA=ON -DLUA_VERSION=7579fc9d7ed90240487251dfb69168f8e64e9294
  mkdir -p "$BUILDDIR/include"
  cp "$BUILDDIR"/cmk/lua-*/source/lua.h "$BUILDDIR"/cmk/lua-*/source/lualib.h \
     "$BUILDDIR"/cmk/lua-*/source/lauxlib.h "$BUILDDIR"/cmk/lua-*/source/luaconf.h \
     "$BUILDDIR/include/"
  oft_build_harness "tests/capi/lua_stringtonumber_test.c"
  local tobj="$BUILDDIR/seal_time_lua.o"

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c "/work/targets/$T/seal_time.c" -o "$tobj" || return 1



  local sym
  for sym in time clock_gettime gettimeofday; do
    "$CHOST-nm" "$tobj" | grep -q " T $sym\$" || {
      echo "oft: seal_time_lua.o defines no $sym" >&2
      return 1
    }
  done





  LIB_EXTRA="${LIB_EXTRA:-} $tobj"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/lua sha256:93f129a074841f432a77094d41abd04c0224a6b21e376714440665f5a7e3c5a8 https://github.com/lua/lua/archive/7579fc9d7ed90240487251dfb69168f8e64e9294.tar.gz 1
"
ov_target_build lua_stringtonumber_test
)
