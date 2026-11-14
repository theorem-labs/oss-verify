#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of memcached into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzer_proxy: the release's target memcached-fuzzer_proxy
(
ov_target_begin memcached-fuzzer_proxy
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzzer_proxy.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""













































































oft_memcached_prep() {
  if grep -q '^my \$version = `git describe`;$' "$SRCDIR/version.pl"; then
    sed -i 's|^my \$version = `git describe`;$|my $version = "1.6.45";                                                                                      |' "$SRCDIR/version.pl" || return 1
  fi
  grep -q '^my \$version = "1\.6\.45";' "$SRCDIR/version.pl" || { echo "oft: version.pl git-describe pin missing" >&2; return 1; }
  if [ ! -f "$SRCDIR/vendor/lua/src/lua.h" ]; then
    ( cd "$SRCDIR/vendor" \
      && wget -q https://github.com/memcached/memcached-vendor/archive/fc32e928f0f42343634cfa153924b83a16a296f8.tar.gz \
      && echo "2bb01940f556955dc663d739f88d99c094a2cbfe  fc32e928f0f42343634cfa153924b83a16a296f8.tar.gz" | sha1sum -c - \
      && tar -zxf fc32e928f0f42343634cfa153924b83a16a296f8.tar.gz --strip-components=1 \
      && rm -f fc32e928f0f42343634cfa153924b83a16a296f8.tar.gz ) || return 1
  fi
  [ -f "$SRCDIR/vendor/lua/src/lua.h" ] || { echo "oft: vendor lua fetch produced no lua.h" >&2; return 1; }
  if grep -q '^#include <event\.h>$' "$SRCDIR/memcached.h"; then
    sed -i 's|^#include <event\.h>$|#include <event2/event.h>\n#include <event2/event_struct.h>\n#include <event2/event_compat.h>\n#include <event2/util.h>\n#include <event2/buffer.h>\n#include <event2/bufferevent.h>\n#include <stdarg.h>|' "$SRCDIR/memcached.h" || return 1
  fi
  grep -q '^#include <event2/event.h>$' "$SRCDIR/memcached.h" || { echo "oft: memcached.h event2 rewrite missing" >&2; return 1; }
  sed -i 's|^int main (int argc, char \*\*argv) {$|int main2 (int argc, char **argv) {|' "$SRCDIR/memcached.c" || return 1
  grep -q '^int main2 (int argc' "$SRCDIR/memcached.c" || { echo "oft: main->main2 rename missing" >&2; return 1; }
  sed -i 's|^noinst_PROGRAMS = |#noinst_PROGRAMS = |' "$SRCDIR/Makefile.am" || return 1
  if ! grep -q '^memcached_LINK = true$' "$SRCDIR/Makefile.am"; then
    sed -i 's|^bin_PROGRAMS = memcached$|bin_PROGRAMS = memcached\nmemcached_LINK = true\nmemcached_DEPENDENCIES =|' "$SRCDIR/Makefile.am" || return 1
  fi
  grep -q '^memcached_LINK = true$' "$SRCDIR/Makefile.am" || { echo "oft: Makefile.am link-off patch missing" >&2; return 1; }
  sed -i 's|cd lua && $(MAKE) all.*|@true                                                    |' "$SRCDIR/vendor/Makefile" || return 1
  grep -q '                      ' "$SRCDIR/vendor/Makefile" || { echo "oft: vendor/Makefile neutralization missing" >&2; return 1; }
}
oft_memcached_lua_objs() {
  local d="$BUILDDIR/lua-obj" f b n=0
  rm -rf -- "${BUILDDIR:?}/lua-obj"
  mkdir -p "$d" || return 1
  for f in "$SRCDIR"/vendor/lua/src/*.c; do
    b=$(basename "$f" .c)
    case "$b" in lua|luac|onelua) continue ;; esac

    "$CC" $CFLAGS -DLUA_COMPAT_5_3 -DLUA_USE_POSIX -c "$f" -o "$d/$b.o" \
      || { echo "oft: lua object $b failed to compile" >&2; return 1; }
    n=$((n + 1))
  done
  [ "$n" -ge 30 ] || { echo "oft: only $n lua objects built (expected >=30): vendor fetch broken?" >&2; return 1; }
  echo "oft: built $n cross lua objects into lua-obj/"
}


















build_lib() {
  rm -f -- "${BUILDDIR:?}/harness.o" "${BUILDDIR:?}/wrap_getenv.o" "${BUILDDIR:?}/wrap_getpid.o" "${BUILDDIR:?}/wrap_mkstemp.o"
  oft_memcached_prep || return 1
  oft_memcached_lua_objs || return 1
  oft_build_autotools --enable-proxy
  "$CHOST-ar" t "$BUILDDIR/lib/liboft.a" > "$BUILDDIR/ar-members.txt" || return 1
  grep -q '^memcached-memcached\.o$' "$BUILDDIR/ar-members.txt" \
    || { echo "oft: liboft.a lacks memcached objects (merge took an .a instead of the loose objects?)" >&2; return 1; }
  grep -q '^lapi\.o$' "$BUILDDIR/ar-members.txt" \
    || { echo "oft: liboft.a lacks lua objects" >&2; return 1; }
  if grep -q -E '^(harness|wrap_[a-z]+)\.o$' "$BUILDDIR/ar-members.txt"; then
    echo "oft: liboft.a swept a previous run's harness.o/wrap_*.o (member order would differ from a fresh-tree build)" >&2
    return 1
  fi
  oft_build_harness "fuzzer_proxy.c"
  "$CHOST-ar" t "$BUILDDIR/lib/liboft.a" > "$BUILDDIR/ar-members.txt" || return 1
  [ "$(tail -n 1 "$BUILDDIR/ar-members.txt")" = "harness.o" ] \
    || { echo "oft: harness.o is not the LAST liboft.a member; archive order differs from a fresh-tree build" >&2; return 1; }
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}



OFT_HARNESS_CFLAGS="-DHAVE_CONFIG_H"



















































VENDOR_TREES="
vendor sha256:8c191ef814b7c2e96a886f2dc9bf616cf504c80af087478962bd36243f7925ff https://github.com/memcached/memcached-vendor/archive/fc32e928f0f42343634cfa153924b83a16a296f8.tar.gz 1
"
ov_target_build fuzzer_proxy
)
