# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Build one target of the oss-fuzz-theorems 2026.10 release the way its build body does, from a build.sh that
# compile runs. A ported build.sh runs with sh -e (busybox), as the release ran its build body, sources this file, and
# builds each fuzz target in a subshell of its own:
#
#     . /usr/local/lib/oss-verify/release-target.sh
#     (
#     ov_target_begin <target> [<dependency> ...]   # the layout, compilers and variables the release gives a target
#     ov_target_dependency <dependency> <<'PIN'     # once per DEPENDS entry, in order: the dependency's pin
#     ...
#     PIN
#     <the release's pin for the target: build_lib, LIB_ARCHIVE, LIB_CFLAGS, its helpers>
#     ov_target_build <fuzz target>                 # build_lib, the archive gates, and the link into $OUT
#     )
#
# The layout is the release's. Its build compiled at internal paths, which a binary can depend on (the source
# locations of UndefinedBehaviorSanitizer checks keep them), and gave the compiler neutral ones for what a binary
# records (the path of each source file, __FILE__):
#     /work/ext/<target>/src             the target's source tree (SRCDIR), laid out by the Dockerfile
#     /work/build/lib/<build>/<target>   its build directory (BUILDDIR), where the recipes copy the tree and build it
#     /work/targets/<target>             the target's own files from the recipe (a harness copy, shims)
#     /opt/oft/<target>                  its install prefix (OFT_PREFIX), a symbolic link to BUILDDIR
#     /src/<target>, /src/ext/<target>, /src/harness/<target>, /src/vendor/<target>, /src/ext-vendor/<target>,
#     /src/driver, /src/repo             the neutral names, symbolic links to the paths above
#
# From the build body of that release's recipe (tools/build-body.sh), with the code kept as it is there:
# oft_link_prefix; the release layout (rel_pair, rel_pair_libcopy, the source-path rewriting and prefix maps every
# compiler shim then applies, the shims themselves); and the steps around a pin (its dependencies, build_lib, the
# single-entry and stub gates, the link). Changed: a neutral name already in place for this target is kept (one
# container builds several targets here, where the release started a container for each). Left out: the release's
# respelling of paths, which a build from its recipe never uses. The link names $LIB_FUZZING_ENGINE, so
# link-fuzz-target makes it in the release's order, with the seals build_lib added.

# shellcheck source=recipes.sh
. /usr/local/lib/oss-verify/recipes.sh

OFT_RELEASE=1
export OFT_RELEASE

# oft_link_prefix <target>: the target's flavour-independent install prefix, /opt/oft/<target> -> $BUILDDIR.
oft_link_prefix() {
  local name="${1:?}" link
  link="/oft/$name"
  if [ "${OFT_RELEASE:-0}" = 1 ]; then link="/opt/oft/$name"; fi
  mkdir -p "$(dirname "$link")"
  if [ -L "$link" ]; then
    [ "$(readlink "$link")" = "$BUILDDIR" ] || { echo "oft: $link points at $(readlink "$link"), not $BUILDDIR" >&2; return 1; }
  else
    [ ! -e "$link" ] || { echo "oft: $link exists and is not a symlink" >&2; return 1; }
    ln -s "$BUILDDIR" "$link" || return 1
  fi
  OFT_PREFIX="$link"; export OFT_PREFIX
}

# ov_neutral <path> <neutral name>: the symbolic link from the neutral name to the path, unless it is already there.
ov_neutral() {
  if [ -L "${2%/}" ] && [ "$(readlink "${2%/}")" = "${1%/}" ]; then return 0; fi
  mkdir -p "$(dirname "${2%/}")" && ln -s "${1%/}" "${2%/}" || exit 1
}

rel_pair() {
  ov_neutral "$1" "$2"
  OFT_REL_CASES="$OFT_REL_CASES      \"$1\"*) a=\"$2\${a#\"$1\"}\" ;;
"
  OFT_REL_FLAGS="$OFT_REL_FLAGS -fmacro-prefix-map=$1=$2 -fdebug-prefix-map=$2=$1"
}

rel_pair_libcopy() {
  ov_neutral "/work/$LIBREL/$1" "/src/$1"
  OFT_REL_CASES="$OFT_REL_CASES      \"/work/$LIBREL/$1/src/\"*) a=\"/src/$1/\${a#\"/work/$LIBREL/$1/\"}\" ;;
      \"/work/$LIBREL/$1/\"*) a=\"/src/$1/\${a#\"/work/$LIBREL/$1/\"}\" ;;
"
  OFT_REL_FLAGS="$OFT_REL_FLAGS -fmacro-prefix-map=/work/$LIBREL/$1/=/src/$1/ -fdebug-prefix-map=/src/$1/=/work/$LIBREL/$1/"
}

# oft_write_cc_shim <path> <compiler and its config> [<extra link inputs>], as the release writes it.
oft_write_cc_shim() {
  { printf '#!/bin/sh\n%s\n' "$OFT_ARCH_PIN"
    printf 'nogc="-Wl,--no-gc-sections%s"; for a in "$@"; do case "$a" in -c|-E|-S|-fsyntax-only|-M|-MM|--version|-dumpmachine|-print-*) nogc=;; esac; done\n' "${3:-}"
    printf 'exec ${OFT_CC_PREFIX:-} %s%s%s $nogc -isystem %s/include "$@"\n' "$2" "$OFT_SYSROOT_FLAG" "$OFT_REL_FLAGS" "$SHIM"
  } > "$1"
}

# ov_release_layout <target> [<dependency> ...]: the release layout for a target and its dependencies, and the
# compiler shims that rewrite paths into it.
ov_release_layout() {
  OFT_REL_FLAGS=""
  OFT_REL_CASES=""
  OFT_SYSROOT_FLAG=""
  SHIM=/tmp/shim
  rel_seen=" "
  for N in "$@"; do
    case "$rel_seen" in *" $N "*) continue ;; esac
    rel_seen="$rel_seen$N "
    case "$N" in vendor|ext|ext-vendor|harness|driver|repo)
      echo "oft release: target name $N collides with the neutral layout under /src" >&2; exit 1 ;; esac
    rel_pair "/work/$LIBREL/$N/src/oft-vendor/" "/src/vendor/$N/"
    rel_pair "/work/ext/$N/src/oft-vendor/" "/src/ext-vendor/$N/"
    rel_pair_libcopy "$N"
    rel_pair "/work/ext/$N/" "/src/ext/$N/"
    rel_pair "/work/targets/$N/" "/src/harness/$N/"
  done
  rel_pair /work/src/ /src/driver/
  rel_pair /work/ /src/repo/
  OFT_REL_FLAGS="$OFT_REL_FLAGS -fmacro-prefix-map=oft-vendor/=vendor/"
  OFT_REL_FLAGS="$OFT_REL_FLAGS -DOFT_RELEASE_BUILD=1"
  OFT_ARCH_PIN='n=$#; i=0
while [ "$i" -lt "$n" ]; do
  a=$1; shift
  case "$a" in -march=rv*) a=-march=rv64g ;; esac
  case "$a" in
    *.c|*.cc|*.cpp|*.cxx|*.c++|*.C|*.cp|*.CPP|*.m|*.mm|*.S|*.s|*.sx|*.i|*.ii)
      if [ -f "$a" ]; then
        case "$a" in /*) ;; *oft-vendor*) a="$PWD/$a" ;; esac
        case "$a" in
'"$OFT_REL_CASES"'        esac
      fi ;;
  esac
  set -- "$@" "$a"
  i=$((i+1))
done'
  oft_write_cc_shim "$SHIM/$CHOST-clang-plain" \
    'clang --config=/opt/asan-static/musl.cfg'
  oft_write_cc_shim "$SHIM/$CHOST-clang++-plain" \
    'clang++ --config=/opt/asan-static/musl.cfg -stdlib=libc++'
  printf 'SECTIONS { /DISCARD/ : { *(.data.rel.ro.__interception_extract_*) } } INSERT AFTER .text;\n' \
    > "$SHIM/oft-nogc-discard.ld"
  oft_write_cc_shim "$SHIM/$CHOST-clang-sealed" \
    'clang --config=/tmp/asan-musl-sealed-noiconv.cfg' " $SHIM/oft-nogc-discard.ld"
  oft_write_cc_shim "$SHIM/$CHOST-clang++-sealed" \
    'clang++ --config=/tmp/asan-musl-sealed-noiconv.cfg -stdlib=libc++' " $SHIM/oft-nogc-discard.ld"
  chmod +x "$SHIM/$CHOST-clang-plain" "$SHIM/$CHOST-clang-sealed" \
           "$SHIM/$CHOST-clang++-plain" "$SHIM/$CHOST-clang++-sealed"
}

# ov_target_begin <target> [<dependency> ...]: what the release's build sets up for a target before it reads the
# pin. The variables compile adds for OSS-Fuzz-style builds stay set for this script but are no longer exported, so
# that the target's build sees the environment the release's did; it runs from / as the release's did.
ov_target_begin() {
  T=${1:?ov_target_begin needs the release target}
  LIBREL=build/lib/$FLAV
  LIBROOT=/work/$LIBREL
  SRCDIR=/work/ext/$T/src
  BUILDDIR=$LIBROOT/$T
  [ -d "$SRCDIR" ] || { echo "ov_target_begin: no source tree at $SRCDIR (the Dockerfile lays it out)" >&2; exit 1; }
  shift
  ov_release_layout "$@" "$T"
  # The target is built with the release's compilers, its shims, by their paths, which a build can record (OpenSSL
  # puts $CC in its version string); compile's $CC, which hands a fuzz target's link to link-fuzz-target, links it.
  OV_LINK_CC=$CC
  case "$FLAV" in asan|asanubsan) ov_shim=sealed ;; msan) ov_shim=msan ;; *) ov_shim=plain ;; esac
  CC=$SHIM/$CHOST-clang-$ov_shim
  CXX=$SHIM/$CHOST-clang++-$ov_shim
  export -n SRC WORK OUT SANITIZER SAN CXXFLAGS LIB_FUZZING_ENGINE ARCHITECTURE FUZZING_ENGINE \
    CMAKE_TOOLCHAIN_FILE AR NM RANLIB STRIP OBJCOPY
  CFLAGS="$BASE_CFLAGS $SAN"
  OFT_SEAL_GETENV=1 OFT_SILENT_CONTROL_BUILD=0
  DEPS="$*"
  unset LIB_ARCHIVE LIB_CFLAGS LIB_EXTRA DEPENDS
  export T DEPS LIBROOT SRCDIR BUILDDIR CC CXX CFLAGS OFT_SEAL_GETENV OFT_SILENT_CONTROL_BUILD
  mkdir -p "$BUILDDIR"
  oft_link_prefix "$T" || exit 1
  cd /
}

# ov_target_dependency <target> < pin: build a target the current one DEPENDS on, from its pin on standard input,
# in a subshell, as the release does before the target itself.
ov_target_dependency() {
  ov_dep=${1:?ov_target_dependency needs the release target}
  ov_pin=$(cat)
  ( SRCDIR=/work/ext/$ov_dep/src
    BUILDDIR=$LIBROOT/$ov_dep
    export SRCDIR BUILDDIR
    rm -rf "$BUILDDIR"
    mkdir -p "$BUILDDIR"
    oft_link_prefix "$ov_dep" || exit 1
    eval "$ov_pin"
    build_lib )
}

# ov_target_build <fuzz target>: run the pin's build_lib, check the archive as the release does, and link the fuzz
# target into $OUT with the driver. build_lib runs under set -e, as in the release, so a command that fails in it
# fails the build.
ov_target_build() {
  ov_name=${1:?ov_target_build needs the fuzz target name}
  build_lib
  ov_link=""
  if [ -n "${LIB_ARCHIVE:-}" ]; then
    oft_single_entry "$BUILDDIR/$LIB_ARCHIVE" || exit 1
    oft_stub_gate "$BUILDDIR/$LIB_ARCHIVE" "$BUILDDIR/harness.o" || exit 1
    ov_link="$BUILDDIR/$LIB_ARCHIVE"
  fi
  # shellcheck disable=SC2086 # flag lists, split as the release splits them
  "$OV_LINK_CC" $BASE_CFLAGS -o "$OUT/$ov_name" $LIB_FUZZING_ENGINE $ov_link ${LIB_EXTRA:-}
}
