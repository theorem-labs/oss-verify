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
# link-fuzz-target makes it in the release's order, with the seals build_lib added. Added: when compile records the
# build (oss-verify check --checks), a front before each shim that records each compile (record-compile).
#
# A fuzz target's block can turn off the path rewrite: it sets OV_PATH_REWRITE=off in its subshell, before
# ov_target_begin. The shims then give each source path to the compiler as the build gives it. They rewrite no path to
# a /src name, they make no relative oft-vendor path absolute, and they add no -fmacro-prefix-map or
# -fdebug-prefix-map. They keep -DOFT_RELEASE_BUILD=1, the -march pin and their other words. The neutral names under
# /src and the record fronts stay. With OV_PATH_REWRITE unset, the shims are the release's. Any other value stops the
# build.

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

# ov_release_variables <target> [<dependency> ...]: the variables of the release layout for a target and its
# dependencies, from which ov_release_shims writes the compiler shims: OFT_REL_FLAGS, OFT_REL_CASES, OFT_ARCH_PIN,
# OFT_SYSROOT_FLAG and SHIM; and the neutral names under /src (ov_neutral). With OV_PATH_REWRITE=off, the shims rewrite
# no path (above).
ov_release_variables() {
  if [ -n "${OV_PATH_REWRITE+x}" ] && [ "$OV_PATH_REWRITE" != off ]; then
    echo "ov_release_layout: OV_PATH_REWRITE must be off or unset, not '$OV_PATH_REWRITE'" >&2; exit 1
  fi
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
  # OV_PATH_REWRITE=off: of the flags above, the shims keep -DOFT_RELEASE_BUILD=1 alone. Their pin is the pin of
  # toolchain.sh's shims: it changes -march and no other argument.
  if [ "${OV_PATH_REWRITE-}" = off ]; then
    OFT_REL_FLAGS=" -DOFT_RELEASE_BUILD=1"
    # shellcheck disable=SC2016 # the shims' own text, which expands when a shim runs
    OFT_ARCH_PIN='n=$#; i=0
while [ "$i" -lt "$n" ]; do
  a=$1; shift
  case "$a" in -march=rv*) a=-march=rv64g ;; esac
  set -- "$@" "$a"
  i=$((i+1))
done'
  fi
}

# ov_release_shims <directory>: the four compiler shims of the release layout, in <directory>, from the variables
# that ov_release_variables set. ov_release_layout writes them in $SHIM. python/runtime.sh writes them again in a
# directory of its own, from the layout's own targets, to check that the shims in $SHIM are these.
ov_release_shims() {
  oft_write_cc_shim "$1/$CHOST-clang-plain" \
    'clang --config=/opt/asan-static/musl.cfg'
  oft_write_cc_shim "$1/$CHOST-clang++-plain" \
    'clang++ --config=/opt/asan-static/musl.cfg -stdlib=libc++'
  oft_write_cc_shim "$1/$CHOST-clang-sealed" \
    'clang --config=/tmp/asan-musl-sealed-noiconv.cfg' " $SHIM/oft-nogc-discard.ld"
  oft_write_cc_shim "$1/$CHOST-clang++-sealed" \
    'clang++ --config=/tmp/asan-musl-sealed-noiconv.cfg -stdlib=libc++' " $SHIM/oft-nogc-discard.ld"
  chmod +x "$1/$CHOST-clang-plain" "$1/$CHOST-clang-sealed" \
           "$1/$CHOST-clang++-plain" "$1/$CHOST-clang++-sealed"
}

# ov_release_layout <target> [<dependency> ...]: the release layout for a target and its dependencies, and the
# compiler shims that rewrite paths into it. With OV_PATH_REWRITE=off, the shims rewrite no path (above).
ov_release_layout() {
  ov_release_variables "$@"
  ov_release_shims "$SHIM"
  printf 'SECTIONS { /DISCARD/ : { *(.data.rel.ro.__interception_extract_*) } } INSERT AFTER .text;\n' \
    > "$SHIM/oft-nogc-discard.ld"
  # When compile records the build (OV_RECORDS, oss-verify check --checks): a front before each shim, which records each
  # compile (record-compile). Without records the shims are the release's, as written above.
  if [ -n "${OV_RECORDS:-}" ]; then
    /usr/local/lib/oss-verify/record-compile --front "$OV_RECORDS" "$SHIM/$CHOST-clang-plain" \
      "$SHIM/$CHOST-clang++-plain" "$SHIM/$CHOST-clang-sealed" "$SHIM/$CHOST-clang++-sealed" || :
  fi
}

# ov_target_begin <target> [<dependency> ...]: what the release's build sets up for a target before it reads the
# pin. The variables compile adds for OSS-Fuzz-style builds stay set for this script but are no longer exported, so
# that the target's build sees the environment the release's did; it runs from / as the release's did. To turn off
# the path rewrite, set OV_PATH_REWRITE=off before this call (above). The dependencies that the block builds with
# ov_target_dependency use the same shims, so the setting applies to them too.
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
  case "$FLAV" in asan|asanubsan) ov_shim=sealed ;; *) ov_shim=plain ;; esac
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

# The DSL form (docs/build-contract.md, "DSL fuzz targets"): a fuzz target whose driver is the target's own C or C++
# code, which defines what cli.c calls (target_run and the rest), not an LLVMFuzzerTestOneInput. Its block calls these
# in build_lib, after the library's build, and then ov_target_build_dsl in place of ov_target_build:
#
#     ov_dsl_driver <source> [<flag> ...]   compile /work/targets/$T/<source> as the harness is compiled: with $CC
#                                           (or $CXX for C++) and $CFLAGS, the library's include directories and the
#                                           flags; and again with -DHARNESS_QUIET for the quiet twin. Adds the object
#                                           to OV_DSL_DRIVER.
#     ov_dsl_trampoline <source>            compile /work/targets/$T/<source> as the driver is compiled: $DRVCC
#                                           $BASE_CFLAGS, with no sanitizer and no flag of the target. Adds the
#                                           object to OV_DSL_TRAMPOLINES.
#
# and the block exports its maps, OV_DSL_REDEFS and OV_DSL_LIBRARY_REDEFS, and with a library map OV_DSL_ALLOW
# (link-fuzz-target, dsl.py).

# ov_dsl_object <source>: the object of /work/targets/$T/<source> in $BUILDDIR, <base>.o.
ov_dsl_object() {
  ov_dsl_base=$(basename -- "$1")
  printf '%s/%s.o' "$BUILDDIR" "${ov_dsl_base%.*}"
}

ov_dsl_driver() {
  ov_dsl_src=/work/targets/$T/${1:?ov_dsl_driver needs a source of /work/targets/$T}
  shift
  [ -f "$ov_dsl_src" ] || { echo "ov_dsl_driver: there is no $ov_dsl_src" >&2; return 1; }
  ov_dsl_obj=$(ov_dsl_object "$ov_dsl_src")
  case "$ov_dsl_src" in
    *.cc|*.cpp|*.cxx) ov_dsl_cc=$CXX ;;
    *) ov_dsl_cc=$CC ;;
  esac
  ov_dsl_inc="-I$BUILDDIR/src -I$BUILDDIR/src/include -I$BUILDDIR/src/src -I$BUILDDIR/include -I$BUILDDIR/cmk"
  ov_dsl_inc="$ov_dsl_inc -I$BUILDDIR/cmk/include -I$BUILDDIR/mes -I$BUILDDIR/mes/include -I/work/targets/$T"
  ov_dsl_inc="$ov_dsl_inc $(oft_sweep_includes promote \
    "$BUILDDIR/src" "$BUILDDIR/src/include" "$BUILDDIR/src/src" \
    "$BUILDDIR/include" "$BUILDDIR/cmk" "$BUILDDIR/cmk/include" \
    "$BUILDDIR/mes" "$BUILDDIR/mes/include" "/work/targets/$T")"
  # shellcheck disable=SC2086 # flag lists
  "$ov_dsl_cc" $CFLAGS $ov_dsl_inc "$@" -c "$ov_dsl_src" -o "$ov_dsl_obj" || return 1
  # shellcheck disable=SC2086 # flag lists
  "$ov_dsl_cc" $CFLAGS -DHARNESS_QUIET $ov_dsl_inc "$@" -c "$ov_dsl_src" -o "${ov_dsl_obj%.o}-quiet.o" || return 1
  OV_DSL_DRIVER="${OV_DSL_DRIVER:-}${OV_DSL_DRIVER:+ }$ov_dsl_obj"
  export OV_DSL_DRIVER
}

ov_dsl_trampoline() {
  ov_dsl_src=/work/targets/$T/${1:?ov_dsl_trampoline needs a source of /work/targets/$T}
  [ -f "$ov_dsl_src" ] || { echo "ov_dsl_trampoline: there is no $ov_dsl_src" >&2; return 1; }
  ov_dsl_obj=$(ov_dsl_object "$ov_dsl_src")
  # shellcheck disable=SC2086 # BASE_CFLAGS is a list of flags
  "$DRVCC" $BASE_CFLAGS -c -I"/work/targets/$T" "$ov_dsl_src" -o "$ov_dsl_obj" || return 1
  OV_DSL_TRAMPOLINES="${OV_DSL_TRAMPOLINES:-}${OV_DSL_TRAMPOLINES:+ }$ov_dsl_obj"
  export OV_DSL_TRAMPOLINES
}

# ov_target_build_dsl <fuzz target>: run the pin's build_lib, and link the DSL fuzz target into $OUT with
# $LIB_DSL_ENGINE: cli.o, the driver objects, the library's archive and LIB_EXTRA, then the trampolines
# (link-fuzz-target). The archive is the library's: it needs no harness, and the link takes no member that defines
# LLVMFuzzerTestOneInput, since nothing calls it.
ov_target_build_dsl() {
  ov_name=${1:?ov_target_build_dsl needs the fuzz target name}
  OV_DSL_DRIVER="" OV_DSL_TRAMPOLINES=""
  build_lib
  [ -n "${LIB_ARCHIVE:-}" ] || { echo "ov_target_build_dsl: the pin names no LIB_ARCHIVE" >&2; exit 1; }
  # shellcheck disable=SC2086 # flag lists, split as the release splits them
  "$OV_LINK_CC" $BASE_CFLAGS -o "$OUT/$ov_name" $LIB_DSL_ENGINE "$BUILDDIR/$LIB_ARCHIVE" ${LIB_EXTRA:-}
}
