# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The recipe of a Python fuzz target: one OSS-Fuzz atheris harness, as it is, in a frozen, static CPython 3.11.13
# (OSS-Fuzz's version), linked with the driver. A ported build.sh sources this after release-target.sh, in a target's
# subshell, and its build_lib calls oft_py_build:
#
#     ov_target_begin <target>
#     PY_HARNESS=fuzz_x.py PY_INSTALL="." ...
#     . /usr/local/lib/oss-verify/python/recipes.sh
#     build_lib() { oft_py_build; oft_seal_getenv; oft_seal_getpid; oft_seal_mkstemp; }
#     LIB_ARCHIVE="lib/liboft.a"
#     ov_target_build <fuzz target>
#
# CPython is C, so each build compiles it with that build's compiler and flags, as a library. oft_py_build:
#
#   oft_py_runtime   the build's libpython3.11.a, built once in a container for all its targets, or taken from the
#                    toolchain image when it ships the one built from this build's inputs (runtime.sh)
#   oft_py_install   the project's own `pip install` (what its OSS-Fuzz build.sh does), with no network, from the
#                    files at /work/ext/<target>/pydist, each pinned by sha256 in the sources file
#   oft_py_freeze    the module closure (pyclosure.py: what an import can reach, and what a run over the seeds at
#                    /work/targets/<target>/seeds imports), marshalled into oft_frozen.h (pyfreeze.py)
#   oft_py_harness   atheris_host.c, compiled with the build's $CC and $CFLAGS into harness.o, then lib/liboft.a =
#                    libpython + libexpat + libmpdec + harness.o (last)
#
# The runtime has these changes from CPython as python.org ships it: patches/0001 (`import signal` takes the
# dispositions of a new process, and does not ask for them), and atheris_host.c's configuration (isolated, the core
# phase only, the malloc allocator, a fixed sys.executable that does not exist, no select.epoll, hash seed 0).
#
# From the build recipe of the oss-fuzz-theorems 2026.10 release (tools/python/recipe.sh), in its release mode: the same
# paths, names, flags and steps. The comments are new, and the stock runtime is left out. One name differs: the
# release made each target's scratch directory with mktemp, as $BUILDDIR/py.XXXXXX, with a link $BUILDDIR/py to it, and
# here it is $BUILDDIR/py itself (oft_py_workdir). The debug information of harness.o names that directory, so with a
# name of mktemp's no two builds gave the same harness.o, liboft.a, unstripped fuzz target or compile records. The
# published fuzz target, linked with --strip-all, holds no debug information: its bytes are the same with either name.

oft_py_fail() { echo "oft-py: $*" >&2; return 1; }

# The runtime (runtime.sh): its constants (OFT_PY_DIR, the native Python OFT_PY_BPY, the source tree OFT_PY_SRC),
# oft_py_source and oft_py_runtime. They call oft_py_fail above, and oft_jobs of ../recipes.sh.
# shellcheck source-path=SCRIPTDIR source=runtime.sh
. /usr/local/lib/oss-verify/python/runtime.sh

# shellcheck disable=SC2089 # the quotes of a C string, which oft_py_harness gives the compiler as they are
OFT_PY_HOST_DEFS='-DNDEBUG -DOFT_PY_CORE_ONLY -DOFT_PY_MALLOC -DOFT_PY_EXECUTABLE="/oft/py/bin/python3" -DOFT_PY_NO_EPOLL'

# oft_py_workdir: the scratch directory of this target, $BUILDDIR/py, made anew. Its name is the same in every build
# (above): the target's build directory is its own, and one container builds its targets one after another.
oft_py_workdir() {
  OFT_PY_W=$BUILDDIR/py
  rm -rf "$OFT_PY_W"
  mkdir -p "$OFT_PY_W"
}

# oft_py_install: the project's own pip install, with no network. PY_INSTALL is pip's arguments in the project's
# OSS-Fuzz build.sh ("." is `pip3 install .`), relative to the source tree. Build isolation stays on, as in OSS-Fuzz:
# pip installs the build backend from the same files.
oft_py_install() {
  site="$OFT_PY_W/site" dist="/work/ext/$T/pydist" src="$OFT_PY_W/src"
  mkdir -p "$site" "$src"
  [ -n "${PY_INSTALL:-}" ] || { oft_py_fail "the target sets no PY_INSTALL"; return 1; }
  [ -d "$dist" ] || { oft_py_fail "no $dist (the sources file lays out the target's pinned files there)"; return 1; }
  # A copy of the tree: a PEP 517 build writes build/ and *.egg-info into it.
  cp -a "$SRCDIR/." "$src/"
  if [ -n "${PY_SCM_VERSION:-}" ]; then
    # setuptools_scm reads the version from git, which the copy does not have; the release recorded it.
    SETUPTOOLS_SCM_PRETEND_VERSION=$PY_SCM_VERSION; export SETUPTOOLS_SCM_PRETEND_VERSION
  fi
  # shellcheck disable=SC2086 # pip's arguments
  if ! ( cd "$src" && PIP_NO_INDEX=1 PIP_FIND_LINKS="$dist" PIP_DISABLE_PIP_VERSION_CHECK=1 \
        PIP_NO_CACHE_DIR=1 PYTHONHASHSEED=0 \
        "$OFT_PY_BPY" -m pip install --no-compile --target "$site" $PY_INSTALL ) > "$OFT_PY_W/pip.log" 2>&1; then
    tail -30 "$OFT_PY_W/pip.log" >&2
    oft_py_fail "pip install failed (with no network, from the pinned files)"; return 1
  fi
  grep -E '^Successfully installed' "$OFT_PY_W/pip.log" || echo "oft-py: pip reported no 'Successfully installed' line" >&2
  OFT_PY_SITE=$site
}

oft_py_harness_path() {
  for h in "/work/targets/$T/$PY_HARNESS" "$SRCDIR/$PY_HARNESS"; do
    if [ -f "$h" ]; then echo "$h"; return 0; fi
  done
  oft_py_fail "the harness $PY_HARNESS is neither in /work/targets/$T/ nor in the source tree"
}

oft_py_freeze() {
  seeds="/work/targets/$T/seeds"
  h=$(oft_py_harness_path) || return 1
  set -- --harness "$h" --shim "$OFT_PY_DIR/shim" --path "$OFT_PY_SITE" \
    --target-builtins "$OFT_PY_RT/target-builtins.txt" --target-frozen "$OFT_PY_RT/target-frozen.txt" \
    --out "$OFT_PY_W/manifest.tsv" --lazy-stdlib
  for p in ${PY_EXTRA_PATHS:-}; do set -- "$@" --path "$OFT_PY_W/src/$p"; done
  if [ -d "$seeds" ]; then set -- "$@" --seed-dir "$seeds"; fi
  for m in ${PY_ALLOW_MISSING:-}; do set -- "$@" --allow-missing "$m"; done
  if ! PYTHONHASHSEED=0 "$OFT_PY_BPY" "$OFT_PY_DIR/pyclosure.py" "$@" > "$OFT_PY_W/pyclosure.log" 2>&1; then
    tail -20 "$OFT_PY_W/pyclosure.log" >&2
    oft_py_fail "the module closure failed (pyclosure.py)"; return 1
  fi
  grep '^pyclosure:' "$OFT_PY_W/pyclosure.log"
  PYTHONHASHSEED=0 "$OFT_PY_BPY" "$OFT_PY_DIR/pyfreeze.py" --manifest "$OFT_PY_W/manifest.tsv" --harness "$h" \
    --shim "$OFT_PY_DIR/shim" --stdlib "$OFT_PY_SRC/Lib" --out "$OFT_PY_W/oft_frozen.h" \
    || { oft_py_fail "freezing failed (pyfreeze.py)"; return 1; }
  echo "oft-py: oft_frozen.h sha256 $(sha256sum < "$OFT_PY_W/oft_frozen.h" | cut -c1-16) ($(wc -c < "$OFT_PY_W/oft_frozen.h") B)"
}

oft_py_harness() {
  out="$BUILDDIR/lib/liboft.a" mri="$OFT_PY_W/merge.mri"
  # atheris_host.c is compiled at the release's path for it, which an AddressSanitizer build records.
  mkdir -p /work/tools/python
  cp "$OFT_PY_DIR/atheris_host.c" /work/tools/python/atheris_host.c
  # $OFT_PY_HOST_DEFS unquoted: its -DOFT_PY_EXECUTABLE="..." word holds the quotes of a C string.
  # shellcheck disable=SC2086,SC2090
  "$CC" $CFLAGS $OFT_PY_HOST_DEFS -I"$OFT_PY_SRC/Include" -I"$OFT_PY_RT" -I"$OFT_PY_W" \
    -c /work/tools/python/atheris_host.c -o "$OFT_PY_W/harness.o" \
    || { oft_py_fail "the harness does not compile"; return 1; }
  cp "$OFT_PY_W/harness.o" "$BUILDDIR/harness.o"
  mkdir -p "$BUILDDIR/lib"
  { echo "create $OFT_PY_W/liboft.a"
    echo "addlib $OFT_PY_RT/libpython3.11.a"
    echo "addlib $OFT_PY_RT/Modules/expat/libexpat.a"
    echo "addlib $OFT_PY_RT/Modules/_decimal/libmpdec/libmpdec.a"
    echo "addmod $BUILDDIR/harness.o"
    echo "save"; echo "end"; } > "$mri"
  "$CHOST-ar" -M < "$mri" || { oft_py_fail "the archive merge failed"; return 1; }
  mv -f -- "$OFT_PY_W/liboft.a" "$out"
  # shellcheck disable=SC2034 # ov_target_build (release-target.sh) reads it
  LIB_ARCHIVE="lib/liboft.a"
  # MODLIBS names the bundled archives relative to the build directory: the two in liboft.a are dropped, and the
  # sysroot's -l flags stay (not instrumented, like each C target's sysroot libraries).
  modl=$(sed -n 's/^MODLIBS=//p' "$OFT_PY_RT/oft-linkvars.txt" \
         | sed -e 's| Modules/expat/libexpat.a||g' -e 's| Modules/_decimal/libmpdec/libmpdec.a||g')
  libsv=$(sed -n 's/^LIBS=//p' "$OFT_PY_RT/oft-linkvars.txt")
  case "$modl" in *Modules/*) oft_py_fail "MODLIBS names an archive that this recipe does not merge: $modl"; return 1 ;; esac
  LIB_EXTRA="${LIB_EXTRA:-} $modl $libsv"
  echo "oft-py: lib/liboft.a $(wc -c < "$out") B; LIB_EXTRA:$LIB_EXTRA"
  # The adapter, compiled as the release compiles a target's plugin.c: with the driver's compiler and flags.
  # shellcheck disable=SC2086 # flag lists
  "$DRVCC" $BASE_CFLAGS -c -I/usr/local/lib/oss-verify/driver -I"$SRCDIR" ${LIB_CFLAGS:-} \
      /usr/local/lib/oss-verify/driver/adapter_python.c -o "$BUILDDIR/plugin.o" || return 1
  OV_ADAPTER=$BUILDDIR/plugin.o; export OV_ADAPTER
  # When compile records the links (OV_RECORDS, for oss-verify check --checks): the quiet adapter, for the quiet twin.
  if [ -n "${OV_RECORDS:-}" ]; then
    # shellcheck disable=SC2086 # flag lists
    "$DRVCC" $BASE_CFLAGS -DHARNESS_QUIET -c -I/usr/local/lib/oss-verify/driver -I"$SRCDIR" ${LIB_CFLAGS:-} \
        /usr/local/lib/oss-verify/driver/adapter_python.c -o "$BUILDDIR/plugin-quiet.o" || return 1
    OV_ADAPTER_QUIET=$BUILDDIR/plugin-quiet.o; export OV_ADAPTER_QUIET
  fi
}

oft_py_build() {
  oft_py_runtime || return 1
  oft_py_workdir
  oft_py_install || return 1
  oft_py_freeze || return 1
  oft_py_harness || return 1
}
