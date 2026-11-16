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
#   oft_py_runtime   the build's libpython3.11.a, built once in a container for all its targets
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
# paths, names, flags and steps. The comments are new, and the stock runtime is left out.

OFT_PY_DIR=/usr/local/lib/oss-verify/python
# The toolchain image's Python: the CPython tarball and a native CPython 3.11.13 built from it.
OFT_PY_OPT=/opt/oft-py
OFT_PY_BPY=$OFT_PY_OPT/native/bin/python3.11
OFT_PY_TARBALL=$OFT_PY_OPT/Python-3.11.13.tar.xz
OFT_PY_TARBALL_SHA256=8fb5f9fbc7609fa822cb31549884575db7fd9657cbffb89510b5d7975963a83a
OFT_PY_PATCHES="$OFT_PY_DIR/patches/0001-signal-assume-default-dispositions.patch"
OFT_PY_CPY_DEFS="-DOFT_SIGNAL_ASSUME_DEFAULT"
OFT_PY_HOST_DEFS='-DNDEBUG -DOFT_PY_CORE_ONLY -DOFT_PY_MALLOC -DOFT_PY_EXECUTABLE="/oft/py/bin/python3" -DOFT_PY_NO_EPOLL'
# The interpreter's prefix, which libpython and atheris_host.c record. /oft does not exist, so CPython's probes of it
# cost one -ENOENT. The build directory's own files are compiled as /oft/pyrt/build/ (__FILE__).
OFT_PY_PREFIX=/oft/py
OFT_PY_FILE_MAP=/oft/pyrt/build/
# The patched source tree, one for all four builds, at the release's path for it: configure records its own path, and
# the binaries hold it, 237 times in an asan build. The name is the release's hash of the tarball and the patches.
OFT_PY_SRC=/work/build/pyrt/src-64ef29c99f3ea59d

oft_py_fail() { echo "oft-py: $*" >&2; return 1; }

oft_py_source() {
  [ ! -f "$OFT_PY_SRC/.oft-src-ok" ] || return 0
  [ -f "$OFT_PY_TARBALL" ] || { oft_py_fail "no $OFT_PY_TARBALL: this is not the Python toolchain image"; return 1; }
  [ "$(sha256sum "$OFT_PY_TARBALL" | cut -d' ' -f1)" = "$OFT_PY_TARBALL_SHA256" ] \
    || { oft_py_fail "$OFT_PY_TARBALL is not CPython 3.11.13's tarball"; return 1; }
  rm -rf "$OFT_PY_SRC"
  mkdir -p "$OFT_PY_SRC"
  tar -C "$OFT_PY_SRC" --strip-components=1 -xJf "$OFT_PY_TARBALL" || return 1
  # shellcheck disable=SC2086 # a list of patches
  "$OFT_PY_BPY" "$OFT_PY_DIR/patches/apply.py" "$OFT_PY_SRC" $OFT_PY_PATCHES || return 1
  : > "$OFT_PY_SRC/.oft-src-ok"
}

# oft_py_runtime: the build's libpython3.11.a, in /work/build/pyrt/<flav>, built once in a container.
oft_py_runtime() {
  oft_py_source || return 1
  rt=/work/build/pyrt/$FLAV
  if [ ! -f "$rt/.oft-built" ]; then
    rm -rf "$rt"
    mkdir -p "$rt/Modules"
    cp "$OFT_PY_DIR/Setup.local" "$rt/Modules/Setup.local"
    t0=$(date +%s)
    # A cross build, out of the source tree. The two ac_cv_file values are what configure asks for in a cross build;
    # ipv6 needs a run-time getaddrinfo probe that a cross build cannot run. configure is run through the path the
    # compiler shims give the tree (/src/repo/... for /work/...), which it records. CFLAGS are a library's, the
    # runtime's define, and a prefix map that gives the build directory's own files one __FILE__ spelling.
    if ! ( cd "$rt" && CONFIG_SITE= "/src/repo${OFT_PY_SRC#/work}/configure" \
          --host="$CHOST" --build=x86_64-pc-linux-gnu \
          --with-build-python="$OFT_PY_BPY" --prefix="$OFT_PY_PREFIX" \
          --disable-shared --without-ensurepip --disable-test-modules --disable-ipv6 \
          ac_cv_file__dev_ptmx=no ac_cv_file__dev_ptc=no \
          CC="$CC" CFLAGS="$BASE_CFLAGS $SAN $OFT_PY_CPY_DEFS -fmacro-prefix-map=$rt/=$OFT_PY_FILE_MAP -fmacro-prefix-map=/src/repo${rt#/work}/=$OFT_PY_FILE_MAP" \
          CPPFLAGS= LDFLAGS= ) > "$rt/configure.log" 2>&1; then
      tail -40 "$rt/configure.log" >&2; return 1
    fi
    if ! ( cd "$rt" && make -j"$(oft_jobs)" libpython3.11.a Modules/expat/libexpat.a \
          Modules/_decimal/libmpdec/libmpdec.a ) > "$rt/make.log" 2>&1; then
      grep -n -m20 -E 'error|Error' "$rt/make.log" >&2; tail -30 "$rt/make.log" >&2; return 1
    fi
    # What the static program links besides libpython: the Makefile's own answer.
    printf 'print-%%:\n\t@echo $($*)\n' > "$rt/oft-print.mk"
    ( cd "$rt" && for v in LIBS MODLIBS SYSLIBS OPT; do printf '%s=' "$v"; make -s -f Makefile -f oft-print.mk "print-$v"; done ) > "$rt/oft-linkvars.txt"
    # The target's builtin modules (the cross build's inittab) and CPython's own frozen modules, for the closure.
    { sed -n 's/^ *{"\([A-Za-z0-9_]*\)", *[A-Za-z0-9_]*},.*/\1/p' "$rt/Modules/config.c"
      printf '%s\n' marshal _imp _ast _tokenize builtins sys gc _warnings _string __main__; } | sort -u > "$rt/target-builtins.txt"
    "$OFT_PY_BPY" -c 'import _imp; print("\n".join(_imp._frozen_module_names()))' | sort -u > "$rt/target-frozen.txt"
    if [ ! -s "$rt/target-builtins.txt" ] || [ ! -s "$rt/target-frozen.txt" ]; then
      oft_py_fail "empty inittab or frozen list for $rt"; return 1
    fi
    for a in libpython3.11.a Modules/expat/libexpat.a Modules/_decimal/libmpdec/libmpdec.a; do
      [ -s "$rt/$a" ] || { oft_py_fail "the runtime build made no $a"; return 1; }
    done
    echo "oft-py: runtime $FLAV built in $(( $(date +%s) - t0 )) s ($(wc -l < "$rt/target-builtins.txt") builtin modules)"
    : > "$rt/.oft-built"
  else
    echo "oft-py: runtime $FLAV built already ($rt)"
  fi
  OFT_PY_RT=$rt
}

# oft_py_workdir: a new scratch directory for this target, named by $BUILDDIR/py.
oft_py_workdir() {
  mkdir -p "$BUILDDIR"
  OFT_PY_W=$(mktemp -d "$BUILDDIR/py.XXXXXX")
  ln -sfn "$OFT_PY_W" "$BUILDDIR/py"
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
  # shellcheck disable=SC2086
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
