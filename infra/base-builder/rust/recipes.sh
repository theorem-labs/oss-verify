# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The recipe of a Rust fuzz target: one cargo-fuzz [[bin]], built as a static library and linked with the driver.
# A ported build.sh sources this after release-target.sh, in a target's subshell, and its build_lib calls
# oft_build_cargo_shim:
#
#     ov_target_begin <target>
#     CARGO_FUZZ_DIR=fuzz FUZZ_BIN=<bin> CARGO_DEBUG_ASSERTIONS=0 ...
#     . /usr/local/lib/oss-verify/rust/recipes.sh
#     build_lib() { oft_build_cargo_shim; oft_seal_getenv; }
#     LIB_ARCHIVE="lib/liboft.a"
#     ov_target_build <fuzz target>
#
# It reads the target's Cargo.lock at /work/targets/<target>/Cargo.lock and the crates it names at
# /work/ext/<target>/vendor (the Dockerfile lays both out: the `crates` directive of lay-out-sources). The build has
# no network: cargo builds --frozen from those crates and the standard library's, which the toolchain image holds.
#
# The builds, each with -Zbuild-std, so that the standard library is compiled with the build's flags too:
#
#     plain       --cfg fuzzing -Zub-checks=no
#     ubsan       --cfg fuzzing -Zub-checks=yes                          rustc's UB checks: they panic
#     asan        --cfg fuzzing -Zub-checks=no -Zsanitizer=address
#     asan-ubsan  --cfg fuzzing -Zub-checks=yes -Zsanitizer=address
#
# with -Cdebug-assertions=on in each when CARGO_DEBUG_ASSERTIONS=1 (as OSS-Fuzz's build fuzzes the project). The
# standard library is the sealed copy in the toolchain image (its seal-std.sh): getrandom with GRND_NONBLOCK,
# available_parallelism() 1, and, with OFT_RUST_QUIET_STDIO=1, the stdio seal that the quiet link's byte switches.
#
# From the build recipe of the oss-fuzz-theorems 2026.10 release (tools/rust/recipes_rust.sh), in its release mode:
# the same paths, crate names, flags and checks. The comments are new, and the switch to the stock standard library
# is left out. The names of the two packages that gen-shim.py makes are not the release's (gen-shim.py says why), so
# the binaries are not the release's either.

oft_rust_fail() { echo "oft-rust: $*" >&2; return 1; }

OFT_RUST_LIB=/usr/local/lib/oss-verify/rust

# oft_rust_image_names: the toolchain image's Rust tree, from its environment, and the names of the stdio seal as the
# sealed standard library spells them: _target (the target JSON), _sealed (the standard library), _vendor (its
# crates), _qcfg (the cfg that compiles the seal in) and _qsym (the byte it reads).
oft_rust_image_names() {
  _target=${OFT_RUST_TARGET:-}; _sealed=${OFT_RUST_SEALED_LIBRARY:-}; _vendor=${OFT_RUST_STD_VENDOR:-}
  [ -n "$_target" ] && [ -n "$_sealed" ] && [ -n "$_vendor" ] \
    || { oft_rust_fail "this image sets no OFT_RUST_TARGET, OFT_RUST_SEALED_LIBRARY or OFT_RUST_STD_VENDOR: it is not the Rust toolchain image"; return 1; }
  _tierdir=${_sealed%/*}
  [ "${_vendor%/*}" = "$_tierdir" ] && [ "${_target%/targets/*}" = "$_tierdir" ] \
    || { oft_rust_fail "the image's sealed std ($_sealed), std vendor ($_vendor) and target ($_target) are not in one directory"; return 1; }
  oft_rust_seal3_names "$_sealed" || return 1
}

# oft_rust_seal3_names <library>: _qcfg and _qsym as <library>'s std/src/sys/stdio/unix.rs spells them.
oft_rust_seal3_names() {
  _qf="$1/std/src/sys/stdio/unix.rs"
  _qcfg=$(sed -n 's/^#\[cfg(\([a-z]*_quiet_stdio\))\]$/\1/p' "$_qf" | sort -u)
  _qsym=$(sed -n 's/^ *static \([a-z]*_rust_quiet_stdio\): u8;$/\1/p' "$_qf" | sort -u)
  [ "$(printf '%s' "$_qcfg" | grep -c '')" = 1 ] && [ "$(printf '%s' "$_qsym" | grep -c '')" = 1 ] \
    || { oft_rust_fail "the stdio seal's cfg (${_qcfg:-none}) or byte (${_qsym:-none}) is not named exactly once in $_qf"; return 1; }
}

# oft_rust_release_tree <scratch>: copies, under <scratch>, of what the build reads from the image: the standard
# library (cargo hashes its absolute path into each crate's -C metadata), the target JSON and the empty libFuzzer
# archive. _lib, _target and _lfz then name the copies.
oft_rust_release_tree() {
  _rw=$1
  cp -a "$_lib" "$_rw/library" || { oft_rust_fail "could not copy the std tree $_lib"; return 1; }
  # The copy is the sealed library: the stdio seal at its four entry points and its helper.
  _n3=$(grep -c 'oft seal (seal-std.sh 3)' "$_rw/library/std/src/sys/stdio/unix.rs" || true)
  [ "$_n3" = 5 ] || { oft_rust_fail "the std copy holds $_n3 stdio seal marker(s), not 5"; return 1; }
  _tnr=$(basename "$_target" .json)
  mkdir -p "$_rw/targets" "$_rw/libfuzzer"
  cp "$_target" "$_rw/targets/$_tnr.json" || return 1
  cp "$_lfz" "$_rw/libfuzzer/" || return 1
  _lib=$_rw/library
  _target=$_rw/targets/$_tnr.json
  _lfz=$_rw/libfuzzer/$(basename "$_lfz")
  oft_rust_seal3_names "$_lib" || return 1
}

# oft_rust_release_rustflags <scratch>: the path maps that make rustc's embedded paths (panic locations, file!())
# independent of the image: the standard library as /rustc/library, and the target directory of the custom target.
oft_rust_release_rustflags() {
  _tn=$(basename "$_target" .json)
  printf '%s' "--remap-path-prefix=$1/library=/rustc/library"
  printf ' %s' "--remap-path-prefix=$1/target/$_tn=$1/target/riscv64"
}

# oft_rust_cargo_home <scratch>: an offline cargo home whose crates.io is one directory of crates, the standard
# library's and the target's; sets CARGO_HOME.
oft_rust_cargo_home() {
  _w=$1
  _v="$_w/vendor"; _pv="/work/ext/$T/vendor"
  [ -d "$_vendor" ] || { oft_rust_fail "no std vendor directory $_vendor in this image"; return 1; }
  [ -d "$_pv" ] || { oft_rust_fail "no ext/$T/vendor (the Dockerfile's crates directive makes it)"; return 1; }
  [ -f "$_pv/.oft-vendor-lock-sha256" ] || { oft_rust_fail "ext/$T/vendor has no .oft-vendor-lock-sha256 stamp"; return 1; }
  _want=$(sha256sum "/work/targets/$T/Cargo.lock" | awk '{print $1}')
  [ "$(cat "$_pv/.oft-vendor-lock-sha256")" = "$_want" ] \
    || { oft_rust_fail "ext/$T/vendor holds the crates of another Cargo.lock than targets/$T/Cargo.lock"; return 1; }
  mkdir -p "$_v"
  _ns=0; _np=0; _nd=0
  for _d in "$_vendor"/*/; do
    [ -d "$_d" ] || continue
    ln -s "${_d%/}" "$_v/$(basename "$_d")"; _ns=$((_ns + 1))
  done
  for _d in "$_pv"/*/; do
    [ -d "$_d" ] || continue
    _b=$(basename "$_d")
    if [ -e "$_v/$_b" ]; then
      # The same name and version in both: it must be the same crates.io package.
      _a=$(sed -n 's/.*"package":"\([0-9a-f]*\)".*/\1/p' "$_v/$_b/.cargo-checksum.json")
      _c=$(sed -n 's/.*"package":"\([0-9a-f]*\)".*/\1/p' "$_d/.cargo-checksum.json")
      [ -n "$_a" ] && [ "$_a" = "$_c" ] \
        || { oft_rust_fail "the std vendor directory and ext/$T/vendor hold different packages $_b"; return 1; }
      _nd=$((_nd + 1))
      continue
    fi
    ln -s "${_d%/}" "$_v/$_b"; _np=$((_np + 1))
  done
  [ "$_ns" -gt 0 ] || { oft_rust_fail "the std vendor directory is empty"; return 1; }
  echo "oft-rust: vendor: $_ns std crate(s), $_np project crate(s), $_nd shared"
  mkdir -p "$_w/cargo-home"
  {
    printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
    printf '[source.vendored-sources]\ndirectory = "%s"\n\n' "$_v"
    # The git sources, as cargo vendor wrote them.
    [ ! -f "$_pv/.oft-git-sources.toml" ] || cat "$_pv/.oft-git-sources.toml"
    printf '\n[net]\noffline = true\n'
  } > "$_w/cargo-home/config.toml"
  CARGO_HOME="$_w/cargo-home"; export CARGO_HOME
}

# oft_build_cargo_shim: build the target's static library into $BUILDDIR/lib/liboft.a, and the adapter object that
# the link uses in place of adapter.o (OV_ADAPTER, which link-fuzz-target reads).
oft_build_cargo_shim() {
  : "${FUZZ_BIN:?a Rust target sets FUZZ_BIN}" "${CARGO_FUZZ_DIR:?a Rust target sets CARGO_FUZZ_DIR}"
  oft_rust_image_names || return 1
  _lib=$_sealed
  [ -f "/work/targets/$T/Cargo.lock" ] || { oft_rust_fail "targets/$T/Cargo.lock is missing: the lock is the pin of the crates"; return 1; }
  # The scratch tree is the same path in each build, so every path rustc records is the same in all four. One
  # container builds each fuzz target of a project in turn, so the scratch tree of the one before goes first.
  _w=/tmp/oft-rust
  rm -rf "$_w"
  mkdir -p "$_w"
  cp -a "$SRCDIR" "$_w/src"
  : > "$_w/src/.oft-scratch-copy"
  cp -a "$OFT_RUST_LIB/oft-rust-rt" "$_w/oft-rust-rt" || return 1
  _rt_dir=$_w/oft-rust-rt
  case "${OFT_RUST_QUIET_STDIO:-0}" in
    0|1) ;;
    *) oft_rust_fail "OFT_RUST_QUIET_STDIO=$OFT_RUST_QUIET_STDIO: want 0 or 1"; return 1 ;;
  esac
  python3 "$OFT_RUST_LIB/gen-shim.py" --src "$_w/src" --fuzz-dir "$CARGO_FUZZ_DIR" --bin "$FUZZ_BIN" \
      --out "$_w/shim" --rt "$_rt_dir" --profile-env "${CARGO_PROFILE_ENV:-}" > "$BUILDDIR/shim.json" \
    || { oft_rust_fail "gen-shim.py refused or failed"; return 1; }
  cp "/work/targets/$T/Cargo.lock" "$_w/shim/Cargo.lock"
  oft_rust_cargo_home "$_w" || return 1
  _lfz=${CUSTOM_LIBFUZZER_PATH:-}
  _others=$OFT_RUST_STOCK_LIBRARY
  oft_rust_release_tree "$_w" || return 1
  _others="$_sealed $OFT_RUST_STOCK_LIBRARY"

  _rf="--cfg fuzzing"
  [ "${CARGO_DEBUG_ASSERTIONS:-0}" = 1 ] && _rf="$_rf -Cdebug-assertions=on"
  case "$FLAV" in
    plain)     _rf="$_rf -Zub-checks=no" ;;
    asan)      _rf="$_rf -Zub-checks=no -Zsanitizer=address" ;;
    ubsan)     _rf="$_rf -Zub-checks=yes" ;;
    asanubsan) _rf="$_rf -Zub-checks=yes -Zsanitizer=address" ;;
    *) oft_rust_fail "the build $FLAV has no Rust meaning"; return 1 ;;
  esac
  [ "${OFT_RUST_QUIET_STDIO:-0}" != 1 ] || _rf="$_rf --cfg $_qcfg"
  _rf="$_rf $(oft_rust_release_rustflags "$_w")"
  _feat=""
  [ -z "${CARGO_FEATURES:-}" ] || _feat="--features $CARGO_FEATURES"
  [ "${CARGO_NO_DEFAULT_FEATURES:-0}" = 1 ] && _feat="$_feat --no-default-features"
  [ "${CARGO_ALL_FEATURES:-0}" = 1 ] && _feat="$_feat --all-features"
  _jobs=""
  [ -z "${OFT_MAKE_JOBS:-}" ] || _jobs="-j $OFT_MAKE_JOBS"
  echo "oft-rust: $T [$FLAV] RUSTFLAGS='$_rf' ${_feat:+features:$_feat}"
  _log="$BUILDDIR/cargo-build.log"
  _t0=$(date +%s)
  # The environment of the build, beyond RUSTFLAGS:
  #   CARGO_BIN_NAME          cargo sets it for a [[bin]], and the shim is a [lib]; a fuzz target can read it.
  #   CRATE_CC_NO_DEFAULTS=1  cc-rs would pass a --target made from the custom target's name, which clang refuses;
  #                           without its defaults, a C dependency gets the build's $CC and $CFLAGS.
  #   CC_<target> and the others, with CC, CXX, CFLAGS and CXXFLAGS unset: the target's C compiles get the build's
  #                           compiler and flags, and a build script's compiles for the host get HOST_CC.
  #   HOST_PKG_CONFIG_LIBDIR  a host build does not find the riscv64 sysroot's libraries.
  _tt=$(basename "$_target" .json | tr '-' '_')
  # shellcheck disable=SC2086 # flag lists
  if ! env -u CC -u CXX -u CFLAGS -u CXXFLAGS RUSTFLAGS="$_rf" __CARGO_TESTS_ONLY_SRC_ROOT="$_lib" \
       CARGO_TARGET_DIR="$_w/target" CARGO_BIN_NAME="$FUZZ_BIN" \
       "CC_$_tt=$CC" "CFLAGS_$_tt=$CFLAGS" "CXX_$_tt=$CXX" "CXXFLAGS_$_tt=$CFLAGS" \
       CRATE_CC_NO_DEFAULTS=1 HOST_CC=cc HOST_CFLAGS="-O2 -fPIC" HOST_CXX=c++ HOST_CXXFLAGS="-O2 -fPIC" \
       ${_lfz:+"CUSTOM_LIBFUZZER_PATH=$_lfz"} \
       HOST_PKG_CONFIG_LIBDIR=/nonexistent/no-host-pkgconfig HOST_PKG_CONFIG_PATH= \
       cargo build --frozen --release -v $_jobs $_feat --manifest-path "$_w/shim/Cargo.toml" \
         --target "$_target" -Zbuild-std=std,panic_abort > "$_log" 2>&1; then
    tail -60 "$_log" >&2
    oft_rust_fail "cargo build failed for $T [$FLAV] (log $_log)"; return 1
  fi
  echo "oft-rust: cargo build ok in $(( $(date +%s) - _t0 )) s"
  # Which standard library rustc compiled, read from cargo's own command lines, both ways.
  _hit=$(grep -c -F -- "$_lib/std/src/lib.rs" "$_log" || true)
  _miss=0
  for _o in $_others; do
    _m=$(grep -c -F -- "$_o/std/src/lib.rs" "$_log" || true); _miss=$((_miss + _m))
  done
  [ "$_hit" -ge 1 ] && [ "$_miss" = 0 ] \
    || { oft_rust_fail "std should come from $_lib: the log names it $_hit time(s) and $_others $_miss time(s)"; return 1; }
  echo "oft-rust: std compiled from $_lib, as cargo's log shows"
  _a="$_w/target/$(basename "$_target" .json)/release/liboft.a"
  [ -f "$_a" ] || { oft_rust_fail "no static library at $_a"; return 1; }
  mkdir -p "$BUILDDIR/lib"
  cp "$_a" "$BUILDDIR/lib/liboft.a"
  _n=$(llvm-nm -u "$BUILDDIR/lib/liboft.a" 2>/dev/null | grep -c ' __asan_' || true)
  case "$FLAV" in
    asan|asanubsan) [ "$_n" -gt 0 ] || { oft_rust_fail "the $FLAV static library references no __asan_ symbol"; return 1; } ;;
    *)              [ "$_n" = 0 ]   || { oft_rust_fail "the $FLAV static library references $_n __asan_ symbol(s)"; return 1; } ;;
  esac
  echo "oft-rust: static library $(wc -c < "$BUILDDIR/lib/liboft.a") bytes, $_n undefined __asan_ reference(s)"
  # The stdio seal, read back from the library, both ways.
  _q=$(llvm-nm -u "$BUILDDIR/lib/liboft.a" 2>/dev/null | grep -c " $_qsym\$" || true)
  if [ "${OFT_RUST_QUIET_STDIO:-0}" = 1 ]; then
    [ "$_q" -gt 0 ] || { oft_rust_fail "OFT_RUST_QUIET_STDIO=1, but the static library never reads $_qsym"; return 1; }
    echo "oft-rust: the stdio seal is compiled in: $_q reference(s) to $_qsym"
    LIB_CFLAGS="${LIB_CFLAGS:-} -DOFT_RUST_QUIET_STDIO=1"
  else
    [ "$_q" = 0 ] || { oft_rust_fail "the static library references $_qsym $_q time(s) with the seal off"; return 1; }
  fi
  LIB_ARCHIVE="lib/liboft.a"
  # The adapter, compiled as the release compiles a target's plugin.c: with the driver's compiler and flags.
  # shellcheck disable=SC2086 # flag lists
  "$DRVCC" $BASE_CFLAGS -c -I/usr/local/lib/oss-verify/driver -I"$SRCDIR" ${LIB_CFLAGS:-} \
      /usr/local/lib/oss-verify/driver/adapter_rust.c -o "$BUILDDIR/plugin.o" || return 1
  OV_ADAPTER=$BUILDDIR/plugin.o; export OV_ADAPTER
  # When compile records the links (OV_RECORDS, for oss-verify check --checks): the quiet adapter, for the quiet twin.
  # With the stdio seal, its byte is 1 (plugin_rust.h), so the twin's standard library writes nothing either.
  if [ -n "${OV_RECORDS:-}" ]; then
    # shellcheck disable=SC2086 # flag lists
    "$DRVCC" $BASE_CFLAGS -DHARNESS_QUIET -c -I/usr/local/lib/oss-verify/driver -I"$SRCDIR" ${LIB_CFLAGS:-} \
        /usr/local/lib/oss-verify/driver/adapter_rust.c -o "$BUILDDIR/plugin-quiet.o" || return 1
    OV_ADAPTER_QUIET=$BUILDDIR/plugin-quiet.o; export OV_ADAPTER_QUIET
  fi
  return 0
}

# oft_rust_entry_gate <archive>: exactly one member defines LLVMFuzzerTestOneInput, and it is libfuzzer-sys's (or,
# with LTO, the shim's); exactly one defines rust_fuzzer_test_input, the fuzz_target! body, and it is the shim's.
# release-target.sh's link asks this in place of the C layout's two checks (below).
oft_rust_entry_gate() {
  _ar=$1
  [ -f "$_ar" ] || { oft_rust_fail "entry gate: no archive $_ar"; return 1; }
  for _pair in "LLVMFuzzerTestOneInput libfuzzer_sys|oft" "rust_fuzzer_test_input oft"; do
    _sym=${_pair% *}; _crates=${_pair#* }
    _defs=$(llvm-nm -A --defined-only "$_ar" 2>/dev/null | awk -v s="$_sym" '$NF == s && $(NF-1) ~ /^[TW]$/ { m=$1; sub(/:$/, "", m); n=split(m, p, ":"); print p[n] }')
    _n=$(printf '%s\n' "$_defs" | grep -c . || true)
    [ "$_n" = 1 ] || { oft_rust_fail "entry gate: $_n archive member(s) define $_sym (want exactly 1): ${_defs:-none}"; return 1; }
    _crate=${_defs%%-*}
    case "|$_crates|" in
      *"|$_crate|"*) ;;
      *) oft_rust_fail "entry gate: $_sym is defined by $_defs, not a member of ${_crates}"; return 1 ;;
    esac
    echo "oft-rust: entry gate: $_sym defined once, by $_defs"
  done
  return 0
}

# The two checks release-target.sh makes of a target's archive, in their Rust form. The C ones look for harness.o,
# which a cargo static library does not have.
oft_single_entry() { oft_rust_entry_gate "$1"; }
oft_stub_gate() {
  echo "oft-rust: stub gate: not asked of a cargo static library (the fuzz target is the project's own [[bin]])" >&2
  return 0
}
