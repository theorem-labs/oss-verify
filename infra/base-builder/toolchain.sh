# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The compilers and flags of one build, sourced by `compile` with FLAV set to plain, asan, ubsan or asanubsan.
#
# Taken from the build body of the oss-fuzz-theorems 2026.10 release recipe (tools/build-body.sh), whose
# binaries this reproduces byte for byte. Kept as it is there: the flags, the compiler shims and what they write,
# the sealed AddressSanitizer configuration and which compiler each build uses. Left out: the release's neutral
# source layout under /src (here every build already compiles at its final path), its link record, and the
# configurations no build here uses. The comments are new.
#
# Defines and exports CHOST, SHIM, PATH, BASE_CFLAGS, SAN, CC, CXX, DRVCC, DRVCXX and CFLAGS.

: "${SOURCE_DATE_EPOCH:=1756684800}"
export SOURCE_DATE_EPOCH

CHOST=riscv64-linux-musl

# Every build compiles with these. The -fno-builtin-* flags keep each allocation an ordinary call in all four builds,
# so that the optimiser cannot remove or merge an allocation in one build and keep it in another.
OFT_NO_BUILTIN_ALLOC="-fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-reallocarray -fno-builtin-free -fno-builtin-aligned_alloc -fno-builtin-posix_memalign -fno-builtin-memalign -fno-builtin-valloc -fno-builtin-strdup -fno-builtin-strndup"
BASE_CFLAGS="-march=rv64g -mabi=lp64d -Os -g -ffunction-sections -fdata-sections -fno-stack-protector -fno-plt -Wdate-time $OFT_NO_BUILTIN_ALLOC"

SHIM=/tmp/shim; mkdir -p "$SHIM"; PATH=$SHIM:$PATH; export PATH

# riscv64-linux-musl-ar and friends are the LLVM tools, which understand riscv64 objects on any host.
for tool in ar nm ranlib strip objdump objcopy readelf size; do
  printf '#!/bin/sh\nexec llvm-%s "$@"\n' "$tool" > "$SHIM/$CHOST-$tool"
  chmod +x "$SHIM/$CHOST-$tool"
done

# Every compiler shim starts by pinning the ISA: whatever -march a build system asks for becomes rv64g.
OFT_ARCH_PIN='n=$#; i=0
while [ "$i" -lt "$n" ]; do
  a=$1; shift
  case "$a" in -march=rv*) a=-march=rv64g ;; esac
  set -- "$@" "$a"
  i=$((i+1))
done'

# Headers for features the modelled machine does not have fail at compile time rather than at run time.
mkdir -p "$SHIM/include/asm"
cat > "$SHIM/include/riscv_vector.h" <<'POISON'
/* The builder pins -march=rv64g, which has no vector extension. */
#if !defined(__riscv_vector)
#error "riscv_vector.h: this toolchain pins -march=rv64g; the vector extension is unavailable"
#endif
#include_next <riscv_vector.h>
POISON
cat > "$SHIM/include/asm/hwprobe.h" <<'POISON'
/* riscv_hwprobe is not part of the modelled platform. */
#error "asm/hwprobe.h: riscv_hwprobe is not part of the modeled platform; use getauxval(AT_HWCAP)"
POISON

# write_cc_shim <path> <compiler and its config> [<extra link inputs> [<words after the arguments>]]: a compiler that
# pins the ISA, adds the poisoned headers, and on a link step (no -c, -E, -S, ...) starts from -Wl,--no-gc-sections,
# which the final link of a fuzz target overrides with -Wl,--gc-sections.
write_cc_shim() {
  { printf '#!/bin/sh\n%s\n' "$OFT_ARCH_PIN"
    printf 'nogc="-Wl,--no-gc-sections%s"; for a in "$@"; do case "$a" in -c|-E|-S|-fsyntax-only|-M|-MM|--version|-dumpmachine|-print-*) nogc=;; esac; done\n' "${3:-}"
    printf 'exec %s $nogc -isystem %s/include "$@"%s\n' "$2" "$SHIM" "${4:-}"
  } > "$1"
  chmod +x "$1"
}
write_cc_shim "$SHIM/$CHOST-clang-plain" 'clang --config=/opt/asan-static/musl.cfg'
write_cc_shim "$SHIM/$CHOST-clang++-plain" 'clang++ --config=/opt/asan-static/musl.cfg -stdlib=libc++'

# The sealed AddressSanitizer configuration, less its interception of iconv.
SEALED_CFG=/opt/asan-static/asan-musl-sealed.cfg
WRAP_SRC=$(sed -n 's/^-Wl,@//p' "$SEALED_CFG")
if [ -z "$WRAP_SRC" ] || [ ! -f "$WRAP_SRC" ]; then
  echo "toolchain.sh: no -Wl,@<wrap list> in $SEALED_CFG (got '${WRAP_SRC:-}')" >&2
  exit 1
fi
if ! grep -qx -- '--wrap=iconv' "$WRAP_SRC"; then
  echo "toolchain.sh: no '--wrap=iconv' in $WRAP_SRC: this is not the toolchain this file was written for" >&2
  exit 1
fi
grep -vx -- '--wrap=iconv' "$WRAP_SRC" > /tmp/asan-noiconv.wrap
sed 's|^-Wl,@.*|-Wl,@/tmp/asan-noiconv.wrap|' "$SEALED_CFG" > /tmp/asan-musl-sealed-noiconv.cfg

# With garbage collection off, the runtime's interception records would be kept; this discards them.
printf 'SECTIONS { /DISCARD/ : { *(.data.rel.ro.__interception_extract_*) } } INSERT AFTER .text;\n' \
  > "$SHIM/nogc-discard.ld"
write_cc_shim "$SHIM/$CHOST-clang-sealed" \
  'clang --config=/tmp/asan-musl-sealed-noiconv.cfg' " $SHIM/nogc-discard.ld"
write_cc_shim "$SHIM/$CHOST-clang++-sealed" \
  'clang++ --config=/tmp/asan-musl-sealed-noiconv.cfg -stdlib=libc++' " $SHIM/nogc-discard.ld"

# The driver is compiled without a sanitizer in every build. The library and the harness get the build's own.
DRVCC=$SHIM/$CHOST-clang-plain
DRVCXX=$SHIM/$CHOST-clang++-plain
# The UBSan checks: the release's fixed flags, unless tools/check gives a project's checks in OV_UBSAN_CHECKS (and
# those that trap mode leaves out in OV_UBSAN_EXCLUDE; compile leaves OV_UBSAN_C_EXCLUDE out of the C compiles of a
# c++ project), which it does only on a toolchain whose infra/toolchains.tsv
# row says so (docs/project-yaml.md#ubsan_checks).
#
# Two names in the checks are not made by trap flags, and only the ubsan build makes them; each needs a file of the
# toolchain image, and the build fails without it. vptr: clang cannot make a vptr check a trap, so the ubsan build
# compiles with -fsanitize=vptr -fno-sanitize-link-runtime and links the image's trap-only handler, which traps on a
# mismatch as the other checks do. A compile with -fno-rtti (the last of -frtti and -fno-rtti wins) gets
# -fno-sanitize=vptr after its arguments, since clang refuses vptr without RTTI. The asan-ubsan build leaves vptr out:
# -fno-sanitize-link-runtime would drop the AddressSanitizer runtime. libcxx-hardening: the ubsan build compiles and
# links C++ against the image's hardened libc++ (musl-hardened.cfg), whose failed checks trap too.
VPTR_TRAP=/opt/ubsan-vptr-trap/libclang_rt.ubsan_vptr_trap.a
HARDENED_CFG=/opt/asan-static/musl-hardened.cfg
UBSAN_LINK=""
UBSAN_TAIL=""
UBSAN_CXX_CFG=/opt/asan-static/musl.cfg
ub_without() { printf '%s' "$1" | tr ',' '\n' | { grep -vx -- "$2" || true; } | paste -sd, -; }
ub_need() {
  if [ ! -f "$1" ]; then
    echo "toolchain.sh: the checks name $2, and this toolchain image has no $1" >&2
    exit 1
  fi
}
if [ -n "${OV_UBSAN_CHECKS:-}" ]; then
  ub_checks=$OV_UBSAN_CHECKS
  ub_exclude=${OV_UBSAN_EXCLUDE:-}
  ub_vptr=""
  case ",$ub_checks," in
    *,libcxx-hardening,*)
      ub_checks=$(ub_without "$ub_checks" libcxx-hardening)
      if [ "$FLAV" = ubsan ]; then
        ub_need "$HARDENED_CFG" libcxx-hardening
        UBSAN_CXX_CFG=$HARDENED_CFG
      fi ;;
  esac
  case ",$ub_checks," in
    *,vptr,*)
      ub_checks=$(ub_without "$ub_checks" vptr)
      if [ "$FLAV" = ubsan ]; then
        ub_need "$VPTR_TRAP" vptr
        ub_vptr=" -fsanitize=vptr -fno-sanitize-link-runtime"
        UBSAN_LINK=" $VPTR_TRAP"
        UBSAN_TAIL=' $(r=; for a in "$@"; do case "$a" in -fno-rtti) r=-fno-sanitize=vptr ;; -frtti) r= ;; esac; done; echo $r)'
      else
        ub_exclude=${ub_exclude:+$ub_exclude,}vptr
      fi ;;
  esac
  UBSAN="${ub_checks:+-fsanitize=$ub_checks }${ub_exclude:+-fno-sanitize=$ub_exclude }"
  UBSAN="$UBSAN${ub_checks:+-fsanitize-trap=$ub_checks }-fno-sanitize-recover=all$ub_vptr"
else
  UBSAN="-fsanitize=undefined -fno-sanitize-recover=all -fsanitize-trap=all -fno-sanitize=function"
fi
case "$FLAV" in
  asan)
    CC=$SHIM/$CHOST-clang-sealed
    CXX=$SHIM/$CHOST-clang++-sealed
    SAN="-fsanitize=address" ;;
  asanubsan)
    CC=$SHIM/$CHOST-clang-sealed
    CXX=$SHIM/$CHOST-clang++-sealed
    SAN="-fsanitize=address $UBSAN" ;;
  ubsan)
    CC=$DRVCC
    CXX=$DRVCXX
    if [ -n "$UBSAN_LINK" ] || [ "$UBSAN_CXX_CFG" != /opt/asan-static/musl.cfg ]; then
      write_cc_shim "$SHIM/$CHOST-clang-ubsan" 'clang --config=/opt/asan-static/musl.cfg' "$UBSAN_LINK" "$UBSAN_TAIL"
      write_cc_shim "$SHIM/$CHOST-clang++-ubsan" "clang++ --config=$UBSAN_CXX_CFG -stdlib=libc++" "$UBSAN_LINK" \
        "$UBSAN_TAIL"
      CC=$SHIM/$CHOST-clang-ubsan
      CXX=$SHIM/$CHOST-clang++-ubsan
    fi
    SAN="$UBSAN" ;;
  plain)
    CC=$DRVCC
    CXX=$DRVCXX
    SAN="" ;;
  *)
    echo "toolchain.sh: FLAV must be plain, asan, ubsan or asanubsan (got '${FLAV:-}')" >&2
    exit 1 ;;
esac
CFLAGS="$BASE_CFLAGS $SAN"
export CHOST CC CXX CFLAGS DRVCC DRVCXX BASE_CFLAGS SAN

# What the release recipe does to CFLAGS before it builds a library or a harness. -fno-plt does nothing in a static
# riscv64 link, so clang reports it as unused, which a project that compiles with -Werror turns into an error: it
# is dropped, and the report silenced. FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION is what OSS-Fuzz defines too.
suppress_unused_arg_werror() {
  local f kept=""
  for f in $CFLAGS; do
    [ "$f" = "-fno-plt" ] || kept="$kept $f"
  done
  CFLAGS="${kept# }"
  case " $CFLAGS " in
    *" -Wno-unused-command-line-argument "*) ;;
    *) CFLAGS="$CFLAGS -Wno-unused-command-line-argument" ;;
  esac
  export CFLAGS
}
define_fuzzing_build_mode() {
  case " $CFLAGS " in
    *" -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "*) return 0 ;;
  esac
  CFLAGS="$CFLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export CFLAGS
}
