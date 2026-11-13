#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of ocudu into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ngap_pdu_decoder_fuzzer: the release's target ocudu-ngap_pdu_decoder_fuzzer
(
ov_target_begin ocudu-ngap_pdu_decoder_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "tests/fuzz/ngap/ngap_pdu_decoder_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































































































































OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-8}"
export OFT_MAKE_JOBS
OFT_CXX_STD="-std=gnu++17"
OFT_OCUDU_FUZZER=ngap_pdu_decoder_fuzzer
OFT_OCUDU_FUZZDIR=ngap
oft_ocudu_build() {
  local cmk="$BUILDDIR/cmk" yml="$BUILDDIR/oft-yaml-cpp-declined" shp="$BUILDDIR/oft-glibc-shape.h" dir lt fl tg
  oft_copy_src
  oft_cmake_toolchain "$BUILDDIR/toolchain.cmake"
  mkdir -p "$cmk" "$yml"
  {
    echo '                                                                           '
    echo '#ifndef OFT_GLIBC_SHAPE_H'
    echo '#define OFT_GLIBC_SHAPE_H'
    echo '#include <stdio.h>'
    echo '#include <sys/time.h>'
    echo '#undef stdin'
    echo '#undef stdout'
    echo '#undef stderr'
    echo '#define stdin stdin'
    echo '#define stdout stdout'
    echo '#define stderr stderr'
    echo 'typedef int __rusage_who_t;'
    echo 'typedef suseconds_t __suseconds_t;'
    echo '#endif'
  } > "$shp"
  echo "add_compile_options(\"SHELL:-include $shp\")" > "$BUILDDIR/oft-ocudu-project-include.cmake"
  {
    echo '                                                                        '
    echo 'set(yaml-cpp_VERSION "0.0.0-oft-declined")'
    echo 'if(NOT TARGET yaml-cpp::yaml-cpp)'
    echo '  add_library(yaml-cpp::yaml-cpp INTERFACE IMPORTED)'
    echo 'endif()'
  } > "$yml/yaml-cpp-config.cmake"
  ( cd "$cmk" \
    && cmake --fresh "$BUILDDIR/src" \
         -DCMAKE_TOOLCHAIN_FILE="$BUILDDIR/toolchain.cmake" \
         -DCMAKE_PROJECT_ocudu_INCLUDE="$BUILDDIR/oft-ocudu-project-include.cmake" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_C_FLAGS_RELEASE=-O3 -DCMAKE_CXX_FLAGS_RELEASE=-O3 \
         -DASSERT_LEVEL=PARANOID \
         -DCMAKE_INSTALL_PREFIX="${OFT_PREFIX:?build.sh sets the flavour-independent install prefix; see oft_link_prefix}" \
         -DBUILD_SHARED_LIBS=OFF \
         -DCMAKE_C_COMPILER_LAUNCHER= -DCMAKE_CXX_COMPILER_LAUNCHER= \
         -DMARCH=rv64g \
         -Dyaml-cpp_DIR="$yml" \
         -DDISABLE_MBEDTLS=ON -DDISABLE_SCTP=ON \
         -DENABLE_FUZZTESTS=ON \
         -DBUILD_TESTING=OFF \
         -DENABLE_WERROR=OFF \
         -DENABLE_UHD=OFF \
         -DENABLE_ZEROMQ=OFF \
         -DENABLE_FFTW=OFF \
         -DENABLE_MKL=OFF \
         -DENABLE_FFTZ=OFF \
         -DENABLE_ARMPL=OFF \
         -DENABLE_DPDK=OFF \
         -DENABLE_LIBNUMA=OFF \
         -DENABLE_BACKWARD=OFF ) || return 1
  dir="$cmk/tests/fuzz/$OFT_OCUDU_FUZZDIR/CMakeFiles/$OFT_OCUDU_FUZZER.dir"
  lt="$dir/link.txt"; fl="$dir/flags.make"
  [ -f "$lt" ] && [ -f "$fl" ] || { echo "oft: ocudu: CMake generated no $lt / $fl" >&2; return 1; }
  tg=$(tr ' ' '\n' < "$lt" | sed "s|^$cmk/||" | grep '\.a$' | grep -v '^/' \
         | sed 's|.*/||; s|^lib||; s|\.a$||' | sort -u | tr '\n' ' ')
  [ -n "$tg" ] || { echo "oft: ocudu: no in-tree archive on $lt" >&2; return 1; }
  echo "oft: ocudu: $OFT_OCUDU_FUZZER archive closure (from its link.txt): $tg"

  ( cd "$cmk" && make -j"$(oft_jobs)" $tg ) || return 1
  oft_ocudu_merge_closure "$lt" || return 1
  OFT_HARNESS_CFLAGS="-include $shp $(sed -n 's/^CXX_DEFINES = //p' "$fl") $(sed -n 's/^CXX_INCLUDES = //p' "$fl")"
  OFT_HARNESS_CFLAGS="$OFT_HARNESS_CFLAGS $(sed -n 's/^CXX_INCLUDES = //p' "$fl" | sed 's/^-I/-iquote /; s/ -I/ -iquote /g')"
  echo "oft: ocudu: harness flags from $OFT_OCUDU_FUZZER's flags.make: $OFT_HARNESS_CFLAGS"
}
oft_ocudu_merge_closure() {
  local lt=$1 d out="$BUILDDIR/lib/liboft.a" mri="$BUILDDIR/merge.mri" list="$BUILDDIR/merge-list.txt" a n=0 other want got
  d=$(dirname "$lt"); d=$(dirname "$(dirname "$d")")
  mkdir -p "$BUILDDIR/lib"
  : > "$list"
  for a in $(tr ' ' '\n' < "$lt" | grep '\.a$' | grep -v '^/' | awk '!seen[$0]++'); do
    [ -f "$d/$a" ] || { echo "oft: ocudu: closure archive $a (from $lt) was not built" >&2; return 1; }
    realpath "$d/$a" >> "$list" || return 1
  done
  echo "create $out" > "$mri"
  while IFS= read -r a; do
    echo "addlib $a" >> "$mri"
    n=$((n + 1))
  done < "$list"
  [ "$n" -ge 1 ] || { echo "oft: ocudu: empty closure on $lt" >&2; return 1; }
  printf 'save\nend\n' >> "$mri"
  "$CHOST-ar" -M < "$mri" || return 1
  [ -f "$out" ] || { echo "oft: ocudu: merging $n archive(s) produced no $out" >&2; return 1; }


  want=0
  while IFS= read -r a; do want=$((want + $("$CHOST-ar" t "$a" | wc -l))); done < "$list"
  got=$("$CHOST-ar" t "$out" | wc -l)
  [ "$got" -eq "$want" ] || { echo "oft: ocudu: $out has $got members, the $n closure archives $want" >&2; return 1; }
  echo "oft: ocudu: merged exactly the $n closure archive(s) ($got members) into lib/liboft.a, link.txt order"
  other=$(find "$BUILDDIR/cmk" -name '*.a' -type f | grep -vxF -f "$list" | tr '\n' ' ')
  [ -z "$other" ] || echo "oft: ocudu: NOTE -- not merged (outside this closure; left in cmk/ by an earlier configuration): $other"
  LIB_ARCHIVE="lib/liboft.a"
  oft_add_sysroot_deps
}
oft_ocudu_fmt_abi_check() {
  local fa want got n
  fa=$(find "$BUILDDIR/cmk/external/fmt" -name 'libfmt*.a' -type f | head -1)
  [ -n "$fa" ] || { echo "oft: ocudu: no libfmt archive under cmk/external/fmt" >&2; return 1; }
  want=$("$CHOST-nm" -C "$fa" 2>/dev/null | grep -o 'fmt::v[0-9][0-9]*::' | sort -u | tr '\n' ' ')
  got=$("$CHOST-nm" -C "$BUILDDIR/harness.o" | grep -o 'fmt::v[0-9][0-9]*::' | sort -u | tr '\n' ' ')
  echo "oft: ocudu: fmt inline namespace -- $(basename "$fa"): ${want:-none}; harness.o: ${got:-none}"
  [ -n "$want" ] || { echo "oft: ocudu: $fa shows no fmt::v<N>:: symbol -- the check examined nothing" >&2; return 1; }
  for n in $got; do
    case " $want " in *" $n "*) ;; *)
      echo "oft: ocudu: harness.o uses $n, which the library's fmt does not define -- refusing" >&2; return 1 ;;
    esac
  done
}
oft_seal_ocudu_pi_probe() {
  local obj="$BUILDDIR/seal_pi_probe.o" cfg=/opt/asan-static/asan-musl-sealed.cfg wl

  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/ocudu-ngap_pdu_decoder_fuzzer/seal_pi_probe.c -o "$obj" || return 1
  "$CHOST-nm" "$obj" | grep -q ' T __wrap_pthread_mutexattr_setprotocol$' || {
    echo "oft: seal_pi_probe.o defines no __wrap_pthread_mutexattr_setprotocol" >&2; return 1; }
  "$CHOST-nm" "$obj" | grep -q ' U __real_pthread_mutexattr_setprotocol$' || {
    echo "oft: seal_pi_probe.o does not forward to __real_pthread_mutexattr_setprotocol" >&2; return 1; }
  case "${CFLAGS:-}" in
    *-fsanitize=address*)



      wl=$(sed -n 's/^-Wl,@//p' "$cfg")
      [ -n "$wl" ] && [ -f "$wl" ] || {
        echo "oft: no -Wl,@<wrap list> in $cfg -- cannot rule out a second wrapper" >&2; return 1; }
      if grep -q -x -e '--wrap=pthread_mutexattr_setprotocol' "$wl"; then
        echo "oft: the sealed ASan runtime now wraps pthread_mutexattr_setprotocol ($wl) -- re-derive this seal" >&2
        return 1
      fi
      ;;
  esac
  LIB_EXTRA="${LIB_EXTRA:-} $obj -Wl,--wrap=pthread_mutexattr_setprotocol"
  echo "oft: PI probe sealed on this link: $obj -Wl,--wrap=pthread_mutexattr_setprotocol"
}
build_lib() {
  oft_require_target_cxx
  oft_ocudu_build || return 1
  oft_build_harness "tests/fuzz/ngap/ngap_pdu_decoder_fuzzer.cpp"
  oft_ocudu_fmt_abi_check || return 1
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid

  oft_seal_ocudu_pi_probe || return 1







  "${DRVCC:?build.sh must export DRVCC}" ${BASE_CFLAGS} -c /work/targets/ocudu-ngap_pdu_decoder_fuzzer/cxa_thread_atexit_shim.c -o "$BUILDDIR/cxa_thread_atexit_shim.o" || return 1
  LIB_EXTRA="${LIB_EXTRA:-} $BUILDDIR/cxa_thread_atexit_shim.o"
}
ov_target_build ngap_pdu_decoder_fuzzer
)
