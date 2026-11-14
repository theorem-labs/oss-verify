#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of phosphor-networkd into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# config_parser_fuzzer: the release's target phosphor-networkd-config_parser_fuzzer
(
ov_target_begin phosphor-networkd-config_parser_fuzzer phosphor-networkd-dep-stdplus phosphor-networkd-dep-sdbusplus phosphor-networkd-dep-pdi phosphor-networkd-dep-phosphor-logging
ov_target_dependency phosphor-networkd-dep-stdplus <<'OV_PIN_END'
build_lib() {
  oft_require_target_cxx
  local stage="$BUILDDIR/stage"




  mkdir -p "$stage" "$BUILDDIR/include" "$BUILDDIR/obj" "$BUILDDIR/lib"
  cp -R "$SRCDIR/include" "$SRCDIR/include-fd" "$SRCDIR/src" "$stage/"
  ( cd "$stage" && patch -p1 --dry-run < /work/targets/phosphor-networkd-dep-stdplus/stdplus.patch >/dev/null \
      && patch -p1 < /work/targets/phosphor-networkd-dep-stdplus/stdplus.patch ) || {
    echo "oft: dep-stdplus: OSS-Fuzz's stdplus.patch did not apply to the staged copy" >&2; return 1; }
  grep -q 'struct std::char_traits<unsigned char>' "$stage/include/stdplus/raw.hpp" || {
    echo "oft: dep-stdplus: stdplus.patch reported success but raw.hpp is unchanged" >&2; return 1; }
  cp -R "$stage/include/stdplus" "$BUILDDIR/include/"
  cp -R "$stage/include-fd/stdplus/." "$BUILDDIR/include/stdplus/"



  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  local f o n=0 objs=""
  for f in cancel debug/lifetime exception flags function_view handle/copyable \
           handle/managed hash hash/array hash/tuple net/addr/ether net/addr/ip \
           net/addr/sock net/addr/subnet net/addr/hostname numeric/endian \
           numeric/str pinned print raw signal str/buf str/cat str/cexpr \
           str/conv str/maps util/cexec variant zstring zstring_view \
           fd/atomic fd/create fd/dupable fd/fmt fd/impl fd/line fd/managed \
           fd/mmap fd/ops; do
    o="$BUILDDIR/obj/stdplus_$(echo "$f" | tr '/' '_').o"

    "$(oft_cxx)" $(oft_cxxflags) -std=c++23 -I"$BUILDDIR/include" \
      -c "$stage/src/$f.cpp" -o "$o" || {
      echo "oft: dep-stdplus: src/$f.cpp failed to compile" >&2; return 1; }
    objs="$objs $o"
    n=$((n + 1))
  done
  [ "$n" = 39 ] || { echo "oft: dep-stdplus: expected 39 objects, compiled $n" >&2; return 1; }
  { echo "create $BUILDDIR/lib/libstdplus.a"
    for o in $objs; do echo "addmod $o"; done
    echo save; echo end; } > "$BUILDDIR/stdplus.mri"
  "$CHOST-ar" -M < "$BUILDDIR/stdplus.mri" || return 1
  n=$("$CHOST-ar" t "$BUILDDIR/lib/libstdplus.a" | wc -l)
  [ "$n" = 39 ] || { echo "oft: dep-stdplus: lib/libstdplus.a has $n members, expected 39" >&2; return 1; }
  echo "oft: dep-stdplus: $n TUs in lib/libstdplus.a"
}
OV_PIN_END
ov_target_dependency phosphor-networkd-dep-sdbusplus <<'OV_PIN_END'
build_lib() {
  oft_require_target_cxx
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  mkdir -p "$BUILDDIR/include" "$BUILDDIR/lib" "$BUILDDIR/obj"
  cp -R "$SRCDIR/include/sdbusplus" "$BUILDDIR/include/"


  grep -q '#include <unistd.h>' "$BUILDDIR/include/sdbusplus/event.hpp" || \
    sed -i '1s/^/#include <unistd.h>\n/' "$BUILDDIR/include/sdbusplus/event.hpp"
  head -1 "$BUILDDIR/include/sdbusplus/event.hpp" | grep -q '^#include <unistd.h>$' || {
    echo "oft: dep-sdbusplus: the event.hpp unistd.h edit did not take" >&2; return 1; }
  local f o n=0 objs=""
  for f in bus.cpp bus/match.cpp event.cpp exception.cpp message/native_types.cpp \
           sdbus.cpp server/interface.cpp server/transaction.cpp; do
    o="$BUILDDIR/obj/sdbusplus_$(echo "$f" | tr '/' '_' | sed 's/\.cpp$/.o/')"

    "$(oft_cxx)" $(oft_cxxflags) -std=c++23 -Wno-c++26-extensions \
      -I"$BUILDDIR/include" -c "$SRCDIR/src/$f" -o "$o" || {
      echo "oft: dep-sdbusplus: $f failed to compile" >&2; return 1; }
    objs="$objs $o"
    n=$((n + 1))
  done
  [ "$n" = 8 ] || { echo "oft: dep-sdbusplus: expected 8 objects, compiled $n" >&2; return 1; }
  { echo "create $BUILDDIR/lib/libsdbusplus.a"
    for o in $objs; do echo "addmod $o"; done
    echo save; echo end; } > "$BUILDDIR/sdbusplus.mri"
  "$CHOST-ar" -M < "$BUILDDIR/sdbusplus.mri" || return 1
  n=$("$CHOST-ar" t "$BUILDDIR/lib/libsdbusplus.a" | wc -l)
  [ "$n" = 8 ] || { echo "oft: dep-sdbusplus: lib/libsdbusplus.a has $n members, expected 8" >&2; return 1; }
  echo "oft: dep-sdbusplus: $n TUs in lib/libsdbusplus.a"
}
OV_PIN_END
ov_target_dependency phosphor-networkd-dep-pdi <<'OV_PIN_END'
build_lib() {
  command -v sdbus++ >/dev/null 2>&1 || {
    echo "oft: dep-pdi: sdbus++ is not on this image's PATH (use the builder image)" >&2; return 1; }
  mkdir -p "$BUILDDIR/yaml" "$BUILDDIR/gen"
  cp -R "$SRCDIR/yaml/." "$BUILDDIR/yaml/"
  local y="$BUILDDIR/yaml" g d


  d="$BUILDDIR/gen/xyz/openbmc_project/Common"; mkdir -p "$d"
  [ -e "$y/xyz/openbmc_project/Common.errors.yaml" ] && [ -e "$y/xyz/openbmc_project/Common.events.yaml" ] || {
    echo "oft: dep-pdi: Common.{errors,events}.yaml missing at this commit" >&2; return 1; }
  sdbus++ -r "$y" error exception-header xyz.openbmc_project.Common > "$d/error.hpp" || return 1
  sdbus++ -r "$y" error exception-cpp    xyz.openbmc_project.Common > "$d/error.cpp" || return 1
  sdbus++ -r "$y" event exception-header xyz.openbmc_project.Common > "$d/event.hpp" || return 1
  sdbus++ -r "$y" event exception-cpp    xyz.openbmc_project.Common > "$d/event.cpp" || return 1

  d="$BUILDDIR/gen/xyz/openbmc_project/Logging/Entry"; mkdir -p "$d"
  [ -e "$y/xyz/openbmc_project/Logging/Entry.interface.yaml" ] || {
    echo "oft: dep-pdi: Logging/Entry.interface.yaml missing at this commit" >&2; return 1; }
  sdbus++ -r "$y" interface common-header  xyz.openbmc_project.Logging.Entry > "$d/common.hpp" || return 1
  sdbus++ -r "$y" interface server-header  xyz.openbmc_project.Logging.Entry > "$d/server.hpp" || return 1
  sdbus++ -r "$y" interface server-cpp     xyz.openbmc_project.Logging.Entry > "$d/server.cpp" || return 1
  sdbus++ -r "$y" interface client-header  xyz.openbmc_project.Logging.Entry > "$d/client.hpp" || return 1
  sdbus++ -r "$y" interface aserver-header xyz.openbmc_project.Logging.Entry > "$d/aserver.hpp" || return 1

  for g in Common/error.hpp Common/error.cpp Logging/Entry/server.hpp Logging/Entry/common.hpp; do
    [ -s "$BUILDDIR/gen/xyz/openbmc_project/$g" ] || {
      echo "oft: dep-pdi: sdbus++ left gen/xyz/openbmc_project/$g empty" >&2; return 1; }
  done
  grep -q 'InternalFailure' "$BUILDDIR/gen/xyz/openbmc_project/Common/error.hpp" || {
    echo "oft: dep-pdi: generated Common/error.hpp declares no InternalFailure" >&2; return 1; }
  echo "oft: dep-pdi: sdbus++ $(command -v sdbus++) generated Common + Logging/Entry"
}
OV_PIN_END
ov_target_dependency phosphor-networkd-dep-phosphor-logging <<'OV_PIN_END'
build_lib() {
  mkdir -p "$BUILDDIR/include" "$BUILDDIR/srcs" "$BUILDDIR/tools"
  cp -R "$SRCDIR/lib/include/phosphor-logging" "$BUILDDIR/include/"
  cp "$SRCDIR/lib/lg2_logger.cpp" "$SRCDIR/lib/sdjournal.cpp" "$BUILDDIR/srcs/"
  cp -R "$SRCDIR/tools/." "$BUILDDIR/tools/"
  [ -f "$BUILDDIR/tools/elog-gen.py" ] && \
    [ -f "$BUILDDIR/tools/phosphor-logging/templates/elog-gen-template.hpp.mako" ] || {
    echo "oft: dep-phosphor-logging: elog-gen.py or its template missing at this commit" >&2; return 1; }
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "config_parser_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































































DEPENDS="phosphor-networkd-dep-stdplus phosphor-networkd-dep-sdbusplus phosphor-networkd-dep-pdi phosphor-networkd-dep-phosphor-logging"
build_lib() {
  oft_require_target_cxx
  oft_copy_src
  local stdp="$LIBROOT/phosphor-networkd-dep-stdplus" sdb="$LIBROOT/phosphor-networkd-dep-sdbusplus"
  local pdi="$LIBROOT/phosphor-networkd-dep-pdi" plog="$LIBROOT/phosphor-networkd-dep-phosphor-logging"
  local f
  for f in "$stdp/lib/libstdplus.a" "$stdp/include/stdplus" "$sdb/lib/libsdbusplus.a" \
           "$sdb/include/sdbusplus" "$pdi/yaml" "$pdi/gen/xyz/openbmc_project/Common/error.cpp" \
           "$plog/include/phosphor-logging" "$plog/srcs/lg2_logger.cpp" "$plog/srcs/sdjournal.cpp" \
           "$plog/tools/elog-gen.py"; do
    [ -e "$f" ] || { echo "oft: phosphor-networkd: DEPENDS left no $f" >&2; return 1; }
  done
  local inc="$BUILDDIR/include" nw="$BUILDDIR/nwconf" obj="$BUILDDIR/nwobj"
  mkdir -p "$inc" "$nw" "$obj" "$BUILDDIR/lib"
  cp -R "$stdp/include/." "$sdb/include/." "$plog/include/." "$pdi/gen/." "$inc/"
  python3 "$plog/tools/elog-gen.py" -t '' \
    -m "$plog/tools/phosphor-logging/templates/elog-gen-template.hpp.mako" \
    -y "$pdi/yaml" -u "$plog/tools/" -o "$inc/phosphor-logging/elog-errors.hpp" || {
    echo "oft: phosphor-networkd: elog-gen.py failed" >&2; return 1; }
  grep -q 'struct InternalFailure' "$inc/phosphor-logging/elog-errors.hpp" || {
    echo "oft: phosphor-networkd: generated elog-errors.hpp has no InternalFailure" >&2; return 1; }
  cat > "$nw/config.h" <<'EOH'
  
                                                                             
                                                                           
               
   

#pragma once

#define DEFAULT_BUSNAME "xyz.openbmc_project.Network"

#define ENABLE_IPV6_ACCEPT_RA 1

#define ENABLE_IPV6_ACCEPT_RA_STR yes

#define FORCE_SYNC_MAC_FROM_INVENTORY 1

#define LINK_LOCAL_AUTOCONFIGURATION 1

#define LINK_LOCAL_AUTOCONFIGURATION_STR yes

#define PERSIST_MAC 1

#define SYNC_MAC_FROM_INVENTORY 1

EOH
  local cxx defs objs="" o
  cxx=$(oft_cxx) || return 1
  defs="-DBOOST_ASIO_DISABLE_THREADS -DBOOST_ALL_NO_LIB -DBOOST_SYSTEM_NO_DEPRECATED"
  defs="$defs -DBOOST_ERROR_CODE_HEADER_ONLY -DBOOST_COROUTINES_NO_DEPRECATION_WARNING"
  for f in config_parser util types netlink rtnetlink; do
    o="$obj/networkd_$f.o"

    "$cxx" $(oft_cxxflags) -std=c++23 $defs -I"$BUILDDIR/src/src" -I"$nw" -I"$inc" \
      -c "$BUILDDIR/src/src/$f.cpp" -o "$o" || {
      echo "oft: phosphor-networkd: src/$f.cpp failed to compile" >&2; return 1; }
    objs="$objs $o"
  done
  for f in lg2_logger sdjournal; do
    o="$obj/phosphor_logging_$f.o"

    "$cxx" $(oft_cxxflags) -std=c++23 -DPLDM_HAS_POLL=1 $defs -I"$inc" \
      -c "$plog/srcs/$f.cpp" -o "$o" || {
      echo "oft: phosphor-networkd: phosphor-logging lib/$f.cpp failed to compile" >&2; return 1; }
    objs="$objs $o"
  done
  o="$obj/pdi_xyz_openbmc_project_Common_error.o"

  "$cxx" $(oft_cxxflags) -std=c++23 $defs -I"$inc" \
    -c "$inc/xyz/openbmc_project/Common/error.cpp" -o "$o" || {
    echo "oft: phosphor-networkd: PDI Common/error.cpp failed to compile" >&2; return 1; }
  objs="$objs $o"

  { echo "create $BUILDDIR/lib/liboft.a"
    for o in $objs; do echo "addmod $o"; done
    echo "addlib $stdp/lib/libstdplus.a"
    echo "addlib $sdb/lib/libsdbusplus.a"
    echo save; echo end; } > "$BUILDDIR/networkd-merge.mri"
  "$CHOST-ar" -M < "$BUILDDIR/networkd-merge.mri" || return 1
  f=$("$CHOST-ar" t "$BUILDDIR/lib/liboft.a" | wc -l)
  [ "$f" = 55 ] || { echo "oft: phosphor-networkd: lib/liboft.a has $f members, expected 55 (8 + 39 stdplus + 8 sdbusplus)" >&2; return 1; }
  LIB_ARCHIVE="lib/liboft.a"
  OFT_CXX_STD="-std=c++23"
  OFT_HARNESS_CFLAGS="$defs -I$BUILDDIR/src/src -I$nw"
  oft_build_harness "config_parser_fuzzer.cpp"
  oft_add_sysroot_deps
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build config_parser_fuzzer
)

# util_fuzzer: the release's target phosphor-networkd-util_fuzzer
(
ov_target_begin phosphor-networkd-util_fuzzer phosphor-networkd-dep-stdplus phosphor-networkd-dep-sdbusplus phosphor-networkd-dep-pdi phosphor-networkd-dep-phosphor-logging
ov_target_dependency phosphor-networkd-dep-stdplus <<'OV_PIN_END'
build_lib() {
  oft_require_target_cxx
  local stage="$BUILDDIR/stage"




  mkdir -p "$stage" "$BUILDDIR/include" "$BUILDDIR/obj" "$BUILDDIR/lib"
  cp -R "$SRCDIR/include" "$SRCDIR/include-fd" "$SRCDIR/src" "$stage/"
  ( cd "$stage" && patch -p1 --dry-run < /work/targets/phosphor-networkd-dep-stdplus/stdplus.patch >/dev/null \
      && patch -p1 < /work/targets/phosphor-networkd-dep-stdplus/stdplus.patch ) || {
    echo "oft: dep-stdplus: OSS-Fuzz's stdplus.patch did not apply to the staged copy" >&2; return 1; }
  grep -q 'struct std::char_traits<unsigned char>' "$stage/include/stdplus/raw.hpp" || {
    echo "oft: dep-stdplus: stdplus.patch reported success but raw.hpp is unchanged" >&2; return 1; }
  cp -R "$stage/include/stdplus" "$BUILDDIR/include/"
  cp -R "$stage/include-fd/stdplus/." "$BUILDDIR/include/stdplus/"



  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  local f o n=0 objs=""
  for f in cancel debug/lifetime exception flags function_view handle/copyable \
           handle/managed hash hash/array hash/tuple net/addr/ether net/addr/ip \
           net/addr/sock net/addr/subnet net/addr/hostname numeric/endian \
           numeric/str pinned print raw signal str/buf str/cat str/cexpr \
           str/conv str/maps util/cexec variant zstring zstring_view \
           fd/atomic fd/create fd/dupable fd/fmt fd/impl fd/line fd/managed \
           fd/mmap fd/ops; do
    o="$BUILDDIR/obj/stdplus_$(echo "$f" | tr '/' '_').o"

    "$(oft_cxx)" $(oft_cxxflags) -std=c++23 -I"$BUILDDIR/include" \
      -c "$stage/src/$f.cpp" -o "$o" || {
      echo "oft: dep-stdplus: src/$f.cpp failed to compile" >&2; return 1; }
    objs="$objs $o"
    n=$((n + 1))
  done
  [ "$n" = 39 ] || { echo "oft: dep-stdplus: expected 39 objects, compiled $n" >&2; return 1; }
  { echo "create $BUILDDIR/lib/libstdplus.a"
    for o in $objs; do echo "addmod $o"; done
    echo save; echo end; } > "$BUILDDIR/stdplus.mri"
  "$CHOST-ar" -M < "$BUILDDIR/stdplus.mri" || return 1
  n=$("$CHOST-ar" t "$BUILDDIR/lib/libstdplus.a" | wc -l)
  [ "$n" = 39 ] || { echo "oft: dep-stdplus: lib/libstdplus.a has $n members, expected 39" >&2; return 1; }
  echo "oft: dep-stdplus: $n TUs in lib/libstdplus.a"
}
OV_PIN_END
ov_target_dependency phosphor-networkd-dep-sdbusplus <<'OV_PIN_END'
build_lib() {
  oft_require_target_cxx
  oft_suppress_unused_arg_werror
  oft_define_fuzzing_build_mode
  mkdir -p "$BUILDDIR/include" "$BUILDDIR/lib" "$BUILDDIR/obj"
  cp -R "$SRCDIR/include/sdbusplus" "$BUILDDIR/include/"


  grep -q '#include <unistd.h>' "$BUILDDIR/include/sdbusplus/event.hpp" || \
    sed -i '1s/^/#include <unistd.h>\n/' "$BUILDDIR/include/sdbusplus/event.hpp"
  head -1 "$BUILDDIR/include/sdbusplus/event.hpp" | grep -q '^#include <unistd.h>$' || {
    echo "oft: dep-sdbusplus: the event.hpp unistd.h edit did not take" >&2; return 1; }
  local f o n=0 objs=""
  for f in bus.cpp bus/match.cpp event.cpp exception.cpp message/native_types.cpp \
           sdbus.cpp server/interface.cpp server/transaction.cpp; do
    o="$BUILDDIR/obj/sdbusplus_$(echo "$f" | tr '/' '_' | sed 's/\.cpp$/.o/')"

    "$(oft_cxx)" $(oft_cxxflags) -std=c++23 -Wno-c++26-extensions \
      -I"$BUILDDIR/include" -c "$SRCDIR/src/$f" -o "$o" || {
      echo "oft: dep-sdbusplus: $f failed to compile" >&2; return 1; }
    objs="$objs $o"
    n=$((n + 1))
  done
  [ "$n" = 8 ] || { echo "oft: dep-sdbusplus: expected 8 objects, compiled $n" >&2; return 1; }
  { echo "create $BUILDDIR/lib/libsdbusplus.a"
    for o in $objs; do echo "addmod $o"; done
    echo save; echo end; } > "$BUILDDIR/sdbusplus.mri"
  "$CHOST-ar" -M < "$BUILDDIR/sdbusplus.mri" || return 1
  n=$("$CHOST-ar" t "$BUILDDIR/lib/libsdbusplus.a" | wc -l)
  [ "$n" = 8 ] || { echo "oft: dep-sdbusplus: lib/libsdbusplus.a has $n members, expected 8" >&2; return 1; }
  echo "oft: dep-sdbusplus: $n TUs in lib/libsdbusplus.a"
}
OV_PIN_END
ov_target_dependency phosphor-networkd-dep-pdi <<'OV_PIN_END'
build_lib() {
  command -v sdbus++ >/dev/null 2>&1 || {
    echo "oft: dep-pdi: sdbus++ is not on this image's PATH (use the builder image)" >&2; return 1; }
  mkdir -p "$BUILDDIR/yaml" "$BUILDDIR/gen"
  cp -R "$SRCDIR/yaml/." "$BUILDDIR/yaml/"
  local y="$BUILDDIR/yaml" g d


  d="$BUILDDIR/gen/xyz/openbmc_project/Common"; mkdir -p "$d"
  [ -e "$y/xyz/openbmc_project/Common.errors.yaml" ] && [ -e "$y/xyz/openbmc_project/Common.events.yaml" ] || {
    echo "oft: dep-pdi: Common.{errors,events}.yaml missing at this commit" >&2; return 1; }
  sdbus++ -r "$y" error exception-header xyz.openbmc_project.Common > "$d/error.hpp" || return 1
  sdbus++ -r "$y" error exception-cpp    xyz.openbmc_project.Common > "$d/error.cpp" || return 1
  sdbus++ -r "$y" event exception-header xyz.openbmc_project.Common > "$d/event.hpp" || return 1
  sdbus++ -r "$y" event exception-cpp    xyz.openbmc_project.Common > "$d/event.cpp" || return 1

  d="$BUILDDIR/gen/xyz/openbmc_project/Logging/Entry"; mkdir -p "$d"
  [ -e "$y/xyz/openbmc_project/Logging/Entry.interface.yaml" ] || {
    echo "oft: dep-pdi: Logging/Entry.interface.yaml missing at this commit" >&2; return 1; }
  sdbus++ -r "$y" interface common-header  xyz.openbmc_project.Logging.Entry > "$d/common.hpp" || return 1
  sdbus++ -r "$y" interface server-header  xyz.openbmc_project.Logging.Entry > "$d/server.hpp" || return 1
  sdbus++ -r "$y" interface server-cpp     xyz.openbmc_project.Logging.Entry > "$d/server.cpp" || return 1
  sdbus++ -r "$y" interface client-header  xyz.openbmc_project.Logging.Entry > "$d/client.hpp" || return 1
  sdbus++ -r "$y" interface aserver-header xyz.openbmc_project.Logging.Entry > "$d/aserver.hpp" || return 1

  for g in Common/error.hpp Common/error.cpp Logging/Entry/server.hpp Logging/Entry/common.hpp; do
    [ -s "$BUILDDIR/gen/xyz/openbmc_project/$g" ] || {
      echo "oft: dep-pdi: sdbus++ left gen/xyz/openbmc_project/$g empty" >&2; return 1; }
  done
  grep -q 'InternalFailure' "$BUILDDIR/gen/xyz/openbmc_project/Common/error.hpp" || {
    echo "oft: dep-pdi: generated Common/error.hpp declares no InternalFailure" >&2; return 1; }
  echo "oft: dep-pdi: sdbus++ $(command -v sdbus++) generated Common + Logging/Entry"
}
OV_PIN_END
ov_target_dependency phosphor-networkd-dep-phosphor-logging <<'OV_PIN_END'
build_lib() {
  mkdir -p "$BUILDDIR/include" "$BUILDDIR/srcs" "$BUILDDIR/tools"
  cp -R "$SRCDIR/lib/include/phosphor-logging" "$BUILDDIR/include/"
  cp "$SRCDIR/lib/lg2_logger.cpp" "$SRCDIR/lib/sdjournal.cpp" "$BUILDDIR/srcs/"
  cp -R "$SRCDIR/tools/." "$BUILDDIR/tools/"
  [ -f "$BUILDDIR/tools/elog-gen.py" ] && \
    [ -f "$BUILDDIR/tools/phosphor-logging/templates/elog-gen-template.hpp.mako" ] || {
    echo "oft: dep-phosphor-logging: elog-gen.py or its template missing at this commit" >&2; return 1; }
}
OV_PIN_END
build_lib() {
  oft_require_target_cxx
  oft_build_meson
  oft_build_harness "util_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""










































































































DEPENDS="phosphor-networkd-dep-stdplus phosphor-networkd-dep-sdbusplus phosphor-networkd-dep-pdi phosphor-networkd-dep-phosphor-logging"
build_lib() {
  oft_require_target_cxx
  oft_copy_src
  local stdp="$LIBROOT/phosphor-networkd-dep-stdplus" sdb="$LIBROOT/phosphor-networkd-dep-sdbusplus"
  local pdi="$LIBROOT/phosphor-networkd-dep-pdi" plog="$LIBROOT/phosphor-networkd-dep-phosphor-logging"
  local f
  for f in "$stdp/lib/libstdplus.a" "$stdp/include/stdplus" "$sdb/lib/libsdbusplus.a" \
           "$sdb/include/sdbusplus" "$pdi/yaml" "$pdi/gen/xyz/openbmc_project/Common/error.cpp" \
           "$plog/include/phosphor-logging" "$plog/srcs/lg2_logger.cpp" "$plog/srcs/sdjournal.cpp" \
           "$plog/tools/elog-gen.py"; do
    [ -e "$f" ] || { echo "oft: phosphor-networkd: DEPENDS left no $f" >&2; return 1; }
  done
  local inc="$BUILDDIR/include" nw="$BUILDDIR/nwconf" obj="$BUILDDIR/nwobj"
  mkdir -p "$inc" "$nw" "$obj" "$BUILDDIR/lib"
  cp -R "$stdp/include/." "$sdb/include/." "$plog/include/." "$pdi/gen/." "$inc/"
  python3 "$plog/tools/elog-gen.py" -t '' \
    -m "$plog/tools/phosphor-logging/templates/elog-gen-template.hpp.mako" \
    -y "$pdi/yaml" -u "$plog/tools/" -o "$inc/phosphor-logging/elog-errors.hpp" || {
    echo "oft: phosphor-networkd: elog-gen.py failed" >&2; return 1; }
  grep -q 'struct InternalFailure' "$inc/phosphor-logging/elog-errors.hpp" || {
    echo "oft: phosphor-networkd: generated elog-errors.hpp has no InternalFailure" >&2; return 1; }
  cat > "$nw/config.h" <<'EOH'
  
                                                                             
                                                                           
               
   

#pragma once

#define DEFAULT_BUSNAME "xyz.openbmc_project.Network"

#define ENABLE_IPV6_ACCEPT_RA 1

#define ENABLE_IPV6_ACCEPT_RA_STR yes

#define FORCE_SYNC_MAC_FROM_INVENTORY 1

#define LINK_LOCAL_AUTOCONFIGURATION 1

#define LINK_LOCAL_AUTOCONFIGURATION_STR yes

#define PERSIST_MAC 1

#define SYNC_MAC_FROM_INVENTORY 1

EOH
  local cxx defs objs="" o
  cxx=$(oft_cxx) || return 1
  defs="-DBOOST_ASIO_DISABLE_THREADS -DBOOST_ALL_NO_LIB -DBOOST_SYSTEM_NO_DEPRECATED"
  defs="$defs -DBOOST_ERROR_CODE_HEADER_ONLY -DBOOST_COROUTINES_NO_DEPRECATION_WARNING"
  for f in config_parser util types netlink rtnetlink; do
    o="$obj/networkd_$f.o"

    "$cxx" $(oft_cxxflags) -std=c++23 $defs -I"$BUILDDIR/src/src" -I"$nw" -I"$inc" \
      -c "$BUILDDIR/src/src/$f.cpp" -o "$o" || {
      echo "oft: phosphor-networkd: src/$f.cpp failed to compile" >&2; return 1; }
    objs="$objs $o"
  done
  for f in lg2_logger sdjournal; do
    o="$obj/phosphor_logging_$f.o"

    "$cxx" $(oft_cxxflags) -std=c++23 -DPLDM_HAS_POLL=1 $defs -I"$inc" \
      -c "$plog/srcs/$f.cpp" -o "$o" || {
      echo "oft: phosphor-networkd: phosphor-logging lib/$f.cpp failed to compile" >&2; return 1; }
    objs="$objs $o"
  done
  o="$obj/pdi_xyz_openbmc_project_Common_error.o"

  "$cxx" $(oft_cxxflags) -std=c++23 $defs -I"$inc" \
    -c "$inc/xyz/openbmc_project/Common/error.cpp" -o "$o" || {
    echo "oft: phosphor-networkd: PDI Common/error.cpp failed to compile" >&2; return 1; }
  objs="$objs $o"

  { echo "create $BUILDDIR/lib/liboft.a"
    for o in $objs; do echo "addmod $o"; done
    echo "addlib $stdp/lib/libstdplus.a"
    echo "addlib $sdb/lib/libsdbusplus.a"
    echo save; echo end; } > "$BUILDDIR/networkd-merge.mri"
  "$CHOST-ar" -M < "$BUILDDIR/networkd-merge.mri" || return 1
  f=$("$CHOST-ar" t "$BUILDDIR/lib/liboft.a" | wc -l)
  [ "$f" = 55 ] || { echo "oft: phosphor-networkd: lib/liboft.a has $f members, expected 55 (8 + 39 stdplus + 8 sdbusplus)" >&2; return 1; }
  LIB_ARCHIVE="lib/liboft.a"
  OFT_CXX_STD="-std=c++23"
  OFT_HARNESS_CFLAGS="$defs -I$BUILDDIR/src/src -I$nw"
  oft_build_harness "util_fuzzer.cpp"
  oft_add_sysroot_deps
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build util_fuzzer
)
