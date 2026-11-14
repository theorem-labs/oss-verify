#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of open5gs into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# gtp_message_fuzz: the release's target open5gs-gtp-message-fuzz
(
ov_target_begin open5gs-gtp-message-fuzz open5gs-dep-talloc open5gs-dep-libyaml
ov_target_dependency open5gs-dep-talloc <<'OV_PIN_END'
build_lib() {
  oft_copy_src
  local root="$BUILDDIR/src" obj="$BUILDDIR/obj" cfg=/work/targets/open5gs-dep-talloc/config.h
  [ -f "$root/talloc.c" ] || { echo "oft: open5gs-dep-talloc: no talloc.c under $root" >&2; return 1; }
  [ -f "$cfg" ] || { echo "oft: open5gs-dep-talloc: shipped $cfg is missing" >&2; return 1; }
  mkdir -p "$obj/cfg" "$BUILDDIR/include" "$BUILDDIR/lib/pkgconfig"


  cp -- "$cfg" "$obj/cfg/config.h"

  "$CC" $CFLAGS -D_GNU_SOURCE=1 -D_XOPEN_SOURCE_EXTENDED=1 -D__STDC_WANT_LIB_EXT1__=1 \
      -I"$obj/cfg" -I"$root" -I"$root/lib/replace" \
      -c "$root/talloc.c" -o "$obj/talloc.o"
  "$CHOST-ar" rcs "$obj/libtalloc.a" "$obj/talloc.o"



  local s
  for s in talloc_named_const _talloc_zero _talloc_realloc _talloc_free \
           talloc_total_size talloc_report_full talloc_enable_null_tracking; do
    "$CHOST-nm" --defined-only "$obj/libtalloc.a" | grep -q " T $s\$" \
      || { echo "oft: open5gs-dep-talloc: $s is not defined in libtalloc.a" >&2; return 1; }
  done
  oft_merge_archives
  cp -- "$BUILDDIR/lib/liboft.a" "$BUILDDIR/lib/libtalloc.a"
  cp -- "$root/talloc.h" "$BUILDDIR/include/talloc.h"


  cat > "$BUILDDIR/lib/pkgconfig/talloc.pc" <<EOP
prefix=${OFT_PREFIX:?}
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: talloc
Description: A hierarchical pool based memory system with destructors
Version: 2.4.3
Libs: -L\${libdir} -ltalloc
Cflags: -I\${includedir}
URL: http://talloc.samba.org/
EOP
  [ -s "$BUILDDIR/lib/pkgconfig/talloc.pc" ] || { echo "oft: open5gs-dep-talloc: talloc.pc not written" >&2; return 1; }
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
OV_PIN_END
ov_target_dependency open5gs-dep-libyaml <<'OV_PIN_END'
build_lib() {




  oft_build_autotools
  local pc="$BUILDDIR/lib/pkgconfig/yaml-0.1.pc"
  [ -f "$pc" ] || { echo "oft: open5gs-dep-libyaml: make install left no $pc" >&2; return 1; }
  [ -f "$BUILDDIR/lib/libyaml.a" ] || { echo "oft: open5gs-dep-libyaml: no installed lib/libyaml.a" >&2; return 1; }
  [ -f "$BUILDDIR/include/yaml.h" ] || { echo "oft: open5gs-dep-libyaml: no installed include/yaml.h" >&2; return 1; }



  local s
  for s in yaml_parser_initialize yaml_parser_set_input_file yaml_parser_load \
           yaml_document_get_root_node yaml_document_get_node yaml_document_delete \
           yaml_parser_delete; do
    "$CHOST-nm" --defined-only "$BUILDDIR/lib/liboft.a" | grep -q " T $s\$" \
      || { echo "oft: open5gs-dep-libyaml: $s is not defined in lib/liboft.a" >&2; return 1; }
  done
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
OV_PIN_END
build_lib() {
  oft_build_meson
  oft_build_harness "tests/fuzzing/gtp-message-fuzz.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""











































if [ -n "${LIBROOT:-}" ]; then
  PKG_CONFIG_PATH="$LIBROOT/open5gs-dep-talloc/lib/pkgconfig:$LIBROOT/open5gs-dep-libyaml/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  export PKG_CONFIG_PATH
fi
DEPENDS="open5gs-dep-talloc open5gs-dep-libyaml"











OFT_HARNESS_CFLAGS="-I$LIBROOT/open5gs-dep-talloc/include -I$LIBROOT/open5gs-dep-libyaml/include"















LIB_EXTRA="${LIB_EXTRA:-} $LIBROOT/open5gs-dep-talloc/lib/liboft.a $LIBROOT/open5gs-dep-libyaml/lib/liboft.a"
ov_target_build gtp_message_fuzz
)
