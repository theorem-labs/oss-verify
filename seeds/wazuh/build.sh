#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of wazuh into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_xml: the release's target wazuh-fuzz_xml
(
ov_target_begin wazuh-fuzz_xml
build_lib() {
  OFT_BUILD_SUBDIR=src
  oft_build_cmake
  oft_build_harness "fuzz_xml.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



































oft_wazuh_build_os_xml() {
  oft_copy_src
  local xml="$BUILDDIR/src/src/shared/os_xml"
  [ -d "$xml" ] || { echo "oft: wazuh os_xml module missing at $xml" >&2; return 1; }
  mkdir -p "$BUILDDIR/oft_shim" "$BUILDDIR/objs" "$BUILDDIR/lib"
  cat > "$BUILDDIR/oft_shim/file_op.h" <<'OFTEOF'
#ifndef OFT_FILE_OP_SHIM_H
#define OFT_FILE_OP_SHIM_H
#include <stdio.h>
FILE * wfopen(const char * pathname, const char * mode);
void w_file_cloexec(FILE * fp);
#endif
OFTEOF
  cat > "$BUILDDIR/oft_shim/oft_file_op_shim.c" <<'OFTEOF'
                                                                         
                                                    
#include <stdio.h>
FILE * wfopen(const char * pathname, const char * mode) {
    return fopen(pathname, mode);
}
void w_file_cloexec(FILE * fp) {
                                                                 
                                                                      
                                                                     
                                      
      
      
       
    (void)fp;
}
OFTEOF
  local f
  for f in os_xml os_xml_access os_xml_node_access os_xml_variables os_xml_writer; do

    "$CC" $CFLAGS ${LIB_CFLAGS:-} -I"$BUILDDIR/oft_shim" \
      -c "$xml/$f.c" -o "$BUILDDIR/objs/$f.o" || return 1
  done

  "$CC" $CFLAGS ${LIB_CFLAGS:-} \
    -c "$BUILDDIR/oft_shim/oft_file_op_shim.c" -o "$BUILDDIR/objs/oft_file_op_shim.o" || return 1
  "$CHOST-ar" rcs "$BUILDDIR/lib/liboft.a" \
    "$BUILDDIR/objs/os_xml.o" "$BUILDDIR/objs/os_xml_access.o" \
    "$BUILDDIR/objs/os_xml_node_access.o" "$BUILDDIR/objs/os_xml_variables.o" \
    "$BUILDDIR/objs/os_xml_writer.o" "$BUILDDIR/objs/oft_file_op_shim.o" || return 1
  echo "oft: wazuh os_xml module -> lib/liboft.a (5 module TUs + 1 shim TU)"
}


build_lib() {
  oft_wazuh_build_os_xml
  OFT_HARNESS_CFLAGS="-include unistd.h -I$BUILDDIR/src/src/shared"
  oft_build_harness "fuzz_xml.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzz_xml
)
