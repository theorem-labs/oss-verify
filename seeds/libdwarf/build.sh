#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libdwarf into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_aranges: the release's target libdwarf-fuzz_aranges
(
ov_target_begin libdwarf-fuzz_aranges
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_aranges.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_aranges
)

# fuzz_crc: the release's target libdwarf-fuzz_crc
(
ov_target_begin libdwarf-fuzz_crc
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_crc.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_crc
)

# fuzz_crc_32: the release's target libdwarf-fuzz_crc_32
(
ov_target_begin libdwarf-fuzz_crc_32
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_crc_32.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_crc_32
)

# fuzz_debug_addr_access: the release's target libdwarf-fuzz_debug_addr_access
(
ov_target_begin libdwarf-fuzz_debug_addr_access
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_debug_addr_access.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_debug_addr_access
)

# fuzz_debug_str: the release's target libdwarf-fuzz_debug_str
(
ov_target_begin libdwarf-fuzz_debug_str
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_debug_str.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_debug_str
)

# fuzz_debuglink: the release's target libdwarf-fuzz_debuglink
(
ov_target_begin libdwarf-fuzz_debuglink
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_debuglink.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_debuglink
)

# fuzz_die_cu: the release's target libdwarf-fuzz_die_cu
(
ov_target_begin libdwarf-fuzz_die_cu
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu
)

# fuzz_die_cu_attrs: the release's target libdwarf-fuzz_die_cu_attrs
(
ov_target_begin libdwarf-fuzz_die_cu_attrs
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_attrs.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_attrs
)

# fuzz_die_cu_attrs_loclist: the release's target libdwarf-fuzz_die_cu_attrs_loclist
(
ov_target_begin libdwarf-fuzz_die_cu_attrs_loclist
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_attrs_loclist.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_attrs_loclist
)

# fuzz_die_cu_e: the release's target libdwarf-fuzz_die_cu_e
(
ov_target_begin libdwarf-fuzz_die_cu_e
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_e.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_e
)

# fuzz_die_cu_e_print: the release's target libdwarf-fuzz_die_cu_e_print
(
ov_target_begin libdwarf-fuzz_die_cu_e_print
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_e_print.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_e_print
)

# fuzz_die_cu_info1: the release's target libdwarf-fuzz_die_cu_info1
(
ov_target_begin libdwarf-fuzz_die_cu_info1
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_info1.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_info1
)

# fuzz_die_cu_offset: the release's target libdwarf-fuzz_die_cu_offset
(
ov_target_begin libdwarf-fuzz_die_cu_offset
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_offset.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_offset
)

# fuzz_die_cu_print: the release's target libdwarf-fuzz_die_cu_print
(
ov_target_begin libdwarf-fuzz_die_cu_print
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_die_cu_print.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_die_cu_print
)

# fuzz_dnames: the release's target libdwarf-fuzz_dnames
(
ov_target_begin libdwarf-fuzz_dnames
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_dnames.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_dnames
)

# fuzz_findfuncbypc: the release's target libdwarf-fuzz_findfuncbypc
(
ov_target_begin libdwarf-fuzz_findfuncbypc
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_findfuncbypc.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_findfuncbypc
)

# fuzz_gdbindex: the release's target libdwarf-fuzz_gdbindex
(
ov_target_begin libdwarf-fuzz_gdbindex
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_gdbindex.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_gdbindex
)

# fuzz_globals: the release's target libdwarf-fuzz_globals
(
ov_target_begin libdwarf-fuzz_globals
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_globals.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_globals
)

# fuzz_gnu_index: the release's target libdwarf-fuzz_gnu_index
(
ov_target_begin libdwarf-fuzz_gnu_index
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_gnu_index.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_gnu_index
)

# fuzz_init_b: the release's target libdwarf-fuzz_init_b
(
ov_target_begin libdwarf-fuzz_init_b
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_init_b.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_init_b
)

# fuzz_init_binary: the release's target libdwarf-fuzz_init_binary
(
ov_target_begin libdwarf-fuzz_init_binary
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_init_binary.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_init_binary
)

# fuzz_init_path: the release's target libdwarf-fuzz_init_path
(
ov_target_begin libdwarf-fuzz_init_path
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_init_path.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_init_path
)

# fuzz_macro_dwarf4: the release's target libdwarf-fuzz_macro_dwarf4
(
ov_target_begin libdwarf-fuzz_macro_dwarf4
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_macro_dwarf4.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_macro_dwarf4
)

# fuzz_macro_dwarf5: the release's target libdwarf-fuzz_macro_dwarf5
(
ov_target_begin libdwarf-fuzz_macro_dwarf5
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_macro_dwarf5.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_macro_dwarf5
)

# fuzz_rng: the release's target libdwarf-fuzz_rng
(
ov_target_begin libdwarf-fuzz_rng
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_rng.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_rng
)

# fuzz_set_frame_all: the release's target libdwarf-fuzz_set_frame_all
(
ov_target_begin libdwarf-fuzz_set_frame_all
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_set_frame_all.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_set_frame_all
)

# fuzz_showsectgrp: the release's target libdwarf-fuzz_showsectgrp
(
ov_target_begin libdwarf-fuzz_showsectgrp
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_showsectgrp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_showsectgrp
)

# fuzz_simplereader_tu: the release's target libdwarf-fuzz_simplereader_tu
(
ov_target_begin libdwarf-fuzz_simplereader_tu
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_simplereader_tu.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_simplereader_tu
)

# fuzz_srcfiles: the release's target libdwarf-fuzz_srcfiles
(
ov_target_begin libdwarf-fuzz_srcfiles
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_srcfiles.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_srcfiles
)

# fuzz_stack_frame_access: the release's target libdwarf-fuzz_stack_frame_access
(
ov_target_begin libdwarf-fuzz_stack_frame_access
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_stack_frame_access.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_stack_frame_access
)

# fuzz_str_offsets: the release's target libdwarf-fuzz_str_offsets
(
ov_target_begin libdwarf-fuzz_str_offsets
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_str_offsets.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_str_offsets
)

# fuzz_tie: the release's target libdwarf-fuzz_tie
(
ov_target_begin libdwarf-fuzz_tie
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_tie.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_tie
)

# fuzz_xuindex: the release's target libdwarf-fuzz_xuindex
(
ov_target_begin libdwarf-fuzz_xuindex
build_lib() {
  oft_build_cmake
  oft_build_harness "fuzz/fuzz_xuindex.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_xuindex
)
