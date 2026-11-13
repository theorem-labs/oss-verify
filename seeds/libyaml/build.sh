#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libyaml into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# libyaml_deconstructor_alt_fuzzer: the release's target libyaml-libyaml_deconstructor_alt_fuzzer
(
ov_target_begin libyaml-libyaml_deconstructor_alt_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_deconstructor_alt_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_deconstructor_alt_fuzzer
)

# libyaml_deconstructor_fuzzer: the release's target libyaml-libyaml_deconstructor_fuzzer
(
ov_target_begin libyaml-libyaml_deconstructor_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_deconstructor_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_deconstructor_fuzzer
)

# libyaml_dumper_fuzzer: the release's target libyaml-libyaml_dumper_fuzzer
(
ov_target_begin libyaml-libyaml_dumper_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_dumper_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_dumper_fuzzer
)

# libyaml_emitter_fuzzer: the release's target libyaml-libyaml_emitter_fuzzer
(
ov_target_begin libyaml-libyaml_emitter_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_emitter_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_emitter_fuzzer
)

# libyaml_loader_fuzzer: the release's target libyaml-libyaml_loader_fuzzer
(
ov_target_begin libyaml-libyaml_loader_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_loader_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_loader_fuzzer
)

# libyaml_parser_fuzzer: the release's target libyaml-libyaml_parser_fuzzer
(
ov_target_begin libyaml-libyaml_parser_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_parser_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_parser_fuzzer
)

# libyaml_reformatter_alt_fuzzer: the release's target libyaml-libyaml_reformatter_alt_fuzzer
(
ov_target_begin libyaml-libyaml_reformatter_alt_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_reformatter_alt_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_reformatter_alt_fuzzer
)

# libyaml_reformatter_fuzzer: the release's target libyaml-libyaml_reformatter_fuzzer
(
ov_target_begin libyaml-libyaml_reformatter_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_reformatter_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_reformatter_fuzzer
)

# libyaml_scanner_fuzzer: the release's target libyaml-libyaml_scanner_fuzzer
(
ov_target_begin libyaml-libyaml_scanner_fuzzer
build_lib() {
  oft_build_cmake
  oft_build_harness "libyaml_scanner_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build libyaml_scanner_fuzzer
)
