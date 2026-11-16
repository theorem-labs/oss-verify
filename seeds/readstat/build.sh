#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of readstat into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_compression_sav: the release's target readstat-fuzz_compression_sav
(
ov_target_begin readstat-fuzz_compression_sav
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_compression_sav.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_compression_sav
)

# fuzz_grammar_dta_timestamp: the release's target readstat-fuzz_grammar_dta_timestamp
(
ov_target_begin readstat-fuzz_grammar_dta_timestamp
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_grammar_dta_timestamp.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_grammar_dta_timestamp
)

# fuzz_grammar_por_double: the release's target readstat-fuzz_grammar_por_double
(
ov_target_begin readstat-fuzz_grammar_por_double
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_grammar_por_double.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_grammar_por_double
)

# fuzz_grammar_sav_date: the release's target readstat-fuzz_grammar_sav_date
(
ov_target_begin readstat-fuzz_grammar_sav_date
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_grammar_sav_date.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_grammar_sav_date
)

# fuzz_grammar_sav_time: the release's target readstat-fuzz_grammar_sav_time
(
ov_target_begin readstat-fuzz_grammar_sav_time
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_grammar_sav_time.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_grammar_sav_time
)

# fuzz_grammar_spss_format: the release's target readstat-fuzz_grammar_spss_format
(
ov_target_begin readstat-fuzz_grammar_spss_format
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_grammar_spss_format.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_grammar_spss_format
)

# fuzz_grammar_xport_format: the release's target readstat-fuzz_grammar_xport_format
(
ov_target_begin readstat-fuzz_grammar_xport_format
build_lib() {
  oft_build_autotools
  oft_build_harness "src/fuzz/fuzz_grammar_xport_format.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_grammar_xport_format
)
