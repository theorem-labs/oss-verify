#!/bin/sh -e
# Ported from the Python build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of tinycss2 into $OUT, each from the release's Python target for it (python/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_components: the release's target tinycss2-fuzz_components
(
ov_target_begin tinycss2-fuzz_components
PY_HARNESS=fuzz_components.py
PY_INSTALL="."
PY_ALLOW_MISSING=""
. /usr/local/lib/oss-verify/python/recipes.sh
build_lib() {
  oft_py_build
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_components
)

# fuzz_parse: the release's target tinycss2-fuzz_parse
(
ov_target_begin tinycss2-fuzz_parse
PY_HARNESS=fuzz_parse.py
PY_INSTALL="."
PY_ALLOW_MISSING=""
. /usr/local/lib/oss-verify/python/recipes.sh
build_lib() {
  oft_py_build
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_parse
)
