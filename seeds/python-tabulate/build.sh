#!/bin/sh -e
# Ported from the Python build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of python-tabulate into $OUT, each from the release's Python target for it (python/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_tabulate: the release's target python-tabulate-fuzz_tabulate
(
ov_target_begin python-tabulate-fuzz_tabulate
PY_HARNESS=fuzz_tabulate.py
PY_INSTALL="."
PY_ALLOW_MISSING=""
PY_SCM_VERSION=0.10.1.dev79+g268615a5c
. /usr/local/lib/oss-verify/python/recipes.sh
build_lib() {
  oft_py_build
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_tabulate
)
