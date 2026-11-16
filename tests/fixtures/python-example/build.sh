#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds the fixture's one Python fuzz target with python/recipes.sh, as a ported Python build.sh does.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

(
ov_target_begin example
PY_HARNESS=fuzz_example.py
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
ov_target_build fuzz_example
)
