#!/bin/sh -e
# Copyright 2026 SQLPage contributors. SPDX-License-Identifier: Apache-2.0
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

(
ov_target_begin sqlpage-sql-file
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=sql_file
CARGO_DEBUG_ASSERTIONS=1
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
    oft_build_cargo_shim
    oft_seal_getenv
}
ov_target_build sql_file
)
