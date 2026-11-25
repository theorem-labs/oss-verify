#!/bin/sh -e
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The build.sh that .github/scripts/python-runtime/make gives compile as $SRC/build.sh, in a builder whose toolchain
# image ships no prebuilt runtime: it builds the CPython runtime of this build as a Python fuzz target's build does
# (python/recipes.sh, oft_py_runtime), for a target oft-py-prebuilt that has nothing else, and stages it in
# $OUT/prebuilt (oft_py_prebuilt_stage): the runtime's files and its manifest. compile runs build.sh with bash; the
# Python recipe runs under sh -e, as a ported Python build.sh does, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
# shellcheck source-path=SCRIPTDIR source=../../../infra/base-builder/release-target.sh
. /usr/local/lib/oss-verify/release-target.sh

# ov_target_begin needs the target's source tree; the runtime's build reads nothing from it.
mkdir -p /work/ext/oft-py-prebuilt/src
(
ov_target_begin oft-py-prebuilt
# shellcheck source-path=SCRIPTDIR source=../../../infra/base-builder/python/recipes.sh
. /usr/local/lib/oss-verify/python/recipes.sh
oft_py_runtime
oft_py_prebuilt_stage "$OUT/prebuilt"
)
