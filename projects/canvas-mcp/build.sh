#!/bin/sh -e
# Copyright 2026 Vishal Sachdev
# SPDX-License-Identifier: Apache-2.0
#
# Builds the fuzz targets of canvas-mcp into $OUT, in the form of a ported Python build (tools/seeds/mdurl/build.sh).
# compile runs build.sh with bash; the Python recipe runs under sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_html: canvas_mcp.core.html, the HTML tokenizer and text extraction.
(
ov_target_begin canvas-mcp-fuzz_html
PY_HARNESS=fuzz_html.py
PY_ALLOW_MISSING=""
. /usr/local/lib/oss-verify/python/recipes.sh

# cm_stage takes the place of oft_py_install. canvas_mcp/__init__.py imports the server, and with it fastmcp, httpx
# and pydantic-core (a Rust extension), which this builder cannot build for riscv64. The modules under test import
# only the standard library. Thus cm_stage installs nothing with pip: it copies each module under test, unchanged,
# to its own package path, below two empty package files. The import path in a report is then the real one.
CM_MODULES="html"
cm_stage() {
  site="$OFT_PY_W/site"
  mkdir -p "$site/canvas_mcp/core"
  : > "$site/canvas_mcp/__init__.py"
  : > "$site/canvas_mcp/core/__init__.py"
  for m in $CM_MODULES; do
    cp "$SRCDIR/src/canvas_mcp/core/$m.py" "$site/canvas_mcp/core/$m.py"
  done
  OFT_PY_SITE=$site
}

build_lib() {
  oft_py_runtime
  oft_py_workdir
  cm_stage
  oft_py_freeze
  oft_py_harness
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_html
)
