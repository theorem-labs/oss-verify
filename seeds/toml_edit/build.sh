#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of toml_edit into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# parse_document: the release's target toml_edit-parse_document
(
ov_target_begin toml_edit-parse_document
CARGO_FUZZ_DIR=crates/toml_edit_fuzz
FUZZ_BIN=parse_document
CARGO_DEBUG_ASSERTIONS=0
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_ALL_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=1
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build parse_document
)
